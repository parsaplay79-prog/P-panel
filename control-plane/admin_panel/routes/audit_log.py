"""Audit log — the searchable record of everything an admin did.

Every state-changing action in the product writes a row here (see
`domain/audit.audit`), and until this page the only way to read one was SQL.
That is the wrong way round: the audit log's whole purpose is to answer "who did
this, and when" during an incident, and an incident is not the moment to be
writing queries.

The filter list is built from the rows actually present rather than from a
hard-coded constant. A hard-coded action list drifts the moment someone adds an
audit call, and the drift is silent — the new action simply never appears in the
filter, so nobody knows it can be searched for.

`details_json` is rendered as JSON, not summarised. The column holds whatever
the caller passed (order ids, from/to values, before/after diffs), and a page
that tried to make it pretty would have to know every action's shape.
"""

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Admin, AuditLog
from domain import rbac

logger = logging.getLogger("verdent.admin_panel.audit_log")

router = APIRouter()

SORT_COLUMNS = {
    "created": AuditLog.created_at,
    "action": AuditLog.action,
    "actor": AuditLog.actor_id,
}


@router.get("/audit")
async def audit_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """The log, newest first, searchable by action, actor, target or free text."""
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("action", "actor_type"),
    )

    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(AuditLog.action).like(pattern),
                func.lower(AuditLog.target_type).like(pattern),
                # target_id is a uuid column; casting lets an operator paste an
                # order or node id straight from another page.
                func.lower(func.cast(AuditLog.target_id, Text)).like(pattern),
                func.lower(func.cast(AuditLog.details_json, Text)).like(pattern),
            )
        )
    if query.filters.get("action"):
        conditions.append(AuditLog.action == query.filters["action"])
    if query.filters.get("actor_type"):
        conditions.append(AuditLog.actor_type == query.filters["actor_type"])

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    rows = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    # Actor names, so the log reads as people rather than uuids. One query for
    # the page's actors, not one per row.
    actor_ids = {r.actor_id for r in rows if r.actor_id}
    actors = {
        a.id: a
        for a in (
            await db.execute(select(Admin).where(Admin.id.in_(actor_ids)))
        ).scalars().all()
    } if actor_ids else {}

    # The filter options, from the rows that exist. Bounded and grouped so this
    # stays one cheap query however large the log grows.
    action_rows = (
        await db.execute(
            select(AuditLog.action, func.count(AuditLog.id))
            .group_by(AuditLog.action)
            .order_by(func.count(AuditLog.id).desc())
            .limit(60)
        )
    ).all()

    context = {
        "title": "گزارش رویدادها",
        "rows": rows,
        "actors": actors,
        "actions": [(action, int(count)) for action, count in action_rows],
        "page": page,
        "query": query,
        "base_path": "/admin/audit",
        "active_nav": "/admin/audit",
    }
    if is_htmx(request):
        return render(request, "audit/_rows.html", **context)
    return render(request, "audit/list.html", **context)
