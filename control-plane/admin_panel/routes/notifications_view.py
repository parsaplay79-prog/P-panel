"""Notifications — the delivery log: who was told what, and when.

This table exists for one reason, and the panel has to show it that reason:
`notifications_log` is the deduplication record for the expiry/quota sweep. The
sweep runs from two services at different cadences (the `cron` service and the
`worker` service) and every step is check-then-act against this table, so the
row here is not "a message was sent" — it is "this customer has already been
warned today, do not warn again".

That distinction is the page. A customer complaining about a missing expiry
warning is answered by "no row exists for 2026-09-24" (the sweep did not run, or
did not reach them) versus "the row exists and the Telegram send failed" — two
completely different problems with the same symptom.

`notification_type` is stored as `"{type}:{ISO date}"` by
`domain.notifications._record` — the date is part of the key, not a separate
column. The page splits it for display and the filter matches on the prefix, so
filtering by `expiry_warn` finds every day's row without a `LIKE '%:...'` that
would also match a hypothetical type ending in `_warn`.
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
from db.models import Customer, NotificationsLog
from domain import rbac

logger = logging.getLogger("verdent.admin_panel.notifications")

router = APIRouter()

SORT_COLUMNS = {
    "sent": NotificationsLog.sent_at,
    "type": NotificationsLog.notification_type,
}

# The types `domain.notifications` writes, with what each one means. Kept next
# to the filter so the dropdown explains itself — "quota_exhausted" is not
# self-evident to a support agent reading the log for the first time.
NOTIFICATION_TYPE_FA = {
    "expired": "منقضی شد",
    "expiry_warn": "هشدار انقضا",
    "quota_exhausted": "اتمام حجم",
    "quota_warn": "هشدار حجم",
}


def split_notification_type(raw: str) -> tuple[str, str]:
    """`"expiry_warn:2026-09-24"` → `("expiry_warn", "2026-09-24")`.

    Tolerant of a row without the date suffix: the column is free text and an
    older row (or a future writer that forgets the convention) should render as
    itself rather than crash the page.
    """
    kind, _, day = raw.partition(":")
    return kind, day


@router.get("/notifications")
async def notifications_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    """The delivery log, newest first, filterable by type and customer.

    Gated on `support.manage` rather than a stats permission: the question this
    page answers is always "why did this customer not get their warning", which
    is a support conversation, and support already has the customer's context
    open in another tab.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="sent",
        filter_keys=("type",),
    )

    stmt = select(NotificationsLog, Customer).join(
        Customer, Customer.id == NotificationsLog.customer_id
    )
    count_stmt = select(func.count()).select_from(NotificationsLog)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        # Free text over the customer, because the id an operator has to hand is
        # almost always the Telegram id or the display name, never our uuid.
        conditions.append(
            or_(
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
                func.lower(NotificationsLog.notification_type).like(pattern),
            )
        )
    if query.filters.get("type"):
        # Prefix match, not equality: the stored value carries the date, and the
        # filter means the type. `like("expiry_warn:%")` cannot match
        # `expiry_warn_extra` the way a bare `like("%expiry_warn%")` would.
        conditions.append(
            NotificationsLog.notification_type.like(f"{query.filters['type']}:%")
        )

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    rows = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).all()

    items = [
        {
            "log": log,
            "customer": customer,
            "kind": split_notification_type(log.notification_type)[0],
            "day": split_notification_type(log.notification_type)[1],
            "kind_fa": NOTIFICATION_TYPE_FA.get(
                split_notification_type(log.notification_type)[0],
                split_notification_type(log.notification_type)[0],
            ),
        }
        for log, customer in rows
    ]

    # Per-type totals, so the dropdown carries the shape of the log: a sudden
    # spike in `quota_exhausted` is the signal that a plan's quota is wrong, and
    # it is visible here without reading a single row.
    type_rows = (
        await db.execute(
            select(NotificationsLog.notification_type, func.count(NotificationsLog.id))
            .group_by(NotificationsLog.notification_type)
            .order_by(func.count(NotificationsLog.id).desc())
            .limit(200)
        )
    ).all()

    counts: dict[str, int] = {}
    for raw_type, count in type_rows:
        kind, _ = split_notification_type(raw_type)
        counts[kind] = counts.get(kind, 0) + int(count)

    context = {
        "title": "گزارش اطلاع‌رسانی",
        "items": items,
        "counts": counts,
        "page": page,
        "query": query,
        "base_path": "/admin/notifications",
        "NOTIFICATION_TYPE_FA": NOTIFICATION_TYPE_FA,
        "active_nav": "/admin/notifications",
    }
    if is_htmx(request):
        return render(request, "notifications/_rows.html", **context)
    return render(request, "notifications/list.html", **context)
