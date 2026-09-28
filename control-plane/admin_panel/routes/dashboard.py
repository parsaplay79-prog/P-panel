"""The dashboard — the operator's traffic light.

Document 4 §S describes what this surface is for: "a quick-operational-glance
surface — counts, pending queues, a health traffic-light". That is exactly right
for the *front page* of the web panel, and it is the one part of the Telegram
design that carries over unchanged. What does not carry over is the depth: every
number here links to the table that can act on it.

The health traffic light is the piece worth reading carefully. It does not show
"nodes online" alone, because a node count that looks fine can hide the two
states that actually need an operator: nodes stuck in PROVISIONING (a job
failed) and nodes an operator deliberately took out of rotation
(MAINTENANCE/QUARANTINED). Those are counted separately and shown in a warning
colour, because a healthy-looking dashboard over a stuck provisioning job is the
exact failure the old panel had.
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.helpers import render
# The state labels are owned by the nodes page and imported here rather than
# restated: the dashboard groups a node-state dict and the nodes table lists
# the same states, and two copies of that mapping drift the moment a state is
# added.
from admin_panel.routes.nodes import NODE_STATE_FA
from db.base import get_db
from db.models import (
    AuditLog,
    Configuration,
    Customer,
    Node,
    Order,
    PaymentAttempt,
    SupportTicket,
)
from domain import jobs as jobs_domain
from domain import rbac

logger = logging.getLogger("verdent.admin_panel.dashboard")

router = APIRouter()


# `"/"` and not `""`. This router is included under `prefix="/admin"`, and
# FastAPI's `include_router` refuses a child path that is empty when no prefix
# is given at that call — the app would fail to build, not just 404. Starlette's
# `redirect_slashes` then turns `GET /admin` into a 307 to `GET /admin/`, so
# every internal link must carry the trailing slash.
@router.get("/")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """Counts, queues and the health light — one page, one query batch."""

    async def count(model, *conditions) -> int:
        stmt = select(func.count()).select_from(model)
        for condition in conditions:
            stmt = stmt.where(condition)
        return int((await db.execute(stmt)).scalar_one())

    n_configs_active = await count(Configuration, Configuration.status == "ACTIVE")
    n_configs_suspended = await count(Configuration, Configuration.status == "SUSPENDED")
    n_configs_test = await count(Configuration, Configuration.is_test.is_(True))

    n_pending_payments = await count(PaymentAttempt, PaymentAttempt.status == "WAITING_REVIEW")
    n_orders_provisioning = await count(Order, Order.status == "PROVISIONING")

    n_customers = await count(Customer)
    n_banned = await count(Customer, Customer.status == "banned")

    # Node breakdown, by state. Grouped so a new state cannot be silently
    # omitted from the light: whatever is in the table appears in the dict.
    node_rows = (
        await db.execute(select(Node.state, func.count(Node.id)).group_by(Node.state))
    ).all()
    node_states = {state: int(count_) for state, count_ in node_rows}
    n_nodes_total = sum(node_states.values())
    n_nodes_online = node_states.get("ONLINE", 0)
    n_nodes_degraded = node_states.get("DEGRADED", 0)
    n_nodes_offline = node_states.get("OFFLINE", 0)
    n_nodes_provisioning = node_states.get("PROVISIONING", 0)
    n_nodes_held = node_states.get("MAINTENANCE", 0) + node_states.get("QUARANTINED", 0)

    n_tickets_open = await count(SupportTicket, SupportTicket.status == "open")

    job_counts = await jobs_domain.queue_stats(db)

    recent_audit = (
        await db.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(12))
    ).scalars().all()

    # Capacity: how much room is left before fulfillment starts failing. This is
    # the number that predicts a problem rather than reporting one — the panel's
    # most useful early warning.
    capacity_rows = (
        await db.execute(
            select(
                func.coalesce(func.sum(Node.max_assignment_count), 0),
                func.coalesce(func.sum(Node.current_assignment_count), 0),
            ).where(Node.state.in_(["ONLINE", "DEGRADED"]))
        )
    ).one()
    capacity_total, capacity_used = int(capacity_rows[0]), int(capacity_rows[1])
    capacity_free = max(0, capacity_total - capacity_used)

    return render(
        request,
        "dashboard.html",
        title="وضعیت سیستم",
        # Rendered on the page rather than left to the client: the light is
        # computed server-side so the rule is testable, and a "last checked"
        # that depends on the browser clock would contradict it.
        now=datetime.now(timezone.utc),
        NODE_STATE_FA=NODE_STATE_FA,
        # Must match the nav href exactly, trailing slash included — see the
        # comment on the route decorator.
        active_nav="/admin/",
        n_configs_active=n_configs_active,
        n_configs_suspended=n_configs_suspended,
        n_configs_test=n_configs_test,
        n_pending_payments=n_pending_payments,
        n_orders_provisioning=n_orders_provisioning,
        n_customers=n_customers,
        n_banned=n_banned,
        n_nodes_total=n_nodes_total,
        n_nodes_online=n_nodes_online,
        n_nodes_degraded=n_nodes_degraded,
        n_nodes_offline=n_nodes_offline,
        n_nodes_provisioning=n_nodes_provisioning,
        n_nodes_held=n_nodes_held,
        node_states=node_states,
        n_tickets_open=n_tickets_open,
        job_counts=job_counts,
        recent_audit=recent_audit,
        capacity_total=capacity_total,
        capacity_used=capacity_used,
        capacity_free=capacity_free,
        # The light is red if anything needs a human, amber if something is
        # merely unhealthy, green otherwise. Computed here rather than in the
        # template so the rule is testable.
        health_light=_health_light(
            n_nodes_offline=n_nodes_offline,
            n_nodes_provisioning=n_nodes_provisioning,
            job_failed=job_counts.get(jobs_domain.STATUS_FAILED, 0),
            n_nodes_degraded=n_nodes_degraded,
            capacity_free=capacity_free,
            n_orders_provisioning=n_orders_provisioning,
        ),
    )


def _health_light(
    *,
    n_nodes_offline: int,
    n_nodes_provisioning: int,
    job_failed: int,
    n_nodes_degraded: int,
    capacity_free: int,
    n_orders_provisioning: int,
) -> dict[str, str]:
    """Traffic light: what needs a human, right now.

    Red — a node is down, a job has permanently failed, or an order is stuck.
          All three mean a customer is not being served and nothing will fix it
          without an operator.
    Amber — degraded nodes, or no free capacity while orders are waiting. Not
          broken yet; about to be.
    Green — nothing above.
    """
    red_reasons = []
    if n_nodes_offline:
        red_reasons.append(f"{n_nodes_offline} نود آفلاین")
    if job_failed:
        red_reasons.append(f"{job_failed} کار ناموفق")
    if n_orders_provisioning:
        red_reasons.append(f"{n_orders_provisioning} سفارش در فعال‌سازی")
    if n_nodes_provisioning:
        red_reasons.append(f"{n_nodes_provisioning} نود در حال ساخت")

    if red_reasons:
        return {"level": "bad", "label": "نیاز به رسیدگی", "detail": "، ".join(red_reasons)}

    amber_reasons = []
    if n_nodes_degraded:
        amber_reasons.append(f"{n_nodes_degraded} نود ناسالم")
    if capacity_free == 0:
        amber_reasons.append("ظرفیت آزاد تمام شده")

    if amber_reasons:
        return {"level": "warn", "label": "هشدار", "detail": "، ".join(amber_reasons)}

    return {"level": "ok", "label": "سالم", "detail": "همه‌چیز طبیعی است"}
