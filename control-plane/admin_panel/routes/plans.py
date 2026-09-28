"""Plans — the `plan.manage` surface.

`plan.manage` was declared in RBAC and granted to OWNER and ADMIN, and used by
nothing. Plans were seeded once at first boot from `domain/plans.DEFAULT_PLANS`
with placeholder IRR prices and a comment saying "the OWNER edits them via the
admin panel (Phase 4)" — but Phase 4 never shipped a plan form. The only way to
change a price was a SQL statement.

Two things this page does that a plain CRUD form would not:

  * **It shows what a plan cannot be deleted for.** `orders.plan_id` is NOT
    NULL and references `plans.id`, so a plan anyone has ever bought cannot be
    deleted without destroying the order history that explains what they paid
    for. The delete button refuses with the order count instead of letting a
    foreign-key error surface as a 500.
  * **It refuses to deactivate the last active plan in a pool**, because a pool
    with no active plan is a buy button that cannot be pressed.

A plan's `pool_id` is what decides which nodes can serve it, so the pool
selector is not decoration: changing it changes which hardware a new customer
lands on, and the form says so.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import GamingProfile, Order, Plan, Pool
from domain import rbac
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.plans")

router = APIRouter()

GB = 1024 * 1024 * 1024

SORT_COLUMNS = {
    "name": Plan.name,
    "price": Plan.price_amount,
    "duration": Plan.duration_days,
    "active": Plan.is_active,
}


def _parse_amount(raw: str) -> int | None:
    """Parse a price. Accepts separators and a bare number; None if unusable.

    Operators paste prices with thousands separators ("1,600,000") straight out
    of a message. Rejecting that with "invalid number" would be technically
    correct and practically annoying, so the separators are stripped here —
    and a negative or zero price is refused at the call site rather than
    silently stored, because a free plan that looks paid is a billing incident.
    """
    cleaned = (raw or "").replace(",", "").replace("٬", "").replace(" ", "").strip()
    if not cleaned:
        return None
    try:
        return int(cleaned)
    except ValueError:
        return None


def _parse_quota_gb(raw: str) -> int | None:
    """Traffic quota in GB, or None for unlimited.

    An empty field means unlimited, which is a real product decision
    (`traffic_quota_bytes` is nullable for exactly that) rather than a missing
    value — so the form labels it "خالی = نامحدود" rather than leaving the
    operator to guess whether blank will be read as zero.
    """
    cleaned = (raw or "").strip()
    if not cleaned:
        return None
    try:
        gb = float(cleaned)
    except ValueError:
        return None
    if gb < 0:
        return None
    return int(gb * GB)


@router.get("/plans")
async def plans_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="name",
        filter_keys=("active",),
    )

    stmt = select(Plan)
    count_stmt = select(func.count()).select_from(Plan)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(func.lower(Plan.name).like(pattern))
    if query.filters.get("active") == "1":
        conditions.append(Plan.is_active.is_(True))
    elif query.filters.get("active") == "0":
        conditions.append(Plan.is_active.is_(False))

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    plans = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    # Purchase counts, so the delete button can say why it refuses. One grouped
    # query rather than one per row.
    order_counts = dict(
        (
            await db.execute(
                select(Order.plan_id, func.count(Order.id)).group_by(Order.plan_id)
            )
        ).all()
    )

    pools = {p.id: p for p in (await db.execute(select(Pool))).scalars().all()}
    profiles = {
        p.id: p
        for p in (
            await db.execute(
                select(GamingProfile).where(GamingProfile.is_current.is_(True))
            )
        ).scalars().all()
    }

    context = {
        "title": "پلن‌ها",
        "plans": plans,
        "order_counts": {k: int(v) for k, v in order_counts.items()},
        "pools": pools,
        "profiles": profiles,
        "page": page,
        "query": query,
        "base_path": "/admin/plans",
        "GB": GB,
        "active_nav": "/admin/plans",
    }
    if is_htmx(request):
        return render(request, "plans/_rows.html", **context)
    return render(request, "plans/list.html", **context)


@router.get("/plans/new")
async def plan_new_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    return render(
        request,
        "plans/form.html",
        title="پلن جدید",
        plan=None,
        pools=(await db.execute(select(Pool).order_by(Pool.name))).scalars().all(),
        profiles=(await db.execute(select(GamingProfile))).scalars().all(),
        GB=GB,
        active_nav="/admin/plans",
    )


@router.post("/plans/new")
async def plan_create(
    request: Request,
    name: str = Form(""),
    description: str = Form(""),
    price_amount: str = Form(""),
    price_currency: str = Form("IRR"),
    duration_days: str = Form(""),
    quota_gb: str = Form(""),
    device_limit: str = Form("1"),
    pool_id: str = Form(""),
    gaming_profile_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    name = name.strip()

    def _fail(code: str):
        return redirect("/admin/plans/new", err=code)

    if not name:
        return _fail("name_required")

    amount = _parse_amount(price_amount)
    if amount is None or amount <= 0:
        return _fail("bad_price")

    try:
        days = int(duration_days)
    except (TypeError, ValueError):
        return _fail("bad_duration")
    if days <= 0 or days > 3650:
        return _fail("bad_duration")

    try:
        devices = int(device_limit or "1")
    except (TypeError, ValueError):
        return _fail("bad_devices")
    if devices <= 0 or devices > 100:
        return _fail("bad_devices")

    quota = _parse_quota_gb(quota_gb)
    if quota_gb.strip() and quota is None:
        return _fail("bad_quota")

    pool = (
        await db.execute(select(Pool).where(Pool.id == pool_id))
    ).scalar_one_or_none()
    if pool is None:
        return _fail("bad_pool")

    plan = Plan(
        name=name,
        description=description.strip() or None,
        price_amount=amount,
        price_currency=(price_currency or "IRR").strip().upper(),
        duration_days=days,
        traffic_quota_bytes=quota,
        device_limit=devices,
        pool_id=pool.id,
        gaming_profile_id=gaming_profile_id or None,
        is_active=True,
    )
    db.add(plan)
    await db.commit()

    await audit(
        db,
        "plan.create",
        actor_id=admin.id,
        target_type="plan",
        target_id=plan.id,
        details={"name": plan.name, "price": amount, "currency": plan.price_currency},
    )
    return redirect("/admin/plans", ok="created")


@router.get("/plans/{plan_id}/edit")
async def plan_edit_form(
    plan_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if plan is None:
        return redirect("/admin/plans", err="notfound")

    return render(
        request,
        "plans/form.html",
        title=f"ویرایش {plan.name}",
        plan=plan,
        pools=(await db.execute(select(Pool).order_by(Pool.name))).scalars().all(),
        profiles=(await db.execute(select(GamingProfile))).scalars().all(),
        GB=GB,
        active_nav="/admin/plans",
    )


@router.post("/plans/{plan_id}/edit")
async def plan_update(
    plan_id: str,
    name: str = Form(""),
    description: str = Form(""),
    price_amount: str = Form(""),
    price_currency: str = Form("IRR"),
    duration_days: str = Form(""),
    quota_gb: str = Form(""),
    device_limit: str = Form("1"),
    pool_id: str = Form(""),
    gaming_profile_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    """Edit a plan. Existing customers are NOT migrated to the new terms.

    A plan row is a template, not a contract: `configurations` copies
    `expires_at` at creation and `usage_current_period_detail` re-reads
    `duration_days` to derive the period start, so changing `duration_days` on a
    plan that has live configs silently moves those customers' usage period
    boundary — their consumed traffic can appear to reset or double overnight.
    The form warns about this; the platform does not attempt a migration,
    because there is no correct one: some customers are mid-period and any
    rewrite would be wrong for some of them.
    """
    plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if plan is None:
        return redirect("/admin/plans", err="notfound")

    name = name.strip()
    if not name:
        return redirect(f"/admin/plans/{plan_id}/edit", err="name_required")

    amount = _parse_amount(price_amount)
    if amount is None or amount <= 0:
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_price")

    try:
        days = int(duration_days)
    except (TypeError, ValueError):
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_duration")
    if days <= 0 or days > 3650:
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_duration")

    try:
        devices = int(device_limit or "1")
    except (TypeError, ValueError):
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_devices")
    if devices <= 0 or devices > 100:
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_devices")

    quota = _parse_quota_gb(quota_gb)
    if quota_gb.strip() and quota is None:
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_quota")

    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    if pool is None:
        return redirect(f"/admin/plans/{plan_id}/edit", err="bad_pool")

    before = {
        "name": plan.name,
        "price_amount": str(plan.price_amount),
        "duration_days": plan.duration_days,
        "traffic_quota_bytes": plan.traffic_quota_bytes,
        "device_limit": plan.device_limit,
        "pool_id": plan.pool_id,
    }

    plan.name = name
    plan.description = description.strip() or None
    plan.price_amount = amount
    plan.price_currency = (price_currency or "IRR").strip().upper()
    plan.duration_days = days
    plan.traffic_quota_bytes = quota
    plan.device_limit = devices
    plan.pool_id = pool.id
    plan.gaming_profile_id = gaming_profile_id or None
    await db.commit()

    after = {
        "name": plan.name,
        "price_amount": str(plan.price_amount),
        "duration_days": plan.duration_days,
        "traffic_quota_bytes": plan.traffic_quota_bytes,
        "device_limit": plan.device_limit,
        "pool_id": plan.pool_id,
    }
    changed = {k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]}

    await audit(
        db,
        "plan.update",
        actor_id=admin.id,
        target_type="plan",
        target_id=plan.id,
        details={"changed": changed},
    )
    return redirect("/admin/plans", ok="updated")


@router.post("/plans/{plan_id}/toggle")
async def plan_toggle(
    plan_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    """Activate or deactivate a plan.

    Deactivating hides it from the bot's purchase menu without touching the
    customers already on it — that is the difference between "stop selling" and
    "cancel everyone", and only the first is what this button means.

    Refuses to deactivate the last active plan in its pool. An empty purchase
    menu with no explanation is indistinguishable from a broken bot.
    """
    plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if plan is None:
        return redirect("/admin/plans", err="notfound")

    if plan.is_active:
        others = (
            await db.execute(
                select(func.count())
                .select_from(Plan)
                .where(
                    Plan.pool_id == plan.pool_id,
                    Plan.is_active.is_(True),
                    Plan.id != plan.id,
                )
            )
        ).scalar_one()
        if int(others) == 0:
            return redirect("/admin/plans", err="last_in_pool")

    plan.is_active = not plan.is_active
    await db.commit()

    await audit(
        db,
        "plan.toggle",
        actor_id=admin.id,
        target_type="plan",
        target_id=plan.id,
        details={"is_active": plan.is_active},
    )
    return redirect("/admin/plans", ok="activated" if plan.is_active else "deactivated")


@router.post("/plans/{plan_id}/delete")
async def plan_delete(
    plan_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PLAN_MANAGE)),
):
    """Delete a plan that nobody has ever bought. Refuses otherwise.

    `orders.plan_id` is NOT NULL with a foreign key to this row, so a plan with
    history cannot be removed at all — Postgres would raise a FK violation,
    which surfaces as a 500 the operator cannot act on. The refusal names the
    count instead, and the correct action (deactivate) is offered in the
    template next to it.

    Deletion is also restricted to plans with no orders for a second reason:
    every price a customer was quoted lives in the order row that points here,
    and losing it loses the only record of what was sold.
    """
    plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
    if plan is None:
        return redirect("/admin/plans", err="notfound")

    order_count = int(
        (
            await db.execute(
                select(func.count()).select_from(Order).where(Order.plan_id == plan.id)
            )
        ).scalar_one()
    )
    if order_count:
        return redirect("/admin/plans", err="has_orders", n=order_count)

    name = plan.name
    await db.delete(plan)
    await db.commit()

    await audit(
        db,
        "plan.delete",
        actor_id=admin.id,
        target_type="plan",
        target_id=plan_id,
        details={"name": name},
    )
    return redirect("/admin/plans", ok="deleted")
