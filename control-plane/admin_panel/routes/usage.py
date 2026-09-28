"""Usage — the ledger, the daily aggregates, and reconciliation.

Three numbers describe one customer's traffic and they come from three places:
`usage_events` (the append-only ledger the nodes report into, keyed by
`(connection_id, sequence_number)`), `usage_daily_aggregates` (the maintained
rollup the quota math reads), and the derived "current period" total the
subscription endpoint publishes.

`scripts/verify_usage.py` already compares ledger against aggregate from a
shell. This page is the same comparison, on demand, with the rows that disagree
listed instead of just a count — because "reconciliation found 3 mismatches" is
not actionable and "config a1b2, day 2026-09-14, ledger 4.2GB, aggregate 0"
is.

The repair is `domain.reconcile.reconcile_usage`, which re-derives the
aggregates *from* the ledger. That direction is deliberate and not symmetric:
the ledger is append-only and trigger-protected, so it is the truth; the
aggregate is a cache. Repairing the ledger from the aggregate would be
repairing the record from the summary.
"""

import logging
from datetime import date, datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import (
    Configuration,
    Customer,
    UsageDailyAggregate,
    UsageEvent,
)
from domain import rbac
from domain.audit import audit
from domain.reconcile import RECONCILE_LOOKBACK_DAYS, reconcile_usage
from domain.subscriptions import usage_current_period_detail

logger = logging.getLogger("verdent.admin_panel.usage")

router = APIRouter()

SORT_COLUMNS = {
    "created": Configuration.created_at,
    "expires": Configuration.expires_at,
    "name": Configuration.display_name,
}


@router.get("/usage")
async def usage_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """Per-config usage for the current period, with quota and percentage.

    The percentage is computed here rather than in the template so the sort is
    available: "who is closest to their cap" is the question this page is
    opened to answer, and it is a sort, not a scan.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("type",),
    )

    stmt = (
        select(Configuration, Customer)
        .join(Customer, Customer.id == Configuration.customer_id)
        .where(Configuration.status.in_(["ACTIVE", "SUSPENDED", "EXPIRED"]))
    )
    count_stmt = (
        select(func.count())
        .select_from(Configuration)
        .where(Configuration.status.in_(["ACTIVE", "SUSPENDED", "EXPIRED"]))
    )

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Configuration.display_name).like(pattern),
                func.lower(Configuration.suffix).like(pattern),
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
            )
        )
    if query.filters.get("type") == "test":
        conditions.append(Configuration.is_test.is_(True))
    elif query.filters.get("type") == "paid":
        conditions.append(Configuration.is_test.is_(False))

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

    items = []
    for config, customer in rows:
        used, up, down, quota = await usage_current_period_detail(db, config)
        items.append(
            {
                "config": config,
                "customer": customer,
                "used": used,
                "up": up,
                "down": down,
                "quota": quota,
                "percent": (round(used / quota * 100, 1) if quota else None),
            }
        )

    context = {
        "title": "مصرف",
        "items": items,
        "page": page,
        "query": query,
        "base_path": "/admin/usage",
        "RECONCILE_LOOKBACK_DAYS": RECONCILE_LOOKBACK_DAYS,
        "active_nav": "/admin/usage",
    }
    if is_htmx(request):
        return render(request, "usage/_rows.html", **context)
    return render(request, "usage/list.html", **context)


@router.get("/usage/{config_id}")
async def usage_detail(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """One config's ledger: recent events and the daily rollup, side by side.

    The two tables are the reconciliation view in miniature. When they disagree,
    seeing which day diverged is the difference between "usage looks wrong" and
    a report that names the date.
    """
    config = (
        await db.execute(select(Configuration).where(Configuration.id == config_id))
    ).scalar_one_or_none()
    if config is None:
        return redirect("/admin/usage", err="notfound")

    customer = (
        await db.execute(select(Customer).where(Customer.id == config.customer_id))
    ).scalar_one_or_none()

    used, up, down, quota = await usage_current_period_detail(db, config)

    aggregates = (
        await db.execute(
            select(UsageDailyAggregate)
            .where(UsageDailyAggregate.configuration_id == config.id)
            .order_by(UsageDailyAggregate.usage_date.desc())
            .limit(60)
        )
    ).scalars().all()

    events = (
        await db.execute(
            select(UsageEvent)
            .where(UsageEvent.configuration_id == config.id)
            .order_by(UsageEvent.reported_at.desc())
            .limit(100)
        )
    ).scalars().all()

    # Ledger totals per day, computed the same way `reconcile_usage` does, so
    # the page can mark which days disagree without running a repair.
    ledger_rows = (
        await db.execute(
            select(
                func.date_trunc("day", UsageEvent.reported_at).label("day"),
                func.coalesce(func.sum(UsageEvent.bytes_up), 0),
                func.coalesce(func.sum(UsageEvent.bytes_down), 0),
            )
            .where(UsageEvent.configuration_id == config.id)
            .group_by(func.date_trunc("day", UsageEvent.reported_at))
        )
    ).all()

    ledger_by_day: dict[date, tuple[int, int]] = {}
    for day, up_bytes, down_bytes in ledger_rows:
        key = day.date() if hasattr(day, "date") else day
        ledger_by_day[key] = (int(up_bytes), int(down_bytes))

    drift = []
    for agg in aggregates:
        truth = ledger_by_day.get(agg.usage_date)
        expected = (truth[0], truth[1]) if truth else (0, 0)
        if (agg.bytes_up, agg.bytes_down) != expected:
            drift.append(
                {
                    "date": agg.usage_date,
                    "aggregate": (agg.bytes_up, agg.bytes_down),
                    "ledger": expected,
                }
            )

    return render(
        request,
        "usage/detail.html",
        title=f"مصرف {config.display_name}_{config.suffix}",
        config=config,
        customer=customer,
        used=used,
        bytes_up=up,
        bytes_down=down,
        quota=quota,
        percent=(round(used / quota * 100, 1) if quota else None),
        aggregates=aggregates,
        events=events,
        drift=drift,
        active_nav="/admin/usage",
    )


@router.get("/reconcile")
async def reconcile_page(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """The drift report: every (config, day) where the aggregate is wrong.

    Read-only and bounded to the reconcile window. Listing the mismatches
    before offering the repair is what makes the repair a decision rather than a
    leap — `reconcile_usage` rewrites rows, and an operator should see how many
    before they press it.
    """
    since = date.today() - timedelta(days=RECONCILE_LOOKBACK_DAYS)
    since_dt = datetime(since.year, since.month, since.day, tzinfo=timezone.utc)

    ledger_rows = (
        await db.execute(
            select(
                UsageEvent.configuration_id,
                func.date_trunc("day", UsageEvent.reported_at).label("day"),
                func.coalesce(func.sum(UsageEvent.bytes_up), 0),
                func.coalesce(func.sum(UsageEvent.bytes_down), 0),
            )
            # A timestamptz column compared against a naive date would be
            # coerced to midnight *local* server time, which is not what the
            # aggregate's UTC-day grouping means. An explicit UTC datetime keeps
            # this window aligned with `reconcile_usage`'s own bound.
            .where(UsageEvent.reported_at >= since_dt)
            .group_by(
                UsageEvent.configuration_id,
                func.date_trunc("day", UsageEvent.reported_at),
            )
        )
    ).all()

    ledger: dict[tuple[str, date], tuple[int, int]] = {}
    for config_id, day, up_bytes, down_bytes in ledger_rows:
        key = day.date() if hasattr(day, "date") else day
        ledger[(config_id, key)] = (int(up_bytes), int(down_bytes))

    aggregates = (
        await db.execute(
            select(UsageDailyAggregate).where(UsageDailyAggregate.usage_date >= since)
        )
    ).scalars().all()

    drift = []
    seen: set[tuple[str, date]] = set()
    for agg in aggregates:
        key = (agg.configuration_id, agg.usage_date)
        seen.add(key)
        expected = ledger.get(key, (0, 0))
        if (agg.bytes_up, agg.bytes_down) != expected:
            drift.append(
                {
                    "configuration_id": agg.configuration_id,
                    "date": agg.usage_date,
                    "aggregate": (agg.bytes_up, agg.bytes_down),
                    "ledger": expected,
                }
            )

    # Days the ledger knows about with no aggregate row at all — the other half
    # of the drift, and the one a "compare existing rows" check would miss.
    missing = [
        {"configuration_id": config_id, "date": day, "ledger": values}
        for (config_id, day), values in ledger.items()
        if (config_id, day) not in seen
    ]

    config_ids = {d["configuration_id"] for d in drift} | {d["configuration_id"] for d in missing}
    configs = {
        c.id: c
        for c in (
            await db.execute(select(Configuration).where(Configuration.id.in_(config_ids)))
        ).scalars().all()
    } if config_ids else {}

    return render(
        request,
        "usage/reconcile.html",
        title="بازبینی مصرف",
        drift=drift,
        missing=missing,
        configs=configs,
        since=since,
        RECONCILE_LOOKBACK_DAYS=RECONCILE_LOOKBACK_DAYS,
        active_nav="/admin/usage",
    )


@router.post("/reconcile/run")
async def reconcile_run(
    days: int = Form(RECONCILE_LOOKBACK_DAYS),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """Re-derive aggregates from the ledger. Audited with the row counts.

    `reconcile_usage` opens its own session (it is written to be called from the
    worker loop), so this route does not pass one in. That is why the audit call
    below uses the request's session — two sessions in one request is unusual
    but correct here: the reconcile is a self-contained unit of work with its
    own transaction, and the audit row belongs to the operator's action.
    """
    if days < 1 or days > 365:
        return redirect("/admin/reconcile", err="bad_days")

    since = date.today() - timedelta(days=days)

    try:
        result = await reconcile_usage(since=since)
    except Exception as exc:  # noqa: BLE001 — a failed repair must be reportable
        logger.exception("usage reconciliation failed")
        return redirect("/admin/reconcile", err="failed", detail=str(exc)[:200])

    await audit(
        db,
        "usage.reconcile",
        actor_id=admin.id,
        target_type="usage",
        target_id=None,
        details={
            "since": str(since),
            "ledger_groups": result.get("ledger_groups", 0),
            "repaired": result.get("repaired", 0),
        },
    )

    return redirect(
        "/admin/reconcile",
        ok="reconciled",
        repaired=result.get("repaired", 0),
    )
