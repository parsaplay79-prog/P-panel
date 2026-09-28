"""Test configs — the `config.test` surface.

Issuing a test config is the one admin action that hands a stranger 100MB of
free relay, so the limits are the feature:

  * **2 per Telegram account, lifetime** (`TEST_MAX_LIFETIME`). Not "one
    active": a one-active rule is defeated by waiting 24 hours, and a free
    100MB on that cadence is a free CDN for anyone with a script.
  * **100MB / 24h** (`TEST_QUOTA_BYTES`, `TEST_DURATION`).
  * **Serialized per customer** by a Postgres advisory lock inside
    `create_test_config` — without it a double-tapped button runs the
    check-then-insert twice, both see zero, and the customer gets double the
    allowance.

The page shows the customer's remaining allowance *before* the button is
pressed, because "this customer has used 2 of 2" is the answer to most of the
requests this page receives, and finding it out by being refused wastes both
sides' time.

Node choice is explicit here, unlike the bot's version which took
`select(pool).limit(1)`. When the reason for the test is "does this node work
for you", the node is the variable under test — picking one at random makes the
answer meaningless.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import notify_customer, redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Configuration, Customer, Node, Pool, PoolNode
from domain import rbac
from domain.audit import audit
from domain.orders import get_or_create_customer
from domain.pools import ELIGIBLE_STATES, select_node_for_pool
from domain.subscriptions import subscription_url
from domain.test_configs import (
    TEST_DURATION,
    TEST_MAX_LIFETIME,
    TEST_QUOTA_BYTES,
    TestConfigLimitError,
    count_lifetime_test_configs,
    create_test_config,
    has_active_test_config,
)

logger = logging.getLogger("verdent.admin_panel.test_configs")

router = APIRouter()

SORT_COLUMNS = {
    "created": Configuration.created_at,
    "expires": Configuration.expires_at,
}


@router.get("/test")
async def test_form(
    request: Request,
    telegram_user_id: str = "",
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    """The issue form, plus the customer's allowance when an id is supplied.

    The allowance lookup is what makes this page useful before it is used: an
    operator pasting an id from a support message sees immediately whether the
    answer is "here is your test" or "you have had two already".
    """
    customer = None
    lifetime = 0
    active = False

    telegram_user_id = telegram_user_id.strip()
    if telegram_user_id.isdigit():
        customer = (
            await db.execute(
                select(Customer).where(Customer.telegram_user_id == int(telegram_user_id))
            )
        ).scalar_one_or_none()
        if customer is not None:
            lifetime = await count_lifetime_test_configs(db, customer.id)
            active = await has_active_test_config(db, customer.id)

    nodes = (
        await db.execute(
            select(Node).where(Node.state.in_(sorted(ELIGIBLE_STATES))).order_by(Node.worker_script_name)
        )
    ).scalars().all()

    return render(
        request,
        "test_configs/form.html",
        title="کانفیگ تستی",
        telegram_user_id=telegram_user_id,
        customer=customer,
        lifetime=lifetime,
        active=active,
        nodes=nodes,
        TEST_MAX_LIFETIME=TEST_MAX_LIFETIME,
        TEST_QUOTA_BYTES=TEST_QUOTA_BYTES,
        TEST_HOURS=int(TEST_DURATION.total_seconds() // 3600),
        active_nav="/admin/test",
    )


@router.get("/test/history")
async def test_history(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    """Every test config ever issued, with who used it and what it cost.

    The velocity view: a platform-wide abuse pattern (many accounts, one
    operator) is only visible as a list, and this is that list. Search by
    Telegram id or config name.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("status",),
    )

    stmt = (
        select(Configuration, Customer)
        .join(Customer, Customer.id == Configuration.customer_id)
        .where(Configuration.is_test.is_(True))
    )
    count_stmt = (
        select(func.count())
        .select_from(Configuration)
        .where(Configuration.is_test.is_(True))
    )

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
                func.lower(Configuration.display_name).like(pattern),
            )
        )
    if query.filters.get("status"):
        conditions.append(Configuration.status == query.filters["status"])

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
        {"config": config, "customer": customer, "ref": config.id[:8]}
        for config, customer in rows
    ]

    # The status dictionary is passed rather than restated: a table that renders
    # raw `ACTIVE`/`SUSPENDED` next to Persian everywhere else reads like a
    # different product, and a second copy of the mapping would drift.
    from domain import configurations as config_domain

    context = {
        "title": "تاریخچه‌ی کانفیگ‌های تستی",
        "items": items,
        "page": page,
        "query": query,
        "base_path": "/admin/test/history",
        "CONFIG_STATUS_FA": config_domain.CONFIG_STATUS_FA,
        "active_nav": "/admin/test",
    }
    if is_htmx(request):
        return render(request, "test_configs/_rows.html", **context)
    return render(request, "test_configs/history.html", **context)


@router.post("/test")
async def test_create(
    telegram_user_id: str = Form(""),
    node_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    """Issue a test config, with each refusal reported for what it is.

    Four distinct causes get four distinct codes — bad id, no node available,
    lifetime cap, already-active test. Collapsing them into one "failed" leaves
    the operator unable to tell the customer why, which is the entire
    conversation this page exists to have.
    """
    telegram_user_id = telegram_user_id.strip()

    def _fail(code: str, **extra):
        return redirect("/admin/test", err=code, tid=telegram_user_id, **extra)

    if not telegram_user_id.isdigit():
        return _fail("bad_id")

    customer = await get_or_create_customer(
        db,
        telegram_user_id=int(telegram_user_id),
        username=None,
        display_name=None,
    )

    node = None
    if node_id:
        node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
        if node is None:
            return _fail("bad_node")
    else:
        # No explicit node: fall back to the first pool that can serve one.
        # Same behaviour as the bot, kept for the case where the operator does
        # not care which node — but explicit choice is offered and preferred.
        pools = (await db.execute(select(Pool))).scalars().all()
        for pool in pools:
            node = await select_node_for_pool(db, pool)
            if node is not None:
                break

    if node is None:
        return _fail("no_node")

    try:
        config = await create_test_config(
            db,
            customer_id=customer.id,
            display_name=f"test-{telegram_user_id}",
            node=node,
            actor_id=admin.id,
        )
    except TestConfigLimitError as exc:
        return _fail("limit", n=exc.lifetime_count, cap=exc.cap)
    except RuntimeError:
        return _fail("already_active")

    link = subscription_url(config)

    # The customer is told, because a test config created from the panel and
    # never sent is a test config the customer never received — and the admin
    # has no other way to hand over a subscription link.
    await notify_customer(
        customer.telegram_user_id,
        "🧪 کانفیگ تستی شما آماده است.\n\n"
        f"{link}\n\n"
        f"حجم: ۱۰۰ مگابایت — مدت: ۲۴ ساعت",
    )

    await audit(
        db,
        "config.test_issued",
        actor_id=admin.id,
        target_type="configuration",
        target_id=config.id,
        details={"customer_id": customer.id, "node_id": node.id},
    )

    return redirect(f"/admin/configurations/{config.id}", ok="test_created")


@router.post("/test/revoke/{config_id}")
async def test_revoke(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    """Revoke a test config early — the abuse lever.

    Routed through `domain.configurations.revoke_configuration` like every other
    revoke, so the edge credential is disabled in the same action. A test config
    revoked in the database but still live at the edge keeps relaying traffic
    for free, which is exactly the abuse this button is pressed for.
    """
    from domain import configurations as config_domain

    config = (
        await db.execute(select(Configuration).where(Configuration.id == config_id))
    ).scalar_one_or_none()
    if config is None or not config.is_test:
        return redirect("/admin/test/history", err="notfound")

    await config_domain.revoke_configuration(db, config, actor_id=admin.id)
    return redirect("/admin/test/history", ok="revoked")
