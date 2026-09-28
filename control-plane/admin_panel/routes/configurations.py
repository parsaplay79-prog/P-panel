"""Configuration management: search, detail, suspend, reactivate, revoke, rotate.

This is the surface `config.manage` never had. Before it, an admin facing an
abusive or leaked config had exactly one lever — ban the customer — which also
killed their support access and their order history.

The detail page is the operator's window into one customer's config: which node
it lives on, the credential, the usage for the current period, the subscription
link, and every action that can be taken on it. Each action's consequences are
labelled in the template, because "rotate credential" and "rotate subscription
link" sound alike and only one of them drops the customer's live connection.
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
from db.models import (
    Configuration,
    Customer,
    Node,
    Plan,
)
from domain import configurations as config_domain
from domain import rbac
from domain.audit import audit
from domain.subscriptions import (
    RenameError,
    active_assignments,
    render_vless_uri,
    subscription_url,
    usage_current_period_detail,
)

logger = logging.getLogger("verdent.admin_panel.configurations")

router = APIRouter()

SORT_COLUMNS = {
    "created": Configuration.created_at,
    "expires": Configuration.expires_at,
    "status": Configuration.status,
    "name": Configuration.display_name,
}


@router.get("/configurations")
async def configurations_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("status", "type"),
    )

    stmt = (
        select(Configuration, Customer)
        .join(Customer, Customer.id == Configuration.customer_id)
    )
    count_stmt = select(func.count()).select_from(Configuration)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Configuration.display_name).like(pattern),
                func.lower(Configuration.suffix).like(pattern),
                func.lower(func.cast(Configuration.id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
            )
        )
    if query.filters.get("status"):
        conditions.append(Configuration.status == query.filters["status"])
    if query.filters.get("type") == "test":
        conditions.append(Configuration.is_test.is_(True))
    elif query.filters.get("type") == "gaming":
        conditions.append(Configuration.config_type == "gaming")
    elif query.filters.get("type") == "normal":
        conditions.append(Configuration.config_type == "normal")

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

    context = {
        "title": "کانفیگ‌ها",
        "items": items,
        "page": page,
        "query": query,
        "base_path": "/admin/configurations",
        "CONFIG_STATUS_FA": config_domain.CONFIG_STATUS_FA,
        "active_nav": "/admin/configurations",
    }
    if is_htmx(request):
        return render(request, "configurations/_rows.html", **context)
    return render(request, "configurations/list.html", **context)


@router.get("/configurations/{config_id}")
async def configuration_detail(
    config_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """One config: node, credential, usage, link, and every action."""
    config = (
        await db.execute(select(Configuration).where(Configuration.id == config_id))
    ).scalar_one_or_none()
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    customer = (
        await db.execute(select(Customer).where(Customer.id == config.customer_id))
    ).scalar_one_or_none()

    plan = None
    if config.plan_id:
        plan = (
            await db.execute(select(Plan).where(Plan.id == config.plan_id))
        ).scalar_one_or_none()

    assignments = await active_assignments(db, config)
    used, up, down, quota = await usage_current_period_detail(db, config)

    uris = []
    for assignment, node in assignments:
        if node.custom_domain:
            uris.append(render_vless_uri(node.custom_domain, assignment.proxy_uuid, config.display_name))

    return render(
        request,
        "configurations/detail.html",
        title=f"کانفیگ {config.display_name}_{config.suffix}",
        config=config,
        customer=customer,
        plan=plan,
        assignments=assignments,
        used=used,
        bytes_up=up,
        bytes_down=down,
        quota=quota,
        percent=(round(used / quota * 100, 1) if quota else None),
        subscription_link=subscription_url(config),
        uris=uris,
        CONFIG_STATUS_FA=config_domain.CONFIG_STATUS_FA,
        active_nav="/admin/configurations",
    )


# ---------------------------------------------------------------------------
# Lifecycle actions
# ---------------------------------------------------------------------------


async def _load(db: AsyncSession, config_id: str) -> Configuration | None:
    return (
        await db.execute(select(Configuration).where(Configuration.id == config_id))
    ).scalar_one_or_none()


@router.post("/configurations/{config_id}/suspend")
async def configuration_suspend(
    config_id: str,
    notify: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Suspend: status SUSPENDED and the edge credential disabled, together.

    The KV flip is queued, not awaited — a Cloudflare round trip in the request
    path makes the button hang, and a failure must not roll back the status the
    admin has already been told about. See `domain/configurations`.
    """
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    try:
        await config_domain.suspend_configuration(db, config, actor_id=admin.id)
    except config_domain.ConfigurationError as exc:
        return redirect(f"/admin/configurations/{config_id}", err=exc.code)

    if notify and config.customer_id:
        customer = (
            await db.execute(select(Customer).where(Customer.id == config.customer_id))
        ).scalar_one_or_none()
        if customer is not None:
            await notify_customer(
                customer.telegram_user_id,
                f"⛔️ کانفیگ <b>{config.display_name}_{config.suffix}</b> موقتاً غیرفعال شد.",
            )

    return redirect(f"/admin/configurations/{config_id}", ok="suspended")


@router.post("/configurations/{config_id}/reactivate")
async def configuration_reactivate(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    try:
        await config_domain.reactivate_configuration(db, config, actor_id=admin.id)
    except config_domain.ConfigurationError as exc:
        return redirect(f"/admin/configurations/{config_id}", err=exc.code)

    return redirect(f"/admin/configurations/{config_id}", ok="reactivated")


@router.post("/configurations/{config_id}/revoke")
async def configuration_revoke(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Revoke for good: DELETED, edge disabled, assignments revoked.

    The irreversible one, so it is a POST behind an explicit confirm in the
    template rather than a button next to suspend.
    """
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    await config_domain.revoke_configuration(db, config, actor_id=admin.id)
    return redirect(f"/admin/configurations/{config_id}", ok="revoked")


@router.post("/configurations/{config_id}/rotate-link")
async def configuration_rotate_link(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Mint a new subscription link. The customer's live connection survives."""
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    await config_domain.rotate_subscription_token(db, config, actor_id=admin.id)
    return redirect(f"/admin/configurations/{config_id}", ok="link_rotated")


@router.post("/configurations/{config_id}/rotate-credential")
async def configuration_rotate_credential(
    config_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Mint a new proxy credential. DISRUPTIVE — drops the customer's session.

    Separate from rotating the link on purpose: this one changes the UUID the
    customer's client authenticates with, so their current connection dies and
    they must re-import. The panel labels it as disruptive and confirms first.
    """
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    try:
        await config_domain.rotate_proxy_credential(db, config, actor_id=admin.id)
    except config_domain.ConfigurationError as exc:
        return redirect(f"/admin/configurations/{config_id}", err=exc.code)

    return redirect(f"/admin/configurations/{config_id}", ok="credential_rotated")


@router.post("/configurations/{config_id}/rename")
async def configuration_rename(
    config_id: str,
    display_name: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Rename, delegating validation to `domain.subscriptions`.

    Distinct error codes for the two refusal reasons, because "the name is
    invalid" and "that name is taken" need different actions from the operator.
    """
    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    from domain.subscriptions import RENAME_INVALID_NAME, RENAME_NAME_TAKEN

    try:
        await config_domain.rename_configuration_by_admin(
            db, config, display_name, actor_id=admin.id
        )
    except RenameError as exc:
        code = {
            RENAME_INVALID_NAME: "name_invalid",
            RENAME_NAME_TAKEN: "name_taken",
        }.get(exc.reason, "rename_failed")
        return redirect(f"/admin/configurations/{config_id}", err=code)

    return redirect(f"/admin/configurations/{config_id}", ok="renamed")


@router.post("/configurations/{config_id}/extend")
async def configuration_extend(
    config_id: str,
    days: int = Form(0),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_CONFIG_MANAGE)),
):
    """Extend a config's expiry by N days, edge included.

    Renewal is not implemented as a customer flow (`domain/subscriptions`
    documents why), but an admin granting goodwill days is a different action:
    it does not reset usage, does not revive a config a human disabled, and is
    audited. It only moves `expires_at` forward.

    Refuses on DELETED. On EXPIRED it moves the config back to ACTIVE **and**
    re-enables the edge credential — an extension that left the proxy switched
    off would bill the customer for nothing, which is exactly the bug the
    renewal comment in `domain/subscriptions.py` records.
    """
    from datetime import timedelta

    from admin_panel.helpers import utcnow

    config = await _load(db, config_id)
    if config is None:
        return redirect("/admin/configurations", err="notfound")

    if days <= 0 or days > 3650:
        return redirect(f"/admin/configurations/{config_id}", err="bad_days")

    if config.status == config_domain.STATUS_DELETED:
        return redirect(f"/admin/configurations/{config_id}", err="is_deleted")

    was_expired = config.status in (config_domain.STATUS_EXPIRED, config_domain.STATUS_SUSPENDED)

    base = config.expires_at or utcnow()
    if base < utcnow():
        base = utcnow()
    config.expires_at = base + timedelta(days=days)

    if was_expired:
        await config_domain.reactivate_configuration(db, config, actor_id=admin.id)
    else:
        await db.commit()

    await audit(
        db,
        "config.extend",
        actor_id=admin.id,
        target_type="configuration",
        target_id=config.id,
        details={"days": days, "new_expiry": config.expires_at.isoformat(), "reactivated": was_expired},
    )
    return redirect(f"/admin/configurations/{config_id}", ok="extended")
