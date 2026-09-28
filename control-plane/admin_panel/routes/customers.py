"""Customer administration: search, detail, ban, unban (user.ban).

`user.ban` was declared in RBAC, granted to OWNER and ADMIN, and enforced by
nothing — there was no way to ban a customer at all. The detail page is the
panel's answer to "what is this customer's situation": every config, every
order, every ticket, in one view, because answering a support question used to
mean querying Postgres by hand.

The ban cascade lives in `domain.customers` — this module only routes to it.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import notify_customer, redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import (
    Configuration,
    Customer,
    Order,
    Plan,
    SubscriptionActivation,
)
from domain import configurations as config_domain
from domain import customers as customer_domain
from domain import rbac
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.customers")

router = APIRouter()

SORT_COLUMNS = {
    "last_seen": Customer.last_interaction_at,
    "first_seen": Customer.first_seen_at,
    "status": Customer.status,
}


@router.get("/customers")
async def customers_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_USER_BAN)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="last_seen",
        filter_keys=("status",),
    )

    customers, total = await customer_domain.search_customers(
        db,
        query=query.q,
        status=query.filters.get("status", ""),
        limit=query.page.per_page,
        offset=query.page.offset,
    )
    page = with_total(query.page, total)

    counts = await customer_domain.customer_config_counts(db, [c.id for c in customers])

    context = {
        "title": "مشتریان",
        "customers": customers,
        "counts": counts,
        "page": page,
        "query": query,
        "base_path": "/admin/customers",
        "CUSTOMER_STATUS_FA": customer_domain.CUSTOMER_STATUS_FA,
        "active_nav": "/admin/customers",
    }
    if is_htmx(request):
        return render(request, "customers/_rows.html", **context)
    return render(request, "customers/list.html", **context)


@router.get("/customers/{customer_id}")
async def customer_detail(
    customer_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_USER_BAN)),
):
    detail = await customer_domain.customer_detail(db, customer_id)
    if detail is None:
        return redirect("/admin/customers", err="notfound")

    plans = {
        p.id: p for p in (await db.execute(select(Plan))).scalars().all()
    }

    activations = dict(
        (
            await db.execute(
                select(SubscriptionActivation.order_id, SubscriptionActivation.configuration_id)
            )
        ).all()
    )

    return render(
        request,
        "customers/detail.html",
        title=f"مشتری {detail['customer'].telegram_user_id}",
        customer=detail["customer"],
        configurations=detail["configurations"],
        orders=detail["orders"],
        tickets=detail["tickets"],
        plans=plans,
        activations=activations,
        CUSTOMER_STATUS_FA=customer_domain.CUSTOMER_STATUS_FA,
        CONFIG_STATUS_FA=config_domain.CONFIG_STATUS_FA,
        active_nav="/admin/customers",
    )


@router.post("/customers/{customer_id}/ban")
async def customer_ban(
    customer_id: str,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_USER_BAN)),
):
    """Ban a customer and stop everything they are using.

    The result carries how many configs were suspended, so the admin learns
    whether the customer is actually offline. "Done" would hide a partial
    failure — a config that refused to suspend leaves the customer online while
    the panel says they are banned.
    """
    customer = (
        await db.execute(select(Customer).where(Customer.id == customer_id))
    ).scalar_one_or_none()
    if customer is None:
        return redirect("/admin/customers", err="notfound")

    result = await customer_domain.ban_customer(db, customer, actor_id=admin.id, reason=reason)

    return redirect(
        f"/admin/customers/{customer_id}",
        ok="banned",
        n=result["suspended"],
        of=result["attempted"],
    )


@router.post("/customers/{customer_id}/unban")
async def customer_unban(
    customer_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_USER_BAN)),
):
    """Lift a ban. Deliberately does not restore service — see domain.customers."""
    customer = (
        await db.execute(select(Customer).where(Customer.id == customer_id))
    ).scalar_one_or_none()
    if customer is None:
        return redirect("/admin/customers", err="notfound")

    await customer_domain.unban_customer(db, customer, actor_id=admin.id)
    return redirect(f"/admin/customers/{customer_id}", ok="unbanned")


@router.post("/customers/{customer_id}/notify")
async def customer_notify(
    customer_id: str,
    message: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_USER_BAN)),
):
    """Send an arbitrary Telegram message to a customer, and audit it.

    Support answers belong in tickets, where the exchange is threaded and
    searchable. This exists for the case a ticket cannot cover: telling a
    customer their payment needs a clearer receipt, or that a ban is being
    reviewed. Every send is audited with the actor, because an out-of-band
    message from an admin is something the OWNER should be able to see.
    """
    message = message.strip()
    if not message:
        return redirect(f"/admin/customers/{customer_id}", err="empty_message")

    customer = (
        await db.execute(select(Customer).where(Customer.id == customer_id))
    ).scalar_one_or_none()
    if customer is None:
        return redirect("/admin/customers", err="notfound")

    sent = await notify_customer(customer.telegram_user_id, message)

    await audit(
        db,
        "customer.notify",
        actor_id=admin.id,
        target_type="customer",
        target_id=customer.id,
        details={"delivered": sent, "length": len(message)},
    )
    # A failed send is reported as a failure, not as a neutral chip. Telegram
    # refusing the message (the customer blocked the bot, most often) is
    # something the admin has to act on — it means the customer is not reachable
    # through this channel at all.
    if sent:
        return redirect(f"/admin/customers/{customer_id}", ok="notified")
    return redirect(f"/admin/customers/{customer_id}", err="notify_failed")
