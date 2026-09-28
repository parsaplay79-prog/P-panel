"""Refunds — the `payment.refund` surface.

`payment.refund` was declared in RBAC and granted to OWNER, ADMIN and FINANCE,
and enforced by nothing: there was no way, anywhere in the product, to give a
customer their money back. A FINANCE admin's entire role was unreachable.

The rule this page exists to make visible: **a refund that leaves the VPN
running is not a refund.** Marking the attempt REFUNDED is bookkeeping; the
thing the platform actually owes the customer is that they stop receiving
service they are no longer paying for. So the refund route offers — and by
default performs — the config revocation in the same action, and reports
separately how many configurations it stopped. A refund that failed to revoke
is shown as exactly that rather than "done".

`orders.status` has no REFUNDED value (the CHECK constraint is
CREATED/AWAITING_PAYMENT/PAID/PROVISIONING/FULFILLED/REJECTED/CANCELLED), so a
refunded order stays FULFILLED. The payment attempt carries the refund and the
audit row carries the reasoning; inventing an order status the schema does not
allow would be a lie the constraint would reject anyway.
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
    Order,
    PaymentAttempt,
    Plan,
    SubscriptionActivation,
)
from domain import configurations as config_domain
from domain import rbac
from domain.audit import audit

logger = logging.getLogger("verdent.admin_panel.payments")

router = APIRouter()

PAYMENT_STATUS_FA = {
    "SUBMITTED": "ثبت شده",
    "WAITING_REVIEW": "در انتظار بررسی",
    "APPROVED": "تأیید شده",
    "REJECTED": "رد شده",
    "REFUNDED": "بازپرداخت شده",
}

PAYMENT_STATUS_TAG = {
    "SUBMITTED": "",
    "WAITING_REVIEW": "tag-warn",
    "APPROVED": "tag-ok",
    "REJECTED": "tag-bad",
    "REFUNDED": "tag-warn",
}

SORT_COLUMNS = {
    "created": PaymentAttempt.created_at,
    "reviewed": PaymentAttempt.reviewed_at,
    "status": PaymentAttempt.status,
}


@router.get("/payments")
async def payments_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_REFUND_MARK)),
):
    """Every payment attempt, searchable. Defaults to the refundable ones.

    Ordered by reviewed_at rather than created_at: the list is used to find a
    payment that was *approved* and now needs to go back, and the approval is
    the event being looked for.
    """
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="reviewed",
        filter_keys=("status",),
    )

    stmt = (
        select(PaymentAttempt, Order, Plan, Customer)
        .join(Order, Order.id == PaymentAttempt.order_id)
        .join(Plan, Plan.id == Order.plan_id)
        .join(Customer, Customer.id == Order.customer_id)
    )
    count_stmt = select(func.count()).select_from(PaymentAttempt)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(func.cast(PaymentAttempt.order_id, Text)).like(pattern),
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
                func.lower(func.coalesce(PaymentAttempt.external_reference, "")).like(pattern),
            )
        )
    status_filter = query.filters.get("status")
    if status_filter:
        conditions.append(PaymentAttempt.status == status_filter)
    else:
        # Default view: what can still be refunded. A REFUNDED attempt is
        # terminal, and burying the actionable rows under history is how a
        # finance queue stops being usable.
        conditions.append(PaymentAttempt.status.in_(["APPROVED", "REFUNDED"]))

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc().nullslast() if query.direction == "desc" else column.asc().nullsfirst()

    rows = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).all()

    items = [
        {"attempt": attempt, "order": order, "plan": plan, "customer": customer, "ref": order.id[:8]}
        for attempt, order, plan, customer in rows
    ]

    context = {
        "title": "پرداخت‌ها و بازپرداخت",
        "items": items,
        "page": page,
        "query": query,
        "base_path": "/admin/payments",
        "statuses": list(PAYMENT_STATUS_FA),
        "PAYMENT_STATUS_FA": PAYMENT_STATUS_FA,
        "PAYMENT_STATUS_TAG": PAYMENT_STATUS_TAG,
        "active_nav": "/admin/payments",
    }
    if is_htmx(request):
        return render(request, "payments/_rows.html", **context)
    return render(request, "payments/list.html", **context)


@router.get("/payments/{attempt_id}")
async def payment_detail(
    attempt_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_REFUND_MARK)),
):
    attempt = (
        await db.execute(select(PaymentAttempt).where(PaymentAttempt.id == attempt_id))
    ).scalar_one_or_none()
    if attempt is None:
        return redirect("/admin/payments", err="notfound")

    order = (
        await db.execute(select(Order).where(Order.id == attempt.order_id))
    ).scalar_one_or_none()
    plan = None
    customer = None
    config = None
    if order is not None:
        plan = (await db.execute(select(Plan).where(Plan.id == order.plan_id))).scalar_one_or_none()
        customer = (
            await db.execute(select(Customer).where(Customer.id == order.customer_id))
        ).scalar_one_or_none()
        activation = (
            await db.execute(
                select(SubscriptionActivation).where(SubscriptionActivation.order_id == order.id)
            )
        ).scalar_one_or_none()
        if activation is not None:
            config = (
                await db.execute(
                    select(Configuration).where(Configuration.id == activation.configuration_id)
                )
            ).scalar_one_or_none()

    return render(
        request,
        "payments/detail.html",
        title=f"پرداخت {attempt.id[:8]}",
        attempt=attempt,
        order=order,
        plan=plan,
        customer=customer,
        config=config,
        PAYMENT_STATUS_FA=PAYMENT_STATUS_FA,
        PAYMENT_STATUS_TAG=PAYMENT_STATUS_TAG,
        CONFIG_STATUS_FA=config_domain.CONFIG_STATUS_FA,
        active_nav="/admin/payments",
    )


@router.post("/payments/{attempt_id}/refund")
async def payment_refund(
    attempt_id: str,
    reason: str = Form(""),
    reference: str = Form(""),
    revoke: str = Form("1"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_REFUND_MARK)),
):
    """Mark a payment refunded, and stop the service it bought.

    Row-locked, and refuses anything that is not APPROVED: a refund is a
    financial correction to a settled payment, and letting it apply to an
    attempt still under review (or already rejected) would put the ledger out
    of step with what actually happened. The lock is the same protection the
    approve path takes — two FINANCE admins refunding the same receipt would
    otherwise both pass the status check and both send a refund.

    `revoke` defaults on. The revoke is best-effort and its outcome is
    reported, never assumed: `revoke_configuration` disables the edge
    credential, stamps the assignments and releases node capacity, and if any
    of that fails the operator needs to know the customer is still online
    rather than read "refunded" and move on.
    """
    attempt = (
        await db.execute(
            select(PaymentAttempt).where(PaymentAttempt.id == attempt_id).with_for_update()
        )
    ).scalar_one_or_none()
    if attempt is None:
        return redirect("/admin/payments", err="notfound")

    if attempt.status == "REFUNDED":
        return redirect(f"/admin/payments/{attempt_id}", ok="already_refunded")

    if attempt.status != "APPROVED":
        return redirect(f"/admin/payments/{attempt_id}", err="not_refundable")

    attempt.status = "REFUNDED"
    await db.commit()

    order = (
        await db.execute(select(Order).where(Order.id == attempt.order_id))
    ).scalar_one_or_none()

    customer = None
    config = None
    if order is not None:
        customer = (
            await db.execute(select(Customer).where(Customer.id == order.customer_id))
        ).scalar_one_or_none()
        activation = (
            await db.execute(
                select(SubscriptionActivation).where(SubscriptionActivation.order_id == order.id)
            )
        ).scalar_one_or_none()
        if activation is not None:
            config = (
                await db.execute(
                    select(Configuration).where(Configuration.id == activation.configuration_id)
                )
            ).scalar_one_or_none()

    revoked = False
    revoke_error = ""
    if revoke == "1" and config is not None and config.status != config_domain.STATUS_DELETED:
        try:
            await config_domain.revoke_configuration(db, config, actor_id=admin.id)
            revoked = True
        except Exception as exc:  # noqa: BLE001 — the refund stands either way
            logger.exception("could not revoke config %s while refunding", config.id)
            revoke_error = str(exc)[:120]

    await audit(
        db,
        "payment.refund",
        actor_id=admin.id,
        target_type="payment_attempt",
        target_id=attempt.id,
        details={
            "reason": reason,
            "reference": reference,
            "order_id": attempt.order_id,
            "configuration_id": config.id if config is not None else None,
            "revoked": revoked,
            "revoke_error": revoke_error,
        },
    )

    if customer is not None:
        await notify_customer(
            customer.telegram_user_id,
            _refund_message(reason, revoked),
        )

    return redirect(
        f"/admin/payments/{attempt_id}",
        ok="refunded" if (revoked or config is None) else "refunded_no_revoke",
        detail=revoke_error,
    )


def _refund_message(reason: str, revoked: bool) -> str:
    """The customer-facing refund notice.

    Written here rather than in `bot/texts.py` because there is no refund flow
    in the bot — a customer cannot ask for one, only an admin can grant one.
    A message constant that only one surface can ever send belongs with that
    surface; putting it in the bot's shared texts would imply a customer path
    that does not exist.
    """
    base = "💸 پرداخت شما بازپرداخت شد."
    if reason and reason != "—":
        base += f"\n\nدلیل: {reason}"
    if revoked:
        base += "\n\nاشتراک مربوط به این پرداخت غیرفعال شد."
    return base
