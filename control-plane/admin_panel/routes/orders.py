"""Order lifecycle: the review queue, order detail, approve, reject, retry, cancel.

The queue is the panel's most-used page and the one the bot did worst — it could
show fifty pending payments and nothing else. Here the queue is searchable,
paginated, and every row opens an order detail page showing the payment proofs,
the customer's history, and every attempt made on the order.

**The retry button is the substantive change.** The old panel refused to render
one, with a comment claiming `fulfill_order` was not idempotent. That was wrong
in a way worth spelling out, because believing it is what left orders stranded:
`create_configuration_for_order` IS idempotent (via the
`subscription_activations.order_id` UNIQUE index). The real hazard was that a
naive retry would re-run `select_node_for_pool` and could sync the credential to
a different node than the one the existing assignment lives on —
`domain/fulfillment.retry_fulfillment` now handles that by reusing the
assignment's node. An order stuck in PROVISIONING is therefore recoverable, both
by the button here and by the background job queue.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
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
    PaymentProof,
    Plan,
    SubscriptionActivation,
)
from domain import rbac
from domain.audit import audit
from domain.fulfillment import FulfillmentError, retry_fulfillment
from domain.jobs import (
    JOB_FULFILL_ORDER,
    enqueue,
    enqueue_key_for_order,
)
from domain.orders import (
    mark_order_provisioning,
    reject_payment,
)
from domain.subscriptions import subscription_url

logger = logging.getLogger("verdent.admin_panel.orders")

router = APIRouter()

ORDER_STATUS_FA = {
    "CREATED": "ایجاد شده",
    "AWAITING_PAYMENT": "در انتظار پرداخت",
    "PAID": "پرداخت شده",
    "PROVISIONING": "در حال فعال‌سازی",
    "FULFILLED": "تکمیل شده",
    "REJECTED": "رد شده",
    "CANCELLED": "لغو شده",
}

ORDER_STATUS_TAG = {
    "CREATED": "",
    "AWAITING_PAYMENT": "tag-warn",
    "PAID": "tag-warn",
    "PROVISIONING": "tag-warn",
    "FULFILLED": "tag-ok",
    "REJECTED": "tag-bad",
    "CANCELLED": "tag-bad",
}

SORT_COLUMNS = {
    "created": Order.created_at,
    "status": Order.status,
    "updated": Order.updated_at,
}

# ---------------------------------------------------------------------------
# The review queue
# ---------------------------------------------------------------------------


async def _pending_orders(db: AsyncSession) -> list[dict]:
    """Attempts awaiting review, joined to their order, plan and customer.

    Same predicate as the bot's `_show_pending_orders`: the attempt must be
    WAITING_REVIEW *and* the order PAID. Both conditions matter — an order that
    was rejected still has a REJECTED attempt, and a PAID order whose attempt
    was already approved must leave the queue.
    """
    rows = (
        await db.execute(
            select(PaymentAttempt, Order, Plan, Customer)
            .join(Order, Order.id == PaymentAttempt.order_id)
            .join(Plan, Plan.id == Order.plan_id)
            .join(Customer, Customer.id == Order.customer_id)
            .where(
                PaymentAttempt.status == "WAITING_REVIEW",
                Order.status == "PAID",
            )
            .order_by(PaymentAttempt.created_at.desc())
            .limit(200)
        )
    ).all()

    proof_counts = dict(
        (
            await db.execute(
                select(PaymentProof.payment_attempt_id, func.count(PaymentProof.id)).group_by(
                    PaymentProof.payment_attempt_id
                )
            )
        ).all()
    )

    items = []
    for attempt, order, plan, customer in rows:
        items.append(
            {
                "attempt": attempt,
                "order": order,
                "plan": plan,
                "customer": customer,
                "ref": order.id[:8],
                "proof_count": int(proof_counts.get(attempt.id, 0)),
            }
        )
    return items


@router.get("/orders")
async def orders_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """The pending-review queue.

    Only WAITING_REVIEW work lives here — the full order history is under
    `/admin/orders/all`, because mixing "needs a decision now" with "decided six
    weeks ago" is how a queue stops being a queue.
    """
    items = await _pending_orders(db)
    context = {
        "title": "سفارش‌های در انتظار بررسی",
        "items": items,
        "active_nav": "/admin/orders",
    }
    if is_htmx(request):
        return render(request, "orders/_queue_rows.html", **context)
    return render(request, "orders/queue.html", **context)


@router.get("/orders/all")
async def orders_all(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Every order, searchable by ref, customer id, status or plan name."""
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("status",),
    )

    stmt = (
        select(Order, Plan, Customer)
        .join(Plan, Plan.id == Order.plan_id)
        .join(Customer, Customer.id == Order.customer_id)
    )
    count_stmt = select(func.count()).select_from(Order)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        # Order ids are uuids, so a search for a ref is a prefix match. Casting
        # to text is what lets an operator paste "a1b2c3d4" from a ticket.
        conditions.append(
            or_(
                func.lower(func.cast(Order.id, Text)).like(pattern),
                func.lower(Plan.name).like(pattern),
                func.lower(func.cast(Customer.telegram_user_id, Text)).like(pattern),
                func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
            )
        )
    if query.filters.get("status"):
        conditions.append(Order.status == query.filters["status"])

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
        {"order": order, "plan": plan, "customer": customer, "ref": order.id[:8]}
        for order, plan, customer in rows
    ]

    context = {
        "title": "همه سفارش‌ها",
        "items": items,
        "page": page,
        "query": query,
        "base_path": "/admin/orders/all",
        "statuses": list(ORDER_STATUS_FA),
        "ORDER_STATUS_FA": ORDER_STATUS_FA,
        "ORDER_STATUS_TAG": ORDER_STATUS_TAG,
        "active_nav": "/admin/orders/all",
    }
    if is_htmx(request):
        return render(request, "orders/_all_rows.html", **context)
    return render(request, "orders/all.html", **context)


@router.get("/orders/{order_id}")
async def order_detail(
    order_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """One order: its plan, customer, every attempt, every proof, the config.

    The detail page is where the "stuck in PROVISIONING" case becomes
    actionable — it shows whether a configuration was already created (in which
    case a retry re-syncs the edge) or not (in which case a retry selects a
    node), and offers the retry that does the right thing either way.
    """
    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders/all", err="notfound")

    plan = (await db.execute(select(Plan).where(Plan.id == order.plan_id))).scalar_one_or_none()
    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    attempts = (
        await db.execute(
            select(PaymentAttempt)
            .where(PaymentAttempt.order_id == order.id)
            .order_by(PaymentAttempt.created_at.desc())
        )
    ).scalars().all()

    proofs: dict[str, list[PaymentProof]] = {}
    if attempts:
        rows = (
            await db.execute(
                select(PaymentProof)
                .where(PaymentProof.payment_attempt_id.in_([a.id for a in attempts]))
                .order_by(PaymentProof.uploaded_at.asc())
            )
        ).scalars().all()
        for proof in rows:
            proofs.setdefault(proof.payment_attempt_id, []).append(proof)

    activation = (
        await db.execute(
            select(SubscriptionActivation).where(SubscriptionActivation.order_id == order.id)
        )
    ).scalar_one_or_none()

    config = None
    config_url = None
    if activation is not None:
        config = (
            await db.execute(
                select(Configuration).where(Configuration.id == activation.configuration_id)
            )
        ).scalar_one_or_none()
        if config is not None:
            config_url = subscription_url(config)

    return render(
        request,
        "orders/detail.html",
        title=f"سفارش {order.id[:8]}",
        order=order,
        plan=plan,
        customer=customer,
        attempts=attempts,
        proofs=proofs,
        activation=activation,
        config=config,
        config_url=config_url,
        ORDER_STATUS_FA=ORDER_STATUS_FA,
        ORDER_STATUS_TAG=ORDER_STATUS_TAG,
        active_nav="/admin/orders/all",
    )


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@router.post("/orders/{order_id}/approve")
async def order_approve(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Approve a payment: mark the order PROVISIONING, then fulfil it.

    The shape is the bot's `cb_review_approve` exactly, including the row lock.
    The lock is not optional: the status check below is check-then-act, so two
    admins reviewing the same receipt — or one double-submitting the form —
    both read WAITING_REVIEW, both pass, and the payment is fulfilled twice,
    producing two configurations and two KV credentials for one payment. FOR
    UPDATE serializes them; the second waits, re-reads, and sees APPROVED.

    On a fulfilment failure the order stays PROVISIONING **and a job is
    enqueued** to finish the work. That is the difference from the old panel,
    which left the order for a human with no retry offered. The job's
    idempotency key is per-order, so an approve and a manual retry cannot
    produce two concurrent fulfilments of the same order.
    """
    attempt = (
        await db.execute(
            select(PaymentAttempt)
            .where(
                PaymentAttempt.order_id == order_id,
                PaymentAttempt.status == "WAITING_REVIEW",
            )
            .with_for_update()
            .limit(1)
        )
    ).scalar_one_or_none()

    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()

    if order is None or attempt is None or attempt.status != "WAITING_REVIEW":
        return redirect("/admin/orders", err="already")

    await mark_order_provisioning(db, order, attempt, admin.id)

    try:
        config = await retry_fulfillment(db, order, attempt, admin.id)
    except FulfillmentError as exc:
        logger.error("fulfillment failed for order %s: %s", order.id, exc)
        # Queue it. The admin gets an honest "it is stuck, we are retrying"
        # rather than a dead end, and the job retries with backoff.
        await enqueue(
            db,
            JOB_FULFILL_ORDER,
            {"order_id": order.id, "admin_id": admin.id},
            idempotency_key=enqueue_key_for_order(order.id),
            requested_by=admin.id,
        )
        return redirect(
            f"/admin/orders/{order.id}",
            err="fulfillment",
            detail=str(exc)[:200],
        )

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    if customer is not None:
        await notify_customer(customer.telegram_user_id, _approved_message(config))

    return redirect(f"/admin/orders/{order.id}", ok="approved")


@router.post("/orders/{order_id}/retry")
async def order_retry(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Finish a fulfilment that failed part-way. The button that did not exist.

    `retry_fulfillment` reuses the existing assignment's node when a
    configuration already exists, so this cannot write a credential to a node
    the customer was not assigned — the defect that made the old panel refuse to
    offer a retry at all.

    The row lock is taken on the order so two admins clicking retry
    simultaneously serialize; the second finds the order FULFILLED and returns
    without redoing the work.
    """
    order = (
        await db.execute(select(Order).where(Order.id == order_id).with_for_update())
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders/all", err="notfound")

    if order.status == "FULFILLED":
        return redirect(f"/admin/orders/{order.id}", ok="already_fulfilled")

    if order.status != "PROVISIONING":
        return redirect(f"/admin/orders/{order.id}", err="not_provisioning")

    attempt = (
        await db.execute(
            select(PaymentAttempt)
            .where(
                PaymentAttempt.order_id == order.id,
                PaymentAttempt.status == "APPROVED",
            )
            .order_by(PaymentAttempt.reviewed_at.desc().nullslast())
            .limit(1)
        )
    ).scalar_one_or_none()

    try:
        config = await retry_fulfillment(db, order, attempt, admin.id)
    except FulfillmentError as exc:
        logger.error("retry failed for order %s: %s", order.id, exc)
        return redirect(f"/admin/orders/{order.id}", err="fulfillment", detail=str(exc)[:200])

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()
    if customer is not None:
        await notify_customer(customer.telegram_user_id, _approved_message(config))

    await audit(
        db,
        "order.retry",
        actor_id=admin.id,
        target_type="order",
        target_id=order.id,
        details={"configuration_id": config.id},
    )
    return redirect(f"/admin/orders/{order.id}", ok="retried")


@router.post("/orders/{order_id}/queue-job")
async def order_queue_job(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Hand a stuck order to the background worker instead of blocking here.

    Same work as the retry button, but it returns immediately and the worker
    retries with backoff. Preferred when the failure was an infrastructure
    outage (Cloudflare down, no eligible node) rather than a one-off.
    """
    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders/all", err="notfound")

    job = await enqueue(
        db,
        JOB_FULFILL_ORDER,
        {"order_id": order.id, "admin_id": admin.id},
        idempotency_key=enqueue_key_for_order(order.id),
        requested_by=admin.id,
    )
    await audit(
        db,
        "order.queue_job",
        actor_id=admin.id,
        target_type="order",
        target_id=order.id,
        details={"job_id": job.id},
    )
    return redirect(f"/admin/jobs/{job.id}", ok="queued")


@router.post("/orders/{order_id}/cancel")
async def order_cancel(
    order_id: str,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Cancel an order that was never paid. Refuses once money is involved.

    A PAID or PROVISIONING order is not cancellable here: the customer has paid,
    and the correct action is a refund (`/admin/payments`), which leaves an
    audit trail. Silently cancelling a paid order would lose the record that the
    platform owes them something.
    """
    order = (
        await db.execute(select(Order).where(Order.id == order_id).with_for_update())
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders/all", err="notfound")

    if order.status not in ("CREATED", "AWAITING_PAYMENT"):
        return redirect(f"/admin/orders/{order.id}", err="not_cancellable")

    order.status = "CANCELLED"
    from datetime import datetime, timezone

    order.updated_at = datetime.now(timezone.utc)
    await db.commit()

    await audit(
        db,
        "order.cancel",
        actor_id=admin.id,
        target_type="order",
        target_id=order.id,
        details={"reason": reason},
    )
    return redirect(f"/admin/orders/{order.id}", ok="cancelled")


@router.get("/orders/{order_id}/reject")
async def order_reject_form(
    order_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders", err="notfound")

    attempt = (
        await db.execute(
            select(PaymentAttempt)
            .where(
                PaymentAttempt.order_id == order_id,
                PaymentAttempt.status == "WAITING_REVIEW",
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if attempt is None:
        return redirect("/admin/orders", err="already")

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    return render(
        request,
        "orders/reject.html",
        title="رد پرداخت",
        order=order,
        attempt=attempt,
        customer=customer,
        ref=order.id[:8],
    )


@router.post("/orders/{order_id}/reject")
async def order_reject(
    order_id: str,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Reject a payment. Mirrors the bot's `on_reject_reason`, lock included.

    The lock matters here for the same reason as on approve, and additionally
    because a reject racing an approve would otherwise leave the customer with
    both an approval and a rejection message for one receipt.
    """
    attempt = (
        await db.execute(
            select(PaymentAttempt)
            .where(
                PaymentAttempt.order_id == order_id,
                PaymentAttempt.status == "WAITING_REVIEW",
            )
            .with_for_update()
            .limit(1)
        )
    ).scalar_one_or_none()
    if attempt is None:
        return redirect("/admin/orders", err="already")

    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return redirect("/admin/orders", err="notfound")

    reason = reason.strip() or "—"

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    await reject_payment(db, attempt, admin.id, reason)

    if customer is not None:
        await notify_customer(customer.telegram_user_id, _rejected_message(order, reason))

    return redirect("/admin/orders", ok="rejected")


# ---------------------------------------------------------------------------
# Messages (reusing the bot's own templates — see admin_panel/helpers.py)
# ---------------------------------------------------------------------------


def _approved_message(config: Configuration) -> str:
    from bot import texts

    return texts.MSG_ORDER_APPROVED.format(
        display_name=config.display_name,
        link_block=texts.MSG_SUB_LINK.format(link=subscription_url(config)),
    )


def _rejected_message(order: Order, reason: str) -> str:
    from bot import texts

    return texts.MSG_ORDER_REJECTED.format(order_ref=order.id[:8], reason=reason)
