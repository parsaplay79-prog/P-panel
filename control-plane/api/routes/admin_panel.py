"""Verdent Platform — web Admin Panel (HTML, Jinja2).

The panel the operator actually uses. Before this, every admin capability lived
behind the Telegram bot: reviewing a payment, answering a ticket, adding a node
or an admin all required a Telegram client, and the web control plane had no
authenticated surface at all. This module gives each of those actions a page.

Design rules, deliberately held to:

- **No admin logic is reimplemented here.** Every mutation calls the same
  `domain.*` function the bot calls, with the same arguments, so the two
  surfaces cannot drift into different behaviour. Where the bot does its work
  inline (the payment-review row lock, the node provisioning call), the code
  below mirrors it line for line rather than inventing a variant.
- **Every route declares exactly one RBAC permission** through
  `auth.require_permission`. The nav hides what a role cannot use, but hiding
  is not access control — each route re-checks, and
  `scripts/test_admin_panel.py` proves every route carries a real permission
  constant.
- **Every state change is audited** with the acting admin's row id, so an
  action taken in the browser is attributable in `audit_log` exactly as one
  taken in Telegram.

CSRF: there is no token. The session cookie is `SameSite=Lax` (see
`admin_panel/auth.py`), which stops a cross-site form POST from carrying it —
`Lax` sends the cookie on top-level GET navigations only. That is the whole
defence, and it is sufficient only because every mutating route is POST and no
route mutates on GET. Adding a GET that changes state would silently reopen the
hole, which is why the reject form is a GET that only *renders* and the write
is a separate POST.
"""

import logging
import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.templating import templates
from db.base import get_db
from db.models import (
    Admin,
    CloudflareAccount,
    Configuration,
    Customer,
    Node,
    Order,
    PaymentAttempt,
    Plan,
    Pool,
)
from domain import rbac
from domain import support as support_domain
from domain.audit import audit
from domain.fulfillment import FulfillmentError, fulfill_order
from domain.orders import (
    get_or_create_customer,
    mark_order_provisioning,
    reject_payment,
)
from domain.provisioning import ProvisioningError, provision_node
from domain.subscriptions import subscription_url
from domain.test_configs import TestConfigLimitError, create_test_config

logger = logging.getLogger("verdent.admin_panel")

router = APIRouter(prefix="/admin", tags=["admin-panel"])

NODE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")

# The tags a node created from the panel gets. Same three the bot uses, so a
# node provisioned from either surface lands in the same pools.
NODE_CAPABILITY_TAGS = ["general", "doh", "gaming"]


def _render(request: Request, template: str, *, status_code: int = 200, **context):
    return templates.TemplateResponse(
        request, template, context, status_code=status_code
    )


# ---------------------------------------------------------------------------
# login / logout
# ---------------------------------------------------------------------------


@router.get("/login")
async def login_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Login page — or the dashboard, if the visitor is already signed in.

    The cookie is VALIDATED here rather than merely checked for presence. A
    presence check would create a redirect loop the moment anyone arrived with
    a stale or revoked cookie: login sees a cookie and redirects to /admin,
    /admin rejects it and redirects back to login, forever. A bad cookie is
    cleared instead so the form is actually reachable.
    """
    token = request.cookies.get(auth.COOKIE_NAME)
    if token:
        claims = auth.read_session_token(token)
        if claims is not None:
            admin_id, token_version = claims
            admin = (
                await db.execute(select(Admin).where(Admin.id == admin_id))
            ).scalar_one_or_none()
            if (
                admin is not None
                and admin.token_version == token_version
                and admin.web_username
            ):
                return RedirectResponse("/admin", status_code=303)

    return _render(request, "login.html", title="ورود")


@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    username = username.strip()

    failures = await auth.login_failure_count(username)
    if failures >= auth.LOGIN_MAX_FAILURES:
        return _render(
            request,
            "login.html",
            title="ورود",
            error=(
                "تلاش‌های ناموفق بیش از حد مجاز. "
                f"{auth.LOGIN_FAILURE_WINDOW_SECONDS // 60} دقیقه دیگر دوباره امتحان کنید."
            ),
            username=username,
        )

    admin = (
        await db.execute(select(Admin).where(Admin.web_username == username))
    ).scalar_one_or_none()

    # Verify against a dummy hash when the username is unknown, so a failed
    # login costs the same time either way. Returning early here would let an
    # attacker enumerate valid usernames by response time alone.
    stored = admin.web_password_hash if admin is not None else auth.dummy_password_hash()
    if not auth.verify_password(password, stored) or admin is None:
        await auth.record_login_failure(username)
        return _render(
            request,
            "login.html",
            title="ورود",
            error="نام کاربری یا رمز عبور نادرست است.",
            username=username,
        )

    await auth.clear_login_failures(username)

    response = RedirectResponse("/admin", status_code=303)
    auth.set_session_cookie(response, admin)
    logger.info("admin %s signed in to the web panel", admin.id)
    return response


@router.post("/logout")
async def logout(request: Request, admin: Admin = Depends(auth.require_admin)):
    response = RedirectResponse("/admin/login", status_code=303)
    auth.clear_session_cookie(response)
    logger.info("admin %s signed out of the web panel", admin.id)
    return response


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------


@router.get("")
async def dashboard(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """The three counts the bot's stats screen shows, in one query batch."""
    n_configs = (
        await db.execute(
            select(func.count()).select_from(Configuration).where(Configuration.status == "ACTIVE")
        )
    ).scalar_one()
    n_pending = (
        await db.execute(
            select(func.count()).select_from(PaymentAttempt).where(PaymentAttempt.status == "WAITING_REVIEW")
        )
    ).scalar_one()
    n_nodes_online = (
        await db.execute(select(func.count()).select_from(Node).where(Node.state == "ONLINE"))
    ).scalar_one()
    n_nodes_total = (await db.execute(select(func.count()).select_from(Node))).scalar_one()
    n_tickets = len(await support_domain.open_tickets(db))
    n_customers = (await db.execute(select(func.count()).select_from(Customer))).scalar_one()

    return _render(
        request,
        "dashboard.html",
        title="وضعیت سیستم",
        n_configs=n_configs,
        n_pending=n_pending,
        n_nodes_online=n_nodes_online,
        n_nodes_total=n_nodes_total,
        n_tickets=n_tickets,
        n_customers=n_customers,
    )


# ---------------------------------------------------------------------------
# orders — payment review
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
            select(PaymentAttempt, Order, Plan)
            .join(Order, Order.id == PaymentAttempt.order_id)
            .join(Plan, Plan.id == Order.plan_id)
            .where(
                PaymentAttempt.status == "WAITING_REVIEW",
                Order.status == "PAID",
            )
            .order_by(PaymentAttempt.created_at.desc())
            .limit(50)
        )
    ).all()

    customers = {
        c.id: c for c in (await db.execute(select(Customer))).scalars().all()
    }

    items = []
    for attempt, order, plan in rows:
        customer = customers.get(order.customer_id)
        items.append(
            {
                "attempt": attempt,
                "order": order,
                "plan": plan,
                "customer": customer,
                "ref": order.id[:8],
            }
        )
    return items


@router.get("/orders")
async def orders_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    items = await _pending_orders(db)
    return _render(request, "orders.html", title="سفارش‌های در انتظار بررسی", items=items)


@router.post("/orders/{order_id}/approve")
async def order_approve(
    order_id: str,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    """Approve a payment: mark the order PROVISIONING, then fulfil it.

    The shape is the bot's `cb_review_approve` exactly, including the row lock.
    The lock is not optional: the status check below is check-then-act, so two
    admins reviewing the same receipt — or one double-submitting the form —
    both read WAITING_REVIEW, both pass, and the payment is fulfilled twice,
    producing two configurations and two KV credentials for one payment. FOR
    UPDATE serializes them; the second waits, re-reads, and sees APPROVED.

    Note the attempt is located by *order* here, not by attempt id: the form
    only carries the order id, and a locked read of the single open attempt for
    that order is the same row the bot locks.
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
        return RedirectResponse("/admin/orders?err=already", status_code=303)

    await mark_order_provisioning(db, order, attempt, admin.id)

    try:
        config = await fulfill_order(db, order, attempt, admin.id)
    except FulfillmentError as exc:
        logger.error("fulfillment failed for order %s: %s", order.id, exc)
        # The order stays PROVISIONING. Retrying through this button is NOT
        # offered, because `fulfill_order` is not idempotent: if the failure
        # happened after the configuration row was created (a KV sync failure,
        # say), a second approval would create a SECOND configuration and
        # assignment for one payment. The honest message is that the order is
        # stuck and needs attention, not a button that would double-provision.
        return RedirectResponse(f"/admin/orders?err=fulfillment&ref={order.id[:8]}", status_code=303)

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    if customer is not None:
        await _notify_customer(
            customer.telegram_user_id,
            _approved_message(config),
        )

    return RedirectResponse("/admin/orders?ok=approved", status_code=303)


@router.get("/orders/{order_id}/reject")
async def order_reject_form(
    order_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
):
    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return RedirectResponse("/admin/orders?err=notfound", status_code=303)

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
        return RedirectResponse("/admin/orders?err=already", status_code=303)

    return _render(
        request,
        "reject.html",
        title="رد پرداخت",
        order=order,
        attempt=attempt,
        ref=order.id[:8],
    )


@router.post("/orders/{order_id}/reject")
async def order_reject(
    order_id: str,
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_PAYMENT_REVIEW)),
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
        return RedirectResponse("/admin/orders?err=already", status_code=303)

    order = (
        await db.execute(select(Order).where(Order.id == order_id))
    ).scalar_one_or_none()
    if order is None:
        return RedirectResponse("/admin/orders?err=notfound", status_code=303)

    reason = reason.strip() or "—"

    customer = (
        await db.execute(select(Customer).where(Customer.id == order.customer_id))
    ).scalar_one_or_none()

    await reject_payment(db, attempt, admin.id, reason)

    if customer is not None:
        await _notify_customer(
            customer.telegram_user_id,
            _rejected_message(order, reason),
        )

    return RedirectResponse("/admin/orders?ok=rejected", status_code=303)


# ---------------------------------------------------------------------------
# support tickets
# ---------------------------------------------------------------------------


@router.get("/tickets")
async def tickets_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    tickets = await support_domain.open_tickets(db)
    customers = {c.id: c for c in (await db.execute(select(Customer))).scalars().all()}
    return _render(
        request,
        "tickets.html",
        title="تیکت‌های پشتیبانی",
        tickets=tickets,
        customers=customers,
        ticket_ref=support_domain.ticket_ref,
    )


@router.get("/tickets/{ref}")
async def ticket_detail(
    ref: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    ticket, customer, messages = await _load_thread(db, ref)
    if ticket is None:
        return RedirectResponse("/admin/tickets?err=notfound", status_code=303)
    return _render(
        request,
        "ticket.html",
        title=f"تیکت {ref}",
        ticket=ticket,
        customer=customer,
        messages=messages,
        ref=ref,
    )


async def _load_thread(db: AsyncSession, ref: str):
    """(ticket, customer, messages) for a short ref, or (None, None, []).

    Resolution — including the ambiguity rule — lives in
    `domain.support.ticket_by_ref`, shared with the bot. An 8-character prefix
    is short enough that a collision is possible, and resolving it to the wrong
    ticket would show one customer another customer's private messages.
    """
    ticket = await support_domain.ticket_by_ref(db, ref)
    if ticket is None:
        return None, None, []

    customer = (
        await db.execute(select(Customer).where(Customer.id == ticket.customer_id))
    ).scalar_one_or_none()

    from db.models import SupportMessage

    messages = (
        await db.execute(
            select(SupportMessage)
            .where(SupportMessage.ticket_id == ticket.id)
            .order_by(SupportMessage.created_at.asc())
        )
    ).scalars().all()
    return ticket, customer, messages


@router.post("/tickets/{ref}/reply")
async def ticket_reply(
    ref: str,
    body: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    body = body.strip()
    if not body:
        return RedirectResponse(f"/admin/tickets/{ref}?err=empty", status_code=303)

    ticket, customer, _messages = await _load_thread(db, ref)
    if ticket is None:
        return RedirectResponse("/admin/tickets?err=notfound", status_code=303)

    # author_telegram_id, not the admin row id: the column is defined as a
    # Telegram id on purpose (see the SupportMessage docstring), and an admin
    # replying here is the same person who replies from Telegram — recording a
    # uuid there would make the two paths write different-looking rows for the
    # same human.
    await support_domain.add_message(db, ticket, "admin", admin.telegram_user_id, body)

    await audit(
        db,
        "support.reply",
        actor_id=admin.id,
        target_type="support_ticket",
        target_id=ticket.id,
        details={"ref": ref},
    )

    if customer is not None:
        await _notify_customer(
            customer.telegram_user_id,
            _reply_message(ref, body),
        )

    return RedirectResponse(f"/admin/tickets/{ref}?ok=replied", status_code=303)


@router.post("/tickets/{ref}/close")
async def ticket_close(
    ref: str,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_SUPPORT_MANAGE)),
):
    ticket, _customer, _messages = await _load_thread(db, ref)
    if ticket is None:
        return RedirectResponse("/admin/tickets?err=notfound", status_code=303)

    await support_domain.close_ticket(db, ticket)
    await audit(
        db,
        "support.close",
        actor_id=admin.id,
        target_type="support_ticket",
        target_id=ticket.id,
        details={"ref": ref},
    )
    return RedirectResponse("/admin/tickets?ok=closed", status_code=303)


# ---------------------------------------------------------------------------
# nodes
# ---------------------------------------------------------------------------


@router.get("/nodes")
async def nodes_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    nodes = (await db.execute(select(Node).order_by(Node.created_at.desc()))).scalars().all()
    accounts = (await db.execute(select(CloudflareAccount))).scalars().all()
    return _render(
        request,
        "nodes.html",
        title="نودها",
        nodes=nodes,
        accounts=accounts,
    )


@router.get("/nodes/new")
async def node_new_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    accounts = (await db.execute(select(CloudflareAccount))).scalars().all()
    return _render(request, "node_new.html", title="ساخت نود جدید", accounts=accounts)


@router.post("/nodes/new")
async def node_create(
    request: Request,
    script_name: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Provision a node on Cloudflare. Synchronous, and slow — up to ~2 minutes.

    Same call the bot makes (`provision_node`), including the name validation
    and the duplicate check, because both surfaces create the same resource in
    the same Cloudflare account and a node name must be unique platform-wide.

    The Cloudflare API token is never entered here: it lives encrypted in
    Postgres (`cloudflare_accounts.api_token_encrypted`) and was added once
    out-of-band. The panel only chooses a name.
    """
    script_name = script_name.strip().lower()

    def _fail(message: str):
        return _render(
            request,
            "node_new.html",
            title="ساخت نود جدید",
            accounts=[],
            error=message,
            script_name=script_name,
            status_code=400,
        )

    if not NODE_NAME_RE.fullmatch(script_name):
        return _fail("نام نامعتبر است. فقط حروف کوچک انگلیسی، عدد و خط تیره (حداکثر ۳۱ کاراکتر).")

    account = (await db.execute(select(CloudflareAccount).limit(1))).scalar_one_or_none()
    if account is None:
        return _fail("ابتدا حساب Cloudflare را اضافه کنید (SETUP-GUIDE §6 مرحله ۱).")

    taken = (
        await db.execute(
            select(Node.id).where(Node.worker_script_name == script_name).limit(1)
        )
    ).scalar_one_or_none()
    if taken:
        return _fail("نودی با این نام از قبل ثبت شده است.")

    try:
        node = await provision_node(
            db,
            account.id,
            script_name,
            capability_tags=NODE_CAPABILITY_TAGS,
        )
    except ProvisioningError as exc:
        logger.error("node provisioning failed for %r: %s", script_name, exc)
        return _fail(f"خطا در ساخت نود: {exc}")

    await audit(
        db,
        "node.provisioned",
        actor_id=admin.id,
        target_type="node",
        target_id=node.id,
        details={"script": script_name, "url": node.custom_domain},
    )

    return _render(
        request,
        "node_new.html",
        title="ساخت نود جدید",
        accounts=(await db.execute(select(CloudflareAccount))).scalars().all(),
        created=node,
    )


# ---------------------------------------------------------------------------
# admins
# ---------------------------------------------------------------------------


@router.get("/admins")
async def admins_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    admins = (await db.execute(select(Admin).order_by(Admin.created_at.asc()))).scalars().all()
    return _render(request, "admins.html", title="ادمین‌ها", admins=admins)


@router.get("/admins/new")
async def admin_new_form(
    request: Request,
    admin: Admin = Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    return _render(request, "admin_new.html", title="افزودن ادمین")


@router.post("/admins/new")
async def admin_create(
    request: Request,
    telegram_user_id: str = Form(""),
    role: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_ADMIN_MANAGE)),
):
    """Create an admin by Telegram id, exactly as the bot does.

    A new admin gets NO web credentials — `web_username` stays NULL. That is
    deliberate: this form is reached from a Telegram id, and the panel has no
    business inventing a password for someone. The new admin's own web login is
    set separately, out-of-band, by `scripts/set_web_password.py`.
    """
    telegram_user_id = telegram_user_id.strip()

    def _fail(message: str):
        return _render(
            request,
            "admin_new.html",
            title="افزودن ادمین",
            error=message,
            telegram_user_id=telegram_user_id,
            role=role,
            status_code=400,
        )

    if not telegram_user_id.isdigit():
        return _fail("شناسه عددی نامعتبر است.")

    if role not in rbac.ALL_ROLES:
        return _fail("نقش انتخابی نامعتبر است.")

    exists = (
        await db.execute(
            select(Admin).where(Admin.telegram_user_id == int(telegram_user_id))
        )
    ).scalar_one_or_none()
    if exists is not None:
        return _fail("این کاربر قبلاً ادمین شده است.")

    new_admin = Admin(
        telegram_user_id=int(telegram_user_id),
        role=role,
        created_by=admin.id,
    )
    db.add(new_admin)
    await db.commit()

    # target_id is the new admin's UUID, not the Telegram id. audit_log.target_id
    # is a uuid column, and audit() swallows its own failures — passing the
    # digit string here would not error anywhere visible, it would simply never
    # write the row. (The bot's own call does exactly that; this is the correct
    # form of the same record.)
    await audit(
        db,
        "admin.create",
        actor_id=admin.id,
        target_type="admin",
        target_id=new_admin.id,
        details={"role": role, "telegram_user_id": int(telegram_user_id)},
    )

    return _render(
        request,
        "admin_new.html",
        title="افزودن ادمین",
        created=new_admin,
        note="برای فعال‌کردن ورود وب این ادمین، از scripts/set_web_password.py استفاده کنید.",
    )


# ---------------------------------------------------------------------------
# test configs
# ---------------------------------------------------------------------------


@router.get("/test")
async def test_form(
    request: Request,
    admin: Admin = Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    return _render(request, "test.html", title="ساخت کانفیگ تستی")


@router.post("/test")
async def test_create(
    request: Request,
    telegram_user_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin: Admin = Depends(auth.require_permission(rbac.PERM_TEST_CONFIG)),
):
    """Issue a test config to a customer, mirroring the bot's `_admin_create_test`.

    Three refusals have distinct causes and get distinct messages: a bad id, no
    node available, the lifetime cap, and an existing active test. Collapsing
    them into one "failed" would leave the admin unable to tell a customer why.
    """
    telegram_user_id = telegram_user_id.strip()

    def _fail(message: str):
        return _render(
            request,
            "test.html",
            title="ساخت کانفیگ تستی",
            error=message,
            telegram_user_id=telegram_user_id,
            status_code=400,
        )

    if not telegram_user_id.isdigit():
        return _fail("شناسه عددی نامعتبر است.")

    customer = await get_or_create_customer(
        db,
        telegram_user_id=int(telegram_user_id),
        username=None,
        display_name=None,
    )

    from domain.pools import select_node_for_pool

    pool = (await db.execute(select(Pool).limit(1))).scalar_one_or_none()
    node = await select_node_for_pool(db, pool) if pool else None
    if node is None:
        return _fail("نودی در دسترس نیست.")

    try:
        config = await create_test_config(
            db,
            customer_id=customer.id,
            display_name=f"test-{telegram_user_id}",
            # actor_id is the admin's row id — a uuid, which is what the
            # audit_log.actor_id column holds.
            actor_id=admin.id,
        )
    except TestConfigLimitError as exc:
        return _fail(f"سقف تست این مشتری پر شده ({exc.lifetime_count}/{exc.cap}).")
    except RuntimeError:
        return _fail("این مشتری یک تست فعال دارد.")

    return _render(
        request,
        "test.html",
        title="ساخت کانفیگ تستی",
        created=config,
        link=subscription_url(config),
        telegram_user_id=telegram_user_id,
    )


# ---------------------------------------------------------------------------
# customer notifications
# ---------------------------------------------------------------------------
#
# The panel sends these with `bot.webhook.send_message`, the same helper the bot
# uses, and reuses the same message templates from `bot/texts.py`. Two reasons:
# the customer must not be able to tell which surface the admin used, and a
# second copy of the copy would eventually disagree with the first.
#
# Delivery is best-effort: `send_message` never raises, and a Telegram outage
# must not roll back a payment decision the admin has already made. The audit
# row is the durable record of what was decided; the message is a courtesy.


async def _notify_customer(telegram_user_id: int, text: str) -> None:
    from bot.webhook import send_message

    try:
        await send_message(telegram_user_id, text)
    except Exception:  # noqa: BLE001 — send_message is documented never to raise
        logger.exception("customer notification failed for %s", telegram_user_id)


def _approved_message(config: Configuration) -> str:
    from bot import texts

    return texts.MSG_ORDER_APPROVED.format(
        display_name=config.display_name,
        link_block=texts.MSG_SUB_LINK.format(link=subscription_url(config)),
    )


def _rejected_message(order: Order, reason: str) -> str:
    from bot import texts

    return texts.MSG_ORDER_REJECTED.format(order_ref=order.id[:8], reason=reason)


def _reply_message(ref: str, body: str) -> str:
    from datetime import datetime, timezone

    from bot import texts

    return texts.MSG_SUPPORT_ADMIN_TICKET_ANSWER.format(
        ref=ref,
        status_fa=texts.SUPPORT_STATUS_FA.get(
            support_domain.STATUS_ANSWERED, support_domain.STATUS_ANSWERED
        ),
        transcript=texts.MSG_SUPPORT_ADMIN_TRANSCRIPT_ITEM.format(
            author="پشتیبانی",
            when=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
            body=body,
        ),
    )
