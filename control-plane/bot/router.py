"""Verdent Platform — Telegram routers (customer + admin), Persian UX.

Customer flow (Document 4): start/menu → buy (plan → display name → payment
method → proof) → review → fulfilled (link delivered). Plus my-configs,
trial, support, help.

Admin flow: role-gated panel — payment review with inline approve/reject,
test config issuance, admin management, node status. Every action RBAC-
checked and audit-logged.
"""

import logging
from datetime import datetime, timezone

from aiogram import F, Router
from aiogram.filters import CommandObject, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    PreCheckoutQuery,
)
from aiogram.utils.keyboard import InlineKeyboardBuilder
from sqlalchemy import select

from bot import keyboards, states, texts
from bot.webhook import bot_enabled, dp as router_dp  # noqa: F401 (handlers register onto router_dp via decorators below)
from db.base import SessionLocal
from db.models import (
    Admin,
    Configuration,
    ConfigurationNodeAssignment,
    Customer,
    Node,
    Order,
    PaymentAttempt,
    Plan,
    SupportMessage,
    SupportTicket,
)
from domain import fulfillment, naming, rbac
from domain import support as support_domain
from domain.audit import audit
from domain.config import settings
from domain.orders import (
    attach_payment_proof,
    create_order,
    get_or_create_customer,
    get_order_attempts,
    mark_order_provisioning,
    reject_payment,
)
from domain.subscriptions import (
    RENAME_NAME_TAKEN,
    RenameError,
    rename_configuration as subscription_rename,
    subscription_url,
)

logger = logging.getLogger("verdent.bot")

router = Router()

MENU_BACK_KB = keyboards.back_to_main()


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


async def _customer_from_message(message: Message):
    async with SessionLocal() as db:
        return await get_or_create_customer(
            db,
            telegram_user_id=message.from_user.id,
            username=message.from_user.username,
            display_name=message.from_user.full_name,
        )


def _plan_is_stars(plan: Plan) -> bool:
    return plan.price_currency == "XTR"


# ---------------------------------------------------------------------------
# customer: start / menu
# ---------------------------------------------------------------------------


@router.message(CommandStart())
async def cmd_start(message: Message, state: FSMContext, command: CommandObject | None = None):
    await state.clear()
    customer = await _customer_from_message(message)
    await message.answer(
        texts.MSG_WELCOME.format(
            name=message.from_user.first_name or "",
            app=texts.APP_NAME,
        ),
        reply_markup=keyboards.main_menu(),
    )


@router.callback_query(F.data == "menu:main")
async def cb_main(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.message.edit_reply_markup(reply_markup=keyboards.main_menu())
    await call.answer()


@router.callback_query(F.data == "menu:help")
async def cb_help(call: CallbackQuery, state: FSMContext):
    await state.clear()
    await call.message.answer(texts.MSG_HELP, reply_markup=MENU_BACK_KB)
    await call.answer()


@router.callback_query(F.data == "menu:support")
async def cb_support(call: CallbackQuery, state: FSMContext):
    """Support menu: existing tickets, or start a new one.

    This used to print static text and stop. Anything the customer typed next
    was silently discarded, so the flow looked complete and was not.
    """
    await state.clear()
    async with SessionLocal() as db:
        customer = await get_or_create_customer(
            db,
            telegram_user_id=call.from_user.id,
            username=call.from_user.username,
            display_name=call.from_user.full_name,
        )
        tickets = await support_domain.customer_tickets(db, customer.id)

    if tickets:
        await call.message.answer(
            texts.MSG_SUPPORT, reply_markup=keyboards.customer_tickets(tickets)
        )
    else:
        await call.message.answer(
            texts.MSG_SUPPORT, reply_markup=MENU_BACK_KB
        )

    await state.set_state(states.Support.waiting_user_message)
    await call.answer()

@router.callback_query(F.data.startswith("sup:open:"))
async def cb_support_open_ticket(call: CallbackQuery, state: FSMContext):
    """Refill the box on an existing ticket — a follow-up goes to the same
    thread rather than silently starting a second, disconnected one."""
    ref = call.data.split(":")[2]
    await state.set_state(states.Support.waiting_user_message)
    await state.update_data(ticket_ref=ref)
    await call.answer()

@router.message(states.Support.waiting_user_message)
async def on_support_message(message: Message, state: FSMContext):
    text = (message.text or "").strip()
    if text.startswith("/cancel"):
        await state.clear()
        await message.answer(texts.MSG_SUPPORT_CANCELLED)
        return
    if not text:
        await message.answer(texts.MSG_SUPPORT_ASK)
        return

    data = await state.get_data()
    target_ref = data.get("ticket_ref")
    # Any message typed in this state means "I've finished reading the list" —
    # the ref must not survive into the next message, or a later unrelated
    # message would be appended to whatever ticket the button referred to.
    await state.clear()

    async with SessionLocal() as db:
        customer = await get_or_create_customer(
            db,
            telegram_user_id=message.from_user.id,
            username=message.from_user.username,
            display_name=message.from_user.full_name,
        )
        # Scoped to THIS customer's tickets, so a ref can only ever resolve to
        # a thread they own.
        tickets = await support_domain.customer_tickets(db, customer.id)
        ticket = _match_ticket(tickets, target_ref) or _open_ticket(tickets)

        reopened = False
        if ticket is None:
            ticket = await support_domain.create_ticket(
                db, customer.id, message.from_user.id, text
            )
        else:
            reopened = ticket.status == support_domain.STATUS_CLOSED
            ticket = await support_domain.add_message(
                db, ticket, "customer", message.from_user.id, text
            )

        ref = support_domain.ticket_ref(ticket.id)
        customer_name = message.from_user.full_name
        tg_id = message.from_user.id

    if reopened:
        await message.answer(
            texts.MSG_SUPPORT_TICKET_CLOSED_NOTICE.format(ref=ref)
        )
    await message.answer(
        texts.MSG_SUPPORT_TICKET_OPENED.format(ref=ref)
    )
    # After the confirmation, and never inline: Telegram renders whatever the
    # handler manages to send, and a failed admin notification must not cost
    # the customer their ticket id. This also guarantees the reply lands
    # before the admin ping even when the ping throws.
    await _notify_admins_new_ticket(ref, customer_name, tg_id, text)


def _open_ticket(tickets: list):
    """The ticket a new message should continue, or None to start fresh.

    Only `open` counts. Continuing a ticket the admin already answered would
    bury the answer under a new question with no signal that it is unanswered.
    """
    for t in tickets:
        if t.status == support_domain.STATUS_OPEN:
            return t
    return None


async def _notify_admins_new_ticket(
    ref: str, customer: str, tg_id: int, body: str
) -> None:
    """Tell admins a ticket exists.

    Without this the ticket is a row nobody looks at — the same as the old
    static text, just with better bookkeeping.
    """
    from bot.webhook import send_message

    async with SessionLocal() as db:
        admins = (await db.execute(select(Admin))).scalars().all()
        targets = [
            a.telegram_user_id
            for a in admins
            if rbac.PERM_SUPPORT_MANAGE in rbac.permissions_for(a.role)
        ]

    for admin_id in targets:
        try:
            await send_message(
                admin_id,
                texts.MSG_SUPPORT_ADMIN_NEW.format(
                    customer=customer or "—",
                    tg_id=tg_id,
                    ref=ref,
                    body=body,
                ),
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to notify admin %s of ticket %s", admin_id, ref)


# ---------------------------------------------------------------------------
# customer: buy flow
# ---------------------------------------------------------------------------


@router.callback_query(F.data == "menu:buy")
async def cb_buy(call: CallbackQuery, state: FSMContext):
    await state.clear()
    async with SessionLocal() as db:
        plans = (
            await db.execute(
                select(Plan)
                .where(Plan.is_active.is_(True))
                .order_by(Plan.price_amount.asc())
            )
        ).scalars().all()

    if not bot_enabled() and not plans:
        await call.message.answer("پلنی موجود نیست.", reply_markup=MENU_BACK_KB)
        return

    visible = [p for p in plans if not _plan_is_stars(p) or settings.stars_enabled]
    await call.message.answer(
        "🛒 <b>انتخاب پلن</b>", reply_markup=keyboards.plans_menu(visible)
    )
    await call.answer()


@router.callback_query(F.data.startswith("plan:"))
async def cb_plan(call: CallbackQuery, state: FSMContext, ):
    plan_id = call.data.split(":")[1]
    async with SessionLocal() as db:
        plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()

    if plan is None:
        await call.answer("پلن یافت نشد", show_alert=True)
        return

    await call.message.answer(
        texts.MSG_PLAN_DETAILS.format(
            name=plan.name,
            description=plan.description or "",
            price=texts.format_price(plan.price_amount, plan.price_currency),
            duration=texts.format_duration(plan.duration_days),
            traffic=texts.format_traffic(plan.traffic_quota_bytes),
            devices=plan.device_limit,
        ),
        reply_markup=keyboards.payment_methods(
            plan.id, stars_available=_plan_is_stars(plan) and settings.stars_enabled
        ),
    )
    await call.answer()


@router.callback_query(F.data.startswith("pay:card:"))
async def cb_pay_card(call: CallbackQuery, state: FSMContext):
    _, _, plan_id = call.data.split(":")
    async with SessionLocal() as db:
        plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
        if plan is None:
            await call.answer("پلن یافت نشد", show_alert=True)
            return
        customer = await get_or_create_customer(
            db,
            telegram_user_id=call.from_user.id,
            username=call.from_user.username,
            display_name=call.from_user.full_name,
        )

    await state.update_data(plan_id=plan.id)
    await state.set_state(states.Purchase.waiting_display_name)
    await call.message.answer(texts.MSG_ENTER_DISPLAY_NAME)
    await call.answer()


@router.message(states.Purchase.waiting_display_name)
async def on_display_name(message: Message, state: FSMContext):
    name = (message.text or "").strip()
    if not naming.validate_display_name(name):
        await message.answer(texts.MSG_NAME_INVALID)
        return

    data = await state.get_data()
    plan_id = data["plan_id"]

    async with SessionLocal() as db:
        plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
        if plan is None:
            await message.answer("پلن یافت نشد — دوباره تلاش کنید.", reply_markup=MENU_BACK_KB)
            await state.clear()
            return

        customer = await get_or_create_customer(
            db,
            telegram_user_id=message.from_user.id,
            username=message.from_user.username,
            display_name=message.from_user.full_name,
        )

        order = await create_order(
            db,
            customer,
            plan,
            requested_display_name=name,
            idempotency_suffix=str(int(datetime.now(timezone.utc).timestamp() // 60)),
        )

    await state.update_data(order_id=order.id, plan_id=plan.id, display_name=name)
    await state.set_state(states.Purchase.waiting_payment_proof)

    await message.answer(
        texts.MSG_PAYMENT_INSTRUCTIONS.format(
            amount=texts.format_price(plan.price_amount, plan.price_currency),
            card=settings.payment_card_number or "<تنظیم نشده — ادمین را خبر کنید>",
            holder=settings.payment_card_holder or "—",
            instructions=settings.payment_instructions,
            order_ref=order.id[:8],
        ),
        reply_markup=keyboards.back_to_main(),
    )


@router.message(states.Purchase.waiting_payment_proof, F.photo)
async def on_payment_proof(message: Message, state: FSMContext):
    data = await state.get_data()
    order_id = data.get("order_id")
    if not order_id:
        await state.clear()
        return

    photo = message.photo[-1]

    async with SessionLocal() as db:
        order = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
        if order is None:
            await message.answer("سفارش یافت نشد.")
            await state.clear()
            return

        attempt = await attach_payment_proof(
            db,
            order,
            telegram_file_id=photo.file_id,
            mime_type=None,
            size_bytes=photo.file_size,
        )

        await _notify_admins_new_order(db, order, attempt, message)

    await state.clear()
    await message.answer(texts.MSG_PROOF_RECEIVED.format(order_ref=order_id[:8]))


@router.message(states.Purchase.waiting_payment_proof)
async def on_payment_proof_not_photo(message: Message, state: FSMContext):
    await message.answer("لطفاً <b>عکس</b> رسید واریز را بفرستید.")


@router.callback_query(F.data.startswith("pay:stars:"))
async def cb_pay_stars(call: CallbackQuery, state: FSMContext):
    """Stars invoice (Phase 5): XTR needs no provider token; the plan's
    price_amount IS the star count when price_currency == 'XTR'."""
    if not settings.stars_enabled:
        await call.answer("پرداخت با استارز فعلاً غیرفعال است.", show_alert=True)
        return

    _, _, plan_id = call.data.split(":")
    async with SessionLocal() as db:
        plan = (await db.execute(select(Plan).where(Plan.id == plan_id))).scalar_one_or_none()
        if plan is None or plan.price_currency != "XTR":
            await call.answer("این پلن با استارز قابل خرید نیست.", show_alert=True)
            return

        customer = await get_or_create_customer(
            db,
            telegram_user_id=call.from_user.id,
            username=call.from_user.username,
            display_name=call.from_user.full_name,
        )

        order = await create_order(
            db,
            customer,
            plan,
            requested_display_name=f"stars-{call.from_user.id}",
            idempotency_suffix=str(int(datetime.now(timezone.utc).timestamp() // 60)),
        )

    from bot.webhook import bot as current_bot

    if current_bot is None:
        await call.answer("پرداخت در دسترس نیست.", show_alert=True)
        return

    await current_bot.send_invoice(
        chat_id=call.from_user.id,
        title=plan.name,
        description=(plan.description or plan.name)[:255],
        payload=f"stars:{order.id}",
        currency="XTR",
        prices=[{"label": plan.name, "amount": int(plan.price_amount)}],
    )
    await call.answer()


# ---------------------------------------------------------------------------
# customer: my configs / link / trial
# ---------------------------------------------------------------------------


@router.callback_query(F.data == "menu:configs")
async def cb_my_configs(call: CallbackQuery, state: FSMContext):
    await state.clear()
    async with SessionLocal() as db:
        customer = await get_or_create_customer(
            db,
            telegram_user_id=call.from_user.id,
            username=call.from_user.username,
            display_name=call.from_user.full_name,
        )

        configs = (
            await db.execute(
                select(Configuration)
                .where(
                    Configuration.customer_id == customer.id,
                    Configuration.status != "DELETED",
                )
                .order_by(Configuration.created_at.desc())
            )
        ).scalars().all()

        if not configs:
            await call.message.answer(texts.MSG_NO_CONFIGS, reply_markup=MENU_BACK_KB)
            await call.answer()
            return

        from domain.subscriptions import usage_current_period

        chunks = [texts.MSG_MY_CONFIGS_HEADER]
        for config in configs:
            used, quota = await usage_current_period(db, config)
            link = subscription_url(config)
            chunks.append(
                texts.MSG_CONFIG_ITEM.format(
                    display_name=config.display_name,
                    status_fa=texts.STATUS_FA.get(config.status, config.status),
                    used=texts.format_traffic(used),
                    quota=texts.format_traffic(quota),
                    expires=config.expires_at.strftime("%Y-%m-%d") if config.expires_at else "—",
                    link=link,
                )
            )

        await call.message.answer(
            "\n".join(chunks),
            reply_markup=keyboards.my_configs(configs),
            disable_web_page_preview=True,
        )
    await call.answer()


@router.callback_query(F.data == "menu:trial")
async def cb_trial(call: CallbackQuery, state: FSMContext):
    await state.clear()
    from domain import test_configs
    from domain.pools import select_node_for_pool

    async with SessionLocal() as db:
        customer = await get_or_create_customer(
            db,
            telegram_user_id=call.from_user.id,
            username=call.from_user.username,
            display_name=call.from_user.full_name,
        )

        if await test_configs.has_active_test_config(db, customer.id):
            await call.message.answer(texts.MSG_TRIAL_EXISTS)
            await call.answer()
            return

        # Lifetime cap is checked before node selection so a customer who has
        # used both tests isn't told "no capacity" when capacity is fine.
        lifetime = await test_configs.count_lifetime_test_configs(db, customer.id)
        if lifetime >= test_configs.TEST_MAX_LIFETIME:
            await call.message.answer(
                texts.MSG_TRIAL_LIMIT.format(
                    used=lifetime, cap=test_configs.TEST_MAX_LIFETIME
                ),
                reply_markup=MENU_BACK_KB,
            )
            await call.answer()
            return

        pool = (
            await db.execute(
                select(__import__("db.models", fromlist=["Pool"]).Pool).limit(1)
            )
        ).scalar_one_or_none()
        node = await select_node_for_pool(db, pool) if pool else None

        if node is None:
            await call.message.answer(
                "فعلاً ظرفیت تست در دسترس نیست — بعداً دوباره تلاش کنید.",
                reply_markup=MENU_BACK_KB,
            )
            await call.answer()
            return

        try:
            config = await test_configs.create_test_config(
                db,
                customer_id=customer.id,
                display_name=f"test-{call.from_user.username or call.from_user.id}",
                node=node,
            )
        except test_configs.TestConfigLimitError as exc:
            # A concurrent double-tap can still win the race between the check
            # above and this insert; report the cap rather than a raw error.
            await call.message.answer(
                texts.MSG_TRIAL_LIMIT.format(used=exc.lifetime_count, cap=exc.cap),
                reply_markup=MENU_BACK_KB,
            )
            await call.answer()
            return
        except RuntimeError:
            await call.message.answer(texts.MSG_TRIAL_EXISTS, reply_markup=MENU_BACK_KB)
            await call.answer()
            return

        await call.message.answer(
            texts.MSG_TRIAL_OK.format(
                display_name=config.display_name,
                quota=texts.format_traffic(config.test_quota_bytes),
                link_block=texts.MSG_SUB_LINK.format(link=subscription_url(config)),
            ),
            disable_web_page_preview=True,
        )
    await call.answer()


async def _own_config(db, telegram_user_id: int, config_id: str) -> Configuration | None:
    """The config only if it belongs to this Telegram user, else None.

    Every cfg:* handler must go through this. The callback data carries the
    config id, and callback data is client-supplied: without an ownership
    check, any customer who learns or guesses another's id can read their
    subscription link — which is the whole credential. Returning None for a
    foreign id (rather than a distinct error) also avoids confirming that the
    id exists.
    """
    if not config_id:
        return None
    customer = await get_or_create_customer(
        db,
        telegram_user_id=telegram_user_id,
        username=None,
        display_name=None,
    )
    return (
        await db.execute(
            select(Configuration).where(
                Configuration.id == config_id,
                Configuration.customer_id == customer.id,
                Configuration.status != "DELETED",
            )
        )
    ).scalar_one_or_none()


@router.callback_query(F.data.startswith("cfg:view:"))
async def cb_config_view(call: CallbackQuery, state: FSMContext):
    config_id = call.data.split(":")[2]
    await state.clear()
    async with SessionLocal() as db:
        config = await _own_config(db, call.from_user.id, config_id)
        if config is None:
            await call.answer("یافت نشد", show_alert=True)
            return
        from domain.subscriptions import usage_current_period

        used, quota = await usage_current_period(db, config)
        body = texts.MSG_CONFIG_ACTIONS.format(
            display_name=f"{config.display_name}_{config.suffix}",
            status_fa=texts.STATUS_FA.get(config.status, config.status),
            used=texts.format_traffic(used),
            quota=texts.format_traffic(quota),
            expires=config.expires_at.strftime("%Y-%m-%d") if config.expires_at else "—",
        )

    await call.message.answer(
        body, reply_markup=keyboards.config_actions(config_id)
    )
    await call.answer()


@router.callback_query(F.data.startswith("cfg:link:"))
async def cb_config_link(call: CallbackQuery, state: FSMContext):
    config_id = call.data.split(":")[2]
    async with SessionLocal() as db:
        # Was an unscoped id lookup: the handler returned any config's
        # subscription link to whoever asked.
        config = await _own_config(db, call.from_user.id, config_id)
    if config is None:
        await call.answer("یافت نشد", show_alert=True)
        return
    await call.message.answer(texts.MSG_SUB_LINK.format(link=subscription_url(config)))
    await call.answer()


@router.callback_query(F.data.startswith("cfg:rename:"))
async def cb_config_rename(call: CallbackQuery, state: FSMContext):
    config_id = call.data.split(":")[2]
    async with SessionLocal() as db:
        config = await _own_config(db, call.from_user.id, config_id)
        if config is None:
            await call.answer("یافت نشد", show_alert=True)
            return
        old_name, suffix = config.display_name, config.suffix

    await state.set_state(states.ConfigEdit.waiting_new_name)
    await state.update_data(config_id=config_id)
    await call.message.answer(
        texts.MSG_RENAME_ASK.format(old_name=old_name, suffix=suffix)
    )
    await call.answer()


@router.message(states.ConfigEdit.waiting_new_name)
async def on_config_rename(message: Message, state: FSMContext):
    text = (message.text or "").strip()
    if text.startswith("/cancel"):
        await state.clear()
        await message.answer(texts.MSG_RENAME_CANCELLED)
        return

    data = await state.get_data()
    config_id = data.get("config_id")
    # One rename per prompt: the id must not survive into the customer's next
    # unrelated message, or that message would be applied as a rename.
    await state.clear()

    async with SessionLocal() as db:
        # Re-checked here, not just at the button: ownership must hold at the
        # moment of the write, not only when the prompt was shown.
        config = await _own_config(db, message.from_user.id, config_id)
        if config is None:
            # Not MSG_NO_CONFIGS: that says "you have no subscriptions",
            # which is wrong and alarming when the customer has others and
            # merely renamed a config that has since been deleted.
            await message.answer(texts.MSG_CONFIG_NOT_FOUND)
            return

        try:
            config = await subscription_rename(db, config, text)
        except RenameError as exc:
            # Stay in the state so the customer can just retype, rather than
            # making them find the button again for a typo.
            await state.set_state(states.ConfigEdit.waiting_new_name)
            await state.update_data(config_id=config_id)
            if exc.reason == RENAME_NAME_TAKEN:
                await message.answer(texts.MSG_RENAME_FAILED_TAKEN)
            else:
                await message.answer(texts.MSG_RENAME_FAILED_INVALID)
            return

        new_name, suffix = config.display_name, config.suffix
        customer_id = config.customer_id

    # Audited with actor_type="customer": the constraint was widened in
    # migration 004 precisely so this record can exist. audit() swallows its
    # own failures, so if 004 has not been applied this row silently does not
    # appear rather than breaking the rename.
    async with SessionLocal() as db:
        await audit(
            db,
            "config.rename",
            actor_type="customer",
            actor_id=customer_id,
            target_type="configuration",
            target_id=config_id,
            details={"display_name": new_name, "suffix": suffix},
        )

    await message.answer(
        texts.MSG_RENAME_DONE.format(display_name=f"{new_name}_{suffix}", suffix=suffix)
    )


# ---------------------------------------------------------------------------
# admin: panel + payment review
# ---------------------------------------------------------------------------


async def _get_admin_role(telegram_user_id: int) -> str | None:
    async with SessionLocal() as db:
        admins = (await db.execute(select(Admin))).scalars().all()
        return rbac.admin_role_for_telegram_id(telegram_user_id, admins)


def _is_admin_role(role: str | None) -> bool:
    return role is not None


@router.message(F.text.startswith(texts.ADMIN_PREFIX))
async def admin_panel_entry(message: Message, state: FSMContext):
    role = await _get_admin_role(message.from_user.id)
    if not _is_admin_role(role):
        return  # silent for non-admins
    await state.clear()
    await message.answer(
        texts.MSG_ADMIN_PANEL.format(role=role),
        reply_markup=keyboards.admin_panel(rbac.permissions_for(role)),
    )


@router.callback_query(F.data.startswith("adm:"))
async def cb_admin_panel(call: CallbackQuery, state: FSMContext):
    role = await _get_admin_role(call.from_user.id)
    perms = rbac.permissions_for(role) if role else set()

    action = call.data.split(":")[1]

    if action == "pending" and rbac.PERM_PAYMENT_REVIEW in perms:
        await _show_pending_orders(call)
    elif action == "stats" and rbac.PERM_STATS_VIEW in perms:
        await _show_stats(call)
    elif action == "addadmin" and rbac.PERM_ADMIN_MANAGE in perms:
        await state.set_state(states.AdminFlow.waiting_admin_telegram_id)
        await call.message.answer("شناسه عددی تلگرام ادمین جدید را بفرستید:")
    elif action == "addnode" and rbac.PERM_NODE_MANAGE in perms:
        await state.set_state(states.AdminFlow.waiting_node_name)
        await call.message.answer(
            "نام اسکریپت نود جدید را بفرستید (حروف کوچک انگلیسی و خط تیره، "
            "مثلاً verdent-node-2):"
        )
    elif action == "test" and rbac.PERM_TEST_CONFIG in perms:
        await state.set_state(states.AdminFlow.waiting_reject_reason)
        await state.update_data(admin_action="test_config")
        await call.message.answer("شناسه عددی تلگرام مشتری را بفرستید:")
    elif action == "nodes" and rbac.PERM_NODE_MANAGE in perms:
        await _show_nodes(call)
    elif action == "tickets" and rbac.PERM_SUPPORT_MANAGE in perms:
        await _show_support_tickets(call)
    else:
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return
    await call.answer()


async def _show_pending_orders(call: CallbackQuery):
    async with SessionLocal() as db:
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
                .limit(10)
            )
        ).all()

        if not rows:
            await call.message.answer("سفارش در انتظار بررسی وجود ندارد.")
            return

        for attempt, order, plan in rows:
            customer = (
                await db.execute(
                    select(__import__("db.models", fromlist=["Customer"]).Customer).where(
                        __import__("db.models", fromlist=["Customer"]).Customer.id == order.customer_id
                    )
                )
            ).scalar_one_or_none()

            await call.message.answer(
                texts.ADMIN_REVIEW_PAYMENT.format(
                    customer=customer.display_name if customer else "—",
                    tg_id=customer.telegram_user_id if customer else "—",
                    plan=f"{plan.name} ({texts.format_price(plan.price_amount, plan.price_currency)})",
                    amount=texts.format_price(attempt.amount or plan.price_amount, attempt.currency),
                    display_name=order.requested_display_name,
                    order_ref=order.id[:8],
                ),
                reply_markup=keyboards.review_buttons(order.id, attempt.id),
            )


async def _show_stats(call: CallbackQuery):
    from sqlalchemy import func

    async with SessionLocal() as db:
        n_configs = (
            await db.execute(select(func.count()).select_from(Configuration).where(Configuration.status == "ACTIVE"))
        ).scalar_one()
        n_pending = (
            await db.execute(
                select(func.count()).select_from(PaymentAttempt).where(PaymentAttempt.status == "WAITING_REVIEW")
            )
        ).scalar_one()
        n_nodes = (
            await db.execute(
                select(func.count()).select_from(Node).where(Node.state == "ONLINE")
            )
        ).scalar_one()

    await call.message.answer(
        f"📊 <b>وضعیت سیستم</b>\n\n"
        f"کانفیگ‌های فعال: {n_configs}\n"
        f"پرداخت‌های در انتظار: {n_pending}\n"
        f"نودهای آنلاین: {n_nodes}"
    )


async def _show_nodes(call: CallbackQuery):
    async with SessionLocal() as db:
        nodes = (await db.execute(select(Node))).scalars().all()

    if not nodes:
        await call.message.answer("هنوز نودی ثبت نشده. ابتدا زیرساخت اضافه کنید.")
        return

    lines = ["🖥 <b>نودها</b>\n"]
    for n in nodes:
        lines.append(
            f"▫️ <code>{(n.worker_script_name or n.id)[:24]}</code> — {n.state} "
            f"(سلامت: {n.health_score or 0}، ظرفیت: {n.current_assignment_count}/{n.max_assignment_count})"
        )
    await call.message.answer("\n".join(lines))


# ---------------------------------------------------------------------------
# admin: review actions
# ---------------------------------------------------------------------------


@router.callback_query(F.data.startswith("rev:ok:"))
async def cb_review_approve(call: CallbackQuery, state: FSMContext):
    _, _, order_id, attempt_id = call.data.split(":")
    role = await _get_admin_role(call.from_user.id)

    if not role or rbac.PERM_PAYMENT_REVIEW not in rbac.permissions_for(role):
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    async with SessionLocal() as db:
        order = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
        # FOR UPDATE, not a plain read. The status check below is
        # check-then-act: two admins reviewing the same receipt (or one admin
        # double-tapping) both read WAITING_REVIEW, both pass, and the payment
        # is fulfilled TWICE — two configs and two KV credentials for one
        # payment. The row lock serializes them: the second transaction blocks
        # here until the first commits, then re-reads the row and sees the
        # status it actually has.
        attempt = (
            await db.execute(
                select(PaymentAttempt)
                .where(PaymentAttempt.id == attempt_id)
                .with_for_update()
            )
        ).scalar_one_or_none()

        if order is None or attempt is None or attempt.status != "WAITING_REVIEW":
            await call.answer("این سفارش قبلاً بررسی شده است.", show_alert=True)
            return

        admin = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == call.from_user.id))
        ).scalar_one_or_none()
        admin_id = admin.id if admin else None

        await mark_order_provisioning(db, order, attempt, admin_id)

        try:
            config = await fulfillment.fulfill_order(db, order, attempt, admin_id)
        except fulfillment.FulfillmentError as exc:
            logger.error("fulfillment failed for order %s: %s", order.id, exc)
            await call.message.answer(
                f"⚠️ تأیید شد اما فعال‌سازی ناموفق بود:\n<code>{exc}</code>\n"
                "سفارش در حالت PROVISIONING ماند — بعد از رفع مشکل، دوباره تأیید کنید."
            )
            await call.answer()
            return

        customer = (
            await db.execute(
                select(__import__("db.models", fromlist=["Customer"]).Customer).where(
                    __import__("db.models", fromlist=["Customer"]).Customer.id == order.customer_id
                )
            )
        ).scalar_one_or_none()

        if customer is not None:
            from bot.webhook import send_message

            await send_message(
                customer.telegram_user_id,
                texts.MSG_ORDER_APPROVED.format(
                    display_name=config.display_name,
                    link_block=texts.MSG_SUB_LINK.format(link=subscription_url(config)),
                ),
            )

    await call.message.edit_reply_markup(reply_markup=None)
    await call.message.answer(texts.MSG_ADMIN_CONFIRM)
    await call.answer()


@router.callback_query(F.data.startswith("rev:no:"))
async def cb_review_reject(call: CallbackQuery, state: FSMContext):
    _, _, order_id, attempt_id = call.data.split(":")
    role = await _get_admin_role(call.from_user.id)

    if not role or rbac.PERM_PAYMENT_REVIEW not in rbac.permissions_for(role):
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    await state.set_state(states.AdminFlow.waiting_reject_reason)
    await state.update_data(reject_order_id=order_id, reject_attempt_id=attempt_id)
    await call.message.answer(texts.MSG_ADMIN_REJECT_REASON)
    await call.answer()


@router.message(states.AdminFlow.waiting_reject_reason)
async def on_reject_reason(message: Message, state: FSMContext):
    data = await state.get_data()

    if data.get("admin_action") == "test_config":
        # reuse of the state for admin-entered customer telegram id
        await state.clear()
        await _admin_create_test(message, (message.text or "").strip())
        return

    order_id = data.get("reject_order_id")
    attempt_id = data.get("reject_attempt_id")
    reason = (message.text or "—").strip()
    await state.clear()

    role = await _get_admin_role(message.from_user.id)
    if not role or rbac.PERM_PAYMENT_REVIEW not in rbac.permissions_for(role):
        return

    async with SessionLocal() as db:
        # Same check-then-act as the approve path, and the same fix: without
        # the row lock a reject racing an approve both see WAITING_REVIEW and
        # the customer gets an approval AND a rejection message for one
        # receipt. Locking here makes the two reviews strictly ordered.
        attempt = (
            await db.execute(
                select(PaymentAttempt)
                .where(PaymentAttempt.id == attempt_id)
                .with_for_update()
            )
        ).scalar_one_or_none()
        if attempt is None or attempt.status != "WAITING_REVIEW":
            await message.answer("این سفارش قبلاً بررسی شده است.")
            return

        order = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
        admin = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == message.from_user.id))
        ).scalar_one_or_none()

        customer = (
            await db.execute(
                select(__import__("db.models", fromlist=["Customer"]).Customer).where(
                    __import__("db.models", fromlist=["Customer"]).Customer.id == order.customer_id
                )
            )
        ).scalar_one_or_none()

        await reject_payment(db, attempt, admin.id if admin else None, reason)

        if customer is not None:
            from bot.webhook import send_message

            await send_message(
                customer.telegram_user_id,
                texts.MSG_ORDER_REJECTED.format(order_ref=order.id[:8], reason=reason),
            )

    await message.answer(texts.MSG_ADMIN_REJECTED)


async def _admin_create_test(message: Message, telegram_id: str):
    from domain import test_configs
    from domain.pools import select_node_for_pool

    if not telegram_id.isdigit():
        await message.answer("شناسه عددی نامعتبر است.")
        return

    async with SessionLocal() as db:
        customer = await get_or_create_customer(
            db,
            telegram_user_id=int(telegram_id),
            username=None,
            display_name=None,
        )
        pool = (
            await db.execute(select(__import__("db.models", fromlist=["Pool"]).Pool).limit(1))
        ).scalar_one_or_none()
        node = await select_node_for_pool(db, pool) if pool else None

        if node is None:
            await message.answer("نودی در دسترس نیست.")
            return

        try:
            config = await test_configs.create_test_config(
                db,
                customer_id=customer.id,
                display_name=f"test-{telegram_id}",
                node=node,
                actor_id=str(message.from_user.id),
            )
        except test_configs.TestConfigLimitError as exc:
            await message.answer(
                f"سقف تست این مشتری پر شده ({exc.lifetime_count}/{exc.cap})."
            )
            return
        except RuntimeError:
            await message.answer("این مشتری یک تست فعال دارد.")
            return

        await message.answer(
            f"🧪 کانفیگ تستی ساخته شد: <b>{config.display_name}</b>\n"
            + texts.MSG_SUB_LINK.format(link=subscription_url(config))
        )


@router.message(states.AdminFlow.waiting_node_name)
async def on_node_name(message: Message, state: FSMContext):
    """Provision a new Node from the stored Cloudflare account (Phase 2).
    The API token itself is never typed into Telegram — it lives encrypted
    in Postgres (added once via web Shell, see SETUP-GUIDE §6)."""
    script_name = (message.text or "").strip().lower()
    await state.clear()

    role = await _get_admin_role(message.from_user.id)
    if not role or rbac.PERM_NODE_MANAGE not in rbac.permissions_for(role):
        return

    import re as _re

    if not _re.fullmatch(r"[a-z0-9][a-z0-9-]{0,30}", script_name):
        await message.answer("نام نامعتبر است. فقط حروف کوچک انگلیسی، عدد و خط تیره.")
        return

    from db.models import CloudflareAccount
    from domain.provisioning import ProvisioningError, provision_node

    async with SessionLocal() as db:
        account = (
            await db.execute(select(CloudflareAccount).limit(1))
        ).scalar_one_or_none()

        if account is None:
            await message.answer(
                "ابتدا حساب Cloudflare را اضافه کنید (SETUP-GUIDE §6 مرحله ۱)."
            )
            return

        taken = (
            await db.execute(
                select(Node.id).where(Node.worker_script_name == script_name).limit(1)
            )
        ).scalar_one_or_none()
        if taken:
            await message.answer("نودی با این نام از قبل ثبت شده است.")
            return

        admin = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == message.from_user.id))
        ).scalar_one_or_none()

        await message.answer("⏳ در حال ساخت نود روی Cloudflare... (تا ۲ دقیقه)")

        try:
            node = await provision_node(
                db, account.id, script_name,
                capability_tags=["general", "doh", "gaming"],
            )
        except ProvisioningError as exc:
            await message.answer(f"❌ خطا در ساخت نود:\n<code>{exc}</code>")
            return

        from domain.audit import audit

        await audit(
            db,
            "node.provisioned",
            actor_id=admin.id if admin else None,
            target_type="node",
            target_id=node.id,
            details={"script": script_name, "url": node.custom_domain},
        )

    await message.answer(
        f"✅ نود ساخته شد:\n🔗 <code>{node.custom_domain}</code>\n\n"
        "در چرخه‌ی بعدی سلامت (حداکثر ۶۰ ثانیه) ONLINE می‌شود."
    )


# ---------------------------------------------------------------------------
# admin: add admin
# ---------------------------------------------------------------------------


@router.message(states.AdminFlow.waiting_admin_telegram_id)
async def on_admin_telegram_id(message: Message, state: FSMContext):
    tg_id = (message.text or "").strip()
    role = await _get_admin_role(message.from_user.id)

    if not role or rbac.PERM_ADMIN_MANAGE not in rbac.permissions_for(role):
        await state.clear()
        return

    if not tg_id.isdigit():
        await message.answer("شناسه عددی نامعتبر است. دوباره بفرستید:")
        return

    await state.update_data(new_admin_tg=tg_id)
    await state.set_state(states.AdminFlow.waiting_admin_role)

    roles_kb = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=r, callback_data=f"admrole:{r}")] for r in rbac.ALL_ROLES
        ]
    )
    await message.answer("نقش ادمین جدید را انتخاب کنید:", reply_markup=roles_kb)


@router.callback_query(F.data.startswith("admrole:"))
async def on_admin_role(call: CallbackQuery, state: FSMContext):
    role = await _get_admin_role(call.from_user.id)
    if not role or rbac.PERM_ADMIN_MANAGE not in rbac.permissions_for(role):
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    new_role = call.data.split(":")[1]
    data = await state.get_data()
    tg_id = data.get("new_admin_tg")
    await state.clear()

    if not tg_id:
        await call.answer("شناسه یافت نشد — دوباره شروع کنید.", show_alert=True)
        return

    async with SessionLocal() as db:
        exists = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == int(tg_id)))
        ).scalar_one_or_none()
        if exists is not None:
            await call.message.answer("این کاربر قبلاً ادمین شده است.")
            await call.answer()
            return

        admin = (
            await db.execute(select(Admin).where(Admin.telegram_user_id == call.from_user.id))
        ).scalar_one_or_none()

        db.add(Admin(telegram_user_id=int(tg_id), role=new_role, created_by=admin.id if admin else None))
        await db.commit()

        from domain.audit import audit

        await audit(
            db,
            "admin.create",
            actor_id=admin.id if admin else None,
            target_type="admin",
            target_id=tg_id,
            details={"role": new_role},
        )

    await call.message.answer(f"✅ ادمین جدید ثبت شد: <code>{tg_id}</code> با نقش {new_role}")
    await call.answer()


# ---------------------------------------------------------------------------
# Stars payments (Phase 5)
# ---------------------------------------------------------------------------


@router.pre_checkout_query()
async def on_pre_checkout(query: PreCheckoutQuery):
    await query.answer(ok=True)


@router.message(F.successful_payment)
async def on_successful_payment(message: Message, state: FSMContext):
    payment = message.successful_payment
    payload = payment.invoice_payload  # format: stars:{order_id}

    if not payload.startswith("stars:"):
        return

    order_id = payload.split(":", 1)[1]

    async with SessionLocal() as db:
        order = (await db.execute(select(Order).where(Order.id == order_id))).scalar_one_or_none()
        if order is None:
            await message.answer("سفارش یافت نشد.")
            return

        customer = await get_or_create_customer(
            db,
            telegram_user_id=message.from_user.id,
            username=message.from_user.username,
            display_name=message.from_user.full_name,
        )

        attempt = await attach_payment_proof(
            db,
            order,
            telegram_file_id=f"stars:{payment.telegram_payment_charge_id}",
            mime_type=None,
            size_bytes=None,
        )
        attempt.external_reference = payment.telegram_payment_charge_id
        await db.commit()

        plan = (await db.execute(select(Plan).where(Plan.id == order.plan_id))).scalar_one_or_none()
        if plan is None:
            return

        admin = (
            await db.execute(select(Admin).where(Admin.role == "OWNER").limit(1))
        ).scalar_one_or_none()

        await mark_order_provisioning(db, order, attempt, admin.id if admin else None)

        try:
            config = await fulfillment.fulfill_order(db, order, attempt, admin.id if admin else None)
            await message.answer(
                texts.MSG_ORDER_APPROVED.format(
                    display_name=config.display_name,
                    link_block=texts.MSG_SUB_LINK.format(link=subscription_url(config)),
                )
            )
        except fulfillment.FulfillmentError as exc:
            logger.error("stars fulfillment failed: %s", exc)
            await message.answer(
                "پرداخت ثبت شد اما فعال‌سازی موقتاً ناموفق بود — به‌زودی دستی فعال می‌کنیم."
            )


# ---------------------------------------------------------------------------
# admin: support tickets
# ---------------------------------------------------------------------------

async def _show_support_tickets(call: CallbackQuery):
    async with SessionLocal() as db:
        tickets = await support_domain.open_tickets(db)
        if not tickets:
            await call.message.answer(
                texts.MSG_SUPPORT_ADMIN_NO_TICKETS, reply_markup=keyboards.back_to_main()
            )
            return

        customers = {
            c.id: c
            for c in (await db.execute(select(Customer))).scalars().all()
        }
        chunks = [texts.MSG_SUPPORT_ADMIN_TICKETS_HEADER]
        kb = InlineKeyboardBuilder()
        for t in tickets:
            ref = support_domain.ticket_ref(t.id)
            cust = customers.get(t.customer_id)
            chunks.append(
                texts.MSG_SUPPORT_ADMIN_TICKET_ITEM.format(
                    ref=ref,
                    status_fa=texts.SUPPORT_STATUS_FA.get(t.status, t.status),
                    updated=t.updated_at.strftime("%Y-%m-%d %H:%M"),
                    customer=(cust.display_name or "—") if cust else "—",
                    tg_id=cust.telegram_user_id if cust else "—",
                )
            )
            kb.button(
                text=f"{ref} — {texts.SUPPORT_STATUS_FA.get(t.status, t.status)}",
                callback_data=f"supadm:view:{ref}",
            )
        kb.button(text=texts.BTN_BACK, callback_data="menu:main")
        kb.adjust(1)
        await call.message.answer(
            "\n".join(chunks), reply_markup=kb.as_markup()
        )


@router.callback_query(F.data.startswith("supadm:view:"))
async def cb_admin_view_ticket(call: CallbackQuery, state: FSMContext):
    role = await _get_admin_role(call.from_user.id)
    perms = rbac.permissions_for(role) if role else set()
    if rbac.PERM_SUPPORT_MANAGE not in perms:
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    ref = call.data.split(":")[2]
    async with SessionLocal() as db:
        ticket, customer, messages = await _load_ticket_thread(db, ref)

    if ticket is None:
        await call.answer(texts.MSG_SUPPORT_ADMIN_TICKET_NOT_FOUND, show_alert=True)
        return

    await state.clear()
    await call.message.answer(
        texts.MSG_SUPPORT_ADMIN_TICKET_ANSWER.format(
            ref=ref,
            status_fa=texts.SUPPORT_STATUS_FA.get(ticket.status, ticket.status),
            transcript=_render_transcript(messages),
        ),
        reply_markup=keyboards.admin_ticket_actions(ref),
    )
    await call.answer()


def _render_transcript(messages: list) -> str:
    lines = []
    for m in messages:
        lines.append(
            texts.MSG_SUPPORT_ADMIN_TRANSCRIPT_ITEM.format(
                author="پشتیبانی" if m.author_type == "admin" else "مشتری",
                when=m.created_at.strftime("%Y-%m-%d %H:%M"),
                body=m.body,
            )
        )
    return "".join(lines) or "—"


async def _load_ticket_thread(db, ref: str | None):
    """(ticket, customer, messages) for a short ref, or (None, None, []).

    The ref is the first 8 characters of the uuid — Telegram caps callback
    data at 64 bytes, so the full id does not fit. Resolution and the
    ambiguity rule live in domain.support.ticket_by_ref.
    """
    if not ref:
        return None, None, []

    ticket = await support_domain.ticket_by_ref(db, ref)
    if ticket is None:
        return None, None, []

    customer = (
        await db.execute(select(Customer).where(Customer.id == ticket.customer_id))
    ).scalar_one_or_none()
    messages = (
        await db.execute(
            select(SupportMessage)
            .where(SupportMessage.ticket_id == ticket.id)
            .order_by(SupportMessage.created_at.asc())
        )
    ).scalars().all()
    return ticket, customer, messages


@router.callback_query(F.data.startswith("supadm:reply:"))
async def cb_admin_reply_ticket(call: CallbackQuery, state: FSMContext):
    role = await _get_admin_role(call.from_user.id)
    perms = rbac.permissions_for(role) if role else set()
    if rbac.PERM_SUPPORT_MANAGE not in perms:
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    ref = call.data.split(":")[2]
    await state.set_state(states.SupportAdmin.waiting_reply)
    await state.update_data(ticket_ref=ref)
    await call.message.answer(
        texts.MSG_SUPPORT_ADMIN_REPLY_PROMPT.format(ref=ref)
    )
    await call.answer()


@router.message(states.SupportAdmin.waiting_reply)
async def on_admin_reply(message: Message, state: FSMContext):
    role = await _get_admin_role(message.from_user.id)
    perms = rbac.permissions_for(role) if role else set()
    if rbac.PERM_SUPPORT_MANAGE not in perms:
        # An admin whose role changed mid-reply, or a customer who somehow
        # landed in this state, must not be able to answer a ticket.
        await state.clear()
        return

    body = (message.text or "").strip()
    if not body:
        await message.answer(texts.MSG_SUPPORT_ADMIN_REPLY_PROMPT.format(
            ref=(await state.get_data()).get("ticket_ref", "—")
        ))
        return

    data = await state.get_data()
    ref = data.get("ticket_ref")
    # One reply per prompt: the ref must not survive into the admin's next
    # message, or an unrelated chat would be posted to this customer's ticket.
    await state.clear()

    async with SessionLocal() as db:
        ticket, customer, _ = await _load_ticket_thread(db, ref)
        if ticket is None:
            await message.answer(texts.MSG_SUPPORT_ADMIN_TICKET_NOT_FOUND)
            return
        await support_domain.add_message(
            db, ticket, "admin", message.from_user.id, body
        )
        customer_tg_id = customer.telegram_user_id if customer else None
        # The row is written with server_default now(), which Python does not
        # populate — without this the customer is told the reply arrived at
        # whatever `now` happened to be on their screen (year 1).
        replied_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

    await message.answer(texts.MSG_SUPPORT_ADMIN_REPLIED.format(ref=ref))

    if customer_tg_id is not None:
        from bot.webhook import send_message

        try:
            await send_message(
                customer_tg_id,
                texts.MSG_SUPPORT_ADMIN_TICKET_ANSWER.format(
                    ref=ref,
                    status_fa=texts.SUPPORT_STATUS_FA.get(
                        support_domain.STATUS_ANSWERED, support_domain.STATUS_ANSWERED
                    ),
                    transcript=texts.MSG_SUPPORT_ADMIN_TRANSCRIPT_ITEM.format(
                        author="پشتیبانی",
                        when=replied_at,
                        body=body,
                    ),
                ),
            )
        except Exception:  # noqa: BLE001
            logger.exception("failed to deliver admin reply for ticket %s", ref)


@router.callback_query(F.data.startswith("supadm:close:"))
async def cb_admin_close_ticket(call: CallbackQuery, state: FSMContext):
    role = await _get_admin_role(call.from_user.id)
    perms = rbac.permissions_for(role) if role else set()
    if rbac.PERM_SUPPORT_MANAGE not in perms:
        await call.answer(texts.MSG_ADMIN_FORBIDDEN, show_alert=True)
        return

    ref = call.data.split(":")[2]
    async with SessionLocal() as db:
        ticket, _customer, _messages = await _load_ticket_thread(db, ref)
        if ticket is None:
            await call.answer(texts.MSG_SUPPORT_ADMIN_TICKET_NOT_FOUND, show_alert=True)
            return
        await support_domain.close_ticket(db, ticket)

    await call.message.answer(texts.MSG_SUPPORT_ADMIN_CLOSED.format(ref=ref))
    await call.answer()


async def _notify_admins_new_order(db, order: Order, attempt: PaymentAttempt, customer_message: Message):
    from bot.webhook import send_message

    plan = (await db.execute(select(Plan).where(Plan.id == order.plan_id))).scalar_one_or_none()
    admins = (await db.execute(select(Admin))).scalars().all()

    for admin in admins:
        if not rbac.PERM_PAYMENT_REVIEW in rbac.permissions_for(admin.role):
            continue

        await send_message(
            admin.telegram_user_id,
            texts.MSG_ADMIN_NOTIFY_NEW_ORDER
            + "\n\n"
            + texts.ADMIN_REVIEW_PAYMENT.format(
                customer=customer_message.from_user.full_name,
                tg_id=customer_message.from_user.id,
                plan=plan.name if plan else "—",
                amount=texts.format_price(plan.price_amount, plan.price_currency) if plan else "—",
                display_name=order.requested_display_name,
                order_ref=order.id[:8],
            ),
        )


# include into the webhook dispatcher (module-level, AFTER all handlers register)
from bot.webhook import dp as _dp  # noqa: E402

_dp.include_router(router)
