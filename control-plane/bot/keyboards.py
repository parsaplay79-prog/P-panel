"""Verdent Platform — inline keyboards (aiogram 3)."""

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from bot import texts
from domain.support import ticket_ref


def main_menu() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text=texts.BTN_BUY, callback_data="menu:buy")
    kb.button(text=texts.BTN_MY_CONFIGS, callback_data="menu:configs")
    kb.button(text=texts.BTN_TRIAL, callback_data="menu:trial")
    kb.button(text=texts.BTN_SUPPORT, callback_data="menu:support")
    kb.button(text=texts.BTN_HELP, callback_data="menu:help")
    kb.adjust(2, 2, 1)
    return kb.as_markup()


def plans_menu(plans: list) -> InlineKeyboardMarkup:
    """plans: list[Plan] — label = name + price."""
    kb = InlineKeyboardBuilder()
    for plan in plans:
        label = f"{plan.name} — {texts.format_price(plan.price_amount, plan.price_currency)}"
        kb.button(text=label, callback_data=f"plan:{plan.id}")
    kb.button(text=texts.BTN_BACK, callback_data="menu:main")
    kb.adjust(1)
    return kb.as_markup()


def payment_methods(plan_id: str, stars_available: bool) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text=texts.BTN_PAY_CARD, callback_data=f"pay:card:{plan_id}")
    if stars_available:
        kb.button(text=texts.BTN_PAY_STARS, callback_data=f"pay:stars:{plan_id}")
    kb.button(text=texts.BTN_CANCEL, callback_data="menu:main")
    kb.adjust(1)
    return kb.as_markup()


def my_configs(configs: list) -> InlineKeyboardMarkup:
    """One button per configuration, opening that config's action panel.

    The list used to be a single text blob with only a Back button, which left
    `config_actions` unreachable: its handler was registered but no keyboard
    ever sent it, so the link button existed only in the source.
    """
    kb = InlineKeyboardBuilder()
    for c in configs:
        label = f"{c.display_name}_{c.suffix}"
        kb.button(text=label, callback_data=f"cfg:view:{c.id}")
    kb.button(text=texts.BTN_BACK, callback_data="menu:main")
    kb.adjust(1)
    return kb.as_markup()


def config_actions(config_id: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text=texts.BTN_LINK, callback_data=f"cfg:link:{config_id}")
    kb.button(text=texts.BTN_RENAME, callback_data=f"cfg:rename:{config_id}")
    # No renew button. Renewal was removed from the product deliberately, but
    # the button was still being shipped: Telegram renders it, the customer
    # presses it, and nothing happens because no handler is registered for
    # "cfg:renew:*". A dead button on the customer's own config screen is
    # worse than no button — it advertises a feature that does not exist.
    # Re-add here together with a handler, never on its own.
    kb.adjust(1)
    return kb.as_markup()


def review_buttons(order_id: str, attempt_id: str) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text="✅ تأیید", callback_data=f"rev:ok:{order_id}:{attempt_id}")
    kb.button(text="❌ رد", callback_data=f"rev:no:{order_id}:{attempt_id}")
    kb.adjust(2)
    return kb.as_markup()


def customer_tickets(tickets: list) -> InlineKeyboardMarkup:
    """The customer's own tickets — a tap refills the box for that thread."""
    kb = InlineKeyboardBuilder()
    for t in tickets:
        ref = ticket_ref(t.id)
        label = f"{ref} — {texts.SUPPORT_STATUS_FA.get(t.status, t.status)}"
        kb.button(text=label, callback_data=f"sup:open:{ref}")
    kb.button(text=texts.BTN_BACK, callback_data="menu:main")
    kb.adjust(1)
    return kb.as_markup()


def admin_ticket_actions(ref: str) -> InlineKeyboardMarkup:
    """Reply / close, as buttons on the ticket transcript.

    Reply is a button even though typing also works: an admin reading a queue
    should not have to know the state machine to answer. Both carry the ref so
    the handler never guesses which ticket it is acting on.
    """
    kb = InlineKeyboardBuilder()
    kb.button(text="✍️ پاسخ", callback_data=f"supadm:reply:{ref}")
    kb.button(text="🔒 بستن تیکت", callback_data=f"supadm:close:{ref}")
    kb.button(text=texts.BTN_BACK, callback_data="adm:tickets")
    kb.adjust(1)
    return kb.as_markup()


def admin_panel(permissions: set[str]) -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    rows: list[list[InlineKeyboardButton]] = []

    def add(btn: InlineKeyboardButton, per_row: int = 2) -> None:
        rows.append([btn])

    if "payment.review" in permissions or "stats.view" in permissions:
        add(InlineKeyboardButton(text="🧾 سفارش‌های در انتظار", callback_data="adm:pending"))
    if "config.test" in permissions:
        add(InlineKeyboardButton(text="🧪 ساخت کانفیگ تستی", callback_data="adm:test"))
    if "support.manage" in permissions:
        add(InlineKeyboardButton(text="🆘 تیکت‌های پشتیبانی", callback_data="adm:tickets"))
    if "admin.manage" in permissions:
        add(InlineKeyboardButton(text="👑 افزودن ادمین", callback_data="adm:addadmin"))
    if "node.manage" in permissions:
        add(InlineKeyboardButton(text="🖥 مدیریت نودها", callback_data="adm:nodes"))
        add(InlineKeyboardButton(text="➕ ساخت نود جدید", callback_data="adm:addnode"))
    add(InlineKeyboardButton(text="📊 وضعیت سیستم", callback_data="adm:stats"))

    kb.row(*[b for row in rows for b in row])
    kb.adjust(1)
    return kb.as_markup()


def back_to_main() -> InlineKeyboardMarkup:
    kb = InlineKeyboardBuilder()
    kb.button(text=texts.BTN_BACK, callback_data="menu:main")
    return kb.as_markup()
