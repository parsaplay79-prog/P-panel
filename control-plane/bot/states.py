"""Verdent Platform — Telegram FSM states (aiogram 3)."""

from aiogram.fsm.state import State, StatesGroup


class Purchase(StatesGroup):
    waiting_display_name = State()
    waiting_payment_proof = State()


class AdminFlow(StatesGroup):
    waiting_reject_reason = State()
    waiting_admin_telegram_id = State()
    waiting_admin_role = State()
    waiting_node_name = State()


class Support(StatesGroup):
    """Customer side. The ticket is resolved from the customer row at message
    time rather than remembered in FSM data: FSM storage is per-chat and can be
    dropped, whereas "this customer has an open ticket" is a fact about the
    database that survives a restart."""
    waiting_user_message = State()


class SupportAdmin(StatesGroup):
    """Admin side. The ticket ref IS kept in FSM data here — an admin can be
    replying to any ticket in the queue, so there is no customer row to
    resolve the target from."""
    waiting_reply = State()


class ConfigEdit(StatesGroup):
    """Customer renaming one of their own configurations.

    The config id is held in FSM data. That is safe here only because the
    handler re-checks ownership against the caller's customer row before
    writing — a stale or tampered id must never be enough on its own.
    """
    waiting_new_name = State()
