"""Regression tests for the support ticket workflow (#46).

The support button answered with static copy that told the customer to leave
a message, and then dropped it. Nothing was stored, no admin was told, and the
customer had no ticket id to quote when they followed up — a button that reads
like a workflow but is not one. `bot/states.py` even declared
`Support.waiting_user_message`, a state nothing ever set or handled, which is
the same dead-code shape as the gaming profile that shipped earlier.

The workflow now persists the conversation on both sides. What is pinned here:

  1. the three-value status machine (the part that is easy to get subtly wrong)
  2. that the customer path actually reaches persistence and admin notification
  3. that the admin reply/close path is permission-gated
  4. that an FSM ticket ref cannot survive into an unrelated next message
  5. that the migration creates and drops both tables in a safe order

Run: python scripts/test_support_tickets.py
"""

import asyncio
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import bot.keyboards as kb  # noqa: E402
import bot.router as router  # noqa: E402
import bot.texts as texts  # noqa: E402
from domain import rbac  # noqa: E402
from domain import support as support_domain  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


class FakeTicket:
    def __init__(self, status: str = "open", tid: str = "abcdef1234567890") -> None:
        self.id = tid
        self.status = status


# ---------------------------------------------------------------------------
# 1. the status machine
# ---------------------------------------------------------------------------


def section_status_machine() -> None:
    print("\n1. Status machine: the three values behave as documented")

    check(
        "a customer message always reopens",
        support_domain.derive_status(FakeTicket("answered"), "customer") == "open",
        "an answer is stale the moment a new question arrives",
    )
    check(
        "a customer message on a closed ticket reopens it",
        support_domain.derive_status(FakeTicket("closed"), "customer") == "open",
        "closing must not make a customer unable to get help",
    )
    check(
        "an admin message answers",
        support_domain.derive_status(FakeTicket("open"), "admin") == "answered",
        "the reply is what moves it out of the queue",
    )
    check(
        "an admin message on a closed ticket leaves it closed",
        support_domain.derive_status(FakeTicket("closed"), "admin") == "closed",
        "a stray reply must not silently reopen a closed ticket",
    )
    check(
        "exactly three statuses exist",
        set(support_domain.ALL_STATUSES) == {"open", "answered", "closed"},
        f"got {support_domain.ALL_STATUSES}",
    )
    # Every status must be renderable — an unmapped status shows the raw
    # English key to a Persian-speaking customer.
    for status in support_domain.ALL_STATUSES:
        check(
            f"status {status!r} has Persian text",
            status in texts.SUPPORT_STATUS_FA,
            "an unmapped status is shown to customers as an English key",
        )

    print("\n2. add_message refuses an author that is neither side")
    src = inspect.getsource(support_domain.add_message)
    check(
        "author_type is validated",
        'raise ValueError' in src and "customer" in src and "admin" in src,
        "an unvalidated author_type would write a row the CHECK constraint rejects at commit",
    )


# ---------------------------------------------------------------------------
# 3. the customer path reaches persistence and notifies admins
# ---------------------------------------------------------------------------


def section_customer_path() -> None:
    print("\n3. Customer path: the message is stored and admins are told")

    handler = inspect.getsource(router.on_support_message)
    check(
        "the handler persists the message",
        "create_ticket" in handler and "add_message" in handler,
        "without a write the conversation is still a void",
    )
    check(
        "admins are notified",
        "_notify_admins_new_ticket" in handler,
        "a stored ticket nobody is told about is the old bug with extra steps",
    )
    check(
        "the customer is told their ticket id",
        "MSG_SUPPORT_TICKET_OPENED" in handler,
        "without a ref the customer cannot quote the ticket on a follow-up",
    )
    # The confirmation must be sent before the admin notification, or a failing
    # notification eats the customer's only proof the ticket exists.
    conf_at = handler.find("MSG_SUPPORT_TICKET_OPENED")
    notify_at = handler.find("_notify_admins_new_ticket(ref")
    check(
        "the confirmation precedes the admin notification",
        conf_at != -1 and notify_at != -1 and conf_at < notify_at,
        "a notification failure would otherwise cost the customer their ticket id",
    )

    print("\n4. The support menu sets the waiting state")
    menu = inspect.getsource(router.cb_support)
    check(
        "the menu enters the waiting state",
        "states.Support.waiting_user_message" in menu,
        "without it the message the customer types next is unhandled",
    )
    check(
        "a handler is registered for that state",
        "@router.message(states.Support.waiting_user_message)" in inspect.getsource(
            router.on_support_message
        ),
        "a state with no handler drops every message sent in it",
    )

    print("\n5. An FSM ref cannot leak into an unrelated message")
    handler_src = inspect.getsource(router.on_support_message)
    get_at = handler_src.find("get_data()")
    # The /cancel branch clears the state first, so anchor on the clear that
    # follows the get_data read — that is the one guarding the ref.
    clear_at = handler_src.find("state.clear()", get_at)
    ticket_at = handler_src.find("support_domain.add_message")
    check(
        "the state is cleared after the ref is read and before it is used",
        get_at != -1 and clear_at != -1 and ticket_at != -1
        and get_at < clear_at < ticket_at,
        "a surviving ref would append the next unrelated message to an old ticket",
    )

    # The ref must also be resolved against the CUSTOMER's own tickets.
    check(
        "the ref is matched within the customer's own tickets",
        "customer_tickets(db, customer.id)" in handler_src
        and "_match_ticket(tickets, target_ref)" in handler_src,
        "an unscoped ref lookup would read another customer's private thread",
    )

    open_picker = inspect.getsource(router._open_ticket)
    check(
        "an auto-continued ticket is only an unanswered one",
        "STATUS_OPEN" in open_picker and "STATUS_ANSWERED" not in open_picker,
        "continuing an answered ticket buries the answer with no signal it is stale",
    )


# ---------------------------------------------------------------------------
# 6. admin side is permission-gated
# ---------------------------------------------------------------------------


def section_admin_gating() -> None:
    print("\n6. Admin ticket actions are permission-gated")

    check(
        "the permission is defined",
        rbac.PERM_SUPPORT_MANAGE == "support.manage",
        "the keyboard and handlers must agree on the name",
    )
    for role, expected in (
        (rbac.ROLE_OWNER, True),
        (rbac.ROLE_ADMIN, True),
        (rbac.ROLE_SUPPORT, True),
        (rbac.ROLE_FINANCE, False),
        (rbac.ROLE_INFRASTRUCTURE, False),
    ):
        got = rbac.PERM_SUPPORT_MANAGE in rbac.permissions_for(role)
        check(
            f"{role} {'can' if expected else 'cannot'} manage tickets",
            got == expected,
            f"got {got}, expected {expected}",
        )

    for name, fn in (
        ("view", router.cb_admin_view_ticket),
        ("reply", router.cb_admin_reply_ticket),
        ("close", router.cb_admin_close_ticket),
    ):
        src = inspect.getsource(fn)
        check(
            f"admin {name} checks the permission",
            "PERM_SUPPORT_MANAGE" in src and "MSG_ADMIN_FORBIDDEN" in src,
            "an ungated handler lets any admin read a customer's private messages",
        )

    print("\n7. The admin reply handler re-checks the role")
    reply_src = inspect.getsource(router.on_admin_reply)
    check(
        "the message handler re-checks the permission",
        "PERM_SUPPORT_MANAGE" in reply_src,
        "the role can be revoked between the button press and the message",
    )
    check(
        "an unauthorized admin is left with no state",
        "state.clear()" in reply_src,
        "otherwise they stay armed to reply",
    )
    get_at = reply_src.find("get_data()")
    # The forbidden branch clears the state too, so anchor on the clear that
    # follows the get_data read — that is the one guarding the ref.
    clear_at = reply_src.find("state.clear()", get_at)
    check(
        "the reply ref does not survive into the next message",
        get_at != -1 and clear_at != -1 and get_at < clear_at,
        "the next unrelated admin message would be posted to this customer's ticket",
    )


# ---------------------------------------------------------------------------
# 8. prefix lookup must be unambiguous
# ---------------------------------------------------------------------------


def section_prefix_lookup() -> None:
    print("\n8. A short ticket ref resolves to exactly one ticket")

    src = inspect.getsource(support_domain.ticket_by_ref)
    check(
        "a non-unique prefix is treated as not-found",
        "len(rows) != 1" in src,
        "a uuid prefix match can return more than one row; picking the first "
        "would show one customer another customer's messages",
    )
    check(
        "the uuid is cast before the LIKE",
        "cast(SupportTicket.id, String)" in src,
        "Postgres has no uuid LIKE operator; the query would die with "
        "operator does not exist: uuid ~~* unknown",
    )
    check(
        "the lookup is a prefix match",
        '.like(f"{ref}%")' in src,
        "the ref shown to the customer is only 8 characters of the id",
    )

    router_src = inspect.getsource(router._load_ticket_thread)
    check(
        "the router resolves through the domain function",
        "ticket_by_ref" in router_src,
        "a second copy of the lookup would reintroduce the uuid LIKE bug",
    )
    check(
        "a missing ref short-circuits instead of querying",
        "if not ref" in router_src,
        "an unset FSM ref would otherwise query with LIKE '%%'",
    )


# ---------------------------------------------------------------------------
# 9. migration
# ---------------------------------------------------------------------------


def section_migration() -> None:
    print("\n9. Migration 003 creates and drops both tables")
    import importlib.util

    path = (
        Path(__file__).resolve().parent.parent
        / "db" / "migrations" / "versions" / "003_support_tickets.py"
    )
    if not path.exists():
        check("migration 003 exists", False, f"missing at {path}")
        return

    spec = importlib.util.spec_from_file_location("mig003", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    check("it revises 002", mod.down_revision == "002", f"got {mod.down_revision}")
    src = inspect.getsource(mod)
    check(
        "both tables are created",
        "support_tickets" in src and "support_messages" in src,
        "a conversation needs both halves",
    )
    check(
        "the status CHECK is created",
        "ck_support_tickets_status" in src,
        "without the constraint any status can be written",
    )
    down = inspect.getsource(mod.downgrade)
    mi = down.find('drop_table("support_messages")')
    ti = down.find('drop_table("support_tickets")')
    check(
        "downgrade drops the child before the parent",
        mi != -1 and ti != -1 and mi < ti,
        "dropping the parent first leaves a foreign key pointing nowhere",
    )
    check(
        "downgrade drops both tables",
        mi != -1 and ti != -1,
        "a downgrade that leaves tables behind is the migration-001 defect again",
    )

    # The ORM and the migration must agree, or the app writes columns the
    # database does not have.
    from db.models import SupportMessage, SupportTicket

    def _default_text(column) -> str | None:
        """server_default may be a raw str or a wrapped DefaultClause."""
        default = column.server_default
        if default is None:
            return None
        arg = getattr(default, "arg", default)
        return getattr(arg, "text", None) or str(arg)

    status_default = _default_text(SupportTicket.__table__.c.status)
    check(
        "the ORM ticket status default matches the migration",
        status_default == "open",
        f"got {status_default!r}",
    )
    for col in ("id", "customer_id", "subject", "status"):
        check(
            f"SupportTicket.{col} exists in the ORM",
            col in SupportTicket.__table__.c,
            "an ORM column with no migration column breaks at insert time",
        )
    for col in ("id", "ticket_id", "author_type", "author_telegram_id", "body"):
        check(
            f"SupportMessage.{col} exists in the ORM",
            col in SupportMessage.__table__.c,
            "an ORM column with no migration column breaks at insert time",
        )


# ---------------------------------------------------------------------------
# 10. no text promises a workflow that does not exist
# ---------------------------------------------------------------------------


def section_texts_wired() -> None:
    print("\n10. Every support text is actually referenced")

    router_src = inspect.getsource(router)
    for name in (
        "MSG_SUPPORT",
        "MSG_SUPPORT_ASK",
        "MSG_SUPPORT_TICKET_OPENED",
        "MSG_SUPPORT_TICKET_CLOSED_NOTICE",
        "MSG_SUPPORT_CANCELLED",
        "MSG_SUPPORT_ADMIN_NEW",
        "MSG_SUPPORT_ADMIN_TICKET_ANSWER",
        "MSG_SUPPORT_ADMIN_REPLIED",
        "MSG_SUPPORT_ADMIN_CLOSED",
        "MSG_SUPPORT_ADMIN_TICKET_NOT_FOUND",
        "MSG_SUPPORT_ADMIN_NO_TICKETS",
    ):
        check(f"{name} is used by a handler", name in router_src, "unused copy")

    kb_src = inspect.getsource(kb)
    check(
        "the customer ticket keyboard is used",
        "customer_tickets" in router_src,
        "an unused keyboard is dead UI code",
    )
    check(
        "the admin action keyboard is used",
        "admin_ticket_actions" in router_src,
        "the reply/close buttons would not appear",
    )
    check(
        "the admin panel offers tickets",
        "adm:tickets" in kb_src and "support.manage" in kb_src,
        "without the button the queue is unreachable",
    )


# ---------------------------------------------------------------------------
# 11. configuration rename (#47)
# ---------------------------------------------------------------------------


class _RenameResult:
    def __init__(self, value) -> None:
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _RenameDB:
    """Minimal AsyncSession stand-in: records the commit, answers the
    uniqueness probe."""

    def __init__(self, taken=None) -> None:
        self._taken = taken
        self.committed = False

    async def execute(self, query):
        return _RenameResult(self._taken)

    async def commit(self):
        self.committed = True

    async def refresh(self, _obj):
        return None


class _RenameConfig:
    def __init__(self, display_name="Parsa", suffix="A3F2K") -> None:
        self.id = "cfg-1"
        self.display_name = display_name
        self.suffix = suffix


def section_rename() -> None:
    print("\n11. Configuration rename keeps the suffix and re-checks uniqueness")
    from domain import subscriptions as subs

    async def run():
        # A valid rename applies and commits.
        db = _RenameDB(taken=None)
        cfg = _RenameConfig()
        out = await subs.rename_configuration(db, cfg, "NewName")
        check(
            "a valid rename applies the new name",
            out.display_name == "NewName",
            f"got {out.display_name!r}",
        )
        check(
            "the suffix is preserved",
            out.suffix == "A3F2K",
            "re-minting would silently change the label the customer was shown",
        )
        check("the rename commits", db.committed, "an uncommitted rename is lost")

        # A collision is refused, and refused BEFORE any write.
        db = _RenameDB(taken="other-config")
        cfg = _RenameConfig()
        try:
            await subs.rename_configuration(db, cfg, "Taken")
            raised = False
        except subs.RenameError as exc:
            raised = exc.reason == subs.RENAME_NAME_TAKEN
        check(
            "a name that collides with the same suffix is refused",
            raised,
            "keeping the suffix means a collision is possible",
        )
        check(
            "a refused rename writes nothing",
            cfg.display_name == "Parsa" and not db.committed,
            "the config must be untouched when the rename is rejected",
        )

        # Invalid names are refused with the right reason.
        for bad in ("", "   ", "has space", "punct!", "x" * 25):
            db = _RenameDB(taken=None)
            cfg = _RenameConfig()
            try:
                await subs.rename_configuration(db, cfg, bad)
                reason = None
            except subs.RenameError as exc:
                reason = exc.reason
            check(
                f"invalid name {bad!r} is refused as invalid",
                reason == subs.RENAME_INVALID_NAME,
                f"got {reason!r}",
            )

        # Re-submitting the same name is a no-op, not an error.
        db = _RenameDB(taken=None)
        cfg = _RenameConfig()
        out = await subs.rename_configuration(db, cfg, "Parsa")
        check(
            "re-submitting the current name is not an error",
            out.display_name == "Parsa",
            "a double-tap must not surface as a failure",
        )

    asyncio.run(run())

    print("\n12. Rename is ownership-checked and audited as the customer")
    router_src = inspect.getsource(router)

    own_src = inspect.getsource(router._own_config)
    check(
        "the ownership check scopes by customer",
        "Configuration.customer_id == customer.id" in own_src,
        "an unscoped lookup hands any customer another's subscription link",
    )
    check(
        "the ownership check excludes deleted configs",
        'Configuration.status != "DELETED"' in own_src,
        "a deleted config must not be reachable by id",
    )
    for name, fn in (
        ("view", router.cb_config_view),
        ("link", router.cb_config_link),
        ("rename", router.cb_config_rename),
    ):
        check(
            f"cfg:{name} goes through the ownership check",
            "_own_config" in inspect.getsource(fn),
            "callback data is client-supplied and must never be trusted for ownership",
        )

    rename_src = inspect.getsource(router.on_config_rename)
    check(
        "ownership is re-checked at the moment of the write",
        "_own_config" in rename_src,
        "the button press is not the same moment as the message",
    )
    get_at = rename_src.find("get_data()")
    clear_at = rename_src.find("state.clear()", get_at)
    check(
        "the pending config id does not survive the message",
        get_at != -1 and clear_at != -1 and get_at < clear_at,
        "the next unrelated message would be applied as a rename",
    )
    check(
        "the rename is audited as the customer",
        'actor_type="customer"' in rename_src and "config.rename" in rename_src,
        "attributing it to an admin or the system would be a false record",
    )
    check(
        "a refused rename keeps the prompt open",
        "MSG_RENAME_FAILED_TAKEN" in rename_src
        and "MSG_RENAME_FAILED_INVALID" in rename_src,
        "a typo should not force the customer to find the button again",
    )

    print("\n13. The audit constraint admits a customer actor")
    from db.models import AuditLog

    constraint = [
        c for c in AuditLog.__table__.constraints
        if getattr(c, "name", None) == "ck_audit_log_actor_type"
    ]
    check(
        "the ORM constraint exists",
        len(constraint) == 1,
        "without it nothing stops an invalid actor_type",
    )
    if constraint:
        text = str(constraint[0].sqltext)
        check(
            "the constraint permits 'customer'",
            "customer" in text,
            "audit() swallows failures, so a rejected row would vanish silently",
        )
    check(
        "a migration widens the constraint",
        (Path(__file__).resolve().parent.parent / "db" / "migrations" / "versions"
         / "004_audit_customer_actor.py").exists(),
        "changing the model without a migration leaves the live DB rejecting the row",
    )

    print("\n14. The config action keyboard is reachable")
    kb_src = inspect.getsource(kb)
    check(
        "the config list is tappable",
        "cfg:view:" in kb_src and "my_configs" in router_src,
        "config_actions was unreachable dead UI before this",
    )
    check(
        "rename has a button",
        "BTN_RENAME" in kb_src and "cfg:rename:" in kb_src,
        "a rename with no entry point is unreachable",
    )
    check(
        "the rename button has a handler",
        'F.data.startswith("cfg:rename:")' in router_src,
        "a button with no handler is the dead-button defect again",
    )


def main() -> None:
    section_status_machine()
    section_customer_path()
    section_admin_gating()
    section_prefix_lookup()
    section_migration()
    section_texts_wired()
    section_rename()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All support-ticket checks passed.")


main()
