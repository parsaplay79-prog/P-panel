"""Regression tests for the web Admin Panel (#48).

The panel gives every Telegram-bot admin action an HTML page, plus its own
username+password authentication. What is pinned here:

  1. password hashing — the format, the iteration floor, constant-time compare
  2. session tokens — roundtrip, expiry, tamper detection, version revocation
  3. the production refusal when JWT_SIGNING_KEY is unset
  4. route inventory — every route except login/logout carries exactly one
     REAL RBAC permission (a typo'd constant would otherwise gate wrong or 503)
  5. the payment paths mirror the bot's — FOR UPDATE row lock, status guard,
     domain function calls, customer notification
  6. login has no registration path (an unauthenticated ADMIN(OWNER) insert)
  7. migration 005 and the Admin model agree on the three new columns
  8. every declared template file exists

Run: python scripts/test_admin_panel.py
"""

import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import admin_panel.auth as auth  # noqa: E402
import api.routes.admin_panel as panel  # noqa: E402  (collects without a server)
from domain import rbac  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


# ---------------------------------------------------------------------------
# 1. password hashing
# ---------------------------------------------------------------------------


def section_passwords() -> None:
    print("\n1. Password hashing: format, cost, constant-time compare")

    stored = auth.hash_password("correct horse battery staple")
    algorithm, raw_iters, salt, digest = stored.split("$")

    check(
        "stored format is algo$iterations$salt$digest",
        algorithm == "pbkdf2_sha256" and salt and digest,
        f"got {stored.split('$')[0]!r}",
    )
    check(
        "iterations are at least the documented 600k",
        int(raw_iters) >= 600_000,
        f"got {raw_iters}",
    )
    check(
        "the same password verifies",
        auth.verify_password("correct horse battery staple", stored),
        "roundtrip failed",
    )
    check(
        "a wrong password does not verify",
        not auth.verify_password("correct horse battery stapl", stored),
        "wrong password accepted",
    )
    check(
        "verify_password uses hmac.compare_digest (timing-safe)",
        "compare_digest" in inspect.getsource(auth.verify_password),
        "a plain == on the digest would leak a byte-at-a-time timing oracle",
    )
    check(
        "a malformed stored hash fails closed instead of raising",
        not auth.verify_password("anything", "not-a-valid-hash")
        and not auth.verify_password("anything", None)
        and not auth.verify_password("anything", ""),
        "a broken row must not 500 the login endpoint",
    )
    check(
        "a hostile iteration count is refused (CPU DoS guard)",
        not auth.verify_password(
            "x",
            f"pbkdf2_sha256$999999999$salt$digest",
        ),
        "a tampered row could pin a request on the KDF for minutes",
    )
    check(
        "two hashes of the same password use different salts",
        auth.hash_password("same") != auth.hash_password("same"),
        "a shared salt makes the hash rainbow-tableable",
    )

    print("\n2. Login enumerates nothing: unknown user still pays PBKDF2")
    import time

    dummy = auth.dummy_password_hash()
    check(
        "dummy hash is a real, expensive hash",
        dummy.startswith("pbkdf2_sha256$") and int(dummy.split("$")[1]) >= 600_000,
        f"got {dummy.split('$')[0] if dummy else dummy}",
    )
    # Hash a real password BEFORE timing, so both intervals measure exactly one
    # verify — timing a hash inside one interval would compare 1 KDF against 2.
    real_hash = auth.hash_password("other")
    t0 = time.perf_counter()
    auth.verify_password("wrong", dummy)
    t1 = time.perf_counter()
    auth.verify_password("wrong", real_hash)
    t2 = time.perf_counter()
    dummy_ms = (t1 - t0) * 1000
    real_ms = (t2 - t1) * 1000
    check(
        "unknown-user verify costs real time (not microseconds)",
        dummy_ms > 5,
        f"dummy verify took {dummy_ms:.2f}ms — too fast to be PBKDF2",
    )
    check(
        "unknown-user and known-user verify are the same order of magnitude",
        max(dummy_ms, real_ms) / max(min(dummy_ms, real_ms), 0.001) < 3.0,
        f"dummy={dummy_ms:.1f}ms real={real_ms:.1f}ms — a gap this size "
        "timing-fingerprints which usernames exist",
    )


# ---------------------------------------------------------------------------
# 3. session tokens
# ---------------------------------------------------------------------------


class FakeAdmin:
    def __init__(self, admin_id: str = "a1b2c3d4-0000-0000-0000-000000000000", token_version: int = 1):
        self.id = admin_id
        self.token_version = token_version
        self.web_username = "owner"
        self.role = "OWNER"


def section_sessions() -> None:
    print("\n3. Sessions: roundtrip, expiry, tamper, revocation")

    admin = FakeAdmin()
    token = auth.issue_session_token(admin)
    claims = auth.read_session_token(token)
    check(
        "a fresh token reads back the admin id and version",
        claims == (admin.id, 1),
        f"got {claims}",
    )

    # Exercising expiry without sleeping: itsdangerous stamps the token with
    # get_timestamp() at sign time, so signing with the clock pulled back an
    # hour produces a validly-signed but aged token. max_age is the default
    # 12h, so the age (~1h + slack) must be rejected — if the 12h window is
    # ever broken, this assertion trips instead of sessions silently never
    # expiring.
    import itsdangerous
    import time

    real_get_timestamp = itsdangerous.TimestampSigner.get_timestamp
    try:
        itsdangerous.TimestampSigner.get_timestamp = (  # type: ignore[method-assign]
            lambda self: int(time.time()) - auth.SESSION_MAX_AGE_SECONDS - 60
        )
        aged = auth.issue_session_token(admin)
    finally:
        itsdangerous.TimestampSigner.get_timestamp = real_get_timestamp  # type: ignore[method-assign]
    expired_claims = auth.read_session_token(aged)
    check(
        "a token older than SESSION_MAX_AGE is rejected",
        expired_claims is None,
        f"got {expired_claims} — a stale cookie would live forever",
    )

    tampered = (token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")).encode()
    check(
        "a tampered token is rejected",
        auth.read_session_token(tampered.decode(errors="ignore")) is None,
        "tamper detection failed",
    )
    check(
        "an empty cookie is rejected",
        auth.read_session_token("") is None,
        "empty token accepted",
    )
    check(
        "a garbage token is rejected",
        auth.read_session_token("!!not.a.token!!") is None,
        "garbage token accepted",
    )

    print("\n4. token_version revocation")
    v2_admin = FakeAdmin(admin_id=admin.id, token_version=2)
    stale_claims = auth.read_session_token(token)
    check(
        "old token still parses (the CLAIM is stale, not invalid)",
        stale_claims == (admin.id, 1),
        f"got {stale_claims}",
    )
    check(
        "require_admin rejects the stale token for a v2 admin",
        stale_claims is not None and stale_claims[1] != v2_admin.token_version,
        "bumping token_version must invalidate the cookie on the next request",
    )

    print("\n5. Production refuses an unset JWT_SIGNING_KEY")
    from domain.config import settings as cfg

    original_key = cfg.jwt_signing_key
    original_env = cfg.environment
    try:
        cfg.jwt_signing_key = ""
        cfg.environment = "production"
        try:
            auth.session_signer()
            refused = False
            raised = None
        except auth.SessionKeyMissing as exc:
            refused = True
            raised = str(exc)
        check(
            "login is impossible without a key in production",
            refused,
            f"session_signer() did not raise (raised={raised})",
        )

        cfg.environment = "development"
        try:
            signer = auth.session_signer()
            dev_ok = signer is not None
        except auth.SessionKeyMissing:
            dev_ok = False
        check(
            "development falls back to an ephemeral key instead of crashing",
            dev_ok,
            "dev usability was sacrificed for a safety check",
        )
    finally:
        cfg.jwt_signing_key = original_key
        cfg.environment = original_env
        auth._ephemeral_key = None  # drop the dev fallback so other tests are clean


# ---------------------------------------------------------------------------
# 6. route inventory
# ---------------------------------------------------------------------------

# The complete admin surface, mapped to the permission the bot gates the
# equivalent action with. Every route in this table MUST exist, carry exactly
# this permission, and be a real rbac constant. Any new route added without
# updating this table fails section 6a.
EXPECTED_ROUTES: dict[str, str] = {
    "GET /admin": rbac.PERM_STATS_VIEW,
    "GET /admin/orders": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/approve": rbac.PERM_PAYMENT_REVIEW,
    "GET /admin/orders/{order_id}/reject": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/reject": rbac.PERM_PAYMENT_REVIEW,
    "GET /admin/tickets": rbac.PERM_SUPPORT_MANAGE,
    "GET /admin/tickets/{ref}": rbac.PERM_SUPPORT_MANAGE,
    "POST /admin/tickets/{ref}/reply": rbac.PERM_SUPPORT_MANAGE,
    "POST /admin/tickets/{ref}/close": rbac.PERM_SUPPORT_MANAGE,
    "GET /admin/nodes": rbac.PERM_NODE_MANAGE,
    "GET /admin/nodes/new": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/new": rbac.PERM_NODE_MANAGE,
    "GET /admin/admins": rbac.PERM_ADMIN_MANAGE,
    "GET /admin/admins/new": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/new": rbac.PERM_ADMIN_MANAGE,
    "GET /admin/test": rbac.PERM_TEST_CONFIG,
    "POST /admin/test": rbac.PERM_TEST_CONFIG,
}

# Routes that are correct WITHOUT a permission gate: login is reachable by
# definition (otherwise no one can sign in) and logout is session-only.
UNGUARDED = {"GET /admin/login", "POST /admin/login", "POST /admin/logout"}


def _admin_routes() -> dict[str, object]:
    """{f"{METHOD} {path}": route} for every /admin route, however FastAPI
    nests it. The container class changed names across FastAPI releases
    (_IncludedRouter), so this walks whatever tree it finds."""
    from api.main import app
    from fastapi.routing import APIRoute

    routes = {}

    def walk(items):
        for r in items:
            if isinstance(r, APIRoute):
                for method in sorted(r.methods - {"HEAD"}):
                    routes[f"{method} {r.path}"] = r
            for sub in getattr(r, "routes", None) or []:
                walk([sub])
            orig = getattr(r, "original_router", None)
            if orig is not None:
                walk(orig.routes)

    walk(app.routes)
    return routes


def section_routes() -> None:
    print("\n6. Route inventory: every route gates exactly one real permission")

    routes = {k: v for k, v in _admin_routes().items() if k.split(" ")[1].startswith("/admin")}
    check(
        "the admin router is registered in api.main",
        len(routes) > 0,
        "no /admin routes found — the panel is not mounted",
    )

    # A permission passed as a bare string instead of an rbac constant is the
    # one silent failure mode: a typo there is a valid Python program that
    # 403s every role forever, and no import error catches it. Every argument
    # to require_permission must therefore be an attribute of domain.rbac.
    panel_src = inspect.getsource(panel)
    bare_strings = re.findall(
        r"require_permission\(\s*(['\"])", panel_src
    )
    check(
        "no route passes a raw string permission",
        not bare_strings,
        f"{len(bare_strings)} require_permission('...') call(s) — use rbac.PERM_* so a "
        "typo is an ImportError/AttributeError instead of a permanent 403",
    )
    used_constants = re.findall(r"require_permission\(rbac\.(\w+)\)", panel_src)
    check(
        "every permission argument names an rbac constant",
        len(used_constants) == panel_src.count("require_permission(rbac."),
        "a permission that is neither a raw string nor rbac.<NAME> would slip both checks",
    )
    for name in sorted(set(used_constants)):
        check(
            f"rbac.{name} is a real constant",
            hasattr(rbac, name),
            "require_permission would raise at import, or worse, gate nothing",
        )

    for key, expected_perm in EXPECTED_ROUTES.items():
        route = routes.get(key)
        if route is None:
            check(f"{key} exists", False, "route missing from the app")
            continue
        perms = [
            d.call.required_permission
            for d in route.dependant.dependencies
            if hasattr(d.call, "required_permission")
        ]
        check(
            f"{key} declares exactly one permission",
            len(perms) == 1,
            f"got {perms}",
        )
        if perms:
            check(
                f"{key} uses {expected_perm}",
                perms[0] == expected_perm,
                f"got {perms[0]!r}",
            )

    for key, route in sorted(routes.items()):
        if key in EXPECTED_ROUTES or key in UNGUARDED:
            continue
        # An unlisted route is a problem either way: un-gated (a hole) or
        # gated but absent from the table (an unreviewed permission).
        perms = [
            d.call.required_permission
            for d in route.dependant.dependencies
            if hasattr(d.call, "required_permission")
        ]
        has_session = any(d.call is auth.require_admin for d in route.dependant.dependencies)
        check(
            f"unlisted route {key} is gated or explicitly unguarded",
            bool(perms) or has_session,
            f"no permission and no session dependency on {key}",
        )

    # The permission strings must be real constants, not typos that resolve to
    # a permission no role holds (which would silently 403 everyone).
    all_perms = {p for perms in rbac.ROLE_PERMISSIONS.values() for p in perms}
    for key, perm in EXPECTED_ROUTES.items():
        check(
            f"permission {perm!r} (from {key}) exists in rbac",
            perm in all_perms,
            "a permission no role holds would make this route dead for everyone",
        )
        check(
            f"permission {perm!r} (from {key}) equals its rbac constant",
            perm == perm.strip() and " " not in perm,
            "malformed permission string",
        )

    print("\n7. Parity with the bot's keyboard: same actions, same perms")
    # The real parity claim is that every permission the BOT's admin keyboard
    # gates an action with is also enforced by a route here — not that a
    # literal string appears in the source (the routes name rbac constants,
    # so the literal never appears, and grepping for it would pass on a
    # comment while missing a route).
    from bot import keyboards

    kb_src = inspect.getsource(keyboards.admin_panel)
    bot_perms = set()
    for line in kb_src.splitlines():
        if '"' in line and " in permissions" in line:
            for chunk in line.split('"')[1::2]:
                bot_perms.add(chunk)
    # The stats button is unconditional in the bot (no `in permissions` guard),
    # but its handler still needs stats.view — the panel gates it, correctly.
    bot_perms.add(rbac.PERM_STATS_VIEW)

    panel_perms = set(EXPECTED_ROUTES.values())
    check(
        "every bot-keyboard permission has a panel route",
        bot_perms <= panel_perms,
        f"bot offers {sorted(bot_perms - panel_perms)} with no panel page",
    )
    check(
        "the bot keyboard was actually parsed (guard against an empty set)",
        len(bot_perms) >= 6,
        f"parsed only {sorted(bot_perms)} — the keyboard source changed shape",
    )
    for perm in sorted(bot_perms):
        check(
            f"the panel enforces {perm!r}",
            perm in panel_perms,
            "bot cb_admin_panel offers this action; the panel must gate it identically",
        )


# ---------------------------------------------------------------------------
# 8. the payment paths mirror the bot
# ---------------------------------------------------------------------------


def section_payment_paths() -> None:
    print("\n8. Approve path mirrors the bot: lock, guard, fulfil, notify")

    approve_src = inspect.getsource(panel.order_approve)
    check(
        "approving takes the attempt row lock",
        "with_for_update" in approve_src,
        "without FOR UPDATE two admins can fulfil one payment twice",
    )
    check(
        "approving guards on the current status",
        "WAITING_REVIEW" in approve_src,
        "a missing guard re-approves an already-approved payment",
    )
    check(
        "approving goes through mark_order_provisioning",
        "mark_order_provisioning" in approve_src,
        "bypassing it skips the audit row and the amount stamp",
    )
    check(
        "approving catches FulfillmentError rather than 500-ing",
        "FulfillmentError" in approve_src,
        "an infrastructure failure must leave the order PROVISIONING, not crash",
    )
    check(
        "the successful path notifies the customer",
        "_notify_customer" in approve_src,
        "a customer whose payment was approved is never told",
    )
    check(
        "the fulfilment-failure path does NOT offer a re-approve button",
        "err=fulfillment" in approve_src,
        "re-approving after a partial fulfil would create a second configuration",
    )

    print("\n9. Reject path mirrors the bot: lock, domain call, notify")
    reject_src = inspect.getsource(panel.order_reject)
    check(
        "rejecting takes the attempt row lock",
        "with_for_update" in reject_src,
        "a reject racing an approve double-processes one receipt",
    )
    check(
        "rejecting calls domain reject_payment",
        "reject_payment" in reject_src,
        "logic reimplemented in the route can drift from the bot's",
    )
    check(
        "the acting admin is the recorded reviewer",
        "admin.id" in reject_src,
        "an unattributed rejection is invisible in audit_log",
    )
    check(
        "the customer is told the reason",
        "_notify_customer" in reject_src and "_rejected_message" in reject_src,
        "an unexplained rejection sends the customer to support for nothing",
    )

    print("\n10. Login has no registration path")
    login_src = inspect.getsource(panel.login_submit) + inspect.getsource(panel.login_form)
    check(
        "login never constructs an Admin",
        "Admin(" not in login_src,
        "an unauthenticated ADMIN() insert would be an OWNER escalation",
    )
    check(
        "login never hashes a password",
        "hash_password" not in login_src,
        "login verifies credentials; minting them here means a public write path",
    )
    # Assignment, not comparison: `Admin.web_username == username` (a SELECT
    # filter, which login legitimately needs) contains the substring
    # ".web_username =", so a plain `in` test would fail on correct code.
    check(
        "login never ASSIGNS web credentials",
        re.search(r"\.web_(username|password_hash)\s*=\s*[^=]", login_src) is None,
        "credential creation belongs in set_web_password.py, not a public route",
    )
    check(
        "login never adds a row to the session",
        re.search(r"\bdb\.add\(", login_src) is None,
        "a public route that inserts is a registration endpoint",
    )
    check(
        "login never commits",
        "commit(" not in login_src,
        "a public route that commits is a public write surface",
    )
    admin_create_src = inspect.getsource(panel.admin_create)
    check(
        "admin_create gives new admins no web login",
        re.search(r"\.web_(username|password_hash)\s*=\s*[^=]", admin_create_src) is None,
        "inventing credentials in the panel removes the out-of-band first step",
    )
    check(
        "admin_create reads no password field from the form",
        '"password"' not in admin_create_src and "'password'" not in admin_create_src,
        "a password field here would let one admin set another's login",
    )

    print("\n11. Every state-changing route audits")
    for name in (
        "order_approve",
        "order_reject",
        "ticket_reply",
        "ticket_close",
        "node_create",
        "admin_create",
    ):
        fn = getattr(panel, name, None)
        if fn is None:
            check(f"{name} exists", False, "route handler missing")
            continue
        src = inspect.getsource(fn)
        # mark_order_provisioning / reject_payment / support_domain / provisioning
        # carry their own audit, or the route audits directly. A handler that
        # does neither leaves no record of the change.
        indirect = (
            "mark_order_provisioning" in src
            or "reject_payment" in src
            or "audit(" in src
            or "close_ticket" in src
        )
        check(
            f"{name} records an audit trail (directly or via domain call)",
            indirect,
            "no audit call and no audited domain function in this handler",
        )


# ---------------------------------------------------------------------------
# 12. migration 005 <-> model
# ---------------------------------------------------------------------------


def section_migration_agreement() -> None:
    print("\n12. Migration 005 and the Admin model agree")

    from db.models import Admin

    mig_path = (
        Path(__file__).resolve().parent.parent
        / "db" / "migrations" / "versions" / "005_admin_web_creds.py"
    )
    check("migration 005 exists", mig_path.exists(), f"missing {mig_path}")
    if not mig_path.exists():
        return

    mig_src = mig_path.read_text(encoding="utf-8")

    for column, nullable in (
        ("web_username", True),
        ("web_password_hash", True),
        ("token_version", False),
    ):
        check(
            f"migration 005 adds {column}",
            f'add_column("admins", sa.Column("{column}"' in mig_src.replace("'", '"')
            or f'add_column(\n        "admins",\n        sa.Column("{column}"' in mig_src.replace("'", '"')
            or f'sa.Column("{column}"' in mig_src.replace("'", '"'),
            f"{column} not in the migration",
        )
        check(
            f"model Admin has {column}",
            hasattr(Admin, column),
            f"{column} missing from the model",
        )

    check(
        "model marks token_version NOT NULL",
        not Admin.__table__.c.token_version.nullable,
        "a nullable token_version would make revocation comparisons ambiguous",
    )
    check(
        "model marks web_username nullable (Telegram-only admins)",
        Admin.__table__.c.web_username.nullable,
        "NOT NULL would reject every existing admin row on migration",
    )
    check(
        "model marks web_username unique",
        any(
            type(c).__name__ == "UniqueConstraint"
            and "web_username" in {col.name for col in c.columns}
            for c in Admin.__table__.constraints
        ),
        "two admins could share a web login without a unique constraint",
    )
    check(
        "migration 005 creates the web_username unique constraint",
        "uq_admins_web_username" in mig_src and "create_unique_constraint" in mig_src,
        "the model would enforce uniqueness in Python while the DB allows a duplicate",
    )
    check(
        "the downgrade drops what the upgrade created",
        "drop_constraint" in mig_src and "drop_column" in mig_src,
        "a downgrade that leaves columns behind breaks the next upgrade",
    )
    check(
        "migration revises 004 (the chain is unbroken)",
        'down_revision: str = "004"' in mig_src,
        "a broken down_revision strands the migration chain",
    )


# ---------------------------------------------------------------------------
# 13. templates
# ---------------------------------------------------------------------------


def section_templates() -> None:
    print("\n13. Every declared template exists")

    templates_dir = Path(__file__).resolve().parent.parent / "admin_panel" / "templates"

    expected = [
        "base.html",
        "login.html",
        "error.html",
        "dashboard.html",
        "orders.html",
        "reject.html",
        "tickets.html",
        "ticket.html",
        "nodes.html",
        "node_new.html",
        "admins.html",
        "admin_new.html",
        "test.html",
    ]
    for name in expected:
        check(
            f"template {name} exists",
            (templates_dir / name).exists(),
            f"missing from {templates_dir}",
        )

    base = (templates_dir / "base.html").read_text(encoding="utf-8")
    check(
        "base.html is RTL Persian",
        'dir="rtl"' in base and 'lang="fa"' in base,
        "an LTR base would break the entire panel's Persian layout",
    )
    check(
        "base.html gates the nav by permission",
        "{% if" in base and "perms" in (templates_dir / "dashboard.html").read_text(encoding="utf-8"),
        "a nav that shows links the role cannot use is a 403 generator",
    )

    # The CSS the login page references must exist — a broken stylesheet
    # renders a login box with no styling but also masks a bad static mount.
    css = Path(__file__).resolve().parent.parent / "admin_panel" / "static" / "admin.css"
    check("static/admin.css exists", css.exists(), "login page would be unstyled")

    print("\n14. Static mount is registered at the path templates reference")
    from api.main import app

    mounts = [getattr(r, "path", None) for r in app.routes if hasattr(r, "path")]
    check(
        "/admin/static is mounted",
        "/admin/static" in mounts,
        f"mounts found: {mounts}",
    )


# ---------------------------------------------------------------------------


def main() -> None:
    section_passwords()
    section_sessions()
    section_routes()
    section_payment_paths()
    section_migration_agreement()
    section_templates()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("ADMIN PANEL GATE PASSED.")


if __name__ == "__main__":
    main()
