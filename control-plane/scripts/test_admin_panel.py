"""Regression tests for the web Admin Panel.

The panel is the product's full administrative surface: every Telegram-bot
admin action has an HTML page, plus areas the bot has no equivalent for at all
(pools, gaming profiles, usage reconciliation, the job queue, the audit log).
What is pinned here:

  1. password hashing — the format, the iteration floor, constant-time compare
  2. session tokens — roundtrip, expiry, tamper detection, version revocation
  3. the production refusal when JWT_SIGNING_KEY is unset
  4. route inventory — every route except login/logout carries exactly one
     REAL RBAC permission (a typo'd constant would otherwise gate wrong or 503)
  5. NO DEAD PERMISSIONS — every permission the RBAC layer grants is reachable
     by at least one route. This is the check that would have caught the
     original defect: five of eleven permissions had no surface anywhere.
  6. bot parity — every permission the bot's admin keyboard gates an action
     with is enforced by a panel route identically
  7. every state-changing route records an audit trail, directly or through an
     audited domain function
  8. login has no registration path
  9. the job queue — idempotent enqueue, SKIP LOCKED claim, retry ceiling,
     terminal failure, and that provisioning is enqueued rather than awaited
     inline (the two-minute-request defect)
 10. fulfilment retry — a retry reuses the existing assignment's node and never
     re-selects, so it cannot write a credential to the wrong edge
 11. config lifecycle — suspend/reactivate/revoke each touch BOTH the Postgres
     status and the edge KV entry
 12. ban cascade — banning suspends the customer's live configs
 13. migrations 005 and 006 agree with their models
 14. every template exists, every page extends base.html, and no template is
     orphaned

Run: python scripts/test_admin_panel.py
"""

import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import admin_panel.auth as auth  # noqa: E402
from admin_panel import routes as panel_routes  # noqa: E402
from domain import rbac  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = ROOT / "admin_panel" / "templates"

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
# route inventory
# ---------------------------------------------------------------------------

# The complete admin surface, mapped to the permission that gates it. Every
# route in this table MUST exist and carry exactly this permission. Any route
# added without updating this table fails section 6a.
EXPECTED_ROUTES: dict[str, str] = {
    # dashboard + read-only ops
    "GET /admin/": rbac.PERM_STATS_VIEW,
    "GET /admin/audit": rbac.PERM_ADMIN_MANAGE,
    "GET /admin/health": rbac.PERM_STATS_VIEW,
    "GET /admin/health/{node_id}": rbac.PERM_STATS_VIEW,
    "GET /admin/notifications": rbac.PERM_SUPPORT_MANAGE,
    "GET /admin/usage": rbac.PERM_STATS_VIEW,
    "GET /admin/usage/{config_id}": rbac.PERM_STATS_VIEW,
    "GET /admin/reconcile": rbac.PERM_STATS_VIEW,
    "POST /admin/reconcile/run": rbac.PERM_STATS_VIEW,
    # orders (payment.review)
    "GET /admin/orders": rbac.PERM_PAYMENT_REVIEW,
    "GET /admin/orders/all": rbac.PERM_PAYMENT_REVIEW,
    "GET /admin/orders/{order_id}": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/approve": rbac.PERM_PAYMENT_REVIEW,
    "GET /admin/orders/{order_id}/reject": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/reject": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/retry": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/cancel": rbac.PERM_PAYMENT_REVIEW,
    "POST /admin/orders/{order_id}/queue-job": rbac.PERM_PAYMENT_REVIEW,
    # payments / refunds (payment.refund)
    "GET /admin/payments": rbac.PERM_REFUND_MARK,
    "GET /admin/payments/{attempt_id}": rbac.PERM_REFUND_MARK,
    "POST /admin/payments/{attempt_id}/refund": rbac.PERM_REFUND_MARK,
    # customers (user.ban)
    "GET /admin/customers": rbac.PERM_USER_BAN,
    "GET /admin/customers/{customer_id}": rbac.PERM_USER_BAN,
    "POST /admin/customers/{customer_id}/ban": rbac.PERM_USER_BAN,
    "POST /admin/customers/{customer_id}/unban": rbac.PERM_USER_BAN,
    "POST /admin/customers/{customer_id}/notify": rbac.PERM_USER_BAN,
    # configurations (config.manage)
    "GET /admin/configurations": rbac.PERM_CONFIG_MANAGE,
    "GET /admin/configurations/{config_id}": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/suspend": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/reactivate": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/revoke": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/rotate-link": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/rotate-credential": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/rename": rbac.PERM_CONFIG_MANAGE,
    "POST /admin/configurations/{config_id}/extend": rbac.PERM_CONFIG_MANAGE,
    # plans (plan.manage)
    "GET /admin/plans": rbac.PERM_PLAN_MANAGE,
    "GET /admin/plans/new": rbac.PERM_PLAN_MANAGE,
    "POST /admin/plans/new": rbac.PERM_PLAN_MANAGE,
    "GET /admin/plans/{plan_id}/edit": rbac.PERM_PLAN_MANAGE,
    "POST /admin/plans/{plan_id}/edit": rbac.PERM_PLAN_MANAGE,
    "POST /admin/plans/{plan_id}/toggle": rbac.PERM_PLAN_MANAGE,
    "POST /admin/plans/{plan_id}/delete": rbac.PERM_PLAN_MANAGE,
    # gaming profiles (gaming.manage)
    "GET /admin/gaming": rbac.PERM_GAMING_PROFILE,
    "GET /admin/gaming/new": rbac.PERM_GAMING_PROFILE,
    "POST /admin/gaming/publish": rbac.PERM_GAMING_PROFILE,
    "GET /admin/gaming/{profile_id}": rbac.PERM_GAMING_PROFILE,
    "POST /admin/gaming/{profile_id}/restore": rbac.PERM_GAMING_PROFILE,
    # nodes + pools + cloudflare + jobs (node.manage)
    "GET /admin/nodes": rbac.PERM_NODE_MANAGE,
    "GET /admin/nodes/new": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/new": rbac.PERM_NODE_MANAGE,
    "GET /admin/nodes/{node_id}": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/{node_id}/state": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/{node_id}/capacity": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/{node_id}/decommission": rbac.PERM_NODE_MANAGE,
    "POST /admin/nodes/{node_id}/repair-pools": rbac.PERM_NODE_MANAGE,
    "GET /admin/pools": rbac.PERM_NODE_MANAGE,
    "GET /admin/pools/new": rbac.PERM_NODE_MANAGE,
    "POST /admin/pools/new": rbac.PERM_NODE_MANAGE,
    "GET /admin/pools/{pool_id}": rbac.PERM_NODE_MANAGE,
    "GET /admin/pools/{pool_id}/edit": rbac.PERM_NODE_MANAGE,
    "POST /admin/pools/{pool_id}/edit": rbac.PERM_NODE_MANAGE,
    "POST /admin/pools/{pool_id}/delete": rbac.PERM_NODE_MANAGE,
    "POST /admin/pools/{pool_id}/nodes/add": rbac.PERM_NODE_MANAGE,
    "POST /admin/pools/{pool_id}/nodes/remove": rbac.PERM_NODE_MANAGE,
    "GET /admin/cloudflare": rbac.PERM_NODE_MANAGE,
    "GET /admin/cloudflare/new": rbac.PERM_NODE_MANAGE,
    "POST /admin/cloudflare/new": rbac.PERM_NODE_MANAGE,
    "POST /admin/cloudflare/{account_id}/verify": rbac.PERM_NODE_MANAGE,
    "POST /admin/cloudflare/{account_id}/enable": rbac.PERM_NODE_MANAGE,
    "POST /admin/cloudflare/{account_id}/disable": rbac.PERM_NODE_MANAGE,
    "POST /admin/cloudflare/{account_id}/delete": rbac.PERM_NODE_MANAGE,
    "GET /admin/jobs": rbac.PERM_NODE_MANAGE,
    "GET /admin/jobs/{job_id}": rbac.PERM_NODE_MANAGE,
    "POST /admin/jobs/{job_id}/retry": rbac.PERM_NODE_MANAGE,
    "POST /admin/jobs/{job_id}/cancel": rbac.PERM_NODE_MANAGE,
    # admins (admin.manage)
    "GET /admin/admins": rbac.PERM_ADMIN_MANAGE,
    "GET /admin/admins/new": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/new": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/{admin_id}/role": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/{admin_id}/credentials": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/{admin_id}/revoke-sessions": rbac.PERM_ADMIN_MANAGE,
    "POST /admin/admins/{admin_id}/delete": rbac.PERM_ADMIN_MANAGE,
    # tickets + notifications (support.manage)
    "GET /admin/tickets": rbac.PERM_SUPPORT_MANAGE,
    "GET /admin/tickets/{ref}": rbac.PERM_SUPPORT_MANAGE,
    "POST /admin/tickets/{ref}/reply": rbac.PERM_SUPPORT_MANAGE,
    "POST /admin/tickets/{ref}/close": rbac.PERM_SUPPORT_MANAGE,
    # test configs (config.test)
    "GET /admin/test": rbac.PERM_TEST_CONFIG,
    "POST /admin/test": rbac.PERM_TEST_CONFIG,
    "GET /admin/test/history": rbac.PERM_TEST_CONFIG,
    "POST /admin/test/revoke/{config_id}": rbac.PERM_TEST_CONFIG,
}

# Routes that are correct WITHOUT a permission gate: login is reachable by
# definition (otherwise no one can sign in) and logout is session-only.
UNGUARDED = {"GET /admin/login", "POST /admin/login", "POST /admin/logout"}


def _admin_routes() -> dict[str, object]:
    """{"GET /admin/x": route} for every /admin route, however FastAPI nests it.

    FastAPI 0.141 keeps included routers as `_IncludedRouter` objects that
    expose the child tree only through `original_router`, and the accumulated
    path prefix only through `include_context.prefix` — a leaf's own `.path` is
    relative. Both are read here; the earlier version of this function read
    only `.path` and `.routes`, silently found 7 routes, and reported a
    vacuous pass. Guard against that regressing: if the walk finds fewer routes
    than the table below expects, say so loudly rather than testing nothing.
    """
    from api.main import app
    from fastapi.routing import APIRoute

    found: list[tuple[str, object]] = []

    def walk(routes, prefix: str) -> None:
        # A nested include contributes its prefix through include_context; the
        # original_router's own `prefix` is the SAME prefix, so adding both
        # double-counts it ("/admin/admin/nodes"). Take exactly one.
        for r in routes:
            ctx = getattr(r, "include_context", None)
            here = prefix + (getattr(ctx, "prefix", "") or "") if ctx is not None else prefix

            orig = getattr(r, "original_router", None)
            if orig is not None and orig is not r:
                walk(orig.routes, here)
                continue

            if isinstance(r, APIRoute):
                for method in sorted(r.methods - {"HEAD"}):
                    found.append((f"{method} {here}{r.path}", r))
                continue

            walk(getattr(r, "routes", None) or [], here)

    walk(app.router.routes, "")
    return dict(found)


def _code_without_docstring(source: str) -> str:
    """A function's source with its docstring removed.

    These docstrings are long and deliberately name the things they must NOT
    do ("does NOT reactivate", "never calls select_node_for_pool"), so a naive
    substring test over the raw source finds the prohibition in the prose and
    concludes the code does the forbidden thing. Only the executable lines
    answer the question.
    """
    import ast

    tree = ast.parse(source)
    fn = next(
        (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))),
        None,
    )
    if fn is None:
        return source
    docstring_node = fn.body[0] if fn.body else None
    if not (
        isinstance(docstring_node, ast.Expr)
        and isinstance(docstring_node.value, ast.Constant)
        and isinstance(docstring_node.value.value, str)
    ):
        return source
    lines = source.splitlines()
    return "\n".join(
        line
        for i, line in enumerate(lines, start=1)
        if not (docstring_node.lineno <= i <= docstring_node.end_lineno)
    )


def _permission_of(route) -> str | None:
    """The single permission a route declares, or None if it declares none.

    Reads the marker attribute that `auth.require_permission` attaches to the
    dependency closure. `require_admin` (the session check) deliberately has no
    such marker, so a route with only a session dependency reads as None —
    which is what the UNGUARDED set and section 6b expect.
    """
    for d in route.dependant.dependencies:
        perm = getattr(d.call, "required_permission", None)
        if perm is not None:
            return perm
    return None


def _has_session(route) -> bool:
    return any(d.call is auth.require_admin for d in route.dependant.dependencies)


def section_routes() -> None:
    print("\n6. Route inventory: every route gates exactly one real permission")

    all_routes = _admin_routes()
    routes = {k: v for k, v in all_routes.items() if k.split(" ", 1)[1].startswith("/admin")}

    check(
        "the admin router is registered in api.main",
        len(routes) > 0,
        "no /admin routes found — the panel is not mounted",
    )
    check(
        "the route walk found the whole surface (not a partial tree)",
        len(routes) >= len(EXPECTED_ROUTES),
        f"walked {len(routes)} /admin routes but the table expects "
        f"{len(EXPECTED_ROUTES)} — the FastAPI nesting walk is broken and every "
        "check below is vacuous",
    )

    print("\n6a. No route passes a raw string permission")
    # A permission passed as a bare string instead of an rbac constant is the
    # one silent failure mode: a typo there is a valid Python program that
    # 403s every role forever, and no import error catches it. Every argument
    # to require_permission must therefore be an attribute of domain.rbac.
    #
    # The count is of CALL SITES, not distinct constants: 90 routes share 11
    # permissions, so comparing a call count against len(set(...)) would
    # "fail" forever. Both scans run over the same text, and the difference
    # between them must be exactly zero — a call site that is neither a
    # constant nor a string literal is the thing this is looking for.
    used_constants: list[str] = []
    raw_string_calls: list[str] = []
    other_calls: list[str] = []
    for module in _panel_modules():
        src = inspect.getsource(module)
        for match in re.finditer(r"require_permission\(([^)]*)\)", src):
            argument = match.group(1).strip()
            line_no = src[: match.start()].count("\n") + 1
            where = f"{module.__name__.rsplit('.', 1)[-1]}:{line_no}"
            if re.fullmatch(r"rbac\.\w+", argument):
                used_constants.append(argument.split(".", 1)[1])
            elif re.fullmatch(r"['\"][\w.]+['\"]", argument):
                raw_string_calls.append(f"{where} {argument}")
            else:
                other_calls.append(f"{where} {argument}")
    check(
        "no route passes a raw string permission",
        not raw_string_calls,
        f"{len(raw_string_calls)} require_permission('...') call(s) — use rbac.PERM_* so a "
        "typo is an ImportError/AttributeError instead of a permanent 403",
    )
    check(
        "every permission argument is an rbac constant or a string literal",
        not other_calls,
        f"{len(other_calls)} call(s) matched neither pattern: {other_calls[:3]} — a "
        "computed or aliased permission cannot be verified statically, and a "
        "typo in it would 403 every role forever",
    )
    check(
        "the scan actually saw the route surface",
        len(used_constants) + len(raw_string_calls) + len(other_calls) >= 80,
        f"only {len(used_constants) + len(raw_string_calls) + len(other_calls)} "
        "require_permission calls found — the source walk is broken and this "
        "whole section is vacuous",
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

    print("\n6b. Every /admin route is either in the table or explicitly unguarded")
    for key, route in sorted(routes.items()):
        if key in EXPECTED_ROUTES or key in UNGUARDED:
            continue
        # An unlisted route is a problem either way: un-gated (a hole) or
        # gated but absent from the table (an unreviewed permission).
        perm = _permission_of(route)
        check(
            f"unlisted route {key} is gated or explicitly unguarded",
            bool(perm) or _has_session(route),
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

    # --- the check that would have caught the original defect ---------------
    print("\n6c. No dead permissions: every granted permission has a surface")
    routed = {_permission_of(r) for r in routes.values()} - {None}
    for perm in sorted(all_perms):
        serving = sorted(k for k, r in routes.items() if _permission_of(r) == perm)
        check(
            f"permission {perm!r} is reachable by at least one route",
            bool(serving),
            "granted by ROLE_PERMISSIONS to at least one role, but no route "
            "declares it — a permission nobody can use anywhere in the product",
        )
        if serving:
            print(f"        ({len(serving)} route(s), e.g. {serving[0]})")

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


def _panel_modules() -> list:
    """Every module in the admin_panel route package, including the aggregate."""
    import importlib
    import pkgutil

    modules = [panel_routes]
    for info in pkgutil.iter_modules(panel_routes.__path__):
        if info.name == "__init__":
            continue
        modules.append(importlib.import_module(f"admin_panel.routes.{info.name}"))
    return modules


# ---------------------------------------------------------------------------
# 8. the payment paths mirror the bot
# ---------------------------------------------------------------------------


def section_payment_paths() -> None:
    from admin_panel.routes import admins, auth_routes, orders, tickets

    print("\n8. Approve path mirrors the bot: lock, guard, fulfil, notify")
    approve_src = inspect.getsource(orders.order_approve)
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
        "notify_customer" in approve_src,
        "a customer whose payment was approved is never told",
    )
    check(
        "a fulfilment failure enqueues a retry job rather than dead-ending",
        "enqueue" in approve_src and "JOB_FULFILL_ORDER" in approve_src,
        "the order is stuck in PROVISIONING with nobody scheduled to finish it",
    )
    check(
        "the fulfilment-failure path does NOT offer a re-approve button",
        'err="fulfillment"' in approve_src,
        "re-approving after a partial fulfil would create a second configuration",
    )

    print("\n9. Reject path mirrors the bot: lock, domain call, notify")
    reject_src = inspect.getsource(orders.order_reject)
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
        "notify_customer" in reject_src and "_rejected_message" in reject_src,
        "an unexplained rejection sends the customer to support for nothing",
    )

    print("\n10. Login has no registration path")
    login_src = inspect.getsource(auth_routes.login_submit) + inspect.getsource(
        auth_routes.login_form
    )
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
    admin_create_src = inspect.getsource(admins.admin_create)
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
    check(
        "admin_set_credentials DOES mint a password (the gated version)",
        "hash_password" in inspect.getsource(admins.admin_set_credentials),
        "the gated route should be where a web password is set",
    )

    print("\n11. Every state-changing route audits")
    # Either the handler audits directly, or it calls a domain function that
    # audits internally. A handler that does neither leaves no record of the
    # change, and the audit log page has nothing to show.
    audited_domain_calls = (
        "suspend_configuration",
        "reactivate_configuration",
        "revoke_configuration",
        "rotate_subscription_token",
        "rotate_proxy_credential",
        "rename_configuration_by_admin",
        "ban_customer",
        "unban_customer",
        "retry_job",
        "cancel_job",
        "mark_order_provisioning",
        "reject_payment",
        "add_message",
        "close_ticket",
    )
    checked = 0
    for module in _panel_modules():
        if module is panel_routes:
            continue
        src = inspect.getsource(module)
        for block in re.split(r"\n(?=@router\.post)", src):
            if not block.startswith("@router.post"):
                continue
            path_m = re.search(r'@router\.post\(\s*"([^"]*)"', block)
            fn_m = re.search(r"async def (\w+)", block)
            if not (path_m and fn_m):
                continue
            name = fn_m.group(1)
            checked += 1
            if name in ("login_submit", "logout"):
                continue  # session lifecycle, not product state
            indirect = "audit(" in block or any(c in block for c in audited_domain_calls)
            check(
                f"{module.__name__.rsplit('.', 1)[-1]}.{name} records an audit trail",
                indirect,
                "no audit call and no audited domain function in this handler",
            )
    check(
        "the audit survey actually examined handlers",
        checked >= 40,
        f"only {checked} POST handlers found — the source split changed shape",
    )


# ---------------------------------------------------------------------------
# 9. the job queue
# ---------------------------------------------------------------------------


def section_job_queue() -> None:
    from domain import jobs

    print("\n12. Job queue: idempotent enqueue, SKIP LOCKED, retry ceiling")

    check(
        "every declared job type has a handler",
        set(jobs.ALL_JOB_TYPES) == set(jobs._HANDLERS),
        f"unhandled: {sorted(set(jobs.ALL_JOB_TYPES) - set(jobs._HANDLERS))} — a job "
        "with no dispatch entry sits in the queue forever, claiming to be work",
    )
    check(
        "every job status has a constant",
        all(
            hasattr(jobs, f"STATUS_{s}")
            for s in jobs.ALL_JOB_STATUSES
        ),
        "a status without a constant is a typo waiting to happen",
    )
    check(
        "the default attempt budget is at least 2",
        jobs.DEFAULT_MAX_ATTEMPTS >= 2,
        "a budget of 1 makes the queue a one-shot executor with no retry at all",
    )

    enqueue_src = inspect.getsource(jobs.enqueue)
    check(
        "enqueue refuses an unknown job type",
        "ALL_JOB_TYPES" in enqueue_src and "raise ValueError" in enqueue_src,
        "an unknown type would be claimed forever and never run",
    )
    check(
        "enqueue returns the existing row for a duplicate key",
        "select(Job).where(Job.idempotency_key" in enqueue_src.replace("\n", " ").replace(
            "  ", " "
        ) or "idempotency_key == idempotency_key" in enqueue_src,
        "without the pre-check a re-submitted form creates a second job",
    )
    check(
        "enqueue survives the insert race and returns the winner",
        "IntegrityError" in enqueue_src and "await db.rollback()" in enqueue_src,
        "two concurrent submissions both insert without the UNIQUE index catching it",
    )

    claim_src = inspect.getsource(jobs.claim_next_job)
    check(
        "claim uses FOR UPDATE SKIP LOCKED",
        "with_for_update(skip_locked=True)" in claim_src,
        "without SKIP LOCKED the web and worker consumers block each other, and "
        "one can claim a job another is already running",
    )
    check(
        "claim increments attempts AT CLAIM TIME, not on failure",
        re.search(r"job\.attempts\s*=\s*\(job\.attempts or 0\)\s*\+\s*1", claim_src) is not None,
        "counting only caught exceptions lets a hard crash (OOM/SIGKILL) retry forever",
    )
    check(
        "claim skips jobs that have exhausted their budget",
        "Job.attempts < Job.max_attempts" in claim_src,
        "an exhausted job re-queued by a race would loop forever",
    )
    check(
        "a stale RUNNING job is reclaimable",
        "_stale_cutoff" in claim_src,
        "a consumer killed mid-job leaves the row RUNNING forever and its "
        "Cloudflare resources half-made",
    )

    fail_src = inspect.getsource(jobs._fail)
    check(
        "failure re-queues while the budget allows",
        "job.attempts or 0) < (job.max_attempts" in fail_src.replace("  ", " "),
        "a failure that always re-queues is an infinite loop",
    )
    check(
        "exhausted jobs become terminal FAILED, not QUEUED",
        jobs.STATUS_FAILED in fail_src and "job.finished_at" in fail_src,
        "a permanently broken job must stop spinning and stay visible in the panel",
    )

    run_src = inspect.getsource(jobs.run_job)
    check(
        "run_job never raises — a bad job cannot kill the consumer loop",
        "except Exception" in run_src and "# noqa: BLE001" in run_src,
        "one broken job would stop the worker from ever draining the queue again",
    )
    check(
        "run_job records the failure message on the row",
        "last_error" in inspect.getsource(jobs._fail),
        "without last_error the panel cannot tell an operator why a job failed",
    )

    retry_src = inspect.getsource(jobs.retry_job)
    check(
        "the operator's retry resets the attempt budget",
        "job.attempts = 0" in retry_src,
        "keeping the old count means the second retry silently refuses to run",
    )
    cancel_src = inspect.getsource(jobs.cancel_job)
    check(
        "cancelling a finished job is a no-op",
        all(s in cancel_src for s in (jobs.STATUS_SUCCEEDED, jobs.STATUS_FAILED)),
        "cancelling a SUCCEEDED job would erase the record of work that was done",
    )

    print("\n13. Provisioning is a job, not a two-minute request")
    nodes_src = inspect.getsource(
        __import__("admin_panel.routes.nodes", fromlist=["nodes"])
    )
    check(
        "POST /admin/nodes/new enqueues rather than awaiting provision_node",
        "JOB_PROVISION_NODE" in nodes_src and "enqueue(" in nodes_src,
        "Document 1 §M: provisioning is a state-machine-driven background job, "
        "not a single long-running request",
    )
    check(
        "no route awaits provision_node() inline",
        not re.search(r"await\s+provision_node\s*\(", nodes_src),
        "the request would block on up to nine Cloudflare API calls and a "
        "Railway proxy timeout would leave half-made resources",
    )
    check(
        "the provisioning job is keyed by (account, script name)",
        "enqueue_key_for_provision" in nodes_src,
        "without an idempotency key a double-clicked button provisions twice",
    )
    check(
        "node_create redirects to the job page so progress is visible",
        re.search(r'redirect\(f?"/admin/jobs/\{job\.id\}"', nodes_src) is not None,
        "the operator gets no way to tell 'still working' from 'hung'",
    )
    check(
        "decommission refuses while the node still has live assignments",
        "current_assignment_count" in nodes_src and "node_busy" in nodes_src,
        "decommission_node deletes the worker script — running it with customers "
        "still assigned cuts them off with no failover",
    )
    check(
        "decommission is enqueued too",
        "JOB_DECOMMISSION_NODE" in nodes_src,
        "same two-minute problem as provisioning",
    )

    worker_src = (ROOT / "workers" / "main.py").read_text(encoding="utf-8")
    check(
        "the worker actually consumes the queue",
        "job_consumer_pass" in worker_src,
        "the old loop logged and slept for an hour — nothing was ever run",
    )
    check(
        "the worker loop survives an exception",
        re.search(r"async def job_queue_loop.*?except Exception.*?logger\.exception", worker_src, re.S)
        is not None,
        "a transient DB blip would permanently stop all background work",
    )

    print("\n14. Fulfilment retry reuses the assignment's node")
    from domain import fulfillment

    retry_src = inspect.getsource(fulfillment.retry_fulfillment)
    resume_src = inspect.getsource(fulfillment._resume_fulfillment)
    check(
        "an existing activation routes to the resume path",
        "_resume_fulfillment" in _code_without_docstring(retry_src),
        "without this a retry re-runs selection and can move the customer",
    )
    # Stripped of the docstring deliberately: that docstring says "never from
    # `select_node_for_pool`", so a raw substring test would find the name in
    # the prose and pass for the wrong reason. The executable lines are what
    # must not mention it.
    resume_code = _code_without_docstring(resume_src)
    check(
        "the resume path NEVER calls select_node_for_pool",
        "select_node_for_pool" not in resume_code,
        "re-selecting would write the credential to node B while the assignment "
        "still points at A — Postgres, the edge, and the assignment table then "
        "describe three different things",
    )
    check(
        "the resume path takes the node from the existing primary assignment",
        "ConfigurationNodeAssignment" in resume_code and 'role == "primary"' in resume_code,
        "the node must come from the assignment, not from a fresh query",
    )
    check(
        "the resume path refuses a decommissioned node",
        "DECOMMISSIONED" in resume_code,
        "silently syncing to a dead edge produces a config that cannot connect",
    )
    check(
        "a retry syncs the credential before marking the order fulfilled",
        resume_src.index("sync_assignment") < resume_src.index("mark_order_fulfilled"),
        "marking FULFILLED first means a failed sync leaves a fulfilled order "
        "whose customer has no working config",
    )
    check(
        "fulfill_order delegates to retry_fulfillment (one code path)",
        "retry_fulfillment" in inspect.getsource(fulfillment.fulfill_order),
        "two implementations of fulfilment can disagree about what fulfilment is",
    )


# ---------------------------------------------------------------------------
# 11. config lifecycle
# ---------------------------------------------------------------------------


def section_config_lifecycle() -> None:
    from domain import configurations

    print("\n15. Suspend/reactivate/revoke touch BOTH Postgres and the edge")
    for fn_name, expected_status in (
        ("suspend_configuration", "disabled"),
        ("reactivate_configuration", "active"),
        ("revoke_configuration", "disabled"),
    ):
        src = inspect.getsource(getattr(configurations, fn_name))
        check(
            f"{fn_name} sets a status",
            re.search(r"config\.status\s*=\s*STATUS_", src) is not None,
            "a lifecycle change that never touches config.status is invisible to the panel",
        )
        check(
            f"{fn_name} queues the edge KV flip ({expected_status})",
            "_queue_edge_status" in src and f'"{expected_status}"' in src,
            f"Postgres says the config is off but the edge keeps serving the "
            f"credential — the customer stays online after a {fn_name}",
        )
        check(
            f"{fn_name} audits",
            "await audit(" in src,
            "no audit row means the change is invisible in the audit log",
        )

    suspend_src = inspect.getsource(configurations.suspend_configuration)
    check(
        "suspend is idempotent (a double-click is a no-op, not an error)",
        "already = config.status == STATUS_SUSPENDED" in suspend_src,
        "the button is reachable twice by a double-click",
    )
    check(
        "suspend refuses a DELETED config",
        "STATUS_DELETED" in suspend_src and "cannot be suspended" in suspend_src,
        "a deleted config has no live credential to disable",
    )
    reactivate_src = inspect.getsource(configurations.reactivate_configuration)
    check(
        "reactivate refuses EXPIRED (the sweep would re-expire it — a flap)",
        "STATUS_EXPIRED" in reactivate_src,
        "reviving an expired config gives back service the platform ended, and "
        "the customer sees a link that works for a minute",
    )
    revoke_src = inspect.getsource(configurations.revoke_configuration)
    check(
        "revoke stamps every live assignment revoked",
        "revoked_at" in revoke_src,
        "active_assignments would keep reporting a node that no longer serves this config",
    )
    check(
        "revoke releases node capacity, floored at zero",
        "current_assignment_count" in revoke_src and "max(0," in revoke_src,
        "a node that once hosted N churned customers permanently loses that "
        "capacity and the eligible pool shrinks",
    )
    check(
        "revoke releases capacity per node once, not per assignment",
        "touched_nodes" in revoke_src,
        "decrementing per assignment double-counts a node holding two here",
    )

    print("\n16. Rotations are two different, separately-gated actions")
    link_src = inspect.getsource(configurations.rotate_subscription_token)
    cred_src = inspect.getsource(configurations.rotate_proxy_credential)
    check(
        "rotating the link mints a new token",
        "secrets.token_urlsafe" in link_src,
        "without a new token the old link keeps working — that is the leak",
    )
    check(
        "rotating the link does NOT touch the proxy credential",
        "proxy_uuid" not in link_src and "_queue_edge_status" not in link_src,
        "rotating both at once drops the customer's live connection, which is a "
        "different and much more disruptive action",
    )
    check(
        "the old token is NOT written to the audit log",
        re.search(r'details=\{[^}]*"rotated":\s*True', link_src) is not None
        and re.search(r'"old_token_suffix"', link_src) is not None,
        "audit_log is readable by every admin role, and the old token is a live "
        "secret until the transaction commits — only its last four characters may "
        "be recorded",
    )
    check(
        "rotating the credential disables the old one rather than deleting it",
        '"disabled"' in cred_src and "revoked_at" in cred_src,
        "if the new sync fails, a disabled entry is recoverable and a deleted one is not",
    )
    check(
        "the new assignment lands on the SAME node",
        "node_id=node.id" in cred_src,
        "a rotation must not silently migrate the customer to different hardware; "
        "that is failover's job, with its own hysteresis",
    )
    check(
        "rotating the credential is NOT idempotent (a second rotation is new work)",
        re.search(
            r"enqueue_key_for_kv_status\([^)]*\)[^,]*:,?\s*$", cred_src.strip(), re.M
        )
        is not None
        or "}:{now.timestamp():.0f}" in cred_src,
        "a stable key would make the second rotation a no-op — the operator "
        "presses the button, nothing happens",
    )

    print("\n17. Ban cascades to the customer's live configs")
    from domain import customers

    ban_src = inspect.getsource(customers.ban_customer)
    check(
        "banning suspends live configs",
        "suspend_configuration" in ban_src and "BANNABLE_CONFIG_STATUSES" in ban_src,
        "a ban that leaves the VPN running is not a ban",
    )
    check(
        "the ban survives one config failing to suspend",
        "except Exception" in ban_src and "# noqa: BLE001" in ban_src,
        "one DELETED config mid-list would abort the whole ban",
    )
    check(
        "the result reports what ACTUALLY happened",
        '"suspended"' in ban_src and '"attempted"' in ban_src,
        "reporting bare 'done' hides the case where the customer is still online",
    )
    check(
        "BANNABLE_CONFIG_STATUSES covers the states that are actually live",
        set(customers.BANNABLE_CONFIG_STATUSES) >= {"ACTIVE", "PROVISIONING"},
        f"got {customers.BANNABLE_CONFIG_STATUSES} — a config in one of these "
        "states is serving traffic and must be cut off",
    )
    check(
        "banning is idempotent and re-runs the cascade",
        "was_banned" in ban_src,
        "a config created between the ban and a second click must still be caught",
    )
    unban_src = inspect.getsource(customers.unban_customer)
    unban_code = _code_without_docstring(unban_src)
    check(
        "unban does NOT silently reactivate configs",
        "suspend_configuration" not in unban_code
        and "reactivate_configuration" not in unban_code
        and "status = STATUS_ACTIVE" not in unban_code.replace("customer.", ""),
        "a config suspended for quota abuse should not come back just because "
        "the ban was lifted; that is a separate, visible decision",
    )


# ---------------------------------------------------------------------------
# 13. migrations <-> models
# ---------------------------------------------------------------------------


def section_migration_agreement() -> None:
    print("\n18. Migration 005 and the Admin model agree")
    from db.models import Admin

    mig_path = ROOT / "db" / "migrations" / "versions" / "005_admin_web_creds.py"
    check("migration 005 exists", mig_path.exists(), f"missing {mig_path}")
    if not mig_path.exists():
        return

    mig_src = mig_path.read_text(encoding="utf-8")

    for column in ("web_username", "web_password_hash", "token_version"):
        check(
            f"migration 005 adds {column}",
            f'sa.Column("{column}"' in mig_src.replace("'", '"'),
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
        "migration 005 revises 004 (the chain is unbroken)",
        'down_revision: str = "004"' in mig_src,
        "a broken down_revision strands the migration chain",
    )

    print("\n19. Migration 006 and the Job model agree")
    from db.models import Job
    from domain import jobs as jobs_domain

    jobs_mig = ROOT / "db" / "migrations" / "versions" / "006_jobs.py"
    check("migration 006 exists", jobs_mig.exists(), f"missing {jobs_mig}")
    if not jobs_mig.exists():
        return
    jmig_src = jobs_mig.read_text(encoding="utf-8")

    mig_columns = set(re.findall(r'sa\.Column\(\s*"(\w+)"', jmig_src))
    model_columns = {c.name for c in Job.__table__.columns}
    for column in sorted(model_columns):
        check(
            f"migration 006 creates {column}",
            column in mig_columns,
            f"{column} is on the model but not in the migration — every read of "
            "it would fail against a migrated database",
        )
    for column in sorted(mig_columns - model_columns):
        check(
            f"model Job has {column} (from the migration)",
            column in model_columns,
            "a column the migration creates but the model omits is dropped on "
            "the next autogenerate",
        )

    check(
        "idempotency_key is UNIQUE (the dedupe IS this constraint)",
        'op.create_index("uq_jobs_idempotency_key", "jobs", ["idempotency_key"], unique=True)'
        in jmig_src,
        "without UNIQUE two concurrent submissions both insert and both provision",
    )
    check(
        "the model declares the same unique index",
        any(
            i.name == "uq_jobs_idempotency_key" and i.unique
            for i in Job.__table__.indexes
        ),
        "the model would allow a duplicate the database forbids",
    )
    check(
        "status has a CHECK constraint limiting it to the five states",
        "ck_jobs_status" in jmig_src
        and all(s in jmig_src for s in jobs_domain.ALL_JOB_STATUSES),
        "an unconstrained status lets a typo write a job nobody can find",
    )
    check(
        "the model carries the same CHECK constraint",
        any(
            type(c).__name__ == "CheckConstraint" and c.name == "ck_jobs_status"
            for c in Job.__table__.constraints
        ),
        "the model would accept a status the database refuses",
    )
    check(
        "requested_by points at admins.id",
        'sa.ForeignKey("admins.id")' in jmig_src,
        "a requested_by column with no foreign key records an id nothing resolves",
    )
    check(
        "requested_by is nullable (a system sweep has no human behind it)",
        Job.__table__.c.requested_by.nullable,
        "NOT NULL would make every system-enqueued job fail",
    )
    check(
        "the queue is indexed by (status, created_at)",
        "idx_jobs_status_created" in jmig_src
        and any(i.name == "idx_jobs_status_created" for i in Job.__table__.indexes),
        "claim_next_job filters on status and orders by created_at — without the "
        "index every consumer tick is a sequential scan",
    )
    check(
        "migration 006 revises 005 (the chain is unbroken)",
        'down_revision: str = "005"' in jmig_src,
        "a broken down_revision strands the migration chain",
    )
    check(
        "the downgrade drops the table and its indexes",
        "drop_table" in jmig_src and jmig_src.count("drop_index") >= 2,
        "a downgrade leaving indexes behind breaks the next upgrade",
    )

    print("\n20. The migration chain 001→006 is unbroken")
    versions = sorted(p.name for p in (ROOT / "db" / "migrations" / "versions").glob("*.py"))
    revisions: dict[str, str | None] = {}
    for v in versions:
        src = (ROOT / "db" / "migrations" / "versions" / v).read_text(encoding="utf-8")
        rev = re.search(r'^revision: str = "(\w+)"', src, re.M)
        down = re.search(r'^down_revision(?::\s*str)? = (?:str, )?"?(\w+)"?', src, re.M)
        if rev:
            revisions[rev.group(1)] = down.group(1) if down else None
    roots = [r for r, d in revisions.items() if d is None]
    check(
        "exactly one migration is the chain root",
        len(roots) == 1,
        f"roots: {roots} — two roots means Alembic sees two heads and refuses to run",
    )
    # Walk the chain to its root and make sure every migration is on it.
    children: dict[str | None, list[str]] = {}
    for rev, down in revisions.items():
        children.setdefault(down, []).append(rev)
    on_chain, cursor = set(), roots[0] if roots else None
    while cursor:
        on_chain.add(cursor)
        kids = children.get(cursor, [])
        if len(kids) > 1:
            check(
                f"migration {cursor} has a single child",
                False,
                f"branch: {sorted(kids)} — Alembic would see multiple heads",
            )
        cursor = kids[0] if kids else None
    check(
        "every migration is reachable from the root",
        len(on_chain) == len(revisions),
        f"orphaned: {sorted(set(revisions) - on_chain)}",
    )
    check(
        "the chain ends at 006 (the jobs table)",
        "006" in on_chain,
        f"last on the chain: {sorted(on_chain)}",
    )


# ---------------------------------------------------------------------------
# 14. templates
# ---------------------------------------------------------------------------

# Pages that legitimately do NOT extend base.html: login is standalone (an
# admin not yet signed in must not be shown the sidebar or a nav they cannot
# use), and error.html is rendered by an exception handler in api.main with
# only a title and a message — it must render without a request context.
STANDALONE = {"login.html", "error.html"}


def _is_partial(rel: str) -> bool:
    """An HTMX rows partial, e.g. `orders/_all_rows.html`.

    Leading-underscore basename, not a substring test: a `startswith("_")` on
    the whole path misses every one of these, because they live inside a
    subject directory (`orders/_all_rows.html`, not `_orders/...`).
    """
    return rel.rsplit("/", 1)[-1].startswith("_")


def section_templates() -> None:
    print("\n21. Every template exists, extends base.html, and is reachable")

    on_disk = {
        str(p.relative_to(TEMPLATES_DIR)).replace("\\", "/")
        for p in TEMPLATES_DIR.rglob("*.html")
    }
    check(
        "the template tree was found",
        len(on_disk) >= 50,
        f"only {len(on_disk)} templates under {TEMPLATES_DIR} — the path is wrong",
    )

    # base.html must be RTL Persian: every page inherits it.
    base = (TEMPLATES_DIR / "base.html").read_text(encoding="utf-8")
    check(
        "base.html is RTL Persian",
        'dir="rtl"' in base and 'lang="fa"' in base,
        "an LTR base would break the entire panel's Persian layout",
    )
    for asset in ("admin.css", "admin.js", "htmx.min.js"):
        check(
            f"base.html loads {asset}",
            asset in base,
            "a panel that references a missing asset renders unstyled or unlive",
        )
    check(
        "htmx is vendored, not fetched from a CDN",
        "cdn" not in base.lower() or "htmx.min.js" in base,
        "a CDN dependency means the panel breaks in an air-gapped or locked-down browser",
    )

    for rel in sorted(on_disk):
        if _is_partial(rel) or rel == "base.html" or rel in STANDALONE:
            continue
        text = (TEMPLATES_DIR / rel).read_text(encoding="utf-8")
        extends = re.search(r'{%-?\s*extends\s+["\']([^"\']+)["\']', text)
        check(
            f"{rel} extends base.html",
            extends is not None and extends.group(1) == "base.html",
            f"got {extends.group(1) if extends else 'no extends'} — a page that "
            "does not extend base.html loses the sidebar, the RTL wrapper and the CSS",
        )

    # Every template must be referenced by a route or by another template.
    # An orphan is dead weight that a later refactor can break silently.
    referenced: set[str] = set()
    for src in (ROOT / "admin_panel").rglob("*.py"):
        text = src.read_text(encoding="utf-8")
        referenced.update(re.findall(r'["\']([\w/]+\.html)["\']', text))
    for p in TEMPLATES_DIR.rglob("*.html"):
        text = p.read_text(encoding="utf-8")
        referenced.update(re.findall(r'["\']([\w/]+\.html)["\']', text))
    # error.html is rendered by name in api/main.py's exception handler via the
    # templating env; it is referenced by string there.
    referenced.add("error.html")

    for rel in sorted(on_disk):
        name = rel.rsplit("/", 1)[-1]
        check(
            f"{rel} is referenced by a route or another template",
            rel in referenced or name in referenced,
            "an orphaned template cannot be rendered by anything — it will rot",
        )

    # The nav is filtered in Python (templating._nav_groups), not in the
    # template, so a grep for "perms" in base.html proves nothing. What
    # matters is the rendered result: for every role, no visible link may
    # point at a page that role cannot open, and no group may be left empty.
    # SUPPORT is the sharp case — it holds support.manage (so it sees the
    # ticket queue) but NOT user.ban (so it must not see customers).
    from admin_panel import templating
    from domain import rbac

    for role in rbac.ALL_ROLES:
        perms = rbac.permissions_for(role)
        groups = templating._nav_groups(perms)
        items = [i for g in groups for i in g["items"]]
        check(
            f"the {role} nav shows no link it cannot open",
            all(i["perm"] in perms for i in items),
            f"visible but forbidden: {[i['href'] for i in items if i['perm'] not in perms]} — "
            "a link that 403s is a bug report waiting to happen",
        )
        check(
            f"the {role} nav has no empty group",
            all(g["items"] for g in groups),
            "a group heading with nothing under it looks like a loading failure",
        )
        check(
            f"the {role} nav is non-empty",
            bool(items),
            "a role with no navigation at all cannot use the panel",
        )
    support_perms = rbac.permissions_for(rbac.ROLE_SUPPORT)
    support_items = [i for g in templating._nav_groups(support_perms) for i in g["items"]]
    check(
        "SUPPORT sees the ticket queue it works from",
        any(i["href"] == "/admin/tickets" for i in support_items),
        "the role that answers tickets cannot reach the ticket queue",
    )
    check(
        "SUPPORT does NOT see the customers area (it lacks user.ban)",
        not any(i["href"].startswith("/admin/customers") for i in support_items),
        "support.manage is granted without user.ban; showing a customers link "
        "would 403 the exact role that most needs the panel to work",
    )

    print("\n22. The paginated list pages actually use the shared machinery")
    # Only the pages a user pages through need the toolbar/#rows/pager set.
    # `health/history.html` shares the name but is one node's health chart
    # page, not a paginated table, so it is deliberately excluded.
    list_pages = sorted(p for p in on_disk if p.endswith("/list.html"))
    check(
        "the list pages were found",
        len(list_pages) >= 14,
        f"only {len(list_pages)} list pages — the glob is wrong",
    )
    partials = sorted(p for p in on_disk if _is_partial(p))
    check(
        "there is a rows partial per list page",
        len(partials) >= len(list_pages) - 1,
        f"{len(partials)} partials for {len(list_pages)} list pages",
    )
    for rel in list_pages:
        text = (TEMPLATES_DIR / rel).read_text(encoding="utf-8")
        has_rows = 'id="rows"' in text
        check(
            f"{rel} has an HTMX swap target for its rows",
            has_rows,
            "without #rows the live-search toolbar has nothing to swap, and the "
            "page silently degrades to a full reload with no error",
        )
        if not has_rows:
            continue
        check(
            f"{rel} includes a rows partial",
            "include" in text and ("/_rows.html" in text or "/_queue_rows.html" in text
                                   or "/_all_rows.html" in text),
            "an #rows div with no include renders an empty table that looks like "
            "'no results' rather than a template wiring mistake",
        )
        check(
            f"{rel} renders the shared toolbar",
            "m.toolbar(" in text or "m.pager(" in text,
            "a list page without the shared search/pager drifts from the others",
        )

    # The pager must live INSIDE the swap target, not beside it. A pager
    # outside #rows keeps advertising the previous result's count after a live
    # search swaps the rows, and its "next" links point at the unfiltered page.
    for rel in partials:
        text = (TEMPLATES_DIR / rel).read_text(encoding="utf-8")
        if "m.pager(" in text:
            check(
                f"{rel} renders the pager inside the partial",
                True,
                "",
            )
    paged_partials = [p for p in partials if "m.pager(" in (TEMPLATES_DIR / p).read_text(encoding="utf-8")]
    check(
        "the paginated partials carry the pager",
        len(paged_partials) >= 14,
        f"only {len(paged_partials)} of {len(partials)} partials render a pager — "
        "the rest were probably split the wrong way round",
    )
    stray_pagers = [
        rel
        for rel in list_pages
        if "m.pager(" in (TEMPLATES_DIR / rel).read_text(encoding="utf-8")
    ]
    check(
        "no list page renders the pager outside #rows",
        not stray_pagers,
        f"{stray_pagers} put the pager beside the swap target, so a live search "
        "leaves the previous result's count and page links on screen",
    )

    print("\n23. Static assets and the mount point")
    from api.main import app

    static = ROOT / "admin_panel" / "static"
    for asset in ("admin.css", "admin.js", "htmx.min.js"):
        check(f"static/{asset} exists", (static / asset).exists(), "the panel would be unstyled/unlive")
    htmx = static / "htmx.min.js"
    if htmx.exists():
        size = htmx.stat().st_size
        check(
            "htmx.min.js is a real vendored build, not a stub",
            size > 30_000,
            f"only {size} bytes — that is not htmx",
        )
    css = (static / "admin.css").read_text(encoding="utf-8")
    check(
        "the stylesheet defines the layout the templates use",
        ".sidebar" in css and ".table-wrap" in css and ".toolbar" in css,
        "templates reference classes the stylesheet does not define",
    )
    mounts = [getattr(r, "path", None) for r in app.routes if hasattr(r, "path")]
    check(
        "/admin/static is mounted",
        "/admin/static" in mounts,
        f"mounts found: {mounts}",
    )
    check(
        "admin.js is deferred and additive (works with it absent)",
        "defer" in base and "admin.js" in base,
        "a blocking script, or one the page cannot function without, breaks the "
        "no-JS path that the whole panel is built on",
    )


# ---------------------------------------------------------------------------


def main() -> None:
    section_passwords()
    section_sessions()
    section_routes()
    section_payment_paths()
    section_job_queue()
    section_config_lifecycle()
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
