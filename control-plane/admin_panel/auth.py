"""Verdent Platform — web Admin Panel authentication.

Username + password, deliberately independent of Telegram: the panel has to be
usable when the operator has no Telegram client open, and it has to keep working
when the bot token is misconfigured. Three pieces:

1. **Password storage** — PBKDF2-HMAC-SHA256, stdlib only (`hashlib.pbkdf2_hmac`),
   600k iterations, 16-byte random salt per password, stored in Django's
   `algo$iterations$salt$digest` layout so the scheme can be swapped for argon2
   later by changing this one module and re-hashing on next login.

2. **Sessions** — an `itsdangerous.TimestampSigner` token in an HttpOnly cookie,
   signed with `settings.jwt_signing_key`. That key was declared in
   `domain/config.py` and read nowhere; it now has a job. The payload carries
   `admin_id` and the admin's `token_version`, so bumping that column
   invalidates every cookie issued before the bump — the only way to revoke a
   bearer token that has already been copied out of a browser.

3. **Login throttling** — a Redis failure counter per username. Fails OPEN: if
   Redis is unreachable the panel still lets a legitimate operator in, because
   the alternative (locking every admin out whenever Redis blips) is a worse
   outcome than a slowed brute-force. PBKDF2's ~200ms per attempt is the real
   throttle; this counter only makes a sustained online attack impractical.

Nothing here ever writes an admin. Credentials are set out-of-band by
`scripts/set_web_password.py`, because a "create the first admin" page would be
an unauthenticated privilege escalation — whoever reached the panel first would
become OWNER.
"""

import base64
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone
from typing import Awaitable, Callable

from fastapi import Depends, Request
from itsdangerous import BadSignature, SignatureExpired, TimestampSigner
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.base import get_db
from db.models import Admin
from domain import rbac
from domain.config import settings

logger = logging.getLogger("verdent.admin_panel.auth")

# ---------------------------------------------------------------------------
# Passwords
# ---------------------------------------------------------------------------

HASH_ALGORITHM = "pbkdf2_sha256"
HASH_ITERATIONS = 600_000
SALT_BYTES = 16

# A stored hash with an absurd iteration count would let a tampered database row
# turn one login attempt into a CPU denial-of-service against the web service —
# the request would run the KDF for minutes. The ceiling is far above anything
# we write and far below "hangs the worker".
MAX_HASH_ITERATIONS = 5_000_000


def _pbkdf2(password: str, salt: str, iterations: int) -> str:
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    )
    return base64.b64encode(digest).decode("ascii").rstrip("=")


def hash_password(password: str) -> str:
    """`pbkdf2_sha256$<iterations>$<salt>$<digest>`. Salt is per-password."""
    salt = secrets.token_hex(SALT_BYTES)
    return f"{HASH_ALGORITHM}${HASH_ITERATIONS}${salt}${_pbkdf2(password, salt, HASH_ITERATIONS)}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time compare. Never raises — a malformed row means "no".

    A corrupted or truncated `web_password_hash` must fail the login, not
    return a 500: the difference between "wrong password" and "your account is
    broken" is not something an unauthenticated caller should be able to probe,
    and a 500 in the login path is a bug report nobody can act on.
    """
    if not stored:
        return False
    try:
        algorithm, raw_iterations, salt, expected = stored.split("$")
        iterations = int(raw_iterations)
    except (ValueError, AttributeError):
        logger.warning("malformed stored password hash — refusing login")
        return False

    if algorithm != HASH_ALGORITHM:
        logger.warning("stored password hash uses unknown algorithm %r", algorithm)
        return False
    if iterations <= 0 or iterations > MAX_HASH_ITERATIONS:
        logger.warning("stored password hash has an unusable iteration count")
        return False

    return hmac.compare_digest(_pbkdf2(password, salt, iterations), expected)


# A hash to verify against when the username does not exist, so a failed login
# costs the same whether or not the account is real. Without it, "user not
# found" returns in microseconds and a valid username can be enumerated by
# timing alone. Computed once, lazily, so importing this module stays cheap.
_dummy_hash: str | None = None


def dummy_password_hash() -> str:
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(16))
    return _dummy_hash


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

COOKIE_NAME = "verdent_admin"
SESSION_SALT = "verdent-admin-session"
SESSION_MAX_AGE_SECONDS = 12 * 60 * 60  # one working day

# Used only in development, when JWT_SIGNING_KEY is unset. Regenerated on every
# process start, so a dev restart logs everyone out — which is the honest
# behaviour: without a configured key there is nothing to persist sessions
# against. In production an unset key is a hard refusal (see session_signer).
_ephemeral_key: str | None = None


class SessionKeyMissing(RuntimeError):
    """JWT_SIGNING_KEY is unset in a non-development environment."""


def _signing_key() -> str:
    global _ephemeral_key
    key = settings.jwt_signing_key
    if key:
        return key

    if settings.environment == "development":
        if _ephemeral_key is None:
            _ephemeral_key = secrets.token_hex(32)
            logger.warning(
                "JWT_SIGNING_KEY is not set — using a temporary key for admin "
                "sessions. Sessions end when this process restarts. Set "
                "JWT_SIGNING_KEY before deploying."
            )
        return _ephemeral_key

    # Production with no key: refuse rather than sign sessions with a value the
    # attacker also knows (or with a per-process random one that would look
    # configured while silently logging everyone out on every deploy).
    raise SessionKeyMissing("JWT_SIGNING_KEY is not set")


def session_signer() -> TimestampSigner:
    return TimestampSigner(_signing_key(), salt=SESSION_SALT)


def issue_session_token(admin: Admin) -> str:
    """The cookie value: `<admin_id>.<token_version>`, signed and timestamped."""
    payload = f"{admin.id}.{admin.token_version}"
    return session_signer().sign(payload).decode("ascii")


def read_session_token(token: str, *, max_age: int = SESSION_MAX_AGE_SECONDS) -> tuple[str, int] | None:
    """(admin_id, token_version) from a valid token, else None.

    Every failure mode — bad signature, expired, tampered, malformed payload —
    collapses to None. The caller cannot tell them apart, and does not need to:
    all four mean "log in again".
    """
    try:
        raw = session_signer().unsign(token, max_age=max_age).decode("ascii")
    except (BadSignature, SignatureExpired, SessionKeyMissing):
        return None
    except Exception:  # noqa: BLE001 — any other signing failure is also "invalid"
        logger.exception("unexpected failure reading an admin session token")
        return None

    admin_id, _, version = raw.rpartition(".")
    if not admin_id or not version.isdigit():
        return None
    return admin_id, int(version)


def set_session_cookie(response, admin: Admin) -> None:
    """HttpOnly + SameSite=Lax + Secure outside development.

    SameSite=Lax is load-bearing, not cosmetic: it is what stops a third-party
    page from making the browser POST to /admin/orders/{id}/approve with the
    admin's cookie attached. There is no CSRF token in this panel, so this
    attribute is the entire cross-site request defence — see the note in
    api/routes/admin_panel.py.
    """
    response.set_cookie(
        COOKIE_NAME,
        issue_session_token(admin),
        max_age=SESSION_MAX_AGE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=settings.environment != "development",
        path="/admin",
    )


def clear_session_cookie(response) -> None:
    response.delete_cookie(COOKIE_NAME, path="/admin")


# ---------------------------------------------------------------------------
# Login throttling (Redis; fails open)
# ---------------------------------------------------------------------------

LOGIN_FAIL_PREFIX = "verdent:admin:login:fail:"
LOGIN_MAX_FAILURES = 5
LOGIN_FAILURE_WINDOW_SECONDS = 900  # 15 min


def _failure_key(username: str) -> str:
    # Normalized so "Owner" and "owner " cannot each get their own budget.
    return f"{LOGIN_FAIL_PREFIX}{username.strip().lower()}"


async def login_failure_count(username: str) -> int:
    """0 when unknown — including when Redis is unreachable (fails open)."""
    from domain.security import get_redis

    try:
        raw = await get_redis().get(_failure_key(username))
    except Exception as exc:  # noqa: BLE001 — Redis down is not a login failure
        logger.warning("login throttle unavailable (%s) — allowing the attempt", exc)
        return 0
    try:
        return int(raw or 0)
    except (TypeError, ValueError):
        return 0


async def record_login_failure(username: str) -> None:
    from domain.security import get_redis

    try:
        client = get_redis()
        key = _failure_key(username)
        count = await client.incr(key)
        # Expire is set on every increment, not only the first: a counter whose
        # TTL was lost (eviction, a restart mid-window) would otherwise lock
        # the account permanently.
        await client.expire(key, LOGIN_FAILURE_WINDOW_SECONDS)
        logger.info("failed admin login for %r (%s this window)", username, count)
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not record login failure for %r: %s", username, exc)


async def clear_login_failures(username: str) -> None:
    from domain.security import get_redis

    try:
        await get_redis().delete(_failure_key(username))
    except Exception as exc:  # noqa: BLE001
        logger.warning("could not clear login failures for %r: %s", username, exc)


# ---------------------------------------------------------------------------
# Request-time identity
# ---------------------------------------------------------------------------


class NotAuthenticated(Exception):
    """No usable session cookie. Handled as a redirect to the login page."""


class Forbidden(Exception):
    """Signed in, but the role lacks the permission this route requires."""

    def __init__(self, permission: str) -> None:
        super().__init__(f"missing permission: {permission}")
        self.permission = permission


async def require_admin(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Admin:
    """The signed-in admin, or raise NotAuthenticated.

    The admin row is re-read on every request rather than trusted from the
    cookie: a cookie issued before a role change or a deletion must not keep
    working. `token_version` is checked at the same time, so a bumped version
    invalidates the session on the very next request.
    """
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise NotAuthenticated()

    claims = read_session_token(token)
    if claims is None:
        raise NotAuthenticated()

    admin_id, token_version = claims
    admin = (
        await db.execute(select(Admin).where(Admin.id == admin_id))
    ).scalar_one_or_none()

    if admin is None:
        raise NotAuthenticated()
    if admin.token_version != token_version:
        # Revoked: the cookie predates a logout-everywhere / password change.
        logger.info("admin %s presented a revoked session (v%s != v%s)", admin_id, token_version, admin.token_version)
        raise NotAuthenticated()
    if not admin.web_username:
        # The web login was removed but a cookie survived. Same treatment.
        raise NotAuthenticated()

    # Stashed for the template context processor (admin_panel/templating.py),
    # so every page can render the sidebar and the signed-in identity without
    # each route passing them through.
    request.state.admin = admin
    return admin


def require_permission(permission: str) -> Callable[..., Awaitable[Admin]]:
    """Dependency factory gating a route on one RBAC permission.

    Mirrors how the bot gates its own handlers (`rbac.permissions_for(role)`),
    so the two surfaces cannot drift into different answers to "may this admin
    do this". The marker attribute is what scripts/test_admin_panel.py reads to
    prove every route declares a real permission rather than trusting review.
    """

    async def _dependency(admin: Admin = Depends(require_admin)) -> Admin:
        if not rbac.role_has_permission(admin.role, permission):
            raise Forbidden(permission)
        return admin

    _dependency.required_permission = permission  # type: ignore[attr-defined]
    return _dependency


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
