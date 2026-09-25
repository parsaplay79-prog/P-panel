"""Verdent Platform — hashing & HMAC helpers (no secrets in the data plane).

Node ingest auth (Document 5):
- At provisioning, a random secret is generated per Node. The Control Plane
  stores `H = sha256(secret + NODE_HMAC_SECRET_PEPPER)` in
  `nodes.node_secret_hash` and mirrors `H` into the Node's own KV.
- The Node signs every ingest/health request:
      signature = hex(hmac_sha256(H, `${nodeId}.${timestamp}.${nonce}.${body}`))
- The Control Plane verifies using `node_secret_hash` (it holds H), checks
  the timestamp window, and enforces nonce uniqueness per Node+window.

Result: a compromised Node can forge usage/health reports only for itself —
never for another Node, never against the Control Plane's own API tokens.

The uniqueness half of that is enforced by consume_nonce(), called from
verify_node_auth() once the signature has checked out. Redis is the store: it
is the only shared state we already run, and the nonce only has to outlive the
signature window, so nothing durable is needed.
"""

import hashlib
import hmac
import logging
import time
from typing import Protocol

import redis.asyncio as redis

from domain.config import settings

logger = logging.getLogger("verdent.security")

SIGNATURE_TTL_SECONDS = 120

# Nonce keys carry a TTL slightly longer than the signature window: a nonce can
# only ever be presented alongside a timestamp still inside that window, so
# once the window has closed nothing can replay it and the key can go.
NONCE_TTL_SECONDS = SIGNATURE_TTL_SECONDS + 30
NONCE_PREFIX = "verdent:nonce:"

_client: redis.Redis | None = None


class NonceStoreUnavailable(RuntimeError):
    """Redis is unreachable or unconfigured, so no nonce can be recorded."""


class SupportsSetNX(Protocol):
    """The slice of the Redis client nonce storage depends on."""

    async def set(self, name: str, value: str, *, nx: bool, ex: int) -> object: ...


def get_redis() -> redis.Redis:
    """Shared client; from_url does no I/O, so this never blocks startup.

    One client (one connection pool) for the process — the alternative,
    building a pool per signed request, would grow without bound.
    """
    global _client
    if _client is None:
        _client = redis.from_url(
            settings.redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=1.0,
            socket_timeout=1.0,
        )
    return _client


async def consume_nonce(
    store: SupportsSetNX,
    node_id: str,
    nonce: str,
    ttl_seconds: int = NONCE_TTL_SECONDS,
) -> bool:
    """Record `nonce` for `node_id`; True if it is fresh (or must be tolerated).

    The key is node-scoped, so one node's traffic can never burn another's
    nonces, and the value is fixed — only existence is meaningful. A refused
    SET NX means this exact signed request is already recorded: a replay.

    Redis unreachable: raise NonceStoreUnavailable unless the operator set
    NODE_REPLAY_FAIL_OPEN, in which case log and accept — see the config
    docstring for why rejecting is the default.
    """
    try:
        stored = await store.set(
            f"{NONCE_PREFIX}{node_id}:{nonce}",
            "1",
            nx=True,
            ex=ttl_seconds,
        )
    except Exception as exc:  # noqa: BLE001 — any Redis failure is unavailability
        if settings.node_replay_fail_open:
            logger.error(
                "nonce store unavailable (redis=%s): %s. Failing OPEN per "
                "NODE_REPLAY_FAIL_OPEN=true — replay protection is OFF until Redis "
                "returns.",
                settings.redis_url,
                exc,
            )
            return True
        logger.error(
            "nonce store unavailable (redis=%s): %s. Failing CLOSED: rejecting "
            "signed ingest. Set NODE_REPLAY_FAIL_OPEN=true to accept instead.",
            settings.redis_url,
            exc,
        )
        raise NonceStoreUnavailable("nonce store unavailable") from exc

    return stored is not None


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def derive_node_secret_hash(secret: str) -> str:
    """H = sha256(secret + pepper) — stored both in Postgres and Node KV."""
    return sha256_hex(secret + settings.node_hmac_secret_pepper)


def compute_expected_signature(node_secret_hash: str, node_id: str, timestamp: str, nonce: str, body: bytes) -> str:
    mac = hmac.new(
        node_secret_hash.encode("utf-8"),
        f"{node_id}.{timestamp}.{nonce}.".encode("utf-8") + body,
        hashlib.sha256,
    )
    return mac.hexdigest()


def secure_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def timestamp_within_window(timestamp_ms: str) -> bool:
    try:
        ts = int(timestamp_ms) / 1000.0
    except (TypeError, ValueError):
        return False
    return abs(time.time() - ts) <= SIGNATURE_TTL_SECONDS
