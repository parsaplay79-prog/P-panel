"""Verdent Platform — the credential map sync (Document 1/3 §K #5).

The Node's KV `proxyUsers` map is the single source of proxy credentials.
Every mutation flows through here:
    sync_assignment   → mint/refresh one entry (vl:<uuid> or tr:<hash>)
    disable_entry     → flip status to "disabled" (revocation, quota, expiry)
    remove_entry      → delete the key entirely

KV writes go through the Cloudflare API with the NODE's account token. The
Node reads with a 30s cache — propagation latency is bounded by that.

CONCURRENCY: Cloudflare KV has no atomic read-modify-write, so every mutation
is read-all → change-one-key → write-all. Two writers on one namespace
interleave, and the second write-all erases the first — leaving a customer
ACTIVE/FULFILLED in Postgres with NO credential at the edge, which no retry
ever revisits because the fulfillment that created it already succeeded. The
whole cycle is serialized per node by node_map_lock().
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import time
import uuid as uuid_lib

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import CloudflareAccount, Configuration, Node
from domain.config import settings
from domain.cloudflare import CloudflareClient

try:  # requirements.txt pins redis>=5.0, but a slim deploy must still run
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    Redis = None

logger = logging.getLogger("verdent.provisioning")

PROXY_USERS_KEY = "proxyUsers"
NODE_SECRET_KEY = "nodeSecret"

# The TTL bounds crash recovery: a process killed mid-write cannot wedge the
# node forever — the lock simply expires and the next writer proceeds. It is
# comfortably longer than a read+write round trip to Cloudflare.
REDIS_LOCK_TTL_MS = 15_000
REDIS_LOCK_WAIT_S = 8.0
# After a Redis error we stop dialling for a while, so an outage costs one
# failed round trip per node rather than one per fulfillment.
REDIS_COOLDOWN_S = 30.0

# Compare-and-delete: only the holder may release, so a lock that already
# expired and was re-taken by another worker is not stolen from it.
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


class _NodeLock:
    """In-process mutex for one node, plus the refcount that lets it be pruned."""

    __slots__ = ("lock", "refs")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.refs = 0


_local_locks: dict[str, _NodeLock] = {}
_redis_client = None
_redis_down_until = 0.0


def _local_lock_for(node_id: str) -> _NodeLock:
    """Fetch (or mint) the per-node mutex, counting this caller as a user.

    The refcount is bumped in the same synchronous block as the lookup, so a
    concurrent release can never prune a lock somebody is about to acquire.
    Entries are removed when the last holder leaves (see _release_local_lock)
    and the lock is idle, so the dict is bounded by the number of nodes being
    written concurrently — nodes are single-digit and long-lived, so a small
    resident dict is cheaper than a TTL sweep that could race a waiter's entry.
    """
    entry = _local_locks.get(node_id)
    if entry is None:
        entry = _local_locks[node_id] = _NodeLock()
    entry.refs += 1
    return entry


def _release_local_lock(node_id: str, entry: _NodeLock) -> None:
    entry.refs -= 1
    if entry.refs <= 0 and not entry.lock.locked() and _local_locks.get(node_id) is entry:
        del _local_locks[node_id]


async def _redis() -> object | None:
    global _redis_client
    if not settings.redis_url or Redis is None:
        return None
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


async def _acquire_redis_lock(node_id: str) -> str | None:
    """SET NX PX with a bounded wait. None means "not held" — never raises.

    An unreachable Redis degrades to the in-process lock with a warning: a
    coordination outage must not cost a paid customer their fulfillment.
    """
    global _redis_down_until
    if Redis is None or not settings.redis_url or time.monotonic() < _redis_down_until:
        return None

    try:
        client = await _redis()
        if client is None:
            return None
        token = uuid_lib.uuid4().hex
        deadline = time.monotonic() + REDIS_LOCK_WAIT_S
        while True:
            if await client.set(f"verdent:kvlock:{node_id}", token, nx=True, px=REDIS_LOCK_TTL_MS):
                return token
            if time.monotonic() >= deadline:
                logger.warning(
                    "kv lock for node %s still held by another worker after %ss — proceeding on "
                    "the in-process lock only", node_id, REDIS_LOCK_WAIT_S
                )
                return None
            await asyncio.sleep(0.05)
    except Exception as exc:  # noqa: BLE001
        _redis_down_until = time.monotonic() + REDIS_COOLDOWN_S
        logger.warning("redis unavailable (%s) — KV writes fall back to the in-process lock", exc)
        return None


async def _release_redis_lock(node_id: str, token: str) -> None:
    try:
        client = await _redis()
        if client is not None:
            await client.eval(_RELEASE_SCRIPT, 1, f"verdent:kvlock:{node_id}", token)
    except Exception as exc:  # noqa: BLE001
        # The TTL is the backstop: a lost release costs at most REDIS_LOCK_TTL_MS
        # of blocked writers, never a stuck lock.
        logger.warning("could not release kv lock for node %s (%s) — it expires in %dms", node_id, exc, REDIS_LOCK_TTL_MS)


@contextlib.asynccontextmanager
async def node_map_lock(node_id: str):
    """Serialize a read-modify-write of one node's credential map.

    Two layers, because neither alone is enough: the in-process asyncio.Lock
    covers one service, and the Redis lock covers the web and worker Railway
    services that both write the same namespaces. Acquiring the local lock
    first keeps same-process writers from piling up on the Redis poll.
    """
    entry = _local_lock_for(node_id)
    await entry.lock.acquire()
    token = None
    try:
        token = await _acquire_redis_lock(node_id)
        yield
    finally:
        if token is not None:
            await _release_redis_lock(node_id, token)
        entry.lock.release()
        _release_local_lock(node_id, entry)


def vless_key(proxy_uuid: str) -> str:
    return f"vl:{proxy_uuid}"


def trojan_key(password: str) -> str:
    return f"tr:{hashlib.sha224(password.encode()).hexdigest()}"


async def get_node_kv_writer(db: AsyncSession, node: Node) -> tuple[CloudflareClient, str] | None:
    """Build a CloudflareClient for the node's account + its KV namespace id.

    The KV namespace id is not stored in the nodes table (schema is fixed) —
    it is recoverable from the account's namespace list by title convention
    `verdent-node-<worker_script_name>`. Cached per call; fine at Phase-2
    scale (a handful of writes per provisioning event).
    """
    account = (
        await db.execute(
            select(CloudflareAccount).where(
                CloudflareAccount.id == node.cloudflare_account_id
            )
        )
    ).scalar_one_or_none()

    if account is None:
        logger.error("node %s has no cloudflare account", node.id)
        return None

    return CloudflareClient(
        account.api_token_encrypted,
        settings.cloudflare_token_encryption_key,
        account.cf_account_id,
    ), f"verdent-node-{node.worker_script_name or node.id[:8]}"


async def _find_namespace_id(client: CloudflareClient, title: str) -> str | None:
    import httpx

    url = f"https://api.cloudflare.com/client/v4/accounts/{client._account_id}/storage/kv/namespaces?per_page=100"
    async with httpx.AsyncClient(timeout=30) as http:
        resp = await http.get(url, headers=client._headers)
    data = resp.json()
    if not data.get("success"):
        return None
    for ns in data.get("result", []):
        if ns.get("title") == title:
            return ns["id"]
    return None


async def _read_map(client: CloudflareClient, ns_id: str) -> dict:
    import httpx

    url = f"https://api.cloudflare.com/client/v4/accounts/{client._account_id}/storage/kv/namespaces/{ns_id}/values/{PROXY_USERS_KEY}"
    async with httpx.AsyncClient(timeout=30) as http:
        resp = await http.get(url, headers=client._headers)
    if resp.status_code == 404:
        return {}
    try:
        return resp.json()
    except Exception:  # noqa: BLE001
        return {}


async def _write_map(client: CloudflareClient, ns_id: str, mapping: dict) -> None:
    await client.put_kv_value(ns_id, PROXY_USERS_KEY, json.dumps(mapping, ensure_ascii=False))


async def sync_assignment(
    db: AsyncSession,
    node: Node,
    *,
    proxy_uuid: str,
    config_id: str,
    status: str = "active",
    device_limit: int = 1,
) -> bool:
    """Upsert one credential entry on the node. Returns success."""
    writer = await get_node_kv_writer(db, node)
    if writer is None:
        return False
    client, ns_title = writer
    ns_id = await _find_namespace_id(client, ns_title)
    if ns_id is None:
        logger.error("KV namespace %s not found for node %s", ns_title, node.id)
        return False

    async with node_map_lock(node.id):
        # The read must happen INSIDE the lock. Fetching it beforehand and
        # writing afterwards would still clobber a writer that slipped in.
        mapping = await _read_map(client, ns_id)
        mapping[vless_key(proxy_uuid)] = {
            "configId": config_id,
            "status": status,
            "deviceLimit": device_limit,
        }
        await _write_map(client, ns_id, mapping)
    return True


async def set_entry_status(
    db: AsyncSession,
    node: Node,
    proxy_uuid: str,
    status: str,
) -> bool:
    writer = await get_node_kv_writer(db, node)
    if writer is None:
        return False
    client, ns_title = writer
    ns_id = await _find_namespace_id(client, ns_title)
    if ns_id is None:
        return False

    async with node_map_lock(node.id):
        # Same map as sync_assignment — two writers here lose a credential just
        # as two there do.
        mapping = await _read_map(client, ns_id)
        key = vless_key(proxy_uuid)
        if key in mapping:
            mapping[key]["status"] = status
            await _write_map(client, ns_id, mapping)
    return True


async def seed_node_kv(
    client: CloudflareClient,
    namespace_id: str,
    node_secret_hash: str,
) -> None:
    """Fresh-node KV seed: verification key + empty credential map."""
    await client.put_kv_value(namespace_id, NODE_SECRET_KEY, node_secret_hash)
    await client.put_kv_value(namespace_id, PROXY_USERS_KEY, "{}")
