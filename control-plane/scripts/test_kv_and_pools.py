"""Regression test for the KV lost-update race and the two pool defects.

1. Two concurrent sync_assignment() calls on ONE node used to interleave their
   read-all → write-all cycles: the second write carried a map fetched before
   the first existed, so one customer was FULFILLED in Postgres with no
   credential at the edge. Pinned here with a fake KV client that yields
   control between read and write, which is exactly the window.

2. pools.max_customers_per_node was written once at seed and never read, so
   pools could not cap anything; admission only saw the node's own limit.

3. current_assignment_count was only ever decremented on failover, so slots
   held by expired/suspended/deleted configs leaked and the eligible pool
   drained to nothing. release_stale_node_capacity() must be idempotent —
   running the sweep twice may not double-decrement.

Run: python scripts/test_kv_and_pools.py
"""

import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import domain.kv_sync as kv_sync  # noqa: E402
from domain.kv_sync import (  # noqa: E402
    _local_locks,
    set_entry_status,
    sync_assignment,
    vless_key,
)
from domain.pools import node_eligible, release_stale_node_capacity  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} - {detail}")
        print(f"  FAIL  {name} - {detail}")


# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class _Result:
    def __init__(self, items):
        self._items = list(items)

    def scalars(self):
        return self

    def all(self):
        return list(self._items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None

    def one(self):
        return self._items[0]


class FakeKVClient:
    """Just enough CloudflareClient for the credential-map cycle.

    The value is stored as TEXT (KV is a string store, same as the real
    put_kv_value), and every read/write awaits a zero-second sleep. That
    yield is what makes the lost update reproducible: without the lock, both
    callers read the empty map before either writes it.
    """

    def __init__(self, account_id="acct-1", value: str | None = None):
        self._account_id = account_id
        self._headers = {}
        self._value = value if value is not None else "{}"
        self.writes: list[dict] = []
        self.max_concurrent_writers = 0
        self._in_flight = 0

    async def put_kv_value(self, namespace_id: str, key: str, value: str) -> None:
        self._in_flight += 1
        self.max_concurrent_writers = max(self.max_concurrent_writers, self._in_flight)
        await asyncio.sleep(0)  # the read→write window
        self._value = value
        self.writes.append(json.loads(value))
        self._in_flight -= 1


def _install_fake_kv(monkey_store: dict) -> FakeKVClient:
    """Point the three Cloudflare touch points at one in-memory client."""
    client = FakeKVClient()
    monkey_store["client"] = client

    async def get_node_kv_writer(db, node):
        return client, f"verdent-node-{node.id}"

    async def find_namespace_id(client, title):
        return f"ns-{title}"

    async def read_map(client, ns_id):
        await asyncio.sleep(0)
        try:
            return json.loads(client._value)
        except Exception:  # noqa: BLE001
            return {}

    async def write_map(client, ns_id, mapping):
        await client.put_kv_value(ns_id, kv_sync.PROXY_USERS_KEY, json.dumps(mapping))

    async def no_redis():
        return None  # keep the test off Redis whatever the machine has

    kv_sync.get_node_kv_writer = get_node_kv_writer
    kv_sync._find_namespace_id = find_namespace_id
    kv_sync._read_map = read_map
    kv_sync._write_map = write_map
    kv_sync._redis = no_redis
    kv_sync._redis_down_until = 0.0
    return client


class FakeNode:
    def __init__(self, node_id="node-1", count=0, cap=3):
        self.id = node_id
        self.state = "ONLINE"
        self.current_assignment_count = count
        self.max_assignment_count = cap
        self.capability_tags = ["general"]
        self.health_score = 100
        self.cloudflare_account_id = "acct-1"
        self.worker_script_name = node_id


class FakePool:
    def __init__(self, cap=3, min_health=50, strategy="least_loaded"):
        self.id = "pool-1"
        self.name = "default"
        self.max_customers_per_node = cap
        self.min_health_score = min_health
        self.selection_strategy = strategy


class FakeAssignment:
    def __init__(self, assignment_id, node_id, config_id, revoked_at=None):
        self.id = assignment_id
        self.node_id = node_id
        self.configuration_id = config_id
        self.revoked_at = revoked_at


class FakeConfig:
    def __init__(self, config_id, status="ACTIVE"):
        self.id = config_id
        self.status = status


class FakeCapacityDB:
    """Answers the two shapes release_stale_node_capacity() issues.

    It holds the same store across calls and does NOT re-filter between runs,
    which is what a real second sweep looks like: the stale assignment is
    still there, still non-revoked, and its config still not ACTIVE.
    """

    def __init__(self, assignments, live_counts, nodes):
        self._assignments = assignments
        self._live_counts = live_counts
        self._nodes = nodes
        self.commits = 0

    async def execute(self, query):
        rendered = str(query)
        if "count(" in rendered:
            return _Result([(node_id, n) for node_id, n in self._live_counts.items()])
        if "FROM nodes" in rendered:
            return _Result(self._nodes)
        if "configuration_node_assignments" in rendered:
            return _Result(self._assignments)
        raise AssertionError(f"unexpected query: {rendered}")

    def add(self, obj):
        pass

    async def commit(self):
        self.commits += 1


# ---------------------------------------------------------------------------
# 1. KV lost-update race
# ---------------------------------------------------------------------------


async def test_no_lost_update() -> None:
    print("\n1. Two concurrent sync_assignment calls on one node both survive")
    store: dict = {}
    _install_fake_kv(store)
    client: FakeKVClient = store["client"]
    node = FakeNode()

    results = await asyncio.gather(
        sync_assignment(None, node, proxy_uuid="uuid-A", config_id="cfg-A"),
        sync_assignment(None, node, proxy_uuid="uuid-B", config_id="cfg-B"),
    )

    final = json.loads(client._value)
    check("both calls reported success", results == [True, True], f"got {results}")
    check(
        "credential A survived",
        vless_key("uuid-A") in final,
        f"map is {sorted(final)} - one customer is FULFILLED with no edge credential",
    )
    check(
        "credential B survived",
        vless_key("uuid-B") in final,
        f"map is {sorted(final)} - one customer is FULFILLED with no edge credential",
    )
    check("final map holds exactly 2 entries", len(final) == 2, f"got {len(final)}: {sorted(final)}")
    check(
        "read-modify-write never overlapped",
        client.max_concurrent_writers == 1,
        f"peak concurrent writers = {client.max_concurrent_writers}",
    )
    check(
        "the two writes are not byte-identical (a real interleaving happened)",
        len({json.dumps(w, sort_keys=True) for w in client.writes}) == 2,
        f"writes = {client.writes}",
    )


async def test_set_entry_status_is_serialized() -> None:
    print("\n2. set_entry_status participates in the same lock")
    store: dict = {}
    _install_fake_kv(store)
    client: FakeKVClient = store["client"]
    node = FakeNode()

    await sync_assignment(None, node, proxy_uuid="uuid-A", config_id="cfg-A")
    await sync_assignment(None, node, proxy_uuid="uuid-B", config_id="cfg-B")

    await asyncio.gather(
        set_entry_status(None, node, "uuid-A", "disabled"),
        set_entry_status(None, node, "uuid-B", "disabled"),
    )

    final = json.loads(client._value)
    check("both entries still present", len(final) == 2, f"got {sorted(final)}")
    check(
        "both statuses flipped",
        all(final[vless_key(u)]["status"] == "disabled" for u in ("uuid-A", "uuid-B")),
        f"got {final}",
    )


async def test_redis_outage_does_not_break_fulfillment() -> None:
    print("\n3. An unreachable Redis degrades to the in-process lock")
    store: dict = {}
    _install_fake_kv(store)
    client: FakeKVClient = store["client"]
    node = FakeNode()

    async def dead_redis():
        raise ConnectionError("redis is down")

    kv_sync._redis = dead_redis
    kv_sync._redis_down_until = 0.0
    try:
        result = await sync_assignment(
            None, node, proxy_uuid="uuid-C", config_id="cfg-C"
        )
    finally:
        kv_sync._redis_down_until = 0.0

    check("fulfillment still succeeded", result is True, f"got {result}")
    check("credential written anyway", vless_key("uuid-C") in json.loads(client._value), "missing entry")


async def test_lock_registry_does_not_grow() -> None:
    print("\n4. The per-node lock registry is pruned, not accumulated")
    store: dict = {}
    _install_fake_kv(store)
    node = FakeNode()
    before = len(_local_locks)

    for i in range(5):
        await sync_assignment(None, node, proxy_uuid=f"u{i}", config_id=f"c{i}")

    after = len(_local_locks)
    check(
        "no lock entries leaked across 5 sequential writes",
        after == before,
        f"dict went {before} -> {after} entries",
    )


# ---------------------------------------------------------------------------
# 2. The pool cap
# ---------------------------------------------------------------------------


def test_pool_cap_binds() -> None:
    print("\n5. min(node cap, pool cap) governs admission")
    node = FakeNode(count=2, cap=3)

    check(
        "pool cap of 5 cannot loosen the node's own cap of 3",
        node_eligible(FakeNode(count=3, cap=3), FakePool(cap=5)) is False,
        "a pool raised the node past max_assignment_count",
    )
    check(
        "the node's own cap still admits at count 1",
        node_eligible(FakeNode(count=1, cap=3), FakePool(cap=5)) is True,
        "false negative - eligible node was rejected",
    )
    check(
        "a tighter pool cap of 1 binds ahead of the node's 3",
        node_eligible(node, FakePool(cap=1)) is False,
        "pool cap of 1 was ignored at count=2",
    )
    check(
        "the tighter pool still admits at count 0",
        node_eligible(FakeNode(count=0, cap=3), FakePool(cap=1)) is True,
        "false negative - pool cap of 1 rejected an empty node",
    )
    check(
        "an exact hit is a full node",
        node_eligible(FakeNode(count=1, cap=3), FakePool(cap=1)) is False,
        "count == cap should be full",
    )

    # The old code only ever read the node's cap: at count 2 with the pool
    # capped at 1 it happily returned True.
    print("\n6. Regression guard - the old node-only gate is gone")
    check(
        "count 2 against pool cap 1 is rejected (old code said eligible)",
        node_eligible(FakeNode(count=2, cap=3), FakePool(cap=1)) is False,
        "pool.max_customers_per_node is not being enforced",
    )
    check(
        "the pre-existing gates still apply",
        node_eligible(FakeNode(count=0, cap=3), FakePool(cap=3, min_health=90)) is True
        and node_eligible(FakeNode(count=0, cap=3), FakePool(cap=3, min_health=90), "gaming") is False,
        "capability or health-floor gate regressed",
    )


# ---------------------------------------------------------------------------
# 3. Capacity release
# ---------------------------------------------------------------------------


def _capacity_fixture() -> tuple[FakeCapacityDB, list[FakeNode]]:
    nodes = [FakeNode("node-1", count=3, cap=3), FakeNode("node-2", count=1, cap=3)]
    # node-1: 2 still-active configs, 1 expired → the counter lies by 1.
    # node-2: its only config was deleted → the counter lies by 1.
    live = {"node-1": 2, "node-2": 0}
    stale = [
        FakeAssignment("a-1", "node-1", "cfg-live-1"),
        FakeAssignment("a-2", "node-1", "cfg-live-2"),
        FakeAssignment("a-3", "node-1", "cfg-expired"),
        FakeAssignment("a-4", "node-2", "cfg-deleted"),
    ]
    return FakeCapacityDB(stale, live, nodes), nodes


async def test_capacity_release_idempotent() -> None:
    print("\n7. release_stale_node_capacity gives back churned slots")
    db, nodes = _capacity_fixture()

    released = await release_stale_node_capacity(db)
    check("two slots released", released == 2, f"got {released}")
    check("node-1 dropped to its live count", nodes[0].current_assignment_count == 2, f"got {nodes[0].current_assignment_count}")
    check("node-2 emptied", nodes[1].current_assignment_count == 0, f"got {nodes[1].current_assignment_count}")
    check(
        "the released node is eligible again",
        node_eligible(nodes[0], FakePool(cap=3)) is True,
        "node still read as full after its capacity came back",
    )

    print("\n8. Idempotency: a second sweep changes nothing")
    second = await release_stale_node_capacity(db)
    check("second run released 0", second == 0, f"got {second} - capacity was double-decremented")
    check("node-1 still 2", nodes[0].current_assignment_count == 2, f"got {nodes[0].current_assignment_count}")
    check("node-2 still 0, not negative", nodes[1].current_assignment_count == 0, f"got {nodes[1].current_assignment_count}")

    print("\n9. A third sweep after new churn is still monotonic")
    db._live_counts = {"node-1": 1, "node-2": 0}
    third = await release_stale_node_capacity(db)
    check("only the newly-stale slot released", third == 1, f"got {third}")
    check("node-1 down to 1", nodes[0].current_assignment_count == 1, f"got {nodes[0].current_assignment_count}")
    check("node-2 untouched", nodes[1].current_assignment_count == 0, f"got {nodes[1].current_assignment_count}")

    print("\n10. The sweep never RAISES a counter (decommission writes 0)")
    fresh = [FakeNode("node-9", count=0, cap=3)]
    db2 = FakeCapacityDB([], {"node-9": 4}, fresh)
    released = await release_stale_node_capacity(db2)
    check("decommissioned zero survives the sweep", fresh[0].current_assignment_count == 0 and released == 0, f"got count={fresh[0].current_assignment_count} released={released}")


# ---------------------------------------------------------------------------


_REAL_REDIS = kv_sync._redis
_REAL_FIND_NS = kv_sync._find_namespace_id
_REAL_READ_MAP = kv_sync._read_map
_REAL_WRITE_MAP = kv_sync._write_map
_REAL_WRITER = kv_sync.get_node_kv_writer


async def main() -> None:
    await test_no_lost_update()
    await test_set_entry_status_is_serialized()
    await test_redis_outage_does_not_break_fulfillment()
    await test_lock_registry_does_not_grow()
    test_pool_cap_binds()
    await test_capacity_release_idempotent()

    kv_sync._redis = _REAL_REDIS
    kv_sync._find_namespace_id = _REAL_FIND_NS
    kv_sync._read_map = _REAL_READ_MAP
    kv_sync._write_map = _REAL_WRITE_MAP
    kv_sync.get_node_kv_writer = _REAL_WRITER

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All KV + pool checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
