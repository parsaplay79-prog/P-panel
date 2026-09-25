"""Regression test for node→pool linking.

The bug: provision_node() created a healthy, reachable Cloudflare Worker and
persisted the Node row, but never wrote a PoolNode row. select_node_for_pool()
joins through pool_nodes, so it returned None for every plan and every paid
order failed at fulfillment with "no eligible node" — while the admin panel
showed a perfectly good ONLINE node. In production this left the live database
with pools=1, pool_nodes=0, nodes=1.

attach_node_to_pools() is pure enough to test against fake sessions: the
matching rule is the part worth pinning, since a wrong rule either strands a
node or hands a gaming-only node to general customers.

Run: python scripts/test_pool_linking.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domain.provisioning import attach_node_to_pools  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


class FakeNode:
    def __init__(self, tags):
        self.id = "node-1"
        self.capability_tags = tags


class FakePool:
    def __init__(self, name, tags):
        self.id = f"pool-{name}"
        self.name = name
        self.capability_tags = tags


class FakeDB:
    """Minimal stand-in for AsyncSession.

    attach_node_to_pools() issues exactly two shapes of query, so dispatch on
    the rendered statement rather than trying to interpret SQLAlchemy's
    expression tree: first a SELECT of pools, then a per-pool existence probe
    against pool_nodes.
    """

    def __init__(self, pools, already_linked=()):
        self._pools = pools
        # (pool_id, node_id) pairs that already exist in the table.
        self._linked = set(already_linked)
        self.added = []
        self.commits = 0
        self._probes = 0

    async def execute(self, query):
        rendered = str(query)

        if "FROM pools" in rendered:
            return _Result(self._pools)

        if "FROM pool_nodes" in rendered:
            # One probe per pool, in iteration order — the code probes
            # sequentially, so the Nth probe answers for the Nth pool.
            pool = self._pools[self._probes]
            self._probes += 1
            hit = (pool.id, "node-1") in self._linked
            return _Result([1] if hit else [])
        raise AssertionError(f"unexpected query: {rendered}")

    def add(self, obj):
        self.added.append(obj)
        self._linked.add((obj.pool_id, obj.node_id))

    async def commit(self):
        self.commits += 1


class _Result:
    def __init__(self, items):
        self._items = list(items)

    def scalars(self):
        return self

    def all(self):
        return list(self._items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


async def main() -> None:
    print("\n1. A general node joins a matching pool (the prod case)")
    db = FakeDB([FakePool("general", ["general", "doh", "gaming"])])
    linked = await attach_node_to_pools(db, FakeNode(["general", "doh", "gaming"]))
    check("linked into the general pool", linked == ["general"], f"got {linked}")
    check("one PoolNode row written", len(db.added) == 1, f"got {len(db.added)}")
    check("committed", db.commits == 1, f"got {db.commits}")

    print("\n2. A node that cannot serve a pool's tags is NOT linked")
    db = FakeDB([FakePool("gaming-only", ["gaming"])])
    linked = await attach_node_to_pools(db, FakeNode(["general", "doh"]))
    check("mismatched node excluded", linked == [], f"got {linked}")
    check("no PoolNode row written", len(db.added) == 0, f"got {len(db.added)}")

    print("\n3. A superset node serves a narrower pool (tags are a subset test)")
    db = FakeDB([FakePool("doh-only", ["doh"])])
    linked = await attach_node_to_pools(db, FakeNode(["general", "doh", "gaming"]))
    check("capable node linked into narrower pool", linked == ["doh-only"], f"got {linked}")

    print("\n4. A pool with no declared tags accepts a normal node")
    db = FakeDB([FakePool("untagged", [])])
    linked = await attach_node_to_pools(db, FakeNode(["general"]))
    check("untagged pool is general-purpose", linked == ["untagged"], f"got {linked}")

    print("\n5. Idempotent: re-running does not double-link")
    db = FakeDB([FakePool("general", ["general"])], already_linked=[("pool-general", "node-1")])
    linked = await attach_node_to_pools(db, FakeNode(["general"]))
    check("already-linked pool not re-added", len(db.added) == 0, f"got {len(db.added)}")
    check("still reported as linked", linked == ["general"], f"got {linked}")

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All pool-linking checks passed.")


asyncio.run(main())
