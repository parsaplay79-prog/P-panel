"""Regression test for the pool-link repair (production had pool_nodes: 0).

The bug this pins: attach_node_to_pools() runs only inside provision_node(),
so a node that already existed when that code shipped — or whose pool was
created later — is never linked. Nothing fails loudly. `nodes` shows it
ONLINE, `pools` shows a pool, `pool_nodes` is empty, and every fulfillment
returns "no eligible node" while the dashboard looks perfectly healthy.

repair_pool_links() must close that gap idempotently, because it runs on every
boot and must not double-link or fight itself.

Run: python scripts/test_pool_link_repair.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domain.provisioning import repair_pool_links  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


class FakeNode:
    def __init__(self, node_id: str, tags: list[str], state: str = "ONLINE") -> None:
        self.id = node_id
        self.capability_tags = tags
        self.state = state


class FakePool:
    def __init__(self, pool_id: str, name: str, tags: list[str]) -> None:
        self.id = pool_id
        self.name = name
        self.capability_tags = tags


class _Result:
    def __init__(self, items) -> None:
        self._items = list(items)

    def scalars(self):
        return self

    def all(self):
        return list(self._items)

    def scalar_one_or_none(self):
        return self._items[0] if self._items else None


class FakeDB:
    """Dispatches on the rendered SQL, like the other fakes in this repo.

    `existing_links` is the pool_nodes table; repair must consult it and add
    only the missing rows.
    """

    def __init__(self, nodes: list[FakeNode], pools: list[FakePool], links: set[tuple[str, str]]) -> None:
        self._nodes = nodes
        self._pools = pools
        self.links = links
        self.commits = 0
        self.added: list[tuple[str, str]] = []

    async def execute(self, query):
        # Collapse whitespace first, then match on a normalised string.
        # Two traps this avoids: SQLAlchemy renders "FROM nodes" on its own
        # line (so a plain " FROM nodes" substring misses), and a bound value
        # like "DECOMMISSIONED" contains "FROM nodes" as text — matching the
        # raw statement would answer the wrong query and pass for the wrong
        # reason.
        rendered = " ".join(str(query).split())
        if "FROM pool_nodes" in rendered:
            params = list(query.compile().params.values())
            pool_id = next((v for v in params if isinstance(v, str) and v.startswith("p-")), None)
            node_id = next((v for v in params if isinstance(v, str) and v.startswith("n-")), None)
            if pool_id and node_id and (pool_id, node_id) in self.links:
                return _Result([object()])
            return _Result([])
        if "FROM pools" in rendered:
            return _Result(self._pools)
        if "FROM nodes" in rendered:
            # Honour the state filter, or the DECOMMISSIONED case below is
            # untestable: the query asks Postgres to exclude them and a fake
            # that returns everything would quietly answer a different
            # question than the one the code asked.
            state = next(
                (v for v in query.compile().params.values() if v == "DECOMMISSIONED"),
                None,
            )
            if state is not None:
                return _Result([n for n in self._nodes if n.state != state])
            return _Result(self._nodes)
        raise AssertionError(f"unexpected query: {rendered}")

    def add(self, obj) -> None:
        self.added.append((obj.pool_id, obj.node_id))
        self.links.add((obj.pool_id, obj.node_id))

    async def commit(self) -> None:
        self.commits += 1


def fixture():
    nodes = [FakeNode("n-1", ["general", "doh"]), FakeNode("n-2", ["gaming"])]
    pools = [
        FakePool("p-general", "general", ["general"]),
        FakePool("p-gaming", "gaming", ["gaming"]),
        FakePool("p-any", "catchall", []),  # untagged = general purpose
    ]
    return FakeDB(nodes, pools, set()), nodes, pools


async def main() -> None:
    print("\n1. A pre-existing node in NO pool is linked on startup")
    db, nodes, _ = fixture()
    linked = await repair_pool_links(db)
    check("repair reported the node as linked", "n-1" in linked, f"got {linked}")
    check(
        "n-1 joined the general pool and the untagged catch-all",
        ("p-general", "n-1") in db.links and ("p-any", "n-1") in db.links,
        f"links={sorted(db.links)}",
    )
    check(
        "n-1 did NOT join the gaming pool",
        ("p-gaming", "n-1") not in db.links,
        "a node was linked to a pool whose tags it does not satisfy",
    )
    check(
        "n-2 joined only the gaming pool",
        ("p-gaming", "n-2") in db.links and ("p-general", "n-2") not in db.links,
        f"links={sorted(db.links)}",
    )

    print("\n2. The repair is idempotent — a second boot adds nothing")
    before = set(db.links)
    added_before = len(db.added)
    await repair_pool_links(db)
    check("no new links on the second run", set(db.links) == before, f"gained {set(db.links) - before}")
    check("no duplicate rows were staged", len(db.added) == added_before, f"added {len(db.added) - added_before} more")

    print("\n3. The exact production state is repaired")
    # One node, one pool, zero pool_nodes — what production actually looked like.
    prod = FakeDB([FakeNode("prod-node", ["general", "doh", "gaming"])],
                  [FakePool("p-general", "general", ["general", "doh", "gaming"])],
                  set())
    await repair_pool_links(prod)
    check(
        "the orphaned production node is now selectable",
        ("p-general", "prod-node") in prod.links,
        "fulfillment would still return 'no eligible node'",
    )

    print("\n4. A DECOMMISSIONED node is left alone")
    db2 = FakeDB([FakeNode("n-dead", ["general"], state="DECOMMISSIONED")],
                 [FakePool("p-general", "general", ["general"])], set())
    await repair_pool_links(db2)
    check("no link created for a decommissioned node", db2.links == set(), f"got {db2.links}")

    print("\n5. A node matching no pool is warned about, not force-linked")
    db3 = FakeDB([FakeNode("n-odd", ["exotic"])],
                 [FakePool("p-general", "general", ["general"])], set())
    linked3 = await repair_pool_links(db3)
    check("nothing was linked", db3.links == set() and linked3 == {}, f"links={db3.links} linked={linked3}")

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All pool-link repair checks passed.")


asyncio.run(main())
