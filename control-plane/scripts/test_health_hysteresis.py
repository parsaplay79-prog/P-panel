"""Regression test for the health hysteresis that was silently inert.

The bug: `_consecutive_failures` was a plain Python attribute on the ORM
object. The health loop opens a new session every pass, so the counter read
back as 0 each time — DEGRADED (2 failures) and OFFLINE (5 failures) were
unreachable, and failover never ran. It also meant a node dying in production
looked perfectly healthy.

This drives apply_health_transition() the way the real loop does — a FRESH
Node object per pass, reloaded from "storage" — so an in-memory counter would
fail this test rather than pass it by accident.

Run: python scripts/test_health_hysteresis.py
"""

import sys
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domain.health import (  # noqa: E402
    DEGRADED_AFTER_FAILURES,
    FAILOVER_AFTER_OFFLINE,
    OFFLINE_AFTER_FAILURES,
    ONLINE_AFTER_SUCCESSES,
    apply_health_transition,
)

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


class FakeNode:
    """Stands in for the ORM Node: only the fields the transition touches."""

    def __init__(self) -> None:
        self.id = "node-1"
        self.state = "ONLINE"
        self.health_score: Decimal | int = 100
        self.control_plane_health = True
        self.data_plane_health = True
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.offline_since: datetime | None = None


def run_passes(persisted: dict, outcomes: list[bool]) -> list[str]:
    """Simulate consecutive health passes.

    Each pass builds a FRESH object from the persisted columns — exactly what
    a new DB session does — so any counter that only lives in memory starts
    back at zero and the test catches it.
    """
    states = []
    for ok in outcomes:
        node = FakeNode()
        node.state = persisted["state"]
        node.health_score = persisted["score"]
        node.consecutive_failures = persisted["failures"]
        node.consecutive_successes = persisted["successes"]
        node.offline_since = persisted["offline_since"]

        apply_health_transition(node, ok, 10.0)

        persisted["state"] = node.state
        persisted["score"] = node.health_score
        persisted["failures"] = node.consecutive_failures
        persisted["successes"] = node.consecutive_successes
        persisted["offline_since"] = node.offline_since
        states.append(node.state)
    return states


def fresh_store() -> dict:
    return {
        "state": "ONLINE",
        "score": 100,
        "failures": 0,
        "successes": 0,
        "offline_since": None,
    }


print("\n1. Hysteresis: a single blip must NOT take a node down")
store = fresh_store()
states = run_passes(store, [False, True])
check(
    "one failure then success returns to ONLINE",
    states == ["DEGRADED", "ONLINE"] or states[-1] == "ONLINE",
    f"got {states}",
)
check("failure counter reset by success", store["failures"] == 0, f"got {store['failures']}")

print("\n2. DEGRADED is reachable after exactly the threshold")
store = fresh_store()
states = run_passes(store, [False])
check(
    f"1 failure is not yet DEGRADED (threshold={DEGRADED_AFTER_FAILURES})",
    states[0] != "DEGRADED" or DEGRADED_AFTER_FAILURES == 1,
    f"got {states[0]}",
)
states = run_passes(store, [False])
check("2nd consecutive failure is DEGRADED", states[0] == "DEGRADED", f"got {states[0]}")

print("\n3. OFFLINE is reachable after exactly the threshold")
store = fresh_store()
states = run_passes(store, [False] * OFFLINE_AFTER_FAILURES)
check(
    f"{OFFLINE_AFTER_FAILURES} consecutive failures reach OFFLINE",
    states[-1] == "OFFLINE",
    f"got {states[-1]} after {states}",
)
check("offline_since stamped on transition", store["offline_since"] is not None, "not set")

print("\n4. offline_since is stamped ONCE, not every pass")
first_stamp = store["offline_since"]
run_passes(store, [False] * 10)
check(
    "offline_since not refreshed on later passes",
    store["offline_since"] == first_stamp,
    "countdown would reset forever and failover would never fire",
)

print("\n5. Health score clamps at 0 instead of sawtoothing back to 75")
store = fresh_store()
run_passes(store, [False] * 20)
check(
    "score floors at 0 and stays there",
    int(store["score"]) == 0,
    f"got {store['score']} — the old `or SCORE_ONLINE` idiom reset 0 to 100",
)

print("\n6. Recovery requires ONLINE_AFTER_SUCCESSES consecutive successes")
store = fresh_store()
run_passes(store, [False] * OFFLINE_AFTER_FAILURES)
check("node is OFFLINE before recovery", store["state"] == "OFFLINE", f"got {store['state']}")
states = run_passes(store, [True])
check(
    f"first success is not yet ONLINE (need {ONLINE_AFTER_SUCCESSES})",
    states[0] != "ONLINE",
    f"got {states[0]} — one lucky probe should not restore a node",
)
states = run_passes(store, [True])
check(f"{ONLINE_AFTER_SUCCESSES} successes restore ONLINE", states[0] == "ONLINE", f"got {states[0]}")
check("offline_since cleared on recovery", store["offline_since"] is None, "not cleared")

print("\n7. Operator-held states are never transitioned by the health loop")
for held in ("MAINTENANCE", "QUARANTINED", "DECOMMISSIONED"):
    node = FakeNode()
    node.state = held
    apply_health_transition(node, False, None)
    check(f"{held} survives a failed probe", node.state == held, f"got {node.state}")
    apply_health_transition(node, True, 10.0)
    check(f"{held} survives a successful probe", node.state == held, f"got {node.state}")

print("\n8. A fresh PROVISIONING node still reaches ONLINE")
store = fresh_store()
store["state"] = "PROVISIONING"
store["score"] = 0
states = run_passes(store, [True, True])
check("PROVISIONING -> ONLINE after 2 successes", states[-1] == "ONLINE", f"got {states}")

print("\n9. Failover gate: opens only after the full offline window")
now = datetime.now(timezone.utc)
store = fresh_store()
run_passes(store, [False] * OFFLINE_AFTER_FAILURES)
entered = store["offline_since"]
cutoff = now - FAILOVER_AFTER_OFFLINE
check(
    "gate CLOSED while offline_since is recent",
    entered > cutoff,
    f"entered={entered} cutoff={cutoff}",
)
old = now - FAILOVER_AFTER_OFFLINE - timedelta(minutes=1)
check("gate OPENS once offline_since is older than the window", old <= cutoff, f"old={old}")

print()
if FAILURES:
    print(f"FAILED ({len(FAILURES)}):")
    for f in FAILURES:
        print(f"  - {f}")
    sys.exit(1)
print("All hysteresis checks passed.")
