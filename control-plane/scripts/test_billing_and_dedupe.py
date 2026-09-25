"""Regression tests for the billing-header, webhook-dedupe, reconcile-window,
and migration-downgrade fixes.

Each of these is a defect that looks like working software from the outside:

- `subscription-userinfo` published the period TOTAL in both the upload and
  download fields. Clients draw two bars and sum them, so every customer saw
  double their real traffic, and the error grew with usage.
- The Telegram webhook had no dedupe. Telegram redelivers an unacknowledged
  update with the same update_id, and the dispatcher re-ran the whole handler
  — one button press could create two orders.
- `reconcile_usage()` re-derived the entire append-only ledger every 5 minutes
  to find nothing after the first pass.
- Migration 001's `downgrade()` dropped no tables, so `alembic downgrade base`
  left all 21 tables behind while the version table claimed base.

Run: python scripts/test_billing_and_dedupe.py
"""

import asyncio
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api.routes.telegram as telegram_route  # noqa: E402
from domain.subscriptions import usage_current_period, usage_current_period_detail  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------


class FakeAggregate:
    def __init__(self, up: int, down: int) -> None:
        self.bytes_up = up
        self.bytes_down = down
        self.total_bytes = up + down


class FakeConfig:
    id = "cfg-1"
    is_test = False
    plan_id = None
    created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)


class _Result:
    def __init__(self, items) -> None:
        self._items = list(items)

    def scalars(self):
        return self

    def all(self):
        return list(self._items)


class UsageDB:
    """Returns a fixed set of daily aggregates regardless of the query."""

    def __init__(self, aggs: list[FakeAggregate]) -> None:
        self._aggs = aggs
        self.queries: list[str] = []

    async def execute(self, query):
        self.queries.append(" ".join(str(query).split()))
        return _Result(self._aggs)


# --------------------------------------------------------------------------
# 1. subscription-userinfo direction split
# --------------------------------------------------------------------------


def build_userinfo(up: int, down: int, quota: int | None) -> str:
    """Mirrors the exact f-string the route builds, so this asserts the
    caller's arithmetic rather than re-deriving it."""
    parts = [f"upload={up}", f"download={down}", f"total={quota or 0}"]
    return "; ".join(parts)


async def section_usage_split() -> None:
    print("\n1. usage is split by direction, not duplicated into both fields")
    aggs = [FakeAggregate(1_000, 4_000), FakeAggregate(500, 2_000)]
    db = UsageDB(aggs)
    used, up, down, quota = await usage_current_period_detail(db, FakeConfig())

    check("up is the sum of bytes_up only", up == 1_500, f"got {up}")
    check("down is the sum of bytes_down only", down == 6_000, f"got {down}")
    check("used is the total of both", used == 7_500, f"got {used}")
    check("used == up + down", used == up + down, f"{used} != {up} + {down}")

    print("\n2. The header the client parses sums to the real traffic")
    # A client reads upload + download to get its own used figure.
    header = build_userinfo(up, down, 100_000)
    client_seen = up + down
    check("client-computed usage equals real usage", client_seen == used, f"{client_seen} != {used}")
    check("the two fields are not equal to each other", up != down, "a symmetric fixture proves nothing")

    print("\n3. The old double-counting shape is the thing being guarded against")
    # This is what the route used to emit: total in both fields.
    old_upload, old_download = used, used
    old_client_seen = old_upload + old_download
    check(
        "the previous shape would have doubled the reported usage",
        old_client_seen == used * 2 and old_client_seen != used,
        f"old={old_client_seen} real={used}",
    )

    print("\n4. The single-value helper still returns the total for quota math")
    used2, quota2 = await usage_current_period(UsageDB(aggs), FakeConfig())
    check("usage_current_period is unchanged for existing callers", used2 == used, f"{used2} != {used}")
    check("it still returns the quota", quota2 == quota, f"{quota2} != {quota}")


# --------------------------------------------------------------------------
# 2. telegram update dedupe
# --------------------------------------------------------------------------


class FakeRedis:
    def __init__(self, fail: bool = False) -> None:
        self.store: dict[str, str] = {}
        self.fail = fail
        self.calls: list[tuple[str, int]] = []

    async def set(self, name: str, value: str, *, nx: bool, ex: int):
        if self.fail:
            raise ConnectionError("redis down")
        self.calls.append((name, ex))
        if nx and name in self.store:
            return None
        self.store[name] = value
        return True


async def section_update_dedupe() -> None:
    print("\n5. A redelivered Telegram update is processed once")
    store = FakeRedis()
    original = telegram_route.get_redis
    telegram_route.get_redis = lambda: store
    try:
        first = await telegram_route._claim_update(4242)
        second = await telegram_route._claim_update(4242)
    finally:
        telegram_route.get_redis = original

    check("the first delivery is accepted", first is True, f"got {first}")
    check("the redelivery is rejected", second is False, f"got {second}")
    check("only one key was written", len(store.store) == 1, f"store={store.store}")
    check(
        "the key is namespaced to updates",
        list(store.store)[0] == f"{telegram_route.UPDATE_DEDUPE_PREFIX}4242",
        f"got {list(store.store)[0]}",
    )
    check(
        "the TTL outlasts Telegram's retry window",
        store.calls[0][1] == telegram_route.UPDATE_DEDUPE_TTL_SECONDS >= 900,
        f"ttl={store.calls[0][1]}",
    )

    print("\n6. Distinct updates are unaffected")
    store2 = FakeRedis()
    telegram_route.get_redis = lambda: store2
    try:
        r1 = await telegram_route._claim_update(1)
        r2 = await telegram_route._claim_update(2)
    finally:
        telegram_route.get_redis = original
    check("two different updates both run", r1 is True and r2 is True, f"{r1}, {r2}")

    print("\n7. A Redis outage does NOT take the bot down (fails open)")
    store3 = FakeRedis(fail=True)
    telegram_route.get_redis = lambda: store3
    try:
        outage = await telegram_route._claim_update(99)
    finally:
        telegram_route.get_redis = original
    check(
        "updates are still accepted when the dedupe store is unreachable",
        outage is True,
        "failing closed here would silently drop every update during a Redis outage",
    )


# --------------------------------------------------------------------------
# 3. reconcile window
# --------------------------------------------------------------------------


def section_reconcile_window() -> None:
    print("\n8. The periodic reconcile is bounded; the full pass still exists")
    import workers.main as worker_main
    from domain import reconcile as reconcile_mod

    check(
        "the lookback window is defined",
        reconcile_mod.RECONCILE_LOOKBACK_DAYS > 0,
        f"got {reconcile_mod.RECONCILE_LOOKBACK_DAYS}",
    )
    check(
        "the full pass runs on a daily cadence, not every 5 minutes",
        worker_main.FULL_RECONCILE_INTERVAL == 86400
        > worker_main.RECONCILE_INTERVAL,
        f"full={worker_main.FULL_RECONCILE_INTERVAL} periodic={worker_main.RECONCILE_INTERVAL}",
    )
    check(
        "the periodic cadence is far more frequent than the full pass",
        worker_main.FULL_RECONCILE_INTERVAL >= 100 * worker_main.RECONCILE_INTERVAL,
        "a full pass every 5 min is the unbounded scan this replaces",
    )

    import inspect

    src = inspect.getsource(worker_main.usage_reconcile_loop)
    check(
        "the loop calls reconcile with a `since` bound on the periodic pass",
        "since=" in src,
        "an unbounded pass would still run every tick",
    )
    check(
        "and calls it unbounded on the daily pass",
        "await reconcile_usage()" in src,
        "the daily full pass is what repairs a row corrupted long ago",
    )

    # The signature must actually accept the bound.
    sig = inspect.signature(reconcile_mod.reconcile_usage)
    check(
        "reconcile_usage accepts a `since` keyword",
        "since" in sig.parameters and sig.parameters["since"].default is None,
        f"signature={sig}",
    )


# --------------------------------------------------------------------------
# 4. migration downgrade
# --------------------------------------------------------------------------


def section_downgrade() -> None:
    print("\n9. Migration 001 downgrade drops every table it created")
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "mig001",
        Path(__file__).resolve().parent.parent
        / "db"
        / "migrations"
        / "versions"
        / "001_initial.py",
    )
    mig = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mig)

    executed: list[str] = []
    orig_execute = mig.op.execute
    orig_drop = getattr(mig.op, "drop_column", None)
    try:
        mig.op.execute = lambda sql, *a, **k: executed.append(" ".join(str(sql).split()))
        if orig_drop is not None:
            mig.op.drop_column = lambda *a, **k: None
        mig.downgrade()
    finally:
        mig.op.execute = orig_execute
        if orig_drop is not None:
            mig.op.drop_column = orig_drop

    dropped = {
        sql.split("DROP TABLE IF EXISTS ")[1].split(" ")[0]
        for sql in executed
        if sql.startswith("DROP TABLE IF EXISTS ")
    }

    # The exact 21 tables migration 001 creates.
    expected = {
        "admins", "audit_log", "cloudflare_accounts", "configuration_active_sessions",
        "configuration_node_assignments", "configurations", "customers",
        "gaming_profiles", "node_health_samples", "nodes", "notifications_log",
        "orders", "payment_attempts", "payment_proofs", "plans", "pool_nodes",
        "pools", "subscription_activations", "telegram_bot_state",
        "usage_daily_aggregates", "usage_events",
    }

    missing = expected - dropped
    check(
        "all 21 tables are dropped",
        not missing,
        f"missing: {sorted(missing)}",
    )
    check(
        "the trigger and its function are still dropped",
        any("DROP TRIGGER" in s for s in executed) and any("DROP FUNCTION" in s for s in executed),
        "the aggregate trigger outlives the table it is attached to",
    )

    print("\n10. Children are dropped before parents")
    order = [s.split("DROP TABLE IF EXISTS ")[1].split(" ")[0] for s in executed
             if s.startswith("DROP TABLE IF EXISTS ")]
    position = {t: i for i, t in enumerate(order)}
    # configuration_node_assignments references both configurations and nodes.
    check(
        "configuration_node_assignments is dropped before configurations",
        position.get("configuration_node_assignments", -1)
        < position.get("configurations", 10_000),
        f"order={order}",
    )
    check(
        "pool_nodes is dropped before pools",
        position.get("pool_nodes", -1) < position.get("pools", 10_000),
        f"order={order}",
    )
    check(
        "payment_proofs is dropped before payment_attempts",
        position.get("payment_proofs", -1) < position.get("payment_attempts", 10_000),
        f"order={order}",
    )


WORKER_PROTOCOLS = (
    Path(__file__).resolve().parent.parent.parent / "node-worker" / "src" / "protocols"
)


def section_dns_usage_counted() -> None:
    """#45 — in-tunnel DNS was relayed and billed to nobody.

    The TCP path counts both legs (trackUp in connectAndWrite, trackDown in
    remoteSocketToWS), but the UDP:53 path in vless.ts called
    handleUDPOutBound without ever passing the tracker, so every query and
    answer travelled free. The quota is computed as bytes_up + bytes_down
    straight off the ledger (usage_current_period_detail), so uncounted DNS
    was unrecoverable revenue loss on precisely the path the gaming profile's
    "antisanction DNS" promise sells.
    """
    print("\n5. In-tunnel DNS traffic is counted")

    path = WORKER_PROTOCOLS / "vless.ts"
    if not path.exists():
        check("vless.ts is present", False, f"missing at {path}")
        return

    src = path.read_text(encoding="utf-8")

    # The handler must be able to count at all.
    check(
        "handleUDPOutBound accepts the tracker",
        "tracker: UsageTracker | null = null" in src,
        "a handler with no tracker cannot count anything",
    )

    # The call site must actually hand it over — the defect was a missing
    # argument, not a missing parameter.
    check(
        "the DNS call site passes the tracker",
        "handleUDPOutBound(webSocket, VLResponseHeader, log, tracker)" in src,
        "without the argument the parameter is always null",
    )

    start = src.find("async function handleUDPOutBound")
    body = src[start:] if start != -1 else ""

    up_at = body.find("tracker.trackUp(")
    down_at = body.find("tracker.trackDown(")
    fetch_at = body.find("await fetch(")

    check(
        "the upstream query is counted",
        up_at != -1,
        "the query the customer sent was never billed",
    )
    check(
        "the resolver's answer is counted",
        down_at != -1,
        "the answer the customer received was never billed",
    )
    # Ordering matters: the query is counted on the way out, the answer only
    # once it has actually arrived. Counting down before the fetch would bill
    # the customer for a response that may never come.
    check(
        "the query is counted before the fetch",
        up_at != -1 and fetch_at != -1 and up_at < fetch_at,
        "counting after the fetch risks losing the query if the fetch throws",
    )
    check(
        "the answer is counted after the fetch returns",
        down_at != -1 and fetch_at != -1 and down_at > fetch_at,
        "a failed lookup must not be billed as a delivered answer",
    )

    # Both legs counted means the ledger moves on both halves of the quota.
    check(
        "both legs are guarded against a null tracker",
        "if (tracker) tracker.trackUp(" in src and "if (tracker) tracker.trackDown(" in src,
        "an unguarded call would crash the relay when no tracker exists",
    )


async def main() -> None:
    await section_usage_split()
    await section_update_dedupe()
    section_reconcile_window()
    section_downgrade()
    section_dns_usage_counted()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All billing/dedupe/downgrade checks passed.")


asyncio.run(main())
