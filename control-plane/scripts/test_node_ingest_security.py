"""Security regression tests for the node ingest endpoints.

Three holes in the "a compromised node can only act as itself" model, driven
through the real FastAPI handlers with the DB and Redis faked out:

1. Nonces were mixed into the HMAC but never recorded, so a captured request
   could be replayed for the whole 120s signature window.
2. /health accepted any checkType, silently dropped the submitted checkedAt, and
   appended with no idempotency key at all.
3. /usage took configId straight from the node, so any node could bill any
   customer — and swallowed every IntegrityError, including foreign keys.

Run: python scripts/test_node_ingest_security.py
No network and no database: the session is a stub that answers the exact
queries the handlers issue, and the nonce store is a dict with SET NX semantics.
"""

import asyncio
import json
import logging
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
os.environ.setdefault("TELEGRAM_OWNER_ID", "123456789")
os.environ.setdefault("NODE_HMAC_SECRET_PEPPER", "test-pepper")

import httpx  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402

import api.routes.nodes as nodes_route  # noqa: E402
from domain import security  # noqa: E402
from domain.security import (  # noqa: E402
    compute_expected_signature,
    consume_nonce,
    derive_node_secret_hash,
)

# Several checks here deliberately drive the handlers down their failure paths,
# and those paths log at ERROR — an IntegrityError traceback, a "nonce store
# unavailable" warning. The assertions read HTTP status and rows written, never
# the log, so the noise only makes the PASS/FAIL report harder to read.
logging.disable(logging.ERROR)

FAILURES: list[str] = []

# The route module's real accessor, saved before any test replaces it.
_REAL_GET_REDIS = nodes_route.get_redis

NODE_ID = "11111111-1111-1111-1111-111111111111"
OTHER_NODE_ID = "22222222-2222-2222-2222-222222222222"
OWN_CONFIG = "33333333-3333-3333-3333-333333333333"
FOREIGN_CONFIG = "44444444-4444-4444-4444-444444444444"
SECRET_HASH = derive_node_secret_hash("node-secret")


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------


class FakeRedis:
    """SET NX EX, backed by a dict. `fail` makes every call raise."""

    def __init__(self, fail: bool = False) -> None:
        self.values: dict[str, str] = {}
        self.ttls: list[int] = []
        self.fail = fail

    async def set(self, name: str, value: str, *, nx: bool, ex: int) -> str | None:
        assert nx, "nonce storage must be NX or it is not replay protection"
        self.ttls.append(ex)
        if self.fail:
            raise ConnectionError("redis is down")
        if name in self.values:
            return None
        self.values[name] = value
        return value


class FakeResult:
    def __init__(self, value: Any) -> None:
        self._value = value

    def scalar_one_or_none(self) -> Any:
        return self._value


class FakeSession:
    """Answers the three SELECTs the handlers run, and records what was written.

    `assignments` is the set of live (configuration_id, node_id) rows in
    configuration_node_assignments; `raise_on_commit` simulates the DB refusing
    an insert, so the IntegrityError branches run without a real database.
    """

    def __init__(self, node: FakeNode, assignments: set[tuple[str, str]]) -> None:
        self.node = node
        self.assignments = assignments
        # Series keyed by check_type, exactly as the monotonic guard sees it.
        self.samples: dict[str, list[datetime]] = {}
        self.added: list[Any] = []        # pending, not yet committed
        self.committed_rows: list[Any] = []  # actually in the table
        self.committed = 0
        self.rolled_back = 0
        self.raise_on_commit: Exception | None = None

    def series(self, check_type: str) -> list[datetime]:
        return self.samples.setdefault(check_type, [])

    @staticmethod
    def _bound(statement: Any, prefix: str) -> str:
        params = statement.compile().params
        return next(value for key, value in params.items() if key.startswith(prefix))

    async def execute(self, statement: Any) -> FakeResult:
        target = statement.column_descriptions[0]["entity"].__name__
        if target == "Node":
            return FakeResult(self.node)
        if target == "ConfigurationNodeAssignment":
            # A row only for the exact pair the handler asked about, so a node
            # serving its own config cannot borrow a row for a foreign one.
            pair = (
                self._bound(statement, "configuration_id"),
                self._bound(statement, "node_id"),
            )
            return FakeResult("assignment" if pair in self.assignments else None)
        if target == "NodeHealthSample":
            series = self.series(self._bound(statement, "check_type"))
            return FakeResult(max(series) if series else None)
        raise AssertionError(f"unexpected query against {target}")

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def commit(self) -> None:
        if self.raise_on_commit is not None:
            raise self.raise_on_commit
        self.committed += 1
        self.committed_rows.extend(self.added)
        for obj in self.added:
            if obj.__class__.__name__ == "NodeHealthSample":
                self.series(obj.check_type).append(obj.checked_at)
        # A real session clears its pending set on commit. Without this the
        # already-recorded samples are appended again on every later commit,
        # so a series grows by one per commit and every length assertion
        # downstream is measuring the stub rather than the handler.
        self.added.clear()

    async def rollback(self) -> None:
        self.rolled_back += 1
        self.added.clear()


def usage_body(config_id: str, connection_id: str = "conn-1", sequence: int = 1) -> bytes:
    return json.dumps(
        {
            "configId": config_id,
            "connectionId": connection_id,
            "sequenceNumber": sequence,
            "bytesUp": 1024,
            "bytesDown": 4096,
            "windowStartedAt": "2026-09-25T12:00:00Z",
            "reportedAt": "2026-09-25T12:00:30Z",
        }
    ).encode()


def health_body(check_type: str, checked_at: str | None, success: bool = True) -> bytes:
    body: dict[str, Any] = {"checkType": check_type, "success": success, "latencyMs": 12.5}
    if checked_at is not None:
        body["checkedAt"] = checked_at
    return json.dumps(body).encode()


def integrity_error(message: str) -> IntegrityError:
    """Shaped like the real thing: IntegrityError wrapping asyncpg's message."""
    return IntegrityError("INSERT", {}, Exception(message))


class NodeClient:
    """A signed-request client for one node, with its own fake DB and Redis."""

    def __init__(self, node: FakeNode, assignments: set[tuple[str, str]]) -> None:
        self.db = FakeSession(node, assignments)
        self.redis = FakeRedis()
        self.app = FastAPI()
        self.app.include_router(nodes_route.router)
        self.app.dependency_overrides[nodes_route.get_db] = lambda: self.db
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://testserver",
        )
        nodes_route.get_redis = lambda: self.redis

    def close(self) -> None:
        nodes_route.get_redis = _REAL_GET_REDIS

    def headers(self, body: bytes, nonce: str | None = None, timestamp: str | None = None) -> dict:
        nonce = nonce or uuid.uuid4().hex
        timestamp = timestamp or str(int(time.time() * 1000))
        signature = compute_expected_signature(
            node_secret_hash=SECRET_HASH,
            node_id=NODE_ID,
            timestamp=timestamp,
            nonce=nonce,
            body=body,
        )
        return {
            "content-type": "application/json",
            "x-verdent-timestamp": timestamp,
            "x-verdent-nonce": nonce,
            "x-verdent-signature": signature,
        }

    async def post(self, path: str, body: bytes, nonce: str | None = None) -> httpx.Response:
        return await self.client.post(path, content=body, headers=self.headers(body, nonce=nonce))


class FakeNode:
    """The handlers read `.state` / `.node_secret_hash` / `.id` off the ORM Node.

    A dict cannot stand in — `node.state` on a dict is an AttributeError, not a
    key lookup — so the real code under test has to run against an object.
    """

    def __init__(self, node_id: str, secret_hash: str, state: str = "ONLINE") -> None:
        self.id = node_id
        self.node_secret_hash = secret_hash
        self.state = state


def new_node(state: str = "ONLINE") -> FakeNode:
    return FakeNode(NODE_ID, SECRET_HASH, state)


# This node serves OWN_CONFIG. FOREIGN_CONFIG is live, but assigned to another
# node — so reporting usage for it is a forgery attempt, not a dead config.
OWN_ASSIGNMENT = {(OWN_CONFIG, NODE_ID)}
FOREIGN_ASSIGNMENT = {(FOREIGN_CONFIG, OTHER_NODE_ID)}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_nonce_replay() -> None:
    print("\n1. A fresh nonce is accepted; the same nonce again is a replay")
    node = NodeClient(new_node(), OWN_ASSIGNMENT)
    body = usage_body(OWN_CONFIG)
    headers = node.headers(body, nonce="nonce-once")
    try:
        first = await node.client.post(f"/internal/nodes/{NODE_ID}/usage", content=body, headers=headers)
        replay = await node.client.post(f"/internal/nodes/{NODE_ID}/usage", content=body, headers=headers)

        check("first request with a fresh nonce is accepted", first.status_code == 200, f"got {first.status_code} {first.text}")
        check("immediate replay of the identical nonce+signature is rejected", replay.status_code == 401, f"got {replay.status_code} {replay.text}")
        check("the replay wrote nothing", node.db.committed == 1 and len(node.redis.values) == 1, f"committed={node.db.committed} nonces={len(node.redis.values)}")

        other = usage_body(OWN_CONFIG, connection_id="conn-2")
        second = await node.post(f"/internal/nodes/{NODE_ID}/usage", other)
        check("a different nonce is still accepted", second.status_code == 200, f"got {second.status_code} {second.text}")

        check("nonce keys are node-scoped", all(k.startswith(f"{security.NONCE_PREFIX}{NODE_ID}:") for k in node.redis.values), f"keys={list(node.redis.values)}")
    finally:
        await node.client.aclose()
        node.close()


async def test_cross_node_forgery() -> None:
    print("\n2. A node cannot forge usage for a configuration it does not serve")
    # The foreign config is live AND assigned — to a different node. So a check
    # that only asked "does this configId exist?" would have passed, and the
    # test fails unless the handler asks "is it assigned to *this* node?".
    node = NodeClient(new_node(), OWN_ASSIGNMENT | FOREIGN_ASSIGNMENT)
    body = usage_body(FOREIGN_CONFIG)
    try:
        response = await node.post(f"/internal/nodes/{NODE_ID}/usage", body)
        check("a foreign configId is a 403", response.status_code == 403, f"got {response.status_code} {response.text}")
        check("nothing was written", node.db.committed_rows == [] and node.db.committed == 0, f"rows={node.db.committed_rows} committed={node.db.committed}")
    finally:
        await node.client.aclose()
        node.close()


async def test_own_config_accepted() -> None:
    print("\n3. A node's own configuration is ingested normally")
    node = NodeClient(new_node(), OWN_ASSIGNMENT)
    body = usage_body(OWN_CONFIG)
    try:
        response = await node.post(f"/internal/nodes/{NODE_ID}/usage", body)
        check("own configId is accepted", response.status_code == 200, f"got {response.status_code} {response.text}")
        check("the response is not a drop", response.json().get("dropped") is False, response.text)
        check("exactly one usage event was written", len(node.db.committed_rows) == 1 and node.db.committed == 1, f"rows={len(node.db.committed_rows)} committed={node.db.committed}")
    finally:
        await node.client.aclose()
        node.close()


async def test_duplicate_vs_foreign_key() -> None:
    print("\n4. Only a (connection_id, sequence_number) duplicate is a benign drop")
    node = NodeClient(new_node(), OWN_ASSIGNMENT)
    body = usage_body(OWN_CONFIG)
    try:
        node.db.raise_on_commit = integrity_error(
            'duplicate key value violates unique constraint "uq_usage_events_connection_sequence"'
        )
        duplicate = await node.post(f"/internal/nodes/{NODE_ID}/usage", body)
        check("a duplicate sequence is 200 dropped", duplicate.status_code == 200 and duplicate.json()["dropped"] is True, f"{duplicate.status_code} {duplicate.text}")

        # A foreign-key IntegrityError used to be swallowed here too, so a node
        # whose configuration had vanished kept reporting usage the control
        # plane silently threw away.
        node.db.raise_on_commit = integrity_error(
            'insert or update on table "usage_events" violates foreign key constraint "usage_events_configuration_id_fkey"'
        )
        foreign = await node.post(f"/internal/nodes/{NODE_ID}/usage", body)
        check("a foreign-key IntegrityError surfaces as 5xx", foreign.status_code >= 500, f"got {foreign.status_code} {foreign.text}")
        check("it is not reported as a drop", foreign.json().get("dropped") is not True, foreign.text)
    finally:
        await node.client.aclose()
        node.close()


async def test_health_ingest() -> None:
    print("\n5. Health ingest: validated checkType, honoured checkedAt, no replay rows")
    node = NodeClient(new_node(), OWN_ASSIGNMENT)
    path = f"/internal/nodes/{NODE_ID}/health"
    cp = node.db.series("control_plane")
    try:
        body = health_body("gaming", None)
        bad_type = await node.post(path, body)
        check("an unknown checkType is a 400", bad_type.status_code == 400, f"got {bad_type.status_code} {bad_type.text}")
        check("nothing was written for it", node.db.committed == 0, f"committed={node.db.committed}")

        past = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(microsecond=0)
        body = health_body("control_plane", past.isoformat())
        accepted = await node.post(path, body)
        check("a valid sample is accepted", accepted.status_code == 200, f"got {accepted.status_code} {accepted.text}")
        check("the node's own clock is stored, not arrival time", abs((cp[0] - past).total_seconds()) < 1, f"stored={cp[0]} submitted={past}")

        # A DIFFERENT check type must not be judged against the control_plane
        # series: its guard is per (node, check_type), so a first-ever "dns"
        # sample is new information even though it carries an older timestamp
        # than something already recorded for control_plane. Asserting against
        # `cp` here would pin the wrong series and hide a real regression in
        # the dns guard entirely.
        body = health_body("dns", past.isoformat())
        other_check = await node.post(path, body)
        dns = node.db.series("dns")
        check(
            "check types are guarded independently",
            other_check.status_code == 200 and len(dns) == 1,
            f"{other_check.status_code} dns={dns} - a first dns sample was dropped as a replay",
        )

        body = health_body("control_plane", (past + timedelta(minutes=1)).isoformat())
        forward = await node.post(path, body)
        check("a strictly newer sample still lands", forward.status_code == 200 and len(cp) == 2, f"{forward.status_code} samples={cp}")

        body = health_body("dns", "not-a-timestamp")
        garbage = await node.post(path, body)
        check("an unparseable checkedAt is a 400", garbage.status_code == 400, f"got {garbage.status_code} {garbage.text}")

        body = health_body("data_plane", None, success=False)
        later = await node.post(path, body)
        check("a failing sample with no checkedAt is accepted", later.status_code == 200, f"got {later.status_code} {later.text}")
    finally:
        await node.client.aclose()
        node.close()


async def test_fail_closed() -> None:
    print("\n6. An unreachable nonce store fails closed")

    store = FakeRedis()
    check("a fresh nonce is accepted", await consume_nonce(store, NODE_ID, "abc") is True, "fresh nonce rejected")
    check("the TTL covers the signature window", all(ttl >= security.SIGNATURE_TTL_SECONDS for ttl in store.ttls), f"ttls={store.ttls}")
    check("an immediate repeat is a replay", await consume_nonce(store, NODE_ID, "abc") is False, "second SET NX was accepted")
    check("another node's key space is untouched", await consume_nonce(store, OTHER_NODE_ID, "abc") is True, "keys are not node-scoped")

    closed = False
    try:
        await consume_nonce(FakeRedis(fail=True), NODE_ID, "abc")
    except security.NonceStoreUnavailable:
        closed = True
    check("Redis down fails CLOSED by default", closed, "a down Redis was silently tolerated")

    original = security.settings.node_replay_fail_open
    security.settings.node_replay_fail_open = True
    try:
        opened = await consume_nonce(FakeRedis(fail=True), NODE_ID, "abc")
        check("NODE_REPLAY_FAIL_OPEN=true is the operator's explicit opt-out", opened is True, f"got {opened}")
    finally:
        security.settings.node_replay_fail_open = original

    node = NodeClient(new_node(), OWN_ASSIGNMENT)
    node.redis.fail = True
    body = usage_body(OWN_CONFIG)
    try:
        response = await node.post(f"/internal/nodes/{NODE_ID}/usage", body)
        check("a signed request is refused while the nonce store is down", response.status_code == 401, f"got {response.status_code} {response.text}")
        check("nothing was ingested", node.db.committed == 0, f"committed={node.db.committed}")
    finally:
        await node.client.aclose()
        node.close()


async def main() -> None:
    await test_nonce_replay()
    await test_cross_node_forgery()
    await test_own_config_accepted()
    await test_duplicate_vs_foreign_key()
    await test_health_ingest()
    await test_fail_closed()


if __name__ == "__main__":
    asyncio.run(main())
    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for failure in FAILURES:
            print(f"  - {failure}")
        sys.exit(1)
    print("All node ingest security checks passed.")
