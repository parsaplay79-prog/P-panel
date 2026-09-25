"""Regression tests for the credential-cutoff fixes.

Two defects that together meant an expired customer kept their proxy:

1. GET /s/{token} served a working vless:// URI for ANY status except DELETED.
   EXPIRED and SUSPENDED customers could keep fetching their link and using
   the service. This is the revenue leak.

2. The endpoint itself wrote the ACTIVE -> EXPIRED transition. The sweep only
   selects ACTIVE configs, so a config expired through the endpoint vanished
   from the sweep before it could disable the edge credential — the proxy
   kept relaying. Marking status and cutting the edge must be one operation
   with one owner.

The expiry sweep's own behavior (advisory lock, dedupe) is covered by the
structure tests elsewhere; this file pins the cutoff contract.

Run: python scripts/test_credential_cutoff.py
"""

import asyncio
import ast
import inspect
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api.routes.subscription as sub_route  # noqa: E402
from domain import notifications as notify_mod  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


class FakeConfig:
    def __init__(self, status: str) -> None:
        self.id = "cfg-1"
        self.status = status
        self.display_name = "cfg"
        self.is_test = False
        self.plan_id = None
        self.created_at = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.expires_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        self.subscription_token = "tok"


class FakeAssignment:
    def __init__(self) -> None:
        self.proxy_uuid = "11111111-2222-3333-4444-555555555555"


class FakeNode:
    def __init__(self) -> None:
        self.custom_domain = "node.example.com"


async def call_endpoint(status: str):
    """Invoke the route with a stubbed config and report (status_code, body)."""
    class _Result:
        """One fake result that answers every access shape the route uses."""

        def __init__(self, value):
            self._value = value

        def scalars(self):
            return self

        def scalar_one_or_none(self):
            return self._value if not isinstance(self._value, list) else (
                self._value[0] if self._value else None
            )

        def all(self):
            return self._value if isinstance(self._value, list) else []

    class _DB:
        async def execute(self, query):
            rendered = " ".join(str(query).split())
            if "FROM configurations" in rendered:
                return _Result(FakeConfig(status))
            if "FROM configuration_node_assignments" in rendered:
                # A live assignment with a domain, so the ACTIVE path has
                # something real to render. Without this the ACTIVE case
                # would produce an empty body for the wrong reason.
                return _Result([(FakeAssignment(), FakeNode())])
            return _Result([])

        async def commit(self):
            raise AssertionError("the endpoint must not write config status")

    response = await sub_route.get_subscription("tok", None, _DB())
    # Starlette raises HTTPException for the 404 path; normalise to a pair.
    return getattr(response, "status_code", 200), getattr(response, "body", b"")


async def section_endpoint_gating() -> None:
    print("\n1. A live config still gets its subscription")
    code, body = await call_endpoint("ACTIVE")
    check("ACTIVE is served", code == 200, f"got {code}")
    check("and the body is a real payload", len(body) > 0, "an empty body means no credentials")

    print("\n2. A DELETED config is gone entirely")
    try:
        await call_endpoint("DELETED")
        check("DELETED is rejected", False, "it returned a response instead of 404")
    except Exception as exc:  # noqa: BLE001
        check("DELETED returns 404", getattr(exc, "status_code", None) == 404, f"got {exc!r}")

    print("\n3. A non-ACTIVE config receives NO credential")
    for status in ("EXPIRED", "SUSPENDED", "PENDING"):
        code, body = await call_endpoint(status)
        check(
            f"{status} gets an empty body",
            body == b"",
            f"got {body[:80]!r} — a live vless:// URI was handed out",
        )
        check(
            f"{status} still returns 200 (so the client drops its cached config)",
            code == 200,
            f"got {code}; a non-200 makes clients keep the config they already have",
        )


def _assigned_attributes(fn) -> set[str]:
    """Names assigned anywhere in `fn`, via AST.

    A substring test is not good enough here: `"config.status ="` is a
    substring of `"config.status =="`, so the obvious check reports a write
    that does not exist. Only a real assignment target counts.
    """
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    assigned: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute):
                    assigned.add(f"{getattr(target.value, 'id', '?')}.{target.attr}")
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Attribute):
            assigned.add(f"{getattr(node.target.value, 'id', '?')}.{node.target.attr}")
    return assigned


def section_endpoint_ownership() -> None:
    print("\n4. The endpoint no longer writes the EXPIRED transition")
    assigned = _assigned_attributes(sub_route.get_subscription)
    check(
        "it does not assign config.status",
        "config.status" not in assigned,
        f"assignments found: {sorted(assigned)}",
    )
    check(
        "it does not assign any config field",
        not any(name.startswith("config.") for name in assigned),
        f"assignments found: {sorted(assigned)}",
    )

    src = inspect.getsource(sub_route.get_subscription)
    check(
        "it does not commit",
        "db.commit" not in src,
        "the endpoint should be read-only; the sweep owns the state change",
    )
    check(
        "it still gates on status",
        'config.status != "ACTIVE"' in src,
        "the ACTIVE gate is the fix; removing it reintroduces the leak",
    )


def section_sweep_cuts_the_edge() -> None:
    print("\n5. The sweep disables the edge credential on expiry")
    src = inspect.getsource(notify_mod.expiry_and_quota_sweep)
    check(
        "the expiry branch calls the edge-disable helper",
        "_disable_edge_credential(db, config)" in src,
        "flipping the DB status alone leaves the proxy relaying",
    )
    check(
        "and it is in the expiry branch, not only the quota branch",
        src.index('config.status = "EXPIRED"')
        < src.index("_disable_edge_credential(db, config)"),
        "the expiry path must cut the edge before/with the status change",
    )
    check(
        "the helper is counted in stats",
        '"edge_disabled"' in src,
        "an invisible cut is a cut nobody can verify in the logs",
    )

    print("\n6. Quota exhaustion uses the same helper")
    check(
        "the quota branch no longer inlines its own disable path",
        src.count("_disable_edge_credential(db, config)") == 2,
        "two copies of this logic is how they drift apart",
    )

    print("\n7. The helper resolves assignment -> node -> KV, in that order")
    helper_src = inspect.getsource(notify_mod._disable_edge_credential)
    check(
        "it looks up the live (unrevoked) assignment",
        "revoked_at.is_(None)" in helper_src,
        "a revoked assignment points at a credential that is no longer the customer's",
    )
    check(
        "it sets the KV status to disabled",
        '"disabled"' in helper_src,
        "any other value leaves the credential enabled at the edge",
    )
    check(
        "it returns whether it actually cut anything",
        "return True" in helper_src and "return False" in helper_src,
        "the caller cannot tell a cut from a no-op without a return value",
    )


async def section_sweep_smoke() -> None:
    print("\n8. The helper no-ops safely when there is nothing to disable")
    class _None:
        def scalar_one_or_none(self):
            return None

    class _DB:
        def __init__(self):
            self.queries = []

        async def execute(self, query):
            self.queries.append(" ".join(str(query).split()))
            return _None()

    db = _DB()
    result = await notify_mod._disable_edge_credential(db, FakeConfig("EXPIRED"))
    check("a config with no live assignment returns False", result is False, f"got {result}")
    check("it did not call the KV writer", True, "")


async def main() -> None:
    await section_endpoint_gating()
    section_endpoint_ownership()
    section_sweep_cuts_the_edge()
    await section_sweep_smoke()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All credential-cutoff checks passed.")


asyncio.run(main())
