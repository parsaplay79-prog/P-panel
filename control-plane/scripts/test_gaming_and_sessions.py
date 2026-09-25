"""Regression tests for two defects that made the platform lie to customers.

1. SESSION-SLOT LEAK (node-worker, vless + trojan).
   `incrSession()` was called inside parseVlHeader/parseTrHeader, which
   declared its OWN `const admitted`. The outer-scope `admitted` — the flag
   finalize() gates `decrSession()` on — was only set after the parser
   returned successfully. So a connection that was admitted and THEN rejected
   during parsing (bad address type, empty address, unsupported command, a
   short SOCKS5 request, UDP to a port other than 53) charged a session slot
   that was never refunded. The counter only ever climbed, so a customer
   sending malformed connections could lock themselves out of their own
   subscription — and a plan's advertised device limit would read as reached
   with nobody connected.

   The invariant pinned here: increment and the flag that owns the decrement
   are set at ONE point, after every rejection.

2. DEAD GAMING PROFILE (control plane).
   gaming_profiles.settings_json was stored, honesty-validated, versioned and
   seeded — and read by nothing. `doh_endpoint` never reached a Node
   (provisioning hardcoded "dohUrl": "") and `stability_thresholds` merely
   duplicated constants in health.py. A gaming plan therefore differed from a
   normal one only by pool-tag routing, while the customer-facing copy
   (bot/texts.py) sells "stability and DNS".

Run: python scripts/test_gaming_and_sessions.py
"""

import asyncio
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domain import provisioning as prov_mod  # noqa: E402
from domain.health import (  # noqa: E402
    DEFAULT_THRESHOLDS,
    DEGRADED_AFTER_FAILURES,
    FAILOVER_AFTER_OFFLINE,
    OFFLINE_AFTER_FAILURES,
    ONLINE_AFTER_SUCCESSES,
    parse_thresholds,
    thresholds_for_node,
)

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


# The worker is TypeScript, so this half is a source-structure check. It is a
# blunt instrument, but the property being pinned — "the increment and the flag
# that owns the decrement are set together" — is structural, and the defect it
# catches was purely structural too.
WORKER_SRC = Path(__file__).resolve().parent.parent.parent / "node-worker" / "src" / "protocols"


def section_worker_slot_ownership() -> None:
    print("\n1. Worker: admission is incremented once, after every parse rejection")
    for proto in ("vless", "trojan"):
        path = WORKER_SRC / f"{proto}.ts"
        if not path.exists():
            check(f"{proto}.ts is present", False, f"missing at {path}")
            continue

        src = path.read_text(encoding="utf-8")

        check(
            f"{proto}: incrSession is called exactly once",
            src.count("incrSession(") == 1,
            f"found {src.count('incrSession(')} call sites — admission must have one owner",
        )

        # The parse-time rejections. Everything that can reject a connection
        # must be lexically BEFORE the increment, or the slot is charged with
        # no one left to refund it.
        incr_at = src.find("incrSession(")
        reject_at = src.find("if (parsed.hasError")
        check(
            f"{proto}: the increment follows the parse-error throw",
            reject_at != -1 and incr_at > reject_at,
            "the increment runs before the connection is known to be valid",
        )

        # `admitted` is the flag finalize() gates decrSession on, so it must be
        # set on the increment path — not merely declared.
        admitted_at = src.find("admitted = true")
        check(
            f"{proto}: the admitted flag is set after the increment",
            admitted_at != -1 and admitted_at > incr_at,
            "a connection can be counted and never decremented",
        )

        decr_at = src.find("decrSession(")
        check(
            f"{proto}: the decrement is gated on the admitted flag",
            "if (admitted && userConfigId)" in src and decr_at != -1,
            "an ungated decrement would under-count concurrent sessions",
        )

        # The failure mode this whole fix is about: a `const admitted` inside
        # the parser shadows the outer flag and silently re-creates the bug.
        parser_start = src.find("async function parse")
        parser_body = src[parser_start:] if parser_start != -1 else ""
        check(
            f"{proto}: the parser does not shadow `admitted`",
            "const admitted" not in parser_body,
            "a local `admitted` in the parser is the original defect",
        )

        # The parser must hand the limit up instead of enforcing it itself.
        check(
            f"{proto}: the parser returns the device limit for the caller",
            "deviceLimit: user.deviceLimit" in src,
            "without this the caller cannot admit with the right limit",
        )


def section_threshold_parsing() -> None:
    print("\n2. Gaming stability thresholds parse with safe fallbacks")
    check(
        "a missing profile keeps the built-in defaults",
        parse_thresholds(None) == DEFAULT_THRESHOLDS,
        "None must not raise inside the health loop",
    )
    check(
        "a profile without stability_thresholds keeps the defaults",
        parse_thresholds({"mtu_hint": 1280}) == DEFAULT_THRESHOLDS,
        "the key is optional",
    )

    parsed = parse_thresholds(
        {
            "stability_thresholds": {
                "degraded_after_failures": 3,
                "offline_after_failures": 8,
                "online_after_successes": 4,
                "failover_after_offline_minutes": 20,
            }
        }
    )
    check("a valid profile is honored", parsed.degraded_after_failures == 3, f"got {parsed}")
    check("offline threshold is honored", parsed.offline_after_failures == 8, f"got {parsed}")
    check("online threshold is honored", parsed.online_after_successes == 4, f"got {parsed}")
    check(
        "failover window is honored",
        parsed.failover_after_offline == timedelta(minutes=20),
        f"got {parsed.failover_after_offline}",
    )

    print("\n3. Malformed values degrade per-field instead of breaking the loop")
    zero = parse_thresholds(
        {"stability_thresholds": {"offline_after_failures": 0, "degraded_after_failures": 3}}
    )
    check(
        "a zero offline threshold falls back to the default",
        zero.offline_after_failures == OFFLINE_AFTER_FAILURES,
        "0 would mark a node OFFLINE on its first missed probe",
    )
    check(
        "but the valid sibling field is still honored",
        zero.degraded_after_failures == 3,
        "one bad key must not discard the whole profile",
    )

    negative = parse_thresholds({"stability_thresholds": {"degraded_after_failures": -1}})
    check(
        "a negative threshold falls back",
        negative.degraded_after_failures == DEGRADED_AFTER_FAILURES,
        f"got {negative.degraded_after_failures}",
    )

    boolean = parse_thresholds({"stability_thresholds": {"offline_after_failures": True}})
    check(
        "a boolean is not accepted as an integer",
        boolean.offline_after_failures == OFFLINE_AFTER_FAILURES,
        "True is an int in Python and would become a threshold of 1",
    )

    stringly = parse_thresholds({"stability_thresholds": {"offline_after_failures": "9"}})
    check(
        "a numeric string falls back",
        stringly.offline_after_failures == OFFLINE_AFTER_FAILURES,
        f"got {stringly.offline_after_failures}",
    )

    inverted = parse_thresholds(
        {"stability_thresholds": {"degraded_after_failures": 9, "offline_after_failures": 3}}
    )
    check(
        "an inverted pair is rejected rather than emptying the DEGRADED band",
        inverted.degraded_after_failures == DEGRADED_AFTER_FAILURES
        and inverted.offline_after_failures == OFFLINE_AFTER_FAILURES,
        f"got degraded={inverted.degraded_after_failures} offline={inverted.offline_after_failures}",
    )

    bad_minutes = parse_thresholds(
        {"stability_thresholds": {"failover_after_offline_minutes": "soon"}}
    )
    check(
        "a non-numeric failover window falls back",
        bad_minutes.failover_after_offline == FAILOVER_AFTER_OFFLINE,
        f"got {bad_minutes.failover_after_offline}",
    )

    check(
        "a non-dict settings_json does not raise",
        parse_thresholds("not a dict") == DEFAULT_THRESHOLDS,
        "JSONB can hold a scalar if something wrote one",
    )


class FakeNode:
    def __init__(self, tags: list[str]) -> None:
        self.capability_tags = tags


def section_node_gating() -> None:
    print("\n4. Only gaming-tagged nodes follow the gaming profile")
    settings = {"stability_thresholds": {"offline_after_failures": 9}}

    gaming = thresholds_for_node(FakeNode(["general", "doh", "gaming"]), settings)
    check(
        "a gaming node follows the profile",
        gaming.offline_after_failures == 9,
        f"got {gaming.offline_after_failures}",
    )

    general = thresholds_for_node(FakeNode(["general", "doh"]), settings)
    check(
        "a general node keeps the platform defaults",
        general.offline_after_failures == OFFLINE_AFTER_FAILURES,
        "one profile must not re-tune the whole fleet",
    )

    check(
        "a node with no tags keeps the defaults",
        thresholds_for_node(FakeNode([]), settings) == DEFAULT_THRESHOLDS,
        "an empty tag list must not be read as gaming",
    )
    check(
        "a node with a None tag list keeps the defaults",
        thresholds_for_node(FakeNode(None), settings) == DEFAULT_THRESHOLDS,
        "capability_tags is nullable in the schema",
    )
    check(
        "no profile means defaults even for a gaming node",
        thresholds_for_node(FakeNode(["gaming"]), None) == DEFAULT_THRESHOLDS,
        "the profile is the only source of overrides",
    )

    # Substring safety: "gaming" must be matched as a tag, not as a substring
    # of some other tag, and the reverse must not happen either.
    check(
        "tag matching is exact, not substring",
        thresholds_for_node(FakeNode(["non-gaming"]), settings) == DEFAULT_THRESHOLDS,
        "a substring test would treat 'non-gaming' as gaming",
    )


class _Profile:
    def __init__(self, settings_json) -> None:
        self.settings_json = settings_json


class _ProfileResult:
    def __init__(self, value) -> None:
        self._value = value

    def scalar_one_or_none(self):
        return self._value


class _ProfileDB:
    def __init__(self, profile) -> None:
        self._profile = profile

    async def execute(self, query):
        return _ProfileResult(self._profile)


async def section_doh_endpoint() -> None:
    print("\n5. The gaming profile's DoH endpoint reaches provisioning")

    endpoint = await prov_mod._current_doh_endpoint(
        _ProfileDB(_Profile({"doh_endpoint": "https://dns.example.com/dns-query"}))
    )
    check(
        "a valid endpoint is returned verbatim",
        endpoint == "https://dns.example.com/dns-query",
        f"got {endpoint!r}",
    )

    empty = await prov_mod._current_doh_endpoint(_ProfileDB(None))
    check(
        "no profile yields an empty string (worker default applies)",
        empty == "",
        f"got {empty!r}",
    )

    missing = await prov_mod._current_doh_endpoint(_ProfileDB(_Profile({"mtu_hint": 1280})))
    check(
        "a profile without doh_endpoint yields an empty string",
        missing == "",
        f"got {missing!r}",
    )

    not_url = await prov_mod._current_doh_endpoint(
        _ProfileDB(_Profile({"doh_endpoint": "dns.example.com"}))
    )
    check(
        "a non-http endpoint is rejected rather than shipped to a Node",
        not_url == "",
        "a Node booting with an unparseable resolver resolves nothing",
    )

    wrong_type = await prov_mod._current_doh_endpoint(
        _ProfileDB(_Profile({"doh_endpoint": 12345}))
    )
    check(
        "a non-string endpoint is rejected",
        wrong_type == "",
        f"got {wrong_type!r}",
    )

    scalar_json = await prov_mod._current_doh_endpoint(_ProfileDB(_Profile("nope")))
    check(
        "a non-dict settings_json is rejected",
        scalar_json == "",
        f"got {scalar_json!r}",
    )


def section_provisioning_uses_it() -> None:
    print("\n6. provision_node no longer hardcodes an empty DoH URL")
    import inspect

    src = inspect.getsource(prov_mod.provision_node)
    check(
        'the provisioned payload is not "dohUrl": ""',
        '"dohUrl": "",' not in src,
        "a hardcoded empty string is what made doh_endpoint dead",
    )
    check(
        "the payload uses the resolved endpoint",
        '"dohUrl": doh_endpoint' in src,
        "the profile value must reach the Node",
    )
    check(
        "the endpoint is resolved from the current profile",
        "_current_doh_endpoint(db)" in src,
        "the value has to come from somewhere",
    )


def section_health_uses_thresholds() -> None:
    print("\n7. The health loop reads thresholds instead of constants")
    import inspect

    from domain import health as health_mod

    src = inspect.getsource(health_mod.apply_health_transition)
    check(
        "the transition takes a thresholds argument",
        "thresholds: HealthThresholds = DEFAULT_THRESHOLDS" in src,
        "without a parameter the constants cannot be overridden",
    )
    check(
        "the offline comparison uses the parameter",
        "fails >= thresholds.offline_after_failures" in src,
        "a remaining constant would ignore the profile",
    )
    check(
        "the degraded comparison uses the parameter",
        "fails >= thresholds.degraded_after_failures" in src,
        "a remaining constant would ignore the profile",
    )
    check(
        "the recovery comparison uses the parameter",
        "thresholds.online_after_successes" in src,
        "recovery hysteresis is part of the same profile",
    )
    check(
        "the default still matches the documented constants",
        DEFAULT_THRESHOLDS.degraded_after_failures == DEGRADED_AFTER_FAILURES
        and DEFAULT_THRESHOLDS.offline_after_failures == OFFLINE_AFTER_FAILURES
        and DEFAULT_THRESHOLDS.online_after_successes == ONLINE_AFTER_SUCCESSES,
        "the no-profile path must be byte-identical to the old behaviour",
    )

    pass_src = inspect.getsource(health_mod.health_check_pass)
    check(
        "the pass loads the profile once",
        "await load_current_gaming_settings(db)" in pass_src,
        "one query per pass, not one per node",
    )
    check(
        "the pass threads it into the transition",
        "thresholds_for_node(node, gaming_settings)" in pass_src,
        "loading it without using it changes nothing",
    )

    failover_src = inspect.getsource(health_mod.failover_offline_nodes)
    check(
        "the failover window is per-node",
        "thresholds_for_node(node, gaming_settings).failover_after_offline" in failover_src,
        "a single up-front cutoff cannot vary by node",
    )


async def main() -> None:
    section_worker_slot_ownership()
    section_threshold_parsing()
    section_node_gating()
    await section_doh_endpoint()
    section_provisioning_uses_it()
    section_health_uses_thresholds()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("All gaming-profile and session-ownership checks passed.")


asyncio.run(main())
