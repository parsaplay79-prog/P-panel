"""Verdent Platform — node health loop (Document 3 §M; Phase 2/3).

Runs inside the `worker` service (sub-5-minute cadence — Railway cron can't
go there per Document 6 §N). Per node, every HEALTH_CHECK_INTERVAL:

  GET https://{custom_domain}/{securePath}/health   (5s timeout)

State transitions with REAL hysteresis (Document 3: "sticky failover with
real hysteresis" — no flap on a single missed probe):

  failures: 2 consecutive → DEGRADED (score 50), 5 consecutive → OFFLINE (0)
  successes: 2 consecutive → ONLINE (score 100)

Failover (Phase 2 ordinary / Phase 3 sticky): a config's primary assignment
is re-minted onto another eligible node ONLY after its node has been OFFLINE
for FAILOVER_AFTER_OFFLINE — never on the first blip, never while PROVISIONING.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.base import SessionLocal
from db.models import Configuration, ConfigurationNodeAssignment, Node, NodeHealthSample, Pool, PoolNode
from domain.pools import node_eligible, select_node_for_pool

logger = logging.getLogger("verdent.health")

HEALTH_CHECK_INTERVAL = 60          # seconds
DEGRADED_AFTER_FAILURES = 2
OFFLINE_AFTER_FAILURES = 5
ONLINE_AFTER_SUCCESSES = 2
FAILOVER_AFTER_OFFLINE = timedelta(minutes=10)

SCORE_ONLINE = 100
SCORE_DEGRADED = 50
SCORE_OFFLINE = 0

# States an operator sets deliberately. The health loop may observe them but
# must never transition a node out of them — see apply_health_transition.
OPERATOR_HELD_STATES = {"MAINTENANCE", "QUARANTINED", "DECOMMISSIONED"}


@dataclass(frozen=True)
class HealthThresholds:
    """The hysteresis numbers for one node.

    Defaults reproduce the module constants exactly, so a node with no gaming
    profile behaves as before. A gaming profile may override them, which is
    what makes `settings_json.stability_thresholds` a real setting instead of
    stored-but-unread data.
    """

    degraded_after_failures: int = DEGRADED_AFTER_FAILURES
    offline_after_failures: int = OFFLINE_AFTER_FAILURES
    online_after_successes: int = ONLINE_AFTER_SUCCESSES
    failover_after_offline: timedelta = FAILOVER_AFTER_OFFLINE


DEFAULT_THRESHOLDS = HealthThresholds()


def parse_thresholds(settings_json: dict | None) -> HealthThresholds:
    """Build HealthThresholds from a gaming profile's settings_json.

    Anything malformed falls back to the default for that field rather than
    raising: this runs inside the health loop, and a bad profile must not be
    able to stop every node from being probed. Values are also bounded — a
    zero or negative `offline_after_failures` would mark a node OFFLINE on its
    first missed probe, and `degraded > offline` would make DEGRADED
    unreachable, so both are rejected in favour of the default.
    """
    if not isinstance(settings_json, dict):
        return DEFAULT_THRESHOLDS

    raw = settings_json.get("stability_thresholds")
    if not isinstance(raw, dict):
        return DEFAULT_THRESHOLDS

    def _positive_int(key: str, default: int) -> int:
        value = raw.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            return default
        return value

    degraded = _positive_int("degraded_after_failures", DEGRADED_AFTER_FAILURES)
    offline = _positive_int("offline_after_failures", OFFLINE_AFTER_FAILURES)
    online = _positive_int("online_after_successes", ONLINE_AFTER_SUCCESSES)

    # DEGRADED is the band between the two failure counts; if the profile
    # inverts them the band is empty and only OFFLINE is ever reached. Keep
    # the default shape instead of silently disabling the intermediate state.
    if degraded > offline:
        degraded, offline = DEGRADED_AFTER_FAILURES, OFFLINE_AFTER_FAILURES

    minutes = raw.get("failover_after_offline_minutes")
    if isinstance(minutes, bool) or not isinstance(minutes, (int, float)) or minutes <= 0:
        failover = FAILOVER_AFTER_OFFLINE
    else:
        failover = timedelta(minutes=float(minutes))

    return HealthThresholds(
        degraded_after_failures=degraded,
        offline_after_failures=offline,
        online_after_successes=online,
        failover_after_offline=failover,
    )


def thresholds_for_node(node: Node, gaming_settings: dict | None) -> HealthThresholds:
    """Per-node thresholds: only gaming-tagged nodes follow the gaming profile.

    A general node on the same platform must keep the default hysteresis —
    tuning every node because one profile changed would turn a gaming
    preference into a platform-wide outage risk.
    """
    if gaming_settings is None:
        return DEFAULT_THRESHOLDS
    if "gaming" not in set(node.capability_tags or []):
        return DEFAULT_THRESHOLDS
    return parse_thresholds(gaming_settings)


async def load_current_gaming_settings(db: AsyncSession) -> dict | None:
    """settings_json of the current gaming profile, or None if none exists.

    Read once per pass and shared across nodes — this is one query per health
    pass, not one per node.
    """
    from db.models import GamingProfile

    profile = (
        await db.execute(
            select(GamingProfile).where(GamingProfile.is_current.is_(True)).limit(1)
        )
    ).scalar_one_or_none()
    return profile.settings_json if profile is not None else None


async def check_node_once(node: Node) -> tuple[bool, float | None]:
    """(success, latency_ms) — one probe against the node's health route."""
    from domain.provisioning import derive_secure_path

    base = (node.custom_domain or "").rstrip("/")
    if not base:
        return False, None

    url = f"{base}/{derive_secure_path(node.id)}/health"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        if resp.status_code == 200:
            return True, resp.elapsed.total_seconds() * 1000
        return False, None
    except Exception:  # noqa: BLE001
        return False, None


def apply_health_transition(
    node: Node,
    success: bool,
    latency_ms: float | None,
    thresholds: HealthThresholds = DEFAULT_THRESHOLDS,
) -> str:
    """Update health fields per the hysteresis rules; return new state.

    The counters are real columns, not Python attributes. The health loop
    opens a fresh session per pass, so anything held in memory reads back as
    0 next time and the DEGRADED/OFFLINE thresholds are never reached.
    """
    # `or SCORE_ONLINE` on a 0 score silently substituted 100, so a node that
    # decayed to 0 jumped back to 75 on the next probe and never stayed down.
    # An explicit None check keeps 0 meaning 0.
    current_score = SCORE_OFFLINE if node.health_score is None else int(node.health_score)

    # An operator holding a node in MAINTENANCE or QUARANTINED owns that state.
    # The health loop still probes it and records the sample, but must not
    # overwrite the state — otherwise draining a node for maintenance would
    # silently return it to rotation the moment it fails a probe.
    if node.state in OPERATOR_HELD_STATES:
        return node.state

    if success:
        node.control_plane_health = True
        node.data_plane_health = True
        node.health_score = min(SCORE_ONLINE, current_score + 50)
        node.consecutive_successes = (node.consecutive_successes or 0) + 1
        node.consecutive_failures = 0
        # Clear the OFFLINE clock the moment the node answers again, so a
        # node that flaps doesn't inherit a stale failover countdown.
        node.offline_since = None

        if node.consecutive_successes >= thresholds.online_after_successes:
            node.state = "ONLINE"
        elif node.state == "OFFLINE":
            # First success after being down: recovering, but not yet trusted.
            node.state = "DEGRADED"
        return node.state

    node.control_plane_health = False
    node.data_plane_health = False
    node.health_score = max(SCORE_OFFLINE, current_score - 25)
    node.consecutive_successes = 0
    node.consecutive_failures = (node.consecutive_failures or 0) + 1

    fails = node.consecutive_failures
    if fails >= thresholds.offline_after_failures:
        if node.state != "OFFLINE":
            # Stamp the transition once. Failover waits on this, so overwriting
            # it every pass would reset the countdown forever and never fire.
            node.offline_since = datetime.now(timezone.utc)
        node.state = "OFFLINE"
    elif fails >= thresholds.degraded_after_failures or node.state == "OFFLINE":
        node.state = "DEGRADED"
    return node.state


async def failover_offline_nodes(
    db: AsyncSession, gaming_settings: dict | None = None
) -> int:
    """Re-mint primary assignments of configs on long-offline nodes.

    `gaming_settings` is the current gaming profile's settings_json (or None).
    It only affects gaming-tagged nodes; the failover window is per-node, so
    the gate is computed inside the loop rather than once up front.
    """
    moved = 0

    offline_nodes = (
        await db.execute(select(Node).where(Node.state == "OFFLINE"))
    ).scalars().all()

    for node in offline_nodes:
        # Gate on when the node *entered* OFFLINE, not on its most recent
        # failed sample — that is rewritten every 60s, so it is never older
        # than the cutoff and the gate could never open.
        offline_since = node.offline_since
        window = thresholds_for_node(node, gaming_settings).failover_after_offline
        cutoff = datetime.now(timezone.utc) - window
        if offline_since is None or offline_since > cutoff:
            continue

        assignments = (
            await db.execute(
                select(ConfigurationNodeAssignment).where(
                    ConfigurationNodeAssignment.node_id == node.id,
                    ConfigurationNodeAssignment.revoked_at.is_(None),
                )
            )
        ).scalars().all()

        for assignment in assignments:
            config = (
                await db.execute(
                    select(Configuration).where(
                        Configuration.id == assignment.configuration_id,
                        Configuration.status == "ACTIVE",
                    )
                )
            ).scalar_one_or_none()
            if config is None:
                continue

            pool = (
                await db.execute(
                    select(Pool)
                    .join(PoolNode, PoolNode.pool_id == Pool.id)
                    .where(PoolNode.node_id == node.id)
                    .limit(1)
                )
            ).scalar_one_or_none()
            if pool is None:
                continue

            target = await select_node_for_pool(db, pool, capability="general")
            if target is None:
                logger.warning("failover for config %s: no eligible target", config.id)
                continue

            # Re-mint: revoke old assignment, create a new one with a fresh uuid
            assignment.revoked_at = datetime.now(timezone.utc)
            node.current_assignment_count = max(0, (node.current_assignment_count or 0) - 1)

            import uuid as uuid_lib

            new_assignment = ConfigurationNodeAssignment(
                configuration_id=config.id,
                node_id=target.id,
                role="primary",
                proxy_uuid=str(uuid_lib.uuid4()),
            )
            db.add(new_assignment)
            target.current_assignment_count = (target.current_assignment_count or 0) + 1

            from domain.kv_sync import set_entry_status, sync_assignment

            if assignment.proxy_uuid:
                await set_entry_status(db, node, assignment.proxy_uuid, "disabled")

            plan = None
            if config.plan_id:
                from db.models import Plan

                plan = (
                    await db.execute(select(Plan).where(Plan.id == config.plan_id))
                ).scalar_one_or_none()

            await sync_assignment(
                db,
                target,
                proxy_uuid=new_assignment.proxy_uuid,
                config_id=config.id,
                status="active",
                device_limit=plan.device_limit if plan else 1,
            )

            await audit_failover(config.id, node.id, target.id)
            moved += 1

        await db.commit()

    if moved:
        logger.info("failover moved %d assignment(s)", moved)
    return moved


async def audit_failover(config_id: str, from_node: str, to_node: str) -> None:
    async with SessionLocal() as db:
        from domain.audit import audit

        await audit(
            db,
            "config.failover",
            actor_type="system",
            actor_id=None,
            target_type="configuration",
            target_id=config_id,
            details={"from_node": from_node, "to_node": to_node},
        )


async def health_check_pass() -> dict:
    """One pass over all nodes: probe, transition, record, failover."""
    async with SessionLocal() as db:
        nodes = (
            await db.execute(select(Node).where(Node.state.notin_(["DECOMMISSIONED"])))
        ).scalars().all()

        # One query for the whole pass. Gaming-tagged nodes follow the current
        # profile's stability thresholds; everything else keeps the defaults.
        gaming_settings = await load_current_gaming_settings(db)

        results = []

        for node in nodes:
            success, latency = await check_node_once(node)
            state = apply_health_transition(
                node,
                success,
                latency,
                thresholds_for_node(node, gaming_settings),
            )

            db.add(
                NodeHealthSample(
                    node_id=node.id,
                    check_type="control_plane",
                    success=success,
                    latency_ms=latency,
                )
            )
            results.append({"node": node.id, "state": state, "ok": success})

        await db.commit()

        await failover_offline_nodes(db, gaming_settings)

    online = sum(1 for r in results if r["ok"])
    logger.info("health pass: %d/%d online", online, len(results))
    return {"checked": len(results), "online": online, "results": results}
