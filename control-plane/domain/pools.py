"""Verdent Platform — pool selection & node admission (Phase 2).

Eligibility gate first (state, capacity, capability, health floor), then the
pool's strategy picks among eligible nodes:
- least_loaded: fewest current_assignment_count (default)
- round_robin: least recently assigned (max assigned_at among actives)
- sticky_score: health-score weighted least-loaded (gaming, Phase 3)

current_assignment_count is a denormalized counter, so it needs a sweep of its
own: release_stale_node_capacity() re-derives it from the assignment table.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Configuration, ConfigurationNodeAssignment, Node, Pool, PoolNode

logger = logging.getLogger("verdent.pools")

ELIGIBLE_STATES = {"ONLINE", "DEGRADED"}


def node_eligible(node: Node, pool: Pool, capability: str = "general") -> bool:
    if node.state not in ELIGIBLE_STATES:
        return False
    # Two caps bind at once and the TIGHTER one wins: min(node's own limit,
    # pool's max_customers_per_node). A pool may therefore tighten admission
    # (a quiet residential pool capped at 1 customer per node) but can never
    # loosen the node's own capacity — nodes are shared across pools, so a
    # pool-level raise would silently oversubscribe the hardware.
    capacity = min(node.max_assignment_count, pool.max_customers_per_node)
    if (node.current_assignment_count or 0) >= capacity:
        return False
    tags = set(node.capability_tags or [])
    if capability not in tags:
        return False
    if node.health_score is not None and node.health_score < pool.min_health_score:
        return False
    return True


async def select_node_for_pool(
    db: AsyncSession, pool: Pool | None, capability: str = "general"
) -> Node | None:
    """Pick the best eligible node in this pool, or None."""
    if pool is None:
        return None

    candidates = (
        await db.execute(
            select(Node)
            .join(PoolNode, PoolNode.node_id == Node.id)
            .where(PoolNode.pool_id == pool.id)
        )
        .scalars()
        .all()
    )

    eligible = [n for n in candidates if node_eligible(n, pool, capability)]
    if not eligible:
        return None

    if pool.selection_strategy == "round_robin":
        # least recently assigned among actives
        last_assigned: dict[str, datetime] = {}
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        for candidate in eligible:
            row = (
                await db.execute(
                    select(ConfigurationNodeAssignment.assigned_at)
                    .where(
                        ConfigurationNodeAssignment.node_id == candidate.id,
                        ConfigurationNodeAssignment.revoked_at.is_(None),
                    )
                    .order_by(ConfigurationNodeAssignment.assigned_at.desc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            last_assigned[candidate.id] = row or epoch

        return min(eligible, key=lambda n: last_assigned[n.id])

    if pool.selection_strategy == "sticky_score":
        # health-weighted: prefer high score, then low load
        return max(
            eligible,
            key=lambda n: (float(n.health_score or 0), -n.current_assignment_count),
        )

    # least_loaded (default)
    return min(eligible, key=lambda n: n.current_assignment_count)


async def release_stale_node_capacity(db: AsyncSession) -> int:
    """Give back node slots held by configs that are no longer ACTIVE.

    current_assignment_count only went down on failover/decommission, so a
    node that once hosted N churned customers permanently lost that capacity
    and the eligible pool shrank to nothing. Called from the expiry sweep.

    IDEMPOTENCY: the counter is re-derived from the assignment table, never
    adjusted by a per-assignment delta. The target is
    count(non-revoked assignments whose config is still ACTIVE) — state this
    function does not modify — so a second run computes the same target and
    finds current <= target: nothing to release. A naive "decrement once per
    stale assignment" pass would read the same stale rows twice and
    double-decrement. Release-only (never raises the counter) also means the
    sweep cannot resurrect the zero that decommissioning deliberately writes.
    """
    live_counts = dict(
        (
            await db.execute(
                select(
                    ConfigurationNodeAssignment.node_id,
                    func.count(ConfigurationNodeAssignment.id),
                )
                .join(
                    Configuration,
                    Configuration.id == ConfigurationNodeAssignment.configuration_id,
                )
                .where(
                    ConfigurationNodeAssignment.revoked_at.is_(None),
                    Configuration.status == "ACTIVE",
                )
                .group_by(ConfigurationNodeAssignment.node_id)
            )
        ).all()
    )

    released = 0
    nodes = (await db.execute(select(Node))).scalars().all()
    for node in nodes:
        live = int(live_counts.get(node.id, 0))
        current = node.current_assignment_count or 0
        if current > live:
            node.current_assignment_count = live
            released += current - live

    if released:
        logger.info("released %d stale node capacity slot(s)", released)
    return released
