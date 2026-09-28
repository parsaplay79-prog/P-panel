"""Health — node samples, hysteresis counters, and the failover window.

The health system has three moving parts and the panel has to show all three,
because each one alone is misleading:

  * **The current verdict** (`node.state`, `health_score`) — what the platform
    believes right now.
  * **The samples behind it** (`node_health_samples`) — one row per probe. A
    score that dropped from 100 to 0 over five passes looks identical to one
    that fell in a single pass unless the samples are visible.
  * **The counters that decide the next transition** (`consecutive_failures`,
    `consecutive_successes`, `offline_since`) — the hysteresis. These are the
    reason a node that fails one probe is not immediately OFFLINE, and the
    reason failover waits ten minutes after OFFLINE rather than firing
    instantly.

That third part is the one worth a page. `DEGRADED_AFTER_FAILURES = 2`,
`OFFLINE_AFTER_FAILURES = 5`, `ONLINE_AFTER_SUCCESSES = 2`,
`FAILOVER_AFTER_OFFLINE = 10min` — and a node in MAINTENANCE is deliberately
exempt from all of it (`apply_health_transition` returns early on
OPERATOR_HELD_STATES). Without the counters on screen, "why has failover not
happened yet" is unanswerable from the panel.
"""

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.helpers import redirect, render
# Imported rather than restated: a node's state name is one fact, and a second
# copy of the mapping would drift from the one the nodes page shows.
from admin_panel.routes.nodes import NODE_STATE_FA, NODE_STATE_TAG
from db.base import get_db
from db.models import Node, NodeHealthSample
from domain import rbac
from domain.health import (
    DEGRADED_AFTER_FAILURES,
    FAILOVER_AFTER_OFFLINE,
    HEALTH_CHECK_INTERVAL,
    OFFLINE_AFTER_FAILURES,
    ONLINE_AFTER_SUCCESSES,
    OPERATOR_HELD_STATES,
    load_current_gaming_settings,
    thresholds_for_node,
)

logger = logging.getLogger("verdent.admin_panel.health")

router = APIRouter()


@router.get("/health")
async def health_overview(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """Every node with its verdict, counters, and the window it is inside.

    The per-node thresholds are resolved here through the same
    `thresholds_for_node` the health loop uses, so the numbers on screen are the
    numbers in effect — a gaming-tagged node follows the current profile's
    thresholds, everything else the defaults, and a page that showed the
    defaults for both would be wrong about half the fleet.
    """
    gaming_settings = await load_current_gaming_settings(db)

    nodes = (
        await db.execute(select(Node).order_by(Node.worker_script_name))
    ).scalars().all()

    # Last sample per node, in one query: DISTINCT ON is the Postgres idiom and
    # avoids N+1 on a page that shows the whole fleet.
    last_samples = {
        sample.node_id: sample
        for sample in (
            await db.execute(
                select(NodeHealthSample)
                .distinct(NodeHealthSample.node_id)
                .order_by(NodeHealthSample.node_id, NodeHealthSample.checked_at.desc())
            )
        ).scalars().all()
    }

    # Uptime over the last 24h, as a ratio of successful probes. The single most
    # useful number for "is this node actually reliable" and one that no single
    # sample can answer.
    window_start = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=24)
    success_rows = (
        await db.execute(
            select(
                NodeHealthSample.node_id,
                func.count(NodeHealthSample.id),
                func.count(NodeHealthSample.id).filter(NodeHealthSample.success.is_(True)),
            )
            .where(NodeHealthSample.checked_at >= window_start)
            .group_by(NodeHealthSample.node_id)
        )
    ).all()
    reliability = {
        node_id: {"total": int(total), "ok": int(ok)}
        for node_id, total, ok in success_rows
    }

    items = []
    for node in nodes:
        thresholds = thresholds_for_node(node, gaming_settings)
        stats = reliability.get(node.id, {"total": 0, "ok": 0})
        items.append(
            {
                "node": node,
                "thresholds": thresholds,
                "sample": last_samples.get(node.id),
                "reliability": stats,
                "uptime": (
                    round(stats["ok"] / stats["total"] * 100, 1) if stats["total"] else None
                ),
                "held": node.state in OPERATOR_HELD_STATES,
            }
        )

    return render(
        request,
        "health/overview.html",
        title="سلامت نودها",
        items=items,
        HEALTH_CHECK_INTERVAL=HEALTH_CHECK_INTERVAL,
        DEGRADED_AFTER_FAILURES=DEGRADED_AFTER_FAILURES,
        OFFLINE_AFTER_FAILURES=OFFLINE_AFTER_FAILURES,
        ONLINE_AFTER_SUCCESSES=ONLINE_AFTER_SUCCESSES,
        FAILOVER_AFTER_OFFLINE=FAILOVER_AFTER_OFFLINE,
        OPERATOR_HELD_STATES=OPERATOR_HELD_STATES,
        NODE_STATE_FA=NODE_STATE_FA,
        NODE_STATE_TAG=NODE_STATE_TAG,
        gaming_settings=gaming_settings,
        active_nav="/admin/health",
    )


@router.get("/health/{node_id}")
async def health_history(
    node_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_STATS_VIEW)),
):
    """One node's sample history, newest first, with latency and packet loss.

    Bounded to the most recent 500 samples rather than paginated: a health
    sample is a small row produced every 60 seconds, and the useful question is
    always about the recent past. The bound is stated on the page so a truncated
    view is not mistaken for the whole history.
    """
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/health", err="notfound")

    samples = (
        await db.execute(
            select(NodeHealthSample)
            .where(NodeHealthSample.node_id == node.id)
            .order_by(NodeHealthSample.checked_at.desc())
            .limit(500)
        )
    ).scalars().all()

    gaming_settings = await load_current_gaming_settings(db)
    thresholds = thresholds_for_node(node, gaming_settings)

    # A minute-by-minute failure run, collapsed: the page should show "5
    # consecutive failures starting 14:02" rather than five rows, because the
    # run is what crosses the threshold.
    runs: list[dict] = []
    current: dict | None = None
    for sample in samples:
        if current is None or current["success"] != sample.success:
            current = {
                "success": sample.success,
                "start": sample.checked_at,
                "end": sample.checked_at,
                "count": 1,
            }
            runs.append(current)
        else:
            current["count"] += 1
            current["end"] = sample.checked_at

    return render(
        request,
        "health/history.html",
        title=f"سلامت {node.worker_script_name}",
        node=node,
        samples=samples,
        runs=runs[:40],
        thresholds=thresholds,
        held=node.state in OPERATOR_HELD_STATES,
        active_nav="/admin/health",
    )
