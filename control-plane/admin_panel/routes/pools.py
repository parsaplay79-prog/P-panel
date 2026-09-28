"""Pools — which nodes may serve which plans, and how one is picked.

A pool is the unit of *hardware grouping*: it declares a capability tag set, a
selection strategy, a health floor, and a per-node customer ceiling. A plan
points at exactly one pool, and `domain.pools.select_node_for_pool` picks a node
from it at fulfilment time.

Before this page existed, pools were seeded at first boot and never edited.
That was survivable only while there was one pool. The moment a second pool
existed — a gaming pool with a stricter health floor, say — nothing in the
product could put a node in it, and `attach_node_to_pools` would only ever link
nodes to pools whose tags it already satisfied. A node in the wrong pool is
invisible to fulfilment, and the failure it produces ("no eligible node") names
neither the pool nor the node.

Two things the page makes visible that the schema alone does not:

  * **Why a node is not eligible for a pool.** `node_eligible` is a conjunction
    of five conditions (state, two capacity caps, capability tag, health floor).
    The membership view evaluates each one per node and shows which fails, so
    "this node is not serving traffic" has an answer other than reading source.
  * **That the tighter capacity cap wins.** The effective ceiling is
    `min(node.max_assignment_count, pool.max_customers_per_node)` — a pool can
    tighten admission but never loosen it. The form says so where the number is
    entered, because an operator raising it and seeing nothing change would
    otherwise file a bug.
"""

import logging

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import Node, Plan, Pool, PoolNode
from domain import rbac
from domain.audit import audit
from domain.pools import ELIGIBLE_STATES, node_eligible

logger = logging.getLogger("verdent.admin_panel.pools")

router = APIRouter()

STRATEGY_FA = {
    "round_robin": "گردشی (کمترین استفاده‌ی اخیر)",
    "least_loaded": "کم‌بارترین",
    "sticky_score": "امتیاز سلامت (گیمینگ)",
}

ALL_STRATEGIES = tuple(STRATEGY_FA)

SORT_COLUMNS = {
    "name": Pool.name,
    "strategy": Pool.selection_strategy,
    "health": Pool.min_health_score,
    "cap": Pool.max_customers_per_node,
}


def _eligibility_reasons(node: Node, pool: Pool) -> list[str]:
    """Every reason this node is not eligible, in the order `node_eligible`
    checks them. Empty means eligible.

    A copy of the domain function's logic would drift, so this re-uses
    `node_eligible` for the verdict and only re-derives the *explanation*.
    That split matters: the boolean comes from one place, and the sentence
    explaining it cannot disagree with the boolean.
    """
    reasons: list[str] = []
    if node.state not in ELIGIBLE_STATES:
        reasons.append(f"وضعیت نود {node.state} است")
    capacity = min(node.max_assignment_count, pool.max_customers_per_node)
    if (node.current_assignment_count or 0) >= capacity:
        reasons.append(f"ظرفیت پر است ({node.current_assignment_count}/{capacity})")
    node_tags = set(node.capability_tags or [])
    if pool.capability_tags and not set(pool.capability_tags).issubset(node_tags):
        missing = sorted(set(pool.capability_tags) - node_tags)
        reasons.append("تگ ندارد: " + "، ".join(missing))
    if node.health_score is not None and node.health_score < pool.min_health_score:
        reasons.append(f"امتیاز سلامت {node.health_score} کمتر از حد {pool.min_health_score}")
    return reasons


@router.get("/pools")
async def pools_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="name",
        filter_keys=("strategy",),
    )

    stmt = select(Pool)
    count_stmt = select(func.count()).select_from(Pool)

    conditions = []
    if query.q:
        conditions.append(func.lower(Pool.name).like(f"%{query.q.lower()}%"))
    if query.filters.get("strategy") in ALL_STRATEGIES:
        conditions.append(Pool.selection_strategy == query.filters["strategy"])

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    pools = (
        await db.execute(stmt.order_by(order_by).limit(page.limit).offset(page.offset))
    ).scalars().all()

    # Node counts and plan counts per pool, grouped — a 50-row page must not
    # issue 100 counts.
    node_counts = dict(
        (
            await db.execute(
                select(PoolNode.pool_id, func.count(PoolNode.node_id)).group_by(PoolNode.pool_id)
            )
        ).all()
    )
    plan_counts = dict(
        (
            await db.execute(select(Plan.pool_id, func.count(Plan.id)).group_by(Plan.pool_id))
        ).all()
    )

    context = {
        "title": "استخرها",
        "pools": pools,
        "node_counts": {k: int(v) for k, v in node_counts.items()},
        "plan_counts": {k: int(v) for k, v in plan_counts.items()},
        "page": page,
        "query": query,
        "base_path": "/admin/pools",
        "STRATEGY_FA": STRATEGY_FA,
        "active_nav": "/admin/pools",
    }
    if is_htmx(request):
        return render(request, "pools/_rows.html", **context)
    return render(request, "pools/list.html", **context)


@router.get("/pools/new")
async def pool_new_form(
    request: Request,
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    return render(
        request,
        "pools/form.html",
        title="استخر جدید",
        pool=None,
        strategies=ALL_STRATEGIES,
        STRATEGY_FA=STRATEGY_FA,
        active_nav="/admin/pools",
    )


def _validate_pool_form(
    name: str,
    strategy: str,
    min_health_score: str,
    max_customers_per_node: str,
    backup_count: str,
) -> tuple[dict | None, str]:
    """(validated fields, error code). One implementation for create and edit.

    Two routes validating the same form is how a create that accepts a value
    and an edit that rejects it happens; the checks live here so they cannot.
    """
    name = name.strip()
    if not name:
        return None, "name_required"
    if len(name) > 60:
        return None, "name_too_long"

    if strategy not in ALL_STRATEGIES:
        return None, "bad_strategy"

    try:
        health = float(min_health_score or "50")
    except ValueError:
        return None, "bad_health"
    if health < 0 or health > 100:
        return None, "bad_health"

    try:
        cap = int(max_customers_per_node or "3")
    except ValueError:
        return None, "bad_cap"
    if cap <= 0 or cap > 1000:
        return None, "bad_cap"

    try:
        backups = int(backup_count or "0")
    except ValueError:
        return None, "bad_backups"
    if backups < 0 or backups > 10:
        return None, "bad_backups"

    return {
        "name": name,
        "strategy": strategy,
        "min_health_score": health,
        "max_customers_per_node": cap,
        "backup_count": backups,
    }, ""


def _form_echo(
    name: str,
    capability_tags: str,
    selection_strategy: str,
    min_health_score: str,
    max_customers_per_node: str,
    backup_count: str,
) -> dict[str, str]:
    """The submitted values, to be echoed back on a validation error.

    A rejected form that returns six blank fields makes the operator retype
    everything to fix one typo, and people work around that by not using the
    form. Echoing is cheap and it is the difference between a page that is
    usable and one that is merely correct.
    """
    return {
        "name": name,
        "capability_tags": capability_tags,
        "selection_strategy": selection_strategy,
        "min_health_score": min_health_score,
        "max_customers_per_node": max_customers_per_node,
        "backup_count": backup_count,
    }


@router.post("/pools/new")
async def pool_create(
    name: str = Form(""),
    capability_tags: str = Form(""),
    selection_strategy: str = Form("round_robin"),
    min_health_score: str = Form("50"),
    max_customers_per_node: str = Form("3"),
    backup_count: str = Form("0"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    echo = _form_echo(
        name, capability_tags, selection_strategy, min_health_score,
        max_customers_per_node, backup_count,
    )
    fields, error = _validate_pool_form(
        name, selection_strategy, min_health_score, max_customers_per_node, backup_count
    )
    if fields is None:
        return redirect("/admin/pools/new", err=error, **echo)

    exists = (
        await db.execute(select(Pool).where(Pool.name == fields["name"]))
    ).scalar_one_or_none()
    if exists is not None:
        return redirect("/admin/pools/new", err="name_taken", **echo)

    tags = [t.strip() for t in (capability_tags or "").replace("،", ",").split(",") if t.strip()]

    pool = Pool(
        name=fields["name"],
        capability_tags=tags,
        selection_strategy=fields["strategy"],
        min_health_score=fields["min_health_score"],
        max_customers_per_node=fields["max_customers_per_node"],
        backup_count=fields["backup_count"],
    )
    db.add(pool)
    await db.commit()

    await audit(
        db,
        "pool.create",
        actor_id=admin.id,
        target_type="pool",
        target_id=pool.id,
        details={"name": pool.name, "tags": tags, "strategy": pool.selection_strategy},
    )
    return redirect("/admin/pools", ok="created")


@router.get("/pools/{pool_id}")
async def pool_detail(
    pool_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """A pool, its plans, and every node's eligibility with the reason.

    The eligibility table is the point of this page. `select_node_for_pool`
    returns None for five different reasons and reports none of them; an
    operator staring at a pool that will not serve traffic needs the reason,
    not the boolean.
    """
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    if pool is None:
        return redirect("/admin/pools", err="notfound")

    member_ids = set(
        (
            await db.execute(select(PoolNode.node_id).where(PoolNode.pool_id == pool.id))
        ).scalars().all()
    )

    all_nodes = (await db.execute(select(Node).order_by(Node.worker_script_name))).scalars().all()

    members = []
    non_members = []
    for node in all_nodes:
        entry = {
            "node": node,
            "eligible": node_eligible(node, pool),
            "reasons": _eligibility_reasons(node, pool),
            "is_member": node.id in member_ids,
        }
        (members if entry["is_member"] else non_members).append(entry)

    plans = (
        await db.execute(select(Plan).where(Plan.pool_id == pool.id).order_by(Plan.name))
    ).scalars().all()

    return render(
        request,
        "pools/detail.html",
        title=f"استخر {pool.name}",
        pool=pool,
        members=members,
        non_members=non_members,
        plans=plans,
        STRATEGY_FA=STRATEGY_FA,
        active_nav="/admin/pools",
    )


@router.get("/pools/{pool_id}/edit")
async def pool_edit_form(
    pool_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    if pool is None:
        return redirect("/admin/pools", err="notfound")

    return render(
        request,
        "pools/form.html",
        title=f"ویرایش استخر {pool.name}",
        pool=pool,
        strategies=ALL_STRATEGIES,
        STRATEGY_FA=STRATEGY_FA,
        active_nav="/admin/pools",
    )


@router.post("/pools/{pool_id}/edit")
async def pool_update(
    pool_id: str,
    name: str = Form(""),
    capability_tags: str = Form(""),
    selection_strategy: str = Form("round_robin"),
    min_health_score: str = Form("50"),
    max_customers_per_node: str = Form("3"),
    backup_count: str = Form("0"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    if pool is None:
        return redirect("/admin/pools", err="notfound")

    echo = _form_echo(
        name, capability_tags, selection_strategy, min_health_score,
        max_customers_per_node, backup_count,
    )
    edit_path = f"/admin/pools/{pool_id}/edit"

    fields, error = _validate_pool_form(
        name, selection_strategy, min_health_score, max_customers_per_node, backup_count
    )
    if fields is None:
        return redirect(edit_path, err=error, **echo)

    clash = (
        await db.execute(
            select(Pool).where(Pool.name == fields["name"], Pool.id != pool.id)
        )
    ).scalar_one_or_none()
    if clash is not None:
        return redirect(edit_path, err="name_taken", **echo)

    tags = [t.strip() for t in (capability_tags or "").replace("،", ",").split(",") if t.strip()]

    before = {
        "name": pool.name,
        "capability_tags": sorted(pool.capability_tags or []),
        "selection_strategy": pool.selection_strategy,
        "min_health_score": str(pool.min_health_score),
        "max_customers_per_node": pool.max_customers_per_node,
        "backup_count": pool.backup_count,
    }

    pool.name = fields["name"]
    pool.capability_tags = tags
    pool.selection_strategy = fields["strategy"]
    pool.min_health_score = fields["min_health_score"]
    pool.max_customers_per_node = fields["max_customers_per_node"]
    pool.backup_count = fields["backup_count"]
    await db.commit()

    after = {
        "name": pool.name,
        "capability_tags": sorted(pool.capability_tags or []),
        "selection_strategy": pool.selection_strategy,
        "min_health_score": str(pool.min_health_score),
        "max_customers_per_node": pool.max_customers_per_node,
        "backup_count": pool.backup_count,
    }
    changed = {k: {"from": before[k], "to": after[k]} for k in before if before[k] != after[k]}

    await audit(
        db,
        "pool.update",
        actor_id=admin.id,
        target_type="pool",
        target_id=pool.id,
        details={"changed": changed},
    )
    return redirect(f"/admin/pools/{pool_id}", ok="updated")


@router.post("/pools/{pool_id}/nodes/add")
async def pool_add_node(
    pool_id: str,
    node_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Link a node into the pool. Idempotent.

    Deliberately does NOT check eligibility. Membership and eligibility are
    different questions: a node can legitimately be a member while temporarily
    ineligible (OFFLINE, full, mid-maintenance), and refusing to link it would
    mean an operator cannot pre-stage hardware. The detail page shows the
    ineligibility reason instead, which is the honest version of the same
    information.
    """
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if pool is None or node is None:
        return redirect("/admin/pools", err="notfound")

    exists = (
        await db.execute(
            select(PoolNode).where(PoolNode.pool_id == pool.id, PoolNode.node_id == node.id)
        )
    ).scalar_one_or_none()
    if exists is None:
        db.add(PoolNode(pool_id=pool.id, node_id=node.id))
        await db.commit()
        await audit(
            db,
            "pool.node_add",
            actor_id=admin.id,
            target_type="pool",
            target_id=pool.id,
            details={"node_id": node.id, "script": node.worker_script_name},
        )

    return redirect(f"/admin/pools/{pool_id}", ok="node_added")


@router.post("/pools/{pool_id}/nodes/remove")
async def pool_remove_node(
    pool_id: str,
    node_id: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Unlink a node. Refuses while the pool still has customers on that node.

    Removing membership does not move anyone: the existing assignments stay
    pointing at the node, and `select_node_for_pool` simply stops offering it
    for new ones. That is usually what an operator wants when draining
    hardware — but not when they meant to take a node out of service entirely,
    which is what the node page's decommission is for. The refusal names the
    live assignment count so the two actions can be told apart.
    """
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if pool is None or node is None:
        return redirect("/admin/pools", err="notfound")

    live = int(node.current_assignment_count or 0)
    if live:
        return redirect(f"/admin/pools/{pool_id}", err="node_busy", n=live)

    await db.execute(
        delete(PoolNode).where(PoolNode.pool_id == pool.id, PoolNode.node_id == node.id)
    )
    await db.commit()

    await audit(
        db,
        "pool.node_remove",
        actor_id=admin.id,
        target_type="pool",
        target_id=pool.id,
        details={"node_id": node.id, "script": node.worker_script_name},
    )
    return redirect(f"/admin/pools/{pool_id}", ok="node_removed")


@router.post("/pools/{pool_id}/delete")
async def pool_delete(
    pool_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Delete an unused pool. Refuses when a plan or a node points at it.

    `plans.pool_id` is NOT NULL and `pool_nodes` cascades, so deleting a pool a
    plan uses would either orphan the plan's fulfilment or (via the FK) raise a
    500. Both refusals are reported as counts.
    """
    pool = (await db.execute(select(Pool).where(Pool.id == pool_id))).scalar_one_or_none()
    if pool is None:
        return redirect("/admin/pools", err="notfound")

    plan_count = int(
        (
            await db.execute(
                select(func.count()).select_from(Plan).where(Plan.pool_id == pool.id)
            )
        ).scalar_one()
    )
    if plan_count:
        return redirect("/admin/pools", err="has_plans", n=plan_count)

    node_count = int(
        (
            await db.execute(
                select(func.count()).select_from(PoolNode).where(PoolNode.pool_id == pool.id)
            )
        ).scalar_one()
    )
    if node_count:
        return redirect("/admin/pools", err="has_nodes", n=node_count)

    name = pool.name
    await db.delete(pool)
    await db.commit()

    await audit(
        db,
        "pool.delete",
        actor_id=admin.id,
        target_type="pool",
        target_id=pool_id,
        details={"name": name},
    )
    return redirect("/admin/pools", ok="deleted")
