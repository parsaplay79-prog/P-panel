"""Nodes — the fleet. Provisioning, state, capacity, decommission.

The two structural fixes this page carries:

  * **Provisioning is a job, not a request.** `provision_node` walks nine
    Cloudflare steps (KV namespace → secret → two worker uploads → subdomain →
    pool links → KV seed) and can take two minutes. The old panel called it
    inline from a POST handler, which meant a browser held a socket open for
    two minutes and a proxy timeout turned a node that was *successfully
    created* into an error page. Document 1 §M is explicit: "state-machine-
    driven background job … not a single long-running request". The form now
    enqueues and redirects to the job page, which the admin can watch, leave,
    and come back to.

  * **Operator-held states are separated from health.** MAINTENANCE and
    QUARANTINED are states a *human* sets, and `apply_health_transition`
    deliberately refuses to overwrite them — the health loop keeps probing and
    recording samples but leaves the state alone. That is what makes "drain this
    node" actually drain it. The state buttons here are therefore not a generic
    state setter; each one is a specific operational intent with its own
    consequence, labelled as such.
"""

import logging
import re

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from admin_panel import auth
from admin_panel.filters import is_htmx, parse_list_query
from admin_panel.helpers import redirect, render
from admin_panel.pagination import with_total
from db.base import get_db
from db.models import (
    CloudflareAccount,
    Configuration,
    ConfigurationNodeAssignment,
    Job,
    Node,
    NodeHealthSample,
    Pool,
    PoolNode,
)
from domain import jobs as jobs_domain
from domain import rbac
from domain.audit import audit
from domain.health import OPERATOR_HELD_STATES
from domain.jobs import JOB_DECOMMISSION_NODE, JOB_PROVISION_NODE, enqueue
from domain.jobs import enqueue_key_for_decommission, enqueue_key_for_provision

logger = logging.getLogger("verdent.admin_panel.nodes")

router = APIRouter()

NODE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")

# What a node created from this panel is tagged with. Same set the bot used, so
# a node made in either surface is admitted to the same pools.
NODE_CAPABILITY_TAGS = ["general", "doh", "gaming"]

NODE_STATE_FA = {
    "PROVISIONING": "در حال ساخت",
    "ONLINE": "آنلاین",
    "DEGRADED": "افت کیفیت",
    "OFFLINE": "آفلاین",
    "MAINTENANCE": "تعمیرات",
    "QUARANTINED": "قرنطینه",
    "DECOMMISSIONED": "برچیده شده",
}

NODE_STATE_TAG = {
    "PROVISIONING": "tag-warn",
    "ONLINE": "tag-ok",
    "DEGRADED": "tag-warn",
    "OFFLINE": "tag-bad",
    "MAINTENANCE": "tag-warn",
    "QUARANTINED": "tag-bad",
    "DECOMMISSIONED": "",
}

# The states an operator may set from this page, and what each one means.
# Deliberately excludes DEGRADED/OFFLINE: those are the health loop's verdicts,
# and letting a human write them by hand would put the panel's opinion in
# conflict with the probe's on the very next pass.
OPERATOR_STATES = {
    "ONLINE": "بازگرداندن به چرخه — نود در اولین بررسی موفق آنلاین می‌شود.",
    "MAINTENANCE": "تعمیرات — از چرخه خارج می‌شود، سلامت آن ثبت می‌شود ولی وضعیت دست‌نخورده می‌ماند.",
    "QUARANTINED": "قرنطینه — برای نودی که رفتار مشکوک دارد؛ هیچ کانفیگ جدیدی نمی‌گیرد.",
}

SORT_COLUMNS = {
    "created": Node.created_at,
    "state": Node.state,
    "health": Node.health_score,
    "load": Node.current_assignment_count,
    "name": Node.worker_script_name,
}


@router.get("/nodes")
async def nodes_list(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    query = parse_list_query(
        request,
        allowed_sorts=tuple(SORT_COLUMNS),
        default_sort="created",
        filter_keys=("state", "pool"),
    )

    stmt = select(Node).join(
        CloudflareAccount, CloudflareAccount.id == Node.cloudflare_account_id
    )
    count_stmt = select(func.count()).select_from(Node)

    conditions = []
    if query.q:
        pattern = f"%{query.q.lower()}%"
        conditions.append(
            or_(
                func.lower(Node.worker_script_name).like(pattern),
                func.lower(func.coalesce(Node.custom_domain, "")).like(pattern),
                func.lower(CloudflareAccount.label).like(pattern),
            )
        )
    if query.filters.get("state") in NODE_STATE_FA:
        conditions.append(Node.state == query.filters["state"])
    if query.filters.get("pool"):
        # A node in no pool is invisible to fulfilment, so "which nodes are in
        # this pool" is a question the list has to be able to answer.
        pool_nodes = select(PoolNode.node_id).where(PoolNode.pool_id == query.filters["pool"])
        conditions.append(Node.id.in_(pool_nodes))

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = int((await db.execute(count_stmt)).scalar_one())
    page = with_total(query.page, total)

    column = SORT_COLUMNS[query.sort]
    order_by = column.desc() if query.direction == "desc" else column.asc()

    rows = (
        await db.execute(
            stmt.add_columns(CloudflareAccount)
            .order_by(order_by)
            .limit(page.limit)
            .offset(page.offset)
        )
    ).all()

    items = [{"node": node, "account": account} for node, account in rows]

    pools = (await db.execute(select(Pool).order_by(Pool.name))).scalars().all()
    pool_names: dict[str, list[str]] = {}
    links = (
        await db.execute(
            select(PoolNode.node_id, Pool.name).join(Pool, Pool.id == PoolNode.pool_id)
        )
    ).all()
    for node_id, pool_name in links:
        pool_names.setdefault(node_id, []).append(pool_name)

    context = {
        "title": "نودها",
        "items": items,
        "pool_names": pool_names,
        "pools": pools,
        "page": page,
        "query": query,
        "base_path": "/admin/nodes",
        "NODE_STATE_FA": NODE_STATE_FA,
        "NODE_STATE_TAG": NODE_STATE_TAG,
        "states": list(NODE_STATE_FA),
        "active_nav": "/admin/nodes",
    }
    if is_htmx(request):
        return render(request, "nodes/_rows.html", **context)
    return render(request, "nodes/list.html", **context)


@router.get("/nodes/new")
async def node_new_form(
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    accounts = (
        await db.execute(select(CloudflareAccount).order_by(CloudflareAccount.label))
    ).scalars().all()
    return render(
        request,
        "nodes/form.html",
        title="ساخت نود جدید",
        accounts=accounts,
        default_tags=", ".join(NODE_CAPABILITY_TAGS),
        active_nav="/admin/nodes",
    )


@router.post("/nodes/new")
async def node_create(
    request: Request,
    script_name: str = Form(""),
    account_id: str = Form(""),
    capability_tags: str = Form(""),
    max_assignment_count: str = Form("3"),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Enqueue provisioning and go straight to the job page.

    The account is chosen explicitly rather than defaulting to `limit(1)` as the
    old panel did. With two Cloudflare accounts, "whichever comes first" is not
    a decision the operator made, and a node lands in an account they did not
    intend — visible only later, in a `worker_script_name` that is not where
    they were looking.

    Everything checkable without the network is checked here (name shape, name
    uniqueness, account existence, capacity), so an obvious mistake is a form
    error rather than a job that fails ninety seconds later.
    """
    script_name = script_name.strip().lower()

    def _fail(code: str):
        return redirect("/admin/nodes/new", err=code, name=script_name)

    if not NODE_NAME_RE.fullmatch(script_name):
        return _fail("bad_name")

    try:
        capacity = int(max_assignment_count or "3")
    except ValueError:
        return _fail("bad_capacity")
    if capacity <= 0 or capacity > 1000:
        return _fail("bad_capacity")

    account = (
        await db.execute(select(CloudflareAccount).where(CloudflareAccount.id == account_id))
    ).scalar_one_or_none()
    if account is None:
        return _fail("bad_account")

    taken = (
        await db.execute(
            select(Node.id).where(Node.worker_script_name == script_name).limit(1)
        )
    ).scalar_one_or_none()
    if taken:
        return _fail("name_taken")

    tags = [
        t.strip()
        for t in (capability_tags or "").replace("،", ",").split(",")
        if t.strip()
    ] or list(NODE_CAPABILITY_TAGS)

    job = await enqueue(
        db,
        JOB_PROVISION_NODE,
        {
            "cloudflare_account_id": account.id,
            "worker_script_name": script_name,
            "capability_tags": tags,
            "max_assignment_count": capacity,
        },
        idempotency_key=enqueue_key_for_provision(account.id, script_name),
        requested_by=admin.id,
    )

    await audit(
        db,
        "node.provision_requested",
        actor_id=admin.id,
        target_type="job",
        target_id=job.id,
        details={
            "script": script_name,
            "account_id": account.id,
            "tags": tags,
            "max_assignment_count": capacity,
        },
    )

    return redirect(f"/admin/jobs/{job.id}", ok="queued")


@router.get("/nodes/{node_id}")
async def node_detail(
    node_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """One node: health, capacity, its customers, its pools, its job history."""
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/nodes", err="notfound")

    account = (
        await db.execute(
            select(CloudflareAccount).where(CloudflareAccount.id == node.cloudflare_account_id)
        )
    ).scalar_one_or_none()

    # Live assignments: who is on this node right now. `revoked_at IS NULL` is
    # the definition of live — an assignment row outlives the credential it
    # describes, so counting rows without this filter reports history as load.
    assignment_rows = (
        await db.execute(
            select(ConfigurationNodeAssignment, Configuration)
            .join(Configuration, Configuration.id == ConfigurationNodeAssignment.configuration_id)
            .where(
                ConfigurationNodeAssignment.node_id == node.id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
            )
            .order_by(ConfigurationNodeAssignment.assigned_at.desc())
            .limit(200)
        )
    ).all()

    assignments = [
        {"assignment": assignment, "config": config}
        for assignment, config in assignment_rows
    ]

    samples = (
        await db.execute(
            select(NodeHealthSample)
            .where(NodeHealthSample.node_id == node.id)
            .order_by(NodeHealthSample.checked_at.desc())
            .limit(60)
        )
    ).scalars().all()

    pools = (
        await db.execute(
            select(Pool).join(PoolNode, PoolNode.pool_id == Pool.id).where(PoolNode.node_id == node.id)
        )
    ).scalars().all()

    node_jobs = (
        await db.execute(
            select(Job)
            .where(Job.payload_json["node_id"].astext == node.id)
            .order_by(Job.created_at.desc())
            .limit(20)
        )
    ).scalars().all()

    provision_jobs = (
        await db.execute(
            select(Job)
            .where(Job.payload_json["worker_script_name"].astext == node.worker_script_name)
            .order_by(Job.created_at.desc())
            .limit(10)
        )
    ).scalars().all()

    return render(
        request,
        "nodes/detail.html",
        title=f"نود {node.worker_script_name}",
        node=node,
        account=account,
        assignments=assignments,
        samples=samples,
        pools=pools,
        jobs=list(node_jobs) + [j for j in provision_jobs if j not in node_jobs],
        OPERATOR_STATES=OPERATOR_STATES,
        # The set the health loop refuses to override — the page needs it to
        # explain why a node is not being brought back online automatically.
        OPERATOR_HELD_STATES=OPERATOR_HELD_STATES,
        NODE_STATE_FA=NODE_STATE_FA,
        NODE_STATE_TAG=NODE_STATE_TAG,
        active_nav="/admin/nodes",
    )


@router.post("/nodes/{node_id}/state")
async def node_set_state(
    node_id: str,
    state: str = Form(""),
    reason: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Move a node into an operator-held state (or back out of one).

    Setting ONLINE does not make the node serve traffic by itself — the health
    loop's next successful probe does that. What this button does is release the
    operator's hold, which is the only thing that was keeping the node out of
    rotation. Writing ONLINE directly and stopping there would produce a node
    the panel calls healthy and the probe has not yet agreed with.
    """
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/nodes", err="notfound")

    if state not in OPERATOR_STATES:
        return redirect(f"/admin/nodes/{node_id}", err="bad_state")

    if node.state == "DECOMMISSIONED":
        return redirect(f"/admin/nodes/{node_id}", err="decommissioned")

    previous = node.state
    node.state = state

    if state == "ONLINE":
        # Releasing a hold: clear the failure streak so the node does not carry
        # a maintenance window's worth of accumulated failures into the first
        # probe and immediately fall back to DEGRADED.
        node.consecutive_failures = 0
        node.offline_since = None

    await db.commit()

    await audit(
        db,
        "node.state_change",
        actor_id=admin.id,
        target_type="node",
        target_id=node.id,
        details={"from": previous, "to": state, "reason": reason},
    )
    return redirect(f"/admin/nodes/{node_id}", ok="state_changed", to=state)


@router.post("/nodes/{node_id}/capacity")
async def node_set_capacity(
    node_id: str,
    max_assignment_count: str = Form(""),
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Change how many customers this node may hold.

    Lowering it below the current load is allowed and does NOT evict anyone —
    it only stops new admissions until the node drains naturally. Evicting live
    customers to satisfy a capacity edit would be a much larger action than the
    operator asked for, and the template says so where the number is entered.

    The effective ceiling is still `min(this, pool.max_customers_per_node)`, so
    raising this above the pool's own cap changes nothing until the pool moves
    too.
    """
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/nodes", err="notfound")

    try:
        capacity = int(max_assignment_count)
    except (TypeError, ValueError):
        return redirect(f"/admin/nodes/{node_id}", err="bad_capacity")
    if capacity <= 0 or capacity > 1000:
        return redirect(f"/admin/nodes/{node_id}", err="bad_capacity")

    previous = node.max_assignment_count
    node.max_assignment_count = capacity
    await db.commit()

    await audit(
        db,
        "node.capacity_change",
        actor_id=admin.id,
        target_type="node",
        target_id=node.id,
        details={"from": previous, "to": capacity, "load": node.current_assignment_count},
    )
    return redirect(f"/admin/nodes/{node_id}", ok="capacity_changed")


@router.post("/nodes/{node_id}/decommission")
async def node_decommission(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Take a node out of service for good. Enqueued, and refuses while busy.

    Refusing on live assignments is the important part. `decommission_node`
    deletes the Cloudflare worker script — which is the node's whole data plane
    — so running it with customers still assigned would cut off everyone on the
    node with no failover, because failover is driven by *health* going OFFLINE,
    not by an operator's decision to decommission. The refusal names the count
    and points at the two legitimate routes: let the health loop fail the node
    over, or set it MAINTENANCE first and wait for the assignments to drain.
    """
    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/nodes", err="notfound")

    if node.state == "DECOMMISSIONED":
        return redirect(f"/admin/nodes/{node_id}", ok="already_decommissioned")

    live = int(node.current_assignment_count or 0)
    if live:
        return redirect(f"/admin/nodes/{node_id}", err="node_busy", n=live)

    job = await enqueue(
        db,
        JOB_DECOMMISSION_NODE,
        {"node_id": node.id},
        idempotency_key=enqueue_key_for_decommission(node.id),
        requested_by=admin.id,
    )

    await audit(
        db,
        "node.decommission_requested",
        actor_id=admin.id,
        target_type="job",
        target_id=job.id,
        details={"node_id": node.id, "script": node.worker_script_name},
    )
    return redirect(f"/admin/jobs/{job.id}", ok="queued")


@router.post("/nodes/{node_id}/repair-pools")
async def node_repair_pools(
    node_id: str,
    db: AsyncSession = Depends(get_db),
    admin=Depends(auth.require_permission(rbac.PERM_NODE_MANAGE)),
):
    """Link this node into every pool whose tags it satisfies.

    The startup repair (`repair_pool_links_at_startup`) does this for the whole
    fleet once, but a pool created *after* a node was provisioned leaves that
    node in no pool — and a node in no pool is invisible to fulfilment while
    looking perfectly healthy on its own page. This is the same repair, scoped
    to the node the operator is looking at.
    """
    from domain.provisioning import attach_node_to_pools

    node = (await db.execute(select(Node).where(Node.id == node_id))).scalar_one_or_none()
    if node is None:
        return redirect("/admin/nodes", err="notfound")

    linked = await attach_node_to_pools(db, node)

    await audit(
        db,
        "node.repair_pools",
        actor_id=admin.id,
        target_type="node",
        target_id=node.id,
        details={"linked": linked},
    )
    return redirect(f"/admin/nodes/{node_id}", ok="pools_repaired", n=len(linked))
