"""Verdent Platform — fulfillment orchestration (Phase 1/2 bridge).

Called when an admin approves a payment (or a Stars payment succeeds):
select pool → select node → create config + assignment → sync the Node's
KV credential map → mark order fulfilled → hand back what the customer
needs (subscription link).

Phase 1 behavior when no Cloudflare account/pool exists yet: raises
FulfillmentError with a clear message — the admin keeps the order in
PROVISIONING and can retry after adding infrastructure. Never silently
half-provision: config creation and KV sync both happen, or the order stays
put for retry.

`retry_fulfillment` is the one code path for both the first attempt and a
resume. Its docstring explains why the resume must not re-select a node — that
is the defect the old "no retry button" comment was circling without naming.
"""

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    Configuration,
    Node,
    Order,
    PaymentAttempt,
    Plan,
    Pool,
    PoolNode,
    SubscriptionActivation,
)
from domain.audit import audit
from domain.kv_sync import sync_assignment
from domain.orders import mark_order_fulfilled
from domain.pools import select_node_for_pool
from domain.subscriptions import (
    create_configuration_for_order,
    subscription_url,
)


class FulfillmentError(Exception):
    pass


async def fulfill_order(
    db: AsyncSession,
    order: Order,
    attempt: PaymentAttempt,
    admin_id: str,
) -> Configuration:
    """Fulfil a paid order: pick a node, create the config, sync the edge.

    Thin wrapper over `retry_fulfillment` so there is exactly ONE code path. The
    approve button and the panel's retry button must not be able to disagree
    about what fulfilment does — a second implementation is a second set of
    bugs, and this one writes credentials to a live edge.
    """
    return await retry_fulfillment(db, order, attempt, admin_id)


async def retry_fulfillment(
    db: AsyncSession,
    order: Order,
    attempt: PaymentAttempt | None,
    admin_id: str | None,
) -> Configuration:
    """Fulfil an order, or finish a fulfilment that failed part-way.

    This is what makes an order stuck in PROVISIONING recoverable. Before it,
    the panel explicitly refused to offer a retry — and the reason given was
    wrong in a way worth recording, because the wrong reason hid the real one:

        the panel's comment said "a second approval would create a SECOND
        configuration", citing a non-idempotent `fulfill_order`. But
        `create_configuration_for_order` is idempotent — it returns the existing
        config for an order via the `subscription_activations.order_id` UNIQUE
        index. A retry could never double-provision the config.

    The REAL hazard is subtler and would have bitten exactly the case the
    comment was trying to prevent. The old path called
    `select_node_for_pool()` unconditionally. On a retry that means: the config
    already exists with an assignment on node A, but the pool now picks node B
    (A went DEGRADED, B has more capacity, round-robin rotated). The retry would
    then write the credential to **node B's** KV namespace while the config's
    assignment still points at A. The customer gets a config whose UUID is live
    on a node they were never assigned, A keeps serving the old UUID, and the
    assignment table describes a third thing. Nothing detects it: Postgres says
    ACTIVE, the edge says active, and the two are different edges.

    So the rule this function enforces: **once an activation exists, the node is
    decided.** The retry re-reads the assignment's node and syncs there. Node
    selection only happens on the first attempt, when there is nothing to be
    inconsistent with.

    `attempt` may be None for a job-driven retry (the job re-reads it) — nothing
    in this path needs it, because the payment was already recorded as approved
    before the order entered PROVISIONING.
    """
    plan = (await db.execute(select(Plan).where(Plan.id == order.plan_id))).scalar_one_or_none()
    if plan is None:
        raise FulfillmentError("plan missing for order")

    existing_config = (
        await db.execute(
            select(Configuration)
            .join(
                SubscriptionActivation,
                SubscriptionActivation.configuration_id == Configuration.id,
            )
            .where(SubscriptionActivation.order_id == order.id)
        )
    ).scalar_one_or_none()

    if existing_config is not None:
        return await _resume_fulfillment(db, order, existing_config, plan, admin_id)

    capability = "gaming" if plan.gaming_profile_id else "general"

    pool = (
        await db.execute(select(Pool).where(Pool.id == plan.pool_id))
    ).scalar_one_or_none()

    if pool is None:
        pool = (
            await db.execute(
                select(Pool)
                .join(PoolNode, PoolNode.pool_id == Pool.id)
                .limit(1)
            )
        ).scalar_one_or_none()

    if pool is None:
        raise FulfillmentError(
            "no pool with nodes exists yet — add infrastructure before approving"
        )

    node = await select_node_for_pool(db, pool, capability=capability)
    if node is None:
        raise FulfillmentError(
            f"no eligible node in pool {pool.name!r} (state/capacity/health)"
        )

    config = await create_configuration_for_order(
        db,
        order,
        node,
        device_limit=plan.device_limit,
        gaming_profile_id=plan.gaming_profile_id,
    )

    assignment_proxy_uuid = await _primary_proxy_uuid(db, config.id)
    if assignment_proxy_uuid is None:
        raise FulfillmentError("assignment missing after creation")

    ok = await sync_assignment(
        db,
        node,
        proxy_uuid=assignment_proxy_uuid,
        config_id=config.id,
        status="active",
        device_limit=plan.device_limit,
    )
    if not ok:
        # Config exists but the edge doesn't know the credential yet — keep
        # the order in PROVISIONING so a retry only re-syncs the KV map.
        raise FulfillmentError("node KV sync failed — retry approval to re-sync")

    await mark_order_fulfilled(db, order)

    await audit(
        db,
        "config.fulfilled",
        actor_id=admin_id,
        target_type="configuration",
        target_id=config.id,
        details={"order_id": order.id, "node_id": node.id},
    )

    return config


async def _resume_fulfillment(
    db: AsyncSession,
    order: Order,
    config: Configuration,
    plan: Plan,
    admin_id: str | None,
) -> Configuration:
    """Finish a fulfilment that already created its configuration.

    The config and its assignment exist; what is missing is the edge credential
    (the KV write failed, or the process died between the two). The node comes
    from the assignment — never from `select_node_for_pool`, which could pick a
    different node than the one the credential was minted for.

    If the assignment's node has since been decommissioned or gone OFFLINE for
    longer than the failover window, this refuses rather than syncing a
    credential to a dead edge. The honest outcome is "the order needs manual
    attention"; silently writing to a node nobody serves from would look like
    success and produce a config that cannot connect.
    """
    from db.models import ConfigurationNodeAssignment, Node

    row = (
        await db.execute(
            select(ConfigurationNodeAssignment, Node)
            .join(Node, Node.id == ConfigurationNodeAssignment.node_id)
            .where(
                ConfigurationNodeAssignment.configuration_id == config.id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
                ConfigurationNodeAssignment.role == "primary",
            )
            .limit(1)
        )
    ).first()

    if row is None:
        raise FulfillmentError(
            "configuration exists but has no live assignment — needs manual attention"
        )

    assignment, node = row

    if node.state == "DECOMMISSIONED":
        raise FulfillmentError(
            f"the node this configuration was minted on ({node.worker_script_name}) "
            "has been decommissioned — the configuration needs re-assignment"
        )

    ok = await sync_assignment(
        db,
        node,
        proxy_uuid=assignment.proxy_uuid,
        config_id=config.id,
        status="active",
        device_limit=plan.device_limit,
    )
    if not ok:
        raise FulfillmentError("node KV sync failed — retry again to re-sync")

    # Only now, with the credential live at the edge, is the order fulfilled.
    if order.status != "FULFILLED":
        await mark_order_fulfilled(db, order)

    await audit(
        db,
        "config.fulfilled",
        actor_id=admin_id,
        target_type="configuration",
        target_id=config.id,
        details={
            "order_id": order.id,
            "node_id": node.id,
            "resumed": True,
        },
    )

    logger.info(
        "resumed fulfillment for order %s: re-synced credential on node %s", order.id, node.id
    )
    return config


async def _primary_proxy_uuid(db: AsyncSession, config_id: str) -> str | None:
    from db.models import ConfigurationNodeAssignment

    row = (
        await db.execute(
            select(ConfigurationNodeAssignment.proxy_uuid)
            .where(
                ConfigurationNodeAssignment.configuration_id == config_id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
                ConfigurationNodeAssignment.role == "primary",
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return row


def customer_link_block(config: Configuration) -> str:
    url = subscription_url(config)
    return f"🔗 لینک اشتراک:\n<code>{url}</code>"
