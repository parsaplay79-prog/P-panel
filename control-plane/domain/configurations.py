"""Verdent Platform — configuration lifecycle (config.manage; Document 3 §L).

`config.manage` was declared in `domain/rbac.py`, granted to OWNER, ADMIN and
SUPPORT, and enforced by nothing: there was no way, anywhere in the product, to
suspend a customer's config, revoke a leaked one, rotate a subscription link, or
mint a fresh credential. An admin who needed to cut off abuse had one lever —
ban the customer — which also killed their support access and their order
history.

The rule every function here obeys, and the reason this module exists rather
than a status assignment at each call site:

    **A status change and its edge credential must move together.**

`domain/subscriptions.py` already documents what happens when they do not. An
earlier `extend_configuration()` flipped status back to ACTIVE but never
re-enabled the KV entry, so the customer was billed for a proxy that stayed
switched off, and nothing anywhere re-enabled it — the divergence was permanent
and invisible. The inverse is just as bad: suspending in Postgres while the
edge still serves the credential means the customer keeps using a config the
platform believes is off, and no sweep ever revisits it because the config's
status already looks correct.

So each mutation below does both, in the order that fails safe, and the KV write
goes through the queue so a Cloudflare outage retries instead of silently
skipping.
"""

import logging
import secrets
import uuid as uuid_lib
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    Configuration,
    ConfigurationNodeAssignment,
    Node,
)
from domain.audit import audit
from domain.jobs import (
    JOB_KV_SET_STATUS,
    enqueue,
    enqueue_key_for_kv_status,
)

logger = logging.getLogger("verdent.configurations")

STATUS_PENDING = "PENDING"
STATUS_PROVISIONING = "PROVISIONING"
STATUS_ACTIVE = "ACTIVE"
STATUS_SUSPENDED = "SUSPENDED"
STATUS_EXPIRED = "EXPIRED"
STATUS_DELETED = "DELETED"

ALL_CONFIG_STATUSES = (
    STATUS_PENDING,
    STATUS_PROVISIONING,
    STATUS_ACTIVE,
    STATUS_SUSPENDED,
    STATUS_EXPIRED,
    STATUS_DELETED,
)

CONFIG_STATUS_FA = {
    STATUS_PENDING: "در انتظار",
    STATUS_PROVISIONING: "در حال فعال‌سازی",
    STATUS_ACTIVE: "فعال",
    STATUS_SUSPENDED: "معلق",
    STATUS_EXPIRED: "منقضی",
    STATUS_DELETED: "حذف شده",
}


# Refusal reasons, as stable codes rather than English sentences. The routes put
# this value straight into a redirect's `?err=`, where the panel resolves it to
# a Persian sentence — so an exception carrying a sentence would surface as
# untranslated English in an admin's flash message. `RenameError` in
# `domain/subscriptions.py` works the same way for the same reason.
ERR_DELETED = "config_deleted"
ERR_NOT_REACTIVATABLE = "config_not_reactivatable"
ERR_NO_LIVE_ASSIGNMENT = "config_no_live_assignment"


class ConfigurationError(Exception):
    """A refused lifecycle change. `code` is the panel-facing reason."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code = code
        self.detail = detail


async def primary_assignment(
    db: AsyncSession, config: Configuration
) -> tuple[ConfigurationNodeAssignment, Node] | None:
    """The live primary (assignment, node) for a config, or None.

    `revoked_at IS NULL` and `role = 'primary'`: a failover leaves the old
    assignment row in place with a revoked_at stamp, so a lookup that ignored
    either column would hand back a node that no longer serves this config and
    every KV write would land on the wrong edge.
    """
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
        return None
    return row[0], row[1]


async def _queue_edge_status(
    db: AsyncSession,
    *,
    config: Configuration,
    node: Node,
    proxy_uuid: str,
    status: str,
    actor_id: str | None,
) -> None:
    """Queue the KV status flip for this credential.

    Queued rather than awaited for three reasons: the Cloudflare round trip
    makes a suspend button wait on the network; a failure here must not roll
    back the Postgres status the admin has already been told about; and a
    transient Cloudflare error must retry rather than leave the edge serving a
    credential the platform believes is off.

    The job is keyed by (node, credential, status), so clicking suspend twice
    queues one job while suspend-then-reactivate queues two.
    """
    await enqueue(
        db,
        JOB_KV_SET_STATUS,
        {
            "node_id": node.id,
            "proxy_uuid": proxy_uuid,
            "status": status,
            "configuration_id": config.id,
        },
        idempotency_key=enqueue_key_for_kv_status(node.id, proxy_uuid, status),
        requested_by=actor_id,
    )


async def suspend_configuration(
    db: AsyncSession, config: Configuration, actor_id: str | None = None
) -> Configuration:
    """Turn a config off: status SUSPENDED and the edge credential disabled.

    Idempotent — suspending an already-suspended config is a no-op rather than
    an error, because the panel's button is reachable twice by a double-click.
    Refuses only on a DELETED config, which has no live credential to disable.
    """
    if config.status == STATUS_DELETED:
        raise ConfigurationError(ERR_DELETED, "a deleted configuration cannot be suspended")

    already = config.status == STATUS_SUSPENDED
    config.status = STATUS_SUSPENDED

    live = await primary_assignment(db, config)
    if live is not None:
        assignment, node = live
        await _queue_edge_status(
            db,
            config=config,
            node=node,
            proxy_uuid=assignment.proxy_uuid,
            status="disabled",
            actor_id=actor_id,
        )

    await db.commit()

    if not already:
        await audit(
            db,
            "config.suspend",
            actor_id=actor_id,
            target_type="configuration",
            target_id=config.id,
            details={"node_id": live[1].id if live else None},
        )
    return config


async def reactivate_configuration(
    db: AsyncSession, config: Configuration, actor_id: str | None = None
) -> Configuration:
    """Turn a suspended config back on, edge included.

    Refuses on EXPIRED and DELETED: reviving an expired config would hand back
    service the platform already decided had ended, and the expiry sweep would
    immediately re-expire it — a flap the customer sees as a broken link.
    """
    if config.status in (STATUS_EXPIRED, STATUS_DELETED):
        raise ConfigurationError(
            ERR_NOT_REACTIVATABLE, f"a {config.status.lower()} configuration cannot be reactivated"
        )

    config.status = STATUS_ACTIVE

    live = await primary_assignment(db, config)
    if live is not None:
        assignment, node = live
        await _queue_edge_status(
            db,
            config=config,
            node=node,
            proxy_uuid=assignment.proxy_uuid,
            status="active",
            actor_id=actor_id,
        )

    await db.commit()
    await audit(
        db,
        "config.reactivate",
        actor_id=actor_id,
        target_type="configuration",
        target_id=config.id,
        details={"node_id": live[1].id if live else None},
    )
    return config


async def revoke_configuration(
    db: AsyncSession, config: Configuration, actor_id: str | None = None
) -> Configuration:
    """End a config for good: DELETED, edge disabled, assignments revoked.

    The nuclear option, and the one an admin reaches for when a credential has
    leaked or a customer is relaying traffic. Three things happen and all three
    are required:

      * the edge credential is disabled — otherwise a revoked config keeps
        working, which is the entire failure this button exists to prevent;
      * every live assignment is stamped revoked, so `active_assignments` stops
        reporting a node that no longer serves this config;
      * node capacity is released, or a node that once hosted N churned
        customers permanently loses that capacity and the eligible pool shrinks
        (see `release_stale_node_capacity`, which would eventually repair it,
        but only on the next sweep).
    """
    if config.status == STATUS_DELETED:
        return config

    live = await primary_assignment(db, config)
    if live is not None:
        assignment, node = live
        await _queue_edge_status(
            db,
            config=config,
            node=node,
            proxy_uuid=assignment.proxy_uuid,
            status="disabled",
            actor_id=actor_id,
        )

    now = datetime.now(timezone.utc)
    assignments = (
        await db.execute(
            select(ConfigurationNodeAssignment).where(
                ConfigurationNodeAssignment.configuration_id == config.id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
            )
        )
    ).scalars().all()

    touched_nodes: set[str] = set()
    for assignment in assignments:
        assignment.revoked_at = now
        touched_nodes.add(assignment.node_id)

    # Release capacity per node, once, floored at zero. Decrementing per
    # assignment would double-count a node that held two assignments here.
    for node_id in touched_nodes:
        node = (
            await db.execute(select(Node).where(Node.id == node_id))
        ).scalar_one_or_none()
        if node is not None:
            held = sum(1 for a in assignments if a.node_id == node_id)
            node.current_assignment_count = max(0, (node.current_assignment_count or 0) - held)

    config.status = STATUS_DELETED
    await db.commit()

    await audit(
        db,
        "config.revoke",
        actor_id=actor_id,
        target_type="configuration",
        target_id=config.id,
        details={"revoked_assignments": len(assignments)},
    )
    return config


async def rotate_subscription_token(
    db: AsyncSession, config: Configuration, actor_id: str | None = None
) -> Configuration:
    """Mint a new subscription link, invalidating the old one.

    The button for "the link leaked". `subscription_token` is the only secret in
    the URL — whoever holds it can fetch the full config — so rotating it is the
    only way to cut off someone the customer forwarded the link to.

    Deliberately does NOT touch the proxy credential: the existing client keeps
    working with its already-downloaded config, and the customer re-imports from
    the new link when convenient. Rotating both would drop the customer's
    current connection, which is a different (and much more disruptive) action —
    that is `rotate_proxy_credential`.
    """
    old = config.subscription_token
    config.subscription_token = secrets.token_urlsafe(24)
    await db.commit()
    await db.refresh(config)

    await audit(
        db,
        "config.rotate_subscription_token",
        actor_id=actor_id,
        target_type="configuration",
        target_id=config.id,
        # The old token is NOT recorded. It is a live secret until this
        # transaction commits, and audit_log is read by every admin role.
        details={"rotated": True, "old_token_suffix": (old or "")[-4:]},
    )
    return config


async def rotate_proxy_credential(
    db: AsyncSession, config: Configuration, actor_id: str | None = None
) -> dict:
    """Mint a fresh proxy credential on the same node; disable the old one.

    The button for "the config itself leaked" — the customer's client holds a
    `proxy_uuid`, and anyone who copies it can connect. Unlike the subscription
    token, changing this one DOES drop the customer's live connection, so it is
    a separate action from `rotate_subscription_token` and the panel labels it
    as disruptive.

    The old credential is disabled rather than deleted: if the new one fails to
    sync, the customer is left with nothing, and a disabled entry is
    recoverable — a deleted one is not.

    The new assignment is created on the SAME node as the current primary. A
    rotation must not silently migrate the customer to different hardware; that
    is failover's job, with its own eligibility rules and hysteresis.
    """
    live = await primary_assignment(db, config)
    if live is None:
        raise ConfigurationError(
            ERR_NO_LIVE_ASSIGNMENT, "configuration has no live assignment to rotate"
        )

    old_assignment, node = live

    if old_assignment.proxy_uuid:
        await _queue_edge_status(
            db,
            config=config,
            node=node,
            proxy_uuid=old_assignment.proxy_uuid,
            status="disabled",
            actor_id=actor_id,
        )

    now = datetime.now(timezone.utc)
    old_assignment.revoked_at = now

    new_assignment = ConfigurationNodeAssignment(
        configuration_id=config.id,
        node_id=node.id,
        role="primary",
        proxy_uuid=str(uuid_lib.uuid4()),
    )
    db.add(new_assignment)
    await db.flush()

    await enqueue(
        db,
        JOB_KV_SET_STATUS,
        {
            "node_id": node.id,
            "proxy_uuid": new_assignment.proxy_uuid,
            "status": "active",
            "configuration_id": config.id,
        },
        # Timestamped: a second rotation is a new request, not a duplicate of
        # the first, so it must produce its own job.
        idempotency_key=f"{enqueue_key_for_kv_status(node.id, new_assignment.proxy_uuid, 'active')}:{now.timestamp():.0f}",
        requested_by=actor_id,
    )

    await db.commit()

    await audit(
        db,
        "config.rotate_credential",
        actor_id=actor_id,
        target_type="configuration",
        target_id=config.id,
        details={"node_id": node.id, "new_proxy_uuid": new_assignment.proxy_uuid},
    )

    return {
        "node_id": node.id,
        "proxy_uuid": new_assignment.proxy_uuid,
        "configuration_id": config.id,
    }


async def rename_configuration_by_admin(
    db: AsyncSession,
    config: Configuration,
    new_display_name: str,
    actor_id: str | None = None,
) -> Configuration:
    """Admin-side rename, delegating the rules to `domain.subscriptions`.

    A thin wrapper so the audit row exists: the customer-facing rename in the
    bot is not audited, but an admin renaming someone else's config must be.
    The validation and the uniqueness re-check stay in one place — a second
    implementation of `validate_display_name` is a second set of rules.
    """
    from domain.subscriptions import rename_configuration

    before = config.display_name
    config = await rename_configuration(db, config, new_display_name)

    if config.display_name != before:
        await audit(
            db,
            "config.rename",
            actor_id=actor_id,
            target_type="configuration",
            target_id=config.id,
            details={"from": before, "to": config.display_name},
        )
    return config
