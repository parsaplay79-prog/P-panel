"""Verdent Platform — subscription serving (Document 3 §L; Phase 1).

- create_configuration_for_order: builds the Configuration + mints the
  proxy credential on the selected node (assignment), the ONE place where
  the "one order → one activation" idempotency guarantee is enforced.
- render_vless_uris / build_subscription_body: the /s/{token} renderer.
- usage_totals: quota math — the current period starts at
  (expires_at - plan.duration_days), which makes renewal reset consumption
  WITHOUT any schema change.
"""

import base64
import secrets
import uuid as uuid_lib
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import (
    Configuration,
    ConfigurationNodeAssignment,
    Node,
    Order,
    Plan,
    SubscriptionActivation,
    UsageDailyAggregate,
)
from domain.config import settings
from domain.naming import create_unique_config_name_pair, validate_display_name


class SubscriptionError(Exception):
    pass


async def create_configuration_for_order(
    db: AsyncSession,
    order: Order,
    node: Node,
    *,
    device_limit: int | None = None,
    gaming_profile_id: str | None = None,
) -> Configuration:
    """Create the Configuration + assignment for a PAID order. Idempotent via
    subscription_activations.order_id UNIQUE — a re-run returns the existing
    config instead of double-provisioning."""
    existing = (
        await db.execute(
            select(Configuration)
            .join(SubscriptionActivation, SubscriptionActivation.configuration_id == Configuration.id)
            .where(SubscriptionActivation.order_id == order.id)
        )
    ).scalar_one_or_none()

    if existing is not None:
        return existing

    plan = (
        await db.execute(select(Plan).where(Plan.id == order.plan_id))
    ).scalar_one_or_none()

    display_name, suffix = await create_unique_config_name_pair(
        db, order.requested_display_name
    )

    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=plan.duration_days if plan else 30)

    config = Configuration(
        id=str(uuid_lib.uuid4()),
        customer_id=order.customer_id,
        plan_id=order.plan_id,
        display_name=display_name,
        suffix=suffix,
        subscription_token=secrets.token_urlsafe(24),
        config_type="gaming" if (gaming_profile_id or (plan and plan.gaming_profile_id)) else "normal",
        gaming_profile_id=gaming_profile_id or (plan.gaming_profile_id if plan else None),
        status="ACTIVE",
        is_test=False,
        created_at=now,
        expires_at=expires,
    )
    db.add(config)
    await db.flush()

    proxy_uuid = str(uuid_lib.uuid4())
    assignment = ConfigurationNodeAssignment(
        configuration_id=config.id,
        node_id=node.id,
        role="primary",
        proxy_uuid=proxy_uuid,
    )
    db.add(assignment)

    db.add(SubscriptionActivation(order_id=order.id, configuration_id=config.id))

    node.current_assignment_count = (node.current_assignment_count or 0) + 1
    await db.commit()

    return config


# Renewal is intentionally NOT implemented (decision 2026-09-25: ship without
# it, add it later if wanted). An earlier version had extend_configuration()
# here, and it was wrong in two ways that are hard to see:
#
#   * it flipped status back to ACTIVE but never re-enabled the edge
#     credential in the node's KV map — so the customer would be billed for a
#     subscription whose proxy stayed switched off, and nothing anywhere else
#     re-enables that KV entry, making the divergence permanent;
#   * renewing a config that had been deliberately disabled (suspended, or cut
#     by the quota sweep) silently brought it back, turning an enforcement
#     decision into free service.
#
# If renewal returns it must set the status AND the edge KV entry in one
# operation, and must refuse to revive a config a human or the sweep disabled.
# The usage period is derived (expires_at - plan.duration_days) precisely so a
# future renewal can reset consumption with no schema change — keep that.


# ---------------------------------------------------------------------------
# Usage + quota (Document 3 §K)
# ---------------------------------------------------------------------------


async def usage_current_period_detail(
    db: AsyncSession, config: Configuration
) -> tuple[int, int, int, int | None]:
    """(used, bytes_up, bytes_down, quota|None) for the current period.

    Period start = expiry minus plan duration, so renewals reset consumption
    without a schema change.

    Up and down are returned separately because the ledger and the daily
    aggregate both carry them separately, and `subscription-userinfo` is
    specified per-direction: clients (v2rayN, Clash, sing-box) draw two bars
    and add them up for their own total. Publishing the period TOTAL in both
    fields made every client report double the real traffic — and the more a
    customer used, the more wrong it got.
    """
    quota: int | None = None
    period_start = config.created_at

    if config.is_test:
        quota = config.test_quota_bytes
    elif config.plan_id:
        plan = (await db.execute(select(Plan).where(Plan.id == config.plan_id))).scalar_one_or_none()
        if plan is not None:
            quota = plan.traffic_quota_bytes
            if config.expires_at:
                period_start = config.expires_at - timedelta(days=plan.duration_days)

    rows = (
        await db.execute(
            select(UsageDailyAggregate).where(
                UsageDailyAggregate.configuration_id == config.id,
                UsageDailyAggregate.usage_date >= period_start.date(),
            )
        )
    ).scalars().all()

    bytes_up = sum(a.bytes_up for a in rows)
    bytes_down = sum(a.bytes_down for a in rows)
    return bytes_up + bytes_down, bytes_up, bytes_down, quota


async def usage_current_period(db: AsyncSession, config: Configuration) -> tuple[int, int | None]:
    """(used_bytes, quota_bytes|None) — the total, for quota math and display.
    Callers that emit per-direction numbers use usage_current_period_detail."""
    used, _up, _down, quota = await usage_current_period_detail(db, config)
    return used, quota


class RenameError(SubscriptionError):
    """A rename that must be refused, carrying a machine-readable reason.

    A plain string comparison on the message would make the router depend on
    the wording; the reason is an attribute instead so the bot can map it to
    the right Persian text.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


RENAME_INVALID_NAME = "invalid_display_name"
RENAME_NAME_TAKEN = "display_name_taken"


async def rename_configuration(
    db: AsyncSession, config: Configuration, new_display_name: str
) -> Configuration:
    """Change a configuration's display name, keeping its suffix.

    The suffix is deliberately NOT re-minted. It is the platform's half of an
    identity the customer has already been shown and may have written down
    ("Parsa_A3F2K"), and the guarantee they were sold is that the full
    `{display_name}_{suffix}` string is unique — not that the name is
    permanent. Re-minting on every rename would silently change the label in
    their client for a reason they did not ask for.

    Uniqueness is therefore re-checked against the (display_name, suffix)
    index rather than assumed: keeping the suffix means a rename CAN collide
    with an existing config that already holds that exact pair, and letting
    the INSERT fail would surface as an unhandled IntegrityError.
    """
    new_name = (new_display_name or "").strip()

    if not validate_display_name(new_name):
        raise RenameError(RENAME_INVALID_NAME)

    if new_name == config.display_name:
        # Idempotent, not an error: re-submitting the same name is what a
        # customer does after a double-tap, and telling them it failed would
        # be wrong.
        return config

    taken = (
        await db.execute(
            select(Configuration.id).where(
                Configuration.display_name == new_name,
                Configuration.suffix == config.suffix,
                Configuration.id != config.id,
            )
        )
    ).scalar_one_or_none()
    if taken is not None:
        raise RenameError(RENAME_NAME_TAKEN)

    config.display_name = new_name
    await db.commit()
    await db.refresh(config)
    return config


async def active_assignments(db: AsyncSession, config: Configuration) -> list[tuple[ConfigurationNodeAssignment, Node]]:
    rows = (
        await db.execute(
            select(ConfigurationNodeAssignment, Node)
            .join(Node, Node.id == ConfigurationNodeAssignment.node_id)
            .where(
                ConfigurationNodeAssignment.configuration_id == config.id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
                Node.state.notin_(["DECOMMISSIONED", "OFFLINE", "QUARANTINED"]),
            )
        )
    ).all()
    return [(a, n) for a, n in rows]


# ---------------------------------------------------------------------------
# Subscription rendering
# ---------------------------------------------------------------------------


def render_vless_uri(
    node_domain: str,
    proxy_uuid: str,
    display_name: str,
    port: int = 443,
) -> str:
    host = node_domain.removeprefix("https://").removeprefix("http://").rstrip("/")
    label = quote(f"{display_name}", safe="")
    return (
        f"vless://{proxy_uuid}@{host}:{port}"
        f"?type=ws&path=%2Fvl&security=tls&sni={host}&fp=chrome#{label}"
    )


def build_subscription_body(uris: list[str]) -> str:
    return base64.b64encode("\n".join(uris).encode()).decode()


def subscription_url(config: Configuration) -> str:
    base = settings.subscription_base_url.rstrip("/")
    return f"{base}/s/{config.subscription_token}"
