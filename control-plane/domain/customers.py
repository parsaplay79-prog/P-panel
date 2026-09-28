"""Verdent Platform — customer administration (user.ban; Document 3 §O).

`user.ban` was declared in `domain/rbac.py`, granted to OWNER and ADMIN, and
used by nothing. The only way to cut off an abusive customer was to suspend each
of their configurations one at a time — and a customer with three configs on
three nodes, each rotated on a different day, was a manual sweep nobody finished.

**A ban that leaves the VPN running is not a ban.** `ban_customer` therefore
cascades: every config the customer holds that is still serving traffic is
suspended, edge credential included, through the same
`domain.configurations.suspend_configuration` path the single-config button
uses. One implementation, so the two cannot disagree about what "suspended"
means.

What a ban deliberately does NOT do:

  * It does not delete anything. Orders, configs, tickets and audit rows are
    the record of what happened and of what the customer paid for. A banned
    customer who wins an appeal needs their history intact.
  * It does not block the customer from the bot. They can still open a ticket —
    which is how an appeal reaches a human. The bot's own gate on `banned`
    decides what else they may do.
  * It does not touch EXPIRED or already-DELETED configs. Those serve nothing,
    and suspending them would rewrite history the expiry sweep owns.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import Text, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Configuration, Customer, Order, SupportTicket
from domain.audit import audit
from domain.configurations import (
    STATUS_ACTIVE,
    STATUS_PROVISIONING,
    STATUS_SUSPENDED,
    suspend_configuration,
)

logger = logging.getLogger("verdent.customers")

CUSTOMER_STATUS_ACTIVE = "active"
CUSTOMER_STATUS_BANNED = "banned"

CUSTOMER_STATUS_FA = {
    CUSTOMER_STATUS_ACTIVE: "فعال",
    CUSTOMER_STATUS_BANNED: "مسدود",
}

# Configs that are currently serving (or about to serve) a customer. A ban
# suspends these. EXPIRED and DELETED are excluded on purpose — see the module
# docstring.
BANNABLE_CONFIG_STATUSES = (STATUS_ACTIVE, STATUS_PROVISIONING)


class CustomerError(Exception):
    pass


async def search_customers(
    db: AsyncSession,
    *,
    query: str = "",
    status: str = "",
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Customer], int]:
    """(page of customers, total matching). Search by Telegram id or name.

    `query` matches a partial Telegram id (so an operator can paste the first
    few digits from a support message) and a case-insensitive substring of the
    username or display name. An empty query lists everyone.
    """
    stmt = select(Customer)
    count_stmt = select(func.count()).select_from(Customer)

    conditions = []
    query = (query or "").strip()
    if query:
        # digits-only goes to the id column; anything else to the text columns.
        # Casting the BIGINT to text for a LIKE would work but cannot use the
        # unique index on telegram_user_id, and an id lookup is the common case.
        if query.isdigit():
            conditions.append(
                func.cast(Customer.telegram_user_id, Text).like(f"%{query}%")
            )
        else:
            pattern = f"%{query.lower()}%"
            conditions.append(
                or_(
                    func.lower(func.coalesce(Customer.telegram_username, "")).like(pattern),
                    func.lower(func.coalesce(Customer.display_name, "")).like(pattern),
                )
            )

    if status in (CUSTOMER_STATUS_ACTIVE, CUSTOMER_STATUS_BANNED):
        conditions.append(Customer.status == status)

    for condition in conditions:
        stmt = stmt.where(condition)
        count_stmt = count_stmt.where(condition)

    total = (await db.execute(count_stmt)).scalar_one()
    rows = (
        await db.execute(
            stmt.order_by(Customer.last_interaction_at.desc()).limit(limit).offset(offset)
        )
    ).scalars().all()
    return list(rows), int(total)


async def customer_config_counts(db: AsyncSession, customer_ids: list[str]) -> dict[str, dict[str, int]]:
    """{customer_id: {total, active}} for a page of customers.

    One grouped query rather than one per row: a 50-row page would otherwise
    issue 50 counts, and the panel's table renders both numbers for every row.
    """
    if not customer_ids:
        return {}

    rows = (
        await db.execute(
            select(Configuration.customer_id, Configuration.status, func.count(Configuration.id))
            .where(Configuration.customer_id.in_(customer_ids))
            .group_by(Configuration.customer_id, Configuration.status)
        )
    ).all()

    counts: dict[str, dict[str, int]] = {
        cid: {"total": 0, "active": 0} for cid in customer_ids
    }
    for customer_id, status, count in rows:
        entry = counts.setdefault(customer_id, {"total": 0, "active": 0})
        entry["total"] += int(count)
        if status == STATUS_ACTIVE:
            entry["active"] += int(count)
    return counts


async def customer_detail(db: AsyncSession, customer_id: str) -> dict | None:
    """Everything the customer page shows, in one call.

    Returns None when the customer does not exist, so the route can 404 rather
    than render an empty page that looks like a customer with no history.
    """
    customer = (
        await db.execute(select(Customer).where(Customer.id == customer_id))
    ).scalar_one_or_none()
    if customer is None:
        return None

    configs = (
        await db.execute(
            select(Configuration)
            .where(Configuration.customer_id == customer.id)
            .order_by(Configuration.created_at.desc())
        )
    ).scalars().all()

    orders = (
        await db.execute(
            select(Order)
            .where(Order.customer_id == customer.id)
            .order_by(Order.created_at.desc())
            .limit(50)
        )
    ).scalars().all()

    tickets = (
        await db.execute(
            select(SupportTicket)
            .where(SupportTicket.customer_id == customer.id)
            .order_by(SupportTicket.updated_at.desc())
            .limit(50)
        )
    ).scalars().all()

    return {
        "customer": customer,
        "configurations": list(configs),
        "orders": list(orders),
        "tickets": list(tickets),
    }


async def ban_customer(
    db: AsyncSession,
    customer: Customer,
    actor_id: str | None = None,
    reason: str = "",
) -> dict:
    """Ban a customer and stop everything they are currently using.

    Returns a summary — how many configs were suspended — so the panel can tell
    the admin what actually happened rather than "done". A ban that silently
    failed to suspend a config would leave the operator believing an abusive
    customer was cut off.

    Idempotent: banning an already-banned customer re-runs the cascade (which is
    how a config created between the ban and now gets caught) but does not
    duplicate the audit row's meaning.
    """
    was_banned = customer.status == CUSTOMER_STATUS_BANNED
    customer.status = CUSTOMER_STATUS_BANNED
    await db.commit()

    live_configs = (
        await db.execute(
            select(Configuration).where(
                Configuration.customer_id == customer.id,
                Configuration.status.in_(BANNABLE_CONFIG_STATUSES),
            )
        )
    ).scalars().all()

    suspended: list[str] = []
    for config in live_configs:
        try:
            await suspend_configuration(db, config, actor_id=actor_id)
            suspended.append(config.id)
        except Exception:  # noqa: BLE001 — one bad config must not abort the ban
            # The ban itself is already committed; a config that refused to
            # suspend is reported, not swallowed, because the operator needs to
            # know the customer is still online.
            logger.exception("could not suspend config %s while banning customer %s", config.id, customer.id)

    await audit(
        db,
        "customer.ban",
        actor_id=actor_id,
        target_type="customer",
        target_id=customer.id,
        details={
            "reason": reason,
            "suspended_configs": len(suspended),
            "already_banned": was_banned,
        },
    )

    logger.info(
        "banned customer %s — suspended %d/%d live config(s)",
        customer.id, len(suspended), len(live_configs),
    )
    return {
        "customer_id": customer.id,
        "suspended": len(suspended),
        "attempted": len(live_configs),
    }


async def unban_customer(
    db: AsyncSession, customer: Customer, actor_id: str | None = None
) -> Customer:
    """Lift a ban. Deliberately does NOT reactivate the suspended configs.

    Whether the customer gets their service back is a separate decision with
    separate consequences — a config suspended for quota abuse should not come
    back just because the ban was lifted. The panel offers the config-level
    reactivate button for that, one config at a time, so the operator sees what
    they are restoring.
    """
    customer.status = CUSTOMER_STATUS_ACTIVE
    await db.commit()

    await audit(
        db,
        "customer.unban",
        actor_id=actor_id,
        target_type="customer",
        target_id=customer.id,
        details={},
    )
    return customer
