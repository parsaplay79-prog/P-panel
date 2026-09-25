"""Verdent Platform — notifications + expiry sweep (Phase 5, cron service).

- expiry sweep: EXPIRED at expiry; warning 3 days before (once per day,
  deduplicated through notifications_log)
- quota warnings at 80% (once per day) + exhaustion disable via node KV

CONCURRENCY: two services run this sweep — `cron` (SWEEP_INTERVAL) and
`worker` (QUOTA_PUSH_INTERVAL), at different cadences. Every step below is
check-then-act on notifications_log, which has a plain INDEX and no unique
constraint, so without serialization both can read "not sent" and the customer
receives two expiry warnings for one config. `pg_try_advisory_xact_lock` makes
the whole pass exclusive: the loser skips and tries again next tick. An
advisory lock is used rather than a unique constraint because it needs no
migration, and the sweep is the only writer that needs this.
"""

import contextlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from db.base import SessionLocal
from db.models import Configuration, ConfigurationNodeAssignment, Customer, Node, NotificationsLog
from bot import texts
from domain.kv_sync import set_entry_status
from domain.pools import release_stale_node_capacity
from domain.subscriptions import usage_current_period

logger = logging.getLogger("verdent.notifications")

EXPIRY_WARN_DAYS = 3
QUOTA_WARN_PERCENT = 80


SWEEP_LOCK_CLASS = 0x5EE9  # arbitrary; identifies this lock among others
SWEEP_LOCK_OBJECT = 1


@contextlib.asynccontextmanager
async def _exclusive_sweep(db: AsyncSession):
    """Hold the cross-service sweep lock, or report that we did not get it.

    try-lock, not blocking: the sweep is a periodic background job, so there
    is nothing useful for a second worker to do while the first one runs, and
    a blocking lock would make the loser queue up and then re-run a sweep
    that has nothing left to do.

    The lock is transaction-scoped, so it is released on commit, rollback, or
    a crash — it cannot be leaked by a process being killed mid-sweep.
    """
    acquired = await db.execute(
        text("SELECT pg_try_advisory_xact_lock(:class_id, :object_id)"),
        {"class_id": SWEEP_LOCK_CLASS, "object_id": SWEEP_LOCK_OBJECT},
    )
    if not (await acquired).scalar_one():
        yield False
        return
    try:
        yield True
    finally:
        await db.execute(
            text("SELECT pg_advisory_xact_unlock(:class_id, :object_id)"),
            {"class_id": SWEEP_LOCK_CLASS, "object_id": SWEEP_LOCK_OBJECT},
        )


async def _disable_edge_credential(db: AsyncSession, config: Configuration) -> bool:
    """Turn off this config's credential in the node's KV map.

    The database status and the edge's KV entry are two different switches,
    and the sweep is the only thing that flips them together. Marking a config
    EXPIRED without this left the proxy relaying traffic for a customer whose
    subscription had ended — the status said one thing, the edge did another.
    """
    assignment = (
        await db.execute(
            select(ConfigurationNodeAssignment)
            .where(
                ConfigurationNodeAssignment.configuration_id == config.id,
                ConfigurationNodeAssignment.revoked_at.is_(None),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if assignment is None:
        return False
    node = (
        await db.execute(select(Node).where(Node.id == assignment.node_id))
    ).scalar_one_or_none()
    if node is None:
        return False
    await set_entry_status(db, node, str(assignment.proxy_uuid), "disabled")
    return True


async def _already_sent(db: AsyncSession, customer_id: str, notification_type: str, day: str) -> bool:
    row = (
        await db.execute(
            select(NotificationsLog.id).where(
                NotificationsLog.customer_id == customer_id,
                NotificationsLog.notification_type == f"{notification_type}:{day}",
            )
        )
    ).scalar_one_or_none()
    return row is not None


async def _record(db: AsyncSession, customer_id: str, notification_type: str) -> None:
    db.add(
        NotificationsLog(
            customer_id=customer_id,
            notification_type=f"{notification_type}:{datetime.now(timezone.utc).date().isoformat()}",
        )
    )
    await db.commit()


async def notify_customer(telegram_user_id: str, message: str) -> bool:
    """Fire a Telegram message. Import-guarded so the cron service also works
    without a bot token configured."""
    try:
        from bot.webhook import send_message

        return await send_message(telegram_user_id, message)
    except Exception:  # noqa: BLE001
        logger.exception("notify failed for %s", telegram_user_id)
        return False


async def expiry_and_quota_sweep() -> dict:
    """Runs from BOTH the cron and the worker service. Idempotent per
    (customer, type, day), and exclusive across the two — see the module
    docstring for why the pass is locked as a whole."""
    now = datetime.now(timezone.utc)
    today = now.date().isoformat()
    stats = {
        "expired": 0,
        "expiry_warned": 0,
        "quota_warned": 0,
        "quota_exhausted": 0,
        "edge_disabled": 0,
        "capacity_released": 0,
        "skipped": 0,
    }

    async with SessionLocal() as db:
        async with _exclusive_sweep(db) as acquired:
            if not acquired:
                logger.info("sweep skipped: another service is holding the lock")
                stats["skipped"] = 1
                return stats

            active = (
                await db.execute(
                    select(Configuration).where(
                        Configuration.status == "ACTIVE",
                        Configuration.is_test.is_(False),
                    )
                )
            ).scalars().all()

            for config in active:
                customer = (
                    await db.execute(
                        select(Customer).where(Customer.id == config.customer_id)
                    )
                ).scalar_one_or_none()
                if customer is None:
                    continue

                # ---- expiry -------------------------------------------------
                # Note: this sweep is the ONLY thing that marks a config
                # EXPIRED (the subscription endpoint used to do it too, which
                # made the config vanish from this very query and left its
                # edge credential live forever — see api/routes/subscription.py).
                if config.expires_at is not None:
                    remaining = config.expires_at - now

                    if remaining <= timedelta(0):
                        config.status = "EXPIRED"
                        stats["expired"] += 1
                        # The status alone does not stop the proxy: the node
                        # keeps relaying until its KV entry says otherwise.
                        if await _disable_edge_credential(db, config):
                            stats["edge_disabled"] += 1
                        if not await _already_sent(db, customer.id, "expired", today):
                            await notify_customer(
                                customer.telegram_user_id,
                                texts.MSG_EXPIRED.format(display_name=config.display_name),
                            )
                            await _record(db, customer.id, "expired")
                        continue

                    if remaining <= timedelta(days=EXPIRY_WARN_DAYS):
                        if not await _already_sent(db, customer.id, "expiry_warn", today):
                            await notify_customer(
                                customer.telegram_user_id,
                                texts.MSG_EXPIRY_WARNING.format(
                                    display_name=config.display_name,
                                    days=max(1, remaining.days),
                                ),
                            )
                            await _record(db, customer.id, "expiry_warn")
                            stats["expiry_warned"] += 1

                # ---- quota ---------------------------------------------------
                used, quota = await usage_current_period(db, config)
                if quota:
                    percent = int(used * 100 / quota)
                    if percent >= 100:
                        if await _disable_edge_credential(db, config):
                            stats["edge_disabled"] += 1
                        stats["quota_exhausted"] += 1
                        if not await _already_sent(db, customer.id, "quota_exhausted", today):
                            await notify_customer(
                                customer.telegram_user_id,
                                texts.MSG_QUOTA_EXHAUSTED.format(display_name=config.display_name),
                            )
                            await _record(db, customer.id, "quota_exhausted")
                    elif percent >= QUOTA_WARN_PERCENT:
                        if not await _already_sent(db, customer.id, "quota_warn", today):
                            await notify_customer(
                                customer.telegram_user_id,
                                texts.MSG_QUOTA_WARNING.format(
                                    display_name=config.display_name, percent=percent
                                ),
                            )
                            await _record(db, customer.id, "quota_warn")
                            stats["quota_warned"] += 1

            # This sweep is the only thing that marks configs non-ACTIVE in bulk,
            # so it is also where the nodes they were sitting on get their slots
            # back — otherwise a node keeps counting a customer who has churned.
            stats["capacity_released"] = await release_stale_node_capacity(db)

            await db.commit()

    logger.info("expiry/quota sweep: %s", stats)
    return stats
