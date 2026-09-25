"""Verdent Platform — test configurations (Phase 4; Document 6 §Phase-4).

Abuse mitigations per blueprint:
- a hard cap on test configs per customer, enforced under concurrency
- hard quota: TEST_QUOTA_BYTES (default 100MB), enforced by quota-flag push
- hard expiry: 24h, enforced by the expiry sweep
- config_type='test' keeps them out of normal plan analytics

The cap is a check-then-act on a table with no per-customer aggregate row, so
without a lock two rapid taps both read "0 active tests" and both insert. The
customer row is therefore locked with a PostgreSQL advisory lock keyed on the
customer id — the closest thing to a row lock that works when the thing being
counted is a set of rows rather than one row. See `_customer_test_lock`.
"""

import contextlib
import logging
import secrets
import uuid as uuid_lib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import Configuration, ConfigurationNodeAssignment, Node
from domain.audit import audit
from domain.naming import create_unique_config_name_pair
from domain.kv_sync import sync_assignment

logger = logging.getLogger("verdent.test_configs")

TEST_QUOTA_BYTES = 100 * 1024 * 1024  # 100MB
TEST_DURATION = timedelta(hours=24)

# Tests a customer may hold in total, not merely at once. A per-lifetime cap
# is the only thing that actually bounds abuse: an "one active" rule can be
# defeated by waiting 24h, and a free 100MB handed out on that cadence is a
# free CDN relay for anyone with a script.
TEST_MAX_LIFETIME = 2


class TestConfigLimitError(Exception):
    """Customer has used their test allowance. Carries the cap for the message."""

    def __init__(self, lifetime_count: int, cap: int) -> None:
        super().__init__(f"test config limit reached ({lifetime_count}/{cap})")
        self.lifetime_count = lifetime_count
        self.cap = cap


@contextlib.asynccontextmanager
async def _customer_test_lock(db: AsyncSession, customer_id: str):
    """Serialize test-config creation for one customer across ALL processes.

    pg_advisory_xact_lock takes a 64-bit key derived from the customer uuid and
    is released automatically when the surrounding transaction ends — including
    on a crash or rollback, so there is no lock to leak.

    Why advisory and not SELECT ... FOR UPDATE: the cap counts rows in
    `configurations`, not the state of a single customer row. Locking the
    customer row would work only because every creation path happens to touch
    it, which is a coupling that breaks silently when a new caller is added.
    An explicit named lock makes the serialization visible at the call site.
    """
    # Two-arg form: 32-bit class id + 32-bit object id. Derived from the uuid
    # so the same customer always lands on the same lock, in this process and
    # in the web/worker pair alike.
    digest = int.from_bytes(bytes.fromhex(customer_id.replace("-", "")), "big")
    key = digest % (2**32)

    await db.execute(
        text("SELECT pg_advisory_xact_lock(:key1, :key2)"),
        {"key1": 0x7E57, "key2": key},
    )
    try:
        yield
    finally:
        # The lock is transaction-scoped; the explicit unlock is belt-and-braces
        # for the case where a caller commits early and keeps using the session.
        await db.execute(
            text("SELECT pg_advisory_xact_unlock(:key1, :key2)"),
            {"key1": 0x7E57, "key2": key},
        )


async def count_lifetime_test_configs(db: AsyncSession, customer_id: str) -> int:
    """Test configs this customer has EVER received. Never decreases.

    Rows are kept after they expire precisely so this count cannot be reset by
    waiting. `is_test` is the flag that matters, not `config_type`, which the
    bot also sets to 'test' for admin-created configs.
    """
    row = (
        await db.execute(
            select(Configuration.id)
            .where(
                Configuration.customer_id == customer_id,
                Configuration.is_test.is_(True),
            )
            .limit(TEST_MAX_LIFETIME + 1)
        )
    ).scalars().all()
    return len(row)


async def has_active_test_config(db: AsyncSession, customer_id: str) -> bool:
    now = datetime.now(timezone.utc)
    row = (
        await db.execute(
            select(Configuration.id)
            .where(
                Configuration.customer_id == customer_id,
                Configuration.is_test.is_(True),
                Configuration.status == "ACTIVE",
                (Configuration.expires_at.is_(None)) | (Configuration.expires_at > now),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    return row is not None


async def create_test_config(
    db: AsyncSession,
    customer_id: str,
    display_name: str,
    node: Node,
    actor_id: str | None = None,
) -> Configuration:
    # The lock is held for the whole check-then-insert. Without it, a rapid
    # double-tap runs this function twice concurrently: both count 0, both
    # insert, and the customer walks away with double the intended allowance.
    async with _customer_test_lock(db, customer_id):
        if await has_active_test_config(db, customer_id):
            raise RuntimeError("customer already has an active test config")

        lifetime = await count_lifetime_test_configs(db, customer_id)
        if lifetime >= TEST_MAX_LIFETIME:
            raise TestConfigLimitError(lifetime, TEST_MAX_LIFETIME)

        name, suffix = await create_unique_config_name_pair(db, display_name)
        now = datetime.now(timezone.utc)

        config = Configuration(
            id=str(uuid_lib.uuid4()),
            customer_id=customer_id,
            plan_id=None,
            display_name=name,
            suffix=suffix,
            subscription_token=secrets.token_urlsafe(24),
            config_type="test",
            gaming_profile_id=None,
            status="ACTIVE",
            is_test=True,
            test_quota_bytes=TEST_QUOTA_BYTES,
            created_at=now,
            expires_at=now + TEST_DURATION,
        )
        db.add(config)
        await db.flush()

        assignment = ConfigurationNodeAssignment(
            configuration_id=config.id,
            node_id=node.id,
            role="primary",
            proxy_uuid=str(uuid_lib.uuid4()),
        )
        db.add(assignment)
        node.current_assignment_count = (node.current_assignment_count or 0) + 1
        await db.commit()

    # Outside the lock: the KV write is an external call that must not hold a
    # database lock, and the audit row is bookkeeping.
    await sync_assignment(
        db,
        node,
        proxy_uuid=assignment.proxy_uuid,
        config_id=config.id,
        status="active",
        device_limit=1,
    )

    await audit(
        db,
        "config.test_created",
        actor_id=actor_id,
        actor_type="admin" if actor_id else "system",
        target_type="configuration",
        target_id=config.id,
        details={"customer_id": customer_id, "lifetime_index": lifetime + 1},
    )
    return config
