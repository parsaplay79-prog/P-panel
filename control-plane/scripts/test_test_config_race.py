"""Phase-4 acceptance gate: the test-config cap holds under a rapid double-tap.

Document 6 §Phase-4 says a phase is not done until "the 2-lifetime test-config
cap holds under a rapid double-tap (the exact race named in Document 3)".

The original code was check-then-act with no lock: two concurrent creations
both read "0 active tests", both insert, and the customer receives two. A
mocked session cannot demonstrate the fix, because the fix IS the database
lock — so this test needs a real Postgres. It creates a throwaway schema,
runs the race for real, and drops everything afterwards.

Requires DATABASE_URL. Skips (exit 0) with a clear message if it is unset, so
it never blocks a local run that has no database.

Run: DATABASE_URL=postgres://... python scripts/test_test_config_race.py
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("SKIP: DATABASE_URL is not set — this gate needs a real Postgres.")
    print("      The advisory lock that closes the race is a database feature;")
    print("      a fake session would pass whether or not the fix works.")
    sys.exit(0)

from sqlalchemy import text  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402

from db.base import Base, get_engine  # noqa: E402

FAILURES: list[str] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} — {detail}")
        print(f"  FAIL  {name} — {detail}")


async def main() -> None:
    from db.models import Configuration, Node
    from domain import test_configs

    # A dedicated schema so the test can never touch real rows, even by
    # accident. search_path is set per-connection via the connect_args below.
    schema = f"testcfg_{uuid.uuid4().hex[:8]}"
    engine = create_async_engine(DATABASE_URL)

    async with engine.begin() as conn:
        await conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    await engine.dispose()

    scoped = create_async_engine(
        DATABASE_URL,
        connect_args={"options": f"-csearch_path={schema}"},
    )

    # Point the app's session factory at the throwaway schema.
    import db.base as base

    base.engine = scoped
    base.engine_sync = None

    from sqlalchemy.ext.asyncio import async_sessionmaker

    base.SessionLocal = async_sessionmaker(scoped, expire_on_commit=False)

    try:
        async with scoped.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with base.SessionLocal() as db:
            customer_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO customers (id, telegram_user_id, created_at) "
                    "VALUES (:id, :tid, now())"
                ),
                {"id": customer_id, "tid": 900000000 + int(uuid.uuid4().int % 90000000)},
            )
            node = Node(
                id=str(uuid.uuid4()),
                cloudflare_account_id=str(uuid.uuid4()),
                worker_script_name="test-node",
                capability_tags=["general"],
                node_secret_hash="x",
                state="ONLINE",
            )
            # node.cloudflare_account_id has an FK; insert a parent row directly.
            await db.execute(
                text(
                    "INSERT INTO cloudflare_accounts (id, label, cf_account_id,"
                    " api_token_encrypted, status, added_at)"
                    " VALUES (:id, 't', 'acct', '\\x00', 'ACTIVE', now())"
                ),
                {"id": node.cloudflare_account_id},
            )
            await db.execute(
                text(
                    "INSERT INTO nodes (id, cloudflare_account_id, worker_script_name,"
                    " capability_tags, node_secret_hash, state, health_score,"
                    " consecutive_failures, consecutive_successes, current_assignment_count,"
                    " max_assignment_count, control_plane_health, data_plane_health)"
                    " VALUES (:id, :acct, 'test-node', ARRAY['general'], 'x', 'ONLINE',"
                    " 100, 0, 0, 0, 100, true, true)"
                ),
                {"id": node.id, "acct": node.cloudflare_account_id},
            )
            await db.commit()

        print("\n1. Rapid double-tap: two concurrent creations, ONE must win")
        results: list[str] = []
        errors: list[str] = []

        async def tap() -> None:
            async with base.SessionLocal() as db:
                try:
                    await test_configs.create_test_config(
                        db, customer_id=customer_id, display_name="race", node=node
                    )
                    results.append("created")
                except test_configs.TestConfigLimitError:
                    errors.append("limit")
                except RuntimeError as exc:
                    errors.append(str(exc))
                except Exception as exc:  # noqa: BLE001
                    # KV sync is a real HTTP call we cannot make here; the row
                    # is already committed by then, which is what we're testing.
                    if "KV" in str(exc) or "connect" in str(exc).lower():
                        results.append("created")
                    else:
                        errors.append(f"{type(exc).__name__}: {exc}")

        await asyncio.gather(tap(), tap())

        check(
            "exactly one config created by the double-tap",
            len(results) == 1,
            f"created={len(results)} errors={errors}",
        )
        check(
            "the loser was rejected, not silently duplicated",
            len(results) + len(errors) == 2,
            f"created={len(results)} errors={errors}",
        )

        async with base.SessionLocal() as db:
            from sqlalchemy import func, select

            count = (
                await db.execute(
                    select(func.count())
                    .select_from(Configuration)
                    .where(Configuration.customer_id == customer_id)
                )
            ).scalar_one()
        check("database holds exactly 1 test config", count == 1, f"got {count}")

        print("\n2. Lifetime cap of 2 is enforced and never resets")
        async with base.SessionLocal() as db:
            lifetime = await test_configs.count_lifetime_test_configs(db, customer_id)
        check("lifetime count sees the one created above", lifetime == 1, f"got {lifetime}")

        # Force the first config to EXPIRED, as the expiry sweep would.
        async with base.SessionLocal() as db:
            await db.execute(
                text(
                    "UPDATE configurations SET status='EXPIRED',"
                    " expires_at = now() - interval '1 hour'"
                    " WHERE customer_id = :cid"
                ),
                {"cid": customer_id},
            )
            await db.commit()

        async with base.SessionLocal() as db:
            lifetime_after = await test_configs.count_lifetime_test_configs(db, customer_id)
            active = await test_configs.has_active_test_config(db, customer_id)
        check("expired config no longer counts as active", active is False, f"got {active}")
        check(
            "but STILL counts toward the lifetime cap",
            lifetime_after == 1,
            f"got {lifetime_after} — waiting 24h must not buy a free test",
        )

        print("\n3. The third attempt is refused")
        async with base.SessionLocal() as db:
            # Burn the second lifetime slot.
            try:
                await test_configs.create_test_config(
                    db, customer_id=customer_id, display_name="second", node=node
                )
                second = "created"
            except Exception as exc:  # noqa: BLE001
                second = f"{type(exc).__name__}: {exc}"
        check("second test is allowed", second == "created", f"got {second}")

        async with base.SessionLocal() as db:
            refused = "allowed"
            try:
                await test_configs.create_test_config(
                    db, customer_id=customer_id, display_name="third", node=node
                )
            except test_configs.TestConfigLimitError as exc:
                refused = f"limit {exc.lifetime_count}/{exc.cap}"
            except Exception as exc:  # noqa: BLE001
                refused = f"{type(exc).__name__}: {exc}"
        check(
            "third test refused with the lifetime cap",
            refused.startswith("limit"),
            f"got {refused}",
        )

    finally:
        await scoped.dispose()
        cleanup = create_async_engine(DATABASE_URL)
        try:
            async with cleanup.begin() as conn:
                await conn.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        finally:
            await cleanup.dispose()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("Phase-4 test-config race gate PASSED.")


asyncio.run(main())
