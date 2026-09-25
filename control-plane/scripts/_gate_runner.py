"""Runs the Phase-4 race gate against a real Postgres, from /tmp.

Loaded via `railway ssh ... -- python /tmp/verify/runner.py`. It imports the
LIVE app's models/migrations from /app but the NEW domain/test_configs.py from
/tmp, so the running control plane is never modified.

Why the app's own file can't be used: /app/domain/test_configs.py is whatever
the last deploy shipped. Testing that would prove nothing about this fix.
"""

import asyncio
import base64
import importlib.util
import os
import sys
import uuid

sys.path.insert(0, "/app")

NEW_MODULE = "/tmp/verify/test_configs_new.py"

FAILURES = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        FAILURES.append(f"{name} - {detail}")
        print(f"  FAIL  {name} - {detail}")


def load_new_module():
    spec = importlib.util.spec_from_file_location("test_configs_new", NEW_MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


async def main():
    import asyncpg  # noqa: F401  (proves the driver is present)

    from sqlalchemy import func, select, text
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    import db.base as base
    from db.models import Base, CloudflareAccount, Configuration, Node

    dsn = os.environ["DATABASE_URL"]

    tc = load_new_module()

    # Stub the two side effects that need the network. The DB row is what the
    # race is about; KV sync and audit happen after the commit.
    async def fake_sync(*a, **k):
        return None

    async def fake_audit(*a, **k):
        return None

    tc.sync_assignment = fake_sync
    tc.audit = fake_audit

    schema = f"gate_{uuid.uuid4().hex[:8]}"
    admin = create_async_engine(dsn)
    async with admin.begin() as c:
        await c.execute(text(f'CREATE SCHEMA "{schema}"'))
    await admin.dispose()

    scoped = create_async_engine(dsn, connect_args={"options": f"-csearch_path={schema}"})
    Session = async_sessionmaker(scoped, expire_on_commit=False)

    try:
        async with scoped.begin() as c:
            await c.run_sync(Base.metadata.create_all)

        async with Session() as db:
            acct = CloudflareAccount(
                id=str(uuid.uuid4()),
                label="gate",
                cf_account_id="acct-gate",
                api_token_encrypted=b"\x00",
                status="ACTIVE",
            )
            db.add(acct)
            await db.flush()

            customer_id = str(uuid.uuid4())
            await db.execute(
                text(
                    "INSERT INTO customers (id, telegram_user_id, created_at)"
                    " VALUES (:id, :t, now())"
                ),
                {"id": customer_id, "t": 900000000 + (uuid.uuid4().int % 90000000)},
            )
            node = Node(
                id=str(uuid.uuid4()),
                cloudflare_account_id=acct.id,
                worker_script_name="gate-node",
                capability_tags=["general"],
                node_secret_hash="x",
                state="ONLINE",
                max_assignment_count=100,
            )
            db.add(node)
            await db.commit()

        print("\n1. Rapid double-tap -> exactly one config survives")
        made, refused = [], []

        async def tap():
            async with Session() as db:
                try:
                    await tc.create_test_config(
                        db, customer_id=customer_id, display_name="race", node=node
                    )
                    made.append("ok")
                except tc.TestConfigLimitError:
                    refused.append("limit")
                except RuntimeError as e:
                    refused.append(f"active:{e}")

        await asyncio.gather(tap(), tap())
        check("one created", len(made) == 1, f"made={made} refused={refused}")
        check(
            "one refused",
            len(refused) == 1,
            f"made={made} refused={refused} - the cap did not hold",
        )

        async with Session() as db:
            n = (
                await db.execute(
                    select(func.count())
                    .select_from(Configuration)
                    .where(Configuration.customer_id == customer_id)
                )
            ).scalar_one()
        check("database has exactly 1 row", n == 1, f"rows={n}")

        print("\n2. Lifetime cap survives expiry (no reset by waiting)")
        async with Session() as db:
            await db.execute(
                text(
                    "UPDATE configurations SET status='EXPIRED',"
                    " expires_at=now()-interval '1 hour' WHERE customer_id=:c"
                ),
                {"c": customer_id},
            )
            await db.commit()
        async with Session() as db:
            active = await tc.has_active_test_config(db, customer_id)
            life = await tc.count_lifetime_test_configs(db, customer_id)
        check("expired is no longer active", active is False, f"active={active}")
        check("expired still counts as lifetime", life == 1, f"life={life}")

        print("\n3. Third test is refused at the cap")
        async with Session() as db:
            await tc.create_test_config(
                db, customer_id=customer_id, display_name="second", node=node
            )
        async with Session() as db:
            try:
                await tc.create_test_config(
                    db, customer_id=customer_id, display_name="third", node=node
                )
                verdict = "allowed"
            except tc.TestConfigLimitError as e:
                verdict = f"limit {e.lifetime_count}/{e.cap}"
        check("third refused", verdict.startswith("limit"), f"got {verdict}")

        print("\n4. Control: without the lock the same double-tap DOES double-create")
        # Proves the gate has teeth: same code path, lock stubbed out.
        async def noop_lock(*a, **k):
            class _CM:
                async def __aenter__(self_inner):
                    return None

                async def __aexit__(self_inner, *e):
                    return False

            return _CM()

        original = tc._customer_test_lock
        tc._customer_test_lock = noop_lock
        c2 = str(uuid.uuid4())
        async with Session() as db:
            await db.execute(
                text("INSERT INTO customers (id, telegram_user_id, created_at)"
                     " VALUES (:id, :t, now())"),
                {"id": c2, "t": 800000000 + (uuid.uuid4().int % 90000000)},
            )
            await db.commit()
        made2 = []
        for _ in range(2):
            async with Session() as db:
                try:
                    await tc.create_test_config(
                        db, customer_id=c2, display_name="u", node=node
                    )
                    made2.append("ok")
                except Exception:
                    pass
        tc._customer_test_lock = original
        check(
            "unlocked path really does create 2 (test is not vacuous)",
            len(made2) == 2,
            f"made={len(made2)} - if this is 1 the test proves nothing",
        )
    finally:
        await scoped.dispose()
        cl = create_async_engine(dsn)
        async with cl.begin() as c:
            await c.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        await cl.dispose()

    print()
    if FAILURES:
        print(f"FAILED ({len(FAILURES)}):")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print("PHASE-4 RACE GATE PASSED against real Postgres.")


asyncio.run(main())
