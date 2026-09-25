# Migration 002 — health hysteresis columns

## What this does

Adds three columns to `nodes`:

| Column | Type | Default | Why |
|---|---|---|---|
| `consecutive_failures` | INTEGER NOT NULL | 0 | Hysteresis counter. Was a Python attribute, so it reset every pass and OFFLINE was unreachable. |
| `consecutive_successes` | INTEGER NOT NULL | 0 | Symmetric counter for recovery (`ONLINE_AFTER_SUCCESSES`). |
| `offline_since` | TIMESTAMPTZ NULL | — | When the node entered OFFLINE. Failover waits on this; the old code used the newest health sample, which is rewritten every 60s and so was never old enough. |

**Additive only.** No data is rewritten, no existing column is dropped or
retyped, and existing rows get `0` / `0` / `NULL` — which is the correct
starting state (a node with no failure history is not OFFLINE). Rolling back
just drops the three columns.

## Before you run it

The web service reads `nodes.consecutive_failures` the moment the new code
deploys. **If the columns are missing while the new code is live, the health
loop raises on every pass** and the worker logs an exception each minute. So
run this migration BEFORE deploying commit that contains the new code.

## Run it

The app has no startup migration step (schema is applied deliberately, not at
boot), so run Alembic once against the production database.

Add a `DATABASE_URL` variable pointing at the Railway Postgres, then:

```bash
cd control-plane
alembic upgrade head
alembic current      # expect: 002 (head)
```

If you'd rather not use Alembic, the equivalent DDL is:

```sql
ALTER TABLE nodes ADD COLUMN consecutive_failures  INTEGER     NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN consecutive_successes INTEGER     NOT NULL DEFAULT 0;
ALTER TABLE nodes ADD COLUMN offline_since         TIMESTAMPTZ;
```

Verify:

```sql
SELECT column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_name = 'nodes' AND column_name IN
      ('consecutive_failures','consecutive_successes','offline_since')
ORDER BY column_name;
```

Expect three rows.

## Then repair the existing node

The live node was provisioned before this fix and is in no pool, so it cannot
be selected for any order. After the migration, link it:

```python
# from control-plane/
import asyncio
from sqlalchemy import select
from db.base import SessionLocal
from db.models import Node
from domain.provisioning import attach_node_to_pools

async def main():
    async with SessionLocal() as db:
        for node in (await db.execute(select(Node))).scalars():
            await attach_node_to_pools(db, node)

asyncio.run(main())
```

Then confirm: `SELECT count(*) FROM pool_nodes;` should return 1.
