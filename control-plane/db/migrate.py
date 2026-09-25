"""Run Alembic migrations at boot.

Why this exists: Railway has no release/migrate phase, and the app previously
migrated only by hand. Migrations 003/004 would have shipped to a database that
had never run them, and the failure would not have been obvious — the control
plane would boot, every other table would work, and only the support tables
being read or `audit()` writing a customer actor would break. Because audit()
swallows every exception, the first symptom would have been *silently missing
audit rows*, which is the worst possible time to discover a missing migration.

Design notes:

- **The lock is taken on an async connection, and Alembic runs in a thread.**
  `db/migrations/env.py` ends with `asyncio.run(...)`, so calling
  `command.upgrade()` directly from the lifespan would raise "asyncio.run()
  cannot be called from a running event loop". Running it via
  `asyncio.to_thread` gives Alembic a thread with no running loop, so its own
  `asyncio.run` works and it builds its own engine.

- **Why not a sync engine for the lock.** The obvious approach — a plain
  `create_engine(settings.database_url)` — needs a sync driver, and this project
  is asyncpg-only: `psycopg2` is neither installed nor in requirements.txt, so
  that connection would fail at boot. Taking the lock on the app's async engine
  avoids adding a driver for one query. (SQLAlchemy bundles no sync Postgres
  driver; `psycopg2-binary` would have to be added to requirements.txt.)

- The lock is advisory and session-scoped (`pg_advisory_lock`), so the three
  services (web, worker, cron) racing at deploy time serialize here instead of
  two of them running `upgrade head` concurrently. It is held on a connection
  that is NOT the one Alembic uses — Alembic's connection does not need the
  lock, only the *other* services' calls to this function block on it.

- `CAST(:key AS bigint)` is explicit because asyncpg is strict about parameter
  types and the lock key is a 64-bit integer.

- Released explicitly in a finally block. `pg_advisory_unlock` returns a boolean;
  it is checked and logged rather than assumed, so a leaked lock is visible.

- Failure is fatal. Booting against an out-of-date schema is exactly the silent
  corruption above; a crash-loop that logs the real cause is the better trade.

- `command.upgrade` is a no-op when the database is already at head, so this is
  safe to run on every boot of every service.
"""

import asyncio
import logging
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from sqlalchemy import text

from db.base import engine

logger = logging.getLogger("verdent.platform")

# Arbitrary but fixed: any 64-bit int works, it just has to be the same number
# everywhere so the web/worker/cron services exclude each other rather than
# grabbing different locks and migrating in parallel.
_MIGRATION_LOCK_ID = 0x56455244454E5401  # "VERDENT" + 1

# Absolute, derived from this file (db/migrate.py -> project root), NOT the
# process CWD. alembic.ini's `script_location = db/migrations` is resolved
# relative to the working directory, so a relative Config("alembic.ini") only
# works when CWD happens to be the project root. Verified: from another CWD it
# fails with "Path doesn't exist: db\migrations". The Dockerfile sets
# WORKDIR /app so it would work today, but a start-command change or a cron
# runner with a different CWD would break migrations in a confusing way.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ALEMBIC_INI = _PROJECT_ROOT / "alembic.ini"


def _alembic_config() -> Config:
    cfg = Config(str(_ALEMBIC_INI))
    # script_location inside alembic.ini is relative ("db/migrations") and
    # Alembic resolves it against the process CWD, not against the ini file.
    # Overriding it with an absolute path is what actually makes this CWD-
    # independent; pointing Config() at an absolute ini is not enough on its
    # own. Verified: from another directory, without this line Alembic raises
    # "Path doesn't exist: db\migrations".
    cfg.set_main_option("script_location", str(_PROJECT_ROOT / "db" / "migrations"))
    # sqlalchemy.url is intentionally empty in alembic.ini (env.py reads
    # DATABASE_URL itself and builds the engine, so the two can't drift).
    #
    # Opt out of Alembic's fileConfig() call: it reconfigures logging globally —
    # it replaces root's handlers and applies alembic.ini's [logger_root]
    # level = WARN, and with its default disable_existing_loggers=True it also
    # sets `disabled = True` on the app's loggers. We run inside the app, after
    # logging.basicConfig(), so the app's logging setup must win. Both effects
    # were reproduced (root level 20 -> 30, app logger disabled False -> True).
    # See the guard in db/migrations/env.py.
    cfg.attributes["configure_logger"] = False
    return cfg


def _read_revision(sync_conn) -> str | None:
    """Runs on the sync side of run_sync; MigrationContext needs a sync conn."""
    return MigrationContext.configure(sync_conn).get_current_revision()


def _upgrade_to_head(cfg: Config) -> None:
    """Blocking. Runs in a worker thread so Alembic's own asyncio.run() is legal."""
    command.upgrade(cfg, "head")


async def run_migrations() -> None:
    """Bring the database to head. Idempotent; raises on failure."""
    cfg = _alembic_config()

    async with engine.connect() as lock_conn:
        await lock_conn.execute(
            text("SELECT pg_advisory_lock(CAST(:key AS bigint))"),
            {"key": _MIGRATION_LOCK_ID},
        )
        logger.info("acquired migration lock")
        try:
            before = await lock_conn.run_sync(_read_revision)
            logger.info("database revision before: %s", before or "<none>")

            # Off the event loop: Alembic's env.py calls asyncio.run() itself, and
            # it also opens its own connection, which would otherwise deadlock
            # against the pool slot this function is holding.
            await asyncio.to_thread(_upgrade_to_head, cfg)

            after = await lock_conn.run_sync(_read_revision)
            logger.info("migrations up to date (revision now: %s)", after or "<none>")
        finally:
            released = (
                await lock_conn.execute(
                    text("SELECT pg_advisory_unlock(CAST(:key AS bigint))"),
                    {"key": _MIGRATION_LOCK_ID},
                )
            ).scalar()
            if released:
                logger.info("released migration lock")
            else:
                # Not fatal, but it means the lock outlived this function and
                # other services will block until the connection drops.
                logger.warning("pg_advisory_unlock reported the lock was not held")
