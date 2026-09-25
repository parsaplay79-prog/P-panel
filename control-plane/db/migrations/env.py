"""Verdent Platform — Alembic environment.

DATABASE_URL flows from env via `domain.config.settings` (pydantic-settings);
the `sqlalchemy.url` in `alembic.ini` is intentionally empty.
"""

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from domain.config import settings
from db.models import Base

config = context.config

# Logging is configured here only when Alembic is driven from its own CLI.
# When the app calls run_migrations() at startup (db/migrate.py) it sets
# attributes["configure_logger"] = False, because fileConfig() reconfigures
# logging GLOBALLY: it replaces root's handlers and applies alembic.ini's
# [logger_root] level = WARN. Run after logging.basicConfig() — which is exactly
# what startup does — that silently suppresses every INFO line for the rest of
# the process. Both effects were reproduced: root level 20 -> 30, and with the
# default disable_existing_loggers=True the app logger also went
# disabled False -> True. Either one alone is enough to lose all boot logging.
if config.config_file_name is not None and config.attributes.get(
    "configure_logger", True
):
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", settings.async_database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL without a DBURL connection)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, compare_type=True)

    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
