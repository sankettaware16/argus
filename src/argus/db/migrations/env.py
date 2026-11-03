"""Alembic environment for ARGUS.

Two entry paths:
* ``argus db ...`` / tests pass an open connection in ``config.attributes["connection"]``
  (see ``argus.db.migrate``) so migrations run inside the caller's transaction, which already
  holds the migration lock.
* the plain ``alembic`` CLI builds its own engine from ARGUS settings (as the schema owner)
  and takes the same lock.

Only the tables ARGUS's models declare are compared (``include_name``), so autogenerate never
proposes dropping other tables that share the database.
"""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy.engine import Connection

from argus.db import migrate
from argus.db.models import Base

config = context.config
target_metadata = Base.metadata


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        include_name=migrate.is_argus_table,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_async_migrations() -> None:
    from argus.config import load_settings
    from argus.db.engine import create_engine

    engine = create_engine(load_settings().database, role="owner")  # migrations: D-029
    try:
        async with engine.connect() as connection:
            await migrate.lock_migrations(connection)
            await connection.run_sync(do_run_migrations)
            await connection.commit()
    finally:
        await engine.dispose()


if context.is_offline_mode():
    raise SystemExit("offline (SQL script) migrations are not supported for ARGUS")

shared_connection = config.attributes.get("connection")
if shared_connection is None:
    asyncio.run(run_async_migrations())
else:
    do_run_migrations(shared_connection)
