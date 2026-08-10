import asyncio
from logging.config import fileConfig
from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine
from app.config import settings
from app.database import Base
from app.models import Keyword, Detection, Incident, Indicator, SourceStatus, User, Webhook  # noqa: F401 — registers models with Base.metadata

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# All model tables are registered on Base.metadata via the imports above.
target_metadata = Base.metadata


def run_migrations_offline():
    """Run migrations without a live DB connection (generates SQL only)."""
    context.configure(url=settings.database_url, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online():
    """Run migrations against the live database using an async engine."""
    connectable = create_async_engine(settings.database_url)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
