import os

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault(
    "SECRET_KEY", "test-only-signing-key-that-is-at-least-32-bytes-long"
)

import pytest
import asyncpg
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from httpx import ASGITransport, AsyncClient

from app.database import Base, get_db
from app.main import app


def pytest_configure(config):
    """Register custom markers so pytest --strict-markers doesn't complain."""
    config.addinivalue_line("markers", "no_db: mark test as not requiring a database connection")

TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "")
if not TEST_DATABASE_URL:
    raise RuntimeError("TEST_DATABASE_URL env var is required. Start db-test and set it.")

# asyncpg DSN uses postgresql:// not postgresql+asyncpg://
_ASYNCPG_URL = TEST_DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
test_session = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


async def _reset_schema() -> None:
    """Drop and recreate the public schema using a raw asyncpg connection.

    This bypasses SQLAlchemy's transaction wrapper entirely, which is required
    for DROP/CREATE SCHEMA on asyncpg — those statements cannot run inside a
    transaction block.
    """
    conn = await asyncpg.connect(_ASYNCPG_URL)
    try:
        await conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        await conn.execute("CREATE SCHEMA public")
        await conn.execute("GRANT ALL ON SCHEMA public TO slink")
    finally:
        await conn.close()


@pytest.fixture(autouse=True)
async def setup_db(request):
    # Tests marked no_db are pure unit tests that mock all I/O — skip DB setup.
    if request.node.get_closest_marker("no_db"):
        yield
        return
    # Dispose the connection pool before and after each test to ensure we never
    # get a connection that has a stale transaction left over from a previous
    # test. asyncpg raises "another operation is in progress" if a pooled
    # connection is reused while it still holds an open transaction.
    await test_engine.dispose()
    await _reset_schema()
    async with test_engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=False))

    # Reset the slowapi rate limiter's in-memory storage between tests so that
    # login attempts from one test don't bleed into another and trigger 429s.
    from app.middleware.rate_limit import limiter
    limiter._storage.reset()

    yield
    await test_engine.dispose()
    await _reset_schema()


@pytest.fixture
async def db():
    async with test_session() as session:
        yield session


@pytest.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c
    app.dependency_overrides.clear()
