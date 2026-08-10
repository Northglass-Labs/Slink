from contextlib import asynccontextmanager

import pytest

from app.config import ConfigurationError
from app.main import bootstrap_admin
from app.models.user import User
from app.utils.security import hash_password


def _use_test_session(monkeypatch, db):
    @asynccontextmanager
    async def session():
        yield db

    monkeypatch.setattr("app.main.async_session", session)


async def test_production_startup_rejects_persisted_weak_admin(db, monkeypatch):
    user = User(
        username="admin",
        hashed_password=await hash_password("changeme"),
        role="admin",
    )
    db.add(user)
    await db.commit()

    monkeypatch.setattr("app.main.settings.app_env", "production")
    monkeypatch.setattr("app.main.settings.admin_password", "strong-bootstrap-password")
    _use_test_session(monkeypatch, db)

    with pytest.raises(ConfigurationError):
        await bootstrap_admin()


async def test_production_startup_accepts_persisted_strong_admin(db, monkeypatch):
    user = User(
        username="admin",
        hashed_password=await hash_password("strong-existing-password"),
        role="admin",
    )
    db.add(user)
    await db.commit()

    monkeypatch.setattr("app.main.settings.app_env", "production")
    monkeypatch.setattr("app.main.settings.admin_password", "strong-bootstrap-password")
    _use_test_session(monkeypatch, db)

    await bootstrap_admin()
