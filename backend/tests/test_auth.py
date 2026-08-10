import pytest
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from app.database import get_db
from app.main import app
from app.models.user import User
from app.utils.security import hash_password, verify_password, create_access_token, decode_token
from app.schemas.auth import CreateUserRequest, LoginRequest


# ---------------------------------------------------------------------------
# Pure unit tests — no DB / HTTP needed
# ---------------------------------------------------------------------------

async def test_password_hash_and_verify():
    hashed = await hash_password("testpass123")
    assert hashed != "testpass123"
    assert await verify_password("testpass123", hashed)
    assert not await verify_password("wrongpass", hashed)


async def test_verify_password_rejects_oversized_bcrypt_input_without_raising():
    hashed = await hash_password("testpass123")
    assert await verify_password("x" * 73, hashed) is False


@pytest.mark.parametrize("username", ["", "x" * 101, "bad\nname"])
def test_auth_schemas_reject_invalid_usernames(username):
    with pytest.raises(ValidationError):
        LoginRequest(username=username, password="test")
    with pytest.raises(ValidationError):
        CreateUserRequest(username=username, password="validPassword123!")


def test_access_token_encode_decode():
    token = create_access_token({"sub": "alice"})
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "alice"
    assert payload["type"] == "access"


def test_decode_token_returns_none_on_garbage():
    assert decode_token("not.a.token") is None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def admin_user(db):
    """Insert an admin user into the test DB and return the model instance."""
    user = User(
        username="admin",
        hashed_password=await hash_password("adminpass"),
        role="admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.fixture
async def viewer_user(db):
    """Insert a viewer user into the test DB and return the model instance."""
    user = User(
        username="viewer",
        hashed_password=await hash_password("viewerpass"),
        role="viewer",
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Login endpoint
# ---------------------------------------------------------------------------

async def test_login_success(client, admin_user):
    resp = await client.post("/api/auth/login", json={"username": "admin", "password": "adminpass"})
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["token_type"] == "bearer"
    # refresh token should be set as a cookie
    assert "refresh_token" in resp.cookies


async def test_login_wrong_password(client, admin_user):
    resp = await client.post("/api/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


async def test_login_unknown_user(client):
    resp = await client.post("/api/auth/login", json={"username": "ghost", "password": "pass"})
    assert resp.status_code == 401


async def test_login_oversized_password_has_same_response_for_known_and_unknown_users(
    client, admin_user
):
    oversized = "é" * 40  # 80 UTF-8 bytes; bcrypt accepts at most 72 bytes.

    known = await client.post(
        "/api/auth/login",
        json={"username": "admin", "password": oversized},
    )
    unknown = await client.post(
        "/api/auth/login",
        json={"username": "ghost", "password": oversized},
    )

    assert known.status_code == unknown.status_code == 422
    assert known.json()["detail"] == unknown.json()["detail"]


# ---------------------------------------------------------------------------
# /me endpoint
# ---------------------------------------------------------------------------

async def test_me_requires_auth(client):
    resp = await client.get("/api/auth/me")
    assert resp.status_code == 401


async def test_me_returns_current_user(client, admin_user):
    login = await client.post("/api/auth/login", json={"username": "admin", "password": "adminpass"})
    token = login.json()["access_token"]

    resp = await client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "admin"
    assert body["role"] == "admin"


# ---------------------------------------------------------------------------
# Token refresh
# ---------------------------------------------------------------------------

async def test_refresh_returns_new_access_token(client, admin_user):
    login = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    original_refresh = login.cookies["refresh_token"]
    # httpx AsyncClient carries cookies automatically
    resp = await client.post("/api/auth/refresh")
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert resp.cookies["refresh_token"] != original_refresh


async def test_refresh_token_replay_revokes_the_rotated_family(client, admin_user, db):
    login = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    original_refresh = login.cookies["refresh_token"]

    rotated = await client.post("/api/auth/refresh")
    assert rotated.status_code == 200
    rotated_refresh = rotated.cookies["refresh_token"]

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as replay_client:
            replay_client.cookies.set("refresh_token", original_refresh)
            replay = await replay_client.post("/api/auth/refresh")
            assert replay.status_code == 401

            replay_client.cookies.set("refresh_token", rotated_refresh)
            family_revoked = await replay_client.post("/api/auth/refresh")
            assert family_revoked.status_code == 401
    finally:
        app.dependency_overrides[get_db] = override_get_db


async def test_independent_login_sessions_can_refresh(client, admin_user, db):
    first_login = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    first_refresh = first_login.cookies["refresh_token"]
    second_login = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    second_refresh = second_login.cookies["refresh_token"]
    assert first_refresh != second_refresh

    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        for token in (first_refresh, second_refresh):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as session_client:
                session_client.cookies.set("refresh_token", token)
                response = await session_client.post("/api/auth/refresh")
                assert response.status_code == 200
    finally:
        app.dependency_overrides[get_db] = override_get_db


async def test_refresh_without_cookie_returns_401(client):
    resp = await client.post("/api/auth/refresh")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# User creation (admin only)
# ---------------------------------------------------------------------------

async def test_create_user_as_admin(client, admin_user):
    login = await client.post("/api/auth/login", json={"username": "admin", "password": "adminpass"})
    token = login.json()["access_token"]

    resp = await client.post(
        "/api/auth/users",
        json={"username": "newbie", "password": "newPassword123!", "role": "viewer"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "newbie"
    assert body["role"] == "viewer"


async def test_create_user_as_viewer_returns_403(client, viewer_user):
    login = await client.post("/api/auth/login", json={"username": "viewer", "password": "viewerpass"})
    token = login.json()["access_token"]

    resp = await client.post(
        "/api/auth/users",
        json={"username": "another", "password": "pass"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


async def test_create_duplicate_user_returns_409(client, admin_user):
    login = await client.post("/api/auth/login", json={"username": "admin", "password": "adminpass"})
    token = login.json()["access_token"]

    resp = await client.post(
        "/api/auth/users",
        json={"username": "admin", "password": "duplicatePassword123!"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 409


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

async def test_login_rate_limit_returns_429(client, admin_user):
    """The 6th login attempt within a minute from the same IP returns HTTP 429.

    The limiter is configured for 5 per minute. We exhaust the allowance with
    5 successful logins, then confirm the 6th is rejected with 429.
    The conftest resets the limiter storage between tests so this is isolated.
    """
    for i in range(5):
        resp = await client.post(
            "/api/auth/login", json={"username": "admin", "password": "adminpass"}
        )
        assert resp.status_code == 200, f"Expected 200 on attempt {i + 1}, got {resp.status_code}"

    # 6th attempt — should be rate-limited
    resp = await client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    assert resp.status_code == 429


async def test_spoofed_forwarding_headers_do_not_bypass_login_rate_limit(client):
    for attempt in range(5):
        response = await client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": f"198.51.100.{attempt + 1}"},
            json={"username": "ghost", "password": "not-the-password"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/api/auth/login",
        headers={"X-Forwarded-For": "203.0.113.99"},
        json={"username": "ghost", "password": "not-the-password"},
    )
    assert blocked.status_code == 429
