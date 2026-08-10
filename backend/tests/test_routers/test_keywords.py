"""Tests for the /api/keywords router."""
import pytest
from app.models.keyword import Keyword
from app.models.user import User
from app.utils.security import hash_password


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def admin_user(db):
    user = User(username="admin", hashed_password=await hash_password("adminpass"), role="admin")
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.fixture
async def viewer_user(db):
    user = User(username="viewer", hashed_password=await hash_password("viewerpass"), role="viewer")
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.fixture
async def admin_headers(client, admin_user):
    resp = await client.post("/api/auth/login", json={"username": "admin", "password": "adminpass"})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def viewer_headers(client, viewer_user):
    resp = await client.post("/api/auth/login", json={"username": "viewer", "password": "viewerpass"})
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def auth_headers(admin_headers):
    return admin_headers


@pytest.fixture
async def sample_keyword(db):
    kw = Keyword(term="ransomware", category="malware", enabled=True)
    db.add(kw)
    await db.commit()
    await db.refresh(kw)
    return kw


# ---------------------------------------------------------------------------
# GET /api/keywords
# ---------------------------------------------------------------------------


async def test_list_keywords_requires_auth(client):
    resp = await client.get("/api/keywords")
    assert resp.status_code == 401


async def test_list_keywords(client, auth_headers, sample_keyword):
    resp = await client.get("/api/keywords", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["term"] == "ransomware"
    assert body[0]["category"] == "malware"
    assert body[0]["enabled"] is True


async def test_list_keywords_empty(client, auth_headers):
    resp = await client.get("/api/keywords", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# POST /api/keywords
# ---------------------------------------------------------------------------


async def test_create_keyword_admin_only(client, viewer_headers, admin_headers):
    # Viewer should be rejected
    resp = await client.post(
        "/api/keywords",
        json={"term": "c2", "category": "threat"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403

    # Admin should succeed
    resp = await client.post(
        "/api/keywords",
        json={"term": "c2", "category": "threat"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["term"] == "c2"
    assert body["category"] == "threat"
    assert body["enabled"] is True
    assert "id" in body
    assert "created_at" in body


async def test_create_keyword_defaults_enabled_true(client, admin_headers):
    resp = await client.post(
        "/api/keywords",
        json={"term": "phishing", "category": "social_engineering"},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["enabled"] is True


async def test_create_keyword_can_disable(client, admin_headers):
    resp = await client.post(
        "/api/keywords",
        json={"term": "phishing", "category": "social_engineering", "enabled": False},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["enabled"] is False


async def test_create_keyword_requires_auth(client):
    resp = await client.post("/api/keywords", json={"term": "test", "category": "cat"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PUT /api/keywords/{id}
# ---------------------------------------------------------------------------


async def test_update_keyword(client, admin_headers, sample_keyword):
    resp = await client.put(
        f"/api/keywords/{sample_keyword.id}",
        json={"term": "updated-term", "enabled": False},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["term"] == "updated-term"
    assert body["enabled"] is False
    # Category should be unchanged
    assert body["category"] == "malware"


async def test_update_keyword_admin_only(client, viewer_headers, sample_keyword):
    resp = await client.put(
        f"/api/keywords/{sample_keyword.id}",
        json={"term": "hacked"},
        headers=viewer_headers,
    )
    assert resp.status_code == 403


async def test_update_keyword_not_found(client, admin_headers):
    resp = await client.put(
        "/api/keywords/99999",
        json={"term": "ghost"},
        headers=admin_headers,
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# DELETE /api/keywords/{id}
# ---------------------------------------------------------------------------


async def test_delete_keyword(client, admin_headers, sample_keyword):
    resp = await client.delete(f"/api/keywords/{sample_keyword.id}", headers=admin_headers)
    assert resp.status_code == 204

    # Verify it's gone
    resp = await client.get("/api/keywords", headers=admin_headers)
    assert resp.json() == []


async def test_delete_keyword_admin_only(client, viewer_headers, sample_keyword):
    resp = await client.delete(f"/api/keywords/{sample_keyword.id}", headers=viewer_headers)
    assert resp.status_code == 403


async def test_delete_keyword_not_found(client, admin_headers):
    resp = await client.delete("/api/keywords/99999", headers=admin_headers)
    assert resp.status_code == 404


async def test_delete_keyword_requires_auth(client, sample_keyword):
    resp = await client.delete(f"/api/keywords/{sample_keyword.id}")
    assert resp.status_code == 401
