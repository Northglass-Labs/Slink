"""Tests for the /api/detections router."""
import pytest
from unittest.mock import AsyncMock, patch
from app.models.detection import Detection
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
    """Alias — most tests only need any authenticated user."""
    return admin_headers


@pytest.fixture
async def sample_detection(db):
    detection = Detection(
        source="shodan",
        title="Test finding",
        snippet="A test snippet",
        source_url="https://example.com/finding",
        content_hash="abc123deadbeef",
        matched_keywords=["ransomware", "c2"],
        severity="high",
        status="new",
        raw_data={"secret": "admin_only_payload"},
    )
    db.add(detection)
    await db.commit()
    await db.refresh(detection)
    return detection


# ---------------------------------------------------------------------------
# GET /api/detections
# ---------------------------------------------------------------------------


async def test_list_detections_requires_auth(client):
    resp = await client.get("/api/detections")
    assert resp.status_code == 401


async def test_list_detections(client, auth_headers, sample_detection):
    resp = await client.get("/api/detections", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["id"] == sample_detection.id
    assert item["source"] == "shodan"
    # raw_data must NOT appear in list view
    assert "raw_data" not in item


async def test_list_detections_pagination(client, auth_headers, db):
    # Insert 5 detections
    for i in range(5):
        db.add(Detection(
            source="shodan",
            title=f"Finding {i}",
            snippet="snippet",
            source_url=f"https://example.com/{i}",
            content_hash=f"hash{i}",
            matched_keywords=["test"],
            severity="low",
            status="new",
        ))
    await db.commit()

    # First page
    resp = await client.get("/api/detections?limit=2&offset=0", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 5
    assert len(body["items"]) == 2

    # Second page
    resp = await client.get("/api/detections?limit=2&offset=2", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 2

    # Last page
    resp = await client.get("/api/detections?limit=2&offset=4", headers=auth_headers)
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


async def test_list_detections_filter_by_source(client, auth_headers, db):
    db.add(Detection(
        source="shodan", title="t", snippet="s", source_url="u", content_hash="h1",
        matched_keywords=[], severity="low", status="new",
    ))
    db.add(Detection(
        source="github", title="t2", snippet="s2", source_url="u2", content_hash="h2",
        matched_keywords=[], severity="low", status="new",
    ))
    await db.commit()

    resp = await client.get("/api/detections?source=shodan", headers=auth_headers)
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["source"] == "shodan"


async def test_list_detections_filter_by_status(client, auth_headers, db):
    db.add(Detection(
        source="shodan", title="t", snippet="s", source_url="u", content_hash="h1",
        matched_keywords=[], severity="low", status="new",
    ))
    db.add(Detection(
        source="shodan", title="t2", snippet="s2", source_url="u2", content_hash="h2",
        matched_keywords=[], severity="low", status="acknowledged",
    ))
    await db.commit()

    resp = await client.get("/api/detections?status=acknowledged", headers=auth_headers)
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "acknowledged"


# ---------------------------------------------------------------------------
# GET /api/detections/{id}
# ---------------------------------------------------------------------------


async def test_get_detection_admin_sees_raw_data(client, admin_headers, sample_detection):
    resp = await client.get(f"/api/detections/{sample_detection.id}", headers=admin_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == sample_detection.id
    # Admin should see raw_data
    assert body["raw_data"] == {"secret": "admin_only_payload"}


async def test_get_detection_viewer_no_raw_data(client, viewer_headers, sample_detection):
    resp = await client.get(f"/api/detections/{sample_detection.id}", headers=viewer_headers)
    assert resp.status_code == 200
    body = resp.json()
    # raw_data must be null for non-admin users — security requirement
    assert body["raw_data"] is None


async def test_get_detection_not_found(client, auth_headers):
    resp = await client.get("/api/detections/99999", headers=auth_headers)
    assert resp.status_code == 404


async def test_get_detection_requires_auth(client, sample_detection):
    resp = await client.get(f"/api/detections/{sample_detection.id}")
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# PATCH /api/detections/{id}/status
# ---------------------------------------------------------------------------


async def test_update_detection_status(client, auth_headers, sample_detection):
    resp = await client.patch(
        f"/api/detections/{sample_detection.id}/status",
        json={"status": "acknowledged"},
        headers=auth_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "acknowledged"


async def test_update_detection_status_invalid(client, auth_headers, sample_detection):
    resp = await client.patch(
        f"/api/detections/{sample_detection.id}/status",
        json={"status": "invalid_status"},
        headers=auth_headers,
    )
    assert resp.status_code == 422


async def test_update_detection_status_not_found(client, auth_headers):
    resp = await client.patch(
        "/api/detections/99999/status",
        json={"status": "dismissed"},
        headers=auth_headers,
    )
    assert resp.status_code == 404


async def test_update_detection_status_requires_auth(client, sample_detection):
    resp = await client.patch(
        f"/api/detections/{sample_detection.id}/status",
        json={"status": "acknowledged"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# POST /api/detections/{id}/ai-summary
# ---------------------------------------------------------------------------


async def test_ai_summary_rejects_viewer_before_provider_call(
    client, viewer_headers, sample_detection
):
    with patch(
        "app.routers.detections.ai_generate_summary", new_callable=AsyncMock
    ) as generate:
        response = await client.post(
            f"/api/detections/{sample_detection.id}/ai-summary",
            headers=viewer_headers,
        )

    assert response.status_code == 403
    generate.assert_not_awaited()


async def test_ai_summary_admin_generation_is_audited_and_bounded(
    client, admin_headers, sample_detection, monkeypatch
):
    monkeypatch.setattr("app.services.ai_budget.settings.ai_summary_daily_limit", 1)
    monkeypatch.setattr("app.services.ai_budget.settings.ai_summary_user_daily_limit", 1)
    generated = {
        "summary": "Bounded analyst summary.",
        "attack_techniques": [],
        "pivots": [],
        "generated_at": "2026-07-11T00:00:00+00:00",
        "model": "test-model",
    }
    with patch(
        "app.routers.detections.ai_generate_summary",
        new=AsyncMock(return_value=generated),
    ):
        first = await client.post(
            f"/api/detections/{sample_detection.id}/ai-summary?refresh=true",
            headers=admin_headers,
        )
        second = await client.post(
            f"/api/detections/{sample_detection.id}/ai-summary?refresh=true",
            headers=admin_headers,
        )

    assert first.status_code == 200
    assert second.status_code == 429


async def test_ai_summary_upstream_error_is_generic(
    client, admin_headers, sample_detection
):
    with patch(
        "app.routers.detections.ai_generate_summary",
        new=AsyncMock(side_effect=RuntimeError("credential-bearing internal detail")),
    ):
        response = await client.post(
            f"/api/detections/{sample_detection.id}/ai-summary?refresh=true",
            headers=admin_headers,
        )

    assert response.status_code == 502
    assert "credential-bearing" not in response.text
