"""
Pushover router — manage Delivery Group membership from the Slink UI.

Proxies the Pushover Groups API so admins can add/remove users without
leaving the Slink app. Requires PUSHOVER_API_TOKEN and PUSHOVER_USER_KEY
(group key) to be configured in the environment.

All routes require admin role.
"""
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.middleware.auth import require_admin
from app.models.user import User

router = APIRouter(prefix="/api/pushover", tags=["pushover"])

logger = logging.getLogger(__name__)

_PUSHOVER_BASE = "https://api.pushover.net/1"


# ---------------------------------------------------------------------------
# Request/response schemas
# ---------------------------------------------------------------------------

class PushoverUserAdd(BaseModel):
    user_key: str = Field(min_length=30, max_length=30, pattern=r"^[A-Za-z0-9]+$")
    memo: str = Field(default="", max_length=200)


class PushoverUserRemove(BaseModel):
    user_key: str = Field(min_length=30, max_length=30, pattern=r"^[A-Za-z0-9]+$")


class PushoverGroupMember(BaseModel):
    user: str
    device: str | None = None
    memo: str | None = None
    disabled: bool = False


class PushoverGroupInfo(BaseModel):
    name: str
    members: list[PushoverGroupMember]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_credentials() -> tuple[str, str]:
    """Return (api_token, group_key) or raise 503 if not configured."""
    token = settings.pushover_api_token
    group_key = settings.pushover_user_key
    if not token or not group_key:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Pushover not configured (missing API token or group key)",
        )
    return token, group_key


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/group", response_model=PushoverGroupInfo)
async def get_group(
    _admin: User = Depends(require_admin),
):
    """List all members of the Pushover delivery group. Admin only."""
    token, group_key = _get_credentials()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{_PUSHOVER_BASE}/groups/{group_key}.json",
            params={"token": token},
        )

    if not resp.is_success:
        logger.error("Pushover group info failed with status %s", resp.status_code)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Pushover rejected the request",
        )

    data = resp.json()
    members = []
    for u in data.get("users", []):
        members.append(PushoverGroupMember(
            user=u.get("user", ""),
            device=u.get("device") or None,
            memo=u.get("memo") or None,
            disabled=u.get("disabled", False),
        ))

    return PushoverGroupInfo(name=data.get("name", ""), members=members)


@router.post("/group/add", status_code=status.HTTP_201_CREATED)
async def add_user(
    body: PushoverUserAdd,
    _admin: User = Depends(require_admin),
):
    """Add a user to the Pushover delivery group. Admin only."""
    token, group_key = _get_credentials()

    payload = {"token": token, "user": body.user_key}
    if body.memo:
        payload["memo"] = body.memo[:200]

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{_PUSHOVER_BASE}/groups/{group_key}/add_user.json",
            data=payload,
        )

    if not resp.is_success:
        logger.warning("Pushover add_user failed with status %s", resp.status_code)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pushover rejected the request",
        )

    logger.info("Added a member to the Pushover group")
    return {"success": True, "message": "User added to delivery group"}


@router.post("/group/remove")
async def remove_user(
    body: PushoverUserRemove,
    _admin: User = Depends(require_admin),
):
    """Remove a user from the Pushover delivery group. Admin only."""
    token, group_key = _get_credentials()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{_PUSHOVER_BASE}/groups/{group_key}/remove_user.json",
            data={"token": token, "user": body.user_key},
        )

    if not resp.is_success:
        logger.warning("Pushover remove_user failed with status %s", resp.status_code)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pushover rejected the request",
        )

    logger.info("Removed a member from the Pushover group")
    return {"success": True, "message": "User removed from delivery group"}


@router.post("/group/enable")
async def enable_user(
    body: PushoverUserRemove,
    _admin: User = Depends(require_admin),
):
    """Re-enable a disabled user in the delivery group. Admin only."""
    token, group_key = _get_credentials()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{_PUSHOVER_BASE}/groups/{group_key}/enable_user.json",
            data={"token": token, "user": body.user_key},
        )

    if not resp.is_success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pushover rejected the request",
        )

    return {"success": True, "message": "User enabled"}


@router.post("/group/disable")
async def disable_user(
    body: PushoverUserRemove,
    _admin: User = Depends(require_admin),
):
    """Temporarily disable a user in the delivery group. Admin only."""
    token, group_key = _get_credentials()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{_PUSHOVER_BASE}/groups/{group_key}/disable_user.json",
            data={"token": token, "user": body.user_key},
        )

    if not resp.is_success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Pushover rejected the request",
        )

    return {"success": True, "message": "User disabled (will not receive alerts until re-enabled)"}


@router.post("/group/test")
async def test_group(
    _admin: User = Depends(require_admin),
):
    """Send a test notification to the entire delivery group. Admin only."""
    token, group_key = _get_credentials()

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{_PUSHOVER_BASE}/messages.json",
            data={
                "token": token,
                "user": group_key,
                "title": "SLINK-TEST: Group Connectivity Check",
                "message": "Test notification from Slink. All group members should receive this. No action required.",
                "priority": 0,
                "sound": "pushover",
            },
        )

    if not resp.is_success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Pushover rejected the request",
        )

    return {"success": True, "message": "Test notification sent to all group members"}


class PushoverCustomMessage(BaseModel):
    title: str = Field(min_length=1, max_length=250)
    message: str = Field(min_length=1, max_length=1024)
    priority: int = Field(default=0, ge=-1, le=1)


@router.post("/send")
async def send_custom(
    body: PushoverCustomMessage,
    _admin: User = Depends(require_admin),
):
    """Send a custom Pushover notification to the delivery group. Admin only."""
    token, group_key = _get_credentials()

    priority = body.priority

    data: dict[str, str | int] = {
        "token": token,
        "user": group_key,
        "title": body.title[:250],
        "message": body.message[:1024],
        "priority": priority,
        "sound": "siren" if priority == 1 else "pushover",
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(f"{_PUSHOVER_BASE}/messages.json", data=data)

    if not resp.is_success:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Pushover rejected the request",
        )

    logger.info("Custom Pushover message sent")
    return {"success": True, "message": "Message sent to all group members"}
