from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.notification_channel import NotificationChannel
from app.models.user import User
from app.schemas.notification_channel import NotificationChannelResponse, NotificationChannelUpdate
from app.services.notifier import invalidate_channel_cache

router = APIRouter(prefix="/api/notification-channels", tags=["notification-channels"])


@router.get("", response_model=list[NotificationChannelResponse])
async def list_channels(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all notification channel states."""
    result = await db.execute(select(NotificationChannel).order_by(NotificationChannel.channel_type))
    return result.scalars().all()


@router.patch("/{channel_type}", response_model=NotificationChannelResponse)
async def update_channel(
    channel_type: str,
    body: NotificationChannelUpdate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Toggle a notification channel on/off. Admin only."""
    result = await db.execute(
        select(NotificationChannel).where(NotificationChannel.channel_type == channel_type)
    )
    channel = result.scalar_one_or_none()
    if channel is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Channel not found")

    channel.enabled = body.enabled
    await db.commit()
    await db.refresh(channel)

    # Invalidate the in-memory cache so the toggle takes effect immediately
    # rather than waiting for the 60s TTL to expire.
    invalidate_channel_cache(channel_type)

    return channel


@router.post("/{channel_type}/test")
async def test_channel(
    channel_type: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Send a test notification through the specified channel. Admin only."""
    # Import the module-level singleton so we reuse the same httpx client
    # rather than creating a new one (which would also need to be closed).
    from app.services.scheduler import notifier
    from app.services.notifier import build_adaptive_card

    test_title = "Slink test notification"
    test_message = "This is a test notification from Slink. If you see this, your channel is working."

    try:
        if channel_type == "pushover":
            await notifier._send_pushover(
                title=test_title,
                message=test_message,
                severity="low",
            )
            return {"success": True, "message": "Test sent via Pushover"}

        elif channel_type == "teams_env_webhook":
            from app.config import settings
            if not settings.teams_webhook_url:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="TEAMS_WEBHOOK_URL not configured in backend .env",
                )
            card = build_adaptive_card(
                severity="low",
                source="slink",
                title=test_title,
                matched_keywords=[],
                first_seen=datetime.now(timezone.utc).isoformat(),
                snippet=test_message,
                detection_id=0,
                base_url=notifier._base_url,
            )
            await notifier._send_via_webhook(card, settings.teams_webhook_url, name="test")
            return {"success": True, "message": "Test card sent to Teams webhook"}

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown channel type: {channel_type}",
            )
    except HTTPException:
        raise
    except Exception as exc:
        return {"success": False, "message": f"Test failed: {str(exc)[:200]}"}
