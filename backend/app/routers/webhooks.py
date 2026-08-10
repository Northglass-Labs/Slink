"""
Webhooks router — CRUD + test endpoint for Teams webhook destinations.

All routes require admin role. Webhook URLs are treated as secrets:
they are stored in the database only, never committed to source control.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import require_admin
from app.models.user import User
from app.models.webhook import Webhook
from app.schemas.webhook import WebhookCreate, WebhookResponse, WebhookUpdate
from app.utils.url_validator import WebhookURLError, post_webhook_json

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Test card — a simple Adaptive Card to confirm delivery
# ---------------------------------------------------------------------------
_TEST_CARD = {
    "type": "AdaptiveCard",
    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
    "version": "1.4",
    "body": [
        {
            "type": "Container",
            "style": "good",
            "items": [
                {
                    "type": "TextBlock",
                    "text": "✅ Slink Webhook Test",
                    "weight": "Bolder",
                    "size": "Medium",
                    "color": "Light",
                }
            ],
        },
        {
            "type": "TextBlock",
            "text": "This is a test message from Slink. Your webhook is configured correctly.",
            "wrap": True,
        },
    ],
}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _severity_filter_valid(value: str) -> bool:
    """
    Accept "all" or a comma-separated list of: critical, high, medium, low.
    Rejects arbitrary strings to prevent junk data.
    """
    if value == "all":
        return True
    allowed = {"critical", "high", "medium", "low"}
    parts = {p.strip() for p in value.split(",") if p.strip()}
    return bool(parts) and parts.issubset(allowed)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("", response_model=list[WebhookResponse])
async def list_webhooks(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """List all configured webhook destinations. Admin only."""
    result = await db.execute(select(Webhook).order_by(Webhook.id))
    return result.scalars().all()


@router.post("", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    body: WebhookCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Add a new Teams webhook destination. Admin only."""
    if not _severity_filter_valid(body.severity_filter):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='severity_filter must be "all" or a comma-separated list of: critical, high, medium, low',
        )
    webhook = Webhook(
        name=body.name,
        url=body.url,
        enabled=body.enabled,
        severity_filter=body.severity_filter,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return webhook


@router.put("/{webhook_id}", response_model=WebhookResponse)
async def update_webhook(
    webhook_id: int,
    body: WebhookUpdate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update a webhook destination. Admin only."""
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    if body.name is not None:
        webhook.name = body.name
    if body.url is not None:
        webhook.url = body.url
    if body.enabled is not None:
        webhook.enabled = body.enabled
    if body.severity_filter is not None:
        if not _severity_filter_valid(body.severity_filter):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail='severity_filter must be "all" or a comma-separated list of: critical, high, medium, low',
            )
        webhook.severity_filter = body.severity_filter

    await db.commit()
    await db.refresh(webhook)
    return webhook


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Delete a webhook destination. Admin only."""
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    await db.delete(webhook)
    await db.commit()


@router.post("/{webhook_id}/test", status_code=status.HTTP_200_OK)
async def test_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Send a test Adaptive Card to this webhook. Admin only."""
    result = await db.execute(select(Webhook).where(Webhook.id == webhook_id))
    webhook = result.scalar_one_or_none()
    if webhook is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": _TEST_CARD,
            }
        ],
    }

    # Re-validate the stored URL at send time. Webhooks created before SSRF
    # protection landed may still point at internal hosts; without this check
    # an admin could exfiltrate response bodies (or at least pivot/probe) via
    # the /test endpoint.
    try:
        resp = await post_webhook_json(webhook.url, payload, timeout=15)

        if resp.is_success:
            logger.info("Test card delivered to webhook %d", webhook_id)
            return {"success": True, "message": "Test card delivered successfully."}
        else:
            logger.warning(
                "Test card rejected by webhook %d with status %s",
                webhook_id,
                resp.status_code,
            )
            return {
                "success": False,
                "message": f"Webhook returned HTTP {resp.status_code}",
            }
    except WebhookURLError:
        logger.warning(
            "Test refused because webhook %d failed URL validation",
            webhook_id,
        )
        return {"success": False, "message": "Webhook URL is not allowed."}
    except Exception as exc:
        logger.error(
            "Test card delivery failed for webhook %d: %s",
            webhook_id,
            type(exc).__name__,
        )
        return {"success": False, "message": "Webhook delivery failed (see server logs)."}
