from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.detection import Detection
from app.models.incident import Incident, incident_keywords
from app.models.user import User
from app.schemas.detection import DetectionListItem
from app.schemas.incident import IncidentCreate, IncidentResponse, IncidentUpdate

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentResponse])
async def list_incidents(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List all incidents. Active first, then closed, ordered by creation date."""
    result = await db.execute(
        select(Incident).order_by(
            # active before closed
            Incident.status.desc(),
            Incident.created_at.desc(),
        )
    )
    return result.scalars().all()


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(
    body: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Create a new incident and link keywords by ID. Admin only."""
    incident = Incident(name=body.name, description=body.description)
    db.add(incident)
    await db.flush()

    # Link keywords
    for kid in body.keyword_ids:
        await db.execute(incident_keywords.insert().values(incident_id=incident.id, keyword_id=kid))

    await db.commit()
    await db.refresh(incident)
    return incident


@router.patch("/{incident_id}", response_model=IncidentResponse)
async def update_incident(
    incident_id: int,
    body: IncidentUpdate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update an incident. Admin only.

    When status changes to 'closed', closed_at is set automatically.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    if body.name is not None:
        incident.name = body.name
    if body.description is not None:
        incident.description = body.description
    if body.status is not None:
        if body.status not in ("active", "closed"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Status must be 'active' or 'closed'")
        incident.status = body.status
        if body.status == "closed" and incident.closed_at is None:
            incident.closed_at = datetime.now(timezone.utc)
        elif body.status == "active":
            incident.closed_at = None

    # Update keyword links if provided
    if body.keyword_ids is not None:
        await db.execute(delete(incident_keywords).where(incident_keywords.c.incident_id == incident.id))
        for kid in body.keyword_ids:
            await db.execute(incident_keywords.insert().values(incident_id=incident.id, keyword_id=kid))

    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}/detections", response_model=list[DetectionListItem])
async def get_incident_detections(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List detections whose matched_keywords overlap with this incident's keywords.

    Explicit response_model keeps raw_data (and other internal columns like
    content_hash) out of the response — without it, FastAPI serialises the
    full ORM row and leaks whatever the source API returned.
    """
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")

    # Get incident keyword terms
    incident_terms = [kw.term for kw in incident.keywords]
    if not incident_terms:
        return []

    # Find detections where matched_keywords JSONB array contains any incident term.
    # Uses PostgreSQL @> containment via SQLAlchemy's .contains() — same pattern as
    # the detections router keyword filter, but with OR across all incident terms.
    term_filters = [Detection.matched_keywords.contains([term]) for term in incident_terms]
    detections_result = await db.execute(
        select(Detection)
        .where(or_(*term_filters))
        .order_by(Detection.created_at.desc())
        .limit(100)
    )

    return detections_result.scalars().all()
