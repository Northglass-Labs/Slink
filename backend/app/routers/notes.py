from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user
from app.models.detection import Detection
from app.models.note import Note
from app.models.user import User
from app.schemas.note import NoteCreate, NoteResponse

router = APIRouter(prefix="/api/detections/{detection_id}/notes", tags=["notes"])


async def _verify_detection_exists(detection_id: int, db: AsyncSession) -> None:
    """Raise 404 if the detection does not exist."""
    result = await db.execute(select(Detection.id).where(Detection.id == detection_id))
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Detection not found")


@router.get("", response_model=list[NoteResponse])
async def list_notes(
    detection_id: int,
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """List notes for a detection, oldest first. Includes author username."""
    await _verify_detection_exists(detection_id, db)

    query = (
        select(Note, User.username)
        .join(User, Note.user_id == User.id)
        .where(Note.detection_id == detection_id)
        .order_by(Note.created_at.asc())
    )
    result = await db.execute(query)
    rows = result.all()

    return [
        NoteResponse(
            id=note.id,
            detection_id=note.detection_id,
            user_id=note.user_id,
            username=username,
            content=note.content,
            created_at=note.created_at,
        )
        for note, username in rows
    ]


@router.post("", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def create_note(
    detection_id: int,
    body: NoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create an append-only note on a detection. Any authenticated user."""
    await _verify_detection_exists(detection_id, db)

    note = Note(
        detection_id=detection_id,
        user_id=current_user.id,
        content=body.content,
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)

    return NoteResponse(
        id=note.id,
        detection_id=note.detection_id,
        user_id=note.user_id,
        username=current_user.username,
        content=note.content,
        created_at=note.created_at,
    )
