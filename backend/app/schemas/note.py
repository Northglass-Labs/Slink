from datetime import datetime
from pydantic import BaseModel


class NoteCreate(BaseModel):
    content: str


class NoteResponse(BaseModel):
    id: int
    detection_id: int
    user_id: int
    username: str
    content: str
    created_at: datetime
    model_config = {"from_attributes": True}
