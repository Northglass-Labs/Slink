from datetime import datetime

from pydantic import BaseModel


class IncidentCreate(BaseModel):
    name: str
    description: str | None = None
    keyword_ids: list[int] = []


class IncidentUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None  # "active" or "closed"
    keyword_ids: list[int] | None = None


class IncidentKeywordResponse(BaseModel):
    id: int
    term: str
    category: str
    model_config = {"from_attributes": True}


class IncidentResponse(BaseModel):
    id: int
    name: str
    description: str | None
    status: str
    created_at: datetime
    closed_at: datetime | None
    keywords: list[IncidentKeywordResponse]
    model_config = {"from_attributes": True}
