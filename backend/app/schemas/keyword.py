from datetime import datetime

from pydantic import BaseModel


class KeywordCreate(BaseModel):
    term: str
    category: str
    enabled: bool = True


class KeywordUpdate(BaseModel):
    term: str | None = None
    category: str | None = None
    enabled: bool | None = None


class KeywordResponse(BaseModel):
    id: int
    term: str
    category: str
    enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}
