from pydantic import BaseModel


class SeverityRuleCreate(BaseModel):
    source_pattern: str | None = None
    keyword_category: str | None = None
    base_severity: str
    priority: int = 0
    enabled: bool = True


class SeverityRuleUpdate(BaseModel):
    source_pattern: str | None = None
    keyword_category: str | None = None
    base_severity: str | None = None
    priority: int | None = None
    enabled: bool | None = None


class SeverityRuleResponse(BaseModel):
    id: int
    source_pattern: str | None
    keyword_category: str | None
    base_severity: str
    priority: int
    enabled: bool

    model_config = {"from_attributes": True}
