from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.utils.url_validator import WebhookURLError, validate_webhook_url


class WebhookCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)
    enabled: bool = True
    severity_filter: str = Field(default="all", min_length=1, max_length=50)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        # Reject localhost / private / link-local destinations to prevent SSRF.
        try:
            return validate_webhook_url(v)
        except WebhookURLError as exc:
            raise ValueError(str(exc))


class WebhookUpdate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    name: str | None = Field(default=None, min_length=1, max_length=100)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    enabled: bool | None = None
    severity_filter: str | None = Field(default=None, min_length=1, max_length=50)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            return validate_webhook_url(v)
        except WebhookURLError as exc:
            raise ValueError(str(exc))


class WebhookResponse(BaseModel):
    id: int
    name: str
    url: str
    enabled: bool
    severity_filter: str
    created_at: datetime

    model_config = {"from_attributes": True}
