from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator

from app.utils.security import password_fits_bcrypt
from app.utils.username import normalize_username


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_boundary(cls, value: str) -> str:
        return normalize_username(value)

    @field_validator("password")
    @classmethod
    def password_bcrypt_length(cls, value: str) -> str:
        if not password_fits_bcrypt(value):
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return value


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime | None = None

    model_config = {"from_attributes": True}


class CreateUserRequest(BaseModel):
    username: str
    password: str
    # Closed set — any other value gets a 422 before the handler runs, which
    # prevents a misconfigured frontend from seeding rows like role="superuser"
    # that the RBAC check wouldn't recognize and would silently treat as viewer.
    role: Literal["admin", "viewer"] = "viewer"

    @field_validator("username")
    @classmethod
    def username_boundary(cls, value: str) -> str:
        return normalize_username(value)

    @field_validator("password")
    @classmethod
    def password_min_length(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        if not password_fits_bcrypt(v):
            raise ValueError("Password must be at most 72 UTF-8 bytes")
        return v
