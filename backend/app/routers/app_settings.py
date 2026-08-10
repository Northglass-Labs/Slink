"""
App-level settings router.

Settings are key/value rows in the app_settings table. Admins can update
values from the UI. Since values are stored as strings (to keep the schema
simple), we validate each known key against a typed schema here before
writing — otherwise `retention_days = "abc"` would sneak through and only
crash at 3am when the prune job tries int("abc").

Unknown keys are rejected to prevent typo'd settings accumulating.
"""
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.models.app_setting import AppSetting
from app.models.user import User

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _validate_positive_int(value: Any, *, minimum: int = 1, maximum: int = 10_000) -> str:
    """Return the validated value as a string, or raise ValueError."""
    try:
        ivalue = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("must be a whole number")
    if ivalue < minimum:
        raise ValueError(f"must be >= {minimum}")
    if ivalue > maximum:
        raise ValueError(f"must be <= {maximum}")
    return str(ivalue)


# Per-key validation. Keys absent from this map are rejected outright.
_VALIDATORS: dict[str, Callable[[Any], str]] = {
    "retention_days": lambda v: _validate_positive_int(v, minimum=1, maximum=3650),
}


@router.get("")
async def list_settings(
    db: AsyncSession = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Return all app settings as a key-value map."""
    result = await db.execute(select(AppSetting))
    settings_rows = result.scalars().all()
    return {s.key: {"value": s.value, "description": s.description} for s in settings_rows}


@router.patch("/{key}")
async def update_setting(
    key: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Update a single setting by key. Admin only.

    The value is validated against the per-key schema in _VALIDATORS.
    422 is returned for unknown keys or values that don't pass validation.
    """
    validator = _VALIDATORS.get(key)
    if validator is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown setting key: {key}",
        )

    if "value" not in body:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail='Request body must include "value"',
        )

    try:
        normalized_value = validator(body["value"])
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid value for {key}: {exc}",
        )

    result = await db.execute(select(AppSetting).where(AppSetting.key == key))
    setting = result.scalar_one_or_none()
    if setting is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Setting not found")

    setting.value = normalized_value
    await db.commit()
    await db.refresh(setting)
    return {"key": setting.key, "value": setting.value, "description": setting.description}
