from datetime import datetime, timedelta, timezone
import hmac
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.middleware.auth import get_current_user, require_admin
from app.middleware.rate_limit import enforce_shared_auth_limit, limiter
from app.models.auth_session import RefreshSession
from app.models.user import User
from app.schemas.auth import CreateUserRequest, LoginRequest, TokenResponse, UserResponse
from app.services.audit import log_action
from app.utils.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Cookie name used for the httpOnly refresh token
_REFRESH_COOKIE = "refresh_token"

# Security: lock account after this many consecutive bad passwords for _LOCKOUT_DURATION_MINUTES.
_LOCKOUT_THRESHOLD = 10
_LOCKOUT_DURATION_MINUTES = 15


def _set_refresh_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=_REFRESH_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/api/auth",
        max_age=settings.refresh_token_expire_hours * 3600,
    )


# Security: rate-limit login to 5 attempts per minute per IP to prevent brute-force attacks.
# A second, per-account lockout layer triggers after _LOCKOUT_THRESHOLD consecutive failures.
@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: Request, body: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    await enforce_shared_auth_limit(
        db, request, bucket="login", limit=5, window_seconds=60
    )
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    # Reject locked accounts with the SAME response as bad credentials so a
    # caller cannot tell whether the username exists. The old code returned
    # 423 + a remaining-minutes message which leaked both existence and timing.
    # Lock state is still enforced below — we just refuse to confirm which
    # condition applies.
    if user and user.locked_until and user.locked_until > now:
        # Keep the locked-account path computationally aligned with a normal
        # rejection without checking the caller's password against the real hash.
        await verify_password(body.password, DUMMY_PASSWORD_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )

    password_matches = await verify_password(
        body.password,
        user.hashed_password if user is not None else DUMMY_PASSWORD_HASH,
    )
    if user is None or not password_matches:
        if user is not None:
            user.failed_login_count += 1
            if user.failed_login_count >= _LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(minutes=_LOCKOUT_DURATION_MINUTES)
                # Security: log lockout event to audit trail for forensic review.
                await log_action(
                    db,
                    user_id=user.id,
                    action="user.locked",
                    target_type="user",
                    target_id=user.id,
                    detail={
                        "reason": "failed_login_threshold",
                        "failed_count": user.failed_login_count,
                        "locked_until": user.locked_until.isoformat(),
                    },
                )
            await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Successful login — reset failure counter and any prior lock.
    if user.failed_login_count > 0 or user.locked_until is not None:
        user.failed_login_count = 0
        user.locked_until = None

    access_token = create_access_token({"sub": user.username}, token_version=user.token_version)
    family_id = str(uuid.uuid4())
    refresh_token = create_refresh_token(
        {"sub": user.username},
        token_version=user.token_version,
        family_id=family_id,
    )
    refresh_payload = decode_token(refresh_token)
    assert refresh_payload is not None
    db.add(
        RefreshSession(
            family_id=family_id,
            user_id=user.id,
            token_hash=hash_refresh_token(refresh_token),
            expires_at=datetime.fromtimestamp(refresh_payload["exp"], timezone.utc),
        )
    )
    await db.commit()

    # Store refresh token in an httpOnly cookie so JavaScript cannot access it.
    _set_refresh_cookie(response, refresh_token)
    return TokenResponse(access_token=access_token)


# Security: rate-limit refresh to 30/minute per IP. Combined with refresh-token
# rotation below, this prevents an attacker from rapidly minting access tokens
# from a stolen refresh token.
@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
async def refresh(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    await enforce_shared_auth_limit(
        db, request, bucket="refresh", limit=30, window_seconds=60
    )
    token = request.cookies.get(_REFRESH_COOKIE)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token")

    payload = decode_token(token)
    if payload is None or payload.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    username: str | None = payload.get("sub")
    family_id: str | None = payload.get("fid")
    if username is None or family_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

    session_result = await db.execute(
        select(RefreshSession)
        .where(RefreshSession.family_id == family_id)
        .with_for_update()
    )
    refresh_session = session_result.scalar_one_or_none()
    if refresh_session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if user is None or refresh_session.user_id != user.id:
        await db.delete(refresh_session)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Reject refresh tokens whose version no longer matches the user's current
    # token_version. Logout bumps the version, so any stolen/replayed refresh
    # token that predates a logout is now useless.
    if payload.get("ver", 0) != user.token_version:
        await db.delete(refresh_session)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

    presented_hash = hash_refresh_token(token)
    if not hmac.compare_digest(presented_hash, refresh_session.token_hash):
        # A previously consumed token from this family was replayed. Revoke the
        # entire family so the attacker and legitimate holder must authenticate.
        await db.delete(refresh_session)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    # Atomically rotate the token under the row lock. Only one concurrent use
    # can match the stored digest; every later use triggers family revocation.
    access_token = create_access_token({"sub": user.username}, token_version=user.token_version)
    new_refresh_token = create_refresh_token(
        {"sub": user.username},
        token_version=user.token_version,
        family_id=family_id,
    )
    new_payload = decode_token(new_refresh_token)
    assert new_payload is not None
    refresh_session.token_hash = hash_refresh_token(new_refresh_token)
    refresh_session.expires_at = datetime.fromtimestamp(new_payload["exp"], timezone.utc)
    await db.commit()

    _set_refresh_cookie(response, new_refresh_token)
    return TokenResponse(access_token=access_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    """Invalidate the session and clear the refresh cookie.

    If we can identify the user from the refresh cookie, bump their
    token_version. That rejects every outstanding access + refresh token
    (including one a thief may have copied) on the next request.
    Works silently even with an expired access token.
    """
    token = request.cookies.get(_REFRESH_COOKIE)
    if token:
        payload = decode_token(token)
        if payload and payload.get("type") == "refresh":
            username = payload.get("sub")
            if username:
                result = await db.execute(select(User).where(User.username == username))
                user = result.scalar_one_or_none()
                if user is not None:
                    user.token_version += 1
                    await db.execute(
                        delete(RefreshSession).where(RefreshSession.user_id == user.id)
                    )
                    await db.commit()

    response.delete_cookie(
        key=_REFRESH_COOKIE,
        httponly=True,
        samesite="lax",
        secure=settings.secure_cookies,
        path="/api/auth",
    )


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """List all users. Admin only."""
    result = await db.execute(select(User).order_by(User.id))
    return result.scalars().all()


@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    body: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    result = await db.execute(select(User).where(User.username == body.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")

    user = User(
        username=body.username,
        hashed_password=await hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.flush()
    await log_action(
        db, user_id=_admin.id, action="user.created",
        target_type="user", target_id=user.id,
        detail={"username": user.username, "role": user.role},
    )
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """Delete a user. Admin only. Cannot delete yourself."""
    if current_user.id == user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot delete yourself")
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    await log_action(
        db, user_id=current_user.id, action="user.deleted",
        target_type="user", target_id=user.id,
        detail={"username": user.username, "role": user.role},
    )
    await db.delete(user)
    await db.commit()
