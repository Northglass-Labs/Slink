import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import uuid

import bcrypt
import jwt
from jwt import InvalidTokenError

from app.config import settings

_BCRYPT_MAX_BYTES = 72
# A public, fixed dummy hash makes nonexistent-user checks perform the same
# bcrypt work as existing-user checks without representing a real credential.
DUMMY_PASSWORD_HASH = "$2b$12$ZXD3O5KA2237oHOLPoZF0OUYz7xbz5fL0/ZBVmKFBe1SbfkoRlcju"


def password_fits_bcrypt(password: str) -> bool:
    return len(password.encode("utf-8")) <= _BCRYPT_MAX_BYTES


def _hash_password_sync(password: str) -> str:
    """Synchronous bcrypt hash. Runs in thread pool via asyncio.to_thread()."""
    if not password_fits_bcrypt(password):
        raise ValueError("Password must be at most 72 UTF-8 bytes")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password_sync(plain: str, hashed: str) -> bool:
    """Synchronous bcrypt verify. Runs in thread pool via asyncio.to_thread()."""
    if not password_fits_bcrypt(plain):
        return False
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (TypeError, ValueError):
        return False


async def hash_password(password: str) -> str:
    """Hash a password using bcrypt. Non-blocking — runs in thread pool."""
    return await asyncio.to_thread(_hash_password_sync, password)


async def verify_password(plain: str, hashed: str) -> bool:
    """Verify a password against bcrypt hash. Non-blocking — runs in thread pool."""
    return await asyncio.to_thread(_verify_password_sync, plain, hashed)


def create_access_token(data: dict, *, token_version: int = 0) -> str:
    # Security: only the subject (username) and an opaque "ver" are encoded.
    # Role and other authz claims are intentionally omitted — the server
    # re-fetches the user from the DB on every request, so any role claim
    # in the JWT would be both untrusted and a fragile attack surface if
    # accidentally read. "ver" lets us revoke all tokens for a user by
    # bumping user.token_version.
    payload = {
        "sub": data["sub"],
        "type": "access",
        "ver": token_version,
        "jti": str(uuid.uuid4()),
        "iat": datetime.now(timezone.utc),
    }
    payload["exp"] = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def create_refresh_token(
    data: dict,
    *,
    token_version: int = 0,
    family_id: str | None = None,
) -> str:
    # Same minimal-claims rule as access tokens — see create_access_token.
    payload = {
        "sub": data["sub"],
        "type": "refresh",
        "ver": token_version,
        "fid": family_id or str(uuid.uuid4()),
        "jti": str(uuid.uuid4()),
        "iat": datetime.now(timezone.utc),
    }
    payload["exp"] = datetime.now(timezone.utc) + timedelta(
        hours=settings.refresh_token_expire_hours
    )
    return jwt.encode(payload, settings.secret_key, algorithm="HS256")


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT. Returns the payload dict, or None on any error."""
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=["HS256"],
            options={"require": ["sub", "type", "exp", "iat", "jti"]},
        )
    except InvalidTokenError:
        return None


def hash_refresh_token(token: str) -> str:
    """Return a non-reversible digest for server-side refresh-token state."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
