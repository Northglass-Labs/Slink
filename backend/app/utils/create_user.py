"""CLI utility for creating users manually.

Usage (from backend/ directory with DATABASE_URL set):
    python -m app.utils.create_user <username> [viewer|admin]

role defaults to "viewer". Use "admin" for admin users.
"""
import asyncio
from getpass import getpass
import sys
from sqlalchemy import select
from app.database import async_session
from app.models.user import User
from app.utils.security import hash_password
from app.utils.username import normalize_username


async def create_user(username: str, password: str, role: str = "viewer") -> None:
    async with async_session() as db:
        result = await db.execute(select(User).where(User.username == username))
        if result.scalar_one_or_none():
            print(f"User '{username}' already exists.")
            return
        user = User(
            username=username,
            hashed_password=await hash_password(password),
            role=role,
        )
        db.add(user)
        await db.commit()
        print(f"Created user '{username}' with role '{role}'.")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        print("Usage: python -m app.utils.create_user <username> [viewer|admin]")
        sys.exit(1)
    try:
        _username = normalize_username(sys.argv[1])
    except ValueError as exc:
        print(str(exc))
        sys.exit(1)
    _role = sys.argv[2] if len(sys.argv) == 3 else "viewer"
    if _role not in {"viewer", "admin"}:
        print("Role must be viewer or admin.")
        sys.exit(1)
    _password = getpass("Password: ")
    _confirm = getpass("Confirm password: ")
    if _password != _confirm:
        print("Passwords did not match.")
        sys.exit(1)
    if len(_password) < 12:
        print("Password must be at least 12 characters.")
        sys.exit(1)
    if len(_password.encode("utf-8")) > 72:
        print("Password must be at most 72 UTF-8 bytes.")
        sys.exit(1)
    asyncio.run(create_user(_username, _password, _role))
