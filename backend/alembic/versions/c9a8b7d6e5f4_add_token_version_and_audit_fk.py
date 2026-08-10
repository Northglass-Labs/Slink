"""add user.token_version and relax audit_log.user_id FK

Revision ID: c9a8b7d6e5f4
Revises: 83cf54a6d304
Create Date: 2026-04-18 12:00:00.000000

Adds:
- users.token_version (int, default 0) — bumped on logout to revoke all
  outstanding access + refresh tokens for that user (JWTs carry a "ver"
  claim checked against this column on every request).
- audit_log.user_id FK switched to ON DELETE SET NULL so admin user
  deletions preserve the audit trail rather than failing with a FK
  violation or cascade-deleting history.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c9a8b7d6e5f4"
down_revision: Union[str, Sequence[str], None] = "83cf54a6d304"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default="0"),
    )
    # Existing rows now have 0; drop the server_default so future INSERTs
    # rely on the Python-side default and we avoid accidental drift.
    op.alter_column("users", "token_version", server_default=None)

    # Re-create the audit_log.user_id FK with ON DELETE SET NULL.
    # Migration b3c4d5e6f7a8 created the FK anonymously, so Postgres gave it
    # the conventional name "audit_log_user_id_fkey" — drop and re-add.
    op.drop_constraint("audit_log_user_id_fkey", "audit_log", type_="foreignkey")
    op.create_foreign_key(
        "audit_log_user_id_fkey",
        "audit_log",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("audit_log_user_id_fkey", "audit_log", type_="foreignkey")
    op.create_foreign_key(
        "audit_log_user_id_fkey",
        "audit_log",
        "users",
        ["user_id"],
        ["id"],
    )
    op.drop_column("users", "token_version")
