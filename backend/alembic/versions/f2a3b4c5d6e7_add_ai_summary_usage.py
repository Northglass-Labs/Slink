"""add bounded AI summary usage reservations

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-07-11 00:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "f2a3b4c5d6e7"
down_revision: Union[str, Sequence[str], None] = "e1f2a3b4c5d6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "ai_summary_usage",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("detection_id", sa.Integer(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(["detection_id"], ["detections.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_ai_summary_usage_user_id", "ai_summary_usage", ["user_id"], unique=False
    )
    op.create_index(
        "ix_ai_summary_usage_detection_id",
        "ai_summary_usage",
        ["detection_id"],
        unique=False,
    )
    op.create_index(
        "ix_ai_summary_usage_created_at",
        "ai_summary_usage",
        ["created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_ai_summary_usage_created_at", table_name="ai_summary_usage")
    op.drop_index("ix_ai_summary_usage_detection_id", table_name="ai_summary_usage")
    op.drop_index("ix_ai_summary_usage_user_id", table_name="ai_summary_usage")
    op.drop_table("ai_summary_usage")
