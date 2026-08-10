"""add indexes check constraints and jsonb

Revision ID: 7f79dd21646c
Revises: d8e052524ef1
Create Date: 2026-04-11 15:47:31.132684

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = '7f79dd21646c'
down_revision: Union[str, Sequence[str], None] = 'd8e052524ef1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # D1: Index on created_at for prune job and time-range queries
    op.create_index("ix_detections_created_at", "detections", ["created_at"])

    # D2: Composite index for dashboard queries (status + severity)
    op.create_index("ix_detections_status_severity", "detections", ["status", "severity"])

    # D3: Composite index for cross-source dedup query
    op.create_index(
        "ix_detections_victim_hash_source_created",
        "detections",
        ["victim_hash", "source", "created_at"],
    )

    # D4: Convert matched_keywords from JSON to JSONB
    op.alter_column(
        "detections",
        "matched_keywords",
        type_=postgresql.JSONB,
        existing_type=sa.JSON,
        postgresql_using="matched_keywords::jsonb",
    )

    # D5: CHECK constraints on severity and status
    op.create_check_constraint(
        "ck_detections_severity",
        "detections",
        "severity IN ('critical', 'high', 'medium', 'low')",
    )
    op.create_check_constraint(
        "ck_detections_status",
        "detections",
        "status IN ('new', 'acknowledged', 'dismissed', 'escalated', 'duplicate')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("ck_detections_status", "detections", type_="check")
    op.drop_constraint("ck_detections_severity", "detections", type_="check")
    op.alter_column(
        "detections",
        "matched_keywords",
        type_=sa.JSON,
        existing_type=postgresql.JSONB,
    )
    op.drop_index("ix_detections_victim_hash_source_created", "detections")
    op.drop_index("ix_detections_status_severity", "detections")
    op.drop_index("ix_detections_created_at", "detections")
