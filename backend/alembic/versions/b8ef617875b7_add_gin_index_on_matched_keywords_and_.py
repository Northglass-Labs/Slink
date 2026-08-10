"""add GIN index on matched_keywords and composite on severity_rules

Revision ID: b8ef617875b7
Revises: 85f15732fe53
Create Date: 2026-04-12 14:06:56.996692

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8ef617875b7'
down_revision: Union[str, Sequence[str], None] = '85f15732fe53'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # GIN index on detections.matched_keywords for JSONB containment queries
    # Speeds up incident-to-detection queries that check: Detection.matched_keywords.contains([term])
    op.execute(
        "CREATE INDEX ix_detections_matched_keywords_gin "
        "ON detections USING gin (matched_keywords)"
    )

    # Composite index on severity_rules(enabled, priority DESC)
    # Speeds up score_severity() which filters by enabled=true and sorts by priority
    op.create_index(
        "ix_severity_rules_enabled_priority",
        "severity_rules",
        ["enabled", "priority"],
        postgresql_ops={"priority": "DESC"},
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_severity_rules_enabled_priority", "severity_rules")
    op.execute("DROP INDEX ix_detections_matched_keywords_gin")
