"""add severity rules table

Revision ID: f1a2b3c4d5e6
Revises: aeba0177b577
Create Date: 2026-04-10 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'aeba0177b577'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create severity_rules table and seed with current hardcoded rules."""
    op.create_table(
        "severity_rules",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("source_pattern", sa.String(100), nullable=True),
        sa.Column("keyword_category", sa.String(100), nullable=True),
        sa.Column("base_severity", sa.String(20), nullable=False),
        sa.Column("priority", sa.Integer, nullable=False, default=0),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
    )
    # Seed with current hardcoded rules from score_severity()
    op.execute("""
        INSERT INTO severity_rules (source_pattern, keyword_category, base_severity, priority, enabled) VALUES
        ('crowdstrike_recon', 'threat_actor', 'critical', 100, true),
        ('crowdstrike_recon', NULL, 'high', 90, true),
        ('crowdstrike_intel', NULL, 'high', 80, true),
        (NULL, 'threat_actor', 'high', 70, true),
        (NULL, NULL, 'medium', 0, true)
    """)


def downgrade() -> None:
    """Drop severity_rules table."""
    op.drop_table("severity_rules")
