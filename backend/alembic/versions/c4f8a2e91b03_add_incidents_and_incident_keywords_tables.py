"""add incidents and incident_keywords tables

Revision ID: c4f8a2e91b03
Revises: aeba0177b577
Create Date: 2026-04-10 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c4f8a2e91b03"
down_revision: Union[str, Sequence[str], None] = "aeba0177b577"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create incidents and incident_keywords tables."""
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "incident_keywords",
        sa.Column("incident_id", sa.Integer, sa.ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("keyword_id", sa.Integer, sa.ForeignKey("keywords.id", ondelete="CASCADE"), primary_key=True),
    )


def downgrade() -> None:
    """Drop incidents and incident_keywords tables."""
    op.drop_table("incident_keywords")
    op.drop_table("incidents")
