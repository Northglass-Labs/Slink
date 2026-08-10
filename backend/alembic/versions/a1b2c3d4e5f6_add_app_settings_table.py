"""add app settings table

Revision ID: a1b2c3d4e5f6
Revises: f1a2b3c4d5e6
Create Date: 2026-04-10 15:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create app_settings table and seed retention_days."""
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=True),
    )
    op.execute(
        "INSERT INTO app_settings (key, value, description) VALUES "
        "('retention_days', '90', 'Days to keep detections before pruning') "
        "ON CONFLICT (key) DO NOTHING"
    )


def downgrade() -> None:
    """Drop app_settings table."""
    op.drop_table("app_settings")
