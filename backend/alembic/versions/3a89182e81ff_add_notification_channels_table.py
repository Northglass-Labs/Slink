"""add notification channels table

Revision ID: 3a89182e81ff
Revises: 7f79dd21646c
Create Date: 2026-04-11 15:47:35.130845

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = '3a89182e81ff'
down_revision: Union[str, Sequence[str], None] = '7f79dd21646c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Table may already exist from manual creation — skip if so
    conn = op.get_bind()
    inspector = inspect(conn)
    if "notification_channels" not in inspector.get_table_names():
        op.create_table(
            "notification_channels",
            sa.Column("channel_type", sa.String(50), primary_key=True),
            sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.text("true")),
            sa.Column("display_name", sa.String(100), nullable=False),
        )
    # Always try the seed (ON CONFLICT handles dupes)
    op.execute(
        "INSERT INTO notification_channels (channel_type, enabled, display_name) VALUES "
        "('pushover', true, 'Pushover'), "
        "('teams_env_webhook', true, 'Teams Webhook (.env)') "
        "ON CONFLICT (channel_type) DO NOTHING"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("notification_channels")
