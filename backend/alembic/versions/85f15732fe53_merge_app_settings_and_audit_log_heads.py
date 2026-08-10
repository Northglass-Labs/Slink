"""merge app_settings and audit_log heads

Revision ID: 85f15732fe53
Revises: a1b2c3d4e5f6, b3c4d5e6f7a8
Create Date: 2026-04-12 13:25:47.845759

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '85f15732fe53'
down_revision: Union[str, Sequence[str], None] = ('a1b2c3d4e5f6', 'b3c4d5e6f7a8')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
