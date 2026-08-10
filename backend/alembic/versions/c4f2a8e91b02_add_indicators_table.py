"""add indicators table

Revision ID: c4f2a8e91b02
Revises: aeba0177b577
Create Date: 2026-04-10 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c4f2a8e91b02'
down_revision: Union[str, Sequence[str], None] = ('f1a2b3c4d5e6', 'c4f8a2e91b03')
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'indicators',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('detection_id', sa.Integer(), nullable=False),
        sa.Column('type', sa.String(length=50), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['detection_id'], ['detections.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('detection_id', 'type', 'value', name='uq_indicator_detection_type_value'),
    )
    op.create_index('ix_indicators_detection_id', 'indicators', ['detection_id'])
    op.create_index('ix_indicator_type_value', 'indicators', ['type', 'value'])


def downgrade() -> None:
    op.drop_index('ix_indicator_type_value', table_name='indicators')
    op.drop_index('ix_indicators_detection_id', table_name='indicators')
    op.drop_table('indicators')
