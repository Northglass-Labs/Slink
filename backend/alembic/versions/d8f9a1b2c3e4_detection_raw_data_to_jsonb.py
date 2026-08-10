"""convert detections.raw_data from JSON to JSONB

Revision ID: d8f9a1b2c3e4
Revises: c9a8b7d6e5f4
Create Date: 2026-04-19 00:00:00.000000

JSON stores the row as text and re-parses on every read. JSONB uses a
binary representation that supports containment operators (@>) and
indexes. Same on-disk semantics, better query ergonomics going forward.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "d8f9a1b2c3e4"
down_revision: Union[str, Sequence[str], None] = "c9a8b7d6e5f4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TABLE detections ALTER COLUMN raw_data TYPE jsonb USING raw_data::jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE detections ALTER COLUMN raw_data TYPE json USING raw_data::json")
