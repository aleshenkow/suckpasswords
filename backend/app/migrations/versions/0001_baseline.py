"""Baseline: create tables and apply legacy column additions (idempotent)

Revision ID: 0001
Revises:
"""

from alembic import op
from sqlalchemy import text

from app import models  # noqa: F401
from app.database import Base

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

LEGACY_COLUMNS = (
    "ALTER TABLE folders ADD COLUMN IF NOT EXISTS is_system BOOLEAN DEFAULT FALSE NOT NULL",
    "ALTER TABLE folders ADD COLUMN IF NOT EXISTS icon VARCHAR(32) DEFAULT '📁' NOT NULL",
    "ALTER TABLE entries ADD COLUMN IF NOT EXISTS level VARCHAR(32) DEFAULT 'general' NOT NULL",
    "ALTER TABLE entries ADD COLUMN IF NOT EXISTS created_by VARCHAR(128) DEFAULT '' NOT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER DEFAULT 0 NOT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP WITH TIME ZONE DEFAULT NULL",
    "ALTER TABLE smtp_config ADD COLUMN IF NOT EXISTS anonymous BOOLEAN DEFAULT FALSE NOT NULL",
)


def upgrade() -> None:
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    for stmt in LEGACY_COLUMNS:
        bind.execute(text(stmt))


def downgrade() -> None:
    pass
