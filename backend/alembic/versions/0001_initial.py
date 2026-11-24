"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-24
"""

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    from app.db import Base
    from app import models  # noqa: F401

    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    from app.db import Base
    from app import models  # noqa: F401

    Base.metadata.drop_all(bind=op.get_bind())
