"""Soak samples: hourly snapshots the soak test is judged from

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-13 15:22:42.683412
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "soak_samples",
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(metrics) = 'object'", name=op.f("ck_soak_samples_is_object")
        ),
        sa.PrimaryKeyConstraint("at", name=op.f("pk_soak_samples")),
    )
    # The role name is written out, not imported (see 0003).
    op.execute("GRANT SELECT, INSERT (at, metrics) ON soak_samples TO argus_runtime")


def downgrade() -> None:
    op.drop_table("soak_samples")
