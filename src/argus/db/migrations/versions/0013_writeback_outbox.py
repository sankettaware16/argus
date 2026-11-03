"""The write-back outbox: planned alert status changes, sent at most once

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-13 15:30:38.325320
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "writeback_outbox",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("review_id", sa.BigInteger(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("alert_ids", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("state", sa.Text(), server_default="planned", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "state IN ('planned', 'sent', 'paused', 'skipped')",
            name=op.f("ck_writeback_outbox_state_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('acknowledged', 'closed')", name=op.f("ck_writeback_outbox_status_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_writeback_outbox")),
        sa.UniqueConstraint("review_id", name=op.f("uq_writeback_outbox_review_id")),
    )
    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (review_id, investigation_id, status, alert_ids), UPDATE (state,"
        " sent_at, error) ON writeback_outbox TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_table("writeback_outbox")
