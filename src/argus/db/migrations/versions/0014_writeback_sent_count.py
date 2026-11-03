"""The write-back outbox records the alerts sent of a row (R17 review: no alert sent twice)

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-13 16:10:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "writeback_outbox",
        sa.Column("sent_count", sa.Integer(), server_default="0", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_writeback_outbox_sent_count_in_range"),
        "writeback_outbox",
        "sent_count BETWEEN 0 AND cardinality(alert_ids)",
    )
    # The role name is written out, not imported (see 0003).
    op.execute("GRANT UPDATE (sent_count) ON writeback_outbox TO argus_runtime")


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_writeback_outbox_sent_count_in_range"), "writeback_outbox", type_="check"
    )
    op.drop_column("writeback_outbox", "sent_count")
