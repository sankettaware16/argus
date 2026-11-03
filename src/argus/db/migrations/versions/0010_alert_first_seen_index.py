"""The incremental rules refresh (R9, D-057): an index on alert_records.first_seen_at, and
its cursor ('rules_refresh') in collector_cursors

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-13 14:19:29.072535
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        op.f("ix_alert_records_first_seen_at"), "alert_records", ["first_seen_at"], unique=False
    )
    op.drop_constraint(op.f("ck_collector_cursors_name_valid"), "collector_cursors", type_="check")
    op.create_check_constraint(
        op.f("ck_collector_cursors_name_valid"),
        "collector_cursors",
        "name IN ('live', 'backfill', 'rules_refresh')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM collector_cursors WHERE name = 'rules_refresh'")
    op.drop_constraint(op.f("ck_collector_cursors_name_valid"), "collector_cursors", type_="check")
    op.create_check_constraint(
        op.f("ck_collector_cursors_name_valid"), "collector_cursors", "name IN ('live', 'backfill')"
    )
    op.drop_index(op.f("ix_alert_records_first_seen_at"), table_name="alert_records")
