"""The health probe's readings, one row per probe, for the budget's re-measurement

Each probe's readings are stored as well as the resulting health memory, from what the probe
already read: no request is added. The runtime role appends; nothing updates or deletes a reading.

Revision ID: 0022
Revises: 0021
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from argus.db.siem_names import RENAME

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.create_table(
        "siem_probes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("reasons", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("probe_ok", sa.Boolean(), nullable=False),
        sa.Column("auth_failed", sa.Boolean(), nullable=False),
        sa.Column("disk_percent", sa.Double(), nullable=True),
        sa.Column("heap_percent", sa.Double(), nullable=True),
        sa.Column("load_1m", sa.Double(), nullable=True),
        sa.Column("search_queue", sa.BigInteger(), nullable=True),
        sa.Column("search_rejected", sa.BigInteger(), nullable=True),
        sa.Column("breakers_tripped", sa.BigInteger(), nullable=True),
        sa.Column("write_rejected", sa.BigInteger(), nullable=True),
        sa.Column("blocked_indices", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column(
            "ingest_lag_s",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("stale_rules", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(
            "state IN ('normal', 'caution', 'degraded', 'stop')",
            name=op.f("ck_siem_probes_state_valid"),
        ),
        sa.CheckConstraint(
            "(disk_percent IS NULL OR disk_percent BETWEEN 0 AND 100)"
            " AND (heap_percent IS NULL OR heap_percent BETWEEN 0 AND 100)"
            " AND (load_1m IS NULL OR load_1m >= 0)",
            name=op.f("ck_siem_probes_gauges_valid"),
        ),
        sa.CheckConstraint(
            "coalesce(search_queue, 0) >= 0 AND coalesce(search_rejected, 0) >= 0"
            " AND coalesce(breakers_tripped, 0) >= 0 AND coalesce(write_rejected, 0) >= 0"
            " AND coalesce(stale_rules, 0) >= 0",
            name=op.f("ck_siem_probes_counters_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(ingest_lag_s) = 'object'", name=op.f("ck_siem_probes_lag_is_object")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_probes")),
    )
    op.create_index(op.f("ix_siem_probes_at"), "siem_probes", ["at"], unique=False)
    # The role name is written out, not imported (see 0003). Append-only: no UPDATE, no DELETE.
    op.execute(
        "GRANT SELECT, INSERT (at, state, reasons, probe_ok, auth_failed, disk_percent,"
        " heap_percent, load_1m, search_queue, search_rejected, breakers_tripped,"
        " write_rejected, blocked_indices, ingest_lag_s, stale_rules) ON siem_probes"
        " TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_siem_probes_at"), table_name="siem_probes")
    op.drop_table("siem_probes")
