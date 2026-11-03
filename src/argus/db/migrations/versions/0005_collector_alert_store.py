"""Collector alert store: alert records, cursors, reconciliation runs, coverage gaps

Alerts are never deleted (one gone from the SIEM gets ``source_missing_at``), so the
runtime role may insert and update the columns that change, never delete. Reconciliation runs
are append-only for it.

Revision ID: 0005
Revises: 0004
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "alert_records",
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("index", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("quarantine_field", sa.Text(), nullable=True),
        sa.Column("normalizer_version", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_time", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fingerprint", sa.Text(), nullable=True),
        sa.Column("workflow_status", sa.Text(), nullable=True),
        sa.Column("raw", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("normalized", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("state_hash", sa.Text(), nullable=False),
        sa.Column("recovered_by", sa.Text(), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("source_missing_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(status = 'quarantined') = (quarantine_reason IS NOT NULL)",
            name=op.f("ck_alert_records_quarantine_reason"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(raw) = 'object'", name=op.f("ck_alert_records_raw_is_object")
        ),
        sa.CheckConstraint(
            "recovered_by IN ('live', 'backfill', 'reconciliation')",
            name=op.f("ck_alert_records_recovered_by_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('normalized', 'quarantined')", name=op.f("ck_alert_records_status_valid")
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_alert_records")),
    )
    op.create_index(
        op.f("ix_alert_records_detected_at"), "alert_records", ["detected_at"], unique=False
    )
    op.create_index(
        op.f("ix_alert_records_fingerprint"), "alert_records", ["fingerprint"], unique=False
    )
    op.create_index(
        op.f("ix_alert_records_rule_id_event_time"),
        "alert_records",
        ["rule_id", "event_time"],
        unique=False,
    )
    op.create_table(
        "collector_cursors",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "name IN ('live', 'backfill')", name=op.f("ck_collector_cursors_name_valid")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_collector_cursors")),
    )
    op.create_table(
        "coverage_gaps",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("start_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "kind IN ('rule_not_running', 'rule_gap_reported', 'source_stalled',"
            " 'late_data_beyond_lookback', 'truncated_execution', 'argus_collector_lag',"
            " 'breaker_open')",
            name=op.f("ck_coverage_gaps_kind_valid"),
        ),
        sa.CheckConstraint(
            "end_at IS NULL OR end_at >= start_at", name=op.f("ck_coverage_gaps_range_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_coverage_gaps")),
    )
    op.create_index(op.f("ix_coverage_gaps_start_at"), "coverage_gaps", ["start_at"], unique=False)
    op.create_index(
        "uq_coverage_gaps_open",
        "coverage_gaps",
        ["kind", "subject"],
        unique=True,
        postgresql_where=sa.text("end_at IS NULL"),
    )
    op.create_table(
        "reconciliation_runs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hours", sa.Integer(), nullable=False),
        sa.Column("hours_mismatched", sa.Integer(), nullable=False),
        sa.Column("recovered", sa.Integer(), nullable=False),
        sa.Column("missing_in_es", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.CheckConstraint(
            "hours >= 0 AND hours_mismatched >= 0 AND recovered >= 0 AND missing_in_es >= 0",
            name=op.f("ck_reconciliation_runs_non_negative"),
        ),
        sa.CheckConstraint(
            "window_start < window_end", name=op.f("ck_reconciliation_runs_window_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reconciliation_runs")),
    )
    op.create_index(
        op.f("ix_reconciliation_runs_finished_at"),
        "reconciliation_runs",
        ["finished_at"],
        unique=False,
    )
    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (alert_id, index, status, quarantine_reason, quarantine_field,"
        " normalizer_version, rule_id, detected_at, event_time, fingerprint, workflow_status,"
        " raw, normalized, content_hash, state_hash, recovered_by),"
        " UPDATE (index, status, quarantine_reason, quarantine_field, normalizer_version,"
        " rule_id, detected_at, event_time, fingerprint, workflow_status, raw, normalized,"
        " content_hash, state_hash, last_seen_at, source_missing_at)"
        " ON alert_records TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (name, at), UPDATE (at, updated_at) ON collector_cursors"
        " TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (started_at, finished_at, window_start, window_end, hours,"
        " hours_mismatched, recovered, missing_in_es, outcome) ON reconciliation_runs"
        " TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (kind, subject, start_at, detail), UPDATE (end_at, detail)"
        " ON coverage_gaps TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_reconciliation_runs_finished_at"), table_name="reconciliation_runs")
    op.drop_table("reconciliation_runs")
    op.drop_index(
        "uq_coverage_gaps_open",
        table_name="coverage_gaps",
        postgresql_where=sa.text("end_at IS NULL"),
    )
    op.drop_index(op.f("ix_coverage_gaps_start_at"), table_name="coverage_gaps")
    op.drop_table("coverage_gaps")
    op.drop_table("collector_cursors")
    op.drop_index(op.f("ix_alert_records_rule_id_event_time"), table_name="alert_records")
    op.drop_index(op.f("ix_alert_records_fingerprint"), table_name="alert_records")
    op.drop_index(op.f("ix_alert_records_detected_at"), table_name="alert_records")
    op.drop_table("alert_records")
