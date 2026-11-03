"""Context graph: evidence, dossiers, signals, deferred jobs, LangGraph's checkpoint tables

R8 (D-054). Evidence rows are written by the graph's evidence node and may be retried (not
for ok/empty rows); dossiers and signals are written once per investigation version. The
checkpoint tables live in their own schema, ``langgraph``: a frozen copy of the DDL of
``langgraph-checkpoint-postgres`` 3.1 (its migrations 0-9; ``CONCURRENTLY`` dropped, as the
tables are new and empty), recorded in its ``checkpoint_migrations`` table so that the saver
sees itself as set up. ``tests/unit/context/test_checkpoint_ddl.py`` compares it with the
installed package.

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CHECKPOINT_SCHEMA = "langgraph"
# The saver's MIGRATIONS list, in order; the position is the version it records.
CHECKPOINT_DDL = (
    "CREATE TABLE IF NOT EXISTS checkpoint_migrations (v INTEGER PRIMARY KEY)",
    "CREATE TABLE IF NOT EXISTS checkpoints (thread_id TEXT NOT NULL, checkpoint_ns TEXT NOT NULL"
    " DEFAULT '', checkpoint_id TEXT NOT NULL, parent_checkpoint_id TEXT, type TEXT, checkpoint"
    " JSONB NOT NULL, metadata JSONB NOT NULL DEFAULT '{}', PRIMARY KEY (thread_id,"
    " checkpoint_ns, checkpoint_id))",
    "CREATE TABLE IF NOT EXISTS checkpoint_blobs (thread_id TEXT NOT NULL, checkpoint_ns TEXT"
    " NOT NULL DEFAULT '', channel TEXT NOT NULL, version TEXT NOT NULL, type TEXT NOT NULL,"
    " blob BYTEA, PRIMARY KEY (thread_id, checkpoint_ns, channel, version))",
    "CREATE TABLE IF NOT EXISTS checkpoint_writes (thread_id TEXT NOT NULL, checkpoint_ns TEXT"
    " NOT NULL DEFAULT '', checkpoint_id TEXT NOT NULL, task_id TEXT NOT NULL, idx INTEGER NOT"
    " NULL, channel TEXT NOT NULL, type TEXT, blob BYTEA NOT NULL, PRIMARY KEY (thread_id,"
    " checkpoint_ns, checkpoint_id, task_id, idx))",
    "ALTER TABLE checkpoint_blobs ALTER COLUMN blob DROP not null",
    "SELECT 1",
    "CREATE INDEX IF NOT EXISTS checkpoints_thread_id_idx ON checkpoints(thread_id)",
    "CREATE INDEX IF NOT EXISTS checkpoint_blobs_thread_id_idx ON checkpoint_blobs(thread_id)",
    "CREATE INDEX IF NOT EXISTS checkpoint_writes_thread_id_idx ON checkpoint_writes(thread_id)",
    "ALTER TABLE checkpoint_writes ADD COLUMN IF NOT EXISTS task_path TEXT NOT NULL DEFAULT ''",
)


def upgrade() -> None:
    op.create_table(
        "dossiers",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("facts_version", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.BigInteger(), nullable=False),
        sa.Column("run_kind", sa.Text(), nullable=False),
        sa.Column("family", sa.Text(), nullable=False),
        sa.Column("pack", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("partial_reason", sa.Text(), nullable=True),
        sa.Column("dossier_hash", sa.Text(), nullable=False),
        sa.Column("body", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("dossier_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_dossiers_hash_valid")),
        sa.CheckConstraint(
            "jsonb_typeof(body) = 'object'", name=op.f("ck_dossiers_body_is_object")
        ),
        sa.CheckConstraint(
            "run_kind IN ('collect', 'rederive')", name=op.f("ck_dossiers_run_kind_valid")
        ),
        sa.CheckConstraint(
            "status IN ('evidence_ready', 'evidence_partial', 'evidence_failed')",
            name=op.f("ck_dossiers_status_valid"),
        ),
        sa.CheckConstraint(
            "facts_version >= version", name=op.f("ck_dossiers_facts_version_valid")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_dossiers_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("investigation_id", "version", name=op.f("pk_dossiers")),
    )
    op.create_table(
        "evidence",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("task_key", sa.Text(), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("params", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("coverage", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("source_watermark", sa.DateTime(timezone=True), nullable=True),
        sa.Column("row_count", sa.Integer(), nullable=True),
        sa.Column("truncated", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("result_hash", sa.Text(), nullable=True),
        sa.Column("took_ms", sa.Integer(), nullable=True),
        sa.Column("reused_from_version", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "(status IN ('ok', 'empty')) = (result_hash IS NOT NULL)",
            name=op.f("ck_evidence_result_hash"),
        ),
        sa.CheckConstraint(
            "status IN ('ok', 'empty', 'failed', 'timeout', 'skipped_budget', 'deferred',"
            " 'source_lag', 'source_expired', 'unsupported_value')",
            name=op.f("ck_evidence_status_valid"),
        ),
        sa.CheckConstraint("task_key ~ '^[0-9a-f]{64}$'", name=op.f("ck_evidence_task_key_valid")),
        sa.CheckConstraint(
            "row_count IS NULL OR row_count >= 0", name=op.f("ck_evidence_row_count_valid")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_evidence_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint(
            "investigation_id", "version", "task_key", name=op.f("pk_evidence")
        ),
    )
    op.create_index(
        op.f("ix_evidence_investigation_id_task_key"),
        "evidence",
        ["investigation_id", "task_key"],
        unique=False,
    )
    op.create_table(
        "signals",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("unknown_reason", sa.Text(), nullable=True),
        sa.Column("completeness", sa.Text(), nullable=False),
        sa.Column("evidence", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("definition_version", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "(status = 'known') = (value IS NOT NULL AND unknown_reason IS NULL)",
            name=op.f("ck_signals_known_has_value"),
        ),
        sa.CheckConstraint(
            "completeness IN ('exact', 'lower_bound', 'upper_bound', 'approximate')",
            name=op.f("ck_signals_completeness_valid"),
        ),
        sa.CheckConstraint("status IN ('known', 'unknown')", name=op.f("ck_signals_status_valid")),
        sa.ForeignKeyConstraint(
            ["investigation_id", "version"],
            ["dossiers.investigation_id", "dossiers.version"],
            name=op.f("fk_signals_investigation_id_version_dossiers"),
        ),
        sa.PrimaryKeyConstraint("investigation_id", "version", "name", name=op.f("pk_signals")),
    )
    op.add_column("jobs", sa.Column("deferred_since", sa.DateTime(timezone=True), nullable=True))
    op.add_column("jobs", sa.Column("deferrals", sa.Integer(), server_default="0", nullable=False))
    op.drop_constraint(op.f("ck_jobs_non_negative"), "jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_jobs_non_negative"), "jobs", "claims >= 0 AND failures >= 0 AND deferrals >= 0"
    )

    op.execute(f"CREATE SCHEMA {CHECKPOINT_SCHEMA}")
    op.execute(f"SET LOCAL search_path = {CHECKPOINT_SCHEMA}")
    for statement in CHECKPOINT_DDL:
        op.execute(statement)
    op.execute(
        "INSERT INTO checkpoint_migrations (v) SELECT generate_series(0, "
        f"{len(CHECKPOINT_DDL) - 1})"
    )
    op.execute("SET LOCAL search_path = public, pg_temp")

    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, version, task_key, template, template_version,"
        " params, status, coverage, source_watermark, row_count, truncated, snapshot,"
        " result_hash, took_ms, reused_from_version, error, collected_at), UPDATE (template,"
        " template_version, params, status, coverage, source_watermark, row_count, truncated,"
        " snapshot, result_hash, took_ms, reused_from_version, error, collected_at)"
        " ON evidence TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, version, facts_version, job_id, run_kind,"
        " family, pack, status, partial_reason, dossier_hash, body, evidence_count, created_at)"
        " ON dossiers TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, version, name, value, status, unknown_reason,"
        " completeness, evidence, definition_version) ON signals TO argus_runtime"
    )
    op.execute("GRANT UPDATE (deferred_since, deferrals) ON jobs TO argus_runtime")
    op.execute(f"GRANT USAGE ON SCHEMA {CHECKPOINT_SCHEMA} TO argus_runtime")
    op.execute(f"GRANT SELECT ON {CHECKPOINT_SCHEMA}.checkpoint_migrations TO argus_runtime")
    op.execute(
        "GRANT SELECT, DELETE, INSERT (thread_id, checkpoint_ns, checkpoint_id,"
        " parent_checkpoint_id, checkpoint, metadata), UPDATE (checkpoint, metadata)"
        f" ON {CHECKPOINT_SCHEMA}.checkpoints TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, DELETE, INSERT (thread_id, checkpoint_ns, channel, version, type, blob)"
        f" ON {CHECKPOINT_SCHEMA}.checkpoint_blobs TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, DELETE, INSERT (thread_id, checkpoint_ns, checkpoint_id, task_id,"
        " idx, channel, type, blob, task_path), UPDATE (channel, type, blob)"
        f" ON {CHECKPOINT_SCHEMA}.checkpoint_writes TO argus_runtime"
    )


def downgrade() -> None:
    op.execute(f"DROP SCHEMA {CHECKPOINT_SCHEMA} CASCADE")
    op.drop_constraint(op.f("ck_jobs_non_negative"), "jobs", type_="check")
    op.create_check_constraint(
        op.f("ck_jobs_non_negative"), "jobs", "claims >= 0 AND failures >= 0"
    )
    op.drop_column("jobs", "deferrals")
    op.drop_column("jobs", "deferred_since")
    op.drop_table("signals")
    op.drop_index(op.f("ix_evidence_investigation_id_task_key"), table_name="evidence")
    op.drop_table("evidence")
    op.drop_table("dossiers")
