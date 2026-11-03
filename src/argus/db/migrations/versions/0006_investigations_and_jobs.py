"""Investigations and jobs: grouping alerts, the entity index, the durable job queue

Investigations are derived from their alerts and recomputed, never deleted; the
runtime role may insert and update the columns that change.

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "entities",
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("investigations", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("kind", "value", name=op.f("pk_entities")),
    )
    op.create_table(
        "investigations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("grouping_version", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("rule_name", sa.Text(), nullable=True),
        sa.Column("group_key", sa.Text(), nullable=False),
        sa.Column("bucket_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_id", sa.UUID(), nullable=False),
        sa.Column("continues_id", sa.UUID(), nullable=True),
        sa.Column("alert_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("duplicate_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("first_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("risk_score", sa.Double(), nullable=True),
        sa.Column("version", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "alert_count >= 0 AND duplicate_count >= 0 AND version >= 0",
            name=op.f("ck_investigations_non_negative"),
        ),
        sa.CheckConstraint(
            "bucket_start < bucket_end", name=op.f("ck_investigations_bucket_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_investigations")),
    )
    op.create_index(
        op.f("ix_investigations_bucket_start"), "investigations", ["bucket_start"], unique=False
    )
    op.create_index(
        op.f("ix_investigations_previous_id"), "investigations", ["previous_id"], unique=False
    )
    op.create_index(
        op.f("ix_investigations_rule_id_bucket_start"),
        "investigations",
        ["rule_id", "bucket_start"],
        unique=False,
    )
    op.create_table(
        "investigation_alerts",
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("duplicate_of", sa.Text(), nullable=True),
        sa.Column("late_arrival", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "linked_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alert_records.alert_id"],
            name=op.f("fk_investigation_alerts_alert_id_alert_records"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_investigation_alerts_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_investigation_alerts")),
    )
    op.create_index(
        op.f("ix_investigation_alerts_investigation_id"),
        "investigation_alerts",
        ["investigation_id"],
        unique=False,
    )
    op.create_table(
        "investigation_entities",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_investigation_entities_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint(
            "investigation_id", "kind", "value", name=op.f("pk_investigation_entities")
        ),
    )
    op.create_index(
        op.f("ix_investigation_entities_kind_value"),
        "investigation_entities",
        ["kind", "value"],
        unique=False,
    )
    op.create_table(
        "jobs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("status", sa.Text(), server_default="queued", nullable=False),
        sa.Column("trigger", sa.Text(), nullable=False),
        sa.Column("run_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("claims", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_owner", sa.Text(), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("claimed_version", sa.Integer(), nullable=True),
        sa.Column("failures", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'done', 'failed')", name=op.f("ck_jobs_status_valid")
        ),
        sa.CheckConstraint("claims >= 0 AND failures >= 0", name=op.f("ck_jobs_non_negative")),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_jobs_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_jobs")),
    )
    op.create_index(op.f("ix_jobs_status_run_after"), "jobs", ["status", "run_after"], unique=False)
    op.create_index(
        "uq_jobs_active",
        "jobs",
        ["investigation_id"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (id, grouping_version, rule_id, group_key, bucket_start,"
        " bucket_end, previous_id), UPDATE (rule_name, continues_id, alert_count,"
        " duplicate_count, first_event_at, last_event_at, severity, risk_score, version,"
        " updated_at) ON investigations TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (alert_id, investigation_id, late_arrival), UPDATE (duplicate_of)"
        " ON investigation_alerts TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, kind, value) ON investigation_entities TO"
        " argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (kind, value, investigations), UPDATE (investigations) ON"
        " entities TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, trigger, run_after), UPDATE (status,"
        " run_after, claims, lease_owner, lease_until, claimed_version, failures, error,"
        " finished_at) ON jobs TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(
        "uq_jobs_active",
        table_name="jobs",
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.drop_index(op.f("ix_jobs_status_run_after"), table_name="jobs")
    op.drop_table("jobs")
    op.drop_index(op.f("ix_investigation_entities_kind_value"), table_name="investigation_entities")
    op.drop_table("investigation_entities")
    op.drop_index(
        op.f("ix_investigation_alerts_investigation_id"), table_name="investigation_alerts"
    )
    op.drop_table("investigation_alerts")
    op.drop_index(op.f("ix_investigations_rule_id_bucket_start"), table_name="investigations")
    op.drop_index(op.f("ix_investigations_previous_id"), table_name="investigations")
    op.drop_index(op.f("ix_investigations_bucket_start"), table_name="investigations")
    op.drop_table("investigations")
    op.drop_table("entities")
