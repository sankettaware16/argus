"""Elastic Gateway state: kill switches, shared state machines, request ledger, live sessions

R4 (D-048). Separate ARGUS processes share one budget, one breaker and one health memory
through ``siem_state`` (row-locked read-modify-write). The runtime role may update only the
columns that change; the ledger is append-only for it (no UPDATE, no DELETE).

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "siem_switches",
        sa.Column("component", sa.Text(), nullable=False),
        sa.Column("stopped", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "changed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("changed_by", sa.Text(), server_default="migration", nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "component IN ('global', 'collector', 'enrichment', 'kibana', 'writeback')",
            name=op.f("ck_siem_switches_component_valid"),
        ),
        sa.PrimaryKeyConstraint("component", name=op.f("pk_siem_switches")),
    )
    op.execute(
        "INSERT INTO siem_switches (component) VALUES"
        " ('global'), ('collector'), ('enrichment'), ('kibana'), ('writeback')"
    )
    op.create_table(
        "siem_state",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column(
            "state", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "name IN ('health', 'budget', 'breaker')", name=op.f("ck_siem_state_name_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(state) = 'object'", name=op.f("ck_siem_state_state_is_object")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_siem_state")),
    )
    op.execute("INSERT INTO siem_state (name) VALUES ('health'), ('budget'), ('breaker')")
    op.create_table(
        "siem_requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("component", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("indices", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("took_ms", sa.Integer(), nullable=False),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.Integer(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("live_session", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "took_ms >= 0 AND elapsed_ms >= 0 AND response_bytes >= 0",
            name=op.f("ck_siem_requests_non_negative"),
        ),
        sa.CheckConstraint(
            "attempts BETWEEN 1 AND 2", name=op.f("ck_siem_requests_attempts_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_requests")),
    )
    op.create_index(op.f("ix_siem_requests_at"), "siem_requests", ["at"])
    op.create_index(op.f("ix_siem_requests_live_session"), "siem_requests", ["live_session"])
    op.create_table(
        "siem_live_sessions",
        sa.Column("id", sa.Text(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("ends_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_requests", sa.Integer(), nullable=False),
        sa.Column("used", sa.Integer(), server_default="0", nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "max_requests BETWEEN 1 AND 50",
            name=op.f("ck_siem_live_sessions_max_requests_valid"),
        ),
        sa.CheckConstraint(
            "used >= 0 AND used <= max_requests", name=op.f("ck_siem_live_sessions_used_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_siem_live_sessions")),
    )
    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, UPDATE (stopped, changed_at, changed_by, reason)"
        " ON siem_switches TO argus_runtime"
    )
    op.execute("GRANT SELECT, UPDATE (state, updated_at) ON siem_state TO argus_runtime")
    op.execute(
        "GRANT SELECT, INSERT (at, component, purpose, template, version, indices, outcome,"
        " http_status, took_ms, elapsed_ms, response_bytes, attempts, live_session)"
        " ON siem_requests TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (id, created_by, ends_at, max_requests),"
        " UPDATE (used, ended_at) ON siem_live_sessions TO argus_runtime"
    )


def downgrade() -> None:
    # Dropping a table drops its grants.
    op.drop_table("siem_live_sessions")
    op.drop_index(op.f("ix_siem_requests_live_session"), table_name="siem_requests")
    op.drop_index(op.f("ix_siem_requests_at"), table_name="siem_requests")
    op.drop_table("siem_requests")
    op.drop_table("siem_state")
    op.drop_table("siem_switches")
