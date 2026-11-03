"""Waves and "Check more" (Q-F3, plan §7.3): the queue and the record of the deterministic wave
and of a person's request for one more check.

``investigation_checks``: one row per request, a queue and its result in one (like
``assessments``). The runtime role reads, adds and updates the state columns of rows; the web's
role (the "Check more" button's endpoint, Q-B3) reads rows and adds a ``queued`` request with the
columns a person's request has. Rows go with their investigation (``ON DELETE CASCADE``: the
retention purge and ``argus db regroup`` need no other handling).

Revision ID: 0039
Revises: 0038
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003).
RUNTIME_INSERT = (
    "investigation_id, version, kind, source, template, entity, requested_by, requested_at, status"
)
RUNTIME_UPDATE = "status, claims, lease_until, started_at, finished_at, outcome"
WEB_INSERT = "investigation_id, version, kind, source, template, entity, requested_by, requested_at"
# What the web's role gets (the doctor and the tests compare it with roles.API_GRANTS).
WEB_GRANTS = (f"GRANT SELECT, INSERT ({WEB_INSERT}) ON investigation_checks TO argus_web",)


def upgrade() -> None:
    op.create_table(
        "investigation_checks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("template", sa.Text(), server_default="", nullable=False),
        sa.Column("entity", sa.Text(), server_default="", nullable=False),
        sa.Column("requested_by", sa.Text(), nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.Text(), server_default="queued", nullable=False),
        sa.Column("claims", sa.Integer(), server_default="0", nullable=False),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(
            "kind IN ('wave', 'check')", name=op.f("ck_investigation_checks_kind_valid")
        ),
        sa.CheckConstraint(
            "source IN ('engine', 'person')", name=op.f("ck_investigation_checks_source_valid")
        ),
        sa.CheckConstraint(
            "status IN ('queued', 'running', 'done', 'refused', 'failed')",
            name=op.f("ck_investigation_checks_status_valid"),
        ),
        sa.CheckConstraint(
            "version >= 0 AND claims >= 0", name=op.f("ck_investigation_checks_non_negative")
        ),
        sa.CheckConstraint(
            "(kind = 'check') = (template <> '' AND entity <> '')",
            name=op.f("ck_investigation_checks_check_names_its_target"),
        ),
        sa.CheckConstraint(
            "template ~ '^([a-z][a-z0-9_.]{0,63})?$'",
            name=op.f("ck_investigation_checks_template_valid"),
        ),
        sa.CheckConstraint(
            "length(entity) <= 253 AND entity !~ '[[:cntrl:]]'",
            name=op.f("ck_investigation_checks_entity_valid"),
        ),
        sa.CheckConstraint(
            "(source = 'person') = (requested_by IS NOT NULL)",
            name=op.f("ck_investigation_checks_person_named"),
        ),
        sa.CheckConstraint(
            "kind <> 'check' OR source = 'person'",
            name=op.f("ck_investigation_checks_check_is_a_persons"),
        ),
        sa.CheckConstraint(
            "requested_by IS NULL OR length(requested_by) <= 120",
            name=op.f("ck_investigation_checks_by_short"),
        ),
        sa.CheckConstraint(
            "(status IN ('done', 'refused', 'failed')) = (finished_at IS NOT NULL)",
            name=op.f("ck_investigation_checks_finished_when_over"),
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR jsonb_typeof(outcome) = 'object'",
            name=op.f("ck_investigation_checks_outcome_is_object"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_investigation_checks_investigation_id_investigations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_investigation_checks")),
    )
    op.create_index(
        op.f("ix_investigation_checks_investigation_id"),
        "investigation_checks",
        ["investigation_id"],
    )
    op.create_index(
        op.f("ix_investigation_checks_status_requested_at"),
        "investigation_checks",
        ["status", "requested_at"],
    )
    op.create_index(
        "uq_investigation_checks_engine_wave",
        "investigation_checks",
        ["investigation_id", "version"],
        unique=True,
        postgresql_where=sa.text("kind = 'wave' AND source = 'engine'"),
    )
    op.create_index(
        "uq_investigation_checks_open",
        "investigation_checks",
        ["investigation_id", "kind", "template", "entity"],
        unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running')"),
    )
    op.execute(
        f"GRANT SELECT, INSERT ({RUNTIME_INSERT}), UPDATE ({RUNTIME_UPDATE})"
        " ON investigation_checks TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_table("investigation_checks")
