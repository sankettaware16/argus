"""ARGUS AI's reading of the engine's presented incidents (D-324)

``risk_readings``: one row per incident version and kind, ``story`` (tier 2: what happened, the
strongest case against it, one incident or two, next steps) or ``opinion`` (tier 3: a P1's second
opinion), with the claims that passed the checks, the model that wrote them, or why nothing is
shown. Text only: it never changes the queue. The runtime login writes them (insert only: a
reading is never changed); the web reads them for the incident's engine block.

Revision ID: 0104
Revises: 0101
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0104"
down_revision: str | None = "0101"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INSERT = "incident_id, version, kind, state, body, model, why, facts_sha, created_at"

WEB_GRANTS = ("GRANT SELECT ON risk_readings TO argus_web",)  # argus_web reads it


def upgrade() -> None:
    op.create_table(
        "risk_readings",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column(
            "body", postgresql.JSONB(astext_type=sa.Text()), server_default="{}", nullable=False
        ),
        sa.Column("model", sa.Text(), nullable=True),
        sa.Column("why", sa.Text(), nullable=True),
        sa.Column("facts_sha", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind IN ('story', 'opinion')", name=op.f("ck_risk_readings_kind_valid")
        ),
        sa.CheckConstraint(
            "state IN ('written', 'refused', 'failed')", name=op.f("ck_risk_readings_state_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(body) = 'object'", name=op.f("ck_risk_readings_body_is_object")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_risk_readings_version_valid")),
        sa.CheckConstraint(
            "why IS NULL OR char_length(why) <= 300", name=op.f("ck_risk_readings_why_length")
        ),
        sa.CheckConstraint(
            "model IS NULL OR char_length(model) <= 200",
            name=op.f("ck_risk_readings_model_length"),
        ),
        sa.CheckConstraint(
            "facts_sha ~ '^[0-9a-f]{64}$'", name=op.f("ck_risk_readings_facts_sha_valid")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_readings_incident_id_risk_incidents"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_readings")),
        sa.UniqueConstraint(
            "incident_id", "version", "kind", name=op.f("uq_risk_readings_incident_id_version_kind")
        ),
    )
    op.create_index(
        op.f("ix_risk_readings_kind_created_at"), "risk_readings", ["kind", "created_at"]
    )
    op.execute(f"GRANT SELECT, INSERT ({INSERT}) ON risk_readings TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_index(op.f("ix_risk_readings_kind_created_at"), table_name="risk_readings")
    op.drop_table("risk_readings")
