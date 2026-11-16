"""The incident engine's own evidence for its outbound incidents (D-323)

``risk_evidence``: what the checking lane found for an engine incident's material version, one
row per check: a device's timing to an outside address (``pair``), how many campus devices
reached that address in a day (``contact``) and a device's lookups (``dns``), with its verdict
and facts; ``took_ms`` empty when no request was made (an answer reused, or ARGUS's own alerts
say the address is too common to ask about). Kept 180 days. The presenter reads it into an
incident's checks and alternatives; the engine reads it as signals of the alert groups.

The runtime role inserts, reads and prunes the rows, and replaces an unknown answer.

Revision ID: 0101
Revises: 0097
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0101"
down_revision: str | None = "0097"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = ("pair", "contact", "dns")
VERDICTS = (
    "regular", "irregular", "few", "none", "common", "some", "rare", "tunnel", "plain", "unknown",
)  # fmt: skip
SUBJECT = (
    "char_length(subject) >= 2 AND char_length(subject) <= 100"
    " AND (device IS NULL OR char_length(device) <= 45)"
    " AND (destination IS NULL OR char_length(destination) <= 45)"
    " AND (kind = 'contact' OR device IS NOT NULL)"
    " AND (kind = 'dns' OR destination IS NOT NULL)"
)
INSERT = (
    "incident_id, incident_version, kind, subject, device, destination, day, template,"
    " template_version, task_key, verdict, facts, took_ms, checked_at"
)
UPDATE = (
    "device, destination, day, template, template_version, task_key, verdict, facts, took_ms,"
    " checked_at"
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "risk_evidence",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("incident_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("device", sa.Text(), nullable=True),
        sa.Column("destination", sa.Text(), nullable=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("task_key", sa.Text(), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("took_ms", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_risk_evidence_kind_valid")),
        sa.CheckConstraint(_in("verdict", VERDICTS), name=op.f("ck_risk_evidence_verdict_valid")),
        sa.CheckConstraint(SUBJECT, name=op.f("ck_risk_evidence_subject_valid")),
        sa.CheckConstraint("incident_version >= 1", name=op.f("ck_risk_evidence_version_valid")),
        sa.CheckConstraint(
            "task_key IS NULL OR task_key ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_risk_evidence_task_key_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(facts) = 'object' AND octet_length(facts::text) <= 65536",
            name=op.f("ck_risk_evidence_facts_valid"),
        ),
        sa.CheckConstraint(
            "took_ms IS NULL OR took_ms >= 0", name=op.f("ck_risk_evidence_took_valid")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["risk_incidents.id"],
            name=op.f("fk_risk_evidence_incident_id_risk_incidents"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_evidence")),
        sa.UniqueConstraint(
            "incident_id",
            "incident_version",
            "kind",
            "subject",
            name=op.f("uq_risk_evidence_incident_id_incident_version_kind_subject"),
        ),
    )
    op.create_index(op.f("ix_risk_evidence_checked_at"), "risk_evidence", ["checked_at"])
    op.create_index(op.f("ix_risk_evidence_device_day"), "risk_evidence", ["device", "day"])
    op.create_index(
        op.f("ix_risk_evidence_destination_day"), "risk_evidence", ["destination", "day"]
    )
    # The role names are written out, not imported (see 0003).
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({INSERT}), UPDATE ({UPDATE}) ON risk_evidence"
        " TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_table("risk_evidence")
