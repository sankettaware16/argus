"""The incident report (AR7, D-190): ARGUS writes, for each suggested or open case, the report the
security team writes by hand, and a person confirms or rejects it.

* ``incident_reports``: one row for each version of a case's report. The report is a structured
  object (``body``, ``incident-report@1``), written whole by ARGUS's assessment pass or the
  terminal and **never changed**: when the case's evidence changes ARGUS writes the next version
  (``version`` 1, 2, ...), and the versions are kept. ``content_hash`` is the hash of what the
  report says (without when it was made and without a model's wording), so the same evidence
  gives the same hash. ``generated_at`` is the database's clock. Append-only (the owner's
  trigger, like the case events).
* ``incident_report_decisions``: what a person said about a version: ``confirmed`` or
  ``rejected`` with a reason and the outcome they hold instead. The labels that follow (reviews of
  the case's investigations, through the existing review path) are named in ``review_ids``.
  Append-only; the newest decision of a version counts, and an earlier one stays as the record.
  Confirming never closes anything.
* ``incident_report_checks``: one row for each case ARGUS looked at: the cheap signal of the
  evidence it saw (a case is read again only when it changes), when, which report that was, and
  the last failure (a failed report is reported and never stops the pass).

``argus_runtime`` writes the reports and the checks (and a decision, for the terminal); the web's
role reads all three and writes a person's decision (the reviews it records go through its existing
grants on ``review_events``). Downgrading is refused while a decision exists: a label was written
from it.

The role names are written out, not imported (see 0003).

Revision ID: 0052
Revises: 0051
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0052"
down_revision: str | None = "0051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OUTCOMES = (
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive",
)  # fmt: skip
DECISIONS = ("confirmed", "rejected")
REPORT_INSERT = (
    "case_id, version, schema_version, writer, content_hash, case_version, verdict_outcome,"
    " verdict_confidence, body, prose, prose_by, generated_by, as_at"
)
DECISION_INSERT = "report_id, decision, outcome, reason, by_user_id, review_ids"
CHECK_INSERT = "case_id, signal, checked_at, report_id, failure, failed_at"
CHECK_UPDATE = "signal, checked_at, report_id, failure, failed_at"


# what the web's login reads and records (a person's confirm or reject)
WEB_GRANTS = (
    "GRANT SELECT ON incident_reports, incident_report_checks TO argus_web",
    f"GRANT SELECT, INSERT ({DECISION_INSERT}) ON incident_report_decisions TO argus_web",
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "incident_reports",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("schema_version", sa.Text(), nullable=False),
        sa.Column("writer", sa.Text(), nullable=False),
        sa.Column("content_hash", sa.Text(), nullable=False),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column("verdict_outcome", sa.Text(), nullable=True),
        sa.Column("verdict_confidence", sa.Float(), nullable=True),
        sa.Column("body", postgresql.JSONB(), nullable=False),
        sa.Column("prose", sa.Boolean(), server_default=sa.text("false"), nullable=False),
        sa.Column("prose_by", sa.Text(), nullable=True),
        sa.Column("generated_by", sa.Text(), server_default="argus:incident", nullable=False),
        sa.Column("as_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_incident_reports_version_valid")),
        sa.CheckConstraint(
            "schema_version = 'incident-report@1'", name=op.f("ck_incident_reports_schema_valid")
        ),
        sa.CheckConstraint(
            "content_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_incident_reports_hash_valid")
        ),
        sa.CheckConstraint(
            f"verdict_outcome IS NULL OR {_in('verdict_outcome', OUTCOMES)}",
            name=op.f("ck_incident_reports_outcome_valid"),
        ),
        sa.CheckConstraint(
            "verdict_confidence IS NULL OR (verdict_confidence >= 0 AND verdict_confidence <= 1)",
            name=op.f("ck_incident_reports_confidence_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(body) = 'object'", name=op.f("ck_incident_reports_body_is_object")
        ),
        sa.CheckConstraint(
            "prose = (prose_by IS NOT NULL)", name=op.f("ck_incident_reports_prose_complete")
        ),
        sa.CheckConstraint(
            "case_version >= 1", name=op.f("ck_incident_reports_case_version_valid")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_incident_reports_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_reports")),
        sa.UniqueConstraint("case_id", "version", name=op.f("uq_incident_reports_case_id_version")),
    )
    op.create_index(
        op.f("ix_incident_reports_case_id_generated_at"),
        "incident_reports",
        ["case_id", "generated_at"],
    )
    op.execute(
        "CREATE TRIGGER incident_reports_append_only_rows BEFORE UPDATE OR DELETE"
        " ON incident_reports FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER incident_reports_append_only_truncate BEFORE TRUNCATE ON incident_reports"
        " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    op.execute(
        "ALTER TABLE incident_reports ENABLE ALWAYS TRIGGER incident_reports_append_only_rows"
    )
    op.execute(
        "ALTER TABLE incident_reports ENABLE ALWAYS TRIGGER incident_reports_append_only_truncate"
    )

    op.create_table(
        "incident_report_decisions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("report_id", sa.BigInteger(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("by_user_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "review_ids",
            postgresql.ARRAY(sa.BigInteger()),
            server_default=sa.text("'{}'::bigint[]"),
            nullable=False,
        ),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _in("decision", DECISIONS), name=op.f("ck_incident_report_decisions_decision_valid")
        ),
        sa.CheckConstraint(
            f"outcome IS NULL OR {_in('outcome', OUTCOMES)}",
            name=op.f("ck_incident_report_decisions_outcome_valid"),
        ),
        sa.CheckConstraint(
            "(decision = 'rejected') = (reason IS NOT NULL AND outcome IS NOT NULL)",
            name=op.f("ck_incident_report_decisions_rejection_complete"),
        ),
        sa.CheckConstraint(
            "reason IS NULL OR length(btrim(reason)) BETWEEN 3 AND 4000",
            name=op.f("ck_incident_report_decisions_reason_length"),
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["incident_reports.id"],
            name=op.f("fk_incident_report_decisions_report_id_incident_reports"),
        ),
        sa.ForeignKeyConstraint(
            ["by_user_id"],
            ["users.id"],
            name=op.f("fk_incident_report_decisions_by_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_incident_report_decisions")),
    )
    op.create_index(
        op.f("ix_incident_report_decisions_report_id_decided_at"),
        "incident_report_decisions",
        ["report_id", "decided_at"],
    )
    op.execute(
        "CREATE TRIGGER incident_report_decisions_append_only_rows BEFORE UPDATE OR DELETE"
        " ON incident_report_decisions FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER incident_report_decisions_append_only_truncate BEFORE TRUNCATE"
        " ON incident_report_decisions FOR EACH STATEMENT"
        " EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    op.execute(
        "ALTER TABLE incident_report_decisions ENABLE ALWAYS TRIGGER"
        " incident_report_decisions_append_only_rows"
    )
    op.execute(
        "ALTER TABLE incident_report_decisions ENABLE ALWAYS TRIGGER"
        " incident_report_decisions_append_only_truncate"
    )

    op.create_table(
        "incident_report_checks",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("signal", sa.Text(), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("report_id", sa.BigInteger(), nullable=True),
        sa.Column("failure", sa.Text(), nullable=True),
        sa.Column("failed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "failure IS NULL OR length(failure) <= 500",
            name=op.f("ck_incident_report_checks_failure_length"),
        ),
        sa.CheckConstraint(
            "(failure IS NULL) = (failed_at IS NULL)",
            name=op.f("ck_incident_report_checks_failure_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_incident_report_checks_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["incident_reports.id"],
            name=op.f("fk_incident_report_checks_report_id_incident_reports"),
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_incident_report_checks")),
    )
    op.create_index(
        op.f("ix_incident_report_checks_checked_at"), "incident_report_checks", ["checked_at"]
    )

    op.execute(f"GRANT SELECT, INSERT ({REPORT_INSERT}) ON incident_reports TO argus_runtime")
    op.execute(
        f"GRANT SELECT, INSERT ({DECISION_INSERT}) ON incident_report_decisions TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({CHECK_INSERT}), UPDATE ({CHECK_UPDATE})"
        " ON incident_report_checks TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM incident_report_decisions) THEN
                RAISE EXCEPTION 'people confirmed or rejected incident reports: labels were'
                    ' written from them'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.drop_table("incident_report_checks")
    op.drop_table("incident_report_decisions")
    op.drop_index(op.f("ix_incident_reports_case_id_generated_at"), table_name="incident_reports")
    op.drop_table("incident_reports")
