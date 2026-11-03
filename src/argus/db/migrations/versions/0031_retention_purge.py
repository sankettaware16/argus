"""retention purge: the purge role's grants and the purge markers (Q-A4, D-028)

The purge empties an alert's raw ``_source`` after ``retention.raw_source`` and an evidence
snapshot ``retention.evidence`` after the investigation's newest review, and removes whole
investigations past ``memory.window`` (with the local model's shadow answers about them, 0028).
It runs as ``argus_purge`` (``argus db bootstrap`` makes the role): exactly the grants below,
so the audit trail and the case records stay out of its reach and it can never disable a
trigger. ``raw_purged_at`` and ``snapshot_purged_at`` say
when a value was removed; a check keeps a purged value empty, so nothing writes it back.

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003): argus.db.roles.PURGE_GRANTS lists the same, and doctor's
# test compares the two.
ROLE_CHECK = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_purge') THEN
        RAISE EXCEPTION 'role "argus_purge" does not exist'
            USING ERRCODE = 'undefined_object',
                  HINT = 'run "argus db bootstrap" first';
    END IF;
END
$$
"""
PURGE_GRANTS = (
    "GRANT SELECT, DELETE, UPDATE (raw, raw_purged_at) ON alert_records TO argus_purge",
    "GRANT SELECT, DELETE ON assessments TO argus_purge",
    "GRANT SELECT, INSERT (actor, action, outcome, target_type, target_id, correlation_id,"
    " details) ON audit_events TO argus_purge",
    "GRANT SELECT, DELETE ON dossiers TO argus_purge",
    "GRANT SELECT, DELETE, UPDATE (investigations) ON entities TO argus_purge",
    "GRANT SELECT, DELETE, UPDATE (snapshot, snapshot_purged_at) ON evidence TO argus_purge",
    "GRANT SELECT, DELETE ON evidence_requests TO argus_purge",
    "GRANT SELECT, DELETE ON investigation_alerts TO argus_purge",
    "GRANT SELECT, DELETE ON investigation_entities TO argus_purge",
    "GRANT SELECT, DELETE, UPDATE (continues_id) ON investigations TO argus_purge",
    "GRANT SELECT, DELETE ON jobs TO argus_purge",
    "GRANT SELECT, DELETE ON review_events TO argus_purge",
    "GRANT SELECT, DELETE ON review_state TO argus_purge",
    "GRANT SELECT, DELETE ON signals TO argus_purge",
    "GRANT SELECT, DELETE ON ti_lookups TO argus_purge",
    "GRANT SELECT, DELETE ON tuning_reports TO argus_purge",
    "GRANT SELECT, DELETE ON writeback_outbox TO argus_purge",
    "GRANT SELECT, DELETE ON llm_shadow TO argus_purge",
    "GRANT SELECT ON approval_requests TO argus_purge",
    "GRANT SELECT ON case_members TO argus_purge",
    "GRANT SELECT ON case_openings TO argus_purge",
    "GRANT SELECT ON cases TO argus_purge",
    "GRANT SELECT ON gold_items TO argus_purge",
)
TABLES = (
    "alert_records",
    "assessments",
    "audit_events",
    "dossiers",
    "entities",
    "evidence",
    "evidence_requests",
    "investigation_alerts",
    "investigation_entities",
    "investigations",
    "jobs",
    "review_events",
    "review_state",
    "signals",
    "ti_lookups",
    "tuning_reports",
    "writeback_outbox",
    "llm_shadow",
    "approval_requests",
    "case_members",
    "case_openings",
    "cases",
    "gold_items",
)


def upgrade() -> None:
    op.execute(ROLE_CHECK)
    op.add_column(
        "alert_records", sa.Column("raw_purged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_alert_records_purged_raw_is_empty"),
        "alert_records",
        "raw_purged_at IS NULL OR raw = '{}'::jsonb",
    )
    op.add_column(
        "evidence", sa.Column("snapshot_purged_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_evidence_purged_snapshot_is_empty"),
        "evidence",
        "snapshot_purged_at IS NULL OR snapshot IS NULL",
    )
    # What the purge deletes by and checks against at production size: each removed
    # investigation's foreign-key checks, and the links to it it clears.
    op.create_index(
        "ix_investigations_continues_id",
        "investigations",
        ["continues_id"],
        postgresql_where=sa.text("continues_id IS NOT NULL"),
    )
    op.create_index(op.f("ix_jobs_investigation_id"), "jobs", ["investigation_id"])
    op.create_index(op.f("ix_gold_items_investigation_id"), "gold_items", ["investigation_id"])
    for grant in PURGE_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    revoke = f"REVOKE ALL ON {', '.join(TABLES)} FROM argus_purge"
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_purge') THEN"
        f" {revoke}; END IF; END $$"
    )
    op.drop_index(op.f("ix_gold_items_investigation_id"), table_name="gold_items")
    op.drop_index(op.f("ix_jobs_investigation_id"), table_name="jobs")
    op.drop_index("ix_investigations_continues_id", table_name="investigations")
    op.drop_constraint(op.f("ck_evidence_purged_snapshot_is_empty"), "evidence", type_="check")
    op.drop_column("evidence", "snapshot_purged_at")
    op.drop_constraint(op.f("ck_alert_records_purged_raw_is_empty"), "alert_records", type_="check")
    op.drop_column("alert_records", "raw_purged_at")
