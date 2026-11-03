"""the web's own login: the group role argus_web gets exactly what the web needs

The web logs in as ``argus_api`` (a member of ``argus_web``, made by ``argus db bootstrap``) once
``web.database_role`` is ``api``. The role reads what the pages show and writes sessions, reviews,
gold answers, requested assessments and audit events, nothing else (``argus.db.roles.API_GRANTS``,
checked by ``argus doctor``). A review locks its investigation's row, which needs UPDATE on
``investigations.updated_at``, which nothing decides on.

Revision ID: 0021
Revises: 0020
Create Date: 2026-10-23
"""

from collections.abc import Sequence

from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003): a migration must keep doing what it did when it was
# written.
_READ_ONLY = (
    "alert_records",
    "collector_cursors",
    "coverage_gaps",
    "dossiers",
    "siem_state",
    "entities",
    "gold_items",
    "investigation_alerts",
    "investigation_entities",
    "jobs",
    "llm_calls",
    "llm_state",
    "reconciliation_runs",
    "rules",
    "tuning_reports",
    "users",
)
_GRANTS = (
    "GRANT USAGE ON SCHEMA public TO argus_web",
    "GRANT USAGE ON SCHEMA langgraph TO argus_web",
    f"GRANT SELECT ON {', '.join(_READ_ONLY)} TO argus_web",
    "GRANT SELECT ON langgraph.checkpoints TO argus_web",
    "GRANT SELECT, UPDATE (updated_at) ON investigations TO argus_web",
    "GRANT SELECT, INSERT (investigation_id, version, pack, dossier_hash, view_hash, assessor,"
    " run_after, priority) ON assessments TO argus_web",
    "GRANT SELECT, INSERT (actor, action, outcome, target_type, target_id, correlation_id,"
    " details) ON audit_events TO argus_web",
    "GRANT SELECT, INSERT (set_name, investigation_id, user_id, outcome, note) ON gold_labels"
    " TO argus_web",
    "GRANT SELECT, INSERT (investigation_id, version, alert_count, user_id, action, outcome,"
    " note, assessment_id) ON review_events TO argus_web",
    "GRANT SELECT, INSERT (token_hash, user_id, csrf_token, last_seen_at, previous_seen_at),"
    " UPDATE (last_seen_at, ended_at) ON user_sessions TO argus_web",
)


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_web') THEN
                RAISE EXCEPTION 'role "argus_web" does not exist'
                    USING ERRCODE = 'undefined_object',
                          HINT = 'run "argus db bootstrap" first';
            END IF;
        END
        $$
        """
    )
    for grant in _GRANTS:
        op.execute(grant)
    # The connection right is the database's, not a migration's: bootstrap grants it
    # (grant_connect), as it does for argus_runtime.


def downgrade() -> None:
    # Revoking a table privilege also revokes it on every column. A role that does not exist
    # holds no privileges, so there is nothing to revoke.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_web') THEN
                REVOKE ALL ON alert_records, collector_cursors, coverage_gaps, dossiers,
                    siem_state, entities, gold_items, investigation_alerts,
                    investigation_entities, jobs, llm_calls, llm_state, reconciliation_runs,
                    rules, tuning_reports, users, investigations, assessments, audit_events,
                    gold_labels, review_events, user_sessions FROM argus_web;
                REVOKE ALL ON langgraph.checkpoints FROM argus_web;
                REVOKE USAGE ON SCHEMA langgraph FROM argus_web;
                REVOKE USAGE ON SCHEMA public FROM argus_web;
            END IF;
        END
        $$
        """
    )
