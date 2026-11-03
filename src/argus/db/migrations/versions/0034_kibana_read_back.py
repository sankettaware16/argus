"""The Kibana read-back and reconciliation (Q-D3, plan §5 and §7.1): read-only

- ``kibana_mirror`` (0026) becomes writable by the runtime role, which the read-back runs as
  (``argus-kibana-sync`` in the svc account): it inserts a mirror for a case ARGUS made and
  updates what it reads back. Three new columns: ``actions_seen`` (how many of the case's
  user actions were read), ``argus_actions`` (how many of them were ARGUS's, by kind: each
  must be explained by a sent outbox row) and ``paused_reason`` (ARGUS's writes to the case
  are paused: a person changed ARGUS's ``argus:*`` tags or its settings). As Q-A5's rule
  for the switches (0027, 0029), a row trigger lets services pause, only the owner lift.
- ``kibana_sync_state``: one row (where the change poll starts, the discovery's place, the
  clock offset).
- ``kibana_sync_cycles``: one row per cycle; the runtime may insert, never change.
- ``kibana_findings``: the reconciliation's alarms, items and notes, each once; the runtime
  may insert, never change (a person resolves them, Q-B3).
- ``kibana_people_cases``: people's Kibana cases that hold alerts ARGUS knows (read-only).
- ``kibana_alert_states``: the status of each alert on ARGUS's cases at the last discovery
  (an alert change is found by diffing statuses: Kibana's internal route records neither
  ``workflow_user`` nor ``workflow_status_updated_at``, Q-D1's finding #7).

Revision ID: 0034
Revises: 0033
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDING_KINDS = (
    "person_edited",
    "argus_tags_changed",
    "settings_changed",
    "person_commented",
    "closed_in_kibana",
    "reopened_in_kibana",
    "status_changed_in_kibana",
    "deleted_in_kibana",
    "people_case",
    "unexplained_argus_action",
    "unexplained_argus_case",
    "duplicate_case",
    "not_argus_case",
    "alert_change_unexplained",
    "alert_status_by_person",
    "clock_offset",
    "actions_rewound",
    "answer_unexpected",
)
MIRROR_COLUMNS = (
    "case_id",
    "kibana_case_id",
    "kibana_version",
    "status",
    "title",
    "severity",
    "tags",
    "created_by",
    "sync_alerts",
    "unmanaged",
    "kibana_created_at",
    "kibana_updated_at",
    "read_at",
    "deleted_at",
    "actions_seen",
    "argus_actions",
    "paused_reason",
)
MIRROR_UPDATE = tuple(c for c in MIRROR_COLUMNS if c not in ("case_id", "kibana_case_id"))
STATE_COLUMNS = (
    "id",
    "changes_from",
    "last_cycle_at",
    "last_complete_at",
    "last_status_at",
    "last_discovery_at",
    "last_closed_listing_at",
    "discovery_cursor",
    "alerts_checked_to",
    "clock_offset_ms",
    "clock_checked_at",
    "updated_at",
)
CYCLE_COLUMNS = (
    "started_at",
    "finished_at",
    "outcome",
    "reason",
    "health",
    "reads",
    "changed",
    "findings",
    "oldest_read_s",
    "stale",
    "clock_offset_ms",
    "detail",
)
FINDING_COLUMNS = (
    "found_at",
    "kind",
    "severity",
    "kibana_case_id",
    "case_id",
    "dedupe_key",
    "lag_s",
    "details",
)
PEOPLE_COLUMNS = (
    "kibana_case_id",
    "title",
    "status",
    "created_by",
    "tags",
    "known_alerts",
    "kibana_updated_at",
    "first_seen_at",
    "read_at",
    "deleted_at",
)
PEOPLE_UPDATE = tuple(c for c in PEOPLE_COLUMNS if c not in ("kibana_case_id", "first_seen_at"))
ALERT_COLUMNS = ("alert_id", "status", "workflow_user", "status_updated_at", "seen_at")

# As 0029's argus_kibana_resume_needs_owner: a pause may be set by anyone the grants allow,
# lifted (or changed) only by the table's owner or a member of it.
MIRROR_GUARD_FN = """
CREATE FUNCTION argus_mirror_resume_needs_owner() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF OLD.paused_reason IS NOT NULL
       AND NEW.paused_reason IS DISTINCT FROM OLD.paused_reason
       AND NOT pg_has_role(
           current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
       ) THEN
        RAISE EXCEPTION 'only the owner lifts the pause of ARGUS''s writes to a Kibana case'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'run argus kibana sync resume-case as the owner (Q-A5)';
    END IF;
    RETURN NEW;
END
$$;
"""


def _kinds() -> str:
    return "kind IN (" + ", ".join(f"'{k}'" for k in FINDING_KINDS) + ")"


def upgrade() -> None:
    op.add_column(
        "kibana_mirror",
        sa.Column("actions_seen", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "kibana_mirror",
        sa.Column(
            "argus_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )
    op.add_column("kibana_mirror", sa.Column("paused_reason", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_kibana_mirror_actions_seen_valid"), "kibana_mirror", "actions_seen >= 0"
    )
    op.create_table(
        "kibana_sync_state",
        sa.Column("id", sa.SmallInteger(), autoincrement=False, nullable=False),
        sa.Column("changes_from", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cycle_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_complete_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_discovery_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_closed_listing_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discovery_cursor", sa.Text(), nullable=True),
        sa.Column("alerts_checked_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("clock_offset_ms", sa.Integer(), nullable=True),
        sa.Column("clock_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("id = 1", name=op.f("ck_kibana_sync_state_one_row")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_sync_state")),
    )
    op.create_table(
        "kibana_sync_cycles",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("health", sa.Text(), nullable=True),
        sa.Column("reads", sa.Integer(), nullable=False),
        sa.Column("changed", sa.Integer(), nullable=False),
        sa.Column("findings", sa.Integer(), nullable=False),
        sa.Column("oldest_read_s", sa.Integer(), nullable=True),
        sa.Column("stale", sa.Boolean(), nullable=False),
        sa.Column("clock_offset_ms", sa.Integer(), nullable=True),
        sa.Column(
            "detail",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('complete', 'partial', 'failed')",
            name=op.f("ck_kibana_sync_cycles_outcome_valid"),
        ),
        sa.CheckConstraint(
            "finished_at >= started_at", name=op.f("ck_kibana_sync_cycles_finished_after_start")
        ),
        sa.CheckConstraint(
            "reads >= 0 AND changed >= 0 AND findings >= 0",
            name=op.f("ck_kibana_sync_cycles_counts_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_sync_cycles")),
    )
    op.create_index(op.f("ix_kibana_sync_cycles_started_at"), "kibana_sync_cycles", ["started_at"])
    op.create_table(
        "kibana_findings",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("found_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=True),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("dedupe_key", sa.Text(), nullable=False),
        sa.Column("lag_s", sa.Integer(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("resolved_by", sa.Text(), nullable=True),
        sa.CheckConstraint(_kinds(), name=op.f("ck_kibana_findings_kind_valid")),
        sa.CheckConstraint(
            "severity IN ('alarm', 'attention', 'info')",
            name=op.f("ck_kibana_findings_severity_valid"),
        ),
        sa.CheckConstraint(
            "length(dedupe_key) BETWEEN 1 AND 400", name=op.f("ck_kibana_findings_key_length")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(details) = 'object'", name=op.f("ck_kibana_findings_details_is_object")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_kibana_findings_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_findings")),
        sa.UniqueConstraint("dedupe_key", name=op.f("uq_kibana_findings_dedupe_key")),
    )
    op.create_index(op.f("ix_kibana_findings_found_at"), "kibana_findings", ["found_at"])
    op.create_index(
        op.f("ix_kibana_findings_kibana_case_id"), "kibana_findings", ["kibana_case_id"]
    )
    op.create_table(
        "kibana_people_cases",
        sa.Column("kibana_case_id", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("known_alerts", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("kibana_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('open', 'in-progress', 'closed')",
            name=op.f("ck_kibana_people_cases_status_valid"),
        ),
        sa.PrimaryKeyConstraint("kibana_case_id", name=op.f("pk_kibana_people_cases")),
    )
    op.create_table(
        "kibana_alert_states",
        sa.Column("alert_id", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=True),
        sa.Column("workflow_user", sa.Text(), nullable=True),
        sa.Column("status_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("alert_id", name=op.f("pk_kibana_alert_states")),
    )
    op.execute("INSERT INTO kibana_sync_state (id) VALUES (1)")
    # The role name is written out, not imported (see 0003). Column-level, nothing more.
    op.execute(
        f"GRANT INSERT ({', '.join(MIRROR_COLUMNS)}), UPDATE ({', '.join(MIRROR_UPDATE)})"
        " ON kibana_mirror TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, UPDATE ({', '.join(c for c in STATE_COLUMNS if c != 'id')})"
        " ON kibana_sync_state TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({', '.join(CYCLE_COLUMNS)}) ON kibana_sync_cycles TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({', '.join(FINDING_COLUMNS)}) ON kibana_findings TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({', '.join(PEOPLE_COLUMNS)}), UPDATE ({', '.join(PEOPLE_UPDATE)})"
        " ON kibana_people_cases TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({', '.join(ALERT_COLUMNS)}),"
        f" UPDATE ({', '.join(ALERT_COLUMNS[1:])}) ON kibana_alert_states TO argus_runtime"
    )
    op.execute(MIRROR_GUARD_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_mirror_resume_needs_owner() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER kibana_mirror_resume_needs_owner BEFORE UPDATE ON kibana_mirror"
        " FOR EACH ROW EXECUTE FUNCTION argus_mirror_resume_needs_owner()"
    )
    op.execute("ALTER TABLE kibana_mirror ENABLE ALWAYS TRIGGER kibana_mirror_resume_needs_owner")


def downgrade() -> None:
    op.execute("DROP TRIGGER kibana_mirror_resume_needs_owner ON kibana_mirror")
    op.execute("DROP FUNCTION argus_mirror_resume_needs_owner()")
    op.drop_table("kibana_alert_states")
    op.drop_table("kibana_people_cases")
    op.drop_index(op.f("ix_kibana_findings_kibana_case_id"), table_name="kibana_findings")
    op.drop_index(op.f("ix_kibana_findings_found_at"), table_name="kibana_findings")
    op.drop_table("kibana_findings")
    op.drop_index(op.f("ix_kibana_sync_cycles_started_at"), table_name="kibana_sync_cycles")
    op.drop_table("kibana_sync_cycles")
    op.drop_table("kibana_sync_state")
    # revoking the table's INSERT and UPDATE revokes every column's too (0026's SELECT stays)
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
                REVOKE INSERT, UPDATE ON kibana_mirror FROM argus_runtime;
            END IF;
        END
        $$;
        """
    )
    op.drop_constraint(op.f("ck_kibana_mirror_actions_seen_valid"), "kibana_mirror", type_="check")
    op.drop_column("kibana_mirror", "paused_reason")
    op.drop_column("kibana_mirror", "argus_actions")
    op.drop_column("kibana_mirror", "actions_seen")
