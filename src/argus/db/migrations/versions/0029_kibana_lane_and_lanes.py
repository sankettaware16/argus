"""The Kibana lane and the lane budgets: switches, shared state, ledger columns

- New kill switches: ``investigation``, ``freshness``, ``cases`` (Kibana case writes) and
  ``identity``.
- New shared states: ``lanes`` (every lane's bucket but the collector's, which stays ``budget``),
  ``kibana`` (stopped, paused write classes, the write caps' counters) and ``kibana_breaker``.
- The request ledger records the lane, the target, and for a write its outbox row, payload hash,
  class and approval, with the SIEM's health and the stopped switches; it stays append-only.
- The rule of 0027 (services may stop, only the owner resumes) for the Kibana lane, by a row
  trigger on ``siem_state``.

Revision ID: 0029
Revises: 0028
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from argus.db.siem_names import RENAME

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_SWITCHES = "('global', 'collector', 'enrichment', 'kibana', 'writeback')"
NEW_SWITCHES = (
    "('global', 'collector', 'enrichment', 'kibana', 'writeback', 'investigation',"
    " 'freshness', 'cases', 'identity')"
)
OLD_STATES = "('health', 'budget', 'breaker')"
NEW_STATES = "('health', 'budget', 'breaker', 'lanes', 'kibana', 'kibana_breaker')"
LEDGER_COLUMNS = (
    "lane",
    "target",
    "outbox_id",
    "payload_hash",
    "write_class",
    "approval_id",
    "health",
    "switches",
)

# As 0027's argus_resume_needs_owner: current_user, pg_has_role (a superuser owner passes), and
# "stopped" truthy as Python reads it; a paused class is lifted when a key of the old "paused"
# object is missing from the new one.
KIBANA_GUARD_FN = """
CREATE FUNCTION argus_kibana_resume_needs_owner() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    falsy CONSTANT jsonb[] := ARRAY['false', 'null', '0', '""', '[]', '{}']::jsonb[];
    was_stopped boolean;
    now_stopped boolean;
    lifted boolean;
BEGIN
    IF OLD.name IS DISTINCT FROM 'kibana' AND NEW.name IS DISTINCT FROM 'kibana' THEN
        RETURN NEW;
    END IF;
    was_stopped := coalesce(NOT (OLD.state -> 'stopped' = ANY (falsy)), false);
    now_stopped := coalesce(NOT (NEW.state -> 'stopped' = ANY (falsy)), false);
    SELECT EXISTS (
        SELECT 1 FROM jsonb_object_keys(
            CASE WHEN jsonb_typeof(OLD.state -> 'paused') = 'object'
                 THEN OLD.state -> 'paused' ELSE '{}'::jsonb END
        ) AS paused(class)
        WHERE NOT coalesce(
            jsonb_typeof(NEW.state -> 'paused') = 'object' AND NEW.state -> 'paused' ? class,
            false
        )
    ) INTO lifted;
    IF ((was_stopped AND NOT now_stopped) OR lifted) AND NOT pg_has_role(
        current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
    ) THEN
        RAISE EXCEPTION 'only the owner resumes Kibana work or a paused write class'
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'run argus kibana resume as the owner (Q-A5)';
    END IF;
    RETURN NEW;
END
$$;
"""


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.drop_constraint(op.f("ck_siem_switches_component_valid"), "siem_switches", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_switches_component_valid"), "siem_switches", f"component IN {NEW_SWITCHES}"
    )
    op.execute(
        "INSERT INTO siem_switches (component) VALUES"
        " ('investigation'), ('freshness'), ('cases'), ('identity')"
    )
    op.drop_constraint(op.f("ck_siem_state_name_valid"), "siem_state", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_state_name_valid"), "siem_state", f"name IN {NEW_STATES}"
    )
    op.execute("INSERT INTO siem_state (name) VALUES ('lanes'), ('kibana'), ('kibana_breaker')")

    op.add_column("siem_requests", sa.Column("lane", sa.Text(), nullable=True))
    op.add_column(
        "siem_requests",
        sa.Column("target", sa.Text(), server_default="elasticsearch", nullable=False),
    )
    op.add_column("siem_requests", sa.Column("outbox_id", sa.Text(), nullable=True))
    op.add_column("siem_requests", sa.Column("payload_hash", sa.Text(), nullable=True))
    op.add_column("siem_requests", sa.Column("write_class", sa.Text(), nullable=True))
    op.add_column("siem_requests", sa.Column("approval_id", sa.Text(), nullable=True))
    op.add_column("siem_requests", sa.Column("health", sa.Text(), nullable=True))
    op.add_column(
        "siem_requests",
        sa.Column("switches", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_siem_requests_target_valid"),
        "siem_requests",
        "target IN ('elasticsearch', 'kibana')",
    )
    op.create_check_constraint(
        op.f("ck_siem_requests_write_class_valid"),
        "siem_requests",
        "write_class IS NULL OR write_class IN ('W1', 'W2', 'W3', 'WA', 'WT')",
    )
    op.create_check_constraint(
        op.f("ck_siem_requests_payload_hash_valid"),
        "siem_requests",
        "payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'",
    )
    op.create_check_constraint(
        op.f("ck_siem_requests_lane_valid"),
        "siem_requests",
        "lane IS NULL OR lane IN ('collector', 'investigation', 'freshness', 'kibana_read',"
        " 'kibana_write', 'identity', 'measurement')",
    )
    op.create_index(op.f("ix_siem_requests_outbox_id"), "siem_requests", ["outbox_id"])
    # The role name is written out, not imported (see 0003).
    op.execute(f"GRANT INSERT ({', '.join(LEDGER_COLUMNS)}) ON siem_requests TO argus_runtime")
    op.execute(KIBANA_GUARD_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_kibana_resume_needs_owner() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER siem_state_kibana_resume_needs_owner BEFORE UPDATE ON siem_state"
        " FOR EACH ROW EXECUTE FUNCTION argus_kibana_resume_needs_owner()"
    )
    op.execute("ALTER TABLE siem_state ENABLE ALWAYS TRIGGER siem_state_kibana_resume_needs_owner")


def downgrade() -> None:
    op.execute("DROP TRIGGER siem_state_kibana_resume_needs_owner ON siem_state")
    op.execute("DROP FUNCTION argus_kibana_resume_needs_owner()")
    # Dropping a column drops its grants.
    op.drop_index(op.f("ix_siem_requests_outbox_id"), table_name="siem_requests")
    for name in ("lane_valid", "payload_hash_valid", "write_class_valid", "target_valid"):
        op.drop_constraint(op.f(f"ck_siem_requests_{name}"), "siem_requests", type_="check")
    for column in reversed(LEDGER_COLUMNS):
        op.drop_column("siem_requests", column)
    op.execute("DELETE FROM siem_state WHERE name IN ('lanes', 'kibana', 'kibana_breaker')")
    op.drop_constraint(op.f("ck_siem_state_name_valid"), "siem_state", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_state_name_valid"), "siem_state", f"name IN {OLD_STATES}"
    )
    op.execute(
        "DELETE FROM siem_switches WHERE component IN"
        " ('investigation', 'freshness', 'cases', 'identity')"
    )
    op.drop_constraint(op.f("ck_siem_switches_component_valid"), "siem_switches", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_switches_component_valid"), "siem_switches", f"component IN {OLD_SWITCHES}"
    )
