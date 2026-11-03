"""Kill switches: services may stop them, only the owner resumes them (Q-A5, plan §7.9)

Until now the runtime role could clear ``siem_switches.stopped`` and the LLM gateway's
``stopped`` flag (db/roles.py grants it UPDATE on both), so any ARGUS process, or anything that
got the runtime password, could undo a person's stop. A row trigger now refuses a change from
stopped to running unless the role making it is the table's owner or a member of it (the owner
runs ``argus siem resume`` and ``argus llm resume``). Stopping, and every other update the
runtime makes (budgets, breakers), is unchanged. The runtime role owns nothing, so it cannot
drop or switch off the trigger.

Revision ID: 0027
Revises: 0026
Create Date: 2026-10-23
"""

from collections.abc import Sequence

from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# current_user, not session_user: SET ROLE can only move to a role the login is a member of,
# and the runtime login is a member of argus_runtime alone. pg_has_role counts a superuser as a
# member of every role, so the local Docker owner (a superuser) passes.
GUARD_FN = """
CREATE FUNCTION argus_resume_needs_owner() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    falsy CONSTANT jsonb[] := ARRAY['false', 'null', '0', '""', '[]', '{}']::jsonb[];
    was_stopped boolean;
    now_stopped boolean;
BEGIN
    IF TG_TABLE_NAME = 'llm_state' THEN
        IF OLD.name IS DISTINCT FROM 'gateway' AND NEW.name IS DISTINCT FROM 'gateway' THEN
            RETURN NEW;
        END IF;
        -- truthy as budget.from_json reads it (Python's bool of the JSON value)
        was_stopped := coalesce(NOT (OLD.state -> 'stopped' = ANY (falsy)), false);
        now_stopped := coalesce(NOT (NEW.state -> 'stopped' = ANY (falsy)), false);
    ELSE
        was_stopped := OLD.stopped;
        now_stopped := NEW.stopped;
    END IF;
    IF was_stopped AND NOT now_stopped AND NOT pg_has_role(
        current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
    ) THEN
        RAISE EXCEPTION 'only the owner resumes a stopped switch (%)', TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'run the resume command as the owner (Q-A5)';
    END IF;
    RETURN NEW;
END
$$;
"""


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.execute(GUARD_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_resume_needs_owner() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER siem_switches_resume_needs_owner BEFORE UPDATE ON siem_switches"
        " FOR EACH ROW EXECUTE FUNCTION argus_resume_needs_owner()"
    )
    op.execute(
        "CREATE TRIGGER llm_state_resume_needs_owner BEFORE UPDATE ON llm_state"
        " FOR EACH ROW EXECUTE FUNCTION argus_resume_needs_owner()"
    )
    # ENABLE ALWAYS, as the audit trail's guards: no session_replication_role skips them
    op.execute("ALTER TABLE siem_switches ENABLE ALWAYS TRIGGER siem_switches_resume_needs_owner")
    op.execute("ALTER TABLE llm_state ENABLE ALWAYS TRIGGER llm_state_resume_needs_owner")


def downgrade() -> None:
    op.execute("DROP TRIGGER llm_state_resume_needs_owner ON llm_state")
    op.execute("DROP TRIGGER siem_switches_resume_needs_owner ON siem_switches")
    op.execute("DROP FUNCTION argus_resume_needs_owner()")
