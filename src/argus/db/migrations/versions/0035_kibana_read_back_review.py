"""The Kibana read-back's review fixes (Q-D3, gate report "Review"): three columns and a kind

- ``kibana_mirror.kibana_case_id`` may be changed by the runtime role, once (review R2): a
  case ARGUS recreates after a person deleted it is a second Kibana case for the same ARGUS
  case, and the mirror keeps one row per ARGUS case (its primary key), so the row of the
  deleted case is pointed at the new one. A trigger refuses the change for a row whose case
  was not deleted (``deleted_at`` is set), so a bug cannot move a live mirror.
- ``kibana_mirror.unexplained``: how many of ARGUS's actions on the case no sent write
  explained, by kind, already alarmed (R7): a later action that a sent write does explain is
  not taken for one of them.
- ``kibana_sync_state.diff_cursor``: where the alert-status diff stopped, so each discovery
  asks for a bounded slice of the alerts and the next one goes on (R8).
- ``kibana_findings.kind`` may be ``person_deleted`` (R9): a person removed a comment or an
  alert attachment.

Revision ID: 0035
Revises: 0034
Create Date: 2026-10-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003): 0034's list, and the list with the new kind.
KINDS_0034 = (
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
KINDS = (*KINDS_0034[:1], "person_deleted", *KINDS_0034[1:])

REPOINT_FN = """
CREATE FUNCTION argus_mirror_repoint_after_deletion() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.kibana_case_id IS DISTINCT FROM OLD.kibana_case_id
       AND OLD.deleted_at IS NULL
       AND NOT pg_has_role(
           current_user, (SELECT relowner FROM pg_class WHERE oid = TG_RELID), 'MEMBER'
       ) THEN
        RAISE EXCEPTION 'a mirror is pointed at another Kibana case only after its own was deleted'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END
$$;
"""


def _kinds(kinds: Sequence[str]) -> str:
    return "kind IN (" + ", ".join(f"'{k}'" for k in kinds) + ")"


def upgrade() -> None:
    op.add_column(
        "kibana_mirror",
        sa.Column(
            "unexplained",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )
    op.add_column("kibana_sync_state", sa.Column("diff_cursor", sa.Text(), nullable=True))
    op.drop_constraint(op.f("ck_kibana_findings_kind_valid"), "kibana_findings", type_="check")
    op.create_check_constraint(
        op.f("ck_kibana_findings_kind_valid"), "kibana_findings", _kinds(KINDS)
    )
    op.execute(
        "GRANT INSERT (unexplained), UPDATE (kibana_case_id, unexplained)"
        " ON kibana_mirror TO argus_runtime"
    )
    op.execute("GRANT UPDATE (diff_cursor) ON kibana_sync_state TO argus_runtime")
    op.execute(REPOINT_FN)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_mirror_repoint_after_deletion() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER kibana_mirror_repoint_after_deletion BEFORE UPDATE ON kibana_mirror"
        " FOR EACH ROW EXECUTE FUNCTION argus_mirror_repoint_after_deletion()"
    )
    op.execute(
        "ALTER TABLE kibana_mirror ENABLE ALWAYS TRIGGER kibana_mirror_repoint_after_deletion"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER kibana_mirror_repoint_after_deletion ON kibana_mirror")
    op.execute("DROP FUNCTION argus_mirror_repoint_after_deletion()")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
                REVOKE UPDATE (kibana_case_id) ON kibana_mirror FROM argus_runtime;
            END IF;
        END
        $$;
        """
    )
    op.execute("DELETE FROM kibana_findings WHERE kind = 'person_deleted'")
    op.drop_constraint(op.f("ck_kibana_findings_kind_valid"), "kibana_findings", type_="check")
    op.create_check_constraint(
        op.f("ck_kibana_findings_kind_valid"), "kibana_findings", _kinds(KINDS_0034)
    )
    op.drop_column("kibana_sync_state", "diff_cursor")
    op.drop_column("kibana_mirror", "unexplained")
