"""runtime role: read the audit trail and append to it, nothing else

ARGUS runs as a login that is a member of the group role ``argus_runtime`` (made by ``argus db
bootstrap``). It may read ``alembic_version`` and ``audit_events`` and insert audit events, but not
their ``id`` or ``occurred_at``, and has no UPDATE, DELETE, TRUNCATE or ownership. Later migrations
grant it what each new table needs, explicitly; ``argus.db.roles.RUNTIME_GRANTS`` lists it.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# The role name is written out, not imported: a migration must keep doing what it did when it was
# written.


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
                RAISE EXCEPTION 'role "argus_runtime" does not exist'
                    USING ERRCODE = 'undefined_object',
                          HINT = 'run "argus db bootstrap" first';
            END IF;
        END
        $$
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO argus_runtime")
    op.execute("GRANT SELECT ON alembic_version TO argus_runtime")
    op.execute(
        "GRANT SELECT, INSERT (actor, action, outcome, target_type, target_id, correlation_id,"
        " details) ON audit_events TO argus_runtime"
    )


def downgrade() -> None:
    # Revoking a table privilege also revokes it on every column. A role that does not exist
    # holds no privileges, so there is nothing to revoke.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
                REVOKE SELECT, INSERT ON audit_events FROM argus_runtime;
                REVOKE SELECT ON alembic_version FROM argus_runtime;
                REVOKE USAGE ON SCHEMA public FROM argus_runtime;
            END IF;
        END
        $$
        """
    )
