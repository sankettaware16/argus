"""baseline: append-only audit_events

Revision ID: 0001
Revises:
Create Date: 2026-10-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REJECT_MUTATION_FN = """
CREATE FUNCTION argus_reject_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'table % is append-only: % rejected', TG_TABLE_NAME, TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;
"""


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), server_default="success", nullable=False),
        sa.Column("target_type", sa.Text(), nullable=True),
        sa.Column("target_id", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.Text(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.CheckConstraint("length(actor) > 0", name=op.f("ck_audit_events_actor_not_empty")),
        sa.CheckConstraint("length(action) > 0", name=op.f("ck_audit_events_action_not_empty")),
        sa.CheckConstraint(
            "outcome IN ('success', 'failure', 'denied')",
            name=op.f("ck_audit_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(details) = 'object'", name=op.f("ck_audit_events_details_is_object")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_occurred_at"), "audit_events", ["occurred_at"])
    op.create_index(
        op.f("ix_audit_events_target_type_target_id"), "audit_events", ["target_type", "target_id"]
    )
    op.create_index(
        op.f("ix_audit_events_action_occurred_at"), "audit_events", ["action", "occurred_at"]
    )

    op.execute(REJECT_MUTATION_FN)
    op.execute(
        "CREATE TRIGGER audit_events_append_only_rows BEFORE UPDATE OR DELETE ON audit_events "
        "FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER audit_events_append_only_truncate BEFORE TRUNCATE ON audit_events "
        "FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only_truncate ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_append_only_rows ON audit_events")
    op.drop_index(op.f("ix_audit_events_action_occurred_at"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_target_type_target_id"), table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_occurred_at"), table_name="audit_events")
    op.drop_table("audit_events")
    op.execute("DROP FUNCTION IF EXISTS argus_reject_mutation()")
