"""Settings changed in the app (D-327)

``admin_changes``: one row per setting a person changed in the app's Settings, the rows of one
save sharing ``batch``; ``argus-admin`` (the runtime login) applies them to this host's files and
records the outcome. ``admin_sealed``: a key a person pasted, sealed with ``argus-admin``'s public
key; the web inserts it and may never read it back. ``admin_state``: what ``argus-admin``
publishes (its public key, where each setting is set, its heartbeat), which the web reads.

Revision ID: 0108
Revises: 0107
Create Date: 2026-11-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0108"
down_revision: str | None = "0107"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INSERT = "batch, key, value, reset, risk, created_by, created_at, stepped_up_at"
WEB_GRANTS = (
    f"GRANT SELECT, INSERT ({INSERT}) ON admin_changes TO argus_web",
    "GRANT INSERT (change_id, sealed) ON admin_sealed TO argus_web",  # never read back
    "GRANT SELECT ON admin_state TO argus_web",
)


def upgrade() -> None:
    op.create_table(
        "admin_changes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("batch", sa.UUID(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("reset", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("risk", sa.Text(), nullable=False),
        sa.Column("created_by", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stepped_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.Text(), server_default="pending", nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('pending', 'applying', 'applied', 'refused', 'rolled_back')",
            name=op.f("ck_admin_changes_state_valid"),
        ),
        sa.CheckConstraint(
            "risk IN ('normal', 'sensitive', 'siem_write')",
            name=op.f("ck_admin_changes_risk_valid"),
        ),
        sa.CheckConstraint(
            "key ~ '^[a-z_]+(\\.[a-z0-9_]+)+$'", name=op.f("ck_admin_changes_key_valid")
        ),
        sa.CheckConstraint(
            "NOT (reset AND value IS NOT NULL)", name=op.f("ck_admin_changes_reset_carries_nothing")
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR char_length(outcome) <= 600",
            name=op.f("ck_admin_changes_outcome_length"),
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["users.id"],
            ondelete="RESTRICT",
            name=op.f("fk_admin_changes_created_by_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_admin_changes")),
    )
    op.create_index(op.f("ix_admin_changes_state_id"), "admin_changes", ["state", "id"])
    op.create_index(op.f("ix_admin_changes_batch"), "admin_changes", ["batch"])
    op.create_table(
        "admin_sealed",
        sa.Column("change_id", sa.BigInteger(), nullable=False),
        sa.Column("sealed", sa.LargeBinary(), nullable=False),
        sa.CheckConstraint(
            "octet_length(sealed) <= 20000", name=op.f("ck_admin_sealed_sealed_length")
        ),
        sa.ForeignKeyConstraint(
            ["change_id"],
            ["admin_changes.id"],
            ondelete="CASCADE",
            name=op.f("fk_admin_sealed_change_id_admin_changes"),
        ),
        sa.PrimaryKeyConstraint("change_id", name=op.f("pk_admin_sealed")),
    )
    op.create_table(
        "admin_state",
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("state", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "name IN ('seal', 'snapshot', 'heartbeat')", name=op.f("ck_admin_state_name_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(state) = 'object'", name=op.f("ck_admin_state_state_is_object")
        ),
        sa.PrimaryKeyConstraint("name", name=op.f("pk_admin_state")),
    )
    op.execute(
        "GRANT SELECT, UPDATE (state, outcome, finished_at) ON admin_changes TO argus_runtime"
    )
    op.execute("GRANT SELECT ON admin_sealed TO argus_runtime")
    op.execute("GRANT SELECT, INSERT, UPDATE (state, updated_at) ON admin_state TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_table("admin_state")
    op.drop_table("admin_sealed")
    op.drop_index(op.f("ix_admin_changes_batch"), table_name="admin_changes")
    op.drop_index(op.f("ix_admin_changes_state_id"), table_name="admin_changes")
    op.drop_table("admin_changes")
