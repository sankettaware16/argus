"""Inbox: reviewer accounts, sessions and the append-only review events

R7 (D-052). Review events are append-only for the runtime role (no UPDATE, no DELETE); a
session is stored as the hash of its token.

Revision ID: 0007
Revises: 0006
Create Date: 2026-10-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("username", sa.Text(), nullable=False),
        sa.Column("display_name", sa.Text(), nullable=False),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("disabled", sa.Boolean(), server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "username ~ '^[a-z][a-z0-9_.-]{1,31}$'", name=op.f("ck_users_username_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("username", name=op.f("uq_users_username")),
    )
    op.create_table(
        "review_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("alert_count", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("action", sa.Text(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('reviewed', 'follow_up', 'note')",
            name=op.f("ck_review_events_action_valid"),
        ),
        sa.CheckConstraint(
            "outcome IS NULL OR outcome IN ('benign_expected', 'benign_policy',"
            " 'rule_false_positive', 'true_positive', 'inconclusive')",
            name=op.f("ck_review_events_outcome_valid"),
        ),
        sa.CheckConstraint(
            "note IS NULL OR length(note) <= 4000", name=op.f("ck_review_events_note_length")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_review_events_investigation_id_investigations"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_review_events_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_review_events")),
    )
    op.create_index(
        op.f("ix_review_events_investigation_id_id"),
        "review_events",
        ["investigation_id", "id"],
        unique=False,
    )
    op.create_table(
        "user_sessions",
        sa.Column("token_hash", sa.Text(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("csrf_token", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("previous_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_sessions_user_id_users")
        ),
        sa.PrimaryKeyConstraint("token_hash", name=op.f("pk_user_sessions")),
    )
    op.create_index(op.f("ix_user_sessions_user_id"), "user_sessions", ["user_id"], unique=False)
    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (username, display_name, password_hash), UPDATE (display_name,"
        " password_hash, disabled) ON users TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (token_hash, user_id, csrf_token, last_seen_at,"
        " previous_seen_at), UPDATE (last_seen_at, ended_at) ON user_sessions TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (investigation_id, version, alert_count, user_id, action,"
        " outcome, note) ON review_events TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_user_sessions_user_id"), table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_index(op.f("ix_review_events_investigation_id_id"), table_name="review_events")
    op.drop_table("review_events")
    op.drop_table("users")
