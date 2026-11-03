"""Sessions: an absolute expiry and step-up; local accounts' capabilities (Q-A1)

The session contract of Phase 3 (plan §7.2): a session ends 8 hours after sign-in at most
(``expires_at``; sessions open at upgrade get their sign-in time plus 8 hours), records when
its person last confirmed their password (``stepped_up_at``) and how many step-ups failed
since (``stepup_failures``: three end it). A local account's capabilities are stored on it;
every existing account gets what any reviewer could do before (view, see_logs, review,
answer_gold), so nobody loses anything. The web's login (argus_web, 0021) gets the session
columns it writes.

Revision ID: 0024
Revises: 0023
Create Date: 2026-10-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CAPABILITIES = (
    "view", "see_logs", "review", "answer_gold", "manage_cases", "reopen", "approve", "admin"
)  # fmt: skip
LOCAL_DEFAULT = "'{view,see_logs,review,answer_gold}'::text[]"
# The web's own group role (0021, Q-A2) signs people in and confirms step-ups too; it reads
# users (capabilities included) already and never writes them (argus.db.roles.API_GRANTS).
WEB_GRANTS = (
    "GRANT INSERT (expires_at), UPDATE (stepped_up_at, stepup_failures) ON user_sessions"
    " TO argus_web",
)


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "capabilities",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text(LOCAL_DEFAULT),
            nullable=False,
        ),
    )
    known = ", ".join(f"'{c}'" for c in CAPABILITIES)
    op.create_check_constraint(
        op.f("ck_users_capabilities_valid"),
        "users",
        f"capabilities <@ ARRAY[{known}]::text[] AND array_position(capabilities, NULL) IS NULL",
    )
    op.add_column(
        "user_sessions", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.execute("UPDATE user_sessions SET expires_at = created_at + interval '8 hours'")
    op.alter_column("user_sessions", "expires_at", nullable=False)
    op.add_column(
        "user_sessions", sa.Column("stepped_up_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "user_sessions",
        sa.Column("stepup_failures", sa.SmallInteger(), server_default="0", nullable=False),
    )
    op.create_check_constraint(
        op.f("ck_user_sessions_stepup_failures_valid"), "user_sessions", "stepup_failures >= 0"
    )
    # The role name is written out, not imported (see 0003).
    op.execute("GRANT INSERT (capabilities), UPDATE (capabilities) ON users TO argus_runtime")
    op.execute(
        "GRANT INSERT (expires_at), UPDATE (stepped_up_at, stepup_failures) ON user_sessions"
        " TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_user_sessions_stepup_failures_valid"), "user_sessions", type_="check"
    )
    op.drop_column("user_sessions", "stepup_failures")
    op.drop_column("user_sessions", "stepped_up_at")
    op.drop_column("user_sessions", "expires_at")
    op.drop_constraint(op.f("ck_users_capabilities_valid"), "users", type_="check")
    op.drop_column("users", "capabilities")
