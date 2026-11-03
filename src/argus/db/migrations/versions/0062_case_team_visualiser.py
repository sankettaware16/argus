"""The case team's seventh user, ``argus-visualiser``.

``case_team_steps.author`` was checked against the six original users (0053); the visualiser posts
the "Incident at a glance" comment, so its name joins the list. No table is added and no grant
changes. Downgrading is refused while a step by the visualiser exists.

Revision ID: 0062
Revises: 0061
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0062"
down_revision: str | None = "0061"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ck_case_team_steps_author_valid"
OLD = (
    "argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter",
    "argus-reporter",
)  # fmt: skip
NEW = (*OLD, "argus-visualiser")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint(op.f(NAME), "case_team_steps", type_="check")
    op.create_check_constraint(op.f(NAME), "case_team_steps", _in("author", NEW))


def downgrade() -> None:
    sent = (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM case_team_steps WHERE author = 'argus-visualiser'"))
        .scalar_one()
    )
    if sent:  # the steps are the record of what was sent: never lost to a downgrade
        raise RuntimeError(f"refused: {sent} steps by argus-visualiser would no longer be valid")
    op.drop_constraint(op.f(NAME), "case_team_steps", type_="check")
    op.create_check_constraint(op.f(NAME), "case_team_steps", _in("author", OLD))
