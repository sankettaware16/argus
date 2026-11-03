"""The case team can correct a case it posted (AR8, D-236): steps that edit in place.

``case_team_steps.kind`` gains three kinds: ``retitle`` (the lead sets the Kibana case's title),
``redescribe`` (the lead sets its description) and ``edit_comment`` (the user who wrote a comment
rewrites it). The first two are the lead's alone, as an opening and an alert write are. A
``redescribe`` and an ``edit_comment`` carry their new text in ``text_body``, a ``retitle`` carries
its title in the payload. No table is added, so no grant changes: the writer's login moves the same
columns of the same table.

The three checks are written flat (no BETWEEN, no nesting), so a restore reads them back the same
(D-234). Downgrading is refused while any step of a new kind exists: the steps are the only record
of what the case team wrote to production.

Revision ID: 0061
Revises: 0060
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0061"
down_revision: str | None = "0060"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_KINDS = ("open", "attach", "tag", "comment", "file")
NEW_KINDS = ("retitle", "redescribe", "edit_comment")
KIND = "ck_case_team_steps_kind_valid"
TEXT = "ck_case_team_steps_text_kinds"
LEAD = "ck_case_team_steps_lead_only"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _set(kinds: Sequence[str], texts: Sequence[str], leads: Sequence[str]) -> None:
    for name in (KIND, TEXT, LEAD):
        op.drop_constraint(op.f(name), "case_team_steps", type_="check")
    op.create_check_constraint(op.f(KIND), "case_team_steps", _in("kind", kinds))
    op.create_check_constraint(
        op.f(TEXT), "case_team_steps", f"({_in('kind', texts)}) = (text_body IS NOT NULL)"
    )
    op.create_check_constraint(
        op.f(LEAD),
        "case_team_steps",
        f"kind NOT IN ({', '.join(repr(k) for k in leads)}) OR author = 'argus-lead'",
    )


def upgrade() -> None:
    _set(
        (*OLD_KINDS, *NEW_KINDS),
        ("open", "comment", "redescribe", "edit_comment"),
        ("open", "attach", "tag", "retitle", "redescribe"),
    )


def downgrade() -> None:
    sent = (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT count(*) FROM case_team_steps WHERE kind IN ('retitle', 'redescribe',"
                " 'edit_comment')"
            )
        )
        .scalar_one()
    )
    if sent:  # the steps are the record of what was written to production: never lost
        raise RuntimeError(f"refused: {sent} steps edit a posted case in place")
    _set(OLD_KINDS, ("open", "comment"), ("open", "attach", "tag"))
