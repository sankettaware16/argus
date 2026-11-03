"""An incident ID may carry any prefix (P4-D1 part 2, D-284; D-293).

The prefix of an incident case id is the site's (``site.incident_id_prefix``), so
``case_team_posts.incident_id`` is checked against the same shape with any prefix: a capital
letter, then capital letters, digits and ``-``, at most 16 characters, then ``-YYYY-MMDD-NN``.
A database made before this migration holds a check for one fixed prefix (0053 first wrote it so);
this revision replaces it, and every existing row still passes. 0053 now writes the final form
itself, so a new database has it from the start and this revision only writes it again. The check
is written flat, as one comparison, so a restore reparses it to the same text (D-234).

No table is added and no grant changes. Downgrading keeps the check: the posts are the record of
what was sent to Kibana, and no row is ever refused by going back.

Revision ID: 0063
Revises: 0062
Create Date: 2026-10-31
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0063"
down_revision: str | None = "0062"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ck_case_team_posts_id_valid"
TAIL = "-[0-9]{4}-[0-9]{4}-[0-9]{2}$'"
NEW = r"incident_id ~ '^[A-Z][A-Z0-9-]{0,15}" + TAIL


def upgrade() -> None:
    op.drop_constraint(op.f(NAME), "case_team_posts", type_="check")
    op.create_check_constraint(op.f(NAME), "case_team_posts", NEW)


def downgrade() -> None:
    # 0053 already has this form: going back keeps it (no post is ever refused)
    op.drop_constraint(op.f(NAME), "case_team_posts", type_="check")
    op.create_check_constraint(op.f(NAME), "case_team_posts", NEW)
