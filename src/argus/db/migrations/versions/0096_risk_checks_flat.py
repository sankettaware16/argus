"""The incident engine's link and alias checks are written flat: a restore reads them back the same.

0071 wrote ``char_length(value) BETWEEN 1 AND 600 AND priority BETWEEN 0 AND 9 ...``: PostgreSQL
keeps each BETWEEN as a nested ``(a AND b) AND c``, which a restore parses back flat, so
``pg_get_constraintdef`` differed and the backup drill failed (as 0060 found for the sign-ins). The
checks are recreated with the same meaning, written flat.

Revision ID: 0096
Revises: 0095
Create Date: 2026-11-06
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0096"
down_revision: str | None = "0095"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LINKS = "ck_risk_links_values_valid"
ALIASES = "ck_risk_aliases_values_valid"
LINKS_FLAT = (
    "char_length(value) >= 1 AND char_length(value) <= 600 AND priority >= 0 AND priority <= 9"
    " AND delta_seconds >= 0"
)
ALIASES_FLAT = (
    "valid_from <= valid_to AND char_length(device) >= 1 AND char_length(device) <= 600"
    " AND char_length(value) >= 1 AND char_length(value) <= 600"
)


def upgrade() -> None:
    op.drop_constraint(op.f(LINKS), "risk_links", type_="check")
    op.create_check_constraint(op.f(LINKS), "risk_links", LINKS_FLAT)
    op.drop_constraint(op.f(ALIASES), "risk_aliases", type_="check")
    op.create_check_constraint(op.f(ALIASES), "risk_aliases", ALIASES_FLAT)


def downgrade() -> None:
    op.drop_constraint(op.f(LINKS), "risk_links", type_="check")
    op.create_check_constraint(
        op.f(LINKS), "risk_links",
        "char_length(value) BETWEEN 1 AND 600 AND priority BETWEEN 0 AND 9 AND delta_seconds >= 0",
    )  # fmt: skip
    op.drop_constraint(op.f(ALIASES), "risk_aliases", type_="check")
    op.create_check_constraint(
        op.f(ALIASES), "risk_aliases",
        "valid_from <= valid_to AND char_length(device) BETWEEN 1 AND 600"
        " AND char_length(value) BETWEEN 1 AND 600",
    )  # fmt: skip
