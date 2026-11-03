"""The sign-in hours check is written flat, so a restore reads it back the same.

0056 wrote ``cardinality(hours) BETWEEN 1 AND 24 AND hours <@ ...``: PostgreSQL keeps the BETWEEN as
a nested ``(a AND b) AND c``, which a restore parses back flat, so ``pg_get_constraintdef`` differed
and the backup drill failed. The check is recreated with the same meaning, written flat.

Revision ID: 0060
Revises: 0059
Create Date: 2026-10-30
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0060"
down_revision: str | None = "0059"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ck_signin_sightings_hours_valid"
HOURS = (
    " AND hours <@ ARRAY[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]::smallint[]"
)


def upgrade() -> None:
    op.drop_constraint(op.f(NAME), "signin_sightings", type_="check")
    op.create_check_constraint(
        op.f(NAME),
        "signin_sightings",
        "cardinality(hours) >= 1 AND cardinality(hours) <= 24" + HOURS,
    )


def downgrade() -> None:
    op.drop_constraint(op.f(NAME), "signin_sightings", type_="check")
    op.create_check_constraint(
        op.f(NAME), "signin_sightings", "cardinality(hours) BETWEEN 1 AND 24" + HOURS
    )
