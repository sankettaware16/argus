"""Write-back: a dismissed possible incident closes its alerts (D-336)

A ``writeback_outbox`` row may now come from a person's dismissal of a possible incident: the
case, with no closure request and no review. The runtime plans it with the columns it may
already insert; a case dismissed again after a reopening gets a new row.

Revision ID: 0112
Revises: 0111
Create Date: 2026-11-19
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0112"
down_revision: str | None = "0111"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

T = "writeback_outbox"
REVIEW = (
    "(review_id IS NOT NULL AND investigation_id IS NOT NULL"
    " AND closure_request_id IS NULL AND case_id IS NULL)"
)
SOURCE = f"{REVIEW} OR (review_id IS NULL AND investigation_id IS NULL AND case_id IS NOT NULL)"
OLD_SOURCE = (
    f"{REVIEW} OR (review_id IS NULL AND investigation_id IS NULL"
    " AND closure_request_id IS NOT NULL AND case_id IS NOT NULL)"
)


def upgrade() -> None:
    op.drop_constraint(op.f("ck_writeback_outbox_source_valid"), T, type_="check")
    op.create_check_constraint(op.f("ck_writeback_outbox_source_valid"), T, SOURCE)


def downgrade() -> None:
    # a dismissal's rows
    op.execute(
        "DELETE FROM writeback_outbox WHERE review_id IS NULL AND closure_request_id IS NULL"
    )
    op.drop_constraint(op.f("ck_writeback_outbox_source_valid"), T, type_="check")
    op.create_check_constraint(op.f("ck_writeback_outbox_source_valid"), T, OLD_SOURCE)
