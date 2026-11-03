"""Outside look-ups for domain families.

``outside_requests.purpose`` gains ``families``: the VirusTotal requests ARGUS makes for the
registered parent of a family of many names, with a daily budget of their own
(``outside.families_per_day``). No table is added, so no grant changes. Downgrade: the family
requests are counted as prefetch requests again.

Revision ID: 0049
Revises: 0048
Create Date: 2026-10-28
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CONSTRAINT = "ck_outside_requests_purpose_valid"


def upgrade() -> None:
    op.drop_constraint(op.f(CONSTRAINT), "outside_requests", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT), "outside_requests", "purpose IN ('agent', 'prefetch', 'families')"
    )


def downgrade() -> None:
    op.execute("UPDATE outside_requests SET purpose = 'prefetch' WHERE purpose = 'families'")
    op.drop_constraint(op.f(CONSTRAINT), "outside_requests", type_="check")
    op.create_check_constraint(
        op.f(CONSTRAINT), "outside_requests", "purpose IN ('agent', 'prefetch')"
    )
