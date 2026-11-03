"""Outside look-ups for domain families (AR2c, D-168, D-170).

``outside_requests.purpose`` gains ``families``: the VirusTotal requests ARGUS makes for the
registered parent of a family of many names, and then for the family's first address. They have a
daily budget of their own (``outside.families_per_day``), counted from the ledger like the
prefetch's. Nothing else changes: the answers go in ``outside_lookups`` as before (a domain's
answer now also holds whether it is ranked among the popular sites, its registrar, name servers
and addresses, inside the same size cap), and no table is added, so no grant changes.

Downgrade: the family requests are counted as prefetch requests again (the ledger keeps no
indicator, so nothing else is lost).

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
