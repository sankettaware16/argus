"""Review fixes for the sign-ins: lookup failure reasons, and a report hash without accounts

``signin_lookups`` gains ``unnamed`` and ``store_failures`` and more ``reason`` values.
``incident_reports`` gains ``core_hash``: the hash without its ``users`` section, so a person's
confirm stays valid for a later version that differs only in the accounts.

Revision ID: 0057
Revises: 0056
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0057"
down_revision: str | None = "0056"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_REASONS = ("partial", "bad_answer", "logs_gone", "failed")
REASONS = (*OLD_REASONS, "store_failed", "unnamed_events", "index_missing")
NEW_LOOKUP_REASONS = REASONS[len(OLD_REASONS) :]


def _reasons(names: Sequence[str]) -> str:
    return ", ".join(f"'{r}'" for r in names)


def upgrade() -> None:
    op.add_column(
        "signin_lookups",
        sa.Column("unnamed", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "signin_lookups",
        sa.Column("store_failures", sa.SmallInteger(), server_default="0", nullable=False),
    )
    op.drop_constraint(op.f("ck_signin_lookups_reason_valid"), "signin_lookups", type_="check")
    op.create_check_constraint(
        op.f("ck_signin_lookups_reason_valid"),
        "signin_lookups",
        "(complete AND reason IS NULL AND unnamed = 0 AND store_failures = 0)"
        " OR (NOT complete AND reason IS NOT NULL AND reason IN ("
        + _reasons(REASONS)
        + ") AND accounts = 0 AND more_accounts = 0"
        " AND (unnamed >= 1) = (reason = 'unnamed_events')"
        " AND (store_failures = 0 OR reason = 'store_failed'))",
    )
    op.create_check_constraint(
        op.f("ck_signin_lookups_tries_valid"),
        "signin_lookups",
        "unnamed >= 0 AND store_failures >= 0",
    )
    op.execute(
        "GRANT INSERT (unnamed, store_failures), UPDATE (unnamed, store_failures)"
        " ON signin_lookups TO argus_runtime"
    )
    op.add_column("incident_reports", sa.Column("core_hash", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_incident_reports_core_hash_valid"),
        "incident_reports",
        "core_hash IS NULL OR core_hash ~ '^[0-9a-f]{64}$'",
    )
    op.execute("GRANT INSERT (core_hash) ON incident_reports TO argus_runtime")


def downgrade() -> None:
    op.drop_constraint(
        op.f("ck_incident_reports_core_hash_valid"), "incident_reports", type_="check"
    )
    op.drop_column("incident_reports", "core_hash")
    op.execute(f"DELETE FROM signin_lookups WHERE reason IN ({_reasons(NEW_LOOKUP_REASONS)})")  # noqa: S608
    op.drop_constraint(op.f("ck_signin_lookups_tries_valid"), "signin_lookups", type_="check")
    op.drop_constraint(op.f("ck_signin_lookups_reason_valid"), "signin_lookups", type_="check")
    op.drop_column("signin_lookups", "store_failures")
    op.drop_column("signin_lookups", "unnamed")
    op.create_check_constraint(
        op.f("ck_signin_lookups_reason_valid"),
        "signin_lookups",
        "(complete AND reason IS NULL)"
        " OR (NOT complete AND reason IS NOT NULL AND reason IN ("
        + _reasons(OLD_REASONS)
        + ") AND accounts = 0 AND more_accounts = 0)",
    )
