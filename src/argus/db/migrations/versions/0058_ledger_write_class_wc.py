"""The request ledger accepts the case team's write class ``WC`` (AR8, D-195; D-231).

0029's check on ``siem_requests.write_class`` named W1, W2, W3, WA and WT; AR8 added the class in
code (``WriteClass.WC``) but not here, so the case team's first live write was sent and its ledger
row refused (2026-10-30).

Revision ID: 0058
Revises: 0057
Create Date: 2026-10-30
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0058"
down_revision: str | None = "0057"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

NAME = "ck_siem_requests_write_class_valid"


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.drop_constraint(op.f(NAME), "siem_requests", type_="check")
    op.create_check_constraint(
        op.f(NAME),
        "siem_requests",
        "write_class IS NULL OR write_class IN ('W1', 'W2', 'W3', 'WA', 'WT', 'WC')",
    )


def downgrade() -> None:
    sent = (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM siem_requests WHERE write_class = 'WC'"))
        .scalar_one()
    )
    if sent:  # the ledger is the record of what was sent: never lost to a downgrade
        raise RuntimeError(f"refused: {sent} ledger rows of class WC would no longer be valid")
    op.drop_constraint(op.f(NAME), "siem_requests", type_="check")
    op.create_check_constraint(
        op.f(NAME),
        "siem_requests",
        "write_class IS NULL OR write_class IN ('W1', 'W2', 'W3', 'WA', 'WT')",
    )
