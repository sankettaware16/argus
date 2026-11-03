"""The SIEM's tables carry a neutral name.

The earlier migrations now create ``siem_*`` (the ledger, the health state and probes, the
switches, the live sessions). A database made before the rename holds the same five tables under the
site's old prefix; this finds that prefix and renames them in place with every constraint, index,
sequence and trigger. A database made from the rewritten migrations is left alone. Downgrading is a
no-op.

Revision ID: 0064
Revises: 0063
Create Date: 2026-11-02
"""

from collections.abc import Sequence

from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0064"
down_revision: str | None = "0063"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(RENAME)


def downgrade() -> None:
    pass
