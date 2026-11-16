"""``risk_mode``'s id loses the sequence 0095 gave it: a one-row table needs none.

0095 made ``risk_mode`` (one row, ``CHECK (id = 1)``, written with id 1 by the presenter) with
``op.create_table``, which gave its small integer key a sequence it never draws from. A restore
compares each owned sequence with its column: next 1, highest 1, so the weekly drill failed on
it. The default and the sequence go, as ``kibana_sync_state`` never had them (D-322).

Revision ID: 0097
Revises: 0096
Create Date: 2026-11-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0097"
down_revision: str | None = "0096"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE risk_mode ALTER COLUMN id DROP DEFAULT")
    op.execute("DROP SEQUENCE risk_mode_id_seq")


def downgrade() -> None:
    op.execute("CREATE SEQUENCE risk_mode_id_seq AS smallint OWNED BY risk_mode.id")
    op.execute(
        "ALTER TABLE risk_mode ALTER COLUMN id SET DEFAULT nextval('risk_mode_id_seq'::regclass)"
    )
