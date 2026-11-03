"""The identity lane's own gate (Q-E1, plan §7.2): its reachability and overload state

- A new shared state ``identity`` in ``siem_state``: the identity lane's own gate, opened by
  its own requests finding the SIEM unreachable or overloaded (``argus.identity.reach``), never by
  the SIEM's health state or ARGUS's own key. The runtime role already reads and updates
  ``siem_state`` (0004); no new table, no new grant.

Revision ID: 0032
Revises: 0031
Create Date: 2026-10-23
"""

from collections.abc import Sequence

from alembic import op

from argus.db.siem_names import RENAME

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_STATES = "('health', 'budget', 'breaker', 'lanes', 'kibana', 'kibana_breaker')"
NEW_STATES = "('health', 'budget', 'breaker', 'lanes', 'kibana', 'kibana_breaker', 'identity')"


def upgrade() -> None:
    op.execute(RENAME)  # an old database's tables first (argus.db.siem_names)
    op.drop_constraint(op.f("ck_siem_state_name_valid"), "siem_state", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_state_name_valid"), "siem_state", f"name IN {NEW_STATES}"
    )
    op.execute("INSERT INTO siem_state (name) VALUES ('identity')")


def downgrade() -> None:
    op.execute("DELETE FROM siem_state WHERE name = 'identity'")
    op.drop_constraint(op.f("ck_siem_state_name_valid"), "siem_state", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_state_name_valid"), "siem_state", f"name IN {OLD_STATES}"
    )
