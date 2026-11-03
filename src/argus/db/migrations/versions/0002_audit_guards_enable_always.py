"""audit guard triggers fire in every session (ENABLE ALWAYS)

Ordinary triggers are skipped while ``session_replication_role = replica``, which a superuser can
set with no DDL. ENABLE ALWAYS makes the append-only guards fire anyway; ``argus doctor`` checks.

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-10
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_append_only_rows")
    op.execute("ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_append_only_truncate")


def downgrade() -> None:
    op.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only_truncate")
    op.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_append_only_rows")
