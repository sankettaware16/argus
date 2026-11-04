"""The web reads the Kibana read-back's cycles.

The status bar and the Health page show whether the read-back runs, from its newest cycle, so the
web's group role may read ``kibana_sync_cycles`` (nothing else of the read-back).

Revision ID: 0065
Revises: 0064
Create Date: 2026-11-04
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0065"
down_revision: str | None = "0064"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


WEB_GRANTS = ("GRANT SELECT ON kibana_sync_cycles TO argus_web",)


def upgrade() -> None:
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.execute("REVOKE SELECT ON kibana_sync_cycles FROM argus_web")
