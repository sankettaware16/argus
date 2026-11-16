"""The gateway's enrichment lane (D-321): the request ledger may name it

Enrichment (and the reference jobs, the measuring session and discovery) leave the collector's
lane for a lane of their own, carved out of the collector's share, so a burst of evidence never
refuses the collector's poll. The ledger's ``lane`` column may say ``enrichment``. Nothing else
changes in the schema: the lanes' buckets are one JSON row (``siem_state`` 'lanes'), where a lane
missing from the row starts full. No grant changes.

Revision ID: 0107
Revises: 0104
Create Date: 2026-11-16
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0107"
down_revision: str | None = "0104"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_LEDGER_LANES = (
    "('collector', 'investigation', 'freshness', 'kibana_read', 'kibana_write', 'identity',"
    " 'measurement', 'checking')"
)
NEW_LEDGER_LANES = OLD_LEDGER_LANES[:-1] + ", 'enrichment')"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_siem_requests_lane_valid"), "siem_requests", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_requests_lane_valid"),
        "siem_requests",
        f"lane IS NULL OR lane IN {NEW_LEDGER_LANES}",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("ck_siem_requests_lane_valid"), "siem_requests", type_="check")
    # the ledger is append-only: rows of the enrichment lane stay, so the old rule holds for new
    # rows only
    op.execute(
        "ALTER TABLE siem_requests ADD CONSTRAINT ck_siem_requests_lane_valid"
        f" CHECK (lane IS NULL OR lane IN {OLD_LEDGER_LANES}) NOT VALID"
    )
    # the older code knows no enrichment lane: its bucket leaves the stored lanes row
    op.execute(
        "UPDATE siem_state SET state = jsonb_set(jsonb_set(state, '{buckets}',"
        " coalesce(state->'buckets', '{}'::jsonb) - 'enrichment'), '{starts}',"
        " coalesce(state->'starts', '{}'::jsonb) - 'enrichment'), updated_at = now()"
        " WHERE name = 'lanes' AND state ? 'buckets'"
    )
