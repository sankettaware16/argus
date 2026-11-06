"""Inbound exposure and the checking lane (P4-F E3)

- The gateway's **checking lane**: the request ledger may name it, and it has its own kill switch
  (``checking``, stopped by services, resumed only by the owner, as every switch).
- ``exposure_checks``: what the checking lane found, one row per checked subject: which campus
  sites an outside address reached (``sites``), a site's answers to the probe paths against its
  not-found answers (``catchall``, the soft-404 check), what an outside address got for the
  paths it tried (``paths``) and whether it took many files under one sensitive prefix
  (``take``). Kept 180 days: the facts naming and the incident's "what ARGUS checked" read.
- The engine's lanes may be ``exposure`` (L5) besides decisive, burst and slow.

The runtime role inserts, reads and prunes the checks; the web reads them.

Revision ID: 0075
Revises: 0070
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0075"
down_revision: str | None = "0071"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OLD_SWITCHES = (
    "('global', 'collector', 'enrichment', 'kibana', 'writeback', 'investigation',"
    " 'freshness', 'cases', 'identity')"
)
NEW_SWITCHES = OLD_SWITCHES[:-1] + ", 'checking')"
OLD_LEDGER_LANES = (
    "('collector', 'investigation', 'freshness', 'kibana_read', 'kibana_write', 'identity',"
    " 'measurement')"
)
NEW_LEDGER_LANES = OLD_LEDGER_LANES[:-1] + ", 'checking')"
OLD_LANES = ("decisive", "burst", "slow")
NEW_LANES = (*OLD_LANES, "exposure")
KINDS = ("sites", "catchall", "paths", "take")
VERDICTS = (
    "found", "none", "soft_404", "plain", "served", "not_served", "bulk", "no_bulk", "unknown",
)  # fmt: skip
CHECK_INSERT = (
    "kind, source, site, day, template, template_version, task_key, verdict, facts, took_ms,"
    " checked_at"
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _array(values: Sequence[str]) -> str:
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]::text[]"


def _lanes(values: Sequence[str]) -> None:
    op.drop_constraint(op.f("ck_risk_objects_lanes_valid"), "risk_objects", type_="check")
    op.create_check_constraint(
        op.f("ck_risk_objects_lanes_valid"), "risk_objects", f"lanes <@ {_array(values)}"
    )
    op.drop_constraint(op.f("ck_risk_crossings_lane_valid"), "risk_crossings", type_="check")
    op.create_check_constraint(
        op.f("ck_risk_crossings_lane_valid"), "risk_crossings", _in("lane", values)
    )


def upgrade() -> None:
    op.drop_constraint(op.f("ck_siem_switches_component_valid"), "siem_switches", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_switches_component_valid"), "siem_switches", f"component IN {NEW_SWITCHES}"
    )
    op.execute("INSERT INTO siem_switches (component) VALUES ('checking')")
    op.drop_constraint(op.f("ck_siem_requests_lane_valid"), "siem_requests", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_requests_lane_valid"),
        "siem_requests",
        f"lane IS NULL OR lane IN {NEW_LEDGER_LANES}",
    )
    _lanes(NEW_LANES)

    op.create_table(
        "exposure_checks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("site", sa.Text(), nullable=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("template", sa.Text(), nullable=False),
        sa.Column("template_version", sa.Integer(), nullable=False),
        sa.Column("task_key", sa.Text(), nullable=True),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("facts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("took_ms", sa.Integer(), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_exposure_checks_kind_valid")),
        sa.CheckConstraint(_in("verdict", VERDICTS), name=op.f("ck_exposure_checks_verdict_valid")),
        sa.CheckConstraint(
            "(source IS NULL OR char_length(source) BETWEEN 2 AND 45)"
            " AND (site IS NULL OR char_length(site) BETWEEN 1 AND 600)"
            " AND (kind = 'catchall' OR source IS NOT NULL)"
            " AND (kind = 'sites' OR site IS NOT NULL)",
            name=op.f("ck_exposure_checks_subject_valid"),
        ),
        sa.CheckConstraint(
            "task_key IS NULL OR task_key ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_exposure_checks_task_key_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(facts) = 'object' AND octet_length(facts::text) <= 65536",
            name=op.f("ck_exposure_checks_facts_valid"),
        ),
        sa.CheckConstraint(
            "took_ms IS NULL OR took_ms >= 0", name=op.f("ck_exposure_checks_took_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exposure_checks")),
    )
    op.create_index(op.f("ix_exposure_checks_site_day"), "exposure_checks", ["site", "day"])
    op.create_index(op.f("ix_exposure_checks_source_day"), "exposure_checks", ["source", "day"])
    op.create_index(op.f("ix_exposure_checks_checked_at"), "exposure_checks", ["checked_at"])
    # The role names are written out, not imported (see 0003).
    op.execute(f"GRANT SELECT, DELETE, INSERT ({CHECK_INSERT}) ON exposure_checks TO argus_runtime")
    op.execute("GRANT SELECT ON exposure_checks TO argus_web")


def downgrade() -> None:
    op.drop_table("exposure_checks")
    op.execute("DELETE FROM risk_crossings WHERE lane NOT IN ('decisive', 'burst', 'slow')")
    op.execute(
        "UPDATE risk_objects SET lanes = ARRAY(SELECT x FROM unnest(lanes) AS x"
        " WHERE x IN ('decisive', 'burst', 'slow'))"
    )
    _lanes(OLD_LANES)
    op.drop_constraint(op.f("ck_siem_requests_lane_valid"), "siem_requests", type_="check")
    # the ledger is append-only: rows of the checking lane stay, so the old rule holds for new
    # rows only
    op.execute(
        "ALTER TABLE siem_requests ADD CONSTRAINT ck_siem_requests_lane_valid"
        f" CHECK (lane IS NULL OR lane IN {OLD_LEDGER_LANES}) NOT VALID"
    )
    op.execute("DELETE FROM siem_switches WHERE component = 'checking'")
    op.drop_constraint(op.f("ck_siem_switches_component_valid"), "siem_switches", type_="check")
    op.create_check_constraint(
        op.f("ck_siem_switches_component_valid"), "siem_switches", f"component IN {OLD_SWITCHES}"
    )
