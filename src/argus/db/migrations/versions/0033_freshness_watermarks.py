"""Watermarks and verified zeros (Q-F1, plan §7.3 point 1): readings, watermarks, the shadow

- ``freshness_readings``: every freshness-lane reading of a log source (the newest document
  by ingest time, or why there was none). The runtime role reads and adds rows; it may not
  change or delete them.
- ``freshness_watermarks``: each source's newest ingest time seen. The runtime role adds and
  updates rows; a trigger refuses any update that moves a watermark back (ENABLE ALWAYS, and
  ``argus doctor`` checks it like the other guards).
- ``freshness_shadow``: the verdict a log zero gets, one row per investigation version, pack
  and signal (replaced when the signal is derived again); ``freshness_proposals``: what an
  assessor would propose with the shadow's verified zeros. The web's role gets nothing on
  either, so no page and no API can show them (plan §3 rule 12).
- ``evidence.asked_at``: when the gateway was asked for the evidence; a copy for a later
  version keeps the original's (a verified zero needs a reading from before the search).

Revision ID: 0033
Revises: 0032
Create Date: 2026-10-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported (see 0003).
READING_COLUMNS = "source, sent_at, at, outcome, reason, ingested, event_at, health, took_ms"
WATERMARK_COLUMNS = "source, ingested, event_at, read_at"
WATERMARK_UPDATE = "ingested, event_at, read_at"
SHADOW_COLUMNS = (
    "investigation_id, version, pack, signal, mode, verdict, reason, bridged_verdict,"
    " complete_to, refs, margins, decided_at"
)
SHADOW_UPDATE = "mode, verdict, reason, bridged_verdict, complete_to, refs, margins, decided_at"
PROPOSAL_COLUMNS = (
    "investigation_id, version, pack, dossier_hash, assessor, bridged, outcome, actual,"
    " signals, reasons"
)
SOURCE = "source ~ '^[a-z][a-z0-9_]{0,31}$'"

ADVANCE_FN = """
CREATE FUNCTION argus_watermark_advance() RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.source IS DISTINCT FROM OLD.source OR NEW.ingested < OLD.ingested THEN
        RAISE EXCEPTION 'a watermark only advances (%)', OLD.source
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$
"""


def upgrade() -> None:
    op.add_column("evidence", sa.Column("asked_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        "freshness_readings",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("ingested", sa.DateTime(timezone=True), nullable=True),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("health", sa.Text(), nullable=True),
        sa.Column("took_ms", sa.Integer(), nullable=True),
        sa.CheckConstraint(SOURCE, name=op.f("ck_freshness_readings_source_valid")),
        sa.CheckConstraint(
            "outcome IN ('ok', 'empty', 'refused', 'failed')",
            name=op.f("ck_freshness_readings_outcome_valid"),
        ),
        sa.CheckConstraint(
            "(outcome = 'ok') = (ingested IS NOT NULL AND event_at IS NOT NULL)",
            name=op.f("ck_freshness_readings_document_when_ok"),
        ),
        sa.CheckConstraint(
            "ingested IS NULL = (event_at IS NULL)",
            name=op.f("ck_freshness_readings_times_together"),
        ),
        sa.CheckConstraint("at >= sent_at", name=op.f("ck_freshness_readings_answered_after_sent")),
        sa.CheckConstraint(
            "reason IS NULL OR length(reason) <= 200",
            name=op.f("ck_freshness_readings_reason_short"),
        ),
        sa.CheckConstraint(
            "took_ms IS NULL OR took_ms >= 0", name=op.f("ck_freshness_readings_took_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_freshness_readings")),
    )
    op.create_index(op.f("ix_freshness_readings_source_at"), "freshness_readings", ["source", "at"])
    op.create_table(
        "freshness_watermarks",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("ingested", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(SOURCE, name=op.f("ck_freshness_watermarks_source_valid")),
        sa.PrimaryKeyConstraint("source", name=op.f("pk_freshness_watermarks")),
    )
    op.execute(ADVANCE_FN)
    op.execute(
        "CREATE TRIGGER freshness_watermarks_advance BEFORE UPDATE ON freshness_watermarks"
        " FOR EACH ROW EXECUTE FUNCTION argus_watermark_advance()"
    )
    op.execute(
        "ALTER TABLE freshness_watermarks ENABLE ALWAYS TRIGGER freshness_watermarks_advance"
    )
    op.create_table(
        "freshness_shadow",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("pack", sa.Text(), nullable=False),
        sa.Column("signal", sa.Text(), nullable=False),
        sa.Column("mode", sa.Text(), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("bridged_verdict", sa.Text(), nullable=False),
        sa.Column("complete_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("refs", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("margins", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("mode IN ('shadow', 'on')", name=op.f("ck_freshness_shadow_mode_valid")),
        sa.CheckConstraint(
            "verdict IN ('known_zero', 'could_not_tell')",
            name=op.f("ck_freshness_shadow_verdict_valid"),
        ),
        sa.CheckConstraint(
            "bridged_verdict IN ('known_zero', 'could_not_tell')",
            name=op.f("ck_freshness_shadow_bridged_valid"),
        ),
        sa.CheckConstraint(
            "verdict = 'could_not_tell' OR bridged_verdict = 'known_zero'",
            name=op.f("ck_freshness_shadow_bridge_never_loses"),
        ),
        sa.CheckConstraint(
            "(complete_to IS NOT NULL) = (bridged_verdict = 'known_zero')",
            name=op.f("ck_freshness_shadow_complete_to_when_known"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(refs) = 'array'", name=op.f("ck_freshness_shadow_refs_is_array")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(margins) = 'object'", name=op.f("ck_freshness_shadow_margins_is_object")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_freshness_shadow_investigation_id_investigations"),
            ondelete="CASCADE",  # the retention purge removes the investigation (review F1)
        ),
        sa.PrimaryKeyConstraint(
            "investigation_id", "version", "pack", "signal", name=op.f("pk_freshness_shadow")
        ),
    )
    op.create_table(
        "freshness_proposals",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column(
            "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("pack", sa.Text(), nullable=False),
        sa.Column("dossier_hash", sa.Text(), nullable=False),
        sa.Column("assessor", sa.Text(), nullable=False),
        sa.Column("bridged", sa.Boolean(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column("actual", sa.Text(), nullable=True),
        sa.Column("signals", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(
            "dossier_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_freshness_proposals_hash_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(signals) = 'array'", name=op.f("ck_freshness_proposals_signals_is_array")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reasons) = 'array'", name=op.f("ck_freshness_proposals_reasons_is_array")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_freshness_proposals_investigation_id_investigations"),
            ondelete="CASCADE",  # the retention purge removes the investigation (review F1)
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_freshness_proposals")),
    )
    op.create_index(
        op.f("ix_freshness_proposals_investigation_id_dossier_hash_assessor_bridged"),
        "freshness_proposals",
        ["investigation_id", "dossier_hash", "assessor", "bridged"],
        unique=True,
    )
    op.execute("GRANT INSERT (asked_at), UPDATE (asked_at) ON evidence TO argus_runtime")
    op.execute(f"GRANT SELECT, INSERT ({READING_COLUMNS}) ON freshness_readings TO argus_runtime")
    op.execute(
        f"GRANT SELECT, INSERT ({WATERMARK_COLUMNS}), UPDATE ({WATERMARK_UPDATE})"
        " ON freshness_watermarks TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, INSERT ({SHADOW_COLUMNS}), UPDATE ({SHADOW_UPDATE})"
        " ON freshness_shadow TO argus_runtime"
    )
    op.execute(f"GRANT SELECT, INSERT ({PROPOSAL_COLUMNS}) ON freshness_proposals TO argus_runtime")


def downgrade() -> None:
    op.drop_index(
        op.f("ix_freshness_proposals_investigation_id_dossier_hash_assessor_bridged"),
        table_name="freshness_proposals",
    )
    op.drop_table("freshness_proposals")
    op.drop_table("freshness_shadow")
    op.execute("DROP TRIGGER freshness_watermarks_advance ON freshness_watermarks")
    op.drop_table("freshness_watermarks")
    op.execute("DROP FUNCTION argus_watermark_advance()")
    op.drop_index(op.f("ix_freshness_readings_source_at"), table_name="freshness_readings")
    op.drop_table("freshness_readings")
    op.drop_column("evidence", "asked_at")
