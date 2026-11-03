"""Reference data: rules registry, threat-intel mirror and lookup cache, knowledge store

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-13 14:06:30.007106
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "knowledge_items",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("scope", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("matcher", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("assertion", sa.Text(), nullable=False),
        sa.Column("guards", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("provenance", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "kind <> 'benign_pattern' OR expires_at IS NOT NULL",
            name=op.f("ck_knowledge_items_benign_expires"),
        ),
        sa.CheckConstraint(
            "kind IN ('benign_pattern', 'entity_note', 'context', 'false_positive')",
            name=op.f("ck_knowledge_items_kind_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('proposed', 'active', 'retired')",
            name=op.f("ck_knowledge_items_status_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_knowledge_items")),
        sa.UniqueConstraint("key", name=op.f("uq_knowledge_items_key")),
    )
    op.create_table(
        "rule_revisions",
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("note_hash", sa.Text(), nullable=False),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("rule_id", "revision", "note_hash", name=op.f("pk_rule_revisions")),
    )
    op.create_table(
        "rules",
        sa.Column("rule_id", sa.Text(), nullable=False),
        sa.Column("uuid", sa.Text(), nullable=True),
        sa.Column("name", sa.Text(), nullable=True),
        sa.Column("type", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=True),
        sa.Column("revision", sa.Integer(), nullable=True),
        sa.Column("interval", sa.Text(), nullable=True),
        sa.Column("lookback", sa.Text(), nullable=True),
        sa.Column("max_signals", sa.Integer(), nullable=True),
        sa.Column("severity", sa.Text(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("note_hash", sa.Text(), nullable=True),
        sa.Column("alerts", sa.Integer(), nullable=False),
        sa.Column("first_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_alert_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_execution_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("execution_status", sa.Text(), nullable=False),
        sa.Column("refreshed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "execution_status IN ('unknown', 'ok', 'failing', 'not_running')",
            name=op.f("ck_rules_execution_status_valid"),
        ),
        sa.CheckConstraint("alerts >= 0", name=op.f("ck_rules_alerts_valid")),
        sa.PrimaryKeyConstraint("rule_id", name=op.f("pk_rules")),
    )
    op.create_table(
        "ti_indicators",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("type_raw", sa.Text(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("confidence", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("synced_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('ip', 'domain', 'url', 'hash', 'email', 'other')",
            name=op.f("ck_ti_indicators_kind_valid"),
        ),
        sa.PrimaryKeyConstraint(
            "source", "kind", "value", "type_raw", name=op.f("pk_ti_indicators")
        ),
    )
    op.create_index(op.f("ix_ti_indicators_value"), "ti_indicators", ["value"], unique=False)
    op.create_table(
        "ti_lookups",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("indicators", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "jsonb_typeof(indicators) = 'array'", name=op.f("ck_ti_lookups_is_array")
        ),
        sa.PrimaryKeyConstraint("source", "value", name=op.f("pk_ti_lookups")),
    )
    op.create_table(
        "ti_sources",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("newest", sa.DateTime(timezone=True), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("indicators", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("source", name=op.f("pk_ti_sources")),
    )

    # The role name is written out, not imported (see 0003).
    op.execute(
        "GRANT SELECT, INSERT (rule_id, uuid, name, type, version, revision, interval, lookback,"
        " max_signals, severity, note, note_hash, alerts, first_alert_at, last_alert_at,"
        " last_execution_at, execution_status, refreshed_at), UPDATE (uuid, name, type,"
        " version, revision, interval, lookback, max_signals, severity, note, note_hash, alerts,"
        " first_alert_at, last_alert_at, last_execution_at, execution_status, refreshed_at)"
        " ON rules TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (rule_id, revision, note_hash, name, first_seen_at)"
        " ON rule_revisions TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (source, newest, checked_at, indicators, error), UPDATE (newest,"
        " checked_at, indicators, error) ON ti_sources TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (source, kind, value, type_raw, first_seen, last_seen, confidence,"
        " description, synced_at, removed_at), UPDATE (first_seen, last_seen, confidence,"
        " description, synced_at, removed_at) ON ti_indicators TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (source, value, indicators, checked_at), UPDATE (indicators,"
        " checked_at) ON ti_lookups TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (key, kind, scope, matcher, assertion, guards, provenance, status,"
        " expires_at, created_at), UPDATE (status, expires_at) ON knowledge_items TO"
        " argus_runtime"
    )


def downgrade() -> None:
    op.drop_table("ti_sources")
    op.drop_table("ti_lookups")
    op.drop_index(op.f("ix_ti_indicators_value"), table_name="ti_indicators")
    op.drop_table("ti_indicators")
    op.drop_table("rules")
    op.drop_table("rule_revisions")
    op.drop_table("knowledge_items")
