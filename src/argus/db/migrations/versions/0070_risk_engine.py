"""The incident engine v2's foundations, in shadow (P4-F E0 and E1)

``rules`` gains what the engine reads of a rule: a lineage a recreated rule keeps, its ATT&CK
tactics and their coarse stages, its index entries and the site's log family they name.

New tables, the engine's own (the queue, the suggester and the raises read none of them):
``risk_groups`` (an alert group as the engine last read it, and its digest category),
``risk_entities`` (its entities with a role: actor, target, threat, other), ``risk_objects``
(campus devices, accounts and sites), ``risk_observations`` (the scored facts on them),
``risk_sources`` (each source's label-free noise factor and probation), ``risk_object_scores``
(an object's score per window, with its breakdown) and ``risk_crossings`` (an object entering a
lane). The runtime role writes all of them and prunes them (``risk.keep_days``); the web reads
none yet.

Revision ID: 0070
Revises: 0065
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0070"
down_revision: str | None = "0065"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

OBJECT_KINDS = ("device", "account", "site")
ENTITY_KINDS = ("ip", "domain", "host", "user", "email", "url_pattern", "hash")
ROLES = ("actor", "target", "threat", "other")
DIRECTIONS = ("outbound", "inbound", "lateral", "unknown")
HELD = ("lane", "gray_band", "probation", "rules_only", "below", "target")
LANES = ("decisive", "burst", "slow")
WINDOWS = ("24h", "7d", "14d")
CATEGORIES = (
    "presented", "known_infection", "inbound_blocked", "inbound_attempt", "inbound_success",
    "gray_band", "probation", "rules_only", "outbound_low", "unattributed", "hub_activity",
)  # fmt: skip
RULE_META = "lineage, tactics, stage_mask, indices, family, meta_at"
OBJECT_INSERT = "kind, key, criticality, hub, hub_reason, first_seen, last_seen"
OBJECT_UPDATE = (
    "criticality, hub, hub_reason, last_seen, lanes, held, last_lane_at, item_at, scored_at"
)
GROUP_INSERT = (
    "investigation_id, version, signature, direction, day, at, alerts, outcome, known, kinds,"
    " category, observed_at, scored_at"
)
GROUP_UPDATE = (
    "version, signature, direction, day, at, alerts, outcome, known, kinds, category,"
    " observed_at, scored_at"
)
ENTITY_INSERT = "investigation_id, kind, value, role, fields"
OBSERVATION_INSERT = (
    "object_id, investigation_id, investigation_version, source_kind, source_key, role, at,"
    " day, base, outcome, prevalence, fidelity, score, stages, family, strong, threats, evidence"
)
OBSERVATION_UPDATE = "prevalence, fidelity, score"
SOURCE_COLUMNS = (
    "prevalence, fidelity, probation, objects_median, reach, credited_confirmed,"
    " credited_not_incident, computed_at"
)
SCORE_COLUMNS = (
    "score, sources, families, stages, active_days, strong, anchored, breakdown, computed_at"
)
CROSSING_INSERT = "object_id, lane, at, new_item, score, breakdown"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _array(values: Sequence[str]) -> str:
    return "ARRAY[" + ", ".join(f"'{v}'" for v in values) + "]::text[]"


EMPTY = sa.text("'{}'::text[]")


def upgrade() -> None:
    op.add_column("rules", sa.Column("lineage", sa.Text(), nullable=True))
    op.add_column("rules", sa.Column("tactics", postgresql.ARRAY(sa.Text()), nullable=True))
    op.add_column("rules", sa.Column("stage_mask", sa.SmallInteger(), nullable=True))
    op.add_column("rules", sa.Column("indices", postgresql.ARRAY(sa.Text()), nullable=True))
    op.add_column("rules", sa.Column("family", sa.Text(), nullable=True))
    op.add_column("rules", sa.Column("meta_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        op.f("ck_rules_stage_mask_valid"), "rules", "stage_mask BETWEEN 0 AND 15"
    )
    op.create_index(op.f("ix_rules_lineage"), "rules", ["lineage"])

    op.create_table(
        "risk_objects",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("criticality", sa.Double(), server_default="1", nullable=False),
        sa.Column("hub", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("hub_reason", sa.Text(), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("lanes", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.Column("held", sa.Text(), nullable=True),
        sa.Column("last_lane_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("item_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scored_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("kind", OBJECT_KINDS), name=op.f("ck_risk_objects_kind_valid")),
        sa.CheckConstraint(
            "char_length(key) BETWEEN 1 AND 600", name=op.f("ck_risk_objects_key_length")
        ),
        sa.CheckConstraint(
            "criticality > 0 AND criticality <= 4", name=op.f("ck_risk_objects_criticality_valid")
        ),
        sa.CheckConstraint(f"lanes <@ {_array(LANES)}", name=op.f("ck_risk_objects_lanes_valid")),
        sa.CheckConstraint(
            f"held IS NULL OR {_in('held', HELD)}", name=op.f("ck_risk_objects_held_valid")
        ),
        sa.CheckConstraint("first_seen <= last_seen", name=op.f("ck_risk_objects_seen_valid")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_objects")),
        sa.UniqueConstraint("kind", "key", name=op.f("uq_risk_objects_kind_key")),
    )
    op.create_index(op.f("ix_risk_objects_last_seen"), "risk_objects", ["last_seen"])

    op.create_table(
        "risk_groups",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("direction", sa.Text(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("alerts", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Double(), nullable=False),
        sa.Column("known", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("kinds", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.Column("category", sa.Text(), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("scored_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "signature ~ '^[0-9a-f]{32}$'", name=op.f("ck_risk_groups_signature_valid")
        ),
        sa.CheckConstraint(
            _in("direction", DIRECTIONS), name=op.f("ck_risk_groups_direction_valid")
        ),
        sa.CheckConstraint(
            "alerts >= 0 AND version >= 0", name=op.f("ck_risk_groups_counts_valid")
        ),
        sa.CheckConstraint(
            "outcome > 0 AND outcome <= 1", name=op.f("ck_risk_groups_outcome_valid")
        ),
        sa.CheckConstraint(
            f"category IS NULL OR {_in('category', CATEGORIES)}",
            name=op.f("ck_risk_groups_category_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_groups_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("investigation_id", name=op.f("pk_risk_groups")),
    )
    op.create_index(op.f("ix_risk_groups_day"), "risk_groups", ["day"])
    op.create_index(op.f("ix_risk_groups_at"), "risk_groups", ["at"])

    op.create_table(
        "risk_entities",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("fields", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.CheckConstraint(_in("kind", ENTITY_KINDS), name=op.f("ck_risk_entities_kind_valid")),
        sa.CheckConstraint(_in("role", ROLES), name=op.f("ck_risk_entities_role_valid")),
        sa.CheckConstraint(
            "char_length(value) BETWEEN 1 AND 512", name=op.f("ck_risk_entities_value_length")
        ),
        sa.CheckConstraint(
            "cardinality(fields) BETWEEN 1 AND 20", name=op.f("ck_risk_entities_fields_valid")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["risk_groups.investigation_id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_entities_investigation_id_risk_groups"),
        ),
        sa.PrimaryKeyConstraint(
            "investigation_id", "kind", "value", "role", name=op.f("pk_risk_entities")
        ),
    )
    op.create_index(op.f("ix_risk_entities_kind_value"), "risk_entities", ["kind", "value"])

    op.create_table(
        "risk_observations",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("object_id", sa.BigInteger(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("investigation_version", sa.Integer(), nullable=False),
        sa.Column("source_kind", sa.Text(), nullable=False),
        sa.Column("source_key", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("base", sa.Double(), nullable=False),
        sa.Column("outcome", sa.Double(), nullable=False),
        sa.Column("prevalence", sa.Double(), server_default="1", nullable=False),
        sa.Column("fidelity", sa.Double(), server_default="1", nullable=False),
        sa.Column("score", sa.Double(), nullable=False),
        sa.Column("stages", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("family", sa.Text(), nullable=True),
        sa.Column("strong", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("threats", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.Column("evidence", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.CheckConstraint(
            "source_kind IN ('rule', 'evidence')",
            name=op.f("ck_risk_observations_source_kind_valid"),
        ),
        sa.CheckConstraint(
            "char_length(source_key) BETWEEN 3 AND 200",
            name=op.f("ck_risk_observations_source_key_length"),
        ),
        sa.CheckConstraint(
            "role IN ('actor', 'target')", name=op.f("ck_risk_observations_role_valid")
        ),
        sa.CheckConstraint(
            "base > 0 AND outcome > 0 AND outcome <= 1 AND prevalence > 0 AND prevalence <= 1"
            " AND fidelity > 0 AND score >= 0",
            name=op.f("ck_risk_observations_factors_valid"),
        ),
        sa.CheckConstraint(
            "stages BETWEEN 0 AND 15", name=op.f("ck_risk_observations_stages_valid")
        ),
        sa.CheckConstraint(
            "cardinality(threats) <= 50 AND cardinality(evidence) <= 20",
            name=op.f("ck_risk_observations_lists_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_observations_object_id_risk_objects"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["risk_groups.investigation_id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_observations_investigation_id_risk_groups"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_observations")),
        sa.UniqueConstraint(
            "object_id",
            "source_key",
            "investigation_id",
            name=op.f("uq_risk_observations_object_id_source_key_investigation_id"),
        ),
    )
    op.create_index(op.f("ix_risk_observations_at"), "risk_observations", ["at"])
    op.create_index(
        op.f("ix_risk_observations_object_id_at"), "risk_observations", ["object_id", "at"]
    )
    op.create_index(
        op.f("ix_risk_observations_investigation_id"), "risk_observations", ["investigation_id"]
    )

    op.create_table(
        "risk_sources",
        sa.Column("source_key", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("prevalence", sa.Double(), server_default="1", nullable=False),
        sa.Column("fidelity", sa.Double(), server_default="1", nullable=False),
        sa.Column("probation", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("objects_median", sa.Double(), server_default="0", nullable=False),
        sa.Column("reach", sa.Integer(), server_default="0", nullable=False),
        sa.Column("credited_confirmed", sa.Double(), server_default="0", nullable=False),
        sa.Column("credited_not_incident", sa.Double(), server_default="0", nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("role IN ('actor', 'target')", name=op.f("ck_risk_sources_role_valid")),
        sa.CheckConstraint(
            "prevalence > 0 AND prevalence <= 1 AND fidelity >= 0.25 AND fidelity <= 1.5"
            " AND objects_median >= 0 AND reach >= 0 AND credited_confirmed >= 0"
            " AND credited_not_incident >= 0",
            name=op.f("ck_risk_sources_factors_valid"),
        ),
        sa.PrimaryKeyConstraint("source_key", "role", name=op.f("pk_risk_sources")),
    )

    op.create_table(
        "risk_object_scores",
        sa.Column("object_id", sa.BigInteger(), nullable=False),
        sa.Column("span", sa.Text(), nullable=False),
        sa.Column("score", sa.Double(), nullable=False),
        sa.Column("sources", sa.SmallInteger(), nullable=False),
        sa.Column("families", sa.SmallInteger(), nullable=False),
        sa.Column("stages", sa.SmallInteger(), nullable=False),
        sa.Column("active_days", sa.SmallInteger(), nullable=False),
        sa.Column("strong", sa.Boolean(), nullable=False),
        sa.Column("anchored", sa.Boolean(), nullable=False),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("computed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_in("span", WINDOWS), name=op.f("ck_risk_object_scores_span_valid")),
        sa.CheckConstraint(
            "score >= 0 AND sources >= 0 AND families >= 0 AND stages BETWEEN 0 AND 4"
            " AND active_days >= 0",
            name=op.f("ck_risk_object_scores_counts_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(breakdown) = 'array'",
            name=op.f("ck_risk_object_scores_breakdown_is_array"),
        ),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_object_scores_object_id_risk_objects"),
        ),
        sa.PrimaryKeyConstraint("object_id", "span", name=op.f("pk_risk_object_scores")),
    )

    op.create_table(
        "risk_crossings",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("object_id", sa.BigInteger(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("new_item", sa.Boolean(), nullable=False),
        sa.Column("score", sa.Double(), nullable=False),
        sa.Column("breakdown", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(_in("lane", LANES), name=op.f("ck_risk_crossings_lane_valid")),
        sa.CheckConstraint("score >= 0", name=op.f("ck_risk_crossings_score_valid")),
        sa.CheckConstraint(
            "jsonb_typeof(breakdown) = 'array'", name=op.f("ck_risk_crossings_breakdown_is_array")
        ),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_crossings_object_id_risk_objects"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_crossings")),
    )
    op.create_index(op.f("ix_risk_crossings_at"), "risk_crossings", ["at"])
    op.create_index(op.f("ix_risk_crossings_object_id_at"), "risk_crossings", ["object_id", "at"])

    op.execute(f"GRANT UPDATE ({RULE_META}) ON rules TO argus_runtime")
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({OBJECT_INSERT}), UPDATE ({OBJECT_UPDATE})"
        " ON risk_objects TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({GROUP_INSERT}), UPDATE ({GROUP_UPDATE})"
        " ON risk_groups TO argus_runtime"
    )
    op.execute(f"GRANT SELECT, DELETE, INSERT ({ENTITY_INSERT}) ON risk_entities TO argus_runtime")
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({OBSERVATION_INSERT}), UPDATE ({OBSERVATION_UPDATE})"
        " ON risk_observations TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT (source_key, role, {SOURCE_COLUMNS}),"
        f" UPDATE ({SOURCE_COLUMNS}) ON risk_sources TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT (object_id, span, {SCORE_COLUMNS}),"
        f" UPDATE ({SCORE_COLUMNS}) ON risk_object_scores TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({CROSSING_INSERT}) ON risk_crossings TO argus_runtime"
    )


def downgrade() -> None:
    for table in ("risk_crossings", "risk_object_scores", "risk_sources", "risk_observations",
                  "risk_entities", "risk_groups", "risk_objects"):  # fmt: skip
        op.drop_table(table)
    op.drop_index(op.f("ix_rules_lineage"), table_name="rules")
    op.drop_constraint(op.f("ck_rules_stage_mask_valid"), "rules", type_="check")
    for column in ("meta_at", "family", "indices", "stage_mask", "tactics", "lineage"):
        op.drop_column("rules", column)
