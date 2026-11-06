"""The incident engine v2's incidents, links and identity, in shadow (P4-F E2 and E4)

New tables, the engine's own: ``risk_incidents`` (a set of linked campus objects and the alert
groups on them, with its lifecycle: active, quiet, sealed or merged, its version and what
changed materially; ``case_id`` stays empty until the engine presents incidents as cases),
``risk_incident_objects`` and ``risk_incident_groups`` (its members), ``risk_links`` (why two
objects are in one incident, a sentence each; ``kept`` false: a recommendation past a cap),
``risk_threats`` (the outside things the engine saw flagged, and when the retro-hunt ran for
each) and ``risk_aliases`` (identity over time: a host name on an address, a likely account
behind a device). A GIN index on the observations' outside things makes the retro-hunt a join.
The runtime role writes and prunes all of them; the web reads none yet.

Revision ID: 0071
Revises: 0070
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0071"
down_revision: str | None = "0070"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATES = ("active", "quiet", "sealed", "merged")
VIAS = ("lane", "host", "account", "flagged", "campaign", "rare", "bare_ip")
INCIDENT_COLUMNS = (
    "state, created_at, first_seen, last_seen, updated_at, version, lanes, material,"
    " material_hash, material_at, changed, stop_proposed_at, campaign, parent_id, follows_id,"
    " merged_into, case_id, devices, groups, priority, band, view, recommended"
)
INCIDENT_UPDATE = (  # parent_id: a merge gives the gone incident's overflows to the kept one
    "state, first_seen, last_seen, updated_at, version, lanes, material, material_hash,"
    " material_at, changed, stop_proposed_at, campaign, parent_id, merged_into, case_id, devices,"
    " groups, priority, band, view, recommended"
)
LINK_INSERT = (
    "incident_id, a_object, b_object, via, value, priority, delta_seconds, reason, kept, created_at"
)
THREAT_COLUMNS = "flag_source, flagged_at, noticed_at, hunted_at, reach"
ALIAS_COLUMNS = "device, kind, value, valid_from, valid_to, source, confidence"
EMPTY = sa.text("'{}'::text[]")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "risk_incidents",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("lanes", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.Column("material", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("material_hash", sa.Text(), nullable=False),
        sa.Column("material_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("changed", postgresql.ARRAY(sa.Text()), server_default=EMPTY, nullable=False),
        sa.Column("stop_proposed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("campaign", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("parent_id", sa.BigInteger(), nullable=True),
        sa.Column("follows_id", sa.BigInteger(), nullable=True),
        sa.Column("merged_into", sa.BigInteger(), nullable=True),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("devices", sa.Integer(), server_default="0", nullable=False),
        sa.Column("groups", sa.Integer(), server_default="0", nullable=False),
        sa.Column("priority", sa.SmallInteger(), server_default="0", nullable=False),
        sa.Column("band", sa.Text(), server_default="P4", nullable=False),
        sa.Column("view", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("recommended", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.CheckConstraint(_in("state", STATES), name=op.f("ck_risk_incidents_state_valid")),
        sa.CheckConstraint(
            "version >= 1 AND devices >= 0 AND groups >= 0 AND priority BETWEEN 0 AND 100",
            name=op.f("ck_risk_incidents_counts_valid"),
        ),
        sa.CheckConstraint(
            "band IN ('P1', 'P2', 'P3', 'P4')", name=op.f("ck_risk_incidents_band_valid")
        ),
        sa.CheckConstraint("first_seen <= last_seen", name=op.f("ck_risk_incidents_seen_valid")),
        sa.CheckConstraint(
            "material_hash ~ '^[0-9a-f]{32}$'", name=op.f("ck_risk_incidents_hash_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(material) = 'object' AND jsonb_typeof(view) = 'object'"
            " AND jsonb_typeof(recommended) = 'array'",
            name=op.f("ck_risk_incidents_json_valid"),
        ),
        sa.CheckConstraint(
            "(state = 'merged') = (merged_into IS NOT NULL)",
            name=op.f("ck_risk_incidents_merged_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incidents_parent_id_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["follows_id"],
            ["risk_incidents.id"],
            ondelete="SET NULL",
            name=op.f("fk_risk_incidents_follows_id_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["merged_into"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incidents_merged_into_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["cases.id"],
            ondelete="SET NULL",
            name=op.f("fk_risk_incidents_case_id_cases"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_incidents")),
    )
    op.create_index(op.f("ix_risk_incidents_state"), "risk_incidents", ["state"])
    op.create_index(op.f("ix_risk_incidents_last_seen"), "risk_incidents", ["last_seen"])
    op.create_index(op.f("ix_risk_incidents_parent_id"), "risk_incidents", ["parent_id"])

    op.create_table(
        "risk_incident_objects",
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("object_id", sa.BigInteger(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('actor', 'affected')", name=op.f("ck_risk_incident_objects_role_valid")
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incident_objects_incident_id_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incident_objects_object_id_risk_objects"),
        ),
        sa.PrimaryKeyConstraint("incident_id", "object_id", name=op.f("pk_risk_incident_objects")),
    )
    op.create_index(
        op.f("ix_risk_incident_objects_object_id"), "risk_incident_objects", ["object_id"]
    )

    op.create_table(
        "risk_incident_groups",
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("joined_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incident_groups_incident_id_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_incident_groups_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint(
            "incident_id", "investigation_id", name=op.f("pk_risk_incident_groups")
        ),
    )
    op.create_index(
        op.f("ix_risk_incident_groups_investigation_id"), "risk_incident_groups",
        ["investigation_id"],
    )  # fmt: skip

    op.create_table(
        "risk_links",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("incident_id", sa.BigInteger(), nullable=False),
        sa.Column("a_object", sa.BigInteger(), nullable=False),
        sa.Column("b_object", sa.BigInteger(), nullable=True),
        sa.Column("via", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("priority", sa.SmallInteger(), nullable=False),
        sa.Column("delta_seconds", sa.Integer(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("kept", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("removed_by", sa.Text(), nullable=True),
        sa.Column("removed_why", sa.Text(), nullable=True),
        sa.CheckConstraint(_in("via", VIAS), name=op.f("ck_risk_links_via_valid")),
        sa.CheckConstraint(
            "char_length(reason) BETWEEN 1 AND 200", name=op.f("ck_risk_links_reason_length")
        ),
        sa.CheckConstraint(
            "char_length(value) BETWEEN 1 AND 600 AND priority BETWEEN 0 AND 9"
            " AND delta_seconds >= 0",
            name=op.f("ck_risk_links_values_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["risk_incidents.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_links_incident_id_risk_incidents"),
        ),
        sa.ForeignKeyConstraint(
            ["a_object"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_links_a_object_risk_objects"),
        ),
        sa.ForeignKeyConstraint(
            ["b_object"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_links_b_object_risk_objects"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_links")),
    )
    op.create_index(op.f("ix_risk_links_incident_id"), "risk_links", ["incident_id"])

    op.create_table(
        "risk_threats",
        sa.Column("threat", sa.Text(), nullable=False),
        sa.Column("flag_source", sa.Text(), nullable=False),
        sa.Column("flagged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("noticed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("hunted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reach", sa.Integer(), server_default="0", nullable=False),
        sa.CheckConstraint(
            "char_length(threat) BETWEEN 3 AND 600", name=op.f("ck_risk_threats_threat_length")
        ),
        sa.CheckConstraint(
            "flag_source IN ('outside', 'ti', 'operator', 'campaign', 'person')",
            name=op.f("ck_risk_threats_flag_source_valid"),
        ),
        sa.CheckConstraint("reach >= 0", name=op.f("ck_risk_threats_reach_valid")),
        sa.PrimaryKeyConstraint("threat", name=op.f("pk_risk_threats")),
    )
    op.create_index(op.f("ix_risk_threats_noticed_at"), "risk_threats", ["noticed_at"])

    op.create_table(
        "risk_aliases",
        sa.Column("device", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("confidence", sa.Text(), nullable=False),
        sa.CheckConstraint("kind IN ('host', 'account')", name=op.f("ck_risk_aliases_kind_valid")),
        sa.CheckConstraint(
            "source IN ('alert', 'signin', 'asset_map', 'person')",
            name=op.f("ck_risk_aliases_source_valid"),
        ),
        sa.CheckConstraint(
            "confidence IN ('certain', 'likely')", name=op.f("ck_risk_aliases_confidence_valid")
        ),
        sa.CheckConstraint(
            "valid_from <= valid_to AND char_length(device) BETWEEN 1 AND 600"
            " AND char_length(value) BETWEEN 1 AND 600",
            name=op.f("ck_risk_aliases_values_valid"),
        ),
        sa.PrimaryKeyConstraint(
            "device", "kind", "value", "valid_from", name=op.f("pk_risk_aliases")
        ),
    )
    op.create_index(op.f("ix_risk_aliases_valid_to"), "risk_aliases", ["valid_to"])

    op.create_index(
        op.f("ix_risk_observations_threats"), "risk_observations", ["threats"],
        postgresql_using="gin",
    )  # fmt: skip

    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({INCIDENT_COLUMNS}), UPDATE ({INCIDENT_UPDATE})"
        " ON risk_incidents TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, DELETE, INSERT (incident_id, object_id, role, joined_at),"
        " UPDATE (incident_id, role) ON risk_incident_objects TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, DELETE, INSERT (incident_id, investigation_id, joined_at),"
        " UPDATE (incident_id) ON risk_incident_groups TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({LINK_INSERT}),"
        " UPDATE (incident_id, kept, removed_at, removed_by, removed_why)"
        " ON risk_links TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT (threat, {THREAT_COLUMNS}), UPDATE ({THREAT_COLUMNS})"
        " ON risk_threats TO argus_runtime"
    )
    op.execute(
        f"GRANT SELECT, DELETE, INSERT ({ALIAS_COLUMNS}), UPDATE (valid_to)"
        " ON risk_aliases TO argus_runtime"
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_risk_observations_threats"), table_name="risk_observations")
    for table in ("risk_aliases", "risk_threats", "risk_links", "risk_incident_groups",
                  "risk_incident_objects", "risk_incidents"):  # fmt: skip
        op.drop_table(table)
