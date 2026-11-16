"""The incident engine's presenter (P4-F E5) on the linker's incidents, and the switch

``risk_incidents`` gains what the presenter adds to the linker's incident: its title, the
certainty word, whether the capacity governor has shown it (and on which day), when it was last
queued for a person, whether the AI raised it, and what a person was last shown of it
(``presented``: the material at that time, for the "not an incident" memory of a closed case).
``risk_gray_items``: the gray band, one row per campus object just under a lane, with its
priority and view (Today shows five). ``risk_mode``: one row, whether the engine presents its
incidents as cases (``risk.present``), as the last pass saw the setting; the queue's pages read
it, so the old raise stops feeding Needs attention when it is on.

The runtime role writes them; the web reads the incidents, their alert groups, the gray band,
the switch and the engine's digest (``risk_groups``) for the Today page and the queue.

Revision ID: 0095
Revises: 0075
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0095"
down_revision: str | None = "0100"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

LANES = ("decisive", "burst", "slow", "campaign", "exposure")
CERTAINTY = ("Confirmed", "Likely", "Suspected", "Unclear", "Likely harmless")
PRESENT_COLUMNS = (
    "title, certainty, shown, shown_day, queued_at, raised_by_ai, presented, presented_at"
)
GRAY_COLUMNS = "priority, band, lane, certainty, title, view, first_seen, last_seen, updated_at"
WEB_READS = ("risk_incidents", "risk_incident_groups", "risk_gray_items", "risk_mode",
             "risk_groups")  # fmt: skip
WEB_GRANTS = tuple(f"GRANT SELECT ON {t} TO argus_web" for t in WEB_READS)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.add_column("risk_incidents", sa.Column("title", sa.Text(), nullable=True))
    op.add_column(
        "risk_incidents",
        sa.Column("certainty", sa.Text(), server_default="Unclear", nullable=False),
    )
    op.add_column(
        "risk_incidents", sa.Column("shown", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("risk_incidents", sa.Column("shown_day", sa.Date(), nullable=True))
    op.add_column(
        "risk_incidents", sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "risk_incidents",
        sa.Column("raised_by_ai", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "risk_incidents",
        sa.Column(
            "presented",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
    )
    op.add_column(
        "risk_incidents", sa.Column("presented_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.create_check_constraint(
        op.f("ck_risk_incidents_certainty_valid"), "risk_incidents", _in("certainty", CERTAINTY)
    )
    op.create_check_constraint(
        op.f("ck_risk_incidents_title_length"), "risk_incidents",
        "title IS NULL OR char_length(title) BETWEEN 1 AND 200",
    )  # fmt: skip
    op.create_check_constraint(
        op.f("ck_risk_incidents_presented_is_object"), "risk_incidents",
        "jsonb_typeof(presented) = 'object'",
    )  # fmt: skip
    op.create_index(op.f("ix_risk_incidents_shown_day"), "risk_incidents", ["shown_day"])
    op.create_index(op.f("ix_risk_incidents_case_id"), "risk_incidents", ["case_id"])

    op.create_table(
        "risk_gray_items",
        sa.Column("object_id", sa.BigInteger(), nullable=False),
        sa.Column("priority", sa.SmallInteger(), nullable=False),
        sa.Column("band", sa.Text(), nullable=False),
        sa.Column("lane", sa.Text(), nullable=True),
        sa.Column("certainty", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("view", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "priority BETWEEN 0 AND 100", name=op.f("ck_risk_gray_items_priority_valid")
        ),
        sa.CheckConstraint(
            "band IN ('P1', 'P2', 'P3', 'P4')", name=op.f("ck_risk_gray_items_band_valid")
        ),
        sa.CheckConstraint(
            f"lane IS NULL OR {_in('lane', LANES)}", name=op.f("ck_risk_gray_items_lane_valid")
        ),
        sa.CheckConstraint(
            _in("certainty", CERTAINTY), name=op.f("ck_risk_gray_items_certainty_valid")
        ),
        sa.CheckConstraint(
            "char_length(title) BETWEEN 1 AND 200", name=op.f("ck_risk_gray_items_title_length")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(view) = 'object'", name=op.f("ck_risk_gray_items_view_is_object")
        ),
        sa.CheckConstraint("first_seen <= last_seen", name=op.f("ck_risk_gray_items_seen_valid")),
        sa.ForeignKeyConstraint(
            ["object_id"],
            ["risk_objects.id"],
            ondelete="CASCADE",
            name=op.f("fk_risk_gray_items_object_id_risk_objects"),
        ),
        sa.PrimaryKeyConstraint("object_id", name=op.f("pk_risk_gray_items")),
    )
    op.create_index(op.f("ix_risk_gray_items_priority"), "risk_gray_items", ["priority"])

    op.create_table(
        "risk_mode",
        sa.Column("id", sa.SmallInteger(), nullable=False),
        sa.Column("present", sa.Boolean(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id = 1", name=op.f("ck_risk_mode_one_row")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_risk_mode")),
    )

    op.execute(f"GRANT UPDATE ({PRESENT_COLUMNS}) ON risk_incidents TO argus_runtime")
    op.execute(
        f"GRANT SELECT, DELETE, INSERT (object_id, {GRAY_COLUMNS}), UPDATE ({GRAY_COLUMNS})"
        " ON risk_gray_items TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (id, present, at), UPDATE (present, at) ON risk_mode TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    for table in WEB_READS:
        if table not in ("risk_gray_items", "risk_mode"):  # those are dropped with their tables
            op.execute(f"REVOKE SELECT ON {table} FROM argus_web")  # noqa: S608 - constant names
    op.drop_table("risk_mode")
    op.drop_table("risk_gray_items")
    op.drop_index(op.f("ix_risk_incidents_case_id"), table_name="risk_incidents")
    op.drop_index(op.f("ix_risk_incidents_shown_day"), table_name="risk_incidents")
    for name in ("certainty_valid", "title_length", "presented_is_object"):
        op.drop_constraint(op.f(f"ck_risk_incidents_{name}"), "risk_incidents", type_="check")
    for column in ("presented_at", "presented", "raised_by_ai", "queued_at", "shown_day", "shown",
                   "certainty", "title"):  # fmt: skip
        op.drop_column("risk_incidents", column)
