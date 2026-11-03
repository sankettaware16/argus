"""One investigator run per pattern; raise by evidence.

``assessment_shares``: the investigations an investigator run stands for (its own and each other
investigation of the same pattern and local day), shown as "same pattern as ..."; display only.
``investigation_raises``: the generic flags found on an investigation's newest dossier; an
unreviewed investigation with a flag is in Needs attention. ``cases.cause`` gains ``raised``: a
suspected case ARGUS suggests from evidence across investigations.

Revision ID: 0047
Revises: 0046
Create Date: 2026-10-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0047"
down_revision: str | None = "0046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CAUSES = ("verdict", "proposal", "person", "watch")
SHARE_INSERT = "assessment_id, investigation_id, version, pattern, day"
RAISE_INSERT = "investigation_id, version, dossier_hash, flags"
RAISE_UPDATE = "version, dossier_hash, flags, evaluated_at"
WEB_GRANTS = (
    "GRANT SELECT ON assessment_shares TO argus_web",
    "GRANT SELECT ON investigation_raises TO argus_web",
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.drop_constraint(op.f("ck_cases_cause_valid"), "cases", type_="check")
    op.create_check_constraint(
        op.f("ck_cases_cause_valid"), "cases", _in("cause", (*CAUSES, "raised"))
    )
    op.create_table(
        "assessment_shares",
        sa.Column("assessment_id", sa.BigInteger(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.CheckConstraint(
            "pattern ~ '^[0-9a-f]{64}$'", name=op.f("ck_assessment_shares_pattern_valid")
        ),
        sa.CheckConstraint("version >= 0", name=op.f("ck_assessment_shares_version_valid")),
        sa.ForeignKeyConstraint(
            ["assessment_id"],
            ["assessments.id"],
            name=op.f("fk_assessment_shares_assessment_id_assessments"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_assessment_shares_investigation_id_investigations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "assessment_id", "investigation_id", "version", name=op.f("pk_assessment_shares")
        ),
    )
    op.create_index(
        op.f("ix_assessment_shares_pattern_day"), "assessment_shares", ["pattern", "day"]
    )
    op.create_index(
        op.f("ix_assessment_shares_investigation_id_version"),
        "assessment_shares",
        ["investigation_id", "version"],
    )
    op.create_table(
        "investigation_raises",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("dossier_hash", sa.Text(), nullable=False),
        sa.Column(
            "flags",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "evaluated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(flags) = 'array'", name=op.f("ck_investigation_raises_flags_is_array")
        ),
        sa.CheckConstraint("version >= 0", name=op.f("ck_investigation_raises_version_valid")),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_investigation_raises_investigation_id_investigations"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("investigation_id", name=op.f("pk_investigation_raises")),
    )
    op.execute(f"GRANT SELECT, INSERT ({SHARE_INSERT}) ON assessment_shares TO argus_runtime")
    op.execute(
        f"GRANT SELECT, INSERT ({RAISE_INSERT}), UPDATE ({RAISE_UPDATE})"
        " ON investigation_raises TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_table("investigation_raises")
    op.drop_index(
        op.f("ix_assessment_shares_investigation_id_version"), table_name="assessment_shares"
    )
    op.drop_index(op.f("ix_assessment_shares_pattern_day"), table_name="assessment_shares")
    op.drop_table("assessment_shares")
    op.drop_constraint(op.f("ck_cases_cause_valid"), "cases", type_="check")
    op.create_check_constraint(op.f("ck_cases_cause_valid"), "cases", _in("cause", CAUSES))
