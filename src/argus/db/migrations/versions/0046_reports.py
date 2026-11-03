"""The Reporter's history (Q-H3, plan §5 and §7.7).

``reports`` holds one row for each (kind, period): the numbers (``numbers``, every figure with
its definition), the deterministic text written from them (``text``) and, only when the optional
prose agent is switched on and its prose passed the number check, that prose (``prose``). A
period is a whole UTC day (``daily``) or seven whole UTC days (``weekly``), ending at
``period_end`` (exclusive); the CHECKs hold the shape and tie the kind and the period named in
``numbers`` to the columns, so a report cannot claim another kind or period. ``generated_at`` is
the database's clock (``now()``): the runtime cannot set it.

A report is a record, not a view: ``argus_runtime`` may INSERT and SELECT (no UPDATE, no DELETE),
so a report that was made stays as it was, and a second run for the same period is refused by the
unique key (the CLI says "already made"). The web's role reads it (SELECT) and writes nothing.

The role names are written out, not imported (see 0003).

Revision ID: 0046
Revises: 0045
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0046"
down_revision: str | None = "0045"  # Q-D5's 0045_alert_writeback publishes first
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = ("daily", "weekly")
INSERT = "kind, period_start, period_end, numbers, text, prose, prose_agent"
WEB_GRANTS = ("GRANT SELECT ON reports TO argus_web",)


def upgrade() -> None:
    op.create_table(
        "reports",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "generated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("numbers", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("text", sa.Text(), nullable=False),
        sa.Column("prose", sa.Text(), nullable=True),
        sa.Column("prose_agent", sa.Text(), nullable=True),
        sa.CheckConstraint("kind IN ('daily', 'weekly')", name=op.f("ck_reports_kind_valid")),
        sa.CheckConstraint(
            "(kind = 'daily' AND period_end = period_start + interval '1 day')"
            " OR (kind = 'weekly' AND period_end = period_start + interval '7 days')",
            name=op.f("ck_reports_period_valid"),
        ),
        sa.CheckConstraint(
            "(period_start AT TIME ZONE 'UTC')::time = '00:00'",
            name=op.f("ck_reports_period_is_utc_days"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(numbers) = 'object'", name=op.f("ck_reports_numbers_is_object")
        ),
        sa.CheckConstraint(
            "((numbers ->> 'kind') = kind"
            " AND (numbers ->> 'period_start')::timestamptz = period_start"
            " AND (numbers ->> 'period_end')::timestamptz = period_end) IS TRUE",
            name=op.f("ck_reports_numbers_match_period"),
        ),
        sa.CheckConstraint(
            "length(text) BETWEEN 1 AND 400000", name=op.f("ck_reports_text_length")
        ),
        sa.CheckConstraint(
            "(prose IS NULL) = (prose_agent IS NULL)"
            " AND (prose IS NULL OR length(prose) BETWEEN 1 AND 20000)",
            name=op.f("ck_reports_prose_complete"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
        sa.UniqueConstraint("kind", "period_end", name=op.f("uq_reports_kind_period_end")),
    )
    op.create_index(op.f("ix_reports_kind_period_end"), "reports", ["kind", "period_end"])
    op.execute(f"GRANT SELECT, INSERT ({INSERT}) ON reports TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.drop_index(op.f("ix_reports_kind_period_end"), table_name="reports")
    op.drop_table("reports")
