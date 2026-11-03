"""Minimal notices (Q-H4, plan §5 and §7.7, DQ26).

* ``notices``: what ARGUS remembers about each thing it may tell a person about, so that one
  notice goes out per (kind, subject) until the thing is resolved or its severity rises, a
  reminder at most once a day, one notice for an outage and one when it ends, and so that all of
  this survives a restart. A row holds a kind, an opaque subject (a case's or an investigation's
  id, or a fixed word), the severity and count now, when it was first and last seen, when it
  ended, and the last notice that went out for it. It holds no host, address, user or rule name.
  There is at most one live row (not resolved) per (kind, subject): a later occurrence of
  something resolved is a new row.

``argus_runtime`` reads the table and writes the columns the pass writes (it cannot delete a
row: the table keeps the record of what went out); the web's role gets nothing.

Revision ID: 0043
Revises: 0042
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0043"
down_revision: str | None = "0042"  # Q-B3's web case access
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

KINDS = ("case_active", "after_closure", "closure_waiting", "ioc_hit", "outage")
SEVERITIES = ("low", "medium", "high", "critical")
INSERT = "kind, subject, severity, count, first_seen, last_seen"
UPDATE = "severity, count, last_seen, resolved_at, sent_at, sent_severity, notified, ended_at"


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "notices",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_severity", sa.Text(), nullable=True),
        sa.Column("notified", sa.Integer(), server_default="0", nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_notices_kind_valid")),
        sa.CheckConstraint(
            "subject ~ '^[A-Za-z0-9:_.-]{1,64}$'", name=op.f("ck_notices_subject_valid")
        ),
        sa.CheckConstraint(_in("severity", SEVERITIES), name=op.f("ck_notices_severity_valid")),
        sa.CheckConstraint(
            f"sent_severity IS NULL OR {_in('sent_severity', SEVERITIES)}",
            name=op.f("ck_notices_sent_severity_valid"),
        ),
        sa.CheckConstraint("count >= 0", name=op.f("ck_notices_count_valid")),
        sa.CheckConstraint("last_seen >= first_seen", name=op.f("ck_notices_seen_valid")),
        sa.CheckConstraint(
            "resolved_at IS NULL OR resolved_at >= first_seen",
            name=op.f("ck_notices_resolved_valid"),
        ),
        sa.CheckConstraint(
            "(sent_at IS NULL) = (sent_severity IS NULL) AND (sent_at IS NULL) = (notified = 0)"
            " AND notified >= 0",
            name=op.f("ck_notices_sent_complete"),
        ),
        sa.CheckConstraint(
            "ended_at IS NULL OR (kind = 'outage' AND resolved_at IS NOT NULL"
            " AND sent_at IS NOT NULL AND ended_at >= resolved_at)",
            name=op.f("ck_notices_ended_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_notices")),
    )
    op.create_index(
        "uq_notices_live",
        "notices",
        ["kind", "subject"],
        unique=True,
        postgresql_where=sa.text("resolved_at IS NULL"),
    )
    op.execute(f"GRANT SELECT, INSERT ({INSERT}), UPDATE ({UPDATE}) ON notices TO argus_runtime")


def downgrade() -> None:
    op.drop_index(
        "uq_notices_live", table_name="notices", postgresql_where=sa.text("resolved_at IS NULL")
    )
    op.drop_table("notices")
