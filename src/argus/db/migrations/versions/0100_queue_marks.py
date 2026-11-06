"""A person's marks on the queue (P4-F UI v2, the spec's A1-A4 and A14)

``case_holds``: a person's "I'm checking" on a possible incident, with why and when it comes back
(one open hold per case). ``case_seen``: what each person last looked at of a case (the engine's
version and the case's), so "new since you last looked" is theirs. ``spot_checks``: a person's
answer to a spot-check of what ARGUS closed on its own. ``user_rounds``: when a person last said
"I'm caught up". ``report_sends``: a person's record that an incident report went to the CISO.

The web's login reads them and writes a person's own rows (the routes audit every write); the
runtime login holds the same (the presenter ends a hold on a material change), no DELETE.

Revision ID: 0100
Revises: 0070
Create Date: 2026-11-06
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0100"
down_revision: str | None = "0075"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

HOLD_ENDINGS = ("released", "replaced", "expired", "decided", "changed", "p1")
SPOT_KINDS = ("incident", "alert_group")
ANSWERS = ("right", "wrong", "cant_tell")
HOLD_INSERT = "case_id, user_id, reason, until, case_version"
HOLD_UPDATE = "ended_at, ended_why"
SEEN_INSERT = "case_id, user_id, engine_version, case_version, seen_at"
SEEN_UPDATE = "engine_version, case_version, seen_at"
SPOT_INSERT = "kind, target_id, user_id, answer, closed_as"
SPOT_UPDATE = "answer, closed_as, answered_at"
ROUND_INSERT = "user_id, caught_up_at"
ROUND_UPDATE = "caught_up_at"
SEND_INSERT = "case_id, report_version, sent_to, by_user_id"
TABLES = ("case_holds", "case_seen", "spot_checks", "user_rounds", "report_sends")


def _grants(role: str) -> tuple[str, ...]:
    return (
        f"GRANT SELECT, INSERT ({HOLD_INSERT}), UPDATE ({HOLD_UPDATE}) ON case_holds TO {role}",
        f"GRANT SELECT, INSERT ({SEEN_INSERT}), UPDATE ({SEEN_UPDATE}) ON case_seen TO {role}",
        f"GRANT SELECT, INSERT ({SPOT_INSERT}), UPDATE ({SPOT_UPDATE}) ON spot_checks TO {role}",
        f"GRANT SELECT, INSERT ({ROUND_INSERT}), UPDATE ({ROUND_UPDATE}) ON user_rounds TO {role}",
        f"GRANT SELECT, INSERT ({SEND_INSERT}) ON report_sends TO {role}",
    )


# what the doctor and the tests compare with ``roles.API_GRANTS``
WEB_GRANTS = _grants("argus_web")


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "case_holds",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_why", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "char_length(reason) BETWEEN 1 AND 300", name=op.f("ck_case_holds_reason_length")
        ),
        sa.CheckConstraint(
            "until > created_at AND until <= created_at + interval '15 days'",
            name=op.f("ck_case_holds_until_valid"),
        ),
        sa.CheckConstraint("case_version >= 1", name=op.f("ck_case_holds_version_valid")),
        sa.CheckConstraint(
            "(ended_at IS NULL) = (ended_why IS NULL)", name=op.f("ck_case_holds_ended_valid")
        ),
        sa.CheckConstraint(
            f"ended_why IS NULL OR {_in('ended_why', HOLD_ENDINGS)}",
            name=op.f("ck_case_holds_ended_why_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_holds_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_case_holds_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_holds")),
    )
    op.create_index(
        "uq_case_holds_open",
        "case_holds",
        ["case_id"],
        unique=True,
        postgresql_where=sa.text("ended_at IS NULL"),
    )
    op.create_index(op.f("ix_case_holds_user_id_ended_at"), "case_holds", ["user_id", "ended_at"])

    op.create_table(
        "case_seen",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("engine_version", sa.Integer(), nullable=True),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column(
            "seen_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "(engine_version IS NULL OR engine_version >= 1) AND case_version >= 1",
            name=op.f("ck_case_seen_versions_valid"),
        ),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], name=op.f("fk_case_seen_case_id_cases")),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], name=op.f("fk_case_seen_user_id_users")),
        sa.PrimaryKeyConstraint("case_id", "user_id", name=op.f("pk_case_seen")),
    )
    op.create_index(op.f("ix_case_seen_user_id_seen_at"), "case_seen", ["user_id", "seen_at"])

    op.create_table(
        "spot_checks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("target_id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("answer", sa.Text(), nullable=False),
        sa.Column("closed_as", sa.Text(), nullable=True),
        sa.Column(
            "answered_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(_in("kind", SPOT_KINDS), name=op.f("ck_spot_checks_kind_valid")),
        sa.CheckConstraint(_in("answer", ANSWERS), name=op.f("ck_spot_checks_answer_valid")),
        sa.CheckConstraint(
            "closed_as IS NULL OR char_length(closed_as) BETWEEN 1 AND 200",
            name=op.f("ck_spot_checks_closed_as_length"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_spot_checks_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_spot_checks")),
        sa.UniqueConstraint(
            "kind", "target_id", "user_id", name=op.f("uq_spot_checks_kind_target_id_user_id")
        ),
    )
    op.create_index(op.f("ix_spot_checks_answered_at"), "spot_checks", ["answered_at"])

    op.create_table(
        "user_rounds",
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column("caught_up_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_user_rounds_user_id_users")
        ),
        sa.PrimaryKeyConstraint("user_id", name=op.f("pk_user_rounds")),
    )

    op.create_table(
        "report_sends",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("report_version", sa.Integer(), nullable=False),
        sa.Column("sent_to", sa.Text(), nullable=False),
        sa.Column("by_user_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "sent_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint("report_version >= 1", name=op.f("ck_report_sends_version_valid")),
        sa.CheckConstraint("sent_to IN ('ciso')", name=op.f("ck_report_sends_sent_to_valid")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_report_sends_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["by_user_id"], ["users.id"], name=op.f("fk_report_sends_by_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_report_sends")),
    )
    op.create_index(op.f("ix_report_sends_case_id_id"), "report_sends", ["case_id", "id"])

    for grant in (*_grants("argus_runtime"), *WEB_GRANTS):
        op.execute(grant)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)
