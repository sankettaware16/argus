# ruff: noqa: S608 - the f-strings put fixed table and column names in the SQL
"""Alert status write-back v2 (Q-D5, plan §5 and §7.10, DQ8 and DQ11).

``writeback_outbox`` (R17, 0013 and 0014) gets what a sender that checks Kibana's answer and
reads every alert back needs:

* ``previous``: the status each alert had before ARGUS changed it (kept, never rewritten);
* ``written_count``: the alerts Kibana changed and the read-back confirmed, at most
  ``sent_count`` (the position in ``alert_ids``; an alert already at the target or gone from
  Kibana moves the position without a write);
* ``needs_operator`` and ``operator``: a review made without an ELK check that showed alert-write
  is sent only in a terminal run whose operator signed in with their own ELK account; a row
  that needs one cannot move without the operator's name;
* ``held``: a benign verdict that rests on Q-F1's "nothing found" waits for the audit (DQ11).
  Both flags are a cache the writer fills in: the sender derives them from ``review_events``,
  ``users`` and ``freshness_shadow`` before every request, so the runtime may not write them
  (Q-D5 review, finding 2);
* ``case_id`` and ``closure_request_id``: an approved case closure also closes its alerts, one
  row per closure; such a row has no review and no investigation (``source_valid`` keeps the
  two kinds apart).

Grants: the runtime plans (INSERT of what a plan chooses: the alerts and the source, not the
flags) and supersedes (its R17 UPDATEs are unchanged); the columns that record a send
(``written_count``, ``previous``, ``operator``, and the flags' cache) are the writer's alone. The
writer's login, the only one that holds the alert writer's key, moves the rows and reads, before
each request, the columns of ``review_events`` and ``freshness_shadow`` that say whether the row
may still go out (``argus.db.roles.WRITER_GRANTS``); not the notes.

Revision ID: 0045
Revises: 0044
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0045"
down_revision: str | None = "0044"  # Q-H2's case actions (published first)
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

T = "writeback_outbox"
CHECKS = {
    "written_count_in_range": "written_count BETWEEN 0 AND sent_count",
    "source_valid": (
        "(review_id IS NOT NULL AND investigation_id IS NOT NULL"
        " AND closure_request_id IS NULL AND case_id IS NULL)"
        " OR (review_id IS NULL AND investigation_id IS NULL"
        " AND closure_request_id IS NOT NULL AND case_id IS NOT NULL)"
    ),
    "held_valid": "held IS NULL OR held = 'f1_zeros'",
    "previous_object": "jsonb_typeof(previous) = 'object'",
    "operator_named": "NOT needs_operator OR sent_count = 0 OR operator IS NOT NULL",
}
RUNTIME_INSERT = "case_id, closure_request_id"
WRITER_UPDATE = (
    "state, sent_at, error, sent_count, written_count, previous, operator, needs_operator, held"
)
REVIEW_COLUMNS = "id, investigation_id, action, outcome, kibana_ok, user_id, created_at"
F1_COLUMNS = "investigation_id, mode, verdict"


def upgrade() -> None:
    op.add_column(T, sa.Column("case_id", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column(T, sa.Column("closure_request_id", sa.BigInteger(), nullable=True))
    op.add_column(T, sa.Column("written_count", sa.Integer(), server_default="0", nullable=False))
    op.add_column(
        T,
        sa.Column(
            "previous",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.add_column(
        T, sa.Column("needs_operator", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column(T, sa.Column("operator", sa.Text(), nullable=True))
    op.add_column(T, sa.Column("held", sa.Text(), nullable=True))
    op.alter_column(T, "review_id", existing_type=sa.BigInteger(), nullable=True)
    op.alter_column(T, "investigation_id", existing_type=postgresql.UUID(), nullable=True)
    op.create_foreign_key(
        op.f("fk_writeback_outbox_case_id_cases"), T, "cases", ["case_id"], ["id"]
    )
    op.create_foreign_key(
        op.f("fk_writeback_outbox_closure_request_id_approval_requests"),
        T,
        "approval_requests",
        ["closure_request_id"],
        ["id"],
    )
    op.create_unique_constraint(
        op.f("uq_writeback_outbox_closure_request_id"), T, ["closure_request_id"]
    )
    for name, expression in CHECKS.items():
        op.create_check_constraint(op.f(f"ck_writeback_outbox_{name}"), T, expression)
    op.execute(f"GRANT INSERT ({RUNTIME_INSERT}) ON {T} TO argus_runtime")
    op.execute(f"GRANT SELECT ON {T} TO argus_writer")
    op.execute(f"GRANT SELECT ({REVIEW_COLUMNS}) ON review_events TO argus_writer")
    op.execute(f"GRANT SELECT ({F1_COLUMNS}) ON freshness_shadow TO argus_writer")
    op.execute(f"GRANT UPDATE ({WRITER_UPDATE}) ON {T} TO argus_writer")


def downgrade() -> None:
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_writer') THEN
                REVOKE UPDATE ({WRITER_UPDATE}) ON {T} FROM argus_writer;
                REVOKE SELECT ON {T} FROM argus_writer;
                REVOKE SELECT ({REVIEW_COLUMNS}) ON review_events FROM argus_writer;
                REVOKE SELECT ({F1_COLUMNS}) ON freshness_shadow FROM argus_writer;
            END IF;
            IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_runtime') THEN
                REVOKE INSERT ({RUNTIME_INSERT}) ON {T} FROM argus_runtime;
            END IF;
        END
        $$;
        """
    )
    op.execute(f"DELETE FROM {T} WHERE review_id IS NULL")  # an approved closure's row
    for name in CHECKS:
        op.drop_constraint(op.f(f"ck_writeback_outbox_{name}"), T, type_="check")
    op.drop_constraint(op.f("uq_writeback_outbox_closure_request_id"), T, type_="unique")
    op.drop_constraint(
        op.f("fk_writeback_outbox_closure_request_id_approval_requests"), T, type_="foreignkey"
    )
    op.drop_constraint(op.f("fk_writeback_outbox_case_id_cases"), T, type_="foreignkey")
    op.alter_column(T, "investigation_id", existing_type=postgresql.UUID(), nullable=False)
    op.alter_column(T, "review_id", existing_type=sa.BigInteger(), nullable=False)
    for column in (
        "held",
        "operator",
        "needs_operator",
        "previous",
        "written_count",
        "closure_request_id",
        "case_id",
    ):
        op.drop_column(T, column)
