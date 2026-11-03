"""The case team: Kibana users post an incident case; ARGUS keeps every request.

``case_team_posts`` (one row per posted ARGUS case), ``case_team_steps`` (every request of a post,
in order, with its state; the database keeps the rules the code keeps: only the lead opens a case
or touches alerts, only the reporter uploads a file), ``case_team_approvals`` (a person's approval
of a case's first sequence, append-only) and ``case_team_seen`` (a person's ``Verdict:`` comment,
read once). The writer's login writes posts and steps, the web's login records approvals, the
runtime login records the comments it read.

Revision ID: 0053
Revises: 0052
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0053"
down_revision: str | None = "0052"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

AUTHORS = (
    "argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter",
    "argus-reporter",
)  # fmt: skip
KINDS = ("open", "attach", "tag", "comment", "file")
STEP_STATES = (
    "planned", "sending", "sent", "verified", "ambiguous", "resend", "failed", "skipped", "held",
    "superseded",
)  # fmt: skip
POST_STATES = ("active", "held", "done")
SEEN_STATUS = ("recorded", "ignored", "unmatched", "needs_reason", "refused")
OUTCOMES = (
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive",
)  # fmt: skip
STEP_INSERT = (
    "case_id, gen, seq, key, kind, author, part, report_version, payload, text_body, units,"
    " request_hash"
)
STEP_UPDATE = (
    "state, state_reason, sent_count, kibana_ids, lookups, next_lookup_at, sent_at, verified_at"
)
POST_UPDATE = "kibana_case_id, state, held_reason, opened_at, last_version, last_round_at"
APPROVAL_INSERT = (
    "case_id, gen, plan_hash, report_version, approver_user_id, statement, signature,"
    " approved_at, expires_at"
)
SEEN_INSERT = (
    "kibana_comment_id, text_hash, case_id, author, written_at, verdict, status, detail,"
    " user_id, review_ids"
)


# what the web's login reads, and the approval of a first sequence it records and signs
WEB_GRANTS = (
    "GRANT SELECT ON case_team_posts, case_team_steps, case_team_seen TO argus_web",
    f"GRANT SELECT, INSERT ({APPROVAL_INSERT}) ON case_team_approvals TO argus_web",
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _append_only(table: str) -> None:
    op.execute(
        f"CREATE TRIGGER {table}_append_only_rows BEFORE UPDATE OR DELETE"
        f" ON {table} FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        f"CREATE TRIGGER {table}_append_only_truncate BEFORE TRUNCATE ON {table}"
        " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_append_only_rows")
    op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_append_only_truncate")


def upgrade() -> None:
    op.create_table(
        "case_team_posts",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("incident_id", sa.Text(), nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=True),
        sa.Column("state", sa.Text(), server_default="active", nullable=False),
        sa.Column("held_reason", sa.Text(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_version", sa.Integer(), nullable=True),
        sa.Column("last_round_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("state", POST_STATES), name=op.f("ck_case_team_posts_state_valid")),
        sa.CheckConstraint(
            r"incident_id ~ '^[A-Z][A-Z0-9-]{0,15}-[0-9]{4}-[0-9]{4}-[0-9]{2}$'",
            name=op.f("ck_case_team_posts_id_valid"),
        ),
        sa.CheckConstraint(
            "last_version IS NULL OR last_version >= 1",
            name=op.f("ck_case_team_posts_version_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_team_posts_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_case_team_posts")),
        sa.UniqueConstraint("incident_id", name=op.f("uq_case_team_posts_incident_id")),
    )
    op.create_index(op.f("ix_case_team_posts_opened_at"), "case_team_posts", ["opened_at"])

    op.create_table(
        "case_team_steps",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("gen", sa.Integer(), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("author", sa.Text(), nullable=False),
        sa.Column("part", sa.Text(), nullable=False),
        sa.Column("report_version", sa.Integer(), nullable=False),
        sa.Column(
            "payload", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb"), nullable=False
        ),
        sa.Column("text_body", sa.Text(), nullable=True),
        sa.Column(
            "units", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb"), nullable=False
        ),
        sa.Column("request_hash", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), server_default="planned", nullable=False),
        sa.Column("state_reason", sa.Text(), nullable=True),
        sa.Column("sent_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "kibana_ids",
            postgresql.JSONB(),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("lookups", sa.Integer(), server_default="0", nullable=False),
        sa.Column("next_lookup_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("gen >= 1 AND seq >= 1", name=op.f("ck_case_team_steps_position_valid")),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_case_team_steps_kind_valid")),
        sa.CheckConstraint(_in("author", AUTHORS), name=op.f("ck_case_team_steps_author_valid")),
        sa.CheckConstraint(_in("state", STEP_STATES), name=op.f("ck_case_team_steps_state_valid")),
        sa.CheckConstraint(
            "request_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_case_team_steps_hash_valid")
        ),
        sa.CheckConstraint(
            "sent_count >= 0 AND lookups >= 0", name=op.f("ck_case_team_steps_counts_valid")
        ),
        sa.CheckConstraint(
            "(kind IN ('open', 'comment')) = (text_body IS NOT NULL)",
            name=op.f("ck_case_team_steps_text_kinds"),
        ),
        sa.CheckConstraint(
            "kind NOT IN ('open', 'attach', 'tag') OR author = 'argus-lead'",
            name=op.f("ck_case_team_steps_lead_only"),
        ),
        sa.CheckConstraint(
            "kind <> 'file' OR author = 'argus-reporter'",
            name=op.f("ck_case_team_steps_reporter_only"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["case_team_posts.case_id"],
            name=op.f("fk_case_team_steps_case_id_case_team_posts"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_team_steps")),
        sa.UniqueConstraint(
            "case_id", "gen", "key", name=op.f("uq_case_team_steps_case_id_gen_key")
        ),
        sa.UniqueConstraint(
            "case_id", "gen", "seq", name=op.f("uq_case_team_steps_case_id_gen_seq")
        ),
    )

    op.create_table(
        "case_team_approvals",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("gen", sa.Integer(), nullable=False),
        sa.Column("plan_hash", sa.Text(), nullable=False),
        sa.Column("report_version", sa.Integer(), nullable=False),
        sa.Column("approver_user_id", sa.BigInteger(), nullable=False),
        sa.Column("statement", postgresql.JSONB(), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column(
            "approved_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("gen >= 1", name=op.f("ck_case_team_approvals_gen_valid")),
        sa.CheckConstraint(
            "plan_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_case_team_approvals_hash_valid")
        ),
        sa.CheckConstraint(
            "expires_at > approved_at", name=op.f("ck_case_team_approvals_expiry_valid")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_team_approvals_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["approver_user_id"],
            ["users.id"],
            name=op.f("fk_case_team_approvals_approver_user_id_users"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_team_approvals")),
    )
    op.create_index(
        op.f("ix_case_team_approvals_case_id_plan_hash"),
        "case_team_approvals",
        ["case_id", "plan_hash"],
    )
    _append_only("case_team_approvals")

    op.create_table(
        "case_team_seen",
        sa.Column("kibana_comment_id", sa.Text(), nullable=False),
        sa.Column("text_hash", sa.Text(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("author", sa.Text(), nullable=False),
        sa.Column("written_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("verdict", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("user_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "review_ids",
            postgresql.ARRAY(sa.BigInteger()),
            server_default=sa.text("'{}'::bigint[]"),
            nullable=False,
        ),
        sa.Column(
            "read_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(_in("status", SEEN_STATUS), name=op.f("ck_case_team_seen_status_valid")),
        sa.CheckConstraint(
            f"verdict IS NULL OR {_in('verdict', OUTCOMES)}",
            name=op.f("ck_case_team_seen_verdict_valid"),
        ),
        sa.CheckConstraint(
            "text_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_case_team_seen_hash_valid")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"],
            ["case_team_posts.case_id"],
            name=op.f("fk_case_team_seen_case_id_case_team_posts"),
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_case_team_seen_user_id_users")
        ),
        sa.PrimaryKeyConstraint("kibana_comment_id", "text_hash", name=op.f("pk_case_team_seen")),
    )
    op.create_index(
        op.f("ix_case_team_seen_case_id_written_at"), "case_team_seen", ["case_id", "written_at"]
    )
    _append_only("case_team_seen")

    # the writer posts; the web approves; the runtime records the verdicts it read; all read
    op.execute(
        "GRANT SELECT, INSERT (case_id, incident_id), UPDATE (" + POST_UPDATE + ")"
        " ON case_team_posts TO argus_writer"
    )
    op.execute(
        "GRANT SELECT, INSERT (" + STEP_INSERT + "), UPDATE (" + STEP_UPDATE + ")"
        " ON case_team_steps TO argus_writer"
    )
    op.execute("GRANT SELECT ON case_team_posts TO argus_runtime")
    op.execute("GRANT SELECT ON case_team_steps TO argus_runtime")
    op.execute("GRANT SELECT ON case_team_approvals TO argus_runtime")
    op.execute(f"GRANT SELECT, INSERT ({SEEN_INSERT}) ON case_team_seen TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)
    op.execute("GRANT SELECT ON case_team_approvals, case_team_seen TO argus_writer")
    op.execute("GRANT SELECT ON incident_reports, incident_report_decisions TO argus_writer")


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM case_team_seen WHERE status = 'recorded') THEN
                RAISE EXCEPTION 'people wrote verdicts in Kibana cases: labels were written'
                    ' from them'
                    USING ERRCODE = 'QC422';
            END IF;
            IF EXISTS (SELECT 1 FROM case_team_steps WHERE sent_count > 0) THEN
                RAISE EXCEPTION 'the case team sent requests to Kibana: the record of what was'
                    ' written to production would be lost'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.execute("REVOKE SELECT ON incident_reports, incident_report_decisions FROM argus_writer")
    op.drop_table("case_team_seen")
    op.drop_table("case_team_approvals")
    op.drop_table("case_team_steps")
    op.drop_table("case_team_posts")
