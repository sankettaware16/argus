"""The case writer (Q-D4, plan §5 and §7.1): what ``argus-writer`` keeps and may do.

* ``kibana_steps``: the writes the writer derives from an outbox row and sends itself: a
  created case's opening comment and alert attachments, and an approved compensating write's
  change and comment. A step has the outbox's states and the same rule (``sending`` is
  committed before the request, nothing is retried), except that it is sent at most once and
  never resent: no approval covers a resend of a step. The trigger ``argus_step_guard`` holds
  the moves, the counts and the fixed fields, and a compensating step needs its complete,
  unexpired approval.
* ``kibana_lookups``: the looks at 2, 5, 15 and 30 minutes for a write in doubt, with outcomes.
* ``kibana_writer_runs`` and ``kibana_writer_ramp``: every run of a class that did something (a
  canary or ramp step at the terminal, or the service's schedule), written once when it ends,
  with what it sent and read back (the writer may insert, never change), and the class's ramp
  step (1, then 5, then 10), which the ramp rule reads.
* The group role ``argus_writer`` (made by ``argus db bootstrap``, like ``argus_web``) holds
  what only the writer may do: move outbox rows to ``sending``, ``sent``, ``verified``,
  ``ambiguous`` and the rest (the runtime keeps SELECT and INSERT only, and Q-C3's closure
  moves), and write the four tables above. The writer's login (``database.writer_user``) was
  made a member of ``argus_runtime`` too, for the gateway's state and the audit trail it writes
  through: **superseded by 0038** (review R8), which gives ``argus_writer`` exactly what it needs
  and takes the login out of ``argus_runtime``. ``argus_runtime`` gets SELECT on the four tables,
  nothing more.

Revision ID: 0037
Revises: 0036
Create Date: 2026-10-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

STATES = (
    "planned",
    "approved",
    "sending",
    "sent",
    "verified",
    "ambiguous",
    "conflict",
    "paused",
    "skipped",
)
KINDS = ("comment", "attach", "compensate_update", "compensate_comment")
OUTBOX_UPDATE = (
    "state",
    "state_reason",
    "sent_count",
    "resends",
    "kibana_case_id",
    "sent_at",
    "verified_at",
)
STEP_INSERT = (
    "case_id",
    "outbox_id",
    "approval_request_id",
    "kind",
    "seq",
    "key",
    "write_class",
    "payload",
    "payload_hash",
)
STEP_UPDATE = ("state", "state_reason", "sent_count", "kibana_case_id", "sent_at", "verified_at")
LOOKUP_INSERT = ("subject", "subject_id", "sent_count", "attempt", "due_at")
LOOKUP_UPDATE = ("due_at", "done_at", "outcome", "details")
RUN_INSERT = (
    "write_class",
    "kind",
    "step",
    "started_at",
    "finished_at",
    "units",
    "sent",
    "verified",
    "mismatches",
    "ambiguous",
    "stopped",
    "by",
)
RAMP_INSERT = ("write_class", "step", "since", "changed_by", "note")
RAMP_UPDATE = ("step", "since", "changed_by", "note")

STEP_GUARD = """
CREATE FUNCTION argus_step_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    req record;
    approved bigint;
    rejected bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'planned' OR NEW.sent_count <> 0
           OR NEW.sent_at IS NOT NULL OR NEW.verified_at IS NOT NULL THEN
            RAISE EXCEPTION 'a new step is planned and unsent' USING ERRCODE = 'QC422';
        END IF;
        IF NEW.outbox_id IS NOT NULL AND NOT EXISTS (
               SELECT 1 FROM public.kibana_outbox o
               WHERE o.id = NEW.outbox_id AND o.case_id = NEW.case_id) THEN
            RAISE EXCEPTION 'the step''s outbox row is not this case''s' USING ERRCODE = 'QC422';
        END IF;
        IF NEW.kind LIKE 'compensate%' THEN
            SELECT r.case_id, r.kind, r.outbox_id, r.required_approvals, r.expires_at INTO req
                FROM public.approval_requests r WHERE r.id = NEW.approval_request_id;
            IF NOT FOUND OR req.kind <> 'compensating' OR req.case_id <> NEW.case_id
               OR req.outbox_id IS DISTINCT FROM NEW.outbox_id THEN
                RAISE EXCEPTION 'a compensating step follows an approval of its own outbox row'
                    USING ERRCODE = 'QC422';
            END IF;
            SELECT count(*) FILTER (WHERE d.decision = 'approved'),
                   count(*) FILTER (WHERE d.decision = 'rejected')
                INTO approved, rejected FROM public.approval_decisions d
                WHERE d.request_id = NEW.approval_request_id;
            IF clock_timestamp() > req.expires_at OR rejected > 0
               OR approved < req.required_approvals THEN
                RAISE EXCEPTION 'approval % is not complete', NEW.approval_request_id
                    USING ERRCODE = 'QC422';
            END IF;
        ELSIF NEW.approval_request_id IS NOT NULL THEN
            RAISE EXCEPTION 'only a compensating step carries an approval' USING ERRCODE = 'QC422';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.case_id <> OLD.case_id
       OR NEW.outbox_id IS DISTINCT FROM OLD.outbox_id
       OR NEW.approval_request_id IS DISTINCT FROM OLD.approval_request_id
       OR NEW.kind <> OLD.kind OR NEW.seq <> OLD.seq OR NEW.key <> OLD.key
       OR NEW.write_class <> OLD.write_class OR NEW.payload <> OLD.payload
       OR NEW.payload_hash <> OLD.payload_hash OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'step %: a fixed field changed', OLD.id USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
        ('planned', 'approved'), ('planned', 'paused'), ('planned', 'skipped'),
        ('approved', 'sending'), ('approved', 'paused'), ('approved', 'skipped'),
        ('sending', 'sent'), ('sending', 'ambiguous'), ('sending', 'conflict'),
        ('sending', 'paused'),
        ('sent', 'verified'), ('sent', 'conflict'), ('sent', 'paused'),
        ('ambiguous', 'sent'), ('ambiguous', 'verified'), ('ambiguous', 'paused'),
        ('ambiguous', 'skipped'),
        ('conflict', 'paused'), ('conflict', 'skipped'),
        ('paused', 'approved'), ('paused', 'skipped')
    ) THEN
        RAISE EXCEPTION 'step %: % to % is not a step move', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'QC422';
    END IF;
    IF (NEW.state = 'sending' AND OLD.state <> 'sending')
       <> (NEW.sent_count = OLD.sent_count + 1) OR NEW.sent_count < OLD.sent_count THEN
        RAISE EXCEPTION 'step %: each send is counted once', OLD.id USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state = 'sending' AND OLD.state <> 'sending' AND NEW.kind LIKE 'compensate%' THEN
        SELECT r.required_approvals, r.expires_at INTO req
            FROM public.approval_requests r WHERE r.id = NEW.approval_request_id;
        SELECT count(*) FILTER (WHERE d.decision = 'approved'),
               count(*) FILTER (WHERE d.decision = 'rejected')
            INTO approved, rejected FROM public.approval_decisions d
            WHERE d.request_id = NEW.approval_request_id;
        IF clock_timestamp() > req.expires_at OR rejected > 0
           OR approved < req.required_approvals THEN
            RAISE EXCEPTION 'approval % is not complete', NEW.approval_request_id
                USING ERRCODE = 'QC422';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
"""


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def upgrade() -> None:
    op.create_table(
        "kibana_steps",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("outbox_id", sa.BigInteger(), nullable=True),
        sa.Column("approval_request_id", sa.BigInteger(), nullable=True),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("seq", sa.SmallInteger(), nullable=False),
        sa.Column("key", sa.Text(), nullable=False),
        sa.Column("write_class", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), server_default="planned", nullable=False),
        sa.Column("state_reason", sa.Text(), nullable=True),
        sa.Column("sent_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_in("kind", KINDS), name=op.f("ck_kibana_steps_kind_valid")),
        sa.CheckConstraint(
            _in("write_class", ("W1", "W2", "W3")), name=op.f("ck_kibana_steps_class_valid")
        ),
        sa.CheckConstraint(_in("state", STATES), name=op.f("ck_kibana_steps_state_valid")),
        sa.CheckConstraint(
            "sent_count BETWEEN 0 AND 1", name=op.f("ck_kibana_steps_sent_at_most_once")
        ),
        sa.CheckConstraint("seq BETWEEN 0 AND 999", name=op.f("ck_kibana_steps_seq_valid")),
        sa.CheckConstraint(
            "length(key) BETWEEN 1 AND 200", name=op.f("ck_kibana_steps_key_length")
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_kibana_steps_payload_hash_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_kibana_steps_payload_is_object")
        ),
        sa.CheckConstraint(
            "(kind LIKE 'compensate%') = (approval_request_id IS NOT NULL)",
            name=op.f("ck_kibana_steps_compensation_has_approval"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_kibana_steps_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["outbox_id"],
            ["kibana_outbox.id"],
            name=op.f("fk_kibana_steps_outbox_id_kibana_outbox"),
        ),
        sa.ForeignKeyConstraint(
            ["approval_request_id"],
            ["approval_requests.id"],
            name=op.f("fk_kibana_steps_approval_request_id_approval_requests"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_steps")),
        sa.UniqueConstraint("key", name=op.f("uq_kibana_steps_key")),
    )
    op.create_index(op.f("ix_kibana_steps_state_id"), "kibana_steps", ["state", "id"])
    op.create_index(op.f("ix_kibana_steps_case_id_id"), "kibana_steps", ["case_id", "id"])
    op.create_index(op.f("ix_kibana_steps_outbox_id"), "kibana_steps", ["outbox_id"])
    op.create_table(
        "kibana_lookups",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column("subject_id", sa.BigInteger(), nullable=False),
        sa.Column("sent_count", sa.Integer(), nullable=False),
        sa.Column("attempt", sa.SmallInteger(), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("done_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("outcome", sa.Text(), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _in("subject", ("outbox", "step")), name=op.f("ck_kibana_lookups_subject_valid")
        ),
        sa.CheckConstraint("attempt BETWEEN 1 AND 4", name=op.f("ck_kibana_lookups_attempt_valid")),
        sa.CheckConstraint(
            "outcome IS NULL OR "
            + _in("outcome", ("found", "not_found", "duplicate", "foreign", "not_needed")),
            name=op.f("ck_kibana_lookups_outcome_valid"),
        ),
        sa.CheckConstraint(
            "(outcome IS NULL) = (done_at IS NULL)", name=op.f("ck_kibana_lookups_done_has_outcome")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(details) = 'object'", name=op.f("ck_kibana_lookups_details_is_object")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_lookups")),
        sa.UniqueConstraint(
            "subject",
            "subject_id",
            "sent_count",
            "attempt",
            name=op.f("uq_kibana_lookups_subject_subject_id_sent_count_attempt"),
        ),
    )
    op.create_index(
        op.f("ix_kibana_lookups_due_at"),
        "kibana_lookups",
        ["due_at"],
        postgresql_where=sa.text("done_at IS NULL"),
    )
    op.create_table(
        "kibana_writer_runs",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("write_class", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("step", sa.SmallInteger(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("units", sa.Integer(), server_default="0", nullable=False),
        sa.Column("sent", sa.Integer(), server_default="0", nullable=False),
        sa.Column("verified", sa.Integer(), server_default="0", nullable=False),
        sa.Column("mismatches", sa.Integer(), server_default="0", nullable=False),
        sa.Column("ambiguous", sa.Integer(), server_default="0", nullable=False),
        sa.Column("stopped", sa.Text(), nullable=True),
        sa.Column("by", sa.Text(), nullable=False),
        sa.CheckConstraint(
            _in("write_class", ("W1", "W2", "W3")), name=op.f("ck_kibana_writer_runs_class_valid")
        ),
        sa.CheckConstraint(
            _in("kind", ("canary", "ramp", "scheduled")),
            name=op.f("ck_kibana_writer_runs_kind_valid"),
        ),
        sa.CheckConstraint("step IN (1, 5, 10)", name=op.f("ck_kibana_writer_runs_step_valid")),
        sa.CheckConstraint(
            "units >= 0 AND sent >= 0 AND verified >= 0 AND mismatches >= 0 AND ambiguous >= 0",
            name=op.f("ck_kibana_writer_runs_counts_valid"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_writer_runs")),
    )
    op.create_index(
        op.f("ix_kibana_writer_runs_write_class_started_at"),
        "kibana_writer_runs",
        ["write_class", "started_at"],
    )
    op.create_table(
        "kibana_writer_ramp",
        sa.Column("write_class", sa.Text(), nullable=False),
        sa.Column("step", sa.SmallInteger(), nullable=False),
        sa.Column("since", sa.DateTime(timezone=True), nullable=False),
        sa.Column("changed_by", sa.Text(), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.CheckConstraint(
            _in("write_class", ("W1", "W2", "W3")), name=op.f("ck_kibana_writer_ramp_class_valid")
        ),
        sa.CheckConstraint("step IN (1, 5, 10)", name=op.f("ck_kibana_writer_ramp_step_valid")),
        sa.PrimaryKeyConstraint("write_class", name=op.f("pk_kibana_writer_ramp")),
    )
    op.execute(STEP_GUARD)
    op.execute("REVOKE EXECUTE ON FUNCTION argus_step_guard() FROM PUBLIC")
    op.execute(
        "CREATE TRIGGER kibana_steps_guard BEFORE INSERT OR UPDATE ON kibana_steps"
        " FOR EACH ROW EXECUTE FUNCTION argus_step_guard()"
    )
    op.execute("ALTER TABLE kibana_steps ENABLE ALWAYS TRIGGER kibana_steps_guard")
    # The role names are written out, not imported (see 0003). The runtime reads; the writer
    # (a member of argus_runtime as well) writes, column by column.
    for table in ("kibana_steps", "kibana_lookups", "kibana_writer_runs", "kibana_writer_ramp"):
        op.execute(f"GRANT SELECT ON {table} TO argus_runtime")
    op.execute(f"GRANT UPDATE ({', '.join(OUTBOX_UPDATE)}) ON kibana_outbox TO argus_writer")
    op.execute(
        f"GRANT INSERT ({', '.join(STEP_INSERT)}), UPDATE ({', '.join(STEP_UPDATE)})"
        " ON kibana_steps TO argus_writer"
    )
    op.execute(
        f"GRANT INSERT ({', '.join(LOOKUP_INSERT)}), UPDATE ({', '.join(LOOKUP_UPDATE)})"
        " ON kibana_lookups TO argus_writer"
    )
    op.execute(f"GRANT INSERT ({', '.join(RUN_INSERT)}) ON kibana_writer_runs TO argus_writer")
    op.execute(
        f"GRANT INSERT ({', '.join(RAMP_INSERT)}), UPDATE ({', '.join(RAMP_UPDATE)})"
        " ON kibana_writer_ramp TO argus_writer"
    )


def downgrade() -> None:
    op.execute("REVOKE UPDATE ON kibana_outbox FROM argus_writer")
    op.execute("DROP TRIGGER kibana_steps_guard ON kibana_steps")
    op.execute("DROP FUNCTION argus_step_guard()")
    op.drop_table("kibana_writer_ramp")
    op.drop_table("kibana_writer_runs")
    op.drop_table("kibana_lookups")
    op.drop_table("kibana_steps")
