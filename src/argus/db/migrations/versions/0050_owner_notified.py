"""The owner was told: a true positive on a personal laptop that keeps alerting (AR4b, D-169).

A university's devices are mostly the students', researchers' and staff's own; the security team
finds one and tells its owner, and cannot wipe or isolate it, so a reported true positive keeps
alerting. This migration holds what ARGUS needs to track such a case quietly (D-176):

* ``cases.notified_at``: the first time the device's owner was told (a person's record, a fact
  on an open or assigned case, not a state: the lifecycle's edges are unchanged); cleared when
  the case is contained or closed. ``cases.blocked_at``: the first network-side block recorded.
  A CHECK holds that a notified case is open or assigned, a blocked one confirmed.
* ``case_events.kind`` gains ``notified``, ``blocked`` and ``address_moved``; the closure reasons
  of ``cases`` and ``approval_requests`` gain ``stopped_after_notice`` (no matching activity for
  14 days after the notice: ARGUS proposes it, an approver decides), and the owner's function
  ``argus_approval_propose`` may propose it (its text is 0030's with that reason added).
* ``case_notices``: the record of what a person told and did: who was told, when, how, by whom
  (``kind`` ``owner``), and the blocks put on the network (``kind`` ``block``). Append-only
  (the owner's trigger, like the case events).
* ``case_known_matches``: for an investigation of a notified case's device, what ARGUS decided at
  one version of it: ``known`` (it belongs to the known infection: it leaves Needs attention and
  the AI queue) or ``changed`` (something is new since the notice: ``why`` says what, and it is
  in Needs attention). One row for each investigation, replaced as it gets a new version.
* ``case_known_keys``: what the known infection already includes beyond the case's own devices
  and indicators (evidence flags, destinations, domain families, university services, the data
  volume), so that each change speaks once.
* ``case_reminders``: ARGUS's two suggestions for a case that stays active after the notice
  (notify again after 7 days, ask for network-side action after 21): never an alarm, shown on
  the case; a person dismisses one.

``argus_runtime`` writes what the pass and the terminal write; the web's role reads all of it and
writes what a person records (the case row's two columns, a notice, a block) and dismisses.

Downgrading is refused while a case event, closure or notice uses what this adds: the case events
are append-only and a closed case keeps its reason.

The role names are written out, not imported (see 0003).

Revision ID: 0050
Revises: 0049
Create Date: 2026-10-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0050"
down_revision: str | None = "0049"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

HOWS = ("email", "phone", "in_person", "through_it", "other")
OUTCOMES = ("known", "changed")
KEY_KINDS = ("seed", "flag", "destination", "family", "service", "bytes")
KEY_SOURCES = ("notice", "change")
REMINDERS = ("notify_again", "network_action")
NEW_KINDS = ("notified", "blocked", "address_moved")
EVENT_KINDS = (
    "suspected", "opened", "confirmed", "dismissed", "taken", "assigned", "released",
    "contained", "new_activity", "activity_after_closure", "linked", "published",
    "closure_requested", "merge_requested", "closed", "merged_into", "merged_in", "reopened",
)  # fmt: skip
REASONS = (
    "remediated_verified", "remediated_unverified", "risk_accepted", "attempt_no_impact",
    "rule_false_positive", "benign_expected", "benign_policy", "duplicate", "created_in_error",
)  # fmt: skip
NEW_REASON = "stopped_after_notice"
PROPOSABLE = (
    "remediated_verified", "attempt_no_impact", "rule_false_positive", "benign_expected",
    "benign_policy",
)  # fmt: skip
# 0030's function (made again in place: its rights stay) with one more reason in its list;
# ``{reasons}`` is the list
PROPOSE = """
CREATE OR REPLACE FUNCTION argus_approval_propose(
    p_proposer text, p_case uuid, p_case_version integer, p_kind text, p_reason text,
    p_outbox bigint, p_payload jsonb, p_payload_hash text, p_kibana_version text,
    p_expires_at timestamptz, p_note text
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c record;
    o record;
    original record;
    n_alerts bigint;
    digest text;
    needed smallint := 1;
    new_id bigint;
BEGIN
    IF p_proposer IS NULL OR p_proposer !~ '^argus:[a-z][a-z0-9_.-]{0,59}$' THEN
        RAISE EXCEPTION 'a proposal names the part of ARGUS that made it'
            USING ERRCODE = 'QC422';
    END IF;
    IF p_kind IS NULL OR p_kind NOT IN ('closure', 'reconfirm') THEN
        RAISE EXCEPTION 'ARGUS proposes closures and re-confirmations only'
            USING ERRCODE = 'QC422';
    END IF;
    SELECT k.version, k.state INTO c FROM public.cases k WHERE k.id = p_case FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such case' USING ERRCODE = 'QC404';
    END IF;
    IF c.version <> p_case_version THEN
        RAISE EXCEPTION 'the case is at version %, not %', c.version, p_case_version
            USING ERRCODE = 'QC409';
    END IF;
    IF p_kind = 'closure' THEN
        IF p_reason IS NULL OR p_reason NOT IN ({reasons}) THEN
            RAISE EXCEPTION 'ARGUS does not propose a closure as %', p_reason
                USING ERRCODE = 'QC422';
        END IF;
        IF c.state NOT IN ('open', 'assigned', 'contained') OR p_outbox IS NOT NULL THEN
            RAISE EXCEPTION 'a % case cannot be proposed for closure', c.state
                USING ERRCODE = 'QC409';
        END IF;
        IF NOT EXISTS (SELECT 1 FROM public.case_events e WHERE e.case_id = p_case
                       AND e.case_version = p_case_version AND e.kind = 'closure_requested'
                       AND e.actor = p_proposer AND e.details ->> 'reason' = p_reason) THEN
            RAISE EXCEPTION 'a proposal follows its own request event' USING ERRCODE = 'QC422';
        END IF;
    ELSE
        IF p_reason IS NOT NULL OR p_outbox IS NULL OR c.state <> 'closed' THEN
            RAISE EXCEPTION 're-confirming names a closure write of a closed case'
                USING ERRCODE = 'QC422';
        END IF;
        SELECT x.id, x.approval_request_id, x.case_event_id INTO o FROM public.kibana_outbox x
            WHERE x.id = p_outbox AND x.case_id = p_case AND x.write_class = 'W3'
              AND x.state = 'paused' FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the closure write is not this case''s, or not held back'
                USING ERRCODE = 'QC422';
        END IF;
        SELECT q.payload, q.payload_hash, q.required_approvals INTO original
            FROM public.approval_requests q WHERE q.id = o.approval_request_id;
        IF original.payload IS DISTINCT FROM p_payload
           OR original.payload_hash IS DISTINCT FROM p_payload_hash THEN
            RAISE EXCEPTION 'a re-confirmation asks for exactly the approved writes'
                USING ERRCODE = 'QC422';
        END IF;
        IF EXISTS (SELECT 1 FROM public.approval_requests q
                   WHERE q.kind = 'reconfirm' AND q.outbox_id IN (
                           SELECT y.id FROM public.kibana_outbox y
                           WHERE y.case_event_id = o.case_event_id AND y.write_class = 'W3')
                     AND clock_timestamp() <= q.expires_at
                     AND NOT EXISTS (SELECT 1 FROM public.approval_decisions d
                                     WHERE d.request_id = q.id AND d.decision = 'rejected')
                     AND (SELECT count(*) FROM public.approval_decisions d
                          WHERE d.request_id = q.id AND d.decision = 'approved')
                         < q.required_approvals) THEN
            RAISE EXCEPTION 'a re-confirmation of this write is already waiting'
                USING ERRCODE = 'QC409';
        END IF;
        needed := original.required_approvals;
    END IF;
    IF p_expires_at <= clock_timestamp() OR p_expires_at > now() + interval '72 hours' THEN
        RAISE EXCEPTION 'an approval expires within 72 hours' USING ERRCODE = 'QC422';
    END IF;
    -- the alert set as 0026's request binds it; a closed case's alerts as of its closure (a
    -- merge moved its members to the target at that version)
    SELECT count(*), encode(sha256(convert_to(coalesce(
               string_agg(a.alert_id, E'\\n' ORDER BY a.alert_id COLLATE "C"), ''), 'UTF8')), 'hex')
        INTO n_alerts, digest
        FROM (SELECT DISTINCT ia.alert_id::text AS alert_id FROM public.case_members m
              JOIN public.investigation_alerts ia ON ia.investigation_id = m.investigation_id
              WHERE m.case_id = p_case
                AND (m.removed_at IS NULL OR m.removed_version >= p_case_version)) a;
    INSERT INTO public.approval_requests (case_id, case_version, kind, reason, target_case_id,
            outbox_id, outbox_sent_count, payload, payload_hash, alert_count, alert_digest,
            kibana_version, required_approvals, requested_by_user_id, proposed_by, expires_at,
            note)
        VALUES (p_case, p_case_version, p_kind, p_reason, NULL, p_outbox, NULL, p_payload,
                p_payload_hash, n_alerts, digest, p_kibana_version, needed, NULL, p_proposer,
                p_expires_at, p_note)
        RETURNING id INTO new_id;
    INSERT INTO public.audit_events (actor, action, target_type, target_id, details)
        VALUES (p_proposer, 'case.approval.requested', 'case', p_case::text,
                jsonb_build_object('request', new_id, 'kind', p_kind, 'reason', p_reason,
                    'case_version', p_case_version, 'payload_hash', p_payload_hash,
                    'alert_count', n_alerts, 'alert_digest', digest, 'required', needed,
                    'expires_at', public.argus_chain_time(p_expires_at), 'outbox', p_outbox,
                    'outbox_sent_count', NULL, 'target', NULL, 'proposed_by', p_proposer,
                    'via', 'approvals'));
    RETURN new_id;
END
$$;
"""

NOTICE_INSERT = "case_id, case_version, kind, at, told, how, managed, note, by_user_id"
MATCH_INSERT = "investigation_id, case_id, version, outcome, why"
MATCH_UPDATE = "case_id, version, outcome, why, decided_at"
KEY_INSERT = "case_id, kind, value, source"
REMINDER_INSERT = "case_id, kind, why"
# what a person's case commands write on the case row, and the reminder the page dismisses
WEB_GRANTS = (
    "GRANT UPDATE (notified_at, blocked_at) ON cases TO argus_web",
    f"GRANT SELECT, INSERT ({NOTICE_INSERT}) ON case_notices TO argus_web",
    "GRANT SELECT ON case_known_matches, case_known_keys TO argus_web",
    "GRANT SELECT, UPDATE (dismissed_at, dismissed_by) ON case_reminders TO argus_web",
)


def _in(column: str, values: Sequence[str]) -> str:
    return f"{column} IN (" + ", ".join(f"'{v}'" for v in values) + ")"


def _list(values: Sequence[str]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def upgrade() -> None:
    op.add_column("cases", sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("cases", sa.Column("blocked_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint(
        op.f("ck_cases_notified_valid"),
        "cases",
        "notified_at IS NULL OR (state IN ('open', 'assigned') AND opened_at IS NOT NULL)",
    )
    op.create_check_constraint(
        op.f("ck_cases_blocked_valid"),
        "cases",
        "blocked_at IS NULL OR (state IN ('open', 'assigned', 'contained')"
        " AND opened_at IS NOT NULL)",
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"),
        "case_events",
        _in("kind", (*EVENT_KINDS, *NEW_KINDS)),
    )
    op.drop_constraint(op.f("ck_cases_closure_reason_valid"), "cases", type_="check")
    op.create_check_constraint(
        op.f("ck_cases_closure_reason_valid"),
        "cases",
        f"closure_reason IS NULL OR {_in('closure_reason', (*REASONS, NEW_REASON))}",
    )
    op.drop_constraint(
        op.f("ck_approval_requests_reason_valid"), "approval_requests", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_approval_requests_reason_valid"),
        "approval_requests",
        f"reason IS NULL OR {_in('reason', (*REASONS, NEW_REASON))}",
    )
    op.execute(PROPOSE.replace("{reasons}", _list((*PROPOSABLE, NEW_REASON))))

    op.create_table(
        "case_notices",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("told", sa.Text(), nullable=False),
        sa.Column("how", sa.Text(), nullable=False),
        sa.Column("managed", sa.Boolean(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("by_user_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _in("kind", ("owner", "block")), name=op.f("ck_case_notices_kind_valid")
        ),
        sa.CheckConstraint(
            "length(told) BETWEEN 1 AND 200", name=op.f("ck_case_notices_told_length")
        ),
        sa.CheckConstraint(
            "length(how) BETWEEN 1 AND 100", name=op.f("ck_case_notices_how_length")
        ),
        sa.CheckConstraint(
            f"kind <> 'owner' OR {_in('how', HOWS)}", name=op.f("ck_case_notices_how_valid")
        ),
        sa.CheckConstraint(
            "(kind = 'owner') = (managed IS NOT NULL)", name=op.f("ck_case_notices_managed_valid")
        ),
        sa.CheckConstraint(
            "note IS NULL OR length(note) <= 4000", name=op.f("ck_case_notices_note_length")
        ),
        sa.CheckConstraint("case_version >= 2", name=op.f("ck_case_notices_version_valid")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_notices_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["by_user_id"], ["users.id"], name=op.f("fk_case_notices_by_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_notices")),
        sa.UniqueConstraint(
            "case_id", "case_version", name=op.f("uq_case_notices_case_id_case_version")
        ),
    )
    op.create_index(
        op.f("ix_case_notices_case_id_kind_at"), "case_notices", ["case_id", "kind", "at"]
    )
    op.execute(
        "CREATE TRIGGER case_notices_append_only_rows BEFORE UPDATE OR DELETE ON case_notices"
        " FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER case_notices_append_only_truncate BEFORE TRUNCATE ON case_notices"
        " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    op.execute("ALTER TABLE case_notices ENABLE ALWAYS TRIGGER case_notices_append_only_rows")
    op.execute("ALTER TABLE case_notices ENABLE ALWAYS TRIGGER case_notices_append_only_truncate")

    op.create_table(
        "case_known_matches",
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("why", sa.Text(), nullable=True),
        sa.Column(
            "decided_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            _in("outcome", OUTCOMES), name=op.f("ck_case_known_matches_outcome_valid")
        ),
        sa.CheckConstraint(
            "(outcome = 'changed') = (why IS NOT NULL) AND (why IS NULL OR length(why) <= 500)",
            name=op.f("ck_case_known_matches_why_valid"),
        ),
        sa.CheckConstraint("version >= 0", name=op.f("ck_case_known_matches_version_valid")),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_case_known_matches_investigation_id_investigations"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_known_matches_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("investigation_id", name=op.f("pk_case_known_matches")),
    )
    op.create_index(
        op.f("ix_case_known_matches_case_id_outcome"), "case_known_matches", ["case_id", "outcome"]
    )
    op.create_table(
        "case_known_keys",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column(
            "added_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.CheckConstraint(_in("kind", KEY_KINDS), name=op.f("ck_case_known_keys_kind_valid")),
        sa.CheckConstraint(
            _in("source", KEY_SOURCES), name=op.f("ck_case_known_keys_source_valid")
        ),
        sa.CheckConstraint("length(value) <= 512", name=op.f("ck_case_known_keys_value_length")),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_known_keys_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", "kind", "value", name=op.f("pk_case_known_keys")),
    )
    op.create_table(
        "case_reminders",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("why", sa.Text(), nullable=False),
        sa.Column(
            "suggested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("dismissed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("dismissed_by", sa.BigInteger(), nullable=True),
        sa.CheckConstraint(_in("kind", REMINDERS), name=op.f("ck_case_reminders_kind_valid")),
        sa.CheckConstraint(
            "length(why) BETWEEN 1 AND 300", name=op.f("ck_case_reminders_why_length")
        ),
        sa.CheckConstraint(
            "(dismissed_at IS NULL) = (dismissed_by IS NULL)",
            name=op.f("ck_case_reminders_dismissal_complete"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_reminders_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["dismissed_by"], ["users.id"], name=op.f("fk_case_reminders_dismissed_by_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_reminders")),
        sa.UniqueConstraint("case_id", "kind", name=op.f("uq_case_reminders_case_id_kind")),
    )

    op.execute("GRANT UPDATE (notified_at, blocked_at) ON cases TO argus_runtime")
    op.execute(f"GRANT SELECT, INSERT ({NOTICE_INSERT}) ON case_notices TO argus_runtime")
    op.execute(
        f"GRANT SELECT, INSERT ({MATCH_INSERT}), UPDATE ({MATCH_UPDATE})"
        " ON case_known_matches TO argus_runtime"
    )
    op.execute(f"GRANT SELECT, INSERT ({KEY_INSERT}) ON case_known_keys TO argus_runtime")
    op.execute(
        f"GRANT SELECT, INSERT ({REMINDER_INSERT}), UPDATE (dismissed_at, dismissed_by)"
        " ON case_reminders TO argus_runtime"
    )
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM case_events
                       WHERE kind IN ('notified', 'blocked', 'address_moved')) THEN
                RAISE EXCEPTION 'cases were notified or blocked: the case events are append-only'
                    USING ERRCODE = 'QC422';
            END IF;
            IF EXISTS (SELECT 1 FROM cases WHERE closure_reason = 'stopped_after_notice')
               OR EXISTS (SELECT 1 FROM approval_requests WHERE reason = 'stopped_after_notice')
            THEN
                RAISE EXCEPTION 'a case was closed (or asked to close) as stopped after notice'
                    USING ERRCODE = 'QC422';
            END IF;
        END
        $$
        """
    )
    op.drop_table("case_reminders")
    op.drop_table("case_known_keys")
    op.drop_index(op.f("ix_case_known_matches_case_id_outcome"), table_name="case_known_matches")
    op.drop_table("case_known_matches")
    op.drop_index(op.f("ix_case_notices_case_id_kind_at"), table_name="case_notices")
    op.drop_table("case_notices")
    op.execute(PROPOSE.replace("{reasons}", _list(PROPOSABLE)))
    op.drop_constraint(
        op.f("ck_approval_requests_reason_valid"), "approval_requests", type_="check"
    )
    op.create_check_constraint(
        op.f("ck_approval_requests_reason_valid"),
        "approval_requests",
        f"reason IS NULL OR {_in('reason', REASONS)}",
    )
    op.drop_constraint(op.f("ck_cases_closure_reason_valid"), "cases", type_="check")
    op.create_check_constraint(
        op.f("ck_cases_closure_reason_valid"),
        "cases",
        f"closure_reason IS NULL OR {_in('closure_reason', REASONS)}",
    )
    op.drop_constraint(op.f("ck_case_events_kind_valid"), "case_events", type_="check")
    op.create_check_constraint(
        op.f("ck_case_events_kind_valid"), "case_events", _in("kind", EVENT_KINDS)
    )
    op.drop_constraint(op.f("ck_cases_blocked_valid"), "cases", type_="check")
    op.drop_constraint(op.f("ck_cases_notified_valid"), "cases", type_="check")
    op.drop_column("cases", "blocked_at")
    op.drop_column("cases", "notified_at")
