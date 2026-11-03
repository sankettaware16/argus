"""Closure approval: step-up, signatures, live checks, groups, ARGUS's proposals (Q-C3)

What the database adds to 0026's approvals (plan §7.1, §7.2, §7.9):

* **A decision needs this session's step-up within 5 minutes** (the one the web signed), a live
  identity check of the approver at most 30 seconds old showing ``approve`` (and Kibana's
  ``updateCase`` when the closure writes to Kibana), and the web's signature. The decision
  stores all three; ``argus-writer`` verifies the signature before sending (argus.cases.
  sendcheck). Group approvals (≤ 20 benign, false-positive or no-impact closures) need their
  sample approved one by one first.
* **Identity checks** (``identity_checks``, append-only): sign-ins, re-checks, step-ups and
  approvals record their outcome through ``argus_identity_record()``. A denied check (a 401 or
  403) voids the person's earlier approvals; a disabled account does too.
* **Only valid approvals count**: the case guard, the outbox guard and the decide function count
  an approval only while its approver is not revoked since they gave it.
* **ARGUS proposes** closures (``argus_approval_propose()``, which the runtime may call) after
  its own request event; it may also ask for a **re-confirmation** of a closure write whose
  send-time check failed. ARGUS never approves: a proposal still needs a person.
* **A request binds its requester's live check** (``requester_check``, at most 30 seconds old,
  recorded as an identity check too), so one person behind two accounts never approves their
  own request, nor re-confirms a closure they asked for (a re-confirmation's requester is its
  closure's).
* **An approval of an outbox row's write** (a resend, a compensating write, a re-confirmation)
  needs the approver's own Kibana privilege for that write; a merge into a closed case is not
  approved.
* **A closure write leaves the outbox** (to ``approved`` or ``sending``) only while its case is
  still closed by that approval and a complete, unexpired, signed approval (the closure's own
  or a re-confirmation of one of this closure's writes) allows it. The runtime moves closure
  writes only through ``argus_closure_write_move()`` (the send-time check's holds, releases,
  refusals and skips, each audited); a write refused for a person stays until its case changes.

Revision ID: 0030
Revises: 0029
Create Date: 2026-10-23
"""

import importlib.util
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _m0026() -> ModuleType:
    """0026's text (frozen, approved as q-c1-approved): the guards are 0026's with the counts
    and one rule changed, and the downgrade restores 0026's own."""
    path = Path(__file__).with_name("0026_cases_outbox_approvals_chain.py")
    spec = importlib.util.spec_from_file_location("argus_migration_0026", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _swap(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise RuntimeError("0030: 0026's guard text is not what 0030 was written against")
    return source.replace(old, new)


# An approval counts only while its approver is not revoked since they gave it: the account is
# not disabled and no identity check denied them afterwards (plan §7.1: any 401 or 403 in a
# sign-in, re-check or step-up voids their approvals).
NOT_REVOKED = """NOT EXISTS (SELECT 1 FROM public.users u
                    WHERE u.id = d.approver_user_id AND u.disabled)
            AND NOT EXISTS (SELECT 1 FROM public.identity_checks c
                    WHERE c.user_id = d.approver_user_id AND c.outcome = 'denied'
                      AND c.recorded_at >= d.decided_at)"""

_CASE_COUNT_OLD = """        SELECT count(*) FILTER (WHERE d.decision = 'approved'),
               count(*) FILTER (WHERE d.decision = 'rejected')
            INTO approved, rejected
            FROM public.approval_decisions d WHERE d.request_id = req.id;"""
_CASE_COUNT_NEW = f"""        SELECT count(*) FILTER (WHERE d.decision = 'approved'
                                AND {NOT_REVOKED}),
               count(*) FILTER (WHERE d.decision = 'rejected')
            INTO approved, rejected
            FROM public.approval_decisions d WHERE d.request_id = req.id;"""  # noqa: S608 - constant SQL

_OUTBOX_COUNT_OLD = """            SELECT count(*) FILTER (WHERE d.decision = 'approved'),
                   count(*) FILTER (WHERE d.decision = 'rejected')
                INTO approved, rejected FROM public.approval_decisions d
                WHERE d.request_id = NEW.approval_request_id;"""
_OUTBOX_COUNT_NEW = f"""            SELECT count(*) FILTER (WHERE d.decision = 'approved'
                                    AND {NOT_REVOKED}),
                   count(*) FILTER (WHERE d.decision = 'rejected')
                INTO approved, rejected FROM public.approval_decisions d
                WHERE d.request_id = NEW.approval_request_id;"""  # noqa: S608 - constant SQL

_OUTBOX_END_OLD = """    NEW.updated_at := now();
    RETURN NEW;
END
$$;"""
# A closure write leaves the outbox only while its case is still closed by its approval (a
# reopen in between skips it) and a complete, unexpired, signed approval allows it: the
# closure's own, or a re-confirmation ARGUS asked for one of this closure's writes (the closing
# change and its comment are re-confirmed together; argus.cases.sendcheck).
_OUTBOX_END_NEW = f"""    IF NEW.write_class = 'W3' AND NEW.state IN ('approved', 'sending')
       AND NEW.state <> OLD.state THEN
        SELECT e.case_version, e.kind, e.to_state, e.kibana_rows, e.case_id INTO ev
            FROM public.case_events e WHERE e.id = NEW.case_event_id;
        IF NOT EXISTS (SELECT 1 FROM public.cases k WHERE k.id = NEW.case_id
                       AND k.state = 'closed' AND k.version = ev.case_version
                       AND k.closure_request_id = NEW.approval_request_id) THEN
            RAISE EXCEPTION 'outbox row %: the case changed after the closure it writes', OLD.id
                USING ERRCODE = 'QC409';
        END IF;
        IF NOT EXISTS (
            SELECT 1 FROM public.approval_requests r
            WHERE (r.id = NEW.approval_request_id
                   OR (r.kind = 'reconfirm' AND r.outbox_id IN (
                           SELECT x.id FROM public.kibana_outbox x
                           WHERE x.case_event_id = NEW.case_event_id
                             AND x.write_class = 'W3')))
              AND clock_timestamp() <= r.expires_at
              AND NOT EXISTS (SELECT 1 FROM public.approval_decisions d
                              WHERE d.request_id = r.id AND d.decision = 'rejected')
              AND (SELECT count(*) FROM public.approval_decisions d
                   WHERE d.request_id = r.id AND d.decision = 'approved'
                     AND d.signature IS NOT NULL AND {NOT_REVOKED})
                  >= r.required_approvals) THEN
            RAISE EXCEPTION 'outbox row %: no complete, unexpired, signed approval allows it',
                OLD.id USING ERRCODE = 'QC422';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;"""  # noqa: S608 - constant SQL

# A person's live check as the web hands it in (identity.LiveCheck.snapshot): an ok check of a
# person, this user, with its lists, at most 30 seconds old, its time a UTC time as the web
# writes it (never a word PostgreSQL reads as one, such as 'now'). Returns its time.
LIVE_CHECK = """
CREATE FUNCTION argus_live_check_at(p_check jsonb, p_user bigint, p_act text, p_role text)
RETURNS timestamptz
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    checked timestamptz;
BEGIN
    IF jsonb_typeof(p_check) IS DISTINCT FROM 'object'
       OR p_check ->> 'outcome' IS DISTINCT FROM 'ok'
       OR p_check ->> 'kind' IS DISTINCT FROM 'person'
       OR p_check ->> 'user_id' IS DISTINCT FROM p_user::text
       OR jsonb_typeof(p_check -> 'capabilities') IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_check -> 'kibana') IS DISTINCT FROM 'array'
       OR jsonb_typeof(p_check -> 'checked_at') IS DISTINCT FROM 'string' THEN
        RAISE EXCEPTION '% needs a live check of the %', p_act, p_role USING ERRCODE = 'QC403';
    END IF;
    IF p_check ->> 'checked_at' !~ ('^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}'
                                    || ':[0-9]{2}[.][0-9]{6}[+]00:00$') THEN
        RAISE EXCEPTION 'the live check has no valid time' USING ERRCODE = 'QC422';
    END IF;
    BEGIN
        checked := (p_check ->> 'checked_at')::timestamptz;
    EXCEPTION WHEN others THEN
        RAISE EXCEPTION 'the live check has no valid time' USING ERRCODE = 'QC422';
    END;
    IF checked < clock_timestamp() - interval '30 seconds'
       OR checked > clock_timestamp() + interval '5 seconds' THEN
        RAISE EXCEPTION 'the live check is older than 30 seconds' USING ERRCODE = 'QC403';
    END IF;
    RETURN checked;
END
$$;
"""

IDENTITY_RECORD = """
CREATE FUNCTION argus_identity_record(
    p_user bigint, p_outcome text, p_provider text, p_purpose text, p_snapshot jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    new_id bigint;
BEGIN
    INSERT INTO public.identity_checks (user_id, outcome, provider, purpose, snapshot)
        VALUES (p_user, p_outcome, p_provider, p_purpose, coalesce(p_snapshot, '{}'::jsonb))
        RETURNING id INTO new_id;
    RETURN new_id;
END
$$;
"""

# The approver is the person of the session (as in 0026); the step-up is that session's own,
# within 5 minutes, and exactly the one the web signed; the identity check is the web's live
# check of that person (Q-E1's provider), at most 30 seconds old.
DECIDE = f"""
CREATE FUNCTION argus_approval_decide(
    p_session_token text, p_request bigint, p_decision text, p_note text,
    p_stepped_up_at timestamptz, p_check jsonb, p_signature text, p_batch jsonb
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint := public.argus_approval_session_user(p_session_token);
    stepped timestamptz;
    checked timestamptz;
    r record;
    w record;
    requester bigint;
    requester_check jsonb;
    privilege text;
    approved bigint;
    rejected bigint;
    decision_id bigint;
    status text;
    members bigint[];
    sample bigint[];
    n integer;
BEGIN
    IF p_decision NOT IN ('approved', 'rejected') THEN
        RAISE EXCEPTION 'a decision is approved or rejected' USING ERRCODE = 'QC422';
    END IF;
    SELECT s.stepped_up_at INTO stepped FROM public.user_sessions s
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex');
    IF stepped IS NULL OR stepped < clock_timestamp() - interval '5 minutes'
       OR stepped > clock_timestamp() THEN
        RAISE EXCEPTION 'confirm your password first: approving needs a step-up within 5 minutes'
            USING ERRCODE = 'QC412';
    END IF;
    IF p_stepped_up_at IS DISTINCT FROM stepped THEN
        RAISE EXCEPTION 'the decision names another step-up than this session''s latest'
            USING ERRCODE = 'QC422';
    END IF;
    checked := public.argus_live_check_at(p_check, uid, 'approving', 'approver');
    IF NOT (p_check -> 'capabilities' ? 'approve' AND p_check -> 'capabilities' ? 'manage_cases'
            AND p_check -> 'capabilities' ? 'view') THEN
        RAISE EXCEPTION 'approving needs the approver capability' USING ERRCODE = 'QC403';
    END IF;
    IF p_signature IS NULL OR p_signature !~ '^hmac-sha256:[0-9a-f]{{16}}:[0-9a-f]{{64}}$' THEN
        RAISE EXCEPTION 'a decision carries the web''s signature' USING ERRCODE = 'QC422';
    END IF;
    PERFORM 1 FROM public.cases k WHERE k.id IN (
            SELECT q.case_id FROM public.approval_requests q WHERE q.id = p_request
            UNION SELECT q.target_case_id FROM public.approval_requests q WHERE q.id = p_request)
        ORDER BY k.id FOR UPDATE;
    SELECT q.id, q.case_id, q.case_version, q.kind, q.reason, q.required_approvals,
           q.expires_at, q.requested_by_user_id, q.requester_check, q.payload, q.outbox_id,
           q.target_case_id INTO r
        FROM public.approval_requests q WHERE q.id = p_request FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such approval request' USING ERRCODE = 'QC404';
    END IF;
    -- who asked: the person of the request, or for a re-confirmation the person who asked for
    -- the closure it re-confirms (ARGUS's own proposals have no person behind them)
    requester := r.requested_by_user_id;
    requester_check := r.requester_check;
    IF r.kind = 'reconfirm' THEN
        SELECT q.requested_by_user_id, q.requester_check INTO requester, requester_check
            FROM public.kibana_outbox x JOIN public.approval_requests q
              ON q.id = x.approval_request_id
            WHERE x.id = r.outbox_id;
    END IF;
    IF requester = uid THEN
        RAISE EXCEPTION 'a person cannot approve their own request' USING ERRCODE = 'QC403';
    END IF;
    IF p_decision = 'approved' AND requester IS NOT NULL AND requester_check IS NULL THEN
        RAISE EXCEPTION 'this request was made before requests named their requester''s check:'
            ' ask again' USING ERRCODE = 'QC409';
    END IF;
    IF EXISTS (SELECT 1 FROM public.approval_decisions d
               WHERE d.request_id = r.id AND d.approver_user_id = uid) THEN
        RAISE EXCEPTION 'this person already decided' USING ERRCODE = 'QC409';
    END IF;
    -- one person behind two accounts (the same argus_uid or e-mail address, plan §7.1) is one
    -- person: never the requester's approver, never both approvers
    IF requester IS NOT NULL AND (
            (requester_check ->> 'argus_uid') = (p_check ->> 'argus_uid')
            OR lower(requester_check ->> 'email') = lower(p_check ->> 'email')
            OR EXISTS (SELECT 1 FROM public.identity_checks c
                       WHERE c.user_id = requester AND c.outcome = 'ok'
                         AND ((c.snapshot ->> 'argus_uid') = (p_check ->> 'argus_uid')
                              OR lower(c.snapshot ->> 'email') = lower(p_check ->> 'email'))))
    THEN
        RAISE EXCEPTION 'a person cannot approve their own request' USING ERRCODE = 'QC403';
    END IF;
    IF EXISTS (SELECT 1 FROM public.approval_decisions d
               WHERE d.request_id = r.id AND d.decision = 'approved'
                 AND ((d.identity_check ->> 'argus_uid') = (p_check ->> 'argus_uid')
                      OR lower(d.identity_check ->> 'email') = lower(p_check ->> 'email'))) THEN
        RAISE EXCEPTION 'two approvals of one request come from two different people'
            USING ERRCODE = 'QC403';
    END IF;
    SELECT count(*) FILTER (WHERE d.decision = 'approved' AND {NOT_REVOKED}),
           count(*) FILTER (WHERE d.decision = 'rejected')
        INTO approved, rejected FROM public.approval_decisions d WHERE d.request_id = r.id;
    IF rejected > 0 OR approved >= r.required_approvals THEN
        RAISE EXCEPTION 'approval request % is already decided', r.id USING ERRCODE = 'QC409';
    END IF;
    IF clock_timestamp() > r.expires_at THEN
        RAISE EXCEPTION 'approval request % expired', r.id USING ERRCODE = 'QC410';
    END IF;
    IF (SELECT k.version FROM public.cases k WHERE k.id = r.case_id) <> r.case_version THEN
        RAISE EXCEPTION 'the case changed after the request' USING ERRCODE = 'QC409';
    END IF;
    IF p_decision = 'approved' AND r.kind = 'merge' AND EXISTS (
            SELECT 1 FROM public.cases t WHERE t.id = r.target_case_id AND t.state = 'closed') THEN
        RAISE EXCEPTION 'the target case is closed: this merge cannot be approved'
            USING ERRCODE = 'QC409';
    END IF;
    -- a write of an outbox row (a resend, a compensating write, a re-confirmation) needs the
    -- approver's own Kibana privilege for it: createCase for a create, createComment for
    -- another W1 write, updateCase for a W2 or W3 write
    IF p_decision = 'approved' AND r.outbox_id IS NOT NULL THEN
        SELECT x.write_class, x.op INTO w FROM public.kibana_outbox x WHERE x.id = r.outbox_id;
        privilege := CASE WHEN w.write_class = 'W1' AND w.op = 'create' THEN 'createCase'
                          WHEN w.write_class = 'W1' THEN 'createComment'
                          ELSE 'updateCase' END;
        IF NOT p_check -> 'kibana' ? privilege THEN
            RAISE EXCEPTION 'this write to Kibana needs your own % privilege there', privilege
                USING ERRCODE = 'QC403';
        END IF;
    END IF;
    -- what the approval lets ARGUS write to Kibana: only what the approver's own Kibana
    -- privileges allow (no confused deputy, plan §3 rule 6)
    IF p_decision = 'approved'
       AND jsonb_typeof(r.payload -> 'writes') = 'array'
       AND jsonb_array_length(r.payload -> 'writes') > 0
       AND NOT p_check -> 'kibana' ? 'updateCase' THEN
        RAISE EXCEPTION 'closing this case in Kibana needs your own updateCase privilege there'
            USING ERRCODE = 'QC403';
    END IF;
    IF p_batch IS NOT NULL THEN
        IF jsonb_typeof(p_batch) IS DISTINCT FROM 'object'
           OR jsonb_typeof(p_batch -> 'requests') IS DISTINCT FROM 'array'
           OR jsonb_typeof(p_batch -> 'sample') IS DISTINCT FROM 'array' THEN
            RAISE EXCEPTION 'a group names its requests and its sample' USING ERRCODE = 'QC422';
        END IF;
        IF jsonb_array_length(p_batch -> 'requests') > 20 OR EXISTS (
                SELECT 1 FROM jsonb_array_elements(
                    (p_batch -> 'requests') || (p_batch -> 'sample')) x
                WHERE jsonb_typeof(x) <> 'number' OR (x #>> '{{}}') !~ '^[1-9][0-9]{{0,17}}$') THEN
            RAISE EXCEPTION 'a group names its requests and its sample by their ids'
                USING ERRCODE = 'QC422';
        END IF;
        members := ARRAY(SELECT (x #>> '{{}}')::bigint
                         FROM jsonb_array_elements(p_batch -> 'requests') x);
        sample := ARRAY(SELECT (x #>> '{{}}')::bigint
                        FROM jsonb_array_elements(p_batch -> 'sample') x);
        n := cardinality(members);
        IF n < 2 OR n > 20
           OR n <> (SELECT count(DISTINCT m) FROM unnest(members) m)
           OR cardinality(sample) <> (SELECT count(DISTINCT s) FROM unnest(sample) s)
           OR cardinality(sample) <> least(n, greatest(3, ceil(n / 10.0)::integer))
           OR NOT sample <@ members OR NOT r.id = ANY(members) THEN
            RAISE EXCEPTION 'a group holds 2 to 20 requests and a sample of max(3, 10 %%) of them'
                USING ERRCODE = 'QC422';
        END IF;
        IF p_decision <> 'approved' THEN
            RAISE EXCEPTION 'a group only approves: reject an item on its own'
                USING ERRCODE = 'QC422';
        END IF;
        IF (SELECT count(*) FROM public.approval_requests q WHERE q.id = ANY(members)
              AND q.kind = 'closure' AND q.required_approvals = 1
              AND q.reason IN ('attempt_no_impact', 'rule_false_positive', 'benign_expected',
                               'benign_policy')) <> n THEN
            RAISE EXCEPTION 'only benign, false-positive and no-impact closures go in groups'
                USING ERRCODE = 'QC422';
        END IF;
        IF NOT r.id = ANY(sample) AND EXISTS (
                SELECT 1 FROM unnest(sample) s WHERE NOT EXISTS (
                    SELECT 1 FROM public.approval_decisions d WHERE d.request_id = s
                      AND d.approver_user_id = uid AND d.decision = 'approved'
                      AND d.batch = p_batch)) THEN
            RAISE EXCEPTION 'approve the group''s sample one by one first'
                USING ERRCODE = 'QC409';
        END IF;
    END IF;
    INSERT INTO public.approval_decisions (request_id, approver_user_id, decision, capabilities,
            stepped_up_at, identity_check, signature, batch, note)
        VALUES (r.id, uid, p_decision, p_check -> 'capabilities', stepped, p_check, p_signature,
                p_batch, p_note)
        RETURNING id INTO decision_id;
    INSERT INTO public.identity_checks (user_id, outcome, provider, purpose, snapshot)
        VALUES (uid, 'ok', coalesce(p_check ->> 'provider', 'unknown'), 'approval', p_check);
    status := CASE WHEN p_decision = 'rejected' THEN 'rejected'
                   WHEN approved + 1 >= r.required_approvals THEN 'approved'
                   ELSE 'pending' END;
    INSERT INTO public.audit_events (actor, action, target_type, target_id, details)
        VALUES ('user:' || uid, 'case.approval.' || p_decision, 'case', r.case_id::text,
                jsonb_build_object('request', r.id, 'decision', decision_id, 'kind', r.kind,
                    'capabilities', p_check -> 'capabilities', 'status', status,
                    'approvals', approved + CASE WHEN p_decision = 'approved' THEN 1 ELSE 0 END,
                    'required', r.required_approvals, 'signature', p_signature,
                    'stepped_up_at', public.argus_chain_time(stepped),
                    'batch', p_batch, 'via', 'approvals'));
    RETURN status;
END
$$;
"""  # noqa: S608 - constant SQL

# ARGUS's own requests (the runtime may call it): a closure it proposes after its own request
# event, for a reason with positive evidence; or a re-confirmation of a closure write its
# send-time check held back (bound to the case's alerts and Kibana version now). A person still
# approves each one; ARGUS never approves.
PROPOSE = """
CREATE FUNCTION argus_approval_propose(
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
        IF p_reason IS NULL OR p_reason NOT IN ('remediated_verified', 'attempt_no_impact',
                'rule_false_positive', 'benign_expected', 'benign_policy') THEN
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

# 0026's request function, which now also takes the requester's live check (as the decide
# function takes the approver's): validated, stored with the request (and so signed with
# every decision on it) and recorded as an identity check, so the decide function and the
# send-time check can tell one person behind two accounts (plan §7.1).
REQUEST = """
CREATE FUNCTION argus_approval_request(
    p_session_token text, p_case uuid, p_case_version integer, p_kind text, p_reason text,
    p_target uuid, p_outbox bigint, p_payload jsonb, p_payload_hash text,
    p_kibana_version text, p_expires_at timestamptz, p_note text, p_check jsonb
) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint := public.argus_approval_session_user(p_session_token);
    c record;
    sent integer;
    n_alerts bigint;
    digest text;
    needed smallint;
    new_id bigint;
BEGIN
    PERFORM public.argus_live_check_at(p_check, uid, 'requesting', 'requester');
    SELECT k.version, k.state INTO c FROM public.cases k WHERE k.id = p_case FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such case' USING ERRCODE = 'QC404';
    END IF;
    IF c.version <> p_case_version THEN
        RAISE EXCEPTION 'the case is at version %, not %', c.version, p_case_version
            USING ERRCODE = 'QC409';
    END IF;
    IF p_kind IN ('closure', 'merge') AND c.state NOT IN ('open', 'assigned', 'contained') THEN
        RAISE EXCEPTION 'a % case cannot be closed or merged by approval', c.state
            USING ERRCODE = 'QC409';
    END IF;
    IF p_target IS NOT NULL AND (p_target = p_case OR NOT EXISTS (
            SELECT 1 FROM public.cases t WHERE t.id = p_target AND t.state <> 'closed')) THEN
        RAISE EXCEPTION 'a merge goes into another case that is not closed'
            USING ERRCODE = 'QC409';
    END IF;
    IF p_outbox IS NOT NULL THEN
        SELECT o.sent_count INTO sent FROM public.kibana_outbox o
            WHERE o.id = p_outbox AND o.case_id = p_case
              AND (p_kind <> 'resend' OR o.state = 'ambiguous') FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the outbox row is not this case''s, or (for a resend) not in doubt'
                USING ERRCODE = 'QC422';
        END IF;
    END IF;
    IF p_expires_at <= clock_timestamp() OR p_expires_at > now() + interval '72 hours' THEN
        RAISE EXCEPTION 'an approval expires within 72 hours' USING ERRCODE = 'QC422';
    END IF;
    SELECT count(*), encode(sha256(convert_to(coalesce(
               string_agg(a.alert_id, E'\\n' ORDER BY a.alert_id COLLATE "C"), ''), 'UTF8')), 'hex')
        INTO n_alerts, digest
        FROM (SELECT DISTINCT ia.alert_id::text AS alert_id FROM public.case_members m
              JOIN public.investigation_alerts ia ON ia.investigation_id = m.investigation_id
              WHERE m.case_id = p_case AND m.removed_at IS NULL) a;
    needed := CASE WHEN p_reason IN ('remediated_unverified', 'risk_accepted') THEN 2 ELSE 1 END;
    INSERT INTO public.approval_requests (case_id, case_version, kind, reason, target_case_id,
            outbox_id, outbox_sent_count, payload, payload_hash, alert_count, alert_digest,
            kibana_version, required_approvals, requested_by_user_id, requester_check,
            expires_at, note)
        VALUES (p_case, p_case_version, p_kind, p_reason, p_target, p_outbox,
                CASE WHEN p_kind = 'resend' THEN sent END, p_payload, p_payload_hash, n_alerts,
                digest, p_kibana_version, needed, uid, p_check, p_expires_at, p_note)
        RETURNING id INTO new_id;
    INSERT INTO public.identity_checks (user_id, outcome, provider, purpose, snapshot)
        VALUES (uid, 'ok', coalesce(p_check ->> 'provider', 'unknown'), 'request', p_check);
    INSERT INTO public.audit_events (actor, action, target_type, target_id, details)
        VALUES ('user:' || uid, 'case.approval.requested', 'case', p_case::text,
                jsonb_build_object('request', new_id, 'kind', p_kind, 'reason', p_reason,
                    'case_version', p_case_version, 'payload_hash', p_payload_hash,
                    'alert_count', n_alerts, 'alert_digest', digest, 'required', needed,
                    'expires_at', public.argus_chain_time(p_expires_at), 'outbox', p_outbox,
                    'outbox_sent_count', CASE WHEN p_kind = 'resend' THEN sent END,
                    'target', p_target, 'via', 'approvals'));
    RETURN new_id;
END
$$;
"""

# The send-time check's lock on a closure write (argus.cases.sendcheck.admit): the row lock
# belongs to the caller's transaction, which a plain SELECT ... FOR UPDATE would give only to a
# role holding UPDATE on the outbox.
CLOSURE_WRITE_LOCK = """
CREATE FUNCTION argus_closure_write_lock(p_outbox bigint) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM 1 FROM public.kibana_outbox x WHERE x.id = p_outbox AND x.write_class = 'W3'
        FOR UPDATE;
    RETURN FOUND;
END
$$;
"""

# The send-time check's moves of a closure write (argus.cases.sendcheck.release), the only
# outbox moves the runtime may make (it holds no UPDATE on the outbox): let it go (approved),
# hold it for a re-confirmation or refuse it (paused, the reason saying which) or skip it. A
# write paused for any other reason (refused, or by anything but this function) waits for a
# person: only a skip (its case changed) moves it. The outbox guard keeps every other rule;
# each move that changes the state, or turns a hold into a refusal, is audited.
CLOSURE_WRITE_MOVE = """
CREATE FUNCTION argus_closure_write_move(p_outbox bigint, p_state text, p_reason text)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    o record;
    action text;
BEGIN
    SELECT x.case_id, x.write_class, x.state, x.state_reason INTO o
        FROM public.kibana_outbox x WHERE x.id = p_outbox FOR UPDATE;
    IF NOT FOUND OR o.write_class <> 'W3' THEN
        RAISE EXCEPTION 'outbox row %: not a closure write', p_outbox USING ERRCODE = 'QC422';
    END IF;
    IF o.state NOT IN ('planned', 'approved', 'paused') THEN
        RAISE EXCEPTION 'outbox row %: a % closure write is the writer''s', p_outbox, o.state
            USING ERRCODE = 'QC409';
    END IF;
    IF p_state IS NULL OR p_state NOT IN ('approved', 'paused', 'skipped')
       OR (p_state = 'approved') <> (p_reason IS NULL)
       OR (p_state = 'paused' AND NOT (starts_with(p_reason, 're-confirm: ')
                                       OR starts_with(p_reason, 'refused: ')))
       OR length(p_reason) > 1000 THEN
        RAISE EXCEPTION 'outbox row %: not a move of the send-time check', p_outbox
            USING ERRCODE = 'QC422';
    END IF;
    IF o.state = 'paused' AND NOT starts_with(coalesce(o.state_reason, ''), 're-confirm: ')
       AND p_state <> 'skipped' THEN
        RAISE EXCEPTION 'outbox row %: the closure write waits for a person', p_outbox
            USING ERRCODE = 'QC409';
    END IF;
    IF o.state = p_state AND o.state_reason IS NOT DISTINCT FROM p_reason THEN
        RETURN false;
    END IF;
    UPDATE public.kibana_outbox SET state = p_state, state_reason = p_reason WHERE id = p_outbox;
    action := CASE WHEN p_state = 'approved' THEN 'released'
                   WHEN p_state = 'skipped' THEN 'skipped'
                   WHEN starts_with(p_reason, 'refused: ') THEN 'refused'
                   ELSE 'held' END;
    IF o.state <> p_state OR (action = 'refused'
                              AND NOT starts_with(coalesce(o.state_reason, ''), 'refused: ')) THEN
        INSERT INTO public.audit_events (actor, action, target_type, target_id, details)
            VALUES ('argus:sendcheck', 'case.closure_write.' || action, 'case', o.case_id::text,
                    jsonb_build_object('outbox', p_outbox, 'from', o.state, 'to', p_state,
                                       'reason', p_reason));
    END IF;
    RETURN true;
END
$$;
"""

OLD_DECIDE = "argus_approval_decide(text, bigint, text, jsonb, text)"
NEW_DECIDE = "argus_approval_decide(text, bigint, text, text, timestamptz, jsonb, text, jsonb)"
PROPOSE_FN = (
    "argus_approval_propose(text, uuid, integer, text, text, bigint, jsonb, text, text,"
    " timestamptz, text)"
)
IDENTITY_FN = "argus_identity_record(bigint, text, text, text, jsonb)"
OLD_REQUEST = (
    "argus_approval_request(text, uuid, integer, text, text, uuid, bigint, jsonb, text, text,"
    " timestamptz, text)"
)
NEW_REQUEST = (
    "argus_approval_request(text, uuid, integer, text, text, uuid, bigint, jsonb, text, text,"
    " timestamptz, text, jsonb)"
)
LIVE_CHECK_FN = "argus_live_check_at(jsonb, bigint, text, text)"
MOVE_FN = "argus_closure_write_move(bigint, text, text)"
LOCK_FN = "argus_closure_write_lock(bigint)"

# The web signs what it approves: it reads the request and the person's checks (Q-A2's
# argus_web holds nothing else on the case tables; Q-B3 adds what its pages need).
WEB_GRANTS = (
    "GRANT SELECT ON approval_requests TO argus_web",
    "GRANT SELECT ON approval_decisions TO argus_web",
    "GRANT SELECT ON identity_checks TO argus_web",
)

KIND_FIELDS_OLD = (
    "(kind IN ('closure', 'merge')) = (reason IS NOT NULL)"
    " AND (kind <> 'closure' OR reason <> 'duplicate')"
    " AND (kind = 'merge') = (target_case_id IS NOT NULL)"
    " AND (kind <> 'merge' OR reason = 'duplicate')"
    " AND (kind IN ('compensating', 'resend')) = (outbox_id IS NOT NULL)"
    " AND (kind = 'resend') = (outbox_sent_count IS NOT NULL)"
)
KIND_FIELDS_NEW = (
    "(kind IN ('closure', 'merge')) = (reason IS NOT NULL)"
    " AND (kind <> 'closure' OR reason <> 'duplicate')"
    " AND (kind = 'merge') = (target_case_id IS NOT NULL)"
    " AND (kind <> 'merge' OR reason = 'duplicate')"
    " AND (kind IN ('compensating', 'resend', 'reconfirm')) = (outbox_id IS NOT NULL)"
    " AND (kind = 'resend') = (outbox_sent_count IS NOT NULL)"
    " AND (kind <> 'reconfirm' OR proposed_by IS NOT NULL)"
)
KINDS_OLD = "kind IN ('closure', 'merge', 'compensating', 'resend')"
KINDS_NEW = "kind IN ('closure', 'merge', 'compensating', 'resend', 'reconfirm')"


def upgrade() -> None:
    m0026 = _m0026()
    op.add_column("approval_requests", sa.Column("proposed_by", sa.Text(), nullable=True))
    op.add_column(
        "approval_requests",
        sa.Column("requester_check", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_approval_requests_requester_check_is_object"),
        "approval_requests",
        "requester_check IS NULL OR jsonb_typeof(requester_check) = 'object'",
    )
    op.alter_column("approval_requests", "requested_by_user_id", nullable=True)
    op.create_check_constraint(
        op.f("ck_approval_requests_requester_or_proposer"),
        "approval_requests",
        "(requested_by_user_id IS NULL) = (proposed_by IS NOT NULL)"
        " AND (proposed_by IS NULL OR proposed_by ~ '^argus:[a-z][a-z0-9_.-]{0,59}$')",
    )
    op.drop_constraint(op.f("ck_approval_requests_kind_fields"), "approval_requests", "check")
    op.create_check_constraint(
        op.f("ck_approval_requests_kind_fields"), "approval_requests", KIND_FIELDS_NEW
    )
    op.drop_constraint(op.f("ck_approval_requests_kind_valid"), "approval_requests", "check")
    op.create_check_constraint(
        op.f("ck_approval_requests_kind_valid"), "approval_requests", KINDS_NEW
    )

    op.add_column(
        "approval_decisions",
        sa.Column("identity_check", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("approval_decisions", sa.Column("signature", sa.Text(), nullable=True))
    op.add_column(
        "approval_decisions",
        sa.Column("batch", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.create_check_constraint(
        op.f("ck_approval_decisions_signed_check"),
        "approval_decisions",
        "(signature IS NULL) = (identity_check IS NULL)"
        " AND (signature IS NULL OR signature ~ '^hmac-sha256:[0-9a-f]{16}:[0-9a-f]{64}$')"
        " AND (identity_check IS NULL OR jsonb_typeof(identity_check) = 'object')"
        " AND (batch IS NULL OR jsonb_typeof(batch) = 'object')",
    )

    op.create_table(
        "identity_checks",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("user_id", sa.BigInteger(), nullable=False),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("clock_timestamp()"),
            nullable=False,
        ),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("provider", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column(
            "snapshot",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('ok', 'denied', 'unavailable')",
            name=op.f("ck_identity_checks_outcome_valid"),
        ),
        sa.CheckConstraint(
            "purpose IN ('signin', 'recheck', 'stepup', 'request', 'approval', 'send')",
            name=op.f("ck_identity_checks_purpose_valid"),
        ),
        sa.CheckConstraint(
            "provider ~ '^[a-z][a-z0-9_.-]{0,31}$'", name=op.f("ck_identity_checks_provider_valid")
        ),
        sa.CheckConstraint(
            "jsonb_typeof(snapshot) = 'object'", name=op.f("ck_identity_checks_snapshot_is_object")
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_identity_checks_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_identity_checks")),
    )
    op.create_index(
        op.f("ix_identity_checks_user_id_recorded_at"),
        "identity_checks",
        ["user_id", "recorded_at"],
    )
    op.execute(
        "CREATE TRIGGER identity_checks_append_only_rows BEFORE UPDATE OR DELETE ON identity_checks"
        " FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER identity_checks_append_only_truncate BEFORE TRUNCATE ON identity_checks"
        " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    for trigger in ("identity_checks_append_only_rows", "identity_checks_append_only_truncate"):
        op.execute(f"ALTER TABLE identity_checks ENABLE ALWAYS TRIGGER {trigger}")

    guard = _swap(m0026.CASE_GUARD, _CASE_COUNT_OLD, _CASE_COUNT_NEW)
    op.execute(guard.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    outbox = _swap(m0026.OUTBOX_GUARD, _OUTBOX_COUNT_OLD, _OUTBOX_COUNT_NEW)
    outbox = _swap(outbox, _OUTBOX_END_OLD, _OUTBOX_END_NEW)
    op.execute(outbox.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))

    op.execute(f"DROP FUNCTION {OLD_DECIDE}")
    op.execute(f"DROP FUNCTION {OLD_REQUEST}")
    op.execute(LIVE_CHECK)
    op.execute(REQUEST)
    op.execute(DECIDE)
    op.execute(PROPOSE)
    op.execute(IDENTITY_RECORD)
    op.execute(CLOSURE_WRITE_MOVE)
    op.execute(CLOSURE_WRITE_LOCK)
    for function in (
        LIVE_CHECK_FN, NEW_REQUEST, NEW_DECIDE, PROPOSE_FN, IDENTITY_FN, MOVE_FN, LOCK_FN
    ):  # fmt: skip
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
    op.execute(f"GRANT EXECUTE ON FUNCTION {NEW_REQUEST} TO argus_approvals")
    op.execute(f"GRANT EXECUTE ON FUNCTION {NEW_DECIDE} TO argus_approvals")
    op.execute(f"GRANT EXECUTE ON FUNCTION {IDENTITY_FN} TO argus_approvals")
    op.execute(f"GRANT EXECUTE ON FUNCTION {IDENTITY_FN} TO argus_web")
    op.execute(f"GRANT EXECUTE ON FUNCTION {PROPOSE_FN} TO argus_runtime")
    op.execute(f"GRANT EXECUTE ON FUNCTION {MOVE_FN} TO argus_runtime")
    op.execute(f"GRANT EXECUTE ON FUNCTION {LOCK_FN} TO argus_runtime")

    # The role names are written out, not imported (see 0003).
    op.execute("GRANT SELECT ON identity_checks TO argus_runtime")
    for grant in WEB_GRANTS:
        op.execute(grant)


def downgrade() -> None:
    m0026 = _m0026()
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM approval_requests WHERE proposed_by IS NOT NULL)"
        " THEN RAISE EXCEPTION 'ARGUS proposals exist: 0026 cannot hold them'"
        " USING ERRCODE = 'QC409'; END IF; END $$"
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'argus_web') THEN"
        " REVOKE SELECT ON approval_requests FROM argus_web;"
        " REVOKE SELECT ON approval_decisions FROM argus_web; END IF;"
        " END $$"
    )
    for function in (
        LOCK_FN, MOVE_FN, PROPOSE_FN, IDENTITY_FN, NEW_DECIDE, NEW_REQUEST, LIVE_CHECK_FN
    ):  # fmt: skip
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
    old = m0026.APPROVAL_FUNCTIONS.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION")
    op.execute(old)
    for function in (OLD_REQUEST, OLD_DECIDE):
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO argus_approvals")
    op.execute(m0026.CASE_GUARD.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    op.execute(m0026.OUTBOX_GUARD.replace("CREATE FUNCTION", "CREATE OR REPLACE FUNCTION"))
    op.drop_table("identity_checks")
    op.drop_constraint(op.f("ck_approval_decisions_signed_check"), "approval_decisions", "check")
    for column in ("batch", "signature", "identity_check"):
        op.drop_column("approval_decisions", column)
    op.drop_constraint(op.f("ck_approval_requests_kind_valid"), "approval_requests", "check")
    op.create_check_constraint(
        op.f("ck_approval_requests_kind_valid"), "approval_requests", KINDS_OLD
    )
    op.drop_constraint(op.f("ck_approval_requests_kind_fields"), "approval_requests", "check")
    op.create_check_constraint(
        op.f("ck_approval_requests_kind_fields"), "approval_requests", KIND_FIELDS_OLD
    )
    op.drop_constraint(
        op.f("ck_approval_requests_requester_or_proposer"), "approval_requests", "check"
    )
    op.drop_constraint(
        op.f("ck_approval_requests_requester_check_is_object"), "approval_requests", "check"
    )
    op.drop_column("approval_requests", "requester_check")
    op.alter_column("approval_requests", "requested_by_user_id", nullable=False)
    op.drop_column("approval_requests", "proposed_by")
