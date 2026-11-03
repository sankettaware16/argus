"""Cases, the Kibana outbox, approvals, notes, and the audit hash chain (Q-C1, plan §7.1, §7.9)

What the database itself guarantees, whatever code runs against it:

* **Hash chain** on ``audit_events`` and ``case_events``: an owner's trigger numbers every new
  row and stores sha256(previous hash, the row), so a changed, removed or reordered row breaks
  the chain (``argus audit verify``). The audit rows written before this migration are sealed
  into the chain's genesis hash. The runtime role cannot set the chain columns, and cannot write
  ``chain_heads``.
* **Cases** move only along the lifecycle's edges, their version rises by exactly one per change,
  every version has its case event with the same state, and a confirmed case is closed only with
  a complete, unexpired approval bound to its version and reason.
* **Outbox**: a case event's Kibana rows are exactly ``kibana_rows`` (checked at commit), rows
  never change their payload, their state moves only along the outbox's edges, and a write is
  sent a second time only after a person's approved resend.
* **Approvals** are inserted only by ``argus_approval_request()`` and ``argus_approval_decide()``,
  which ``argus_approvals`` may call and ARGUS's runtime role may not; requests, decisions,
  case events, notes, openings and the action ledger are append-only.

Revision ID: 0026
Revises: 0025
Create Date: 2026-10-22 (written as 0021; renumbered after Q-A2's 0021 and 0022, Q-F2's 0023 and
Q-A1's 0024 and 0025, 2026-10-23)
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Written out, not imported: a migration must keep doing what it did when it was written (0003).
# One advisory lock for both chains, so a transaction appending to both never waits for one head
# while holding the other (argus.cases.chain.CHAIN_LOCK_KEY).
CHAIN_LOCK_KEY = int.from_bytes(b"ARGUSCHN", "big")
APPEND_ONLY = (
    "case_events",
    "case_notes",
    "entity_notes",
    "case_openings",
    "approval_requests",
    "approval_decisions",
    "action_ledger",
)

ROLE_CHECK = """
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{role}') THEN
        RAISE EXCEPTION 'role "{role}" does not exist'
            USING ERRCODE = 'undefined_object',
                  HINT = 'run "argus db bootstrap" first';
    END IF;
END
$$
"""

# ---------------------------------------------------------------------------- the hash chain
# A field: 'N' for NULL, else 'S' <UTF-8 length> ':' <UTF-8 bytes>; self-delimiting, so no value
# can pass for two (argus.cases.chain.field mirrors it byte for byte). STABLE, as what they call
# (to_char, convert_to): the planner inlines them only then, which makes them ~10x faster.
CHAIN_FUNCTIONS = r"""
CREATE FUNCTION argus_chain_field(v text) RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT CASE WHEN v IS NULL THEN 'N' ELSE 'S' || octet_length(v) || ':' || v END
$$;

CREATE FUNCTION argus_chain_time(v timestamptz) RETURNS text
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT to_char(v AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

CREATE FUNCTION argus_audit_message(
    seq bigint, prev text, id bigint, occurred_at timestamptz, actor text, action text,
    outcome text, target_type text, target_id text, correlation_id text, details text
) RETURNS bytea
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT convert_to('argus-chain-v1:audit_events' || chr(10)
        || public.argus_chain_field(seq::text)
        || public.argus_chain_field(prev)
        || public.argus_chain_field(id::text)
        || public.argus_chain_field(public.argus_chain_time(occurred_at))
        || public.argus_chain_field(actor)
        || public.argus_chain_field(action)
        || public.argus_chain_field(outcome)
        || public.argus_chain_field(target_type)
        || public.argus_chain_field(target_id)
        || public.argus_chain_field(correlation_id)
        || public.argus_chain_field(details), 'UTF8')
$$;

CREATE FUNCTION argus_case_event_message(
    seq bigint, prev text, id bigint, case_id uuid, case_version integer, kind text,
    actor text, actor_user_id bigint, from_state text, to_state text, details text,
    kibana_rows integer, occurred_at timestamptz
) RETURNS bytea
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT convert_to('argus-chain-v1:case_events' || chr(10)
        || public.argus_chain_field(seq::text)
        || public.argus_chain_field(prev)
        || public.argus_chain_field(id::text)
        || public.argus_chain_field(case_id::text)
        || public.argus_chain_field(case_version::text)
        || public.argus_chain_field(kind)
        || public.argus_chain_field(actor)
        || public.argus_chain_field(actor_user_id::text)
        || public.argus_chain_field(from_state)
        || public.argus_chain_field(to_state)
        || public.argus_chain_field(details)
        || public.argus_chain_field(kibana_rows::text)
        || public.argus_chain_field(public.argus_chain_time(occurred_at)), 'UTF8')
$$;

CREATE FUNCTION argus_chain_append() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    head record;
    last record;
    message bytea;
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME NOT IN ('audit_events', 'case_events') THEN
        RAISE EXCEPTION 'argus_chain_append is not for %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- One writer at a time (to commit). Each row follows the newest chained row, which may be
    -- one this transaction wrote; the head moves once, at commit (argus_chain_flush), so a
    -- transaction writing many rows never updates one row many times. If rows were removed
    -- from the chain's end, the next row follows the head instead and the gap stays visible.
    PERFORM pg_advisory_xact_lock({lock_key});
    SELECT h.seq, h.head_hash INTO head FROM public.chain_heads h WHERE h.chain = TG_TABLE_NAME;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the % hash chain has no head', TG_TABLE_NAME;
    END IF;
    IF TG_TABLE_NAME = 'audit_events' THEN
        SELECT a.chain_seq, a.row_hash INTO last FROM public.audit_events a
            WHERE a.chain_seq IS NOT NULL ORDER BY a.chain_seq DESC LIMIT 1;
    ELSE
        SELECT e.chain_seq, e.row_hash INTO last FROM public.case_events e
            WHERE e.chain_seq IS NOT NULL ORDER BY e.chain_seq DESC LIMIT 1;
    END IF;
    IF FOUND AND last.chain_seq >= head.seq THEN
        NEW.chain_seq := last.chain_seq + 1;
        NEW.prev_hash := last.row_hash;
    ELSE
        NEW.chain_seq := head.seq + 1;
        NEW.prev_hash := head.head_hash;
    END IF;
    IF TG_TABLE_NAME = 'audit_events' THEN
        message := public.argus_audit_message(
            NEW.chain_seq, NEW.prev_hash, NEW.id, NEW.occurred_at, NEW.actor, NEW.action,
            NEW.outcome, NEW.target_type, NEW.target_id, NEW.correlation_id, NEW.details::text);
    ELSE
        message := public.argus_case_event_message(
            NEW.chain_seq, NEW.prev_hash, NEW.id, NEW.case_id, NEW.case_version, NEW.kind,
            NEW.actor, NEW.actor_user_id, NEW.from_state, NEW.to_state, NEW.details::text,
            NEW.kibana_rows, NEW.occurred_at);
    END IF;
    NEW.row_hash := encode(sha256(message), 'hex');
    RETURN NEW;
END
$$;

CREATE FUNCTION argus_chain_flush() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    head record;
    last record;
BEGIN
    IF TG_TABLE_SCHEMA <> 'public' OR TG_TABLE_NAME NOT IN ('audit_events', 'case_events') THEN
        RAISE EXCEPTION 'argus_chain_flush is not for %.%', TG_TABLE_SCHEMA, TG_TABLE_NAME
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    SELECT h.seq INTO head FROM public.chain_heads h WHERE h.chain = TG_TABLE_NAME;
    IF NEW.chain_seq IS NULL OR NEW.chain_seq <= head.seq THEN
        RETURN NULL;  -- an earlier row of this transaction moved the head already
    END IF;
    IF TG_TABLE_NAME = 'audit_events' THEN
        SELECT a.chain_seq, a.row_hash INTO last FROM public.audit_events a
            WHERE a.chain_seq IS NOT NULL ORDER BY a.chain_seq DESC LIMIT 1;
    ELSE
        SELECT e.chain_seq, e.row_hash INTO last FROM public.case_events e
            WHERE e.chain_seq IS NOT NULL ORDER BY e.chain_seq DESC LIMIT 1;
    END IF;
    UPDATE public.chain_heads SET seq = last.chain_seq, head_hash = last.row_hash
        WHERE chain = TG_TABLE_NAME;
    RETURN NULL;
END
$$;
""".replace("{lock_key}", str(CHAIN_LOCK_KEY))

# The audit rows written before the chain, sealed into its genesis: sha256(seed, then each row's
# digest in id order) (argus.cases.chain.seal).
LEGACY_SEAL = """
DO $$
DECLARE
    n bigint;
    top bigint;
    seal bytea;
BEGIN
    IF current_setting('server_encoding') <> 'UTF8' THEN
        RAISE EXCEPTION 'the hash chain needs a UTF8 database (octet_length is its UTF-8 length)';
    END IF;
    SELECT count(*), coalesce(max(a.id), 0),
           sha256(sha256(convert_to('argus-chain-v1:audit_events:legacy', 'UTF8'))
                  || coalesce(string_agg(sha256(public.argus_audit_message(
                         NULL, NULL, a.id, a.occurred_at, a.actor, a.action, a.outcome,
                         a.target_type, a.target_id, a.correlation_id, a.details::text)),
                     ''::bytea ORDER BY a.id), ''::bytea))
        INTO n, top, seal FROM public.audit_events a;
    INSERT INTO public.chain_heads (chain, seq, head_hash, genesis_hash, legacy_rows, legacy_max_id)
        VALUES ('audit_events', 0, encode(seal, 'hex'), encode(seal, 'hex'), n, top);
    INSERT INTO public.chain_heads (chain, seq, head_hash, genesis_hash, legacy_rows, legacy_max_id)
        VALUES ('case_events', 0,
                encode(sha256(convert_to('argus-chain-v1:case_events:genesis', 'UTF8')), 'hex'),
                encode(sha256(convert_to('argus-chain-v1:case_events:genesis', 'UTF8')), 'hex'),
                0, 0);
END
$$
"""

# A TRUNCATE of an append-only table that holds rows is refused; of an empty one (the rebuild
# of derived tables, argus db regroup, which refuses while cases exist) it loses nothing. The
# TRUNCATE holds its exclusive lock while this runs, so no row can arrive meanwhile.
TRUNCATE_GUARD = """
CREATE FUNCTION argus_reject_truncate_unless_empty() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    found boolean;
BEGIN
    EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I.%I)', TG_TABLE_SCHEMA, TG_TABLE_NAME)
        INTO found;
    IF found THEN
        RAISE EXCEPTION 'table % is append-only: % rejected', TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END IF;
    RETURN NULL;
END
$$;
"""

# ---------------------------------------------------------------------------- cases
# The lifecycle's edges (plan §7.1), as argus.cases.machine.EDGES; a same-state update (a link,
# a request, a reassignment) keeps the state.
CASE_GUARD = """
CREATE FUNCTION argus_case_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    req record;
    approved bigint;
    rejected bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state NOT IN ('suspected', 'open') THEN
            RAISE EXCEPTION 'a case starts at version 1, suspected or open'
                USING ERRCODE = 'QC422';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.number <> OLD.number OR NEW.cause <> OLD.cause
       OR NEW.cause_review_id IS DISTINCT FROM OLD.cause_review_id
       OR NEW.cause_assessment_id IS DISTINCT FROM OLD.cause_assessment_id
       OR NEW.parent_case_id IS DISTINCT FROM OLD.parent_case_id
       OR NEW.created_at <> OLD.created_at
       OR (OLD.opened_at IS NOT NULL AND NEW.opened_at IS DISTINCT FROM OLD.opened_at) THEN
        RAISE EXCEPTION 'case %: a fixed field changed', OLD.id USING ERRCODE = 'QC422';
    END IF;
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'case %: version % does not follow %', OLD.id, NEW.version, OLD.version
            USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
        ('suspected', 'open'), ('suspected', 'closed'),
        ('open', 'assigned'), ('open', 'contained'), ('open', 'closed'),
        ('assigned', 'open'), ('assigned', 'contained'), ('assigned', 'closed'),
        ('contained', 'open'), ('contained', 'closed'),
        ('closed', 'open'), ('closed', 'suspected')
    ) THEN
        RAISE EXCEPTION 'case %: % to % is not a lifecycle move', OLD.id, OLD.state, NEW.state
            USING ERRCODE = 'QC422';
    END IF;
    IF OLD.state = 'closed' AND NEW.state = 'closed' AND (
        NEW.closure_reason IS DISTINCT FROM OLD.closure_reason
        OR NEW.closure_request_id IS DISTINCT FROM OLD.closure_request_id
        OR NEW.closed_at IS DISTINCT FROM OLD.closed_at
        OR NEW.merged_into_id IS DISTINCT FROM OLD.merged_into_id) THEN
        RAISE EXCEPTION 'case %: a closed case keeps its closure', OLD.id USING ERRCODE = 'QC422';
    END IF;
    IF OLD.state = 'closed' AND NEW.state = 'open' AND OLD.opened_at IS NULL THEN
        RAISE EXCEPTION 'case %: a dismissed case reopens as suspected', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF OLD.state = 'closed' AND NEW.state = 'suspected' AND OLD.opened_at IS NOT NULL THEN
        RAISE EXCEPTION 'case %: a confirmed case reopens as open', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state = 'closed' AND OLD.state <> 'closed' AND NEW.opened_at IS NOT NULL THEN
        SELECT r.id, r.case_id, r.case_version, r.kind, r.reason, r.target_case_id,
               r.required_approvals, r.expires_at INTO req
            FROM public.approval_requests r WHERE r.id = NEW.closure_request_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'case %: closing a confirmed case needs an approval', OLD.id
                USING ERRCODE = 'QC422';
        END IF;
        SELECT count(*) FILTER (WHERE d.decision = 'approved'),
               count(*) FILTER (WHERE d.decision = 'rejected')
            INTO approved, rejected
            FROM public.approval_decisions d WHERE d.request_id = req.id;
        IF req.case_id <> OLD.id OR req.case_version <> OLD.version
           OR req.kind NOT IN ('closure', 'merge') OR req.reason <> NEW.closure_reason
           OR clock_timestamp() > req.expires_at OR rejected > 0
           OR approved < req.required_approvals
           OR (req.kind = 'merge') <> (NEW.merged_into_id IS NOT NULL)
           OR (req.kind = 'merge' AND req.target_case_id <> NEW.merged_into_id) THEN
            RAISE EXCEPTION 'case %: approval % does not allow this closure', OLD.id, req.id
                USING ERRCODE = 'QC422';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;

CREATE FUNCTION argus_case_has_event() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM public.case_events e WHERE e.case_id = NEW.id
                   AND e.case_version = NEW.version AND e.to_state = NEW.state) THEN
        RAISE EXCEPTION 'case % version % (%) has no case event', NEW.id, NEW.version, NEW.state
            USING ERRCODE = 'QC422';
    END IF;
    RETURN NULL;
END
$$;

-- An event records the change just made: the case row is already at the event's version and
-- state (CaseService writes the row first), and the event starts where the one before ended.
CREATE FUNCTION argus_case_event_follows() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    c record;
    before_state text;
BEGIN
    SELECT k.version, k.state INTO c FROM public.cases k WHERE k.id = NEW.case_id;
    IF NOT FOUND OR c.version <> NEW.case_version OR c.state <> NEW.to_state THEN
        RAISE EXCEPTION 'case event: case % is not at version % (%)', NEW.case_id,
            NEW.case_version, NEW.to_state USING ERRCODE = 'QC422';
    END IF;
    IF NEW.case_version > 1 THEN
        SELECT e.to_state INTO before_state FROM public.case_events e
            WHERE e.case_id = NEW.case_id AND e.case_version = NEW.case_version - 1;
    END IF;
    IF NEW.from_state IS DISTINCT FROM before_state THEN
        RAISE EXCEPTION 'case event: version % of case % does not start where % ended',
            NEW.case_version, NEW.case_id, NEW.case_version - 1 USING ERRCODE = 'QC422';
    END IF;
    RETURN NEW;
END
$$;

CREATE FUNCTION argus_case_event_outbox() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (SELECT count(*) FROM public.kibana_outbox o WHERE o.case_event_id = NEW.id)
       <> NEW.kibana_rows THEN
        RAISE EXCEPTION 'case event % planned % Kibana rows, not what was written', NEW.id,
            NEW.kibana_rows USING ERRCODE = 'QC422';
    END IF;
    RETURN NULL;
END
$$;
"""

# ---------------------------------------------------------------------------- outbox
# argus.cases.outbox.MOVES; entering 'sending' counts a send, and the table's check
# (sent_count <= 1 + resends) stops a second one unless a person approved a resend.
OUTBOX_GUARD = """
CREATE FUNCTION argus_outbox_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    ev record;
    req record;
    approved bigint;
    rejected bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT e.case_id, e.case_version, e.kind, e.to_state, e.kibana_rows INTO ev
            FROM public.case_events e WHERE e.id = NEW.case_event_id;
        IF NOT FOUND OR ev.case_id <> NEW.case_id OR NEW.position >= ev.kibana_rows THEN
            RAISE EXCEPTION 'outbox row does not belong to case event %', NEW.case_event_id
                USING ERRCODE = 'QC422';
        END IF;
        IF NEW.state <> 'planned' OR NEW.sent_count <> 0 OR NEW.resends <> 0
           OR NEW.sent_at IS NOT NULL OR NEW.verified_at IS NOT NULL THEN
            RAISE EXCEPTION 'a new outbox row is planned and unsent' USING ERRCODE = 'QC422';
        END IF;
        IF NEW.payload ? 'argus_tags' AND jsonb_typeof(NEW.payload -> 'argus_tags') <> 'array' THEN
            RAISE EXCEPTION 'outbox row: argus_tags is a list' USING ERRCODE = 'QC422';
        END IF;
        -- Closing a Kibana case (its status, ARGUS's closed tags or the closing comment) is a
        -- W3 write, which only a closure's complete approval allows.
        IF NEW.write_class <> 'W3' AND (
               NEW.payload ->> 'status' = 'closed'
               OR NEW.payload ->> 'template' = 'closed'
               OR EXISTS (SELECT 1 FROM jsonb_array_elements_text(
                              CASE WHEN jsonb_typeof(NEW.payload -> 'argus_tags') = 'array'
                                   THEN NEW.payload -> 'argus_tags' ELSE '[]'::jsonb END) t(tag)
                          WHERE t.tag IN ('argus:closed', 'argus:state:closed')
                             OR starts_with(t.tag, 'argus:reason:'))) THEN
            RAISE EXCEPTION 'outbox row: closing a Kibana case is a W3 write with its approval'
                USING ERRCODE = 'QC422';
        END IF;
        IF NEW.write_class = 'W3' THEN
            -- a closure's write is exactly one its complete approval named, at its position,
            -- planned with the closure that approval allowed (the case closed at the version
            -- after the request, naming the approval), once
            SELECT r.case_id, r.case_version, r.kind, r.payload, r.required_approvals,
                   r.expires_at INTO req
                FROM public.approval_requests r WHERE r.id = NEW.approval_request_id;
            IF NOT FOUND OR req.case_id <> NEW.case_id OR req.kind NOT IN ('closure', 'merge')
               OR (req.payload -> 'writes' -> NEW.position::integer) IS DISTINCT FROM
                  jsonb_build_object('class', NEW.write_class, 'op', NEW.op,
                                     'payload', NEW.payload) THEN
                RAISE EXCEPTION 'outbox row is not a write approval % named',
                    NEW.approval_request_id USING ERRCODE = 'QC422';
            END IF;
            IF ev.kind NOT IN ('closed', 'merged_into') OR ev.to_state <> 'closed'
               OR ev.case_version <> req.case_version + 1
               OR NOT EXISTS (SELECT 1 FROM public.cases k WHERE k.id = NEW.case_id
                              AND k.version = ev.case_version AND k.state = 'closed'
                              AND k.closure_request_id = NEW.approval_request_id) THEN
                RAISE EXCEPTION 'outbox row: approval % allowed another closure than case event %',
                    NEW.approval_request_id, NEW.case_event_id USING ERRCODE = 'QC422';
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
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id <> OLD.id OR NEW.case_id <> OLD.case_id OR NEW.case_event_id <> OLD.case_event_id
       OR NEW.position <> OLD.position OR NEW.idempotency_key <> OLD.idempotency_key
       OR NEW.write_class <> OLD.write_class OR NEW.op <> OLD.op
       OR NEW.payload <> OLD.payload OR NEW.payload_hash <> OLD.payload_hash
       OR NEW.before_image IS DISTINCT FROM OLD.before_image
       OR NEW.approval_request_id IS DISTINCT FROM OLD.approval_request_id
       OR NEW.created_at <> OLD.created_at THEN
        RAISE EXCEPTION 'outbox row %: a fixed field changed', OLD.id USING ERRCODE = 'QC422';
    END IF;
    IF NEW.state <> OLD.state AND NOT (OLD.state, NEW.state) IN (
        ('planned', 'approved'), ('planned', 'paused'), ('planned', 'skipped'),
        ('approved', 'planned'), ('approved', 'sending'), ('approved', 'paused'),
        ('approved', 'skipped'),
        ('sending', 'sent'), ('sending', 'ambiguous'), ('sending', 'conflict'),
        ('sending', 'paused'),
        ('sent', 'verified'), ('sent', 'conflict'), ('sent', 'paused'),
        ('ambiguous', 'sent'), ('ambiguous', 'verified'), ('ambiguous', 'planned'),
        ('ambiguous', 'paused'), ('ambiguous', 'skipped'),
        ('conflict', 'paused'), ('conflict', 'skipped'),
        ('paused', 'planned'), ('paused', 'approved'), ('paused', 'skipped')
    ) THEN
        RAISE EXCEPTION 'outbox row %: % to % is not an outbox move', OLD.id, OLD.state,
            NEW.state USING ERRCODE = 'QC422';
    END IF;
    IF (NEW.state = 'sending' AND OLD.state <> 'sending')
       <> (NEW.sent_count = OLD.sent_count + 1) OR NEW.sent_count < OLD.sent_count THEN
        RAISE EXCEPTION 'outbox row %: each send is counted once', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF (OLD.state = 'ambiguous' AND NEW.state = 'planned')
       <> (NEW.resends = OLD.resends + 1) OR NEW.resends < OLD.resends THEN
        RAISE EXCEPTION 'outbox row %: a resend is counted with its approval', OLD.id
            USING ERRCODE = 'QC422';
    END IF;
    IF OLD.state = 'ambiguous' AND NEW.state = 'planned' THEN
        -- a person's complete, unexpired approval of a resend, asked while this row was in
        -- doubt after its latest send (bound to that send count: each send needs its own)
        IF NOT EXISTS (
            SELECT 1 FROM public.approval_requests r
            WHERE r.kind = 'resend' AND r.outbox_id = OLD.id
              AND r.outbox_sent_count = OLD.sent_count AND clock_timestamp() <= r.expires_at
              AND NOT EXISTS (SELECT 1 FROM public.approval_decisions d
                              WHERE d.request_id = r.id AND d.decision = 'rejected')
              AND (SELECT count(*) FROM public.approval_decisions d
                   WHERE d.request_id = r.id AND d.decision = 'approved')
                  >= r.required_approvals) THEN
            RAISE EXCEPTION 'outbox row %: a resend needs a person''s approval given after send %',
                OLD.id, OLD.sent_count USING ERRCODE = 'QC422';
        END IF;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END
$$;
"""

# ---------------------------------------------------------------------------- approvals
# Only argus_approvals may call these (the web's own login joins it, Q-A2). The approver is the
# user of a live web session, never a parameter: the caller hands in the session's raw token
# (the cookie) and the function hashes it, so the hashes anyone may read in user_sessions are
# useless here; a session past its absolute end (expires_at, Q-A1's 0024) or idle longer than
# the web's default idle expiry (12 hours) is refused. Every request and decision is written to
# the audit trail (and so the hash chain) in the same transaction, naming the person; argus
# audit verify compares the two. Expiries are checked against the clock, never the
# transaction's start. The cases are locked before the request row and the chain, in id order,
# as CaseService locks them. Errors carry SQLSTATE QC4xx (argus.cases.approvals).
APPROVAL_FUNCTIONS = """
CREATE FUNCTION argus_approval_session_user(p_session_token text) RETURNS bigint
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint;
BEGIN
    SELECT s.user_id INTO uid FROM public.user_sessions s JOIN public.users u ON u.id = s.user_id
        WHERE s.token_hash = encode(sha256(convert_to(p_session_token, 'UTF8')), 'hex')
          AND s.ended_at IS NULL AND s.expires_at > clock_timestamp()
          AND s.last_seen_at >= clock_timestamp() - interval '12 hours'
          AND NOT u.disabled AND u.username <> 'argus-assistant';
    IF uid IS NULL THEN
        RAISE EXCEPTION 'no live session of a person' USING ERRCODE = 'QC401';
    END IF;
    RETURN uid;
END
$$;

CREATE FUNCTION argus_approval_request(
    p_session_token text, p_case uuid, p_case_version integer, p_kind text, p_reason text,
    p_target uuid, p_outbox bigint, p_payload jsonb, p_payload_hash text,
    p_kibana_version text, p_expires_at timestamptz, p_note text
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
    -- the alert set the approval covers: the case's members' alerts now, as a count and the
    -- sha256 of their ids (sorted by code point, one per line)
    SELECT count(*), encode(sha256(convert_to(coalesce(
               string_agg(a.alert_id, E'\\n' ORDER BY a.alert_id COLLATE "C"), ''), 'UTF8')), 'hex')
        INTO n_alerts, digest
        FROM (SELECT DISTINCT ia.alert_id::text AS alert_id FROM public.case_members m
              JOIN public.investigation_alerts ia ON ia.investigation_id = m.investigation_id
              WHERE m.case_id = p_case AND m.removed_at IS NULL) a;
    needed := CASE WHEN p_reason IN ('remediated_unverified', 'risk_accepted') THEN 2 ELSE 1 END;
    INSERT INTO public.approval_requests (case_id, case_version, kind, reason, target_case_id,
            outbox_id, outbox_sent_count, payload, payload_hash, alert_count, alert_digest,
            kibana_version, required_approvals, requested_by_user_id, expires_at, note)
        VALUES (p_case, p_case_version, p_kind, p_reason, p_target, p_outbox,
                CASE WHEN p_kind = 'resend' THEN sent END, p_payload, p_payload_hash, n_alerts,
                digest, p_kibana_version, needed, uid, p_expires_at, p_note)
        RETURNING id INTO new_id;
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

CREATE FUNCTION argus_approval_decide(
    p_session_token text, p_request bigint, p_decision text, p_capabilities jsonb, p_note text
) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    uid bigint := public.argus_approval_session_user(p_session_token);
    r record;
    approved bigint;
    rejected bigint;
    decision_id bigint;
    status text;
BEGIN
    IF p_decision NOT IN ('approved', 'rejected') THEN
        RAISE EXCEPTION 'a decision is approved or rejected' USING ERRCODE = 'QC422';
    END IF;
    IF jsonb_typeof(p_capabilities) IS DISTINCT FROM 'array'
       OR NOT p_capabilities ? 'approve' THEN
        RAISE EXCEPTION 'approving needs the approver capability' USING ERRCODE = 'QC403';
    END IF;
    PERFORM 1 FROM public.cases k WHERE k.id IN (
            SELECT q.case_id FROM public.approval_requests q WHERE q.id = p_request
            UNION SELECT q.target_case_id FROM public.approval_requests q WHERE q.id = p_request)
        ORDER BY k.id FOR UPDATE;
    SELECT q.id, q.case_id, q.case_version, q.kind, q.required_approvals, q.expires_at,
           q.requested_by_user_id INTO r
        FROM public.approval_requests q WHERE q.id = p_request FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'no such approval request' USING ERRCODE = 'QC404';
    END IF;
    IF r.requested_by_user_id = uid THEN
        RAISE EXCEPTION 'a person cannot approve their own request' USING ERRCODE = 'QC403';
    END IF;
    IF EXISTS (SELECT 1 FROM public.approval_decisions d
               WHERE d.request_id = r.id AND d.approver_user_id = uid) THEN
        RAISE EXCEPTION 'this person already decided' USING ERRCODE = 'QC409';
    END IF;
    SELECT count(*) FILTER (WHERE d.decision = 'approved'),
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
    INSERT INTO public.approval_decisions (request_id, approver_user_id, decision, capabilities,
            note)
        VALUES (r.id, uid, p_decision, p_capabilities, p_note)
        RETURNING id INTO decision_id;
    status := CASE WHEN p_decision = 'rejected' THEN 'rejected'
                   WHEN approved + 1 >= r.required_approvals THEN 'approved'
                   ELSE 'pending' END;
    INSERT INTO public.audit_events (actor, action, target_type, target_id, details)
        VALUES ('user:' || uid, 'case.approval.' || p_decision, 'case', r.case_id::text,
                jsonb_build_object('request', r.id, 'decision', decision_id, 'kind', r.kind,
                    'capabilities', p_capabilities, 'status', status,
                    'approvals', approved + CASE WHEN p_decision = 'approved' THEN 1 ELSE 0 END,
                    'required', r.required_approvals, 'via', 'approvals'));
    RETURN status;
END
$$;
"""

FUNCTIONS = (
    "argus_chain_field(text)",
    "argus_chain_time(timestamptz)",
    "argus_audit_message(bigint, text, bigint, timestamptz, text, text, text, text, text, text,"
    " text)",
    "argus_case_event_message(bigint, text, bigint, uuid, integer, text, text, bigint, text,"
    " text, text, integer, timestamptz)",
    "argus_chain_append()",
    "argus_chain_flush()",
    "argus_case_guard()",
    "argus_case_has_event()",
    "argus_case_event_follows()",
    "argus_case_event_outbox()",
    "argus_outbox_guard()",
    "argus_reject_truncate_unless_empty()",
    "argus_approval_session_user(text)",
    "argus_approval_request(text, uuid, integer, text, text, uuid, bigint, jsonb, text, text,"
    " timestamptz, text)",
    "argus_approval_decide(text, bigint, text, jsonb, text)",
)
APPROVALS_CALL = (
    "argus_approval_request(text, uuid, integer, text, text, uuid, bigint, jsonb, text, text,"
    " timestamptz, text)",
    "argus_approval_decide(text, bigint, text, jsonb, text)",
)


def _timestamps(*names: str) -> list[sa.Column]:  # type: ignore[type-arg]
    return [
        sa.Column(name, sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False)
        for name in names
    ]


def upgrade() -> None:
    op.execute(ROLE_CHECK.format(role="argus_runtime"))
    op.execute(ROLE_CHECK.format(role="argus_approvals"))
    # The legacy seal reads every audit row; production's trail is ~10^5 rows (seconds), the
    # engine's 30 s statement limit is for ARGUS's own queries.
    op.execute("SET LOCAL statement_timeout = '15min'")

    op.create_table(
        "chain_heads",
        sa.Column("chain", sa.Text(), nullable=False),
        sa.Column("seq", sa.BigInteger(), nullable=False),
        sa.Column("head_hash", sa.Text(), nullable=False),
        sa.Column("genesis_hash", sa.Text(), nullable=False),
        sa.Column("legacy_rows", sa.BigInteger(), nullable=False),
        sa.Column("legacy_max_id", sa.BigInteger(), nullable=False),
        *_timestamps("started_at"),
        sa.CheckConstraint(
            "chain IN ('audit_events', 'case_events')", name=op.f("ck_chain_heads_chain_valid")
        ),
        sa.CheckConstraint(
            "head_hash ~ '^[0-9a-f]{64}$' AND genesis_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_chain_heads_hashes_valid"),
        ),
        sa.CheckConstraint(
            "seq >= 0 AND legacy_rows >= 0 AND legacy_max_id >= 0",
            name=op.f("ck_chain_heads_non_negative"),
        ),
        sa.PrimaryKeyConstraint("chain", name=op.f("pk_chain_heads")),
    )
    op.create_table(
        "entity_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("author_user_id", sa.BigInteger(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        *_timestamps("created_at"),
        sa.CheckConstraint(
            "kind IN ('ip', 'domain', 'host', 'user')", name=op.f("ck_entity_notes_kind_valid")
        ),
        sa.CheckConstraint(
            "length(body) BETWEEN 1 AND 4000", name=op.f("ck_entity_notes_body_length")
        ),
        sa.CheckConstraint(
            "length(value) BETWEEN 1 AND 512", name=op.f("ck_entity_notes_value_length")
        ),
        sa.ForeignKeyConstraint(
            ["author_user_id"], ["users.id"], name=op.f("fk_entity_notes_author_user_id_users")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_entity_notes")),
    )
    op.create_index(op.f("ix_entity_notes_kind_value_id"), "entity_notes", ["kind", "value", "id"])
    op.create_table(
        "cases",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("number", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("owner_user_id", sa.BigInteger(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("cause", sa.Text(), nullable=False),
        sa.Column("cause_review_id", sa.BigInteger(), nullable=True),
        sa.Column("cause_assessment_id", sa.BigInteger(), nullable=True),
        sa.Column("parent_case_id", sa.UUID(), nullable=True),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closure_reason", sa.Text(), nullable=True),
        sa.Column("closure_request_id", sa.BigInteger(), nullable=True),
        sa.Column("merged_into_id", sa.UUID(), nullable=True),
        sa.Column("attention", sa.Text(), nullable=True),
        sa.Column("kibana_wait", sa.Text(), nullable=True),
        *_timestamps("created_at", "updated_at"),
        sa.CheckConstraint(
            "(cause = 'verdict') = (cause_review_id IS NOT NULL)"
            " AND (cause = 'proposal') = (cause_assessment_id IS NOT NULL)",
            name=op.f("ck_cases_cause_reference"),
        ),
        sa.CheckConstraint(
            "(state <> 'assigned' OR owner_user_id IS NOT NULL)"
            " AND (state NOT IN ('suspected', 'open') OR owner_user_id IS NULL)",
            name=op.f("ck_cases_owner_valid"),
        ),
        sa.CheckConstraint(
            "(state <> 'closed' OR opened_at IS NULL OR closure_request_id IS NOT NULL)"
            " AND (closure_request_id IS NULL OR state = 'closed')",
            name=op.f("ck_cases_confirmed_closes_by_approval"),
        ),
        sa.CheckConstraint(
            "(state <> 'suspected' OR opened_at IS NULL)"
            " AND (state NOT IN ('open', 'assigned', 'contained') OR opened_at IS NOT NULL)",
            name=op.f("ck_cases_confirmed_states"),
        ),
        sa.CheckConstraint(
            "(state = 'closed') = (closed_at IS NOT NULL)"
            " AND (state = 'closed') = (closure_reason IS NOT NULL)",
            name=op.f("ck_cases_closed_has_reason"),
        ),
        sa.CheckConstraint(
            "cause IN ('verdict', 'proposal', 'person')", name=op.f("ck_cases_cause_valid")
        ),
        sa.CheckConstraint(
            "closure_reason IS NULL OR closure_reason IN ('remediated_verified',"
            " 'remediated_unverified', 'risk_accepted', 'attempt_no_impact',"
            " 'rule_false_positive', 'benign_expected', 'benign_policy', 'duplicate',"
            " 'created_in_error')",
            name=op.f("ck_cases_closure_reason_valid"),
        ),
        sa.CheckConstraint(
            "merged_into_id IS NULL OR (state = 'closed' AND closure_reason = 'duplicate'"
            " AND merged_into_id <> id)",
            name=op.f("ck_cases_merge_valid"),
        ),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_cases_severity_valid"),
        ),
        sa.CheckConstraint(
            "state IN ('suspected', 'open', 'assigned', 'contained', 'closed')",
            name=op.f("ck_cases_state_valid"),
        ),
        sa.CheckConstraint(
            "(attention IS NULL OR length(attention) <= 500)"
            " AND (kibana_wait IS NULL OR length(kibana_wait) <= 500)",
            name=op.f("ck_cases_notes_length"),
        ),
        sa.CheckConstraint("length(title) BETWEEN 1 AND 200", name=op.f("ck_cases_title_length")),
        sa.CheckConstraint(
            "title !~ '[\\x01-\\x1f\\x7f-\\x9f]'", name=op.f("ck_cases_title_printable")
        ),
        sa.CheckConstraint("version >= 1", name=op.f("ck_cases_version_valid")),
        sa.ForeignKeyConstraint(
            ["cause_assessment_id"],
            ["assessments.id"],
            name=op.f("fk_cases_cause_assessment_id_assessments"),
        ),
        sa.ForeignKeyConstraint(
            ["cause_review_id"],
            ["review_events.id"],
            name=op.f("fk_cases_cause_review_id_review_events"),
        ),
        sa.ForeignKeyConstraint(
            ["merged_into_id"], ["cases.id"], name=op.f("fk_cases_merged_into_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["owner_user_id"], ["users.id"], name=op.f("fk_cases_owner_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["parent_case_id"], ["cases.id"], name=op.f("fk_cases_parent_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_cases")),
        sa.UniqueConstraint("number", name=op.f("uq_cases_number")),
    )
    op.create_index(op.f("ix_cases_parent_case_id"), "cases", ["parent_case_id"])
    op.create_index(op.f("ix_cases_state_updated_at"), "cases", ["state", "updated_at"])
    op.create_index(
        "uq_cases_cause_review_id",
        "cases",
        ["cause_review_id"],
        unique=True,
        postgresql_where=sa.text("cause_review_id IS NOT NULL"),
    )
    op.create_table(
        "case_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("actor", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.BigInteger(), nullable=True),
        sa.Column("from_state", sa.Text(), nullable=True),
        sa.Column("to_state", sa.Text(), nullable=False),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("kibana_rows", sa.Integer(), server_default="0", nullable=False),
        *_timestamps("occurred_at"),
        sa.Column("chain_seq", sa.BigInteger(), nullable=True),
        sa.Column("prev_hash", sa.Text(), nullable=True),
        sa.Column("row_hash", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "(from_state IS NULL OR from_state IN ('suspected', 'open', 'assigned', 'contained',"
            " 'closed')) AND to_state IN ('suspected', 'open', 'assigned', 'contained',"
            " 'closed')",
            name=op.f("ck_case_events_states_valid"),
        ),
        sa.CheckConstraint(
            "actor ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$'",
            name=op.f("ck_case_events_actor_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(details) = 'object'", name=op.f("ck_case_events_details_is_object")
        ),
        sa.CheckConstraint(
            "kind IN ('suspected', 'opened', 'confirmed', 'dismissed', 'taken', 'assigned',"
            " 'released', 'contained', 'new_activity', 'activity_after_closure', 'linked',"
            " 'published', 'closure_requested', 'merge_requested', 'closed', 'merged_into',"
            " 'merged_in', 'reopened')",
            name=op.f("ck_case_events_kind_valid"),
        ),
        sa.CheckConstraint(
            "(chain_seq IS NULL) = (row_hash IS NULL)"
            " AND (chain_seq IS NULL) = (prev_hash IS NULL)",
            name=op.f("ck_case_events_chain_complete"),
        ),
        sa.CheckConstraint(
            "case_version >= 1 AND kibana_rows BETWEEN 0 AND 10",
            name=op.f("ck_case_events_counts"),
        ),
        sa.CheckConstraint(
            "(kind IN ('suspected', 'opened')) = (from_state IS NULL)"
            " AND (kind IN ('closed', 'dismissed', 'merged_into'))"
            " = (to_state = 'closed' AND from_state IS DISTINCT FROM 'closed')"
            " AND (kind = 'reopened')"
            " = (from_state IS NOT DISTINCT FROM 'closed' AND to_state <> 'closed')",
            name=op.f("ck_case_events_kind_states"),
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"], ["users.id"], name=op.f("fk_case_events_actor_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_events_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_events")),
        sa.UniqueConstraint(
            "case_id", "case_version", name=op.f("uq_case_events_case_id_case_version")
        ),
    )
    op.create_index(
        op.f("ix_case_events_chain_seq"),
        "case_events",
        ["chain_seq"],
        unique=True,
        postgresql_where=sa.text("chain_seq IS NOT NULL"),
    )
    op.create_table(
        "case_indicators",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("role", sa.Text(), nullable=False),
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("added_version", sa.Integer(), nullable=False),
        sa.Column("added_by", sa.Text(), nullable=False),
        *_timestamps("added_at"),
        sa.Column("removed_version", sa.Integer(), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('ip', 'domain', 'host', 'user', 'url', 'hash')",
            name=op.f("ck_case_indicators_kind_valid"),
        ),
        sa.CheckConstraint(
            "role IN ('actor', 'c2', 'indicator')", name=op.f("ck_case_indicators_role_valid")
        ),
        sa.CheckConstraint(
            "source IN ('investigation', 'threat_intel', 'person', 'merge')",
            name=op.f("ck_case_indicators_source_valid"),
        ),
        sa.CheckConstraint(
            "(removed_at IS NULL) = (removed_version IS NULL)"
            " AND (removed_version IS NULL OR removed_version > added_version)",
            name=op.f("ck_case_indicators_removal_valid"),
        ),
        sa.CheckConstraint(
            "length(value) BETWEEN 1 AND 512", name=op.f("ck_case_indicators_value_length")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_indicators_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", "kind", "value", name=op.f("pk_case_indicators")),
    )
    op.create_index(op.f("ix_case_indicators_kind_value"), "case_indicators", ["kind", "value"])
    op.create_table(
        "case_members",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("link", sa.Text(), nullable=False),
        sa.Column("link_value", sa.Text(), nullable=True),
        sa.Column("added_version", sa.Integer(), nullable=False),
        sa.Column("added_by", sa.Text(), nullable=False),
        *_timestamps("added_at"),
        sa.Column("removed_version", sa.Integer(), nullable=True),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "link IN ('verdict', 'proposal', 'actor', 'indicator', 'c2', 'person', 'merge')",
            name=op.f("ck_case_members_link_valid"),
        ),
        sa.CheckConstraint(
            "(removed_at IS NULL) = (removed_version IS NULL)"
            " AND (removed_version IS NULL OR removed_version > added_version)",
            name=op.f("ck_case_members_removal_valid"),
        ),
        sa.CheckConstraint(
            "link_value IS NULL OR length(link_value) <= 512",
            name=op.f("ck_case_members_value_length"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_members_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_case_members_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("case_id", "investigation_id", name=op.f("pk_case_members")),
    )
    op.create_index(
        "uq_case_members_active_investigation",
        "case_members",
        ["investigation_id"],
        unique=True,
        postgresql_where=sa.text("removed_at IS NULL"),
    )
    op.create_table(
        "case_notes",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("author_user_id", sa.BigInteger(), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        *_timestamps("created_at"),
        sa.CheckConstraint(
            "length(body) BETWEEN 1 AND 4000", name=op.f("ck_case_notes_body_length")
        ),
        sa.ForeignKeyConstraint(
            ["author_user_id"], ["users.id"], name=op.f("fk_case_notes_author_user_id_users")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_notes_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_case_notes")),
    )
    op.create_index(op.f("ix_case_notes_case_id_id"), "case_notes", ["case_id", "id"])
    op.create_table(
        "case_openings",
        sa.Column("source", sa.Text(), nullable=False),
        sa.Column("source_id", sa.BigInteger(), nullable=False),
        sa.Column("investigation_id", sa.UUID(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=True),
        sa.Column("reasons", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("decided_by", sa.Text(), nullable=False),
        *_timestamps("decided_at"),
        sa.CheckConstraint(
            "(decision = 'attempt') = (case_id IS NULL)", name=op.f("ck_case_openings_case_given")
        ),
        sa.CheckConstraint(
            "decision IN ('opened', 'suspected', 'linked', 'member_already', 'attempt')",
            name=op.f("ck_case_openings_decision_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(reasons) = 'array'", name=op.f("ck_case_openings_reasons_is_array")
        ),
        sa.CheckConstraint(
            "source IN ('review', 'assessment')", name=op.f("ck_case_openings_source_valid")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_case_openings_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["investigation_id"],
            ["investigations.id"],
            name=op.f("fk_case_openings_investigation_id_investigations"),
        ),
        sa.PrimaryKeyConstraint("source", "source_id", name=op.f("pk_case_openings")),
    )
    op.create_index(op.f("ix_case_openings_case_id"), "case_openings", ["case_id"])
    op.create_index(op.f("ix_case_openings_decided_at"), "case_openings", ["decided_at"])
    op.create_table(
        "kibana_mirror",
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=False),
        sa.Column("kibana_version", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("severity", sa.Text(), nullable=False),
        sa.Column("tags", postgresql.ARRAY(sa.Text()), nullable=False),
        sa.Column("created_by", sa.Text(), nullable=False),
        sa.Column("sync_alerts", sa.Boolean(), nullable=False),
        sa.Column("unmanaged", postgresql.ARRAY(sa.Text()), server_default="{}", nullable=False),
        sa.Column("kibana_created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("kibana_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "severity IN ('low', 'medium', 'high', 'critical')",
            name=op.f("ck_kibana_mirror_severity_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in-progress', 'closed')",
            name=op.f("ck_kibana_mirror_status_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_kibana_mirror_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("case_id", name=op.f("pk_kibana_mirror")),
        sa.UniqueConstraint("kibana_case_id", name=op.f("uq_kibana_mirror_kibana_case_id")),
    )
    op.create_table(
        "kibana_outbox",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("case_event_id", sa.BigInteger(), nullable=False),
        sa.Column("position", sa.SmallInteger(), nullable=False),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("write_class", sa.Text(), nullable=False),
        sa.Column("op", sa.Text(), nullable=False),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("before_image", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("approval_request_id", sa.BigInteger(), nullable=True),
        sa.Column("state", sa.Text(), server_default="planned", nullable=False),
        sa.Column("state_reason", sa.Text(), nullable=True),
        sa.Column("sent_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("resends", sa.Integer(), server_default="0", nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=True),
        *_timestamps("created_at", "updated_at"),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "(op <> 'create' OR write_class = 'W1') AND (op <> 'close' OR write_class = 'W3')"
            " AND (write_class <> 'W3' OR approval_request_id IS NOT NULL)",
            name=op.f("ck_kibana_outbox_class_rules"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_kibana_outbox_payload_is_object")
        ),
        sa.CheckConstraint(
            "op IN ('create', 'update', 'comment', 'close')", name=op.f("ck_kibana_outbox_op_valid")
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_kibana_outbox_payload_hash_valid")
        ),
        sa.CheckConstraint(
            "state IN ('planned', 'approved', 'sending', 'sent', 'verified', 'ambiguous',"
            " 'conflict', 'paused', 'skipped')",
            name=op.f("ck_kibana_outbox_state_valid"),
        ),
        sa.CheckConstraint(
            "write_class IN ('W1', 'W2', 'W3')", name=op.f("ck_kibana_outbox_class_valid")
        ),
        sa.CheckConstraint(
            "length(idempotency_key) BETWEEN 1 AND 200", name=op.f("ck_kibana_outbox_key_length")
        ),
        sa.CheckConstraint(
            "position BETWEEN 0 AND 9", name=op.f("ck_kibana_outbox_position_valid")
        ),
        sa.CheckConstraint(
            "sent_count >= 0 AND resends >= 0 AND sent_count <= 1 + resends",
            name=op.f("ck_kibana_outbox_sent_at_most_once"),
        ),
        sa.ForeignKeyConstraint(
            ["case_event_id"],
            ["case_events.id"],
            name=op.f("fk_kibana_outbox_case_event_id_case_events"),
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_kibana_outbox_case_id_cases")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_kibana_outbox")),
        sa.UniqueConstraint(
            "case_event_id", "position", name=op.f("uq_kibana_outbox_case_event_id_position")
        ),
        sa.UniqueConstraint("idempotency_key", name=op.f("uq_kibana_outbox_idempotency_key")),
    )
    op.create_index(op.f("ix_kibana_outbox_case_id_id"), "kibana_outbox", ["case_id", "id"])
    op.create_index(op.f("ix_kibana_outbox_state_id"), "kibana_outbox", ["state", "id"])
    op.create_index(
        "uq_kibana_outbox_w3_approval_position",
        "kibana_outbox",
        ["approval_request_id", "position"],
        unique=True,
        postgresql_where=sa.text("write_class = 'W3'"),
    )
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("case_id", sa.UUID(), nullable=False),
        sa.Column("case_version", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("target_case_id", sa.UUID(), nullable=True),
        sa.Column("outbox_id", sa.BigInteger(), nullable=True),
        sa.Column("outbox_sent_count", sa.Integer(), nullable=True),
        sa.Column("payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=False),
        sa.Column("alert_count", sa.BigInteger(), nullable=False),
        sa.Column("alert_digest", sa.Text(), nullable=False),
        sa.Column("kibana_version", sa.Text(), nullable=True),
        sa.Column("required_approvals", sa.SmallInteger(), nullable=False),
        sa.Column("requested_by_user_id", sa.BigInteger(), nullable=False),
        *_timestamps("requested_at"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("note", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "(kind IN ('closure', 'merge')) = (reason IS NOT NULL)"
            " AND (kind <> 'closure' OR reason <> 'duplicate')"
            " AND (kind = 'merge') = (target_case_id IS NOT NULL)"
            " AND (kind <> 'merge' OR reason = 'duplicate')"
            " AND (kind IN ('compensating', 'resend')) = (outbox_id IS NOT NULL)"
            " AND (kind = 'resend') = (outbox_sent_count IS NOT NULL)",
            name=op.f("ck_approval_requests_kind_fields"),
        ),
        sa.CheckConstraint(
            "alert_count >= 0 AND alert_digest ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_approval_requests_alert_set_valid"),
        ),
        sa.CheckConstraint(
            "expires_at > requested_at AND expires_at <= requested_at + interval '72 hours'",
            name=op.f("ck_approval_requests_expiry_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(payload) = 'object'", name=op.f("ck_approval_requests_payload_is_object")
        ),
        sa.CheckConstraint(
            "kind IN ('closure', 'merge', 'compensating', 'resend')",
            name=op.f("ck_approval_requests_kind_valid"),
        ),
        sa.CheckConstraint(
            "payload_hash ~ '^[0-9a-f]{64}$'", name=op.f("ck_approval_requests_payload_hash_valid")
        ),
        sa.CheckConstraint(
            "reason IS NULL OR reason IN ('remediated_verified', 'remediated_unverified',"
            " 'risk_accepted', 'attempt_no_impact', 'rule_false_positive', 'benign_expected',"
            " 'benign_policy', 'duplicate', 'created_in_error')",
            name=op.f("ck_approval_requests_reason_valid"),
        ),
        sa.CheckConstraint("case_version >= 1", name=op.f("ck_approval_requests_version_valid")),
        sa.CheckConstraint(
            "target_case_id IS NULL OR target_case_id <> case_id",
            name=op.f("ck_approval_requests_target_not_self"),
        ),
        sa.CheckConstraint(
            "note IS NULL OR length(note) <= 4000", name=op.f("ck_approval_requests_note_length")
        ),
        sa.CheckConstraint(
            "required_approvals IN (1, 2)", name=op.f("ck_approval_requests_required_valid")
        ),
        sa.ForeignKeyConstraint(
            ["case_id"], ["cases.id"], name=op.f("fk_approval_requests_case_id_cases")
        ),
        sa.ForeignKeyConstraint(
            ["outbox_id"],
            ["kibana_outbox.id"],
            name=op.f("fk_approval_requests_outbox_id_kibana_outbox"),
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_approval_requests_requested_by_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["target_case_id"],
            ["cases.id"],
            name=op.f("fk_approval_requests_target_case_id_cases"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_requests")),
    )
    op.create_index(op.f("ix_approval_requests_case_id_id"), "approval_requests", ["case_id", "id"])
    op.create_foreign_key(
        op.f("fk_cases_closure_request_id_approval_requests"),
        "cases",
        "approval_requests",
        ["closure_request_id"],
        ["id"],
    )
    op.create_foreign_key(
        op.f("fk_kibana_outbox_approval_request_id_approval_requests"),
        "kibana_outbox",
        "approval_requests",
        ["approval_request_id"],
        ["id"],
    )
    op.create_table(
        "action_ledger",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        *_timestamps("at"),
        sa.Column("outbox_id", sa.BigInteger(), nullable=True),
        sa.Column("idempotency_key", sa.Text(), nullable=False),
        sa.Column("write_class", sa.Text(), nullable=False),
        sa.Column("method", sa.Text(), nullable=False),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("payload_hash", sa.Text(), nullable=True),
        sa.Column("approval_request_id", sa.BigInteger(), nullable=True),
        sa.Column("health", sa.Text(), nullable=False),
        sa.Column("switches", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("elapsed_ms", sa.Integer(), nullable=False),
        sa.Column("kibana_case_id", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "jsonb_typeof(switches) = 'object'", name=op.f("ck_action_ledger_switches_is_object")
        ),
        sa.CheckConstraint(
            "method IN ('POST', 'PATCH')", name=op.f("ck_action_ledger_method_valid")
        ),
        sa.CheckConstraint(
            "outcome IN ('sent', 'ambiguous', 'conflict', 'refused', 'failed')",
            name=op.f("ck_action_ledger_outcome_valid"),
        ),
        sa.CheckConstraint(
            "payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'",
            name=op.f("ck_action_ledger_payload_hash_valid"),
        ),
        sa.CheckConstraint(
            "write_class IN ('W1', 'W2', 'W3')", name=op.f("ck_action_ledger_class_valid")
        ),
        sa.CheckConstraint("elapsed_ms >= 0", name=op.f("ck_action_ledger_elapsed_valid")),
        sa.ForeignKeyConstraint(
            ["approval_request_id"],
            ["approval_requests.id"],
            name=op.f("fk_action_ledger_approval_request_id_approval_requests"),
        ),
        sa.ForeignKeyConstraint(
            ["outbox_id"],
            ["kibana_outbox.id"],
            name=op.f("fk_action_ledger_outbox_id_kibana_outbox"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_action_ledger")),
    )
    op.create_index(op.f("ix_action_ledger_at"), "action_ledger", ["at"])
    op.create_index(op.f("ix_action_ledger_outbox_id"), "action_ledger", ["outbox_id"])
    op.create_table(
        "approval_decisions",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("request_id", sa.BigInteger(), nullable=False),
        sa.Column("approver_user_id", sa.BigInteger(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("capabilities", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("stepped_up_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        *_timestamps("decided_at"),
        sa.CheckConstraint(
            "decision IN ('approved', 'rejected')",
            name=op.f("ck_approval_decisions_decision_valid"),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(capabilities) = 'array'",
            name=op.f("ck_approval_decisions_capabilities_is_array"),
        ),
        sa.CheckConstraint(
            "note IS NULL OR length(note) <= 4000", name=op.f("ck_approval_decisions_note_length")
        ),
        sa.ForeignKeyConstraint(
            ["approver_user_id"],
            ["users.id"],
            name=op.f("fk_approval_decisions_approver_user_id_users"),
        ),
        sa.ForeignKeyConstraint(
            ["request_id"],
            ["approval_requests.id"],
            name=op.f("fk_approval_decisions_request_id_approval_requests"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_approval_decisions")),
        sa.UniqueConstraint(
            "request_id",
            "approver_user_id",
            name=op.f("uq_approval_decisions_request_id_approver_user_id"),
        ),
    )

    # The audit trail joins the chain; its rows so far are sealed into the genesis hash.
    op.add_column("audit_events", sa.Column("chain_seq", sa.BigInteger(), nullable=True))
    op.add_column("audit_events", sa.Column("prev_hash", sa.Text(), nullable=True))
    op.add_column("audit_events", sa.Column("row_hash", sa.Text(), nullable=True))
    op.create_check_constraint(
        op.f("ck_audit_events_chain_complete"),
        "audit_events",
        "(chain_seq IS NULL) = (row_hash IS NULL) AND (chain_seq IS NULL) = (prev_hash IS NULL)",
    )
    op.create_index(
        op.f("ix_audit_events_chain_seq"),
        "audit_events",
        ["chain_seq"],
        unique=True,
        postgresql_where=sa.text("chain_seq IS NOT NULL"),
    )
    op.execute(CHAIN_FUNCTIONS)
    op.execute(LEGACY_SEAL)
    for table in ("audit_events", "case_events"):
        op.execute(
            f"CREATE TRIGGER {table}_chain BEFORE INSERT ON {table}"
            " FOR EACH ROW EXECUTE FUNCTION argus_chain_append()"
        )
        op.execute(
            f"CREATE CONSTRAINT TRIGGER {table}_chain_head AFTER INSERT ON {table}"
            " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION argus_chain_flush()"
        )
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_chain")
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_chain_head")

    op.execute(TRUNCATE_GUARD)
    for table in APPEND_ONLY:
        op.execute(
            f"CREATE TRIGGER {table}_append_only_rows BEFORE UPDATE OR DELETE ON {table}"
            " FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
        )
        op.execute(
            f"CREATE TRIGGER {table}_append_only_truncate BEFORE TRUNCATE ON {table}"
            " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
        )
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_append_only_rows")
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {table}_append_only_truncate")
    # Outbox rows change state but are never deleted.
    op.execute(
        "CREATE TRIGGER kibana_outbox_no_delete BEFORE DELETE ON kibana_outbox"
        " FOR EACH ROW EXECUTE FUNCTION argus_reject_mutation()"
    )
    op.execute(
        "CREATE TRIGGER kibana_outbox_no_truncate BEFORE TRUNCATE ON kibana_outbox"
        " FOR EACH STATEMENT EXECUTE FUNCTION argus_reject_truncate_unless_empty()"
    )
    op.execute("ALTER TABLE kibana_outbox ENABLE ALWAYS TRIGGER kibana_outbox_no_delete")
    op.execute("ALTER TABLE kibana_outbox ENABLE ALWAYS TRIGGER kibana_outbox_no_truncate")

    op.execute(CASE_GUARD)
    op.execute(OUTBOX_GUARD)
    op.execute(
        "CREATE TRIGGER cases_guard BEFORE INSERT OR UPDATE ON cases"
        " FOR EACH ROW EXECUTE FUNCTION argus_case_guard()"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER cases_have_events AFTER INSERT OR UPDATE ON cases"
        " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION argus_case_has_event()"
    )
    op.execute(
        "CREATE TRIGGER case_events_follow_case BEFORE INSERT ON case_events"
        " FOR EACH ROW EXECUTE FUNCTION argus_case_event_follows()"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER case_events_have_outbox AFTER INSERT ON case_events"
        " DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION argus_case_event_outbox()"
    )
    op.execute(
        "CREATE TRIGGER kibana_outbox_guard BEFORE INSERT OR UPDATE ON kibana_outbox"
        " FOR EACH ROW EXECUTE FUNCTION argus_outbox_guard()"
    )
    for table, trigger in (
        ("cases", "cases_guard"),
        ("cases", "cases_have_events"),
        ("case_events", "case_events_follow_case"),
        ("case_events", "case_events_have_outbox"),
        ("kibana_outbox", "kibana_outbox_guard"),
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ALWAYS TRIGGER {trigger}")

    op.execute(APPROVAL_FUNCTIONS)
    for function in FUNCTIONS:  # PostgreSQL lets PUBLIC execute every new function
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
    for function in APPROVALS_CALL:
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO argus_approvals")

    # The role name is written out, not imported (see 0003).
    op.execute("GRANT SELECT ON chain_heads TO argus_runtime")
    op.execute(
        "GRANT SELECT, INSERT (id, title, state, severity, owner_user_id, version, cause,"
        " cause_review_id, cause_assessment_id, parent_case_id, opened_at, attention,"
        " kibana_wait), UPDATE (title, state, severity, owner_user_id, version, opened_at,"
        " closed_at, closure_reason, closure_request_id, merged_into_id, attention, kibana_wait,"
        " updated_at) ON cases TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (case_id, investigation_id, link, link_value, added_version,"
        " added_by), UPDATE (removed_version, removed_at) ON case_members TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (case_id, kind, value, role, source, added_version, added_by)"
        " ON case_indicators TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (case_id, case_version, kind, actor, actor_user_id, from_state,"
        " to_state, details, kibana_rows) ON case_events TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (case_id, author_user_id, body) ON case_notes TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (kind, value, author_user_id, body) ON entity_notes TO argus_runtime"
    )
    op.execute(
        "GRANT SELECT, INSERT (source, source_id, investigation_id, decision, case_id, reasons,"
        " decided_by) ON case_openings TO argus_runtime"
    )
    op.execute("GRANT SELECT ON approval_requests TO argus_runtime")
    op.execute("GRANT SELECT ON approval_decisions TO argus_runtime")
    op.execute(
        "GRANT SELECT, INSERT (case_id, case_event_id, position, idempotency_key, write_class,"
        " op, payload, payload_hash, before_image, approval_request_id) ON kibana_outbox"
        " TO argus_runtime"
    )
    op.execute("GRANT SELECT ON kibana_mirror TO argus_runtime")
    op.execute("GRANT SELECT ON action_ledger TO argus_runtime")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS audit_events_chain_head ON audit_events")
    op.execute("DROP TRIGGER IF EXISTS audit_events_chain ON audit_events")
    op.drop_index(op.f("ix_audit_events_chain_seq"), table_name="audit_events")
    op.drop_constraint(op.f("ck_audit_events_chain_complete"), "audit_events", type_="check")
    op.drop_column("audit_events", "row_hash")
    op.drop_column("audit_events", "prev_hash")
    op.drop_column("audit_events", "chain_seq")
    op.drop_constraint(
        op.f("fk_kibana_outbox_approval_request_id_approval_requests"),
        "kibana_outbox",
        type_="foreignkey",
    )
    op.drop_constraint(
        op.f("fk_cases_closure_request_id_approval_requests"), "cases", type_="foreignkey"
    )
    # Dropping a table drops its triggers and the privileges on it.
    for table in (
        "approval_decisions",
        "action_ledger",
        "approval_requests",
        "kibana_outbox",
        "kibana_mirror",
        "case_openings",
        "case_notes",
        "case_members",
        "case_indicators",
        "case_events",
        "cases",
        "entity_notes",
        "chain_heads",
    ):
        op.drop_table(table)
    for function in reversed(FUNCTIONS):
        op.execute(f"DROP FUNCTION IF EXISTS {function}")
