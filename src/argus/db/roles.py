"""Database roles: who may do what in ARGUS's database.

The **owner** (``database.owner_user``) owns every table and is the only login ``argus db`` uses.
``argus_runtime`` is a group role (no login, member of nothing) that migrations grant what ARGUS
needs, table by table (:data:`RUNTIME_GRANTS`); the **runtime login** (``database.user``) is its
inheriting member and owns nothing. ``argus_web``, ``argus_writer``, ``argus_purge`` and
``argus_approvals`` are the web's, the case writer's, the retention purge's and the approval
functions' group roles, each with its own grant list. ``argus db bootstrap`` creates or repairs
these roles; ``argus doctor`` checks each login's grants (``*_role_problems``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from psycopg import sql
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.config.errors import ConfigError
from argus.config.settings import DatabaseSettings, usable_password
from argus.observability.redaction import redact_text

RUNTIME_ROLE = "argus_runtime"
API_ROLE = "argus_web"  # the web's group role; its login is database.api_user
APPROVALS_ROLE = "argus_approvals"
PURGE_ROLE = "argus_purge"  # the retention purge; the owner switches to it to purge
WRITER_ROLE = "argus_writer"  # the case writer; its login is database.writer_user
# Functions only argus_approvals may call. The runtime login must not be able to execute
# them, nor the owner's trigger and helper functions (PostgreSQL grants PUBLIC EXECUTE on every
# new function; the migration revokes it).
APPROVALS_FUNCTIONS = (
    "argus_approval_request(text, uuid, integer, text, text, uuid, bigint, jsonb, text, text,"
    " timestamptz, text, jsonb)",
    "argus_approval_decide(text, bigint, text, text, timestamptz, jsonb, text, jsonb)",
    "argus_identity_record(bigint, text, text, text, jsonb)",
)
# What the runtime login may execute: ARGUS's own closure proposals and
# re-confirmation requests, which still need a person's approval; the send-time check's moves
# of closure writes (it holds no UPDATE on the outbox).
RUNTIME_FUNCTIONS = (
    "argus_approval_propose(text, uuid, integer, text, text, bigint, jsonb, text, text,"
    " timestamptz, text)",
    "argus_closure_write_move(bigint, text, text)",
    "argus_closure_write_lock(bigint)",
)
# What the web's login may execute: argus_approvals' functions (it is a member).
WEB_FUNCTIONS = APPROVALS_FUNCTIONS
OWNER_ONLY_FUNCTIONS = (
    "argus_approval_session_user(text)",
    "argus_live_check_at(jsonb, bigint, text, text)",
    "argus_chain_append()",
    "argus_chain_flush()",
    "argus_chain_field(text)",
    "argus_chain_time(timestamptz)",
    "argus_audit_message(bigint, text, bigint, timestamptz, text, text, text, text, text, text,"
    " text)",
    "argus_case_event_message(bigint, text, bigint, uuid, integer, text, text, bigint, text,"
    " text, text, integer, timestamptz)",
    "argus_check_limits()",
    "argus_case_guard()",
    "argus_case_has_event()",
    "argus_case_event_follows()",
    "argus_case_event_outbox()",
    "argus_outbox_guard()",
    "argus_reject_truncate_unless_empty()",
    # the web's login records a case only as the person who acted
    "argus_web_case_writes()",
    # the edges of a case action, and what the web's login may write of one
    "argus_case_action_guard()",
)
_ALL_FUNCTIONS = (*APPROVALS_FUNCTIONS, *RUNTIME_FUNCTIONS, *OWNER_ONLY_FUNCTIONS)
# Transaction-level advisory lock that every bootstrap takes first, so bootstraps connected to
# the same database run one after the other. Advisory locks belong to one database: bootstraps
# connected to different databases can still overlap, and the retries below absorb that.
BOOTSTRAP_LOCK_KEY = int.from_bytes(b"ARGUSROL", "big")

# Names bootstrap creates: lowercase, so they read the same quoted or not.
_ROLE_NAME = re.compile(r"[a-z_][a-z0-9_]{0,62}")
# PostgreSQL reserves these (and every name starting with pg_), or reads them as another role.
_RESERVED_NAMES = frozenset({"public", "none", "current_user", "current_role", "session_user"})
_SAFE_ATTRIBUTES = "NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS INHERIT"
# The attributes bootstrap controls, in the order _state reads them (rolcanlogin, rolsuper,
# rolcreatedb, rolcreaterole, rolreplication, rolbypassrls, rolinherit), as the clauses that
# switch them on and off; then the state each role must have.
_FLAGS = (
    ("LOGIN", "NOLOGIN"),
    ("SUPERUSER", "NOSUPERUSER"),
    ("CREATEDB", "NOCREATEDB"),
    ("CREATEROLE", "NOCREATEROLE"),
    ("REPLICATION", "NOREPLICATION"),
    ("BYPASSRLS", "NOBYPASSRLS"),
    ("INHERIT", "NOINHERIT"),
)
_GROUP_STATE = (False, False, False, False, False, False, True)
_LOGIN_STATE = (True, False, False, False, False, False, True)
_DUPLICATE_ROLE = ("42710", "23505")  # duplicate_object; unique_violation when created meanwhile
# Role catalog rows are not locked: of two bootstraps changing one role at the same moment, the
# later fails once the earlier commits ("tuple concurrently updated", or a duplicate membership).
# Run again, its statement applies on top of the other's. Each overlapping run costs one attempt,
# and bootstraps connected to different databases are not serialised by the advisory lock (every
# test session bootstraps the runtime login), hence the margin.
_ATTEMPTS = 25
_INSUFFICIENT_PRIVILEGE = "42501"
# Session settings that would quietly weaken ARGUS, and the values they must have.
_SESSION_DEFAULTS = {"default_transaction_read_only": "off", "session_replication_role": "origin"}
# Where pg_settings says a value came from, for doctor's message.
_SETTING_SOURCES = {
    "configuration file": "set in the server's configuration",
    "database": "stored for its database",
    "database user": "stored on the login for its database",
    "global": "stored for every role",
    "user": "stored on the login",
}
# Problems runtime_role_problems reports that one `argus db bootstrap` repairs.
_BOOTSTRAP_REPAIRS = (
    "is a superuser",
    "can create roles",
    "can create databases",
    "can replicate",
    "bypasses row-level security",
    "is a member of ",
    "does not inherit ",
    "can grant ",
    "has settings stored on it",
)
# Never granted to the runtime role. UPDATE and REFERENCES can also be granted per column.
_NEVER_ON_TABLES = ("DELETE", "TRUNCATE", "TRIGGER")
_NEVER_ON_COLUMNS = ("UPDATE", "REFERENCES")
_SEQUENCE_PRIVILEGES = ("USAGE", "SELECT", "UPDATE")  # none is needed (identity columns)


class BootstrapError(Exception):
    """Bootstrap could not put the roles into their safe state; nothing it did was kept."""


def repaired_by_bootstrap(problem: str) -> bool:
    """Whether one ``argus db bootstrap`` repairs ``problem`` (from runtime_role_problems)."""
    return problem.startswith(_BOOTSTRAP_REPAIRS) or problem in (
        f"{RUNTIME_ROLE} is missing",
        f"{API_ROLE} is missing",
        f"{WRITER_ROLE} is missing",
    )


@dataclass(frozen=True)
class TableGrant:
    """What the runtime role may do to one table; anything not listed it must not do."""

    select: bool = False
    select_columns: tuple[str, ...] = ()
    """Columns it may read when it holds no table-wide SELECT (``select`` is then False)."""
    insert: tuple[str, ...] = ()
    """Columns it may insert; the database fills in the others."""
    update: tuple[str, ...] = ()
    """Columns it may update (the gateway's state tables); none for the audit trail."""
    delete: bool = False
    """Only LangGraph's checkpoint tables (a finished run's thread is deleted), the
    outside-intel cache (expired answers) and the sign-in sightings (replaced by a complete
    lookup, pruned after ``signins.keep_days``)."""


_EVIDENCE_RESULT = (
    "template",
    "template_version",
    "params",
    "status",
    "coverage",
    "source_watermark",
    "row_count",
    "truncated",
    "snapshot",
    "result_hash",
    "took_ms",
    "reused_from_version",
    "error",
    "collected_at",
)

_RULE_COLUMNS = (
    "uuid",
    "name",
    "type",
    "version",
    "revision",
    "interval",
    "lookback",
    "max_signals",
    "severity",
    "note",
    "note_hash",
    "definition_at",
    "alerts",
    "first_alert_at",
    "last_alert_at",
    "last_execution_at",
    "execution_status",
    "refreshed_at",
)
# what the incident engine writes of a rule (argus.risk.rulemeta): update only
_RULE_META = ("lineage", "tactics", "stage_mask", "indices", "family", "meta_at")
_RISK_OBJECT_UPDATE = (
    "criticality", "hub", "hub_reason", "last_seen", "lanes", "held", "last_lane_at", "item_at",
    "scored_at",
)  # fmt: skip
_RISK_INCIDENT_UPDATE = (
    "state", "first_seen", "last_seen", "updated_at", "version", "lanes", "material",
    "material_hash", "material_at", "changed", "stop_proposed_at", "campaign", "parent_id",
    "merged_into", "case_id", "devices", "groups", "priority", "band", "view", "recommended",
    # the presenter's columns (P4-F E5, migration 0095)
    "title", "certainty", "shown", "shown_day", "queued_at", "raised_by_ai", "presented",
    "presented_at",
)  # fmt: skip
_RISK_GRAY_COLUMNS = (
    "priority", "band", "lane", "certainty", "title", "view", "first_seen", "last_seen",
    "updated_at",
)  # fmt: skip
_RISK_GROUP_UPDATE = (
    "version", "signature", "direction", "day", "at", "alerts", "outcome", "known", "kinds",
    "category", "observed_at", "scored_at",
)  # fmt: skip
_RISK_OBSERVATION_INSERT = (
    "object_id", "investigation_id", "investigation_version", "source_kind", "source_key", "role",
    "at", "day", "base", "outcome", "prevalence", "fidelity", "score", "stages", "family",
    "strong", "threats", "evidence",
)  # fmt: skip
_RISK_SOURCE_COLUMNS = (
    "prevalence", "fidelity", "probation", "objects_median", "reach", "credited_confirmed",
    "credited_not_incident", "computed_at",
)  # fmt: skip
_RISK_SCORE_COLUMNS = (
    "score", "sources", "families", "stages", "active_days", "strong", "anchored", "breakdown",
    "computed_at",
)  # fmt: skip
_TI_COLUMNS = (
    "first_seen",
    "last_seen",
    "confidence",
    "description",
    "synced_at",
    "removed_at",
)

# Granted by migrations; every new table is added here and to its migration.
# what a person marks on the queue (migration 0100): the web writes a person's own rows, the
# runtime login the same (the presenter ends a hold on a material change)
QUEUE_MARKS: dict[str, TableGrant] = {
    "case_holds": TableGrant(
        select=True,
        insert=("case_id", "user_id", "reason", "until", "case_version"),
        update=("ended_at", "ended_why"),
    ),
    "case_seen": TableGrant(
        select=True,
        insert=("case_id", "user_id", "engine_version", "case_version", "seen_at"),
        update=("engine_version", "case_version", "seen_at"),
    ),
    "spot_checks": TableGrant(
        select=True,
        insert=("kind", "target_id", "user_id", "answer", "closed_as"),
        update=("answer", "closed_as", "answered_at"),
    ),
    "user_rounds": TableGrant(
        select=True, insert=("user_id", "caught_up_at"), update=("caught_up_at",)
    ),
    "report_sends": TableGrant(
        select=True, insert=("case_id", "report_version", "sent_to", "by_user_id")
    ),
}
RUNTIME_GRANTS: dict[str, TableGrant] = {
    "alembic_version": TableGrant(select=True),
    # id and occurred_at come from the database: ARGUS cannot renumber or backdate an event.
    "audit_events": TableGrant(
        select=True,
        insert=(
            "actor",
            "action",
            "outcome",
            "target_type",
            "target_id",
            "correlation_id",
            "details",
        ),
    ),
    # the Elastic Gateway's shared state, ledger and live-test sessions.
    "siem_switches": TableGrant(
        select=True, update=("stopped", "changed_at", "changed_by", "reason")
    ),
    "siem_state": TableGrant(select=True, update=("state", "updated_at")),
    "siem_requests": TableGrant(
        select=True,
        insert=(
            "at",
            "component",
            "purpose",
            "template",
            "version",
            "indices",
            "outcome",
            "http_status",
            "took_ms",
            "elapsed_ms",
            "response_bytes",
            "attempts",
            "live_session",
            "task_key",
            # lane, target and a write's outbox, hash, class, approval
            "lane",
            "target",
            "outbox_id",
            "payload_hash",
            "write_class",
            "approval_id",
            "health",
            "switches",
        ),
    ),
    "siem_live_sessions": TableGrant(
        select=True,
        insert=("id", "created_by", "ends_at", "max_requests"),
        update=("used", "ended_at"),
    ),
    # the health probe's readings, append-only.
    "siem_probes": TableGrant(
        select=True,
        insert=(
            "at",
            "state",
            "reasons",
            "probe_ok",
            "auth_failed",
            "disk_percent",
            "heap_percent",
            "load_1m",
            "search_queue",
            "search_rejected",
            "breakers_tripped",
            "write_rejected",
            "blocked_indices",
            "ingest_lag_s",
            "stale_rules",
        ),
    ),
    # the collector's alert store; nothing is ever deleted.
    "alert_records": TableGrant(
        select=True,
        insert=(
            "alert_id",
            "index",
            "status",
            "quarantine_reason",
            "quarantine_field",
            "normalizer_version",
            "rule_id",
            "detected_at",
            "event_time",
            "fingerprint",
            "workflow_status",
            "raw",
            "normalized",
            "content_hash",
            "state_hash",
            "recovered_by",
        ),
        update=(
            "index",
            "status",
            "quarantine_reason",
            "quarantine_field",
            "normalizer_version",
            "rule_id",
            "detected_at",
            "event_time",
            "fingerprint",
            "workflow_status",
            "raw",
            "normalized",
            "content_hash",
            "state_hash",
            "last_seen_at",
            "source_missing_at",
        ),
    ),
    "collector_cursors": TableGrant(
        select=True, insert=("name", "at"), update=("at", "updated_at")
    ),
    "reconciliation_runs": TableGrant(
        select=True,
        insert=(
            "started_at",
            "finished_at",
            "window_start",
            "window_end",
            "hours",
            "hours_mismatched",
            "recovered",
            "missing_in_es",
            "outcome",
        ),
    ),
    "coverage_gaps": TableGrant(
        select=True, insert=("kind", "subject", "start_at", "detail"), update=("end_at", "detail")
    ),
    # investigations, the entity index and the job queue.
    "investigations": TableGrant(
        select=True,
        insert=(
            "id",
            "grouping_version",
            "rule_id",
            "group_key",
            "bucket_start",
            "bucket_end",
            "previous_id",
        ),
        update=(
            "rule_name",
            "continues_id",
            "alert_count",
            "duplicate_count",
            "first_event_at",
            "last_event_at",
            "severity",
            "risk_score",
            "version",
            "updated_at",
        ),
    ),
    "investigation_alerts": TableGrant(
        select=True,
        insert=("alert_id", "investigation_id", "late_arrival"),
        update=("duplicate_of",),
    ),
    "investigation_entities": TableGrant(
        select=True,
        insert=("investigation_id", "kind", "value"),
    ),
    "entities": TableGrant(
        select=True,
        insert=("kind", "value", "investigations"),
        update=("investigations",),
    ),
    "jobs": TableGrant(
        select=True,
        insert=("investigation_id", "trigger", "run_after"),
        update=(
            "status",
            "run_after",
            "claims",
            "lease_owner",
            "lease_until",
            "claimed_version",
            "failures",
            "error",
            "finished_at",
            "deferred_since",
            "deferrals",
        ),
    ),
    # reviewers, sessions, append-only review events; local capabilities; the absolute
    # expiry and step-up of a session; the account's kind and ELK link, set at a terminal
    # (`argus user link`, `argus break-glass`)
    "users": TableGrant(
        select=True,
        insert=("username", "display_name", "password_hash", "capabilities", "kind", "realm"),
        update=(
            "display_name",
            "password_hash",
            "disabled",
            "capabilities",
            "elk_username",
            "realm",
        ),
    ),
    "user_sessions": TableGrant(
        select=True,
        insert=(
            "token_hash",
            "user_id",
            "csrf_token",
            "last_seen_at",
            "previous_seen_at",
            "expires_at",
        ),
        update=(
            "last_seen_at",
            "ended_at",
            "stepped_up_at",
            "stepup_failures",
            "credential",
            "ended_why",  # `argus sessions end-all`
        ),
    ),
    # a browser that signed in well keeps a device cookie: whichever login the
    # web runs as (local mode may still run as the runtime login) remembers it
    "user_devices": TableGrant(
        select=True, insert=("user_id", "token_hash"), update=("last_used_at",)
    ),
    # `argus break-glass on` opens the window and `off` ends it
    "break_glass": TableGrant(
        select=True,
        insert=("user_id", "reason", "enabled_by", "expires_at", "override"),
        update=("consumed_at", "ended_at"),
    ),
    "review_events": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "alert_count",
            "user_id",
            "action",
            "outcome",
            "note",
            "assessment_id",
            "kibana_ok",
        ),
    ),
    # each investigation's newest review; only review_events' trigger writes it.
    "review_state": TableGrant(select=True),
    # evidence (retried in place unless ok/empty), dossiers and signals (once per
    # investigation version), and LangGraph's checkpoint tables in their own schema.
    "evidence": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "task_key",
            *_EVIDENCE_RESULT,
            "asked_at",
        ),
        update=(*_EVIDENCE_RESULT, "asked_at"),
    ),
    # an evidence request's opaque id, never changed or removed at run time.
    "evidence_requests": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "eid",
            "task_key",
            "template",
            "template_version",
            "origin",
            "reason",
            "first_version",
            "created_at",
        ),
    ),
    "dossiers": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "facts_version",
            "job_id",
            "run_kind",
            "family",
            "pack",
            "status",
            "partial_reason",
            "dossier_hash",
            "body",
            "evidence_count",
            "created_at",
        ),
    ),
    "signals": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "name",
            "value",
            "status",
            "unknown_reason",
            "completeness",
            "evidence",
            "definition_version",
        ),
    ),
    "langgraph.checkpoint_migrations": TableGrant(select=True),
    "langgraph.checkpoints": TableGrant(
        select=True,
        insert=(
            "thread_id",
            "checkpoint_ns",
            "checkpoint_id",
            "parent_checkpoint_id",
            "checkpoint",
            "metadata",
        ),
        update=("checkpoint", "metadata"),
        delete=True,
    ),
    "langgraph.checkpoint_blobs": TableGrant(
        select=True,
        insert=("thread_id", "checkpoint_ns", "channel", "version", "type", "blob"),
        delete=True,
    ),
    "langgraph.checkpoint_writes": TableGrant(
        select=True,
        insert=(
            "thread_id",
            "checkpoint_ns",
            "checkpoint_id",
            "task_id",
            "idx",
            "channel",
            "type",
            "blob",
            "task_path",
        ),
        update=("channel", "type", "blob"),
        delete=True,
    ),
    # reference data.
    "rules": TableGrant(
        select=True, insert=("rule_id", *_RULE_COLUMNS), update=(*_RULE_COLUMNS, *_RULE_META)
    ),
    "rule_revisions": TableGrant(
        select=True, insert=("rule_id", "revision", "note_hash", "name", "first_seen_at")
    ),
    "ti_sources": TableGrant(
        select=True,
        insert=("source", "newest", "checked_at", "indicators", "error"),
        update=("newest", "checked_at", "indicators", "error"),
    ),
    "ti_indicators": TableGrant(
        select=True,
        insert=("source", "kind", "value", "type_raw", *_TI_COLUMNS),
        update=_TI_COLUMNS,
    ),
    "ti_lookups": TableGrant(
        select=True,
        insert=("source", "value", "indicators", "checked_at"),
        update=("indicators", "checked_at"),
    ),
    "knowledge_items": TableGrant(
        select=True,
        insert=(
            "key",
            "kind",
            "scope",
            "matcher",
            "assertion",
            "guards",
            "provenance",
            "status",
            "expires_at",
            "created_at",
        ),
        update=("status", "expires_at"),
    ),
    # the soak's hourly samples.
    "soak_samples": TableGrant(select=True, insert=("at", "metrics")),
    # the write-back outbox. The runtime also plans a
    # closure's row; the columns that record a send (written_count, previous, operator) and the
    # cache of the flags the sender derives (needs_operator, held) are the writer's alone.
    "writeback_outbox": TableGrant(
        select=True,
        insert=(
            "review_id",
            "investigation_id",
            "status",
            "alert_ids",
            "case_id",
            "closure_request_id",
        ),
        update=("state", "sent_at", "error", "sent_count"),
    ),
    # the gold set; frozen items and append-only answers.
    "gold_items": TableGrant(
        select=True,
        insert=(
            "set_name",
            "investigation_id",
            "version",
            "pack",
            "dossier_hash",
            "rule_name",
            "split",
            "why",
            "suggestion",
        ),
    ),
    "gold_labels": TableGrant(
        select=True, insert=("set_name", "investigation_id", "user_id", "outcome", "note")
    ),
    # assessments, queue and result in one row.
    "assessments": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "dossier_hash",
            "view_hash",
            "assessor",
            "run_after",
            "priority",
        ),
        update=(
            "status",
            "run_after",
            "claims",
            "lease_owner",
            "lease_until",
            "failures",
            "deferrals",
            "error",
            "outcome",
            "confidence",
            "decided_by",
            "reasons",
            "finished_at",
        ),
    ),
    # the weekly tuning reports.
    "tuning_reports": TableGrant(
        select=True,
        insert=("rule", "week_end", "report", "suggestions", "dropped", "model", "cost_usd"),
    ),
    # cases, the Kibana outbox, approvals (read only: argus_approvals' functions
    # insert them), notes, the opener's decisions and the hash chains' heads (read only).
    "chain_heads": TableGrant(select=True),
    "cases": TableGrant(
        select=True,
        insert=(
            "id",
            "title",
            "state",
            "severity",
            "owner_user_id",
            "version",
            "cause",
            "cause_review_id",
            "cause_assessment_id",
            "parent_case_id",
            "opened_at",
            "attention",
            "kibana_wait",
        ),
        update=(
            "title",
            "state",
            "severity",
            "owner_user_id",
            "version",
            "opened_at",
            "closed_at",
            "closure_reason",
            "closure_request_id",
            "merged_into_id",
            "attention",
            "kibana_wait",
            "updated_at",
            "notified_at",
            "blocked_at",
        ),
    ),
    # a removed member or indicator that is added again has its row revived
    "case_members": TableGrant(
        select=True,
        insert=("case_id", "investigation_id", "link", "link_value", "added_version", "added_by"),
        update=(
            "removed_version",
            "removed_at",
            "link",
            "link_value",
            "added_version",
            "added_by",
            "added_at",
        ),
    ),
    "case_indicators": TableGrant(
        select=True,
        insert=("case_id", "kind", "value", "role", "source", "added_version", "added_by"),
        update=(
            "role",
            "source",
            "added_version",
            "added_by",
            "added_at",
            "removed_version",
            "removed_at",
        ),
    ),
    "case_events": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_version",
            "kind",
            "actor",
            "actor_user_id",
            "from_state",
            "to_state",
            "details",
            "kibana_rows",
        ),
    ),
    "case_notes": TableGrant(select=True, insert=("case_id", "author_user_id", "body")),
    "entity_notes": TableGrant(select=True, insert=("kind", "value", "author_user_id", "body")),
    # a person's marks on the queue (P4-F UI v2, migration 0100): "I'm checking", what they last
    # looked at, spot-check answers, "I'm caught up", and a report sent to the CISO
    **QUEUE_MARKS,
    "case_openings": TableGrant(
        select=True,
        insert=(
            "source",
            "source_id",
            "investigation_id",
            "decision",
            "case_id",
            "reasons",
            "decided_by",
        ),
    ),
    # the still-active watch's answers (a decided one is never replaced: a trigger)
    # and the suggestions for matches that are not joined. The web's role gets neither.
    "case_watch_checks": TableGrant(
        select=True,
        insert=(
            "case_id",
            "day",
            "source",
            "subject",
            "part",
            "outcome",
            "reason",
            "window_start",
            "window_end",
            "asked_at",
            "asked_on",
            "requests",
            "attempts",
            "detail",
        ),
        update=(
            "outcome",
            "reason",
            "window_start",
            "window_end",
            "asked_at",
            "asked_on",
            "requests",
            "attempts",
            "detail",
            "checked_at",
        ),
    ),
    "case_suggestions": TableGrant(
        select=True,
        insert=("investigation_id", "case_id", "link", "link_value", "kind", "why"),
        update=("dismissed_at", "dismissed_by"),
    ),
    # what a person told or blocked (append-only), what ARGUS decided
    # about the investigations of a notified case's device, what that infection already includes
    # and ARGUS's two reminders. The terminal records a person's notice, so the runtime may.
    "case_notices": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_version",
            "kind",
            "at",
            "told",
            "how",
            "managed",
            "note",
            "by_user_id",
        ),
    ),
    "case_known_matches": TableGrant(
        select=True,
        insert=("investigation_id", "case_id", "version", "outcome", "why", "changed_version"),
        update=("case_id", "version", "outcome", "why", "changed_version", "decided_at"),
    ),
    "case_known_keys": TableGrant(select=True, insert=("case_id", "kind", "value", "source")),
    "case_reminders": TableGrant(
        select=True,
        insert=("case_id", "kind", "why"),
        update=("dismissed_at", "dismissed_by"),
    ),
    # the incident report. ARGUS writes the versions (append-only) and its look
    # at each case; a decision is a person's (the terminal does not make one, but may be given one)
    "incident_reports": TableGrant(
        select=True,
        insert=(
            "case_id",
            "version",
            "schema_version",
            "writer",
            "content_hash",
            "case_version",
            "verdict_outcome",
            "verdict_confidence",
            "body",
            "prose",
            "prose_by",
            "generated_by",
            "as_at",
            "core_hash",
        ),
    ),
    "incident_report_decisions": TableGrant(
        select=True,
        insert=("report_id", "decision", "outcome", "reason", "by_user_id", "review_ids"),
    ),
    "incident_report_checks": TableGrant(
        select=True,
        insert=("case_id", "signal", "checked_at", "report_id", "failure", "failed_at"),
        update=("signal", "checked_at", "report_id", "failure", "failed_at"),
    ),
    # the case team's posts. The writer's login posts and the web approves;
    # the runtime reads them, and records the verdict comments it read (the sync's pass).
    "case_team_posts": TableGrant(select=True),
    "case_team_steps": TableGrant(select=True),
    "case_team_approvals": TableGrant(select=True),
    "case_team_seen": TableGrant(
        select=True,
        insert=(
            "kibana_comment_id",
            "text_hash",
            "case_id",
            "author",
            "written_at",
            "verdict",
            "status",
            "detail",
            "counts",
            "user_id",
            "review_ids",
        ),
    ),
    # when the poster last looked at each case (read here; the writer keeps it), and what the
    # sync saw of a posted Kibana case when it last read its comments
    "case_team_looks": TableGrant(select=True),
    "case_team_reads": TableGrant(
        select=True,
        insert=("case_id", "kibana_updated_at", "comment_count", "read_at"),
        update=("kibana_updated_at", "comment_count", "read_at"),
    ),
    # the SSO sign-ins of the internal addresses (personal data). A complete
    # lookup replaces the day's sightings (delete, insert); the pass prunes what is old.
    "signin_sightings": TableGrant(
        select=True,
        delete=True,
        insert=(
            "address",
            "day",
            "user_name",
            "first_at",
            "last_at",
            "events",
            "successes",
            "failures",
            "hours",
            "user_agents",
        ),
    ),
    "signin_lookups": TableGrant(
        select=True,
        delete=True,
        insert=(
            "address",
            "day",
            "looked_at",
            "complete",
            "accounts",
            "more_accounts",
            "reason",
            "unnamed",
            "store_failures",
        ),
        update=(
            "looked_at",
            "complete",
            "accounts",
            "more_accounts",
            "reason",
            "unnamed",
            "store_failures",
        ),
    ),
    # the incident engine v2 in shadow (P4-F E1): its own tables, written and pruned by it
    "risk_objects": TableGrant(
        select=True,
        delete=True,
        insert=("kind", "key", "criticality", "hub", "hub_reason", "first_seen", "last_seen"),
        update=_RISK_OBJECT_UPDATE,
    ),
    "risk_groups": TableGrant(
        select=True,
        delete=True,
        insert=("investigation_id", *_RISK_GROUP_UPDATE),
        update=_RISK_GROUP_UPDATE,
    ),
    "risk_entities": TableGrant(
        select=True, delete=True, insert=("investigation_id", "kind", "value", "role", "fields")
    ),
    "risk_observations": TableGrant(
        select=True,
        delete=True,
        insert=_RISK_OBSERVATION_INSERT,
        update=("prevalence", "fidelity", "score"),
    ),
    "risk_sources": TableGrant(
        select=True,
        delete=True,
        insert=("source_key", "role", *_RISK_SOURCE_COLUMNS),
        update=_RISK_SOURCE_COLUMNS,
    ),
    "risk_object_scores": TableGrant(
        select=True,
        delete=True,
        insert=("object_id", "span", *_RISK_SCORE_COLUMNS),
        update=_RISK_SCORE_COLUMNS,
    ),
    "risk_crossings": TableGrant(
        select=True,
        delete=True,
        insert=("object_id", "lane", "at", "new_item", "score", "breakdown"),
    ),
    # what the engine's checking lane found (P4-F E3), kept 180 days and pruned by it
    "exposure_checks": TableGrant(
        select=True,
        delete=True,
        insert=(
            "kind",
            "source",
            "site",
            "day",
            "template",
            "template_version",
            "task_key",
            "verdict",
            "facts",
            "took_ms",
            "checked_at",
        ),
    ),
    # the engine v2's incidents, links and identity (P4-F E2 and E4), in shadow
    "risk_incidents": TableGrant(
        select=True,
        delete=True,
        insert=(
            "state",
            "created_at",
            "first_seen",
            "last_seen",
            "updated_at",
            "version",
            "lanes",
            "material",
            "material_hash",
            "material_at",
            "changed",
            "stop_proposed_at",
            "campaign",
            "parent_id",
            "follows_id",
            "merged_into",
            "case_id",
            "devices",
            "groups",
            "priority",
            "band",
            "view",
            "recommended",
        ),
        update=_RISK_INCIDENT_UPDATE,
    ),
    "risk_incident_objects": TableGrant(
        select=True,
        delete=True,
        insert=("incident_id", "object_id", "role", "joined_at"),
        update=("incident_id", "role"),
    ),
    "risk_incident_groups": TableGrant(
        select=True,
        delete=True,
        insert=("incident_id", "investigation_id", "joined_at"),
        update=("incident_id",),
    ),
    "risk_links": TableGrant(
        select=True,
        delete=True,
        insert=(
            "incident_id",
            "a_object",
            "b_object",
            "via",
            "value",
            "priority",
            "delta_seconds",
            "reason",
            "kept",
            "created_at",
        ),
        update=("incident_id", "kept", "removed_at", "removed_by", "removed_why"),
    ),
    "risk_threats": TableGrant(
        select=True,
        delete=True,
        insert=("threat", "flag_source", "flagged_at", "noticed_at", "hunted_at", "reach"),
        update=("flag_source", "flagged_at", "noticed_at", "hunted_at", "reach"),
    ),
    "risk_aliases": TableGrant(
        select=True,
        delete=True,
        insert=("device", "kind", "value", "valid_from", "valid_to", "source", "confidence"),
        update=("valid_to",),
    ),
    # the presenter (P4-F E5): the gray band and the switch's row
    "risk_gray_items": TableGrant(
        select=True,
        delete=True,
        insert=("object_id", *_RISK_GRAY_COLUMNS),
        update=_RISK_GRAY_COLUMNS,
    ),
    "risk_mode": TableGrant(select=True, insert=("id", "present", "at"), update=("present", "at")),
    # the investigations an investigator run stands for (insert only), and
    # what the evidence flagged on an investigation's newest dossier (replaced by a newer one)
    "assessment_shares": TableGrant(
        select=True, insert=("assessment_id", "investigation_id", "version", "pattern", "day")
    ),
    "investigation_raises": TableGrant(
        select=True,
        insert=("investigation_id", "version", "dossier_hash", "flags"),
        update=("version", "dossier_hash", "flags", "evaluated_at"),
    ),
    # outside threat-intel answers (a cache: expired ones are deleted) and the
    # ledger of the requests that fetched them
    "outside_lookups": TableGrant(
        select=True,
        insert=("source", "kind", "indicator", "status", "answer", "answer_bytes", "fetched_at"),
        update=("status", "answer", "answer_bytes", "fetched_at"),
        delete=True,
    ),
    "outside_requests": TableGrant(
        select=True,
        insert=("at", "source", "kind", "purpose", "outcome"),
        update=("outcome", "http_status", "answer_bytes", "stopped_until"),
    ),
    # what was advised, asked and done about a case. ARGUS records its advice and
    # its verdict; a person's request and report go in as ``user:<id>``. No DELETE; the guard
    # trigger holds the edges and the row's identity.
    "case_actions": TableGrant(
        select=True,
        insert=(
            "case_id",
            "action",
            "family",
            "owner",
            "catalogue_version",
            "state",
            "recommended_at",
            "recommended_by",
            "requested_at",
            "requested_by",
            "reported_at",
            "reported_by",
            "attestation",
            "verdict_at",
            "verdict",
            "last_beat",
        ),
        update=(
            "state",
            "requested_at",
            "requested_by",
            "reported_at",
            "reported_by",
            "attestation",
            "verdict_at",
            "verdict",
            "last_beat",
        ),
    ),
    # the Reporter's history. A report is written once and read; the runtime
    # login cannot change or delete one, or set its generated_at (the database's clock).
    "reports": TableGrant(
        select=True,
        insert=(
            "kind",
            "period_start",
            "period_end",
            "numbers",
            "text",
            "prose",
            "prose_agent",
        ),
    ),
    # what the notices remember (one live row per kind and subject); the runtime
    # login cannot delete a row. The web's role gets nothing.
    "notices": TableGrant(
        select=True,
        insert=("kind", "subject", "severity", "count", "first_seen", "last_seen"),
        update=(
            "severity",
            "count",
            "last_seen",
            "resolved_at",
            "sent_at",
            "sent_severity",
            "notified",
            "ended_at",
        ),
    ),
    "approval_requests": TableGrant(select=True),
    "approval_decisions": TableGrant(select=True),
    # identity checks (read: the send-time check). The send-time check moves
    # closure writes through argus_closure_write_move() only (RUNTIME_FUNCTIONS).
    "identity_checks": TableGrant(select=True),
    "kibana_outbox": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_event_id",
            "position",
            "idempotency_key",
            "write_class",
            "op",
            "payload",
            "payload_hash",
            "before_image",
            "approval_request_id",
        ),
    ),
    # the read-back writes the mirror (a pause is lifted only by the owner:
    # the trigger argus_mirror_resume_needs_owner), its state, cycles, findings and people's
    # cases; cycles and findings are append-only for the runtime
    "kibana_mirror": TableGrant(
        select=True,
        insert=(
            "case_id",
            "kibana_case_id",
            "kibana_version",
            "status",
            "title",
            "severity",
            "tags",
            "created_by",
            "sync_alerts",
            "unmanaged",
            "kibana_created_at",
            "kibana_updated_at",
            "read_at",
            "deleted_at",
            "actions_seen",
            "argus_actions",
            "paused_reason",
            "unexplained",
        ),
        update=(
            "kibana_case_id",  # once, after the case was deleted (a trigger)
            "kibana_version",
            "status",
            "title",
            "severity",
            "tags",
            "created_by",
            "sync_alerts",
            "unmanaged",
            "kibana_created_at",
            "kibana_updated_at",
            "read_at",
            "deleted_at",
            "actions_seen",
            "argus_actions",
            "paused_reason",
            "unexplained",
        ),
    ),
    "kibana_sync_state": TableGrant(
        select=True,
        update=(
            "changes_from",
            "last_cycle_at",
            "last_complete_at",
            "last_status_at",
            "last_discovery_at",
            "last_closed_listing_at",
            "discovery_cursor",
            "diff_cursor",
            "alerts_checked_to",
            "clock_offset_ms",
            "clock_checked_at",
            "updated_at",
        ),
    ),
    "kibana_sync_cycles": TableGrant(
        select=True,
        insert=(
            "started_at",
            "finished_at",
            "outcome",
            "reason",
            "health",
            "reads",
            "changed",
            "findings",
            "oldest_read_s",
            "stale",
            "clock_offset_ms",
            "detail",
        ),
    ),
    "kibana_findings": TableGrant(
        select=True,
        insert=(
            "found_at",
            "kind",
            "severity",
            "kibana_case_id",
            "case_id",
            "dedupe_key",
            "lag_s",
            "details",
        ),
    ),
    # the case writer's own records, which the runtime may read
    "kibana_steps": TableGrant(select=True),
    "kibana_lookups": TableGrant(select=True),
    "kibana_writer_runs": TableGrant(select=True),
    "kibana_writer_ramp": TableGrant(select=True),
    "kibana_alert_states": TableGrant(
        select=True,
        insert=("alert_id", "status", "workflow_user", "status_updated_at", "seen_at"),
        update=("status", "workflow_user", "status_updated_at", "seen_at"),
    ),
    "kibana_people_cases": TableGrant(
        select=True,
        insert=(
            "kibana_case_id",
            "title",
            "status",
            "created_by",
            "tags",
            "known_alerts",
            "kibana_updated_at",
            "first_seen_at",
            "read_at",
            "deleted_at",
        ),
        update=(
            "title",
            "status",
            "created_by",
            "tags",
            "known_alerts",
            "kibana_updated_at",
            "read_at",
            "deleted_at",
        ),
    ),
    "action_ledger": TableGrant(select=True),
    # the LLM gateway's shared state and call ledger.
    "llm_state": TableGrant(select=True, update=("state", "updated_at")),
    "llm_calls": TableGrant(
        select=True,
        insert=(
            "at",
            "call_id",
            "attempt",
            "provider",
            "model",
            "tier",
            "purpose",
            "priority",
            "outcome",
            "http_status",
            "input_tokens",
            "output_tokens",
            "cost_usd",
            "latency_ms",
            "request_bytes",
            "request_sha256",
        ),
    ),
    # the local model's shadow answers; never the web's (never shown)
    "llm_shadow": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "dossier_hash",
            "task",
            "prompt",
            "provider",
            "model",
            "usable",
            "ok",
            "outcome",
            "floor",
            "reference",
            "detail",
            "answer",
            "latency_ms",
            "lease_ms",
            "input_tokens",
            "output_tokens",
        ),
    ),
    # the freshness lane's readings (append-only), the watermarks (they only
    # advance: a trigger), the shadow's verdicts (replaced when derived again) and would-be
    # proposals (append-only). The web's role gets none of them: shadow output is never shown.
    "freshness_readings": TableGrant(
        select=True,
        insert=(
            "source",
            "sent_at",
            "at",
            "outcome",
            "reason",
            "ingested",
            "event_at",
            "health",
            "took_ms",
        ),
    ),
    "freshness_watermarks": TableGrant(
        select=True,
        insert=("source", "ingested", "event_at", "read_at"),
        update=("ingested", "event_at", "read_at"),
    ),
    # the deterministic wave and "Check more": a queue and its record in one row
    "investigation_checks": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "kind",
            "source",
            "template",
            "entity",
            "requested_by",
            "requested_at",
            "status",
        ),
        update=("status", "claims", "lease_until", "started_at", "finished_at", "outcome"),
    ),
    "freshness_shadow": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "signal",
            "mode",
            "verdict",
            "reason",
            "bridged_verdict",
            "complete_to",
            "refs",
            "margins",
            "decided_at",
        ),
        update=(
            "mode",
            "verdict",
            "reason",
            "bridged_verdict",
            "complete_to",
            "refs",
            "margins",
            "decided_at",
        ),
    ),
    "freshness_proposals": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "dossier_hash",
            "assessor",
            "bridged",
            "outcome",
            "actual",
            "signals",
            "reasons",
        ),
    ),
}

_AUDIT_INSERT = RUNTIME_GRANTS["audit_events"].insert

# The web's grants, granted to API_ROLE by migrations: what its pages and /api read,
# and the rows a person's action writes. It may touch no other table at all, which
# api_role_problems checks table by table; a migration that gives the web more lists it here.
API_GRANTS: dict[str, TableGrant] = {
    "alert_records": TableGrant(select=True),
    # "Ask the AI investigator" queues an assessment, at a person's priority.
    "assessments": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "pack",
            "dossier_hash",
            "view_hash",
            "assessor",
            "run_after",
            "priority",
        ),
    ),
    # every login, refusal and action; the login throttle counts the refusals
    "audit_events": TableGrant(select=True, insert=_AUDIT_INSERT),
    "collector_cursors": TableGrant(select=True),
    "coverage_gaps": TableGrant(select=True),
    "dossiers": TableGrant(select=True),
    # the status bar: whether the Kibana read-back runs
    "kibana_sync_cycles": TableGrant(select=True),
    # the identity lane runs in the web: its gate state (the `identity` row), the
    # switches it obeys and its ledger rows. Its security-index check goes through the
    # Elasticsearch gateway, which keeps the budget, lanes, breaker and health rows of the same
    # table: the column grant covers every row, the trigger `siem_state_web_rows`
    # refuses the web all but those five (never the Kibana lane's rows)
    "siem_state": TableGrant(select=True, update=("state", "updated_at")),
    "siem_switches": TableGrant(select=True),
    # the evidence the report shows, the ids and the ledger rows that answered
    "siem_requests": TableGrant(select=True, insert=RUNTIME_GRANTS["siem_requests"].insert),
    "entities": TableGrant(select=True),
    "evidence": TableGrant(select=True),
    "evidence_requests": TableGrant(select=True),
    # what the incident engine's checking lane found (an incident's "what ARGUS checked")
    "exposure_checks": TableGrant(select=True),
    # the Today page (P4-F E5): the engine's incidents, their alert groups, the gray band, the
    # digest and the switch, read only
    "risk_incidents": TableGrant(select=True),
    "risk_incident_groups": TableGrant(select=True),
    "risk_gray_items": TableGrant(select=True),
    "risk_mode": TableGrant(select=True),
    "risk_groups": TableGrant(select=True),
    "gold_items": TableGrant(select=True),
    "gold_labels": TableGrant(
        select=True, insert=("set_name", "investigation_id", "user_id", "outcome", "note")
    ),
    "investigation_alerts": TableGrant(select=True),
    # a person's "Check more" is queued by the web; ARGUS's service runs it. The web may not
    # set ``kind`` and ``source`` (they default to a check, a person's): the web can add
    # nothing else, and the table's trigger holds the limits.
    "investigation_checks": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "template",
            "entity",
            "requested_by",
            "requested_at",
        ),
    ),
    "investigation_entities": TableGrant(select=True),
    # A review locks the investigation's row (SELECT ... FOR UPDATE), which PostgreSQL allows
    # only with UPDATE on one of its columns: updated_at, which nothing decides on. The web
    # never updates it.
    "investigations": TableGrant(select=True, update=("updated_at",)),
    "jobs": TableGrant(select=True),
    "langgraph.checkpoints": TableGrant(select=True),
    "llm_calls": TableGrant(select=True),
    "llm_state": TableGrant(select=True),
    "reconciliation_runs": TableGrant(select=True),
    "review_events": TableGrant(
        select=True,
        insert=(
            "investigation_id",
            "version",
            "alert_count",
            "user_id",
            "action",
            "outcome",
            "note",
            "assessment_id",
            "kibana_ok",
        ),
    ),
    "rules": TableGrant(select=True),
    "tuning_reports": TableGrant(select=True),
    # each investigation's newest review: the lists read it, a trigger writes it
    "review_state": TableGrant(select=True),
    # sessions with their absolute end and step-up
    "user_sessions": TableGrant(
        select=True,
        insert=(
            "token_hash",
            "user_id",
            "csrf_token",
            "last_seen_at",
            "previous_seen_at",
            "expires_at",
            "mode",
            "capabilities",
            "checked_at",
            "map_version",
            "credential",
            "no_custody",
        ),
        update=(
            "last_seen_at",
            "ended_at",
            "stepped_up_at",
            "stepup_failures",
            # the ELK session's snapshot, credential and verification state
            "capabilities",
            "checked_at",
            "map_version",
            "credential",
            "unverified_since",
            "unverified_why",
            "ended_why",
        ),
    ),
    # accounts are made and disabled at a terminal (`argus user ...`); the web adds the account
    # of a person who signs in through ELK for the first time and freezes the old account of a
    # new person behind a known name
    "users": TableGrant(
        select=True,
        insert=(
            "username",
            "display_name",
            "kind",
            "realm",
            "elk_username",
            "argus_uid",
            "email",
            "capabilities",
            "elk_first_signin_at",
            "last_good_check_at",
        ),
        update=(
            "display_name",
            "email",
            "argus_uid",
            "elk_first_signin_at",
            "last_good_check_at",
            "disabled",
            "frozen_at",
        ),
    ),
    # device cookies of earlier good sign-ins; the emergency window's one-time use
    "user_devices": TableGrant(
        select=True, insert=("user_id", "token_hash"), update=("last_used_at",)
    ),
    "break_glass": TableGrant(select=True, update=("consumed_at",)),
    # what the web signs when a person approves (the request, the decisions so
    # far, the person's identity checks); it records them only through argus_approvals'
    # functions
    "approval_requests": TableGrant(select=True),
    "approval_decisions": TableGrant(select=True),
    "identity_checks": TableGrant(select=True),
    # the case pages read the record and the web runs the case commands a person
    # gives (CaseService writes a command's row, members, indicators, event and outbox rows in
    # one transaction); no case is opened, nothing deleted, no event, note or outbox row
    # changed, and the database's guards (edges, versions, approvals, chains) hold whoever asks
    "cases": TableGrant(
        select=True,
        update=(
            "title",
            "state",
            "severity",
            "owner_user_id",
            "version",
            "opened_at",
            "closed_at",
            "closure_reason",
            "closure_request_id",
            "merged_into_id",
            "attention",
            "kibana_wait",
            "updated_at",
            "notified_at",
            "blocked_at",
        ),
    ),
    # a removed member or indicator that is added again has its row revived
    "case_members": TableGrant(
        select=True,
        insert=("case_id", "investigation_id", "link", "link_value", "added_version", "added_by"),
        update=(
            "removed_version",
            "removed_at",
            "link",
            "link_value",
            "added_version",
            "added_by",
            "added_at",
        ),
    ),
    "case_indicators": TableGrant(
        select=True,
        insert=("case_id", "kind", "value", "role", "source", "added_version", "added_by"),
        update=(
            "role",
            "source",
            "added_version",
            "added_by",
            "added_at",
            "removed_version",
            "removed_at",
        ),
    ),
    "case_events": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_version",
            "kind",
            "actor",
            "actor_user_id",
            "from_state",
            "to_state",
            "details",
            "kibana_rows",
        ),
    ),
    "case_notes": TableGrant(select=True, insert=("case_id", "author_user_id", "body")),
    "entity_notes": TableGrant(select=True, insert=("kind", "value", "author_user_id", "body")),
    # a person's marks on the queue (P4-F UI v2, migration 0100): "I'm checking", what they last
    # looked at, spot-check answers, "I'm caught up", and a report sent to the CISO
    **QUEUE_MARKS,
    "kibana_outbox": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_event_id",
            "position",
            "idempotency_key",
            "write_class",
            "op",
            "payload",
            "payload_hash",
            "before_image",
            "approval_request_id",
        ),
    ),
    "kibana_mirror": TableGrant(select=True),
    "kibana_findings": TableGrant(select=True),
    # the suggested members and the watch's answers are read on the
    # page; a person dismisses a suggestion (audited as theirs)
    "case_suggestions": TableGrant(select=True, update=("dismissed_at", "dismissed_by")),
    # a person records a notice or a block (the case row's two columns and the
    # notice, in CaseService's transaction), the pages read what ARGUS decided, and a person
    # dismisses a reminder
    "case_notices": TableGrant(
        select=True,
        insert=(
            "case_id",
            "case_version",
            "kind",
            "at",
            "told",
            "how",
            "managed",
            "note",
            "by_user_id",
        ),
    ),
    "case_known_matches": TableGrant(select=True),
    "case_known_keys": TableGrant(select=True),
    "case_reminders": TableGrant(select=True, update=("dismissed_at", "dismissed_by")),
    # the pages read the report and its checks; a person's confirm or reject is theirs
    # (the labels it writes go through the web's existing grants on review_events)
    "incident_reports": TableGrant(select=True),
    "incident_report_checks": TableGrant(select=True),
    # the case team's posts are read; a person approves a first sequence (canary)
    "case_team_posts": TableGrant(select=True),
    "case_team_steps": TableGrant(select=True),
    "case_team_seen": TableGrant(select=True),
    "case_team_approvals": TableGrant(
        select=True,
        insert=(
            "case_id",
            "gen",
            "plan_hash",
            "report_version",
            "approver_user_id",
            "statement",
            "signature",
            "approved_at",
            "expires_at",
        ),
    ),
    "incident_report_decisions": TableGrant(
        select=True,
        insert=("report_id", "decision", "outcome", "reason", "by_user_id", "review_ids"),
    ),
    # the pages show the probable users of a device, to people with log access only
    # (the route checks ``see_logs``); the web writes none
    "signin_sightings": TableGrant(select=True),
    "signin_lookups": TableGrant(select=True),
    # the pages show a shared run ("same pattern as ...") and what was raised
    "assessment_shares": TableGrant(select=True),
    "investigation_raises": TableGrant(select=True),
    # the investigation page says what outside intel found; the ledger stays private
    "outside_lookups": TableGrant(select=True),
    "case_watch_checks": TableGrant(select=True),
    # The case finder, which the case pages and the approval desk ask, reads what the opener decided
    "case_openings": TableGrant(select=True),
    # the Reports page reads what the Reporter made; the web writes none
    "reports": TableGrant(select=True),
    # the web reads the advice and writes only a person's request or report
    # (``user:<id>``); the verdict columns and ARGUS's recommendation are ARGUS's
    "case_actions": TableGrant(
        select=True,
        insert=(
            "case_id",
            "action",
            "family",
            "owner",
            "catalogue_version",
            "state",
            "requested_at",
            "requested_by",
            "reported_at",
            "reported_by",
            "attestation",
        ),
        update=(
            "state",
            "requested_at",
            "requested_by",
            "reported_at",
            "reported_by",
            "attestation",
        ),
    ),
}
# The schemas whose tables api_role_problems checks one by one (ARGUS's, LangGraph's).
_API_SCHEMAS = ("public", "langgraph")

# The retention purge's grants, granted to PURGE_ROLE by a migration: it empties
# the raw alert and evidence snapshot columns, deletes investigations past memory.window with
# what hangs off them, reads the holds, and records its runs. Nothing else: purge_role_problems
# checks every table of ARGUS's schemas, so the audit trail and the case records stay out of
# its reach whatever the purge's code does.
PURGE_GRANTS: dict[str, TableGrant] = {
    "alert_records": TableGrant(select=True, update=("raw", "raw_purged_at"), delete=True),
    "assessments": TableGrant(select=True, delete=True),
    "audit_events": TableGrant(select=True, insert=_AUDIT_INSERT),
    "dossiers": TableGrant(select=True, delete=True),
    "entities": TableGrant(select=True, update=("investigations",), delete=True),
    "evidence": TableGrant(select=True, update=("snapshot", "snapshot_purged_at"), delete=True),
    "evidence_requests": TableGrant(select=True, delete=True),
    "investigation_alerts": TableGrant(select=True, delete=True),
    "investigation_entities": TableGrant(select=True, delete=True),
    "investigations": TableGrant(select=True, update=("continues_id",), delete=True),
    "jobs": TableGrant(select=True, delete=True),
    "review_events": TableGrant(select=True, delete=True),
    "review_state": TableGrant(select=True, delete=True),
    "signals": TableGrant(select=True, delete=True),
    "ti_lookups": TableGrant(select=True, delete=True),
    "tuning_reports": TableGrant(select=True, delete=True),
    "writeback_outbox": TableGrant(select=True, delete=True),
    "llm_shadow": TableGrant(select=True, delete=True),
    # the holds (open cases, pending approvals, the gold set), read only
    "approval_requests": TableGrant(select=True),
    "case_members": TableGrant(select=True),
    "case_openings": TableGrant(select=True),
    "cases": TableGrant(select=True),
    "gold_items": TableGrant(select=True),
}


# The case writer's grants, granted to WRITER_ROLE by migrations (including the alert
# status write-back).
# Its login belongs to this role alone, never to ARGUS_RUNTIME: writer_role_problems checks every
# table of ARGUS's schemas, so what is not listed here it cannot touch at all.
_OUTBOX_UPDATE = (
    "state",
    "state_reason",
    "sent_count",
    "resends",
    "kibana_case_id",
    "sent_at",
    "verified_at",
)
# Read only: the cases and what the approvals' send-time checks and the plans read, the Kibana
# lane's health and switches, the people who approved, the alerts a case attaches.
WRITER_READS = (
    "alert_records",
    "approval_decisions",
    "approval_requests",
    "case_events",
    "case_members",
    "cases",
    "siem_live_sessions",
    "siem_probes",
    "siem_switches",
    "identity_checks",
    "incident_report_decisions",  # the case team renders the stored report
    "incident_reports",
    "investigation_alerts",
    "kibana_mirror",
    "users",
)
WRITER_GRANTS: dict[str, TableGrant] = {
    **{table: TableGrant(select=True) for table in WRITER_READS},
    # the audit trail and the findings: it may add, never change
    "audit_events": RUNTIME_GRANTS["audit_events"],
    "kibana_findings": RUNTIME_GRANTS["kibana_findings"],
    # the Kibana lane's shared state and request ledger
    "siem_state": RUNTIME_GRANTS["siem_state"],
    "siem_requests": RUNTIME_GRANTS["siem_requests"],
    # the outbox: it moves rows (the runtime inserts them and cannot move them)
    "kibana_outbox": TableGrant(select=True, update=_OUTBOX_UPDATE),
    # the alert status write-back: it reads, before each request, what says whether
    # a row may still go out (never a review's notes) and moves the rows the runtime planned
    "review_events": TableGrant(
        select_columns=(
            "id",
            "investigation_id",
            "action",
            "outcome",
            "kibana_ok",
            "user_id",
            "created_at",
        )
    ),
    "freshness_shadow": TableGrant(select_columns=("investigation_id", "mode", "verdict")),
    "writeback_outbox": TableGrant(
        select=True,
        update=(
            "state",
            "sent_at",
            "error",
            "sent_count",
            "written_count",
            "previous",
            "operator",
            "needs_operator",
            "held",
        ),
    ),
    "kibana_steps": TableGrant(
        select=True,
        insert=(
            "case_id",
            "outbox_id",
            "approval_request_id",
            "kind",
            "seq",
            "key",
            "write_class",
            "payload",
            "payload_hash",
        ),
        update=("state", "state_reason", "sent_count", "kibana_case_id", "sent_at", "verified_at"),
    ),
    "kibana_lookups": TableGrant(
        select=True,
        insert=("subject", "subject_id", "sent_count", "attempt", "due_at"),
        update=("due_at", "done_at", "outcome", "details"),
    ),
    "kibana_writer_runs": TableGrant(
        select=True,
        insert=(
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
        ),
    ),
    "kibana_writer_ramp": TableGrant(
        select=True,
        insert=("write_class", "step", "since", "changed_by", "note"),
        update=("step", "since", "changed_by", "note"),
    ),
    # the case team's posts and steps are the writer's; it reads the approval
    # of a first sequence and the verdict comments the runtime recorded
    "case_team_posts": TableGrant(
        select=True,
        insert=("case_id", "incident_id"),
        update=(
            "kibana_case_id",
            "state",
            "held_reason",
            "opened_at",
            "last_version",
            "last_round_at",
        ),
    ),
    "case_team_steps": TableGrant(
        select=True,
        insert=(
            "case_id",
            "gen",
            "seq",
            "key",
            "kind",
            "author",
            "part",
            "report_version",
            "payload",
            "text_body",
            "units",
            "request_hash",
        ),
        update=(
            "state",
            "state_reason",
            "sent_count",
            "kibana_ids",
            "lookups",
            "next_lookup_at",
            "sent_at",
            "verified_at",
        ),
    ),
    "case_team_approvals": TableGrant(select=True),
    "case_team_seen": TableGrant(select=True),
    # when the poster last looked at each case (its rotation)
    "case_team_looks": TableGrant(
        select=True, insert=("case_id", "examined_at"), update=("examined_at",)
    ),
}
# What the writer's login may execute: the send-time check's moves of closure writes and
# its request for a person's re-confirmation (ARGUS's own proposals still need a person's approval).
WRITER_FUNCTIONS = RUNTIME_FUNCTIONS


def check_bootstrap_settings(settings: DatabaseSettings) -> None:
    """ConfigError unless bootstrap can create the runtime login from ``settings``."""
    user = settings.user
    if not _ROLE_NAME.fullmatch(user):
        raise ConfigError(
            "database.user must be lowercase letters, digits and _ (not starting with a digit)"
            " for `argus db bootstrap` to create it"
        )
    if user == settings.owner_user:
        raise ConfigError(
            "database.user and database.owner_user must be different roles: ARGUS must not run"
            " as the role that owns its tables (D-029)"
        )
    if settings.owner_user in (RUNTIME_ROLE, API_ROLE):
        raise ConfigError(
            f"database.owner_user may not be {settings.owner_user}: bootstrap keeps that group"
            " role unable to log in, which would lock the owner out"
        )
    if user in (RUNTIME_ROLE, API_ROLE) or user.startswith("pg_") or user in _RESERVED_NAMES:
        raise ConfigError(
            f"database.user may not be {user}: the name belongs to one of ARGUS's group roles"
            " or is reserved by PostgreSQL"
        )
    if settings.password is None or not settings.password.get_secret_value():
        raise ConfigError(
            "database password is not set; put ARGUS_DATABASE__PASSWORD in .env (bootstrap sets"
            " it on the runtime role)"
        )
    try:
        usable_password(settings.password.get_secret_value())
    except ValueError as exc:
        raise ConfigError(f"database.password {exc}") from None


async def ensure_roles(
    conn: AsyncConnection, settings: DatabaseSettings, *, changes: list[str] | None = None
) -> list[str]:
    """Create the runtime group role and login, or put them back into their safe state, and set
    the login's password. Runs in ``conn``'s transaction, as the owner, and copes with another
    bootstrap running at the same moment. Returns the roles it created; what it had to repair
    on roles that existed is appended to ``changes`` (names only, never a value)."""
    check_bootstrap_settings(settings)
    assert settings.password is not None
    repairs = [] if changes is None else changes
    group, user = RUNTIME_ROLE, settings.user  # read now: tests point RUNTIME_ROLE elsewhere
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
    return await _ensure_group_and_login(
        conn, group, user, settings.password.get_secret_value(), settings.name, repairs
    )


def api_login_configured(settings: DatabaseSettings) -> bool:
    """Whether the web's own login is set up: its password is configured."""
    return settings.api_password is not None and bool(settings.api_password.get_secret_value())


def check_api_settings(settings: DatabaseSettings) -> None:
    """ConfigError unless bootstrap can create the web's login (``database.api_user``) from
    ``settings``: a plain name of its own and a password libpq can use."""
    user = settings.api_user
    if not _ROLE_NAME.fullmatch(user):
        raise ConfigError(
            "database.api_user must be lowercase letters, digits and _ (not starting with a"
            " digit) for `argus db bootstrap` to create it"
        )
    if user in (settings.user, settings.owner_user):
        raise ConfigError(
            "database.api_user must be a role of its own, neither database.user nor"
            " database.owner_user: the web logs in with only the grants it needs (Q-A2)"
        )
    if user in (RUNTIME_ROLE, API_ROLE) or user.startswith("pg_") or user in _RESERVED_NAMES:
        raise ConfigError(
            f"database.api_user may not be {user}: the name belongs to one of ARGUS's group"
            " roles or is reserved by PostgreSQL"
        )
    if not api_login_configured(settings):
        raise ConfigError(
            "the web's database password is not set; put ARGUS_DATABASE__API_PASSWORD in .env"
            " (bootstrap sets it on the web's login)"
        )
    assert settings.api_password is not None
    try:
        usable_password(settings.api_password.get_secret_value())
    except ValueError as exc:
        raise ConfigError(f"database.api_password {exc}") from None


async def ensure_api_roles(
    conn: AsyncConnection, settings: DatabaseSettings, *, changes: list[str] | None = None
) -> list[str]:
    """The web's roles, as :func:`ensure_roles` makes the runtime ones: the group role
    ``argus_web`` always (migrations grant it what the web needs), and the web's login
    (``database.api_user``, an inheriting member of that group and of nothing else) once its
    password is configured. In ``conn``'s transaction, as the owner. Returns the roles it
    created; repairs are appended to ``changes``."""
    configured = api_login_configured(settings)
    if configured:
        check_api_settings(settings)  # before anything is sent
    repairs = [] if changes is None else changes
    group = API_ROLE  # read now: tests point it elsewhere
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
    if not configured:
        created = await _ensure_group(conn, group, repairs)
        repairs += await _revoke_memberships(conn, group, keep=None, report_missing=False)
        return created
    assert settings.api_password is not None
    return await _ensure_group_and_login(
        conn,
        group,
        settings.api_user,
        settings.api_password.get_secret_value(),
        settings.name,
        repairs,
        also_keep=(APPROVALS_ROLE,),
    )


def writer_login_configured(settings: DatabaseSettings) -> bool:
    """Whether the case writer's own login is set up: its password is configured."""
    return settings.writer_password is not None and bool(
        settings.writer_password.get_secret_value()
    )


def check_writer_settings(settings: DatabaseSettings) -> None:
    """ConfigError unless bootstrap can create the writer's login (``database.writer_user``)
    from ``settings``: a plain name of its own and a password libpq can use."""
    user = settings.writer_user
    if not _ROLE_NAME.fullmatch(user):
        raise ConfigError(
            "database.writer_user must be lowercase letters, digits and _ (not starting with a"
            " digit) for `argus db bootstrap` to create it"
        )
    if user in (settings.user, settings.owner_user, settings.api_user):
        raise ConfigError(
            "database.writer_user must be a role of its own, none of database.user,"
            " database.owner_user and database.api_user (Q-D4)"
        )
    if (
        user in (RUNTIME_ROLE, API_ROLE, WRITER_ROLE, APPROVALS_ROLE, PURGE_ROLE)
        or user.startswith("pg_")
        or user in _RESERVED_NAMES
    ):
        raise ConfigError(
            f"database.writer_user may not be {user}: the name belongs to one of ARGUS's group"
            " roles or is reserved by PostgreSQL"
        )
    if not writer_login_configured(settings):
        raise ConfigError(
            "the writer's database password is not set; put ARGUS_DATABASE__WRITER_PASSWORD in"
            " the writer's credentials (bootstrap sets it on the writer's login)"
        )
    assert settings.writer_password is not None
    try:
        usable_password(settings.writer_password.get_secret_value())
    except ValueError as exc:
        raise ConfigError(f"database.writer_password {exc}") from None


async def ensure_writer_roles(
    conn: AsyncConnection, settings: DatabaseSettings, *, changes: list[str] | None = None
) -> list[str]:
    """The case writer's roles, as :func:`ensure_api_roles` makes the web's: the group
    role ``argus_writer`` always (migrations grant it what the writer needs), and
    the writer's login (``database.writer_user``) once its password is configured: an inheriting
    member of that group and of nothing else (a membership of ``argus_runtime`` it had is
    revoked). In ``conn``'s transaction, as the owner. Returns the roles it created; repairs are
    appended to ``changes``."""
    configured = writer_login_configured(settings)
    if configured:
        check_writer_settings(settings)  # before anything is sent
    repairs = [] if changes is None else changes
    group = WRITER_ROLE  # read now: tests point it elsewhere
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
    if not configured:
        created = await _ensure_group(conn, group, repairs)
        repairs += await _revoke_memberships(conn, group, keep=None, report_missing=False)
        return created
    assert settings.writer_password is not None
    return await _ensure_group_and_login(
        conn,
        group,
        settings.writer_user,
        settings.writer_password.get_secret_value(),
        settings.name,
        repairs,
    )


async def ensure_web_approvals(
    conn: AsyncConnection, settings: DatabaseSettings, *, changes: list[str] | None = None
) -> bool:
    """Make the web's login (``database.api_user``) an inheriting member of ``argus_approvals``
    without ADMIN OPTION, so the web records the approvals it signs. Run after
    :func:`ensure_api_roles` and :func:`ensure_approvals_role`; a no-op without the web's login.
    Returns whether it granted the membership; a repair is appended to ``changes``."""
    if not api_login_configured(settings):
        return False
    held = (
        await conn.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM pg_auth_members m"
                " JOIN pg_roles g ON g.oid = m.roleid JOIN pg_roles u ON u.oid = m.member"
                " WHERE g.rolname = :g AND u.rolname = :u AND m.inherit_option"
                " AND NOT m.admin_option)"
            ),
            {"g": APPROVALS_ROLE, "u": settings.api_user},
        )
    ).scalar_one()
    if held:
        return False
    grant = sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(
        sql.Identifier(APPROVALS_ROLE), sql.Identifier(settings.api_user)
    )
    await _retrying(conn, grant)
    if changes is not None:
        changes.append(f"{settings.api_user} was not a member of {APPROVALS_ROLE}: granted")
    return True


async def _ensure_group(conn: AsyncConnection, group: str, repairs: list[str]) -> list[str]:
    """CREATE the group role, or put back its attributes; [group] if it was created."""
    if await _create(conn, group, sql.SQL(f"NOLOGIN {_SAFE_ATTRIBUTES}")):
        return [group]
    repairs += await _restore(conn, group, _GROUP_STATE, login=False)
    return []


async def _ensure_group_and_login(
    conn: AsyncConnection,
    group: str,
    user: str,
    password: str,
    database: str,
    repairs: list[str],
    also_keep: tuple[str, ...] = (),
) -> list[str]:
    """The group role and its one login, in their safe states, the login's password set. Both
    belong to nothing else; the login is the group's inheriting member without ADMIN OPTION."""
    created = await _ensure_group(conn, group, repairs)
    verifier = await _password_verifier(conn, user, password)
    login = sql.SQL("LOGIN {} PASSWORD {}").format(sql.SQL(_SAFE_ATTRIBUTES), verifier)
    new_login = await _create(conn, user, login)
    if new_login:
        created.append(user)
    else:
        repairs += await _restore(conn, user, _LOGIN_STATE, login=True)
        # On its own: a CREATEROLE owner may not name SUPERUSER and the like, even to clear them.
        alter = sql.SQL("ALTER ROLE {} WITH PASSWORD {}").format(sql.Identifier(user), verifier)
        await _retrying(conn, alter)
        repairs += await _clear_settings(conn, user, database)
    repairs += await _revoke_memberships(conn, group, keep=None, report_missing=False)
    repairs += await _revoke_memberships(
        conn, user, keep=group, report_missing=not new_login, also_keep=also_keep
    )
    return created


async def ensure_approvals_role(
    conn: AsyncConnection, *, changes: list[str] | None = None
) -> list[str]:
    """Create the group role ``argus_approvals``, or put it back into its safe state: no
    login, no dangerous attribute, a member of nothing. Run with :func:`ensure_roles`, which
    keeps the runtime login out of it. Returns the roles it created (``[]`` or the group);
    repairs are appended to ``changes``. A migration grants it EXECUTE on the approval
    functions, nothing else."""
    repairs = [] if changes is None else changes
    group = APPROVALS_ROLE
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
    created: list[str] = []
    if await _create(conn, group, sql.SQL(f"NOLOGIN {_SAFE_ATTRIBUTES}")):
        created.append(group)
    else:
        repairs += await _restore(conn, group, _GROUP_STATE, login=False)
    repairs += await _revoke_memberships(conn, group, keep=None, report_missing=False)
    return created


async def ensure_purge_role(
    conn: AsyncConnection, *, changes: list[str] | None = None
) -> list[str]:
    """Create the group role ``argus_purge``, or put it back into its safe state: no
    login, no dangerous attribute, a member of nothing. The owner switches to it (``SET ROLE``)
    to purge: a superuser owner may anyway; any other owner gets the membership it needs for
    that, without inheriting the role's privileges. Returns the roles it created; repairs are
    appended to ``changes``. A migration grants it :data:`PURGE_GRANTS`."""
    repairs = [] if changes is None else changes
    group = PURGE_ROLE
    await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
    created = await _ensure_group(conn, group, repairs)
    repairs += await _revoke_memberships(conn, group, keep=None, report_missing=False)
    superuser, may_switch = (
        await conn.execute(
            text(
                "SELECT rolsuper, pg_has_role(current_user, :g, 'SET') FROM pg_roles"
                " WHERE rolname = current_user"
            ),
            {"g": group},
        )
    ).one()
    if not (superuser or may_switch):
        grant = sql.SQL("GRANT {} TO CURRENT_USER WITH INHERIT FALSE, SET TRUE").format(
            sql.Identifier(group)
        )
        try:
            await _retrying(conn, grant)
        except DBAPIError as exc:
            # A CREATEROLE owner may grant only the roles it administers: one a superuser made
            # needs that superuser's grant. The purge says so when it starts (purge_role_problems).
            if _sqlstate(exc) != _INSUFFICIENT_PRIVILEGE:
                raise
    return created


async def grant_connect(conn: AsyncConnection, database: str, role: str | None = None) -> None:
    """Let the runtime role (or ``role``, a group role) connect to ``database`` (PUBLIC may not
    have that right).

    PostgreSQL only warns when the owner may not grant it, so the result is checked: a
    BootstrapError if the role still may not connect.
    """
    group = RUNTIME_ROLE if role is None else role
    await _execute(
        conn,
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
            sql.Identifier(database), sql.Identifier(group)
        ),
    )
    allowed = await conn.execute(
        text("SELECT has_database_privilege(:g, :d, 'CONNECT')"), {"g": group, "d": database}
    )
    if not allowed.scalar_one():
        # Bootstrap is one transaction, so the group role it may just have created is rolled
        # back with it: the remedy names the owner, which exists already. The message ends with
        # the statement, quoted, so that it can be run as printed.
        owner = (await conn.execute(text("SELECT current_user"))).scalar_one()
        remedy = sql.SQL("GRANT CONNECT ON DATABASE {} TO {} WITH GRANT OPTION").format(
            sql.Identifier(database), sql.Identifier(owner)
        )
        raise BootstrapError(
            f"{group} may not connect to the database, and this owner may not grant that:"
            " bootstrap again once the database's owner has run"
            f" {remedy.as_string(await _driver(conn))}"
        )


async def _state(conn: AsyncConnection, role: str) -> tuple[Any, ...] | None:
    """The role's attributes in _FLAGS order, then whether it has no connection limit and no
    password expiry; None if it does not exist."""
    row = (
        await conn.execute(
            text(
                "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolreplication,"
                " rolbypassrls, rolinherit, rolconnlimit = -1,"
                " rolvaliduntil IS NULL OR rolvaliduntil = 'infinity'"
                " FROM pg_roles WHERE rolname = :r"
            ),
            {"r": role},
        )
    ).first()
    return None if row is None else tuple(row)


async def _create(conn: AsyncConnection, role: str, attributes: sql.Composable) -> bool:
    """CREATE ROLE; False if it exists already, or another bootstrap created it meanwhile."""
    if await _state(conn, role) is not None:
        return False
    try:
        async with conn.begin_nested():
            await _execute(
                conn, sql.SQL("CREATE ROLE {} WITH {}").format(sql.Identifier(role), attributes)
            )
    except DBAPIError as exc:
        if _sqlstate(exc) not in _DUPLICATE_ROLE:
            raise
        return False
    return True


async def _restore(
    conn: AsyncConnection, role: str, wanted: tuple[bool, ...], *, login: bool
) -> list[str]:
    """ALTER only the attributes that differ from ``wanted``: since PostgreSQL 16 a role without
    SUPERUSER (a CREATEROLE owner) may not name SUPERUSER, REPLICATION or BYPASSRLS at all."""
    state = await _state(conn, role)
    assert state is not None
    clauses: list[str] = []
    found: list[str] = []
    for index, (on, off) in enumerate(_FLAGS):
        want, have = wanted[index], state[index]
        if have != want:
            clauses.append(on if want else off)
            found.append(on if have else off)
    if login and not state[len(_FLAGS)]:
        clauses.append("CONNECTION LIMIT -1")
        found.append("a connection limit")
    if login and not state[len(_FLAGS) + 1]:
        clauses.append("VALID UNTIL 'infinity'")
        found.append("a password expiry")
    if not clauses:
        return []
    alter = sql.SQL("ALTER ROLE {} WITH {}").format(
        sql.Identifier(role), sql.SQL(" ".join(clauses))
    )
    try:
        await _retrying(conn, alter)
    except DBAPIError as exc:
        if _sqlstate(exc) != _INSUFFICIENT_PRIVILEGE:
            raise
        statement = alter.as_string(await _driver(conn))
        raise BootstrapError(
            f"{role} has {', '.join(found)}, and this owner may not change that: a superuser"
            f" must run {statement}"
        ) from None
    return [f"{role} had {', '.join(found)}: reset"]


async def _stored_settings(
    conn: AsyncConnection, role: str, database: str
) -> list[tuple[bool, list[str]]]:
    """Settings stored on ``role`` everywhere (True) and in ``database`` (False)."""
    rows = await conn.execute(
        text(
            "SELECT s.setdatabase = 0, s.setconfig FROM pg_db_role_setting s"
            " WHERE s.setrole = (SELECT oid FROM pg_roles WHERE rolname = :r)"
            " AND s.setdatabase IN (0, (SELECT oid FROM pg_database WHERE datname = :d))"
        ),
        {"r": role, "d": database},
    )
    return [(bool(everywhere), list(config or ())) for everywhere, config in rows.all()]


def _setting_names(rows: list[tuple[bool, list[str]]]) -> list[str]:
    return sorted({entry.partition("=")[0] for _, config in rows for entry in config})


async def _clear_settings(conn: AsyncConnection, role: str, database: str) -> list[str]:
    """Remove settings stored on the login (ALTER ROLE ... SET), everywhere and in ARGUS's
    database: one stored by a superuser applies even where the login could not set it.

    RESET ALL by an owner that is no superuser silently keeps the settings it may not set itself
    (session_replication_role, say), so what is left is read again: a BootstrapError then, never
    a report that they were cleared.
    """
    rows = await _stored_settings(conn, role, database)
    if not rows:
        return []
    for everywhere in sorted({row[0] for row in rows}):
        where = (
            sql.SQL("")
            if everywhere
            else sql.SQL(" IN DATABASE {}").format(sql.Identifier(database))
        )
        await _retrying(
            conn, sql.SQL("ALTER ROLE {}{} RESET ALL").format(sql.Identifier(role), where)
        )
    left = await _stored_settings(conn, role, database)
    if left:
        statement = sql.SQL("ALTER ROLE {} RESET ALL").format(sql.Identifier(role))
        raise BootstrapError(
            f"{role} has settings stored on it that this owner may not remove"
            f" ({', '.join(_setting_names(left))}): a superuser must run"
            f" {statement.as_string(await _driver(conn))} (also IN DATABASE for its database)"
        )
    return [f"{role} had stored settings ({', '.join(_setting_names(rows))}): cleared"]


async def _grants(conn: AsyncConnection) -> list[tuple[str, str, str, bool, bool]]:
    """Every membership grant in the cluster: (role, member, grantor, admin option, inherit)."""
    rows = await conn.execute(
        text(
            "SELECT r.rolname, m.rolname, g.rolname, am.admin_option, am.inherit_option"
            " FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid"
            " JOIN pg_roles m ON m.oid = am.member JOIN pg_roles g ON g.oid = am.grantor"
            " ORDER BY 1, 2, 3"
        )
    )
    return [(str(r), str(m), str(g), bool(a), bool(i)) for r, m, g, a, i in rows.all()]


async def _revoke_memberships(
    conn: AsyncConnection,
    member: str,
    *,
    keep: str | None,
    report_missing: bool,
    also_keep: tuple[str, ...] = (),
) -> list[str]:
    """Revoke every membership of ``member`` except an inheriting one in ``keep`` without ADMIN
    OPTION, which is granted if none is left. Each grant is revoked as its grantor made it, with
    CASCADE (grants made through it go too, and are reported); whether the kept membership
    survived is read again afterwards, since a CASCADE can take it. An inheriting membership
    without ADMIN OPTION in a role of ``also_keep`` is left as it is (never granted here)."""
    before = await _grants(conn)
    revoked: set[tuple[str, str, str]] = set()
    wrong_in_keep: list[str] = []
    repairs: list[str] = []
    for role, holder, grantor, admin, inherit in before:
        if holder != member or ((role == keep or role in also_keep) and inherit and not admin):
            continue
        revoke = sql.SQL("REVOKE {} FROM {} GRANTED BY {} CASCADE").format(
            sql.Identifier(role), sql.Identifier(member), sql.Identifier(grantor)
        )
        await _retrying(conn, revoke)
        revoked.add((role, member, grantor))
        if role == keep:
            wrong_in_keep.append("ADMIN OPTION" if admin else "no INHERIT")
        else:
            repairs.append(f"{member} was a member of {role}: revoked")
    current = await _grants(conn) if revoked else before
    if revoked:
        gone = {grant[:3] for grant in before} - {grant[:3] for grant in current} - revoked
        repairs += [
            f"{holder} lost its membership in {role} (granted by {grantor}) with that revoke"
            for role, holder, grantor in sorted(gone)
        ]
    if keep is None:
        return repairs
    member_of_keep = any(
        role == keep and holder == member and inherit and not admin
        for role, holder, _, admin, inherit in current
    )
    if not member_of_keep:
        grant = sql.SQL("GRANT {} TO {} WITH INHERIT TRUE").format(
            sql.Identifier(keep), sql.Identifier(member)
        )
        await _retrying(conn, grant)
    outcome = "revoked" if member_of_keep else "granted again"
    repairs += [
        f"{member}'s membership in {keep} had {option}: {outcome}" for option in wrong_in_keep
    ]
    if not member_of_keep and not wrong_in_keep and report_missing:
        repairs.append(f"{member} was not a member of {keep}: granted")
    return repairs


async def _retrying(conn: AsyncConnection, statement: sql.Composable) -> None:
    """Run role DDL in a savepoint, again if a concurrent bootstrap changed the same row first."""
    for attempt in range(1, _ATTEMPTS + 1):
        try:
            async with conn.begin_nested():
                await _execute(conn, statement)
            return
        except DBAPIError as exc:
            if attempt == _ATTEMPTS or not _changed_meanwhile(exc):
                raise


def _changed_meanwhile(exc: DBAPIError) -> bool:
    if _sqlstate(exc) == "23505":  # e.g. the same membership granted by both
        return True
    return _sqlstate(exc) == "XX000" and "concurrently" in str(exc.orig)  # updated or deleted


def _sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


async def _password_verifier(conn: AsyncConnection, user: str, password: str) -> sql.Literal:
    """The SCRAM-SHA-256 verifier for ``password``, computed here by libpq.

    The server only ever sees the verifier, so the password cannot reach its logs (PostgreSQL
    logs the text of a failed statement).
    """
    driver = await _driver(conn)
    verifier = driver.pgconn.encrypt_password(password.encode(), user.encode(), b"scram-sha-256")
    return sql.Literal(verifier.decode("ascii"))


async def _driver(conn: AsyncConnection) -> Any:
    """The psycopg connection under ``conn`` (for libpq's password hashing and SQL quoting)."""
    raw = await conn.get_raw_connection()
    return raw.driver_connection


async def _execute(conn: AsyncConnection, statement: sql.Composable) -> None:
    """Run a statement that cannot take bind parameters (role DDL), quoted by psycopg.

    A password verifier is part of such a statement, and SQLAlchemy repeats a failed statement
    in its exception text (hide_parameters covers parameters only), so that copy is redacted.
    """
    try:
        await conn.exec_driver_sql(statement.as_string(await _driver(conn)))
    except DBAPIError as exc:
        if exc.statement:
            exc.statement = redact_text(exc.statement)
        raise


async def runtime_role_problems(engine: AsyncEngine) -> list[str]:
    """What the login of ``engine`` (the runtime role) may do beyond :data:`RUNTIME_GRANTS`, or
    may not do of it. Empty when it is exactly as intended. Needs the tables to exist."""
    return await _login_problems(
        engine, RUNTIME_ROLE, RUNTIME_GRANTS, every_table=False, may=RUNTIME_FUNCTIONS
    )


async def api_role_problems(engine: AsyncEngine) -> list[str]:
    """What the login of ``engine`` (the web's login) may do beyond :data:`API_GRANTS`, or may
    not do of it, on every table of ARGUS's schemas: a table the list does not name it may not
    touch at all. Empty when it is exactly as intended. Needs the tables to exist."""
    return await _login_problems(
        engine,
        API_ROLE,
        API_GRANTS,
        every_table=True,
        may=WEB_FUNCTIONS,
        also_member_of=(APPROVALS_ROLE,),
    )


async def writer_role_problems(engine: AsyncEngine) -> list[str]:
    """What the login of ``engine`` (the case writer's) may do beyond :data:`WRITER_GRANTS`, or
    may not do of it, on every table of ARGUS's schemas: a table the list does not name it may
    not touch at all, and it is not a member of ``argus_runtime``. Empty when it is exactly as
    the migrations intend. Needs the tables to exist."""
    return await _login_problems(
        engine,
        WRITER_ROLE,
        WRITER_GRANTS,
        every_table=True,
        may=WRITER_FUNCTIONS,
    )


async def purge_role_problems(owner_engine: AsyncEngine) -> list[str]:
    """What ``argus_purge`` may do beyond :data:`PURGE_GRANTS`, or may not do of it, on every
    table of ARGUS's schemas, seen after the owner's ``SET ROLE`` to it. Empty when it is
    exactly as its migration intends; ``argus purge`` refuses to run otherwise."""
    return await _login_problems(
        owner_engine, PURGE_ROLE, PURGE_GRANTS, every_table=True, set_role=PURGE_ROLE, may=()
    )


async def _login_problems(
    engine: AsyncEngine,
    group: str,
    grants: dict[str, TableGrant],
    *,
    every_table: bool,
    set_role: str | None = None,
    may: tuple[str, ...] = RUNTIME_FUNCTIONS,
    also_member_of: tuple[str, ...] = (),
) -> list[str]:
    """A login's attributes, memberships (``group``, and ``also_member_of``), stored settings,
    table grants against ``grants`` and the functions it may execute (``may``); with
    ``every_table`` also every other table of ARGUS's schemas, where it must hold nothing. With
    ``set_role`` the checks are those of that role, switched to after connecting (a group role
    that cannot log in)."""
    problems: list[str] = []
    async with engine.connect() as conn:
        if set_role is not None:
            try:
                async with conn.begin_nested():
                    await _execute(
                        conn, sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(set_role))
                    )
            except DBAPIError:
                return [
                    f"{set_role} is missing, or this login may not switch to it (a superuser:"
                    f" GRANT {set_role} TO <the owner> WITH INHERIT FALSE, SET TRUE)"
                ]
        role = (
            await conn.execute(
                text(
                    "SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,"
                    " has_database_privilege(current_database(), 'CREATE'),"
                    " has_schema_privilege('public', 'CREATE'),"
                    " coalesce(has_schema_privilege(to_regnamespace('langgraph')::oid, 'CREATE'),"
                    " false)"
                    " FROM pg_roles WHERE rolname = current_user"
                )
            )
        ).one()
        labels = (
            "is a superuser",
            "can create roles",
            "can create databases",
            "can replicate",
            "bypasses row-level security",
            "can create schemas",
            "can create tables in schema public",
            "can create tables in schema langgraph",
        )
        problems += [label for label, flag in zip(labels, role, strict=True) if flag]
        if not role[0]:  # a superuser counts as a member of every role: said above
            problems += await _membership_problems(conn, group, also=also_member_of)
        problems += await _settings_problems(conn)
        for table, grant in grants.items():
            problems += await _table_problems(conn, table, grant)
        if every_table:
            for table in await _tables(conn):
                if table not in grants:
                    problems += await _table_problems(conn, table, TableGrant())
        problems += await _sequence_problems(conn)
        problems += await _function_problems(conn, may)
    return problems


async def _function_problems(
    conn: AsyncConnection, may: tuple[str, ...] = RUNTIME_FUNCTIONS
) -> list[str]:
    """The login may execute exactly ``may`` of ARGUS's own functions: the runtime login only
    ARGUS's proposals, never an approval or the owner's chain and guard functions; the
    web's login the approval functions. argus_approvals may execute exactly those."""
    problems: list[str] = []
    for function in _ALL_FUNCTIONS:
        row = (
            await conn.execute(
                text(
                    "SELECT to_regprocedure(:f) IS NOT NULL,"
                    " coalesce(has_function_privilege(to_regprocedure(:f), 'EXECUTE'), false),"
                    " coalesce(has_function_privilege(:g, to_regprocedure(:f), 'EXECUTE'), false)"
                    " FROM pg_roles WHERE rolname = :g"
                ),
                {"f": function, "g": APPROVALS_ROLE},
            )
        ).first()
        name = function.partition("(")[0]
        if row is None:
            return [*problems, f"{APPROVALS_ROLE} is missing"]
        exists, runtime_may, approvals_may = row
        if not exists:
            problems.append(f"function {name} is missing")
            continue
        if runtime_may and function not in may:
            problems.append(f"can execute {name}")
        if function in may and not runtime_may:
            problems.append(f"cannot execute {name}")
        if approvals_may != (function in APPROVALS_FUNCTIONS):
            problems.append(
                f"{APPROVALS_ROLE} {'can' if approvals_may else 'cannot'} execute {name}"
            )
    return problems


async def _sequence_problems(conn: AsyncConnection) -> list[str]:
    """Any privilege on a sequence of ARGUS's schemas. ARGUS's ids are identity columns, whose
    inserts need none; UPDATE would let a login setval() a table's ids into collisions."""
    rows = await conn.execute(
        text(
            "SELECT n.nspname, c.relname, has_sequence_privilege(c.oid, 'USAGE'),"
            " has_sequence_privilege(c.oid, 'SELECT'), has_sequence_privilege(c.oid, 'UPDATE')"
            " FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE c.relkind = 'S' AND n.nspname = ANY(:schemas)"
            " AND has_schema_privilege(n.oid, 'USAGE') ORDER BY 1, 2"
        ),
        {"schemas": list(_API_SCHEMAS)},
    )
    problems = []
    for schema, name, *held in rows.all():
        shown = name if schema == "public" else f"{schema}.{name}"
        problems += [
            f"can {privilege} sequence {shown}"
            for privilege, has in zip(_SEQUENCE_PRIVILEGES, held, strict=True)
            if has
        ]
    return problems


async def _tables(conn: AsyncConnection) -> list[str]:
    """Every table, view and the like in ARGUS's schemas, named as the grant lists name them
    (``schema.table`` outside public)."""
    rows = await conn.execute(
        text(
            "SELECT n.nspname, c.relname FROM pg_class c"
            " JOIN pg_namespace n ON n.oid = c.relnamespace"
            " WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND n.nspname = ANY(:schemas)"
            " ORDER BY 1, 2"
        ),
        {"schemas": list(_API_SCHEMAS)},
    )
    return [name if schema == "public" else f"{schema}.{name}" for schema, name in rows.all()]


async def _membership_problems(
    conn: AsyncConnection, group: str | None = None, *, also: tuple[str, ...] = ()
) -> list[str]:
    """Any role the login belongs to besides its group (argus_runtime unless named) and the
    roles in ``also`` (directly or not, predefined roles such as pg_read_server_files
    included), and how it belongs to its group."""
    group = RUNTIME_ROLE if group is None else group
    params = {"g": group}
    others = await conn.execute(
        text(
            "SELECT rolname FROM pg_roles WHERE pg_has_role(current_user, oid, 'MEMBER')"
            " AND rolname <> current_user AND rolname <> :g ORDER BY rolname"
        ),
        params,
    )
    problems = [f"is a member of {name}" for (name,) in others if name not in also]
    held = (
        await conn.execute(
            text(
                "SELECT pg_has_role(current_user, oid, 'USAGE'),"
                " pg_has_role(current_user, oid, 'MEMBER WITH ADMIN OPTION')"
                " FROM pg_roles WHERE rolname = :g"
            ),
            params,
        )
    ).first()
    if held is None:
        return [*problems, f"{group} is missing"]
    if not held[0]:
        problems.append(f"does not inherit the privileges of {group}")
    if held[1]:
        problems.append(f"can grant {group} to other roles (ADMIN OPTION)")
    for role in also:  # how it belongs to each of them; missing ones show as
        extra = (  # functions it may not execute
            await conn.execute(
                text(
                    "SELECT pg_has_role(current_user, a.oid, 'MEMBER'),"
                    " pg_has_role(current_user, a.oid, 'USAGE'),"
                    " pg_has_role(current_user, a.oid, 'MEMBER WITH ADMIN OPTION')"
                    " FROM pg_roles a WHERE a.rolname = :r"
                ),
                {"r": role},
            )
        ).first()
        if extra is None or not extra[0]:
            continue
        if not extra[1]:
            problems.append(f"does not inherit the privileges of {role}")
        if extra[2]:
            problems.append(f"can grant {role} to other roles (ADMIN OPTION)")
    return problems


async def _settings_problems(conn: AsyncConnection) -> list[str]:
    """Settings stored on the login (ALTER ROLE ... SET) apply to every ARGUS session."""
    rows = await conn.execute(
        text(
            "SELECT setconfig FROM pg_db_role_setting"
            " WHERE setrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)"
            " AND setdatabase IN (0, (SELECT oid FROM pg_database"
            " WHERE datname = current_database()))"
        )
    )
    names = sorted({entry.partition("=")[0] for (config,) in rows for entry in config or ()})
    problems = [f"has settings stored on it ({', '.join(names)})"] if names else []
    # Settings stored for the database or for every role reach ARGUS's sessions too.
    effective = await conn.execute(
        text(
            "SELECT name, setting, source FROM pg_settings WHERE name IN"
            " ('default_transaction_read_only', 'session_replication_role') ORDER BY name"
        )
    )
    for name, setting, source in effective:
        if setting != _SESSION_DEFAULTS[name]:
            where = _SETTING_SOURCES.get(source, f"source: {source}")
            problems.append(f"runs with {name} = {setting} ({where})")
    return problems


async def _table_problems(conn: AsyncConnection, table: str, grant: TableGrant) -> list[str]:
    schema, qualified, _ = table.rpartition(".")
    if qualified:  # outside public: without USAGE on its schema nothing in it can be named
        exists, usage = (
            await conn.execute(
                text(
                    "SELECT to_regnamespace(:s) IS NOT NULL,"
                    " coalesce(has_schema_privilege(to_regnamespace(:s)::oid, 'USAGE'), false)"
                ),
                {"s": schema},
            )
        ).one()
        if not exists:
            return [f"{table} is missing"]
        if not usage:  # fine for a table the login must not touch: it cannot even name it
            return [] if grant == TableGrant() else [f"cannot use schema {schema} (for {table})"]
    params = {"t": table}
    owner = (
        await conn.execute(
            text(
                "SELECT pg_has_role(current_user, relowner, 'MEMBER') FROM pg_class"
                " WHERE oid = to_regclass(:t)"
            ),
            params,
        )
    ).scalar_one_or_none()
    if owner is None:
        return [f"{table} is missing"]
    problems = [f"owns {table} (or is a member of its owner)"] if owner else []
    can_select = (
        await conn.execute(text("SELECT has_table_privilege(:t, 'SELECT')"), params)
    ).scalar_one()
    if can_select != grant.select:
        problems.append(f"{'cannot' if grant.select else 'can'} read {table}")
    elif (
        not grant.select
        and not grant.select_columns
        and (
            await conn.execute(text("SELECT has_any_column_privilege(:t, 'SELECT')"), params)
        ).scalar_one()
    ):
        problems.append(f"can read columns of {table}")
    if grant.select_columns:
        readable = await conn.execute(
            text(
                "SELECT attname, has_column_privilege(attrelid, attnum, 'SELECT') FROM"
                " pg_attribute WHERE attrelid = to_regclass(:t) AND attnum > 0"
                " AND NOT attisdropped ORDER BY attnum"
            ),
            params,
        )
        for column, can_read in readable:
            if can_read != (column in grant.select_columns):
                problems.append(f"{'can' if can_read else 'cannot'} read {table}.{column}")
    checks = [
        ("has_table_privilege", privilege)
        for privilege in _NEVER_ON_TABLES
        if not (privilege == "DELETE" and grant.delete)
    ]
    if (
        grant.delete
        and not (
            await conn.execute(text("SELECT has_table_privilege(:t, 'DELETE')"), params)
        ).scalar_one()
    ):
        problems.append(f"cannot DELETE {table}")
    checks += [
        ("has_any_column_privilege", privilege)
        for privilege in _NEVER_ON_COLUMNS
        if not (privilege == "UPDATE" and grant.update)  # then checked column by column
    ]
    for function, privilege in checks:
        held = await conn.execute(text(f"SELECT {function}(:t, :p)"), {**params, "p": privilege})
        if held.scalar_one():
            problems.append(f"can {privilege} {table}")
    columns = await conn.execute(
        text(
            "SELECT attname, has_column_privilege(attrelid, attnum, 'INSERT'),"
            " has_column_privilege(attrelid, attnum, 'UPDATE') FROM pg_attribute"
            " WHERE attrelid = to_regclass(:t) AND attnum > 0 AND NOT attisdropped"
            " ORDER BY attnum"
        ),
        params,
    )
    for column, can_insert, can_update in columns:
        if can_insert != (column in grant.insert):
            problems.append(f"{'can' if can_insert else 'cannot'} insert {table}.{column}")
        if grant.update and can_update != (column in grant.update):
            problems.append(f"{'can' if can_update else 'cannot'} update {table}.{column}")
    return problems
