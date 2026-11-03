"""ORM models: the audit trail (R1), the Elastic Gateway's shared state (R4, D-048), the
collector's alert store (R5, D-050), investigations and jobs (R6, D-051), reviewers and
reviews (R7, D-052), evidence, dossiers and signals (R8, D-054)."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Double,
    FetchedValue,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

AUDIT_OUTCOMES = ("success", "failure", "denied")


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class AuditEvent(Base):
    """Append-only record of what ARGUS did and why (enforced by triggers, see migrations 0001
    and 0002). Since 0026 (Q-C1) every new row is hash-chained by an owner's trigger: the
    ``chain_*`` columns are set by the database, never by ARGUS (argus.cases.chain)."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False, server_default="success")
    target_type: Mapped[str | None] = mapped_column(Text)
    target_id: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    # Set by the chain trigger; NULL only on rows written before the chain started. In the table
    # but not mapped (__mapper_args__): ARGUS's own writes never name them (the runtime role may
    # not), and the trail keeps working on a database at a revision before 0026 (the CLI audits
    # every migration step). Only argus.cases.chain reads them, through the table's columns.
    chain_seq: Mapped[int | None] = mapped_column(BigInteger, server_default=FetchedValue())
    prev_hash: Mapped[str | None] = mapped_column(Text, server_default=FetchedValue())
    row_hash: Mapped[str | None] = mapped_column(Text, server_default=FetchedValue())

    __mapper_args__ = {"exclude_properties": ["chain_seq", "prev_hash", "row_hash"]}  # noqa: RUF012
    __table_args__ = (
        CheckConstraint("length(actor) > 0", name="actor_not_empty"),
        CheckConstraint("length(action) > 0", name="action_not_empty"),
        CheckConstraint("outcome IN ('success', 'failure', 'denied')", name="outcome_valid"),
        CheckConstraint("jsonb_typeof(details) = 'object'", name="details_is_object"),
        CheckConstraint(
            "(chain_seq IS NULL) = (row_hash IS NULL)"
            " AND (chain_seq IS NULL) = (prev_hash IS NULL)",
            name="chain_complete",
        ),
        Index(None, "occurred_at"),
        Index(None, "target_type", "target_id"),
        Index(None, "action", "occurred_at"),
        Index(None, "chain_seq", unique=True, postgresql_where=text("chain_seq IS NOT NULL")),
    )


# --------------------------------------------------------------------------- Elastic Gateway (R4)

GATEWAY_COMPONENTS = (
    "global", "collector", "enrichment", "kibana", "writeback",
    "investigation", "freshness", "cases", "identity",  # Q-D2 (0029)
)  # fmt: skip
GATEWAY_STATES = ("health", "budget", "breaker", "lanes", "kibana", "kibana_breaker")
LANES = (
    "collector", "investigation", "freshness", "kibana_read", "kibana_write", "identity",
    "measurement",
)  # fmt: skip


class SiemSwitch(Base):
    """The operator's kill switches: ``global`` stops everything but health probes."""

    __tablename__ = "siem_switches"

    component: Mapped[str] = mapped_column(Text, primary_key=True)
    stopped: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    changed_by: Mapped[str] = mapped_column(Text, nullable=False, server_default="migration")
    reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "component IN ('global', 'collector', 'enrichment', 'kibana', 'writeback',"
            " 'investigation', 'freshness', 'cases', 'identity')",
            name="component_valid",
        ),
    )


class SiemState(Base):
    """One row per shared state machine (health memory, budget, breaker), as JSON."""

    __tablename__ = "siem_state"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(
            "name IN ('health', 'budget', 'breaker', 'lanes', 'kibana', 'kibana_breaker',"
            " 'identity')",
            name="name_valid",
        ),
        CheckConstraint("jsonb_typeof(state) = 'object'", name="state_is_object"),
    )


class SiemRequest(Base):
    """The request ledger: every request that reached the SIEM (or es-local), what it cost."""

    __tablename__ = "siem_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    component: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    indices: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    took_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    elapsed_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    response_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    live_session: Mapped[str | None] = mapped_column(Text)
    # Q-F2: the request's content address (``templates.task_key``): joins it to its evidence
    task_key: Mapped[str | None] = mapped_column(Text)
    # Q-D2 (0029): the lane it spent, where it went, a write's outbox row, hash, class and
    # approval, and the SIEM's health and the stopped switches when it was sent
    lane: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text, nullable=False, server_default="elasticsearch")
    outbox_id: Mapped[str | None] = mapped_column(Text)
    payload_hash: Mapped[str | None] = mapped_column(Text)
    write_class: Mapped[str | None] = mapped_column(Text)
    approval_id: Mapped[str | None] = mapped_column(Text)
    health: Mapped[str | None] = mapped_column(Text)
    switches: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default="{}")

    __table_args__ = (
        CheckConstraint(
            "took_ms >= 0 AND elapsed_ms >= 0 AND response_bytes >= 0", name="non_negative"
        ),
        CheckConstraint("attempts BETWEEN 1 AND 2", name="attempts_valid"),
        CheckConstraint("task_key IS NULL OR task_key ~ '^[0-9a-f]{64}$'", name="task_key_valid"),
        CheckConstraint("target IN ('elasticsearch', 'kibana')", name="target_valid"),
        CheckConstraint(
            "write_class IS NULL OR write_class IN ('W1', 'W2', 'W3', 'WA', 'WT', 'WC')",
            name="write_class_valid",
        ),
        CheckConstraint(
            "payload_hash IS NULL OR payload_hash ~ '^[0-9a-f]{64}$'", name="payload_hash_valid"
        ),
        CheckConstraint(
            "lane IS NULL OR lane IN ('collector', 'investigation', 'freshness', 'kibana_read',"
            " 'kibana_write', 'identity', 'measurement')",
            name="lane_valid",
        ),
        Index(None, "at"),
        Index(None, "live_session"),
        Index(None, "task_key"),
        Index(None, "outbox_id"),
    )


HEALTH_STATES = ("normal", "caution", "degraded", "stop")


class SiemProbe(Base):
    """The health probe's readings, one row per probe (Q-A2): what the gateway reads anyway every
    minute (node stats, index blocks) and the state it concluded, kept so that the SIEM's load
    budget can be measured again (Q-A3). Storing them sends no request."""

    __tablename__ = "siem_probes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    reasons: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    probe_ok: Mapped[bool] = mapped_column(Boolean, nullable=False)
    auth_failed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    disk_percent: Mapped[float | None] = mapped_column(Double)
    heap_percent: Mapped[float | None] = mapped_column(Double)
    load_1m: Mapped[float | None] = mapped_column(Double)
    search_queue: Mapped[int | None] = mapped_column(BigInteger)
    search_rejected: Mapped[int | None] = mapped_column(BigInteger)  # cumulative counters
    breakers_tripped: Mapped[int | None] = mapped_column(BigInteger)
    write_rejected: Mapped[int | None] = mapped_column(BigInteger)
    blocked_indices: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    ingest_lag_s: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )  # source: seconds
    stale_rules: Mapped[int | None] = mapped_column(BigInteger)

    __table_args__ = (
        CheckConstraint("state IN ('normal', 'caution', 'degraded', 'stop')", name="state_valid"),
        CheckConstraint(
            "(disk_percent IS NULL OR disk_percent BETWEEN 0 AND 100)"
            " AND (heap_percent IS NULL OR heap_percent BETWEEN 0 AND 100)"
            " AND (load_1m IS NULL OR load_1m >= 0)",
            name="gauges_valid",
        ),
        CheckConstraint(
            "coalesce(search_queue, 0) >= 0 AND coalesce(search_rejected, 0) >= 0"
            " AND coalesce(breakers_tripped, 0) >= 0 AND coalesce(write_rejected, 0) >= 0"
            " AND coalesce(stale_rules, 0) >= 0",
            name="counters_valid",
        ),
        CheckConstraint("jsonb_typeof(ingest_lag_s) = 'object'", name="lag_is_object"),
        Index(None, "at"),
    )


class SiemLiveSession(Base):
    """A human-issued live-test session (plan §10): request cap and end time."""

    __tablename__ = "siem_live_sessions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False)
    used: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("max_requests BETWEEN 1 AND 50", name="max_requests_valid"),
        CheckConstraint("used >= 0 AND used <= max_requests", name="used_valid"),
    )


# --------------------------------------------------------------------------- Collector (R5)

ALERT_STATUSES = ("normalized", "quarantined")
RECOVERED_BY = ("live", "backfill", "reconciliation")
CURSORS = ("live", "backfill")
GAP_KINDS = (
    "rule_not_running",
    "rule_gap_reported",
    "source_stalled",
    "late_data_beyond_lookback",
    "truncated_execution",
    "argus_collector_lag",
    "breaker_open",
)


class AlertRecord(Base):
    """One alert from the SIEM as it was read (raw ``_source``) and as R3 understood it (D-050).
    An alert gone from the SIEM gets ``source_missing_at``. Only the retention purge (Q-A4,
    D-028) removes anything: the raw ``_source`` after ``retention.raw_source``, the whole row
    with its investigation after ``memory.window``."""

    __tablename__ = "alert_records"

    alert_id: Mapped[str] = mapped_column(Text, primary_key=True)
    index: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    quarantine_reason: Mapped[str | None] = mapped_column(Text)
    quarantine_field: Mapped[str | None] = mapped_column(Text)
    normalizer_version: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str | None] = mapped_column(Text)
    detected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    event_time: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    fingerprint: Mapped[str | None] = mapped_column(Text)
    workflow_status: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    normalized: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    state_hash: Mapped[str] = mapped_column(Text, nullable=False)
    recovered_by: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source_missing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Q-A4 (D-028): when the retention purge removed ``raw`` (it is ``{}`` from then on, and the
    # collector never writes it back); set only by the purge role.
    raw_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('normalized', 'quarantined')", name="status_valid"),
        CheckConstraint(
            "recovered_by IN ('live', 'backfill', 'reconciliation')", name="recovered_by_valid"
        ),
        CheckConstraint(
            "(status = 'quarantined') = (quarantine_reason IS NOT NULL)", name="quarantine_reason"
        ),
        CheckConstraint("jsonb_typeof(raw) = 'object'", name="raw_is_object"),
        CheckConstraint("raw_purged_at IS NULL OR raw = '{}'::jsonb", name="purged_raw_is_empty"),
        Index(None, "detected_at"),
        Index(None, "rule_id", "event_time"),
        Index(None, "fingerprint"),
        Index(None, "first_seen_at"),  # R9: what is new since the last rules refresh
    )


class CollectorCursor(Base):
    """How far the live poll (newest stored ``@timestamp``) and the backfill (oldest finished
    hour) have got."""

    __tablename__ = "collector_cursors"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("name IN ('live', 'backfill', 'rules_refresh')", name="name_valid"),
    )


class ReconciliationRun(Base):
    """One comparison of the SIEM's alerts with the store over a window (plan §7.3)."""

    __tablename__ = "reconciliation_runs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    hours: Mapped[int] = mapped_column(Integer, nullable=False)
    hours_mismatched: Mapped[int] = mapped_column(Integer, nullable=False)
    recovered: Mapped[int] = mapped_column(Integer, nullable=False)
    missing_in_es: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint("window_start < window_end", name="window_valid"),
        CheckConstraint(
            "hours >= 0 AND hours_mismatched >= 0 AND recovered >= 0 AND missing_in_es >= 0",
            name="non_negative",
        ),
        Index(None, "finished_at"),
    )


class CoverageGap(Base):
    """A stretch of time ARGUS may not have seen everything (plan §5.6); open while ``end_at``
    is null. One open gap per (kind, subject)."""

    __tablename__ = "coverage_gaps"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    start_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    end_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    detail: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(
            "kind IN ('rule_not_running', 'rule_gap_reported', 'source_stalled',"
            " 'late_data_beyond_lookback', 'truncated_execution', 'argus_collector_lag',"
            " 'breaker_open')",
            name="kind_valid",
        ),
        CheckConstraint("end_at IS NULL OR end_at >= start_at", name="range_valid"),
        Index(
            "uq_coverage_gaps_open",
            "kind",
            "subject",
            unique=True,
            postgresql_where=text("end_at IS NULL"),
        ),
        Index(None, "start_at"),
    )


# --------------------------------------------------------------------------- Grouping and jobs (R6)

JOB_STATUSES = ("queued", "running", "done", "failed")


class Investigation(Base):
    """A group of alerts: one rule, one canonical key, one 24-hour bucket (plan §7.1, D-051).
    Everything but ``version`` is derived from its alerts and recomputed on every change."""

    __tablename__ = "investigations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    grouping_version: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str | None] = mapped_column(Text)
    group_key: Mapped[str] = mapped_column(Text, nullable=False)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    bucket_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    previous_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    continues_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    duplicate_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    first_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    severity: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[float | None] = mapped_column(Double)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("bucket_start < bucket_end", name="bucket_valid"),
        CheckConstraint(
            "alert_count >= 0 AND duplicate_count >= 0 AND version >= 0", name="non_negative"
        ),
        Index(None, "bucket_start"),
        Index(None, "previous_id"),
        Index(None, "rule_id", "bucket_start"),
        # the retention purge clears links to what it removes (migration 0030, Q-A4)
        Index(
            "ix_investigations_continues_id",
            "continues_id",
            postgresql_where=text("continues_id IS NOT NULL"),
        ),
        # The Inbox's orders (migration 0025, Q-A1 review F2; argus.web.queries._ORDER).
        Index("ix_investigations_newest", text("last_event_at DESC NULLS LAST"), "id"),
        Index("ix_investigations_oldest", text("last_event_at ASC NULLS LAST"), "id"),
        Index(  # the rank as Postgres writes it back (the schema check compares the text)
            "ix_investigations_urgent",
            text(
                "(\nCASE severity\n    WHEN 'critical'::text THEN 4"
                "\n    WHEN 'high'::text THEN 3\n    WHEN 'medium'::text THEN 2"
                "\n    WHEN 'low'::text THEN 1\n    ELSE 0\nEND) DESC"
            ),
            text("last_event_at DESC NULLS LAST"),
            "id",
        ),
    )


class InvestigationAlert(Base):
    """An alert's place in its investigation: exactly one (the primary key)."""

    __tablename__ = "investigation_alerts"

    alert_id: Mapped[str] = mapped_column(
        Text, ForeignKey("alert_records.alert_id"), primary_key=True
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    duplicate_of: Mapped[str | None] = mapped_column(Text)
    late_arrival: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    linked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index(None, "investigation_id"),)


class InvestigationEntity(Base):
    """The entity index: which IPs, domains, hosts and users an investigation involves."""

    __tablename__ = "investigation_entities"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)

    __table_args__ = (Index(None, "kind", "value"),)


class Entity(Base):
    """How many investigations an entity appears in (above 200: a supernode, D-051)."""

    __tablename__ = "entities"

    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    investigations: Mapped[int] = mapped_column(Integer, nullable=False)


class Job(Base):
    """Work on an investigation (R8 runs it). At most one active job per investigation; a
    claim is a lease, and only the current claim may finish the job (D-051)."""

    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="queued")
    trigger: Mapped[str] = mapped_column(Text, nullable=False)
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claims: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    lease_owner: Mapped[str | None] = mapped_column(Text)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_version: Mapped[int | None] = mapped_column(Integer)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # R8 (D-054): waiting for the SIEM or Postgres to come back; not a failure.
    deferred_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deferrals: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")

    __table_args__ = (
        CheckConstraint("status IN ('queued', 'running', 'done', 'failed')", name="status_valid"),
        CheckConstraint("claims >= 0 AND failures >= 0 AND deferrals >= 0", name="non_negative"),
        Index(
            "uq_jobs_active",
            "investigation_id",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
        Index(None, "status", "run_after"),
        Index(None, "investigation_id"),  # the purge's deletes and their key checks (0030)
    )


# --------------------------------------------------------------------------- Inbox (R7)

REVIEW_ACTIONS = ("reviewed", "follow_up", "note")
OUTCOMES = (
    "benign_expected",
    "benign_policy",
    "rule_false_positive",
    "true_positive",
    "inconclusive",
)


class User(Base):
    """An ARGUS account (D-052; Q-A1, Q-E2): a local reviewer (argon2id password,
    ``argus user add``) and/or the ELK account behind a person (``elk_username``, the exact
    name Elasticsearch knows; ``username`` stays ARGUS's own 2 to 32 character handle). A
    person who first signed in through ELK has no password hash; a hash is never dropped before
    their ELK sign-in has worked. A new ``argus_uid`` behind a known ELK name is a new person:
    the old account is frozen."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    username: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str | None] = mapped_column(Text)
    disabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Q-A1: what the account may do in local mode (argus.web.capabilities); every account
    # starts with what any reviewer could do before capabilities existed. In ELK mode only
    # ``answer_gold`` counts from it (ARGUS's own gold-key owners, D-080).
    capabilities: Mapped[list[str]] = mapped_column(
        ARRAY(Text),
        nullable=False,
        server_default=text("'{view,see_logs,review,answer_gold}'::text[]"),
    )
    # Q-E2 (0036)
    kind: Mapped[str] = mapped_column(Text, nullable=False, server_default="person")
    realm: Mapped[str] = mapped_column(Text, nullable=False, server_default="local")
    elk_username: Mapped[str | None] = mapped_column(Text)
    argus_uid: Mapped[str | None] = mapped_column(Text)
    email: Mapped[str | None] = mapped_column(Text)
    elk_first_signin_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_good_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    frozen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("username ~ '^[a-z][a-z0-9_.-]{1,31}$'", name="username_valid"),
        CheckConstraint(
            "capabilities <@ ARRAY['view', 'see_logs', 'review', 'answer_gold', 'manage_cases',"
            " 'reopen', 'approve', 'admin']::text[]"
            " AND array_position(capabilities, NULL) IS NULL",
            name="capabilities_valid",
        ),
        CheckConstraint("kind IN ('person', 'service', 'break_glass')", name="kind_valid"),
        CheckConstraint("realm IN ('local', 'native')", name="realm_valid"),
        CheckConstraint(
            "(realm = 'native') = (elk_username IS NOT NULL)", name="realm_matches_elk_name"
        ),
        CheckConstraint(
            "elk_username IS NULL OR char_length(elk_username) BETWEEN 1 AND 507",
            name="elk_username_valid",
        ),
        CheckConstraint(
            "argus_uid IS NULL OR argus_uid ~"
            " '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'",
            name="argus_uid_valid",
        ),
        CheckConstraint(
            "password_hash IS NOT NULL OR elk_first_signin_at IS NOT NULL",
            name="password_or_elk",
        ),
        CheckConstraint("kind <> 'break_glass' OR realm = 'local'", name="break_glass_is_local"),
        Index(
            None,
            "elk_username",
            unique=True,
            postgresql_where=text("elk_username IS NOT NULL AND frozen_at IS NULL"),
        ),
        Index(None, "argus_uid", unique=True, postgresql_where=text("argus_uid IS NOT NULL")),
    )


class UserSession(Base):
    """A sign-in: the token is stored only as its SHA-256; an idle and an absolute expiry
    (D-052, Q-A1), and when its person last confirmed their password (step-up). An ELK session
    (Q-E2) also holds the capability snapshot and when it was checked, the encrypted credential
    (AES-256-GCM under a key from the web's secret and the token, wiped at logout), and when
    ARGUS could not verify the person any longer, and why."""

    __tablename__ = "user_sessions"

    token_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    csrf_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    previous_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    stepped_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stepup_failures: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    # Q-E2 (0036)
    mode: Mapped[str] = mapped_column(Text, nullable=False, server_default="local")
    capabilities: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    map_version: Mapped[int | None] = mapped_column(SmallInteger)
    credential: Mapped[bytes | None] = mapped_column(LargeBinary)
    no_custody: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    unverified_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    unverified_why: Mapped[str | None] = mapped_column(Text)
    ended_why: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index(None, "user_id"),
        Index(
            "ix_user_sessions_with_credential",
            "token_hash",
            postgresql_where=text("credential IS NOT NULL"),
        ),
        CheckConstraint("stepup_failures >= 0", name="stepup_failures_valid"),
        CheckConstraint("mode IN ('local', 'elk', 'break_glass')", name="mode_valid"),
        CheckConstraint(
            "capabilities IS NULL OR (capabilities <@ ARRAY['view', 'see_logs', 'review',"
            " 'answer_gold', 'manage_cases', 'reopen', 'approve', 'admin']::text[]"
            " AND array_position(capabilities, NULL) IS NULL)",
            name="snapshot_valid",
        ),
        CheckConstraint(
            "mode <> 'elk' OR (capabilities IS NOT NULL AND checked_at IS NOT NULL)",
            name="elk_has_snapshot",
        ),
        CheckConstraint(
            "unverified_why IS NULL OR unverified_why IN ('outage', 'refused')",
            name="unverified_why_valid",
        ),
        CheckConstraint(
            "credential IS NULL OR (mode = 'elk' AND NOT no_custody)", name="credential_only_elk"
        ),
    )


class UserDevice(Base):
    """A browser that signed in well once (Q-E2, plan §7.2): the hash of its device cookie. A
    name locked by the throttle still lets this browser try."""

    __tablename__ = "user_devices"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index(None, "user_id"),)


class BreakGlass(Base):
    """The one emergency window (Q-E2, plan §7.2): switched on at the host with a typed reason,
    at most 4 hours, one at a time; its one-time password is used by the first sign-in."""

    __tablename__ = "break_glass"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    slot: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="1")
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    enabled_by: Mapped[str] = mapped_column(Text, nullable=False)
    enabled_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    override: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("char_length(reason) BETWEEN 10 AND 500", name="reason_valid"),
        CheckConstraint(
            "expires_at > enabled_at AND expires_at <= enabled_at + interval '4 hours'",
            name="window_valid",
        ),
        Index(None, "slot", unique=True, postgresql_where=text("ended_at IS NULL")),
    )


class ReviewEvent(Base):
    """What a reviewer did with an investigation (append-only; plan §9.3, D-052)."""

    __tablename__ = "review_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    # P3 (plan §2.8): set when the review accepted an assessment's proposal, a label kind of
    # its own ("confirmed proposal") that never counts as support for P4's decisions
    assessment_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("assessments.id"))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    # Q-E2 (0036): made under a live ELK check that showed the alert-status privileges, in a
    # verified session (never an outage's, never break-glass's): the only reviews that may be
    # written back to Kibana
    kibana_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")

    __table_args__ = (
        CheckConstraint("action IN ('reviewed', 'follow_up', 'note')", name="action_valid"),
        CheckConstraint(
            "outcome IS NULL OR outcome IN ('benign_expected', 'benign_policy',"
            " 'rule_false_positive', 'true_positive', 'inconclusive')",
            name="outcome_valid",
        ),
        CheckConstraint("note IS NULL OR length(note) <= 4000", name="note_length"),
        Index(None, "investigation_id", "id"),
    )


class ReviewState(Base):
    """Each reviewed investigation's newest review, kept by a trigger on ``review_events``
    (migration 0025, Q-A1), so the lists need not rank every review on every request
    (plan §8 criterion 14). ``latest_id`` is the newest review of any kind; the ``decision_``
    columns are the newest one that changes the state (not a note), NULL while there is none.
    ARGUS only reads it: the trigger alone writes it."""

    __tablename__ = "review_state"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    latest_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    decision_id: Mapped[int | None] = mapped_column(BigInteger)
    action: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int | None] = mapped_column(Integer)
    alert_count: Mapped[int | None] = mapped_column(Integer)
    outcome: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    user_id: Mapped[int | None] = mapped_column(BigInteger)

    __table_args__ = (
        Index(None, "decided_at"),
        Index("ix_review_state_decided", text("decided_at DESC"), "investigation_id"),
        Index(
            "ix_review_state_follow_ups",
            "investigation_id",
            postgresql_where=text("action = 'follow_up'"),
        ),
    )


# --------------------------------------------------------------------------- context graph (R8)

EVIDENCE_STATUSES = (
    "ok",
    "empty",
    "failed",
    "timeout",
    "skipped_budget",
    "deferred",
    "source_lag",
    "source_expired",
    "unsupported_value",
)
DOSSIER_STATUSES = ("evidence_ready", "evidence_partial", "evidence_failed")


def _one_of(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class Evidence(Base):
    """One evidence task's result for one investigation version (plan §5.4, D-054). Written
    before the graph node returns; an ``ok``/``empty`` row is reused for the same ``task_key``,
    any other may be overwritten by a later attempt."""

    __tablename__ = "evidence"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_key: Mapped[str] = mapped_column(Text, primary_key=True)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    coverage: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    source_watermark: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    row_count: Mapped[int | None] = mapped_column(Integer)
    truncated: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    snapshot: Mapped[Any | None] = mapped_column(JSONB)
    result_hash: Mapped[str | None] = mapped_column(Text)
    took_ms: Mapped[int | None] = mapped_column(Integer)
    reused_from_version: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Q-F1 (0033): when the gateway was asked for it (a copy keeps the original's), so a
    # verified zero needs a reading that answered before the search was sent
    asked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Q-A4 (D-028): when the retention purge removed ``snapshot``; the row (what was asked,
    # its status, counts and hash) stays. Never reused once purged. Set only by the purge role.
    snapshot_purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("status", EVIDENCE_STATUSES), name="status_valid"),
        CheckConstraint(
            "snapshot_purged_at IS NULL OR snapshot IS NULL", name="purged_snapshot_is_empty"
        ),
        CheckConstraint("task_key ~ '^[0-9a-f]{64}$'", name="task_key_valid"),
        CheckConstraint("row_count IS NULL OR row_count >= 0", name="row_count_valid"),
        CheckConstraint(
            "(status IN ('ok', 'empty')) = (result_hash IS NOT NULL)", name="result_hash"
        ),
        # Q-F2: a row exists only for a request that has its E-id
        ForeignKeyConstraint(
            ["investigation_id", "task_key"],
            ["evidence_requests.investigation_id", "evidence_requests.task_key"],
        ),
        Index(None, "investigation_id", "task_key"),
    )


EVIDENCE_ORIGINS = ("pack", "agent", "wave", "person", "watch")


class EvidenceRequest(Base):
    """An evidence request of an investigation and its opaque id ``E<eid>`` (Q-F2): one per
    task key, whatever the version (an earlier request planned again keeps its id, D-070).
    Numbered in the order ARGUS planned them; never changed or removed at run time. Who asked:
    the dossier's own wave (``pack``), an assessor's tool (``agent``), the deterministic wave
    (``wave``, Q-F3), a person's "check more" (``person``) or the still-active watch
    (``watch``, Q-C2)."""

    __tablename__ = "evidence_requests"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    eid: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_key: Mapped[str] = mapped_column(Text, nullable=False)
    template: Mapped[str] = mapped_column(Text, nullable=False)
    template_version: Mapped[int] = mapped_column(Integer, nullable=False)
    origin: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)  # the gap or step it answers, if any
    first_version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("eid >= 1", name="eid_valid"),
        CheckConstraint("first_version >= 0", name="first_version_valid"),
        CheckConstraint(_one_of("origin", EVIDENCE_ORIGINS), name="origin_valid"),
        CheckConstraint("reason IS NULL OR length(reason) <= 200", name="reason_length"),
        CheckConstraint("task_key ~ '^[0-9a-f]{64}$'", name="task_key_valid"),
        Index(None, "investigation_id", "task_key", unique=True),
    )


class Dossier(Base):
    """What ARGUS found for one investigation version (plan §8, D-054). Written with its
    signals, the job's completion and an audit event in one transaction; never changed."""

    __tablename__ = "dossiers"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    pack: Mapped[str] = mapped_column(Text, primary_key=True)  # D-058: one per pack version
    facts_version: Mapped[int] = mapped_column(Integer, nullable=False)
    job_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    run_kind: Mapped[str] = mapped_column(Text, nullable=False)
    family: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    partial_reason: Mapped[str | None] = mapped_column(Text)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    evidence_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_one_of("status", DOSSIER_STATUSES), name="status_valid"),
        CheckConstraint("run_kind IN ('collect', 'rederive')", name="run_kind_valid"),
        CheckConstraint("dossier_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint("facts_version >= version", name="facts_version_valid"),
        CheckConstraint("jsonb_typeof(body) = 'object'", name="body_is_object"),
    )


class Signal(Base):
    """A typed signal of a dossier (plan §5.4): a value only when it is known (D-023)."""

    __tablename__ = "signals"

    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    pack: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[Any | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    unknown_reason: Mapped[str | None] = mapped_column(Text)
    completeness: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    definition_version: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        ForeignKeyConstraint(
            ["investigation_id", "version", "pack"],
            ["dossiers.investigation_id", "dossiers.version", "dossiers.pack"],
        ),
        CheckConstraint("status IN ('known', 'unknown')", name="status_valid"),
        CheckConstraint(
            "completeness IN ('exact', 'lower_bound', 'upper_bound', 'approximate')",
            name="completeness_valid",
        ),
        CheckConstraint(
            "(status = 'known') = (value IS NOT NULL AND unknown_reason IS NULL)",
            name="known_has_value",
        ),
    )


# --------------------------------------------------------------------------- reference data (R9)

TI_KINDS = ("ip", "domain", "url", "hash", "email", "other")
KNOWLEDGE_STATUSES = ("proposed", "active", "retired")


class Rule(Base):
    """A detection rule as its newest alert describes it (D-057)."""

    __tablename__ = "rules"

    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    uuid: Mapped[str | None] = mapped_column(Text)
    name: Mapped[str | None] = mapped_column(Text)
    type: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int | None] = mapped_column(Integer)
    revision: Mapped[int | None] = mapped_column(Integer)
    interval: Mapped[str | None] = mapped_column(Text)
    lookback: Mapped[str | None] = mapped_column(Text)
    max_signals: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    note_hash: Mapped[str | None] = mapped_column(Text)
    definition_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    alerts: Mapped[int] = mapped_column(Integer, nullable=False)
    first_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_alert_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_execution_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_status: Mapped[str] = mapped_column(Text, nullable=False)
    refreshed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("alerts >= 0", name="alerts_valid"),
        CheckConstraint(
            "execution_status IN ('unknown', 'ok', 'failing', 'not_running')",
            name="execution_status_valid",
        ),
    )


class RuleRevision(Base):
    """Each (rule, revision, note) ARGUS has seen, and when first: a changed note marks the
    dossiers built on the old one (R10)."""

    __tablename__ = "rule_revisions"

    rule_id: Mapped[str] = mapped_column(Text, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, primary_key=True)
    note_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str | None] = mapped_column(Text)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TiSource(Base):
    """How fresh a threat-intel source is (D-057): its newest indicator, the last success."""

    __tablename__ = "ti_sources"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    newest: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    indicators: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


class TiIndicator(Base):
    """A mirrored indicator (a source of mode ``mirror``), canonical value."""

    __tablename__ = "ti_indicators"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    type_raw: Mapped[str] = mapped_column(Text, primary_key=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    confidence: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("kind", TI_KINDS), name="kind_valid"),
        Index(None, "value"),
    )


class TiLookup(Base):
    """A cached answer of a looked-up source (mode ``lookup``) for one value: its
    indicators (empty: no match), valid 24 h."""

    __tablename__ = "ti_lookups"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    indicators: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (CheckConstraint("jsonb_typeof(indicators) = 'array'", name="is_array"),)


class KnowledgeItem(Base):
    """What reviewers taught ARGUS (plan §9.3): typed, scoped, with provenance; benign
    patterns always expire."""

    __tablename__ = "knowledge_items"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    matcher: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    assertion: Mapped[str] = mapped_column(Text, nullable=False)
    guards: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    provenance: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_one_of("status", KNOWLEDGE_STATUSES), name="status_valid"),
        CheckConstraint(
            "kind IN ('benign_pattern', 'entity_note', 'context', 'false_positive')",
            name="kind_valid",
        ),
        CheckConstraint(
            "kind <> 'benign_pattern' OR expires_at IS NOT NULL", name="benign_expires"
        ),
    )


# --------------------------------------------------------------------------- soak (R16)


class SoakSample(Base):
    """An hourly snapshot of how ARGUS is doing (R16): the exit gate is judged from these."""

    __tablename__ = "soak_samples"

    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)
    metrics: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (CheckConstraint("jsonb_typeof(metrics) = 'object'", name="is_object"),)


# --------------------------------------------------------------------------- write-back (R17)


class WritebackItem(Base):
    """A planned change of alert status in Kibana (D-061, Q-D5): from a person's review, or from
    an approved case closure. Sent at most once per alert (``sent_count`` is the position in
    ``alert_ids``; ``written_count`` the alerts Kibana changed and the read-back confirmed;
    ``previous`` the status each of them had before)."""

    __tablename__ = "writeback_outbox"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    review_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    # an approved closure's row (0045): the case and its approval; no investigation
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    closure_request_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id"), unique=True
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)  # the Kibana workflow status
    alert_ids: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="planned")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error: Mapped[str | None] = mapped_column(Text)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    written_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    previous: Mapped[dict[str, str]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    # a review made without an ELK check that showed alert-write is sent only in a terminal run
    # whose operator signed in with their own ELK account (``operator``)
    needs_operator: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    operator: Mapped[str | None] = mapped_column(Text)
    held: Mapped[str | None] = mapped_column(Text)  # waits for something (DQ11: F1's audit)

    __table_args__ = (
        CheckConstraint("status IN ('acknowledged', 'closed')", name="status_valid"),
        CheckConstraint("state IN ('planned', 'sent', 'paused', 'skipped')", name="state_valid"),
        CheckConstraint(
            "sent_count BETWEEN 0 AND cardinality(alert_ids)", name="sent_count_in_range"
        ),
        CheckConstraint("written_count BETWEEN 0 AND sent_count", name="written_count_in_range"),
        CheckConstraint(
            "(review_id IS NOT NULL AND investigation_id IS NOT NULL"
            " AND closure_request_id IS NULL AND case_id IS NULL)"
            " OR (review_id IS NULL AND investigation_id IS NULL"
            " AND closure_request_id IS NOT NULL AND case_id IS NOT NULL)",
            name="source_valid",
        ),
        CheckConstraint("held IS NULL OR held = 'f1_zeros'", name="held_valid"),
        CheckConstraint("jsonb_typeof(previous) = 'object'", name="previous_object"),
        CheckConstraint(
            "NOT needs_operator OR sent_count = 0 OR operator IS NOT NULL",
            name="operator_named",
        ),
    )


# --------------------------------------------------------------------------- gold set (P2)
GOLD_SPLITS = ("dev", "test")


class GoldItem(Base):
    """An investigation of a frozen gold set (P2, D-080): the dossier it was chosen at, why,
    and the pre-filled suggestion shown to the person (never the answer)."""

    __tablename__ = "gold_items"

    set_name: Mapped[str] = mapped_column(Text, primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    pack: Mapped[str] = mapped_column(Text, nullable=False)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str] = mapped_column(Text, nullable=False)
    split: Mapped[str] = mapped_column(Text, nullable=False)
    why: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    suggestion: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("split", GOLD_SPLITS), name="split_valid"),
        CheckConstraint("dossier_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        Index(None, "investigation_id"),  # the purge's holds and key checks (0030)
    )


class GoldLabel(Base):
    """A person's answer for a gold item; append-only, the newest counts (a correction never
    erases what was answered before)."""

    __tablename__ = "gold_labels"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    set_name: Mapped[str] = mapped_column(Text, nullable=False)
    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        ForeignKeyConstraint(
            ["set_name", "investigation_id"],
            ["gold_items.set_name", "gold_items.investigation_id"],
        ),
        CheckConstraint(_one_of("outcome", OUTCOMES), name="outcome_valid"),
        CheckConstraint("note IS NULL OR length(note) <= 4000", name="note_length"),
        Index(None, "set_name", "investigation_id", "id"),
    )


# --------------------------------------------------------------------------- assessments (P3)
ASSESSMENT_STATUSES = ("queued", "running", "proposed", "no_decision", "failed")


class Assessment(Base):
    """A proposed outcome for one investigation, by one assessor, from one exact view of its
    dossier (P3, D-084): queue and result in one row. Keyed by the view's hash, so a
    re-derivation that changes nothing the assessor reads is never assessed again. A claim
    is a lease with a fencing number (as ``jobs``, D-051); waiting for a model's budget gives
    the lease back."""

    __tablename__ = "assessments"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    pack: Mapped[str] = mapped_column(Text, nullable=False)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    view_hash: Mapped[str] = mapped_column(Text, nullable=False)
    assessor: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="queued")
    run_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    claims: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    lease_owner: Mapped[str | None] = mapped_column(Text)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failures: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    deferrals: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    # 1: a person asked for it (D-097): claimed before what waits, deferred or not
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Double)
    decided_by: Mapped[str | None] = mapped_column(Text)
    reasons: Mapped[list[Any] | None] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("status", ASSESSMENT_STATUSES), name="status_valid"),
        CheckConstraint(f"outcome IS NULL OR {_one_of('outcome', OUTCOMES)}", name="outcome_valid"),
        CheckConstraint(
            "(status = 'proposed') = (outcome IS NOT NULL)", name="proposal_has_outcome"
        ),
        CheckConstraint(
            "confidence IS NULL OR confidence BETWEEN 0 AND 1", name="confidence_range"
        ),
        CheckConstraint("claims >= 0 AND failures >= 0 AND deferrals >= 0", name="non_negative"),
        CheckConstraint("view_hash ~ '^[0-9a-f]{64}$'", name="view_hash_valid"),
        CheckConstraint("priority IN (0, 1)", name="priority_valid"),
        Index(None, "investigation_id", "view_hash", "assessor", unique=True),
        Index(None, "status", "run_after"),
        Index(None, "investigation_id", "assessor", "id"),
    )


class AssessmentShare(Base):
    """An investigation an investigator run stands for (AR2, D-160): the run's own
    investigation and each other investigation of the same pattern (``display.signature``,
    the Patterns page's key) and IST day, which show the run as "same pattern as ...". Display
    only: the run's outcome, score, closure and write-back stay with the assessed
    investigation, so nothing here is ever a proposal for the others."""

    __tablename__ = "assessment_shares"

    assessment_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("assessments.id", ondelete="CASCADE"), primary_key=True
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),  # the retention purge removes it
        primary_key=True,
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    pattern: Mapped[str] = mapped_column(Text, nullable=False)  # sha256 of the pattern's key
    day: Mapped[date] = mapped_column(Date, nullable=False)  # the IST day of the bucket

    __table_args__ = (
        CheckConstraint("pattern ~ '^[0-9a-f]{64}$'", name="pattern_valid"),
        CheckConstraint("version >= 0", name="version_valid"),
        Index(None, "pattern", "day"),
        Index(None, "investigation_id", "version"),
    )


class InvestigationRaise(Base):
    """What ARGUS's evidence flagged on an investigation's newest dossier (AR2b, D-160): the
    generic flags of ``evaluation.gold.flags`` (a threat-list hit, success after an attack, a
    beacon-like regularity, risky ports). One row per investigation, replaced when a newer dossier
    is read; a row with no flags records that the dossier was read. An unreviewed investigation
    with flags is in Needs attention whatever its severity."""

    __tablename__ = "investigation_raises"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),  # the retention purge removes it
        primary_key=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    flags: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, server_default="[]")
    evaluated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("jsonb_typeof(flags) = 'array'", name="flags_is_array"),
        CheckConstraint("version >= 0", name="version_valid"),
    )


class OutsideLookup(Base):
    """An outside threat-intel answer (AR3, D-165): what VirusTotal, Shodan or Censys said of one
    external indicator, parsed and size-capped (never the raw reply), valid for
    ``outside.cache_window``. Only external indicators get a row. ``not_found``: the source has no
    record of it (cached too, so a miss is not asked again)."""

    __tablename__ = "outside_lookups"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    indicator: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    answer: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    answer_bytes: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("source IN ('virustotal', 'shodan', 'censys')", name="source_valid"),
        CheckConstraint("kind IN ('ip', 'domain', 'url', 'hash')", name="kind_valid"),
        CheckConstraint("status IN ('found', 'not_found')", name="status_valid"),
        CheckConstraint("char_length(indicator) BETWEEN 1 AND 2048", name="indicator_length"),
        CheckConstraint("jsonb_typeof(answer) = 'object'", name="answer_is_object"),
        CheckConstraint("answer_bytes >= 0", name="bytes_valid"),
        Index(None, "fetched_at"),
        Index(None, "kind", "indicator"),
    )


class OutsideRequest(Base):
    """The outside-intel ledger (AR3, D-165): one row per request made, with the purpose that
    asked, the outcome, the HTTP status, the answer's size and, for a 429, until when the source
    is stopped. Never the key and never the indicator. The limits are counted from it."""

    __tablename__ = "outside_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    source: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    answer_bytes: Mapped[int | None] = mapped_column(Integer)
    stopped_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("source IN ('virustotal', 'shodan', 'censys')", name="source_valid"),
        CheckConstraint("kind IN ('ip', 'domain', 'url', 'hash')", name="kind_valid"),
        CheckConstraint("purpose IN ('agent', 'prefetch', 'families')", name="purpose_valid"),
        CheckConstraint(
            "outcome IN ('reserved', 'ok', 'not_found', 'limited', 'error')", name="outcome_valid"
        ),
        CheckConstraint("answer_bytes IS NULL OR answer_bytes >= 0", name="bytes_valid"),
        Index(None, "source", "at"),
    )


class LlmState(Base):
    """The LLM gateway's shared state (P5, D-086): budgets, cool-downs, breakers, the kill
    switch, as JSON in one row."""

    __tablename__ = "llm_state"

    name: Mapped[str] = mapped_column(Text, primary_key=True)
    state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("name = 'gateway'", name="name_valid"),
        CheckConstraint("jsonb_typeof(state) = 'object'", name="state_is_object"),
    )


class LlmCall(Base):
    """The LLM ledger: every attempt at a provider, what it cost. Never the content."""

    __tablename__ = "llm_calls"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    call_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    tier: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Double, nullable=False)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    request_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    request_sha256: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(
            "attempt >= 0 AND input_tokens >= 0 AND output_tokens >= 0 AND cost_usd >= 0"
            " AND latency_ms >= 0 AND request_bytes >= 0",
            name="non_negative",
        ),
        CheckConstraint("request_sha256 ~ '^([0-9a-f]{64})?$'", name="sha_valid"),
        Index(None, "at"),
        Index(None, "call_id"),
    )


SHADOW_TASKS = ("extract", "triage", "summary", "notes", "fallback")


class LlmShadow(Base):
    """A model's answer to a live item in shadow (Q-G2, plan §7.4): stored for the evaluation
    ladder, never shown (no page, no API, no grant to the web's role) and never revealed (the
    answer stays pseudonymized: the pseudonyms' values are not kept)."""

    __tablename__ = "llm_shadow"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    pack: Mapped[str] = mapped_column(Text, nullable=False)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    task: Mapped[str] = mapped_column(Text, nullable=False)
    prompt: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    usable: Mapped[bool] = mapped_column(Boolean, nullable=False)
    ok: Mapped[bool | None] = mapped_column(Boolean)
    outcome: Mapped[str | None] = mapped_column(Text)
    floor: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reference: Mapped[str | None] = mapped_column(Text)  # production's outcome then, if any
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    answer: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    lease_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    output_tokens: Mapped[int] = mapped_column(Integer, nullable=False)

    __table_args__ = (
        CheckConstraint(_one_of("task", SHADOW_TASKS), name="task_valid"),
        CheckConstraint("dossier_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint(
            "latency_ms >= 0 AND lease_ms >= 0 AND input_tokens >= 0 AND output_tokens >= 0",
            name="non_negative",
        ),
        CheckConstraint("jsonb_typeof(detail) = 'object'", name="detail_is_object"),
        CheckConstraint(
            "answer IS NULL OR (jsonb_typeof(answer) = 'object' AND length(answer::text) <= 20000)",
            name="answer_valid",
        ),
        CheckConstraint("usable OR (ok IS NULL AND answer IS NULL)", name="unusable_is_empty"),
        Index(
            None,
            "investigation_id",
            "dossier_hash",
            "task",
            "prompt",
            "provider",
            "model",
            unique=True,
        ),
        Index(None, "provider", "model", "task", "at"),
    )


class TuningReport(Base):
    """A rule's weekly tuning report (P7, D-090): the numbers, and the suggestions drafted
    for a person (kept only with evidence). ARGUS never edits a rule."""

    __tablename__ = "tuning_reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    rule: Mapped[str] = mapped_column(Text, nullable=False)
    week_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    suggestions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    dropped: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    cost_usd: Mapped[float] = mapped_column(Double, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("jsonb_typeof(report) = 'object'", name="report_is_object"),
        CheckConstraint(
            "jsonb_typeof(suggestions) = 'array' AND jsonb_typeof(dropped) = 'array'",
            name="lists_are_arrays",
        ),
        CheckConstraint("cost_usd >= 0", name="cost_non_negative"),
        Index(None, "rule", "week_end", unique=True),
    )


# --------------------------------------------------------------------------- cases (Q-C1)
# Plan §7.1 and §7.9 (Phase 3): ARGUS's case record is the system of record; Kibana is a verified
# mirror fed by an outbox. Words (DQ23): an *investigation* is one rule, actor and IST day; a
# *case* is one real problem across days, hosts and rules; an *incident* is a confirmed case.
CASE_STATES = ("suspected", "open", "assigned", "contained", "closed")
CASE_SEVERITIES = ("low", "medium", "high", "critical")
CASE_CAUSES = ("verdict", "proposal", "person", "watch", "raised")
CLOSURE_REASONS = (
    "remediated_verified",
    "remediated_unverified",
    "risk_accepted",
    "attempt_no_impact",
    "rule_false_positive",
    "benign_expected",
    "benign_policy",
    "duplicate",
    "created_in_error",
    "stopped_after_notice",
)
CASE_EVENT_KINDS = (
    "suspected",
    "opened",
    "confirmed",
    "dismissed",
    "taken",
    "assigned",
    "released",
    "contained",
    "new_activity",
    "activity_after_closure",
    "linked",
    "notified",
    "blocked",
    "address_moved",
    "notice_withdrawn",
    "unlinked",
    "retitled",
    "published",
    "closure_requested",
    "merge_requested",
    "closed",
    "merged_into",
    "merged_in",
    "reopened",
)
MEMBER_LINKS = ("verdict", "proposal", "actor", "indicator", "c2", "person", "merge")
INDICATOR_KINDS = ("ip", "domain", "host", "user", "url", "hash")
INDICATOR_ROLES = ("actor", "c2", "indicator")
INDICATOR_SOURCES = ("investigation", "threat_intel", "person", "merge")
APPROVAL_KINDS = ("closure", "merge", "compensating", "resend", "reconfirm")
APPROVAL_DECISIONS = ("approved", "rejected")
WRITE_CLASSES = ("W1", "W2", "W3")
OUTBOX_OPS = ("create", "update", "comment", "close")
OUTBOX_STATES = (
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
OPENING_SOURCES = ("review", "assessment")
OPENING_DECISIONS = ("opened", "suspected", "linked", "member_already", "attempt")
LEDGER_OUTCOMES = ("sent", "ambiguous", "conflict", "refused", "failed")
CHAIN_NAMES = ("audit_events", "case_events")
_HEX64 = "'^[0-9a-f]{64}$'"


class ChainHead(Base):
    """Where each hash chain (audit_events, case_events) stands: the rows chained so far and the
    newest row's hash. Written only by the owner's chain trigger; ``genesis_hash`` seals the rows
    written before the chain started (``legacy_rows`` of them, ids up to ``legacy_max_id``)."""

    __tablename__ = "chain_heads"

    chain: Mapped[str] = mapped_column(Text, primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger, nullable=False)
    head_hash: Mapped[str] = mapped_column(Text, nullable=False)
    genesis_hash: Mapped[str] = mapped_column(Text, nullable=False)
    legacy_rows: Mapped[int] = mapped_column(BigInteger, nullable=False)
    legacy_max_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("chain", CHAIN_NAMES), name="chain_valid"),
        CheckConstraint(
            "seq >= 0 AND legacy_rows >= 0 AND legacy_max_id >= 0", name="non_negative"
        ),
        CheckConstraint(f"head_hash ~ {_HEX64} AND genesis_hash ~ {_HEX64}", name="hashes_valid"),
    )


class Case(Base):
    """One real-world problem (plan §7.1): its state, owner and version. Every change raises
    ``version`` by one and writes exactly one ``case_events`` row with that version (a database
    trigger checks both, and a confirmed case closes only with a valid approval)."""

    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    number: Mapped[int] = mapped_column(
        BigInteger, Identity(always=True), nullable=False, unique=True
    )
    title: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    owner_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    cause: Mapped[str] = mapped_column(Text, nullable=False)
    cause_review_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("review_events.id"))
    cause_assessment_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("assessments.id")
    )
    parent_case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id")
    )
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closure_reason: Mapped[str | None] = mapped_column(Text)
    closure_request_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id", use_alter=True)
    )
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id")
    )
    attention: Mapped[str | None] = mapped_column(Text)
    kibana_wait: Mapped[str | None] = mapped_column(Text)
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    blocked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("state", CASE_STATES), name="state_valid"),
        CheckConstraint(_one_of("severity", CASE_SEVERITIES), name="severity_valid"),
        CheckConstraint(_one_of("cause", CASE_CAUSES), name="cause_valid"),
        CheckConstraint(
            f"closure_reason IS NULL OR {_one_of('closure_reason', CLOSURE_REASONS)}",
            name="closure_reason_valid",
        ),
        CheckConstraint("version >= 1", name="version_valid"),
        CheckConstraint("length(title) BETWEEN 1 AND 200", name="title_length"),
        CheckConstraint("title !~ '[\\x01-\\x1f\\x7f-\\x9f]'", name="title_printable"),
        CheckConstraint(
            "(state = 'closed') = (closed_at IS NOT NULL)"
            " AND (state = 'closed') = (closure_reason IS NOT NULL)",
            name="closed_has_reason",
        ),
        CheckConstraint(
            "(state <> 'suspected' OR opened_at IS NULL)"
            " AND (state NOT IN ('open', 'assigned', 'contained') OR opened_at IS NOT NULL)",
            name="confirmed_states",
        ),
        CheckConstraint(
            "(state <> 'closed' OR opened_at IS NULL OR closure_request_id IS NOT NULL)"
            " AND (closure_request_id IS NULL OR state = 'closed')",
            name="confirmed_closes_by_approval",
        ),
        CheckConstraint(
            "(state <> 'assigned' OR owner_user_id IS NOT NULL)"
            " AND (state NOT IN ('suspected', 'open') OR owner_user_id IS NULL)",
            name="owner_valid",
        ),
        CheckConstraint(
            "merged_into_id IS NULL OR (state = 'closed' AND closure_reason = 'duplicate'"
            " AND merged_into_id <> id)",
            name="merge_valid",
        ),
        CheckConstraint(
            "notified_at IS NULL OR (state IN ('open', 'assigned') AND opened_at IS NOT NULL)",
            name="notified_valid",
        ),
        CheckConstraint(
            "blocked_at IS NULL OR (state IN ('open', 'assigned', 'contained')"
            " AND opened_at IS NOT NULL)",
            name="blocked_valid",
        ),
        CheckConstraint(
            "(cause = 'verdict') = (cause_review_id IS NOT NULL)"
            " AND (cause = 'proposal') = (cause_assessment_id IS NOT NULL)",
            name="cause_reference",
        ),
        CheckConstraint(
            "(attention IS NULL OR length(attention) <= 500)"
            " AND (kibana_wait IS NULL OR length(kibana_wait) <= 500)",
            name="notes_length",
        ),
        Index(None, "state", "updated_at"),
        Index(None, "parent_case_id"),
        Index(
            "uq_cases_cause_review_id",
            "cause_review_id",
            unique=True,
            postgresql_where=text("cause_review_id IS NOT NULL"),
        ),
    )


class CaseMember(Base):
    """An investigation in a case, and why (DQ4: a verdict, an actor, an indicator, a C2, a
    person; never model similarity). An investigation is in at most one case at a time."""

    __tablename__ = "case_members"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), primary_key=True
    )
    link: Mapped[str] = mapped_column(Text, nullable=False)
    link_value: Mapped[str | None] = mapped_column(Text)
    added_version: Mapped[int] = mapped_column(Integer, nullable=False)
    added_by: Mapped[str] = mapped_column(Text, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    removed_version: Mapped[int | None] = mapped_column(Integer)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("link", MEMBER_LINKS), name="link_valid"),
        CheckConstraint(
            "(removed_at IS NULL) = (removed_version IS NULL)"
            " AND (removed_version IS NULL OR removed_version > added_version)",
            name="removal_valid",
        ),
        CheckConstraint("link_value IS NULL OR length(link_value) <= 512", name="value_length"),
        Index(
            "uq_case_members_active_investigation",
            "investigation_id",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
    )


class CaseIndicator(Base):
    """What links new activity to a case: its actors (campus hosts, users, attackers), its C2
    destinations and other indicators."""

    __tablename__ = "case_indicators"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    added_version: Mapped[int] = mapped_column(Integer, nullable=False)
    added_by: Mapped[str] = mapped_column(Text, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    removed_version: Mapped[int | None] = mapped_column(Integer)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("kind", INDICATOR_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("role", INDICATOR_ROLES), name="role_valid"),
        CheckConstraint(_one_of("source", INDICATOR_SOURCES), name="source_valid"),
        CheckConstraint("length(value) BETWEEN 1 AND 512", name="value_length"),
        CheckConstraint(
            "(removed_at IS NULL) = (removed_version IS NULL)"
            " AND (removed_version IS NULL OR removed_version > added_version)",
            name="removal_valid",
        ),
        Index(None, "kind", "value"),
    )


class CaseEvent(Base):
    """What happened to a case, one row per version (append-only, hash-chained). ``details``
    holds everything the change set, so replaying the events rebuilds the case;
    ``kibana_rows`` is how many outbox rows were planned with it (checked at commit)."""

    __tablename__ = "case_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    actor_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    from_state: Mapped[str | None] = mapped_column(Text)
    to_state: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    kibana_rows: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    chain_seq: Mapped[int | None] = mapped_column(BigInteger, server_default=FetchedValue())
    prev_hash: Mapped[str | None] = mapped_column(Text, server_default=FetchedValue())
    row_hash: Mapped[str | None] = mapped_column(Text, server_default=FetchedValue())

    __table_args__ = (
        UniqueConstraint("case_id", "case_version"),
        CheckConstraint(_one_of("kind", CASE_EVENT_KINDS), name="kind_valid"),
        CheckConstraint(
            f"(from_state IS NULL OR {_one_of('from_state', CASE_STATES)})"
            f" AND {_one_of('to_state', CASE_STATES)}",
            name="states_valid",
        ),
        CheckConstraint("case_version >= 1 AND kibana_rows BETWEEN 0 AND 10", name="counts"),
        CheckConstraint(
            "(kind IN ('suspected', 'opened')) = (from_state IS NULL)"
            " AND (kind IN ('closed', 'dismissed', 'merged_into'))"
            " = (to_state = 'closed' AND from_state IS DISTINCT FROM 'closed')"
            " AND (kind = 'reopened')"
            " = (from_state IS NOT DISTINCT FROM 'closed' AND to_state <> 'closed')",
            name="kind_states",
        ),
        CheckConstraint("jsonb_typeof(details) = 'object'", name="details_is_object"),
        CheckConstraint("actor ~ '^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}$'", name="actor_valid"),
        CheckConstraint(
            "(chain_seq IS NULL) = (row_hash IS NULL)"
            " AND (chain_seq IS NULL) = (prev_hash IS NULL)",
            name="chain_complete",
        ),
        Index(None, "chain_seq", unique=True, postgresql_where=text("chain_seq IS NOT NULL")),
    )


class CaseNote(Base):
    """A person's note on a case: for people only, never sent to a model (plan Q-B3)."""

    __tablename__ = "case_notes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    author_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("length(body) BETWEEN 1 AND 4000", name="body_length"),
        Index(None, "case_id", "id"),
    )


class EntityNote(Base):
    """A person's note on an IP, domain, host or user (D-025): for people only, never sent to a
    model."""

    __tablename__ = "entity_notes"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    author_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("kind IN ('ip', 'domain', 'host', 'user')", name="kind_valid"),
        CheckConstraint("length(value) BETWEEN 1 AND 512", name="value_length"),
        CheckConstraint("length(body) BETWEEN 1 AND 4000", name="body_length"),
        Index(None, "kind", "value", "id"),
    )


class CaseOpening(Base):
    """What the case opener (DQ4) decided for one true-positive verdict or proposal: once."""

    __tablename__ = "case_openings"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    source_id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    reasons: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    decided_by: Mapped[str] = mapped_column(Text, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("source", OPENING_SOURCES), name="source_valid"),
        CheckConstraint(_one_of("decision", OPENING_DECISIONS), name="decision_valid"),
        CheckConstraint("(decision = 'attempt') = (case_id IS NULL)", name="case_given"),
        CheckConstraint("jsonb_typeof(reasons) = 'array'", name="reasons_is_array"),
        Index(None, "case_id"),
        Index(None, "decided_at"),
    )


WATCH_SOURCES = ("alerts", "proxy.contact", "proxy.pair")
WATCH_OUTCOMES = ("active", "quiet", "unverified", "not_checked")
SUGGESTION_KINDS = ("shared", "tie", "also")


class CaseWatchCheck(Base):
    """One answer of the still-active watch (Q-C2, plan §7.1): was a case's activity seen on a
    UTC day, by ARGUS's own alerts (``alerts``, local) or in the proxy logs (``proxy.contact``,
    ``proxy.pair``; one request per member address and daily index). ``active``: activity was
    seen; ``quiet``: none, and the zero is verified (the collector's coverage, or Q-F1's
    verified zero for logs); ``unverified``: none seen but it cannot be vouched for (final for
    that day); ``not_checked``: nothing was asked or the question did not finish (the reason is
    shown, and the next run asks again). A row is decided once: only a ``not_checked`` row may
    be replaced (a trigger holds it). ``requests`` counts SIEM requests sent for it on
    ``asked_on`` (at most 6 a case a day)."""

    __tablename__ = "case_watch_checks"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    day: Mapped[date] = mapped_column(Date, nullable=False)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    part: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    asked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    asked_on: Mapped[date | None] = mapped_column(Date)
    requests: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")
    attempts: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="1")
    detail: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    checked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("case_id", "day", "source", "subject", "part"),
        CheckConstraint(_one_of("source", WATCH_SOURCES), name="source_valid"),
        CheckConstraint(_one_of("outcome", WATCH_OUTCOMES), name="outcome_valid"),
        CheckConstraint("window_start < window_end", name="window_valid"),
        CheckConstraint("reason IS NULL OR length(reason) <= 300", name="reason_length"),
        CheckConstraint(
            "outcome IN ('active', 'quiet') OR reason IS NOT NULL", name="reason_given"
        ),
        CheckConstraint("requests BETWEEN 0 AND 20", name="requests_valid"),
        CheckConstraint("(requests = 0) = (asked_on IS NULL)", name="requests_have_a_day"),
        CheckConstraint("(source = 'alerts') = (subject = '')", name="alerts_have_no_subject"),
        CheckConstraint("source <> 'alerts' OR requests = 0", name="alerts_are_local"),
        CheckConstraint("attempts BETWEEN 1 AND 10000", name="attempts_valid"),
        CheckConstraint("jsonb_typeof(detail) = 'object'", name="detail_is_object"),
        Index(None, "case_id", "day"),
        Index(None, "asked_on", "case_id"),
    )


class CaseSuggestion(Base):
    """An investigation that may belong to a case but is not joined (Q-C2, plan §5): its only
    match is through a shared address or name (a content-delivery or cloud network, or a value
    in very many unrelated investigations: ``shared``), or it matches several cases equally
    (``tie``), or a case it matches is not the strongest it matches (``also``). A person joins
    it with ``argus case link``, or dismisses the suggestion."""

    __tablename__ = "case_suggestions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),  # the retention purge removes it
        nullable=False,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    link: Mapped[str] = mapped_column(Text, nullable=False)
    link_value: Mapped[str | None] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))

    __table_args__ = (
        UniqueConstraint("investigation_id", "case_id"),
        CheckConstraint("link IN ('actor', 'c2', 'indicator')", name="link_valid"),
        CheckConstraint(_one_of("kind", SUGGESTION_KINDS), name="kind_valid"),
        CheckConstraint("link_value IS NULL OR length(link_value) <= 512", name="value_length"),
        CheckConstraint("length(why) BETWEEN 1 AND 300", name="why_length"),
        CheckConstraint(
            "(dismissed_at IS NULL) = (dismissed_by IS NULL)", name="dismissal_complete"
        ),
        Index(None, "case_id"),
    )


CASE_NOTICE_KINDS = ("owner", "block")
CASE_NOTICE_HOWS = ("email", "phone", "in_person", "through_it", "other")
KNOWN_OUTCOMES = ("known", "changed")
KNOWN_KEY_KINDS = ("seed", "flag", "destination", "family", "service", "bytes", "new_destination")
KNOWN_KEY_SOURCES = ("notice", "change")
REMINDER_KINDS = ("notify_again", "network_action")


class CaseNotice(Base):
    """What a person recorded about a case whose device keeps alerting after a true positive
    (AR4b, D-169): ``owner``: who was told (``told``: the owner, a department, a hostel, a lab),
    when (``at``), how (``how``) and whether the machines are campus-managed; ``block``: who put
    a network-side block on the case's servers or domains (``told``), where (``how``: DNS,
    firewall, proxy) and when. Append-only; ``case_version`` is the case event that records it."""

    __tablename__ = "case_notices"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    told: Mapped[str] = mapped_column(Text, nullable=False)
    how: Mapped[str] = mapped_column(Text, nullable=False)
    managed: Mapped[bool | None] = mapped_column(Boolean)
    note: Mapped[str | None] = mapped_column(Text)
    by_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("case_id", "case_version"),
        CheckConstraint(_one_of("kind", CASE_NOTICE_KINDS), name="kind_valid"),
        CheckConstraint("length(told) BETWEEN 1 AND 200", name="told_length"),
        CheckConstraint("length(how) BETWEEN 1 AND 100", name="how_length"),
        CheckConstraint(f"kind <> 'owner' OR {_one_of('how', CASE_NOTICE_HOWS)}", name="how_valid"),
        CheckConstraint("(kind = 'owner') = (managed IS NOT NULL)", name="managed_valid"),
        CheckConstraint("note IS NULL OR length(note) <= 4000", name="note_length"),
        CheckConstraint("case_version >= 2", name="version_valid"),
        Index(None, "case_id", "kind", "at"),
    )


class CaseKnownMatch(Base):
    """What ARGUS decided about one investigation of a notified case's device at one version of
    it (AR4b, D-169, D-176): ``known`` (it belongs to the known infection, so it is counted and
    kept out of Needs attention and the AI queue) or ``changed`` (something is new since the
    notice; ``why`` says what, and it is in Needs attention). One row for each investigation,
    replaced as the investigation gets a new version; removed with it by the retention purge.
    A change is durable (0051, D-181): ``changed_version`` is the version at which it was decided,
    and the row stays ``changed`` (its ``why`` kept, a later change adding its own) until a person
    reviews a version at or after it."""

    __tablename__ = "case_known_matches"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("investigations.id", ondelete="CASCADE"),
        primary_key=True,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    why: Mapped[str | None] = mapped_column(Text)
    changed_version: Mapped[int | None] = mapped_column(Integer)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("outcome", KNOWN_OUTCOMES), name="outcome_valid"),
        CheckConstraint(
            "(outcome = 'changed') = (why IS NOT NULL) AND (why IS NULL OR length(why) <= 500)",
            name="why_valid",
        ),
        CheckConstraint(
            "(outcome = 'changed') = (changed_version IS NOT NULL)"
            " AND (changed_version IS NULL OR changed_version >= 0)",
            name="changed_version_valid",
        ),
        CheckConstraint("version >= 0", name="version_valid"),
        Index(None, "case_id", "outcome"),
    )


class CaseKnownKey(Base):
    """A thing the known infection of a notified case already includes beyond the case's own
    devices and indicators (AR4b, D-169): an evidence flag, a destination, a domain family, a
    university service, the data volume (``bytes``), or the ``seed`` that says the first set was
    taken. ``source``: the notice, or a change that was raised once and is now known."""

    __tablename__ = "case_known_keys"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    kind: Mapped[str] = mapped_column(Text, primary_key=True)
    value: Mapped[str] = mapped_column(Text, primary_key=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("kind", KNOWN_KEY_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("source", KNOWN_KEY_SOURCES), name="source_valid"),
        CheckConstraint("length(value) <= 512", name="value_length"),
    )


class CaseReminder(Base):
    """ARGUS's suggestion for a notified case that stays active (AR4b, D-169): notify the owner
    again (7 days after the notice), or ask for network-side action (21 days). Shown on the case,
    never an alarm; one of each kind for a case; a person dismisses one."""

    __tablename__ = "case_reminders"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    why: Mapped[str] = mapped_column(Text, nullable=False)
    suggested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    dismissed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dismissed_by: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))

    __table_args__ = (
        UniqueConstraint("case_id", "kind"),
        CheckConstraint(_one_of("kind", REMINDER_KINDS), name="kind_valid"),
        CheckConstraint("length(why) BETWEEN 1 AND 300", name="why_length"),
        CheckConstraint(
            "(dismissed_at IS NULL) = (dismissed_by IS NULL)", name="dismissal_complete"
        ),
    )


ACTION_STATES = ("recommended", "requested", "reported_done", "verified", "not_verified")


class CaseAction(Base):
    """What was advised, asked and done about a case (Q-H2, plan §7.7): one row for each
    (case, catalogue action). ``recommended`` is ARGUS's advice; ``requested`` and
    ``reported_done`` are a person's (``user:<id>``; "done" is an attestation, ARGUS cannot see
    the action and nothing is executed before Phase 6); ``verified`` and ``not_verified`` are
    ARGUS's own answer from the still-active watch (``last_beat``: the newest sign of activity
    after the action). The guard trigger holds the edges, the identity of a row and what the
    web's login may write."""

    __tablename__ = "case_actions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    family: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(Text, nullable=False)
    catalogue_version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)
    recommended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recommended_by: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_by: Mapped[str | None] = mapped_column(Text)
    reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reported_by: Mapped[str | None] = mapped_column(Text)
    attestation: Mapped[str | None] = mapped_column(Text)
    verdict_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verdict: Mapped[str | None] = mapped_column(Text)
    last_beat: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("case_id", "action"),
        CheckConstraint(_one_of("state", ACTION_STATES), name="state_valid"),
        CheckConstraint(
            "action ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_]*$' AND length(action) <= 80",
            name="action_valid",
        ),
        CheckConstraint(
            "family ~ '^[a-z][a-z0-9_]*$' AND owner ~ '^[a-z][a-z0-9_]*$'"
            " AND length(family) <= 60 AND length(owner) <= 60",
            name="names_valid",
        ),
        CheckConstraint("catalogue_version >= 1", name="catalogue_version_valid"),
        CheckConstraint(
            "recommended_by IS NULL OR recommended_by = 'argus:responder'",
            name="recommended_by_argus",
        ),
        CheckConstraint(
            "(requested_by IS NULL OR requested_by ~ '^user:[1-9][0-9]{0,17}$')"
            " AND (reported_by IS NULL OR reported_by ~ '^user:[1-9][0-9]{0,17}$')",
            name="people_are_users",
        ),
        CheckConstraint(
            "(recommended_at IS NULL) = (recommended_by IS NULL)"
            " AND (requested_at IS NULL) = (requested_by IS NULL)"
            " AND (reported_at IS NULL) = (reported_by IS NULL)"
            " AND (reported_at IS NULL) = (attestation IS NULL)"
            " AND (verdict_at IS NULL) = (verdict IS NULL)",
            name="pairs_complete",
        ),
        CheckConstraint(
            "state <> 'recommended' OR recommended_at IS NOT NULL", name="recommended_is_recorded"
        ),
        CheckConstraint(
            "state <> 'requested' OR requested_at IS NOT NULL", name="requested_is_recorded"
        ),
        CheckConstraint(
            "state NOT IN ('reported_done', 'verified', 'not_verified') OR reported_at IS NOT NULL",
            name="done_is_recorded",
        ),
        CheckConstraint(
            "(state IN ('verified', 'not_verified')) = (verdict_at IS NOT NULL)",
            name="verdict_is_recorded",
        ),
        CheckConstraint(
            "last_beat IS NULL OR state = 'not_verified'", name="last_beat_means_not_verified"
        ),
        CheckConstraint(
            "attestation IS NULL OR length(attestation) BETWEEN 1 AND 500",
            name="attestation_length",
        ),
        CheckConstraint(
            "verdict IS NULL OR length(verdict) BETWEEN 1 AND 300", name="verdict_length"
        ),
        Index(None, "state"),
    )


class ApprovalRequest(Base):
    """A closure, merge, compensating write or resend waiting for people (plan §7.1), bound to
    the case and its version, the payload, the alert set (count and sha256 of the sorted ids,
    computed by the database from the members) and the Kibana version seen. Inserted
    only through ``argus_approval_request()`` (``argus_approvals`` may call it; ARGUS's runtime
    role may not); append-only."""

    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    target_case_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id")
    )
    outbox_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("kibana_outbox.id"))
    outbox_sent_count: Mapped[int | None] = mapped_column(Integer)  # a resend: asked after send n
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(Text, nullable=False)
    alert_count: Mapped[int] = mapped_column(BigInteger, nullable=False)
    alert_digest: Mapped[str] = mapped_column(Text, nullable=False)
    kibana_version: Mapped[str | None] = mapped_column(Text)
    required_approvals: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    # a person's request, or ARGUS's own proposal or re-confirmation (``argus:<part>``, 0030)
    requested_by_user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    proposed_by: Mapped[str | None] = mapped_column(Text)
    # the requester's live check when they asked (0030, review F2): one person behind two
    # accounts never approves their own request
    requester_check: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(_one_of("kind", APPROVAL_KINDS), name="kind_valid"),
        CheckConstraint(
            f"reason IS NULL OR {_one_of('reason', CLOSURE_REASONS)}", name="reason_valid"
        ),
        CheckConstraint(
            "(kind IN ('closure', 'merge')) = (reason IS NOT NULL)"
            " AND (kind <> 'closure' OR reason <> 'duplicate')"
            " AND (kind = 'merge') = (target_case_id IS NOT NULL)"
            " AND (kind <> 'merge' OR reason = 'duplicate')"
            " AND (kind IN ('compensating', 'resend', 'reconfirm')) = (outbox_id IS NOT NULL)"
            " AND (kind = 'resend') = (outbox_sent_count IS NOT NULL)"
            " AND (kind <> 'reconfirm' OR proposed_by IS NOT NULL)",
            name="kind_fields",
        ),
        CheckConstraint(
            "(requested_by_user_id IS NULL) = (proposed_by IS NOT NULL)"
            " AND (proposed_by IS NULL OR proposed_by ~ '^argus:[a-z][a-z0-9_.-]{0,59}$')",
            name="requester_or_proposer",
        ),
        CheckConstraint(
            "requester_check IS NULL OR jsonb_typeof(requester_check) = 'object'",
            name="requester_check_is_object",
        ),
        CheckConstraint(f"alert_count >= 0 AND alert_digest ~ {_HEX64}", name="alert_set_valid"),
        CheckConstraint(f"payload_hash ~ {_HEX64}", name="payload_hash_valid"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_is_object"),
        CheckConstraint("required_approvals IN (1, 2)", name="required_valid"),
        CheckConstraint("case_version >= 1", name="version_valid"),
        CheckConstraint(
            "target_case_id IS NULL OR target_case_id <> case_id", name="target_not_self"
        ),
        CheckConstraint(
            "expires_at > requested_at AND expires_at <= requested_at + interval '72 hours'",
            name="expiry_valid",
        ),
        CheckConstraint("note IS NULL OR length(note) <= 4000", name="note_length"),
        Index(None, "case_id", "id"),
    )


class ApprovalDecision(Base):
    """One person's decision on an approval request, with the capabilities they held when they
    made it; append-only, one per person and request, inserted only through
    ``argus_approval_decide()``."""

    __tablename__ = "approval_decisions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    request_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id"), nullable=False
    )
    approver_user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    capabilities: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    stepped_up_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 0030 (Q-C3): the web's live check of the approver, its signature over the decision
    # (argus.cases.signing), and the group it approved with its sample
    identity_check: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    signature: Mapped[str | None] = mapped_column(Text)
    batch: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    note: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("request_id", "approver_user_id"),
        CheckConstraint(_one_of("decision", APPROVAL_DECISIONS), name="decision_valid"),
        CheckConstraint("jsonb_typeof(capabilities) = 'array'", name="capabilities_is_array"),
        CheckConstraint("note IS NULL OR length(note) <= 4000", name="note_length"),
        CheckConstraint(
            "(signature IS NULL) = (identity_check IS NULL)"
            " AND (signature IS NULL OR signature ~ '^hmac-sha256:[0-9a-f]{16}:[0-9a-f]{64}$')"
            " AND (identity_check IS NULL OR jsonb_typeof(identity_check) = 'object')"
            " AND (batch IS NULL OR jsonb_typeof(batch) = 'object')",
            name="signed_check",
        ),
    )


IDENTITY_OUTCOMES = ("ok", "denied", "unavailable")
IDENTITY_PURPOSES = ("signin", "recheck", "stepup", "request", "approval", "send")


class IdentityCheck(Base):
    """One check of a person against the identity source (plan §7.2; Q-E1's provider, a local
    one before it): its outcome and what it showed. Append-only, inserted only through
    ``argus_identity_record()`` and the decide function (0030). A denied check voids the
    person's earlier approvals; the newest good one dates their live check at send time."""

    __tablename__ = "identity_checks"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("clock_timestamp()"), nullable=False
    )
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        CheckConstraint(_one_of("outcome", IDENTITY_OUTCOMES), name="outcome_valid"),
        CheckConstraint(_one_of("purpose", IDENTITY_PURPOSES), name="purpose_valid"),
        CheckConstraint("provider ~ '^[a-z][a-z0-9_.-]{0,31}$'", name="provider_valid"),
        CheckConstraint("jsonb_typeof(snapshot) = 'object'", name="snapshot_is_object"),
        Index(None, "user_id", "recorded_at"),
    )


class KibanaOutboxItem(Base):
    """A planned change to a case's Kibana mirror (plan §3 rule 1), committed with the case
    change that caused it. Sent at most once without a person's approved resend; its state only
    moves along the outbox's edges (argus.cases.outbox, checked again by a trigger)."""

    __tablename__ = "kibana_outbox"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    case_event_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("case_events.id"), nullable=False
    )
    position: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    write_class: Mapped[str] = mapped_column(Text, nullable=False)
    op: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(Text, nullable=False)
    before_image: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    approval_request_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id", use_alter=True)
    )
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="planned")
    state_reason: Mapped[str | None] = mapped_column(Text)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    resends: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    kibana_case_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("case_event_id", "position"),
        CheckConstraint(_one_of("write_class", WRITE_CLASSES), name="class_valid"),
        CheckConstraint(_one_of("op", OUTBOX_OPS), name="op_valid"),
        CheckConstraint(_one_of("state", OUTBOX_STATES), name="state_valid"),
        CheckConstraint(
            "(op <> 'create' OR write_class = 'W1') AND (op <> 'close' OR write_class = 'W3')"
            " AND (write_class <> 'W3' OR approval_request_id IS NOT NULL)",
            name="class_rules",
        ),
        CheckConstraint(
            "sent_count >= 0 AND resends >= 0 AND sent_count <= 1 + resends",
            name="sent_at_most_once",
        ),
        CheckConstraint("position BETWEEN 0 AND 9", name="position_valid"),
        CheckConstraint(f"payload_hash ~ {_HEX64}", name="payload_hash_valid"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_is_object"),
        CheckConstraint("length(idempotency_key) BETWEEN 1 AND 200", name="key_length"),
        Index(None, "state", "id"),
        Index(None, "case_id", "id"),
        Index(
            "uq_kibana_outbox_w3_approval_position",
            "approval_request_id",
            "position",
            unique=True,
            postgresql_where=text("write_class = 'W3'"),
        ),
    )


class KibanaMirror(Base):
    """What ARGUS last read back of a case's Kibana mirror (written by the read-back and
    reconciliation, Q-D3); ``unmanaged`` lists fields a person edited there, which ARGUS no
    longer changes."""

    __tablename__ = "kibana_mirror"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    kibana_case_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    kibana_version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    sync_alerts: Mapped[bool] = mapped_column(Boolean, nullable=False)
    unmanaged: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default="{}")
    kibana_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kibana_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 0034 (Q-D3): how many of the case's user actions were read, and why ARGUS's writes to
    # the case are paused (a person changed ARGUS's tags or its settings); only the owner
    # lifts a pause (the trigger argus_mirror_resume_needs_owner)
    actions_seen: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    argus_actions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default="{}"
    )
    paused_reason: Mapped[str | None] = mapped_column(Text)
    # 0035: ARGUS's actions on the case that no sent write explained, by kind, already alarmed
    unexplained: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        CheckConstraint("status IN ('open', 'in-progress', 'closed')", name="status_valid"),
        CheckConstraint(_one_of("severity", CASE_SEVERITIES), name="severity_valid"),
        CheckConstraint("actions_seen >= 0", name="actions_seen_valid"),
    )


SYNC_OUTCOMES = ("complete", "partial", "failed")
FINDING_SEVERITIES = ("alarm", "attention", "info")
FINDING_KINDS = (
    "person_edited",
    "person_deleted",  # 0035
    "argus_tags_changed",
    "settings_changed",
    "person_commented",
    "closed_in_kibana",
    "reopened_in_kibana",
    "status_changed_in_kibana",
    "deleted_in_kibana",
    "people_case",
    "unexplained_argus_action",
    "unexplained_argus_case",
    "duplicate_case",
    "not_argus_case",
    "alert_change_unexplained",
    "alert_status_by_person",
    "clock_offset",
    "actions_rewound",
    "answer_unexpected",
)


class KibanaSyncState(Base):
    """The read-back's one row (Q-D3): where the change poll starts, the discovery's place in
    the known alerts, Kibana's clock offset and the last cycles."""

    __tablename__ = "kibana_sync_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True, autoincrement=False)
    changes_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_cycle_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_complete_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_discovery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_closed_listing_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discovery_cursor: Mapped[str | None] = mapped_column(Text)
    diff_cursor: Mapped[str | None] = mapped_column(Text)  # 0035: the alert-status diff's place
    alerts_checked_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    clock_offset_ms: Mapped[int | None] = mapped_column(Integer)
    clock_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (CheckConstraint("id = 1", name="one_row"),)


class KibanaSyncCycle(Base):
    """One read-back cycle (Q-D3): what it read, found and how it ended. Append-only for the
    runtime (it may insert, never change)."""

    __tablename__ = "kibana_sync_cycles"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    health: Mapped[str | None] = mapped_column(Text)
    reads: Mapped[int] = mapped_column(Integer, nullable=False)
    changed: Mapped[int] = mapped_column(Integer, nullable=False)
    findings: Mapped[int] = mapped_column(Integer, nullable=False)
    oldest_read_s: Mapped[int | None] = mapped_column(Integer)
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False)
    clock_offset_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")

    __table_args__ = (
        CheckConstraint(_one_of("outcome", SYNC_OUTCOMES), name="outcome_valid"),
        CheckConstraint("finished_at >= started_at", name="finished_after_start"),
        CheckConstraint("reads >= 0 AND changed >= 0 AND findings >= 0", name="counts_valid"),
        Index(None, "started_at"),
    )


class KibanaFinding(Base):
    """What the reconciliation found (plan §7.1): an alarm, an item that needs a person, or a
    note. Each once (``dedupe_key``); the runtime may insert, never change one; a person
    resolves it (Q-B3)."""

    __tablename__ = "kibana_findings"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    found_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    kibana_case_id: Mapped[str | None] = mapped_column(Text)
    case_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id"))
    dedupe_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    lag_s: Mapped[int | None] = mapped_column(Integer)
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default="{}")
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    resolved_by: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(_one_of("kind", FINDING_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("severity", FINDING_SEVERITIES), name="severity_valid"),
        CheckConstraint("length(dedupe_key) BETWEEN 1 AND 400", name="key_length"),
        CheckConstraint("jsonb_typeof(details) = 'object'", name="details_is_object"),
        Index(None, "found_at"),
        Index(None, "kibana_case_id"),
    )


class KibanaAlertState(Base):
    """An alert on one of ARGUS's cases as the last discovery saw it (Q-D3): a change is found
    by diffing statuses (Kibana's internal route records no user or time)."""

    __tablename__ = "kibana_alert_states"

    alert_id: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str | None] = mapped_column(Text)
    workflow_user: Mapped[str | None] = mapped_column(Text)
    status_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KibanaPeopleCase(Base):
    """A case people made in Kibana that holds alerts ARGUS knows (plan §7.1): shown read-only,
    never adopted, never written to."""

    __tablename__ = "kibana_people_cases"

    kibana_case_id: Mapped[str] = mapped_column(Text, primary_key=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    tags: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default="{}")
    known_alerts: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, server_default="{}"
    )
    kibana_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("status IN ('open', 'in-progress', 'closed')", name="status_valid"),
    )


STEP_KINDS = ("comment", "attach", "compensate_update", "compensate_comment")
LOOKUP_SUBJECTS = ("outbox", "step")
LOOKUP_OUTCOMES = ("found", "not_found", "duplicate", "foreign", "not_needed")
RUN_KINDS = ("canary", "ramp", "scheduled")


class KibanaStep(Base):
    """A write the case writer derives from an outbox row (Q-D4): the opening comment and the
    alert attachments of a created case, and the comment and change of an approved compensating
    write. Its states are the outbox's (``argus.cases.outbox``) except that a step is sent at
    most once and never resent: a lost one stays lost and is shown, never sent again."""

    __tablename__ = "kibana_steps"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    outbox_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("kibana_outbox.id"))
    approval_request_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id")
    )
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    seq: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    write_class: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    payload_hash: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, server_default="planned")
    state_reason: Mapped[str | None] = mapped_column(Text)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    kibana_case_id: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("kind", STEP_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("write_class", WRITE_CLASSES), name="class_valid"),
        CheckConstraint(_one_of("state", OUTBOX_STATES), name="state_valid"),
        CheckConstraint("sent_count BETWEEN 0 AND 1", name="sent_at_most_once"),
        CheckConstraint("seq BETWEEN 0 AND 999", name="seq_valid"),
        CheckConstraint("length(key) BETWEEN 1 AND 200", name="key_length"),
        CheckConstraint(f"payload_hash ~ {_HEX64}", name="payload_hash_valid"),
        CheckConstraint("jsonb_typeof(payload) = 'object'", name="payload_is_object"),
        CheckConstraint(
            "(kind LIKE 'compensate%') = (approval_request_id IS NOT NULL)",
            name="compensation_has_approval",
        ),
        Index(None, "state", "id"),
        Index(None, "case_id", "id"),
        Index(None, "outbox_id"),
    )


class KibanaLookup(Base):
    """One scheduled look for a write whose outcome is unknown (plan §7.1: at 2, 5, 15 and 30
    minutes), for an outbox row (``subject`` ``outbox``) or a step; the outcome is kept."""

    __tablename__ = "kibana_lookups"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    subject_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sent_count: Mapped[int] = mapped_column(Integer, nullable=False)
    attempt: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    due_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        UniqueConstraint("subject", "subject_id", "sent_count", "attempt"),
        CheckConstraint(_one_of("subject", LOOKUP_SUBJECTS), name="subject_valid"),
        CheckConstraint("attempt BETWEEN 1 AND 4", name="attempt_valid"),
        CheckConstraint(
            f"outcome IS NULL OR {_one_of('outcome', LOOKUP_OUTCOMES)}", name="outcome_valid"
        ),
        CheckConstraint("(outcome IS NULL) = (done_at IS NULL)", name="done_has_outcome"),
        CheckConstraint("jsonb_typeof(details) = 'object'", name="details_is_object"),
        Index(None, "due_at", postgresql_where=text("done_at IS NULL")),
    )


class KibanaWriterRun(Base):
    """One run of the case writer for one class (Q-D4): its kind (a canary or ramp step at the
    terminal, or the service's schedule), its limit, what it sent and read back. The ramp reads
    these (plan §7.1: a class moves up after at least 3 runs on 3 days with 100 % verified
    read-backs)."""

    __tablename__ = "kibana_writer_runs"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    write_class: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    step: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    units: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    sent: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    verified: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    mismatches: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    ambiguous: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    stopped: Mapped[str | None] = mapped_column(Text)
    by: Mapped[str] = mapped_column(Text, nullable=False)

    __table_args__ = (
        CheckConstraint(_one_of("write_class", WRITE_CLASSES), name="class_valid"),
        CheckConstraint(_one_of("kind", RUN_KINDS), name="kind_valid"),
        CheckConstraint("step IN (1, 5, 10)", name="step_valid"),
        CheckConstraint(
            "units >= 0 AND sent >= 0 AND verified >= 0 AND mismatches >= 0 AND ambiguous >= 0",
            name="counts_valid",
        ),
        Index(None, "write_class", "started_at"),
    )


class KibanaWriterRamp(Base):
    """A class's ramp step: how many units a run may write (1 at a canary, then 5, then 10),
    raised only by a person at the terminal who typed the class's name (``argus kibana
    ramp``)."""

    __tablename__ = "kibana_writer_ramp"

    write_class: Mapped[str] = mapped_column(Text, primary_key=True)
    step: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    since: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    changed_by: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint(_one_of("write_class", WRITE_CLASSES), name="class_valid"),
        CheckConstraint("step IN (1, 5, 10)", name="step_valid"),
    )


class ActionLedgerEntry(Base):
    """Every request ARGUS sends to change something outside it (brief §10; Kibana writes from
    Q-D2): its outbox row, payload hash, approval, health and switches. Append-only; never a
    DELETE (the method check)."""

    __tablename__ = "action_ledger"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    outbox_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("kibana_outbox.id"))
    idempotency_key: Mapped[str] = mapped_column(Text, nullable=False)
    write_class: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(Text, nullable=False)
    path: Mapped[str] = mapped_column(Text, nullable=False)
    payload_hash: Mapped[str | None] = mapped_column(Text)
    approval_request_id: Mapped[int | None] = mapped_column(
        BigInteger, ForeignKey("approval_requests.id")
    )
    health: Mapped[str] = mapped_column(Text, nullable=False)
    switches: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    http_status: Mapped[int | None] = mapped_column(Integer)
    elapsed_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    kibana_case_id: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        CheckConstraint("method IN ('POST', 'PATCH')", name="method_valid"),
        CheckConstraint(_one_of("write_class", WRITE_CLASSES), name="class_valid"),
        CheckConstraint(_one_of("outcome", LEDGER_OUTCOMES), name="outcome_valid"),
        CheckConstraint(
            f"payload_hash IS NULL OR payload_hash ~ {_HEX64}", name="payload_hash_valid"
        ),
        CheckConstraint("jsonb_typeof(switches) = 'object'", name="switches_is_object"),
        CheckConstraint("elapsed_ms >= 0", name="elapsed_valid"),
        Index(None, "outbox_id"),
        Index(None, "at"),
    )


# --------------------------------------------------------------------------- Q-F1 (0033)

FRESHNESS_OUTCOMES = ("ok", "empty", "refused", "failed")
FRESHNESS_VERDICTS = ("known_zero", "could_not_tell")
FRESHNESS_MODES = ("shadow", "on")


class FreshnessReading(Base):
    """One freshness-lane reading of a log source (Q-F1, plan §7.3): the newest document by
    ingest time, or why there was none. Append-only for the runtime role."""

    __tablename__ = "freshness_readings"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    source: Mapped[str] = mapped_column(Text, nullable=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str | None] = mapped_column(Text)
    ingested: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    event_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    health: Mapped[str | None] = mapped_column(Text)
    took_ms: Mapped[int | None] = mapped_column(Integer)

    __table_args__ = (
        CheckConstraint("source ~ '^[a-z][a-z0-9_]{0,31}$'", name="source_valid"),
        CheckConstraint(_one_of("outcome", FRESHNESS_OUTCOMES), name="outcome_valid"),
        CheckConstraint(
            "(outcome = 'ok') = (ingested IS NOT NULL AND event_at IS NOT NULL)",
            name="document_when_ok",
        ),
        CheckConstraint("ingested IS NULL = (event_at IS NULL)", name="times_together"),
        CheckConstraint("at >= sent_at", name="answered_after_sent"),
        CheckConstraint("reason IS NULL OR length(reason) <= 200", name="reason_short"),
        CheckConstraint("took_ms IS NULL OR took_ms >= 0", name="took_valid"),
        Index(None, "source", "at"),
    )


class FreshnessWatermark(Base):
    """Each log source's watermark: the newest ingest time any reading saw. It only advances
    (a trigger refuses an update that moves it back)."""

    __tablename__ = "freshness_watermarks"

    source: Mapped[str] = mapped_column(Text, primary_key=True)
    ingested: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    read_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (CheckConstraint("source ~ '^[a-z][a-z0-9_]{0,31}$'", name="source_valid"),)


class FreshnessShadow(Base):
    """The verdict a log zero gets (Q-F1): in shadow, stored and never used or shown (no grant
    to the web's role); once switched on, also the record of each verified zero. One row per
    investigation version, pack and signal, replaced when the signal is derived again."""

    __tablename__ = "freshness_shadow"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), primary_key=True
    )
    version: Mapped[int] = mapped_column(Integer, primary_key=True)
    pack: Mapped[str] = mapped_column(Text, primary_key=True)
    signal: Mapped[str] = mapped_column(Text, primary_key=True)
    mode: Mapped[str] = mapped_column(Text, nullable=False)
    verdict: Mapped[str] = mapped_column(Text, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    bridged_verdict: Mapped[str] = mapped_column(Text, nullable=False)
    complete_to: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refs: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    margins: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    decided_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint(_one_of("mode", FRESHNESS_MODES), name="mode_valid"),
        CheckConstraint(_one_of("verdict", FRESHNESS_VERDICTS), name="verdict_valid"),
        CheckConstraint(_one_of("bridged_verdict", FRESHNESS_VERDICTS), name="bridged_valid"),
        CheckConstraint(
            "verdict = 'could_not_tell' OR bridged_verdict = 'known_zero'",
            name="bridge_never_loses",
        ),
        CheckConstraint(
            "(complete_to IS NOT NULL) = (bridged_verdict = 'known_zero')",
            name="complete_to_when_known",
        ),
        CheckConstraint("jsonb_typeof(refs) = 'array'", name="refs_is_array"),
        CheckConstraint("jsonb_typeof(margins) = 'object'", name="margins_is_object"),
    )


class FreshnessProposal(Base):
    """A would-be proposal in the shadow (Q-F1): what an assessor would propose if the shadow's
    verified zeros were used, beside what it proposed. Stored for the user's audit, never used
    or shown."""

    __tablename__ = "freshness_proposals"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    pack: Mapped[str] = mapped_column(Text, nullable=False)
    dossier_hash: Mapped[str] = mapped_column(Text, nullable=False)
    assessor: Mapped[str] = mapped_column(Text, nullable=False)
    bridged: Mapped[bool] = mapped_column(Boolean, nullable=False)
    outcome: Mapped[str | None] = mapped_column(Text)
    actual: Mapped[str | None] = mapped_column(Text)
    signals: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    reasons: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)

    __table_args__ = (
        CheckConstraint("dossier_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint("jsonb_typeof(signals) = 'array'", name="signals_is_array"),
        CheckConstraint("jsonb_typeof(reasons) = 'array'", name="reasons_is_array"),
        Index(None, "investigation_id", "dossier_hash", "assessor", "bridged", unique=True),
    )


CHECK_KINDS = ("wave", "check")
CHECK_SOURCES = ("engine", "person")
CHECK_STATUSES = ("queued", "running", "done", "refused", "failed")


class InvestigationCheck(Base):
    """A deterministic wave or a person's "Check more" (Q-F3): the request, who wanted it, and
    what it came to. A queue and its record in one row, like an assessment: ``queued`` until the
    service claims it (``running``, with a lease), then ``done`` (``outcome`` holds the checks,
    their E-ids and server time), ``refused`` (a rule of the catalogue said no) or ``failed``.
    The engine's own wave runs once per investigation version. ``template`` and ``entity`` are
    empty for a wave and named for a check."""

    __tablename__ = "investigation_checks"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    # the defaults are what a person's "Check more" is: the web's login inserts neither (0040)
    kind: Mapped[str] = mapped_column(Text, nullable=False, server_default="check")
    source: Mapped[str] = mapped_column(Text, nullable=False, server_default="person")
    template: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    entity: Mapped[str] = mapped_column(Text, nullable=False, server_default="")
    requested_by: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # the server's own clock, which no one inserts: the daily limit of a person's checks (0040)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="queued")
    claims: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    outcome: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    __table_args__ = (
        CheckConstraint(_one_of("kind", CHECK_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("source", CHECK_SOURCES), name="source_valid"),
        CheckConstraint(_one_of("status", CHECK_STATUSES), name="status_valid"),
        CheckConstraint("version >= 0 AND claims >= 0", name="non_negative"),
        CheckConstraint(
            "(kind = 'check') = (template <> '' AND entity <> '')", name="check_names_its_target"
        ),
        CheckConstraint("template ~ '^([a-z][a-z0-9_.]{0,63})?$'", name="template_valid"),
        CheckConstraint("length(entity) <= 253 AND entity !~ '[[:cntrl:]]'", name="entity_valid"),
        CheckConstraint("(source = 'person') = (requested_by IS NOT NULL)", name="person_named"),
        CheckConstraint("kind <> 'check' OR source = 'person'", name="check_is_a_persons"),
        CheckConstraint("requested_by IS NULL OR length(requested_by) <= 120", name="by_short"),
        CheckConstraint(
            "(status IN ('done', 'refused', 'failed')) = (finished_at IS NOT NULL)",
            name="finished_when_over",
        ),
        CheckConstraint(
            "outcome IS NULL OR jsonb_typeof(outcome) = 'object'", name="outcome_is_object"
        ),
        Index(None, "investigation_id"),
        Index(None, "status", "requested_at"),
        Index(
            "ix_investigation_checks_by_day",
            "requested_by",
            "created_at",
            postgresql_where=text("kind = 'check'"),
        ),
        # the engine's own wave runs once for an investigation version
        Index(
            "uq_investigation_checks_engine_wave",
            "investigation_id",
            "version",
            unique=True,
            postgresql_where=text("kind = 'wave' AND source = 'engine'"),
        ),
        # one open request for the same thing at a time
        Index(
            "uq_investigation_checks_open",
            "investigation_id",
            "kind",
            "template",
            "entity",
            unique=True,
            postgresql_where=text("status IN ('queued', 'running')"),
        ),
    )


NOTICE_KINDS = ("case_active", "after_closure", "closure_waiting", "ioc_hit", "outage")


class Notice(Base):
    """What the notices (Q-H4) remember about one subject, one occurrence of it: the kind, an
    opaque subject (a case's or an investigation's id, or a fixed word: never shown in a
    message), the severity and count now, when it was first and last seen, when it ended
    (``resolved_at``: a later occurrence is a new row), and the last notice that went out for it
    (``sent_at``, the severity it carried, how many went out). One live row per (kind, subject).
    Holds no host, address, user or rule name. Never purged (it names nothing personal)."""

    __tablename__ = "notices"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(Text, nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_severity: Mapped[str | None] = mapped_column(Text)
    notified: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(_one_of("kind", NOTICE_KINDS), name="kind_valid"),
        CheckConstraint("subject ~ '^[A-Za-z0-9:_.-]{1,64}$'", name="subject_valid"),
        CheckConstraint(_one_of("severity", CASE_SEVERITIES), name="severity_valid"),
        CheckConstraint(
            f"sent_severity IS NULL OR {_one_of('sent_severity', CASE_SEVERITIES)}",
            name="sent_severity_valid",
        ),
        CheckConstraint("count >= 0", name="count_valid"),
        CheckConstraint("last_seen >= first_seen", name="seen_valid"),
        CheckConstraint("resolved_at IS NULL OR resolved_at >= first_seen", name="resolved_valid"),
        CheckConstraint(
            "(sent_at IS NULL) = (sent_severity IS NULL) AND (sent_at IS NULL) = (notified = 0)"
            " AND notified >= 0",
            name="sent_complete",
        ),
        CheckConstraint(
            "ended_at IS NULL OR (kind = 'outage' AND resolved_at IS NOT NULL"
            " AND sent_at IS NOT NULL AND ended_at >= resolved_at)",
            name="ended_valid",
        ),
        Index(
            "uq_notices_live",
            "kind",
            "subject",
            unique=True,
            postgresql_where=text("resolved_at IS NULL"),
        ),
    )


# --------------------------------------------------------------------------- Q-H3 (0046)

REPORT_KINDS = ("daily", "weekly")


class ReportRecord(Base):
    """A report the Reporter made (Q-H3): the numbers with their definitions, the deterministic
    text written from them and, only when the optional prose agent was on and its prose passed
    the number check, that prose. One row for each (kind, ``period_end``); never changed (the
    runtime role may insert and read, the web's role may read). A period is whole UTC days."""

    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    numbers: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    prose: Mapped[str | None] = mapped_column(Text)
    prose_agent: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("kind", "period_end"),
        CheckConstraint(_one_of("kind", REPORT_KINDS), name="kind_valid"),
        CheckConstraint(
            "(kind = 'daily' AND period_end = period_start + interval '1 day')"
            " OR (kind = 'weekly' AND period_end = period_start + interval '7 days')",
            name="period_valid",
        ),
        CheckConstraint(
            "(period_start AT TIME ZONE 'UTC')::time = '00:00'", name="period_is_utc_days"
        ),
        CheckConstraint("jsonb_typeof(numbers) = 'object'", name="numbers_is_object"),
        CheckConstraint("length(text) BETWEEN 1 AND 400000", name="text_length"),
        CheckConstraint(
            "(prose IS NULL) = (prose_agent IS NULL)"
            " AND (prose IS NULL OR length(prose) BETWEEN 1 AND 20000)",
            name="prose_complete",
        ),
        Index(None, "kind", "period_end"),
    )


INCIDENT_OUTCOMES = OUTCOMES
INCIDENT_DECISIONS = ("confirmed", "rejected")


class IncidentReport(Base):
    """One version of a case's incident report (AR7, D-190): the structured object ARGUS writes
    for a suggested or open case (``body``, ``incident-report@1``), written whole and never
    changed. When the case's evidence changes ARGUS writes the next version; the versions are
    kept. ``content_hash`` is the hash of what the report says, without when it was made and
    without a model's wording. Append-only (the owner's trigger)."""

    __tablename__ = "incident_reports"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    schema_version: Mapped[str] = mapped_column(Text, nullable=False)
    writer: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(Text, nullable=False)
    core_hash: Mapped[str | None] = mapped_column(Text)  # 0057: the hash without the accounts
    case_version: Mapped[int] = mapped_column(Integer, nullable=False)
    verdict_outcome: Mapped[str | None] = mapped_column(Text)
    verdict_confidence: Mapped[float | None] = mapped_column(Double)
    body: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    prose: Mapped[bool] = mapped_column(Boolean, server_default=text("false"), nullable=False)
    prose_by: Mapped[str | None] = mapped_column(Text)
    generated_by: Mapped[str] = mapped_column(Text, server_default="argus:incident", nullable=False)
    as_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("case_id", "version"),
        CheckConstraint("version >= 1", name="version_valid"),
        CheckConstraint("schema_version = 'incident-report@1'", name="schema_valid"),
        CheckConstraint("content_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint(
            "core_hash IS NULL OR core_hash ~ '^[0-9a-f]{64}$'", name="core_hash_valid"
        ),
        CheckConstraint(
            f"verdict_outcome IS NULL OR {_one_of('verdict_outcome', INCIDENT_OUTCOMES)}",
            name="outcome_valid",
        ),
        CheckConstraint(
            "verdict_confidence IS NULL OR (verdict_confidence >= 0 AND verdict_confidence <= 1)",
            name="confidence_valid",
        ),
        CheckConstraint("jsonb_typeof(body) = 'object'", name="body_is_object"),
        CheckConstraint("prose = (prose_by IS NOT NULL)", name="prose_complete"),
        CheckConstraint("case_version >= 1", name="case_version_valid"),
        Index(None, "case_id", "generated_at"),
    )


class IncidentReportDecision(Base):
    """What a person said about a version of a report (AR7): ``confirmed`` or ``rejected`` (with
    a reason and the outcome they hold instead). The labels written from it (reviews of the case's
    investigations, through the existing review path) are named in ``review_ids``. Append-only;
    the newest decision of a version counts."""

    __tablename__ = "incident_report_decisions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    report_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("incident_reports.id"), nullable=False
    )
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    outcome: Mapped[str | None] = mapped_column(Text)
    reason: Mapped[str | None] = mapped_column(Text)
    by_user_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("users.id"), nullable=False)
    review_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("decision", INCIDENT_DECISIONS), name="decision_valid"),
        CheckConstraint(
            f"outcome IS NULL OR {_one_of('outcome', INCIDENT_OUTCOMES)}", name="outcome_valid"
        ),
        CheckConstraint(
            "(decision = 'rejected') = (reason IS NOT NULL AND outcome IS NOT NULL)",
            name="rejection_complete",
        ),
        CheckConstraint(
            "reason IS NULL OR length(btrim(reason)) BETWEEN 3 AND 4000", name="reason_length"
        ),
        Index(None, "report_id", "decided_at"),
    )


class IncidentReportCheck(Base):
    """A case ARGUS looked at for its incident report: the cheap signal of the evidence it saw (a
    case is read again only when the signal changes), when, which report that was, and the last
    failure (a failed report is reported and never stops the pass)."""

    __tablename__ = "incident_report_checks"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    signal: Mapped[str] = mapped_column(Text, nullable=False)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    report_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("incident_reports.id"))
    failure: Mapped[str | None] = mapped_column(Text)
    failed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint("failure IS NULL OR length(failure) <= 500", name="failure_length"),
        CheckConstraint("(failure IS NULL) = (failed_at IS NULL)", name="failure_complete"),
        Index(None, "checked_at"),
    )


CASE_TEAM_AUTHORS = (
    "argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter",
    "argus-reporter", "argus-visualiser",
)  # fmt: skip
CASE_TEAM_KINDS = (
    "open", "attach", "tag", "comment", "file", "retitle", "redescribe", "edit_comment",
)  # fmt: skip
CASE_TEAM_STEP_STATES = (
    "planned", "sending", "sent", "verified", "ambiguous", "resend", "failed", "skipped", "held",
    "superseded",
)  # fmt: skip
CASE_TEAM_POST_STATES = ("active", "held", "done")
CASE_TEAM_SEEN_STATUS = ("recorded", "ignored", "unmatched", "needs_reason", "refused")


class CaseTeamPost(Base):
    """The Kibana incident case ARGUS's case team posted for an ARGUS case (AR8, D-195): one row
    for each case, made when its first sequence is planned. ``kibana_case_id`` is set once the
    lead's create is read back; ``last_version`` is the report version the newest finished
    generation posted. Written by the writer's login."""

    __tablename__ = "case_team_posts"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    incident_id: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    kibana_case_id: Mapped[str | None] = mapped_column(Text)
    state: Mapped[str] = mapped_column(Text, server_default="active", nullable=False)
    held_reason: Mapped[str | None] = mapped_column(Text)
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_version: Mapped[int | None] = mapped_column(Integer)
    last_round_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("state", CASE_TEAM_POST_STATES), name="state_valid"),
        CheckConstraint(
            r"incident_id ~ '^[A-Z][A-Z0-9-]{0,15}-[0-9]{4}-[0-9]{4}-[0-9]{2}$'", name="id_valid"
        ),
        CheckConstraint("last_version IS NULL OR last_version >= 1", name="version_valid"),
        Index(None, "opened_at"),
    )


class CaseTeamStep(Base):
    """One request of a post: who sends it, what exactly (``text_body``, ``payload``), and where
    it stands. A generation's steps are written when it is planned and are never reordered; a
    step moves ``planned -> sending -> sent -> verified``, or into doubt (``ambiguous``: looked
    for in Kibana before anything is sent again; ``resend``: a person decides)."""

    __tablename__ = "case_team_steps"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("case_team_posts.case_id"), nullable=False
    )
    gen: Mapped[int] = mapped_column(Integer, nullable=False)
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    key: Mapped[str] = mapped_column(Text, nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    author: Mapped[str] = mapped_column(Text, nullable=False)
    part: Mapped[str] = mapped_column(Text, nullable=False)
    report_version: Mapped[int] = mapped_column(Integer, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    text_body: Mapped[str | None] = mapped_column(Text)
    units: Mapped[list[str]] = mapped_column(
        JSONB, server_default=text("'[]'::jsonb"), nullable=False
    )
    request_hash: Mapped[str] = mapped_column(Text, nullable=False)
    state: Mapped[str] = mapped_column(Text, server_default="planned", nullable=False)
    state_reason: Mapped[str | None] = mapped_column(Text)
    sent_count: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    kibana_ids: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=text("'{}'::jsonb"), nullable=False
    )
    lookups: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    next_lookup_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("case_id", "gen", "key"),
        UniqueConstraint("case_id", "gen", "seq"),
        CheckConstraint("gen >= 1 AND seq >= 1", name="position_valid"),
        CheckConstraint(_one_of("kind", CASE_TEAM_KINDS), name="kind_valid"),
        CheckConstraint(_one_of("author", CASE_TEAM_AUTHORS), name="author_valid"),
        CheckConstraint(_one_of("state", CASE_TEAM_STEP_STATES), name="state_valid"),
        CheckConstraint("request_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint("sent_count >= 0 AND lookups >= 0", name="counts_valid"),
        CheckConstraint(
            "(kind IN ('open', 'comment', 'redescribe', 'edit_comment')) = (text_body IS NOT NULL)",
            name="text_kinds",
        ),
        CheckConstraint(
            "kind NOT IN ('open', 'attach', 'tag', 'retitle', 'redescribe')"
            " OR author = 'argus-lead'",
            name="lead_only",
        ),
        CheckConstraint("kind <> 'file' OR author = 'argus-reporter'", name="reporter_only"),
    )


class CaseTeamApproval(Base):
    """A person's approval of one case's first sequence (the canary, AR8): it binds the plan's
    hash, so a plan that changed needs a new one. ``signature`` is the web's HMAC over
    ``statement`` (the approval key of the closures). Append-only."""

    __tablename__ = "case_team_approvals"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), nullable=False
    )
    gen: Mapped[int] = mapped_column(Integer, nullable=False)
    plan_hash: Mapped[str] = mapped_column(Text, nullable=False)
    report_version: Mapped[int] = mapped_column(Integer, nullable=False)
    approver_user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id"), nullable=False
    )
    statement: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    approved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        CheckConstraint("gen >= 1", name="gen_valid"),
        CheckConstraint("plan_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        CheckConstraint("expires_at > approved_at", name="expiry_valid"),
        Index(None, "case_id", "plan_hash"),
    )


class CaseTeamSeen(Base):
    """A person's ``Verdict:`` comment on a posted case, read once (AR8): what it said, who wrote
    it and what ARGUS did (``recorded``: a label through the review path; ``ignored``,
    ``unmatched``: the author is no known ARGUS person; ``needs_reason``; ``refused``).
    Append-only; the same comment text is never read twice."""

    __tablename__ = "case_team_seen"

    kibana_comment_id: Mapped[str] = mapped_column(Text, primary_key=True)
    text_hash: Mapped[str] = mapped_column(Text, primary_key=True)
    status: Mapped[str] = mapped_column(Text, primary_key=True)  # 0054: unmatched, then decided
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("case_team_posts.case_id"), nullable=False
    )
    author: Mapped[str] = mapped_column(Text, nullable=False)
    written_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verdict: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[str | None] = mapped_column(Text)
    counts: Mapped[dict[str, Any] | None] = mapped_column(JSONB)  # 0054: what the review did
    user_id: Mapped[int | None] = mapped_column(BigInteger, ForeignKey("users.id"))
    review_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), server_default=text("'{}'::bigint[]"), nullable=False
    )
    read_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint(_one_of("status", CASE_TEAM_SEEN_STATUS), name="status_valid"),
        CheckConstraint(
            f"verdict IS NULL OR {_one_of('verdict', INCIDENT_OUTCOMES)}", name="verdict_valid"
        ),
        CheckConstraint("text_hash ~ '^[0-9a-f]{64}$'", name="hash_valid"),
        Index(None, "case_id", "written_at"),
    )


class CaseTeamLook(Base):
    """When the case team's poster last looked at a case (0054): it picks its candidates in SQL
    and rotates through them by this time, so a case at the back of a long list is reached.
    Written by the writer's login."""

    __tablename__ = "case_team_looks"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("cases.id"), primary_key=True
    )
    examined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (Index(None, "examined_at"),)


class CaseTeamRead(Base):
    """What the Kibana case looked like at the last read of its comments (0054): its
    ``updated_at`` and comment count. The sync reads a posted case's comments again only when
    either changed. Written by the runtime login (the sync's pass)."""

    __tablename__ = "case_team_reads"

    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("case_team_posts.case_id"), primary_key=True
    )
    kibana_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    comment_count: Mapped[int] = mapped_column(Integer, nullable=False)
    read_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (CheckConstraint("comment_count >= 0", name="count_valid"),)


SIGNIN_REASONS = (
    "partial", "bad_answer", "logs_gone", "failed", "store_failed", "unnamed_events",
    "index_missing",
)  # fmt: skip


class SigninSighting(Base):
    """One account's SSO sign-ins from one internal address on one UTC day (AR6, D-216, 0056).
    The user name is personal data: shown only to people with log access, never given to a model.
    Not derived from grouping: the logs last five days at the SIEM and this copy stays."""

    __tablename__ = "signin_sightings"

    address: Mapped[str] = mapped_column(INET, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    user_name: Mapped[str] = mapped_column(Text, primary_key=True)
    first_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    events: Mapped[int] = mapped_column(Integer, nullable=False)
    successes: Mapped[int] = mapped_column(Integer, nullable=False)
    failures: Mapped[int] = mapped_column(Integer, nullable=False)
    hours: Mapped[list[int]] = mapped_column(ARRAY(SmallInteger), nullable=False)
    user_agents: Mapped[list[Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'[]'::jsonb")
    )
    written_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    __table_args__ = (
        CheckConstraint("char_length(user_name) BETWEEN 1 AND 256", name="user_name_length"),
        CheckConstraint("first_at <= last_at", name="span_valid"),
        CheckConstraint(
            "events >= 1 AND successes >= 0 AND failures >= 0 AND successes + failures <= events",
            name="counts_valid",
        ),
        CheckConstraint(
            "cardinality(hours) >= 1 AND cardinality(hours) <= 24"  # flat: D-234
            " AND hours <@ ARRAY[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23]"
            "::smallint[]",
            name="hours_valid",
        ),
        CheckConstraint(
            "jsonb_typeof(user_agents) = 'array' AND jsonb_array_length(user_agents) <= 3",
            name="agents_valid",
        ),
        Index(None, "day"),
    )


class SigninLookup(Base):
    """That ARGUS asked about an address on a UTC day, when, and whether the answer was whole
    (AR6, D-216, 0056): "looked, none seen", "not looked yet", "incomplete" and "logs no longer
    kept" are different things."""

    __tablename__ = "signin_lookups"

    address: Mapped[str] = mapped_column(INET, primary_key=True)
    day: Mapped[date] = mapped_column(Date, primary_key=True)
    looked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    complete: Mapped[bool] = mapped_column(Boolean, nullable=False)
    accounts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    more_accounts: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    reason: Mapped[str | None] = mapped_column(Text)
    unnamed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")  # 0057
    store_failures: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default="0")

    __table_args__ = (
        CheckConstraint(
            "accounts >= 0 AND more_accounts >= 0 AND more_accounts <= accounts",
            name="counts_valid",
        ),
        CheckConstraint(
            "(complete AND reason IS NULL AND unnamed = 0 AND store_failures = 0)"
            " OR (NOT complete AND reason IS NOT NULL AND reason IN ("
            + ", ".join(f"'{r}'" for r in SIGNIN_REASONS)
            + ") AND accounts = 0 AND more_accounts = 0"
            " AND (unnamed >= 1) = (reason = 'unnamed_events')"
            " AND (store_failures = 0 OR reason = 'store_failed'))",
            name="reason_valid",
        ),
        CheckConstraint("unnamed >= 0 AND store_failures >= 0", name="tries_valid"),
        Index(None, "day"),
    )
