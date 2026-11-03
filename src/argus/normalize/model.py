"""What the normalizer returns: a :class:`NormalizedAlert` or a :class:`Quarantined` record.

Every enumeration here is closed: a new value is a code change and a normalizer version bump.
Nothing in these models is free text taken from the document except names and ids that are
cleaned (no NUL, no lone surrogates) and capped; quarantine records name a field, never a value.
"""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict

NORMALIZER_VERSION = "1.1.0"  # bump when the normalized output changes

Scalar = str | int | float | bool
KeyValue = Scalar | tuple[Scalar, ...] | None


class RuleType(StrEnum):
    QUERY = "query"
    SAVED_QUERY = "saved_query"
    THREAT_MATCH = "threat_match"
    NEW_TERMS = "new_terms"
    THRESHOLD = "threshold"
    ESQL = "esql"
    EQL = "eql"
    MACHINE_LEARNING = "machine_learning"
    UNKNOWN = "unknown"


class Adapter(StrEnum):
    """How time, window and fingerprint are derived."""

    EVENT = (
        "event"  # one source event: query, saved_query, threat_match, new_terms, eql, ES|QL rows
    )
    THRESHOLD = "threshold"
    ESQL_AGGREGATE = "esql_aggregate"  # an aggregated ES|QL row: no ancestor, no original_time
    EQL_SEQUENCE = "eql_sequence"  # the shell alert of an EQL sequence
    GENERIC = "generic"  # an unknown rule type: best available time, approximate


class ExecutionType(StrEnum):
    SCHEDULED = "scheduled"
    MANUAL = "manual"
    UNKNOWN = "unknown"


class TimeBasis(StrEnum):
    ORIGINAL_TIME = "original_time"
    INTENDED_TIMESTAMP = "intended_timestamp"
    DETECTION_TIMESTAMP = "detection_timestamp"  # @timestamp: the last resort


class WindowBasis(StrEnum):
    POINT = "point"  # [event_time, event_time]; evidence templates pad it themselves
    THRESHOLD = "threshold"  # [threshold_result.from, original_time]
    ESQL_LOOKBACK = "esql_lookback"  # [anchor - rule.from - slack, anchor - rule.to]


class TimeAnomaly(StrEnum):
    EVENT_AFTER_INGEST = "event_after_ingest"  # event_time > event.ingested + 2 min
    EVENT_AFTER_DETECTION = "event_after_detection"  # event_time > @timestamp + 2 min
    WINDOW_INVERTED = "window_inverted"  # threshold_result.from after original_time


class AncestorKind(StrEnum):
    CONCRETE = "concrete"  # an exact index and id: fetchable
    PATTERN = "pattern"  # an index pattern (threshold alerts): not fetchable
    EMPTY = "empty"  # no index or id (aggregating ES|QL alerts)


class KeySource(StrEnum):
    SUPPRESSION = "suppression"  # the rule's declared alert_suppression.group_by
    THRESHOLD = "threshold"  # the threshold rule's group-by fields
    CONFIG = "config"  # config/grouping.yaml
    GENERIC = "generic"  # [source.ip, destination.ip]


class SingletonReason(StrEnum):
    ALL_NULL = "all_null"  # every key field is null: never a rule-wide bucket
    MISSING_FIELD = "missing_field"  # a key field is null and the rule says doNotSuppress


class QuarantineReason(StrEnum):
    NOT_A_DOCUMENT = "not_a_document"  # the hit or its _source is not a JSON object
    TOO_LARGE = "too_large"  # deeper, bigger or longer than the normalizer's limits
    MISSING_FIELD = "missing_field"  # a required field is absent or null
    INVALID_FIELD = "invalid_field"  # a required field has the wrong type or format
    CONFLICTING_FIELD = "conflicting_field"  # a required field has several distinct values
    ID_MISMATCH = "id_mismatch"  # kibana.alert.uuid differs from _id


class FieldIssueKind(StrEnum):
    INVALID_IP = "invalid_ip"
    INVALID_PORT = "invalid_port"
    INVALID_DOMAIN = "invalid_domain"
    NOT_SCALAR = "not_scalar"
    VALUE_TOO_LONG = "value_too_long"
    UNSTORABLE_TEXT = "unstorable_text"  # NUL or a lone surrogate: PostgreSQL cannot store it
    TOO_MANY_VALUES = "too_many_values"
    CONFLICTING_VALUES = "conflicting_values"
    INVALID_TIME = "invalid_time"
    MISSING_TIME = "missing_time"
    INVALID_VALUE = "invalid_value"
    INVALID_RULE_PARAMETER = "invalid_rule_parameter"
    RULE_TYPE_MISMATCH = "rule_type_mismatch"


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class TimeWindow(_Model):
    start: AwareDatetime
    end: AwareDatetime
    basis: WindowBasis
    approximate: bool


class Ancestor(_Model):
    index: str
    id: str
    kind: AncestorKind
    type: str | None
    depth: int | None


class FieldIssue(_Model):
    field: str
    issue: FieldIssueKind


class GroupKey(_Model):
    """Canonical group-key inputs; the grouping step turns them into an investigation id."""

    source: KeySource
    fields: tuple[str, ...]
    values: tuple[KeyValue, ...]
    missing_fields_strategy: Literal["suppress", "doNotSuppress"]
    singleton: SingletonReason | None
    canonical: str | None  # canonical JSON of the sorted (field, value) pairs; None if singleton


class Entity(_Model):
    kind: Literal["ip", "domain", "host", "user"]
    field: str
    value: str


class NormalizedAlert(_Model):
    normalizer_version: str
    alert_id: str  # _id, equal to kibana.alert.uuid (opaque)
    index: str
    rule_id: str  # the stable kibana.alert.rule.rule_id
    rule_uuid: str | None
    rule_revision: int | None
    rule_name: str | None
    rule_type: RuleType
    rule_type_raw: str | None
    adapter: Adapter
    severity: str | None
    risk_score: float | None
    workflow_status: str | None
    building_block: bool
    sequence_group_id: str | None
    max_signals: int | None
    execution_type: ExecutionType
    execution_uuid: str | None
    detected_at: AwareDatetime  # @timestamp
    intended_timestamp: AwareDatetime | None
    original_time: AwareDatetime | None
    event_time: AwareDatetime
    time_basis: TimeBasis
    event_time_approximate: bool
    time_fallback: bool  # the adapter's own time basis was missing
    detection_lag: timedelta  # detected_at - event_time
    evidence_window: TimeWindow
    time_anomalies: tuple[TimeAnomaly, ...]
    ancestors: tuple[Ancestor, ...]
    fingerprint: str
    group_key: GroupKey
    entities: tuple[Entity, ...]
    field_issues: tuple[FieldIssue, ...]


class Quarantined(_Model):
    normalizer_version: str
    alert_id: str | None  # the hit's _id when it is a usable id
    index: str | None
    reason: QuarantineReason
    field: str | None  # the field or limit concerned; never a value
