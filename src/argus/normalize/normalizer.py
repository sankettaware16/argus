"""The alert normalizer: one Elasticsearch hit in, a typed alert or a quarantine record out.

A pure function of the hit and a small context (grouping file, observed rule durations): it
never raises on any JSON input and never does I/O. A required field that is missing, malformed
or ambiguous quarantines the alert with a reason from a closed set; anything else that is odd
becomes a field issue and the alert is still normalized.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from argus.normalize.canon import canon_values, canonical_json, digest
from argus.normalize.fields import leaf_values, values
from argus.normalize.grouping import GENERIC_KEY_FIELDS, MAX_KEY_FIELDS, GroupingConfig
from argus.normalize.model import (
    NORMALIZER_VERSION,
    Adapter,
    Ancestor,
    AncestorKind,
    Entity,
    ExecutionType,
    FieldIssue,
    FieldIssueKind,
    GroupKey,
    KeySource,
    KeyValue,
    NormalizedAlert,
    Quarantined,
    QuarantineReason,
    RuleType,
    SingletonReason,
    TimeAnomaly,
    TimeBasis,
    TimeWindow,
    WindowBasis,
)
from argus.normalize.times import MAX_RULE_DURATION, parse_interval, parse_lookback, parse_time

FINGERPRINT_VERSION = 1
TIME_SLACK = timedelta(minutes=2)  # sanity margin for time anomalies

# Document limits: an alert is a few hundred nodes; anything near these is not an alert.
MAX_DEPTH = 64
MAX_NODES = 200_000
MAX_CHARS = 32 * 1024 * 1024
MAX_ID_CHARS = 512
MAX_ANCESTORS = 100
MAX_ENTITY_VALUES = 16
MAX_INT_BITS = 4096  # json and str() refuse integers above ~14,000 bits; ES longs have 64

_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")
_PATTERN_CHARS = frozenset("*?,:<>")
_RULE_TYPES = {t.value: t for t in RuleType if t is not RuleType.UNKNOWN}
_EVENT_TYPES = frozenset(
    {RuleType.QUERY, RuleType.SAVED_QUERY, RuleType.THREAT_MATCH, RuleType.NEW_TERMS}
)
_ROW_EXCLUDED = frozenset({"@timestamp", "event.kind"})
ENTITY_FIELDS: tuple[tuple[Literal["ip", "domain", "host", "user"], str], ...] = (
    ("ip", "source.ip"),
    ("ip", "destination.ip"),
    ("domain", "url.domain"),
    ("domain", "destination.domain"),
    ("domain", "dns.question.name"),
    ("host", "host.name"),
    ("user", "user.name"),
)
# The device that saw or shipped the event (ECS observer, agent): a proxy or firewall often also
# writes its own name into host.name. That name is no party to the activity, and as an entity
# it would link every alert the device saw.
REPORTER_FIELDS = ("observer.hostname", "observer.name", "agent.hostname", "agent.name")

_ALERT = "kibana.alert."
_RULE = "kibana.alert.rule."
_PARAMS = "kibana.alert.rule.parameters."


@dataclass(frozen=True)
class NormalizeContext:
    grouping: GroupingConfig = field(default_factory=GroupingConfig)
    # rule_id -> the longest execution seen for the rule (slack for ES|QL windows)
    observed_max_execution: Mapping[str, timedelta] = field(default_factory=dict)


_DEFAULT_CONTEXT = NormalizeContext()


class _QuarantineError(Exception):
    def __init__(self, reason: QuarantineReason, field_name: str | None) -> None:
        self.reason = reason
        self.field_name = field_name


def normalize(
    hit: Any, context: NormalizeContext = _DEFAULT_CONTEXT
) -> NormalizedAlert | Quarantined:
    """Normalize one search hit (``{"_id", "_index", "_source"}``)."""
    alert_id = _usable_id(hit.get("_id")) if isinstance(hit, dict) else None
    index = _usable_id(hit.get("_index")) if isinstance(hit, dict) else None
    try:
        return _Normalizer(hit, context).run()
    except _QuarantineError as q:
        return Quarantined(
            normalizer_version=NORMALIZER_VERSION,
            alert_id=alert_id,
            index=index,
            reason=q.reason,
            field=q.field_name,
        )


def _usable_id(value: Any) -> str | None:
    if isinstance(value, str) and 0 < len(value) <= MAX_ID_CHARS and not _UNSTORABLE.search(value):
        return value
    return None


def _clean(value: Any, cap: int) -> str | None:
    """Text for storage: NUL and lone surrogates replaced, capped; None if not a string."""
    if not isinstance(value, str) or not value:
        return None
    return _UNSTORABLE.sub("�", value[:cap])


def _check_document(doc: dict[str, Any]) -> None:
    """JSON types only, within the limits; iterative, so depth cannot exhaust the stack."""
    stack: list[tuple[Any, int]] = [(doc, 1)]
    nodes = chars = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise _QuarantineError(QuarantineReason.TOO_LARGE, "nodes")
        if isinstance(node, dict):
            if depth > MAX_DEPTH:
                raise _QuarantineError(QuarantineReason.TOO_LARGE, "depth")
            for key, item in node.items():
                if not isinstance(key, str):
                    raise _QuarantineError(QuarantineReason.NOT_A_DOCUMENT, "_source")
                chars += len(key)
                stack.append((item, depth + 1))
        elif isinstance(node, list):
            if depth > MAX_DEPTH:
                raise _QuarantineError(QuarantineReason.TOO_LARGE, "depth")
            stack.extend((item, depth + 1) for item in node)
        elif isinstance(node, str):
            chars += len(node)
        elif isinstance(node, int) and node.bit_length() > MAX_INT_BITS:
            raise _QuarantineError(QuarantineReason.TOO_LARGE, "number")
        elif node is not None and not isinstance(node, bool | int | float):
            raise _QuarantineError(QuarantineReason.NOT_A_DOCUMENT, "_source")
        if chars > MAX_CHARS:
            raise _QuarantineError(QuarantineReason.TOO_LARGE, "chars")


class _Normalizer:
    def __init__(self, hit: Any, context: NormalizeContext) -> None:
        if not isinstance(hit, dict):
            raise _QuarantineError(QuarantineReason.NOT_A_DOCUMENT, None)
        source = hit.get("_source")
        if not isinstance(source, dict):
            raise _QuarantineError(QuarantineReason.NOT_A_DOCUMENT, "_source")
        self.hit = hit
        self.source: dict[str, Any] = source
        self.context = context
        self.issues: set[tuple[str, FieldIssueKind]] = set()
        self.window_inverted = False

    # ------------------------------------------------------------------ field access

    def issue(self, name: str, kind: FieldIssueKind) -> None:
        self.issues.add((name, kind))

    def single(self, path: str) -> tuple[Literal["missing", "one", "conflict"], Any]:
        found = values(self.source, path)
        if not found:
            return "missing", None
        first = found[0]
        if len(found) > 1:
            key = canonical_json(first)
            if any(canonical_json(other) != key for other in found[1:]):
                return "conflict", None
        return "one", first

    def optional(self, path: str) -> Any:
        status, value = self.single(path)
        if status == "conflict":
            self.issue(path, FieldIssueKind.CONFLICTING_VALUES)
        return value

    def text(self, path: str, cap: int) -> str | None:
        value = self.optional(path)
        if value is not None and not isinstance(value, str):
            self.issue(path, FieldIssueKind.INVALID_VALUE)
        return _clean(value, cap)

    def integer(self, path: str) -> int | None:
        value = self.optional(path)
        if value is None:
            return None
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**63:
            return value
        self.issue(path, FieldIssueKind.INVALID_VALUE)
        return None

    def time(self, path: str) -> datetime | None:
        value = self.optional(path)
        if value is None:
            return None
        parsed = parse_time(value)
        if parsed is None:
            self.issue(path, FieldIssueKind.INVALID_TIME)
        return parsed

    def required_text(self, path: str) -> str:
        status, value = self.single(path)
        if status == "missing":
            raise _QuarantineError(QuarantineReason.MISSING_FIELD, path)
        if status == "conflict":
            raise _QuarantineError(QuarantineReason.CONFLICTING_FIELD, path)
        if _usable_id(value) is None:
            raise _QuarantineError(QuarantineReason.INVALID_FIELD, path)
        return str(value)

    # ------------------------------------------------------------------ main

    def run(self) -> NormalizedAlert:
        _check_document(self.source)
        alert_id = self.hit.get("_id")
        if alert_id is None:
            raise _QuarantineError(QuarantineReason.MISSING_FIELD, "_id")
        if _usable_id(alert_id) is None:
            raise _QuarantineError(QuarantineReason.INVALID_FIELD, "_id")
        index = self.hit.get("_index")
        if index is None:
            raise _QuarantineError(QuarantineReason.MISSING_FIELD, "_index")
        if _usable_id(index) is None:
            raise _QuarantineError(QuarantineReason.INVALID_FIELD, "_index")
        if self.required_text(_ALERT + "uuid") != alert_id:
            raise _QuarantineError(QuarantineReason.ID_MISMATCH, _ALERT + "uuid")
        rule_id = self.required_text(_RULE + "rule_id")
        detected_raw = self.single("@timestamp")
        if detected_raw[0] == "missing":
            raise _QuarantineError(QuarantineReason.MISSING_FIELD, "@timestamp")
        if detected_raw[0] == "conflict":
            raise _QuarantineError(QuarantineReason.CONFLICTING_FIELD, "@timestamp")
        detected_at = parse_time(detected_raw[1])
        if detected_at is None:
            raise _QuarantineError(QuarantineReason.INVALID_FIELD, "@timestamp")

        rule_type, rule_type_raw = self.rule_type()
        execution = self.execution_type()
        building_block = self.text(_ALERT + "building_block_type", 64) is not None
        group_id = self.text(_ALERT + "group.id", 128)
        ancestors = self.ancestors()
        intended = self.time(_ALERT + "intended_timestamp")
        original = self.time(_ALERT + "original_time")
        adapter = self.adapter(rule_type, ancestors, original, group_id, building_block)

        event_time, basis, fallback = self.event_time(adapter, original, intended, detected_at)
        approximate = basis is not TimeBasis.ORIGINAL_TIME
        window = self.window(adapter, rule_id, execution, event_time, approximate, original)
        anomalies = self.anomalies(event_time, basis, detected_at)

        risk = self.optional(_ALERT + "risk_score")
        if risk is not None and (
            isinstance(risk, bool) or not isinstance(risk, int | float) or not 0 <= risk <= 100
        ):
            self.issue(_ALERT + "risk_score", FieldIssueKind.INVALID_VALUE)
            risk = None

        group_key = self.group_key(rule_id, rule_type)
        entities = self.entities()
        return NormalizedAlert(
            normalizer_version=NORMALIZER_VERSION,
            alert_id=alert_id,
            index=index,
            rule_id=rule_id,
            rule_uuid=self.text(_RULE + "uuid", 128),
            rule_revision=self.integer(_RULE + "revision"),
            rule_name=self.text(_RULE + "name", 512),
            rule_type=rule_type,
            rule_type_raw=rule_type_raw,
            adapter=adapter,
            severity=self.text(_ALERT + "severity", 32),
            risk_score=None if risk is None else float(risk),
            workflow_status=self.text(_ALERT + "workflow_status", 32),
            building_block=building_block,
            sequence_group_id=group_id,
            max_signals=self.integer(_RULE + "max_signals"),
            execution_type=execution,
            execution_uuid=self.text(_RULE + "execution.uuid", 128),
            detected_at=detected_at,
            intended_timestamp=intended,
            original_time=original,
            event_time=event_time,
            time_basis=basis,
            event_time_approximate=approximate,
            time_fallback=fallback,
            detection_lag=detected_at - event_time,
            evidence_window=window,
            time_anomalies=anomalies,
            ancestors=ancestors,
            fingerprint=self.fingerprint(adapter, rule_id, ancestors, intended),
            group_key=group_key,
            entities=entities,
            field_issues=tuple(FieldIssue(field=f, issue=k) for f, k in sorted(self.issues)),
        )

    # ------------------------------------------------------------------ rule

    def rule_type(self) -> tuple[RuleType, str | None]:
        declared = self.optional(_RULE + "type")
        from_params = self.optional(_PARAMS + "type")
        if declared is not None and from_params is not None and declared != from_params:
            self.issue(_RULE + "type", FieldIssueKind.RULE_TYPE_MISMATCH)
        raw = declared if declared is not None else from_params
        if raw is not None and not isinstance(raw, str):
            self.issue(_RULE + "type", FieldIssueKind.INVALID_VALUE)
            raw = None
        rule_type = _RULE_TYPES.get(raw, RuleType.UNKNOWN) if raw else RuleType.UNKNOWN
        return rule_type, _clean(raw, 64)

    def execution_type(self) -> ExecutionType:
        value = self.optional(_RULE + "execution.type")
        if value == "scheduled":
            return ExecutionType.SCHEDULED
        if value == "manual":
            return ExecutionType.MANUAL
        if value is not None:
            self.issue(_RULE + "execution.type", FieldIssueKind.INVALID_VALUE)
        return ExecutionType.UNKNOWN

    def ancestors(self) -> tuple[Ancestor, ...]:
        path = _ALERT + "ancestors"
        out: list[Ancestor] = []
        for item in values(self.source, path):
            if not isinstance(item, dict):
                self.issue(path, FieldIssueKind.INVALID_VALUE)
                continue
            if len(out) == MAX_ANCESTORS:
                self.issue(path, FieldIssueKind.TOO_MANY_VALUES)
                break
            index = _usable_id(item.get("index")) or ""
            doc_id = _usable_id(item.get("id")) or ""
            depth = item.get("depth")
            if not index or not doc_id:
                kind = AncestorKind.EMPTY
            elif _PATTERN_CHARS.intersection(index):
                kind = AncestorKind.PATTERN
            else:
                kind = AncestorKind.CONCRETE
            out.append(
                Ancestor(
                    index=index,
                    id=doc_id,
                    kind=kind,
                    type=_clean(item.get("type"), 32),
                    depth=depth
                    if isinstance(depth, int) and not isinstance(depth, bool) and 0 <= depth < 1000
                    else None,
                )
            )
        return tuple(out)

    @staticmethod
    def adapter(
        rule_type: RuleType,
        ancestors: tuple[Ancestor, ...],
        original: datetime | None,
        group_id: str | None,
        building_block: bool,
    ) -> Adapter:
        if rule_type in _EVENT_TYPES:
            return Adapter.EVENT
        if rule_type is RuleType.THRESHOLD:
            return Adapter.THRESHOLD
        if rule_type is RuleType.ESQL:
            concrete = any(a.kind is AncestorKind.CONCRETE for a in ancestors)
            return Adapter.EVENT if concrete and original is not None else Adapter.ESQL_AGGREGATE
        if rule_type is RuleType.EQL:
            return Adapter.EQL_SEQUENCE if group_id and not building_block else Adapter.EVENT
        return Adapter.GENERIC

    # ------------------------------------------------------------------ time

    def event_time(
        self,
        adapter: Adapter,
        original: datetime | None,
        intended: datetime | None,
        detected_at: datetime,
    ) -> tuple[datetime, TimeBasis, bool]:
        if adapter is Adapter.ESQL_AGGREGATE:
            if intended is not None:
                return intended, TimeBasis.INTENDED_TIMESTAMP, False
            self.issue(_ALERT + "intended_timestamp", FieldIssueKind.MISSING_TIME)
            return detected_at, TimeBasis.DETECTION_TIMESTAMP, True
        if original is not None:
            return original, TimeBasis.ORIGINAL_TIME, False
        self.issue(_ALERT + "original_time", FieldIssueKind.MISSING_TIME)
        if intended is not None:
            return intended, TimeBasis.INTENDED_TIMESTAMP, True
        return detected_at, TimeBasis.DETECTION_TIMESTAMP, True

    def window(
        self,
        adapter: Adapter,
        rule_id: str,
        execution: ExecutionType,
        event_time: datetime,
        approximate: bool,
        original: datetime | None,
    ) -> TimeWindow:
        if adapter is Adapter.THRESHOLD and original is not None:
            start = self.time(_ALERT + "threshold_result.from")
            if start is None:
                self.issue(_ALERT + "threshold_result.from", FieldIssueKind.MISSING_TIME)
            else:
                self.window_inverted = start > original
                low, high = sorted((start, original))
                return TimeWindow(
                    start=low, end=high, basis=WindowBasis.THRESHOLD, approximate=approximate
                )
        if adapter is Adapter.ESQL_AGGREGATE:
            return self.esql_window(rule_id, execution, event_time)
        return TimeWindow(
            start=event_time, end=event_time, basis=WindowBasis.POINT, approximate=approximate
        )

    def rule_duration(self, name: str, parse: Any) -> timedelta | None:
        raw = self.optional(_RULE + name)
        if raw is None:
            raw = self.optional(_PARAMS + name)
        if raw is None:
            return None
        parsed: timedelta | None = parse(raw)
        if parsed is None:
            self.issue(_RULE + name, FieldIssueKind.INVALID_RULE_PARAMETER)
        return parsed

    def esql_window(self, rule_id: str, execution: ExecutionType, anchor: datetime) -> TimeWindow:
        """[anchor - rule.from - slack, anchor - rule.to]; slack = 0 for manual runs, else
        max(interval, observed max execution)."""
        lookback = self.rule_duration("from", parse_lookback)
        until = self.rule_duration("to", parse_lookback) or timedelta(0)
        interval = self.rule_duration("interval", parse_interval)
        if execution is ExecutionType.MANUAL:
            slack = timedelta(0)
        else:
            observed = self.context.observed_max_execution.get(rule_id, timedelta(0))
            slack = max(interval or timedelta(0), min(observed, MAX_RULE_DURATION))
        reach = lookback if lookback is not None else interval
        if reach is None:
            return TimeWindow(start=anchor, end=anchor, basis=WindowBasis.POINT, approximate=True)
        end = anchor - until
        start = min(anchor - reach - slack, end)
        return TimeWindow(start=start, end=end, basis=WindowBasis.ESQL_LOOKBACK, approximate=True)

    def anomalies(
        self, event_time: datetime, basis: TimeBasis, detected_at: datetime
    ) -> tuple[TimeAnomaly, ...]:
        """Sanity flags. The ingest check applies to a source event's own time only: a
        fallback time is the rule run's, which is after ingest by nature."""
        found: list[TimeAnomaly] = []
        if basis is TimeBasis.ORIGINAL_TIME:
            ingested = self.time(_ALERT + "original_event.ingested")
            if ingested is None:
                ingested = self.time("event.ingested")
            if ingested is not None and event_time > ingested + TIME_SLACK:
                found.append(TimeAnomaly.EVENT_AFTER_INGEST)
        if event_time > detected_at + TIME_SLACK:
            found.append(TimeAnomaly.EVENT_AFTER_DETECTION)
        if self.window_inverted:
            found.append(TimeAnomaly.WINDOW_INVERTED)
        return tuple(found)

    # ------------------------------------------------------------------ duplicates

    def fingerprint(
        self,
        adapter: Adapter,
        rule_id: str,
        ancestors: tuple[Ancestor, ...],
        intended: datetime | None,
    ) -> str:
        """Detection fingerprint: equal for two alerts that report the same detection."""
        concrete = sorted({(a.index, a.id) for a in ancestors if a.kind is AncestorKind.CONCRETE})
        if adapter in (Adapter.EVENT, Adapter.EQL_SEQUENCE, Adapter.GENERIC) and concrete:
            return digest(FINGERPRINT_VERSION, "event", rule_id, concrete)
        if adapter is Adapter.THRESHOLD:
            terms = self.threshold_terms()
            start = self.time(_ALERT + "threshold_result.from")
            return digest(
                FINGERPRINT_VERSION,
                "threshold",
                rule_id,
                sorted([name, canonical_json(value)] for name, value in terms),
                None if start is None else start.isoformat(),
            )
        row = sorted(
            (path, found)
            for path, found in leaf_values(self.source).items()
            if path not in _ROW_EXCLUDED and not path.startswith("kibana.")
        )
        return digest(
            FINGERPRINT_VERSION,
            "row",
            rule_id,
            None if intended is None else intended.isoformat(),
            canonical_json(row),
        )

    # ------------------------------------------------------------------ group key

    def field_names(self, path: str) -> list[str]:
        names: list[str] = []
        for item in values(self.source, path):
            if not isinstance(item, str) or _usable_id(item) is None or len(item) > 256:
                self.issue(path, FieldIssueKind.INVALID_RULE_PARAMETER)
            elif item not in names:
                names.append(item)
        if len(names) > MAX_KEY_FIELDS:
            self.issue(path, FieldIssueKind.TOO_MANY_VALUES)
            names = names[:MAX_KEY_FIELDS]
        return names

    def threshold_terms(self) -> list[tuple[str, Any]]:
        terms: list[tuple[str, Any]] = []
        for item in values(self.source, _ALERT + "threshold_result.terms"):
            if isinstance(item, dict) and isinstance(item.get("field"), str):
                terms.append((item["field"], item.get("value")))
            else:
                self.issue(_ALERT + "threshold_result.terms", FieldIssueKind.INVALID_VALUE)
        return terms

    def group_key(self, rule_id: str, rule_type: RuleType) -> GroupKey:
        strategy: Literal["suppress", "doNotSuppress"] = "suppress"
        terms: dict[str, list[Any]] | None = None
        fields = self.field_names(_PARAMS + "alert_suppression.group_by")
        if fields:
            source = KeySource.SUPPRESSION
            declared = self.optional(_PARAMS + "alert_suppression.missing_fields_strategy")
            if declared == "doNotSuppress":
                strategy = "doNotSuppress"
            elif declared not in (None, "suppress"):
                self.issue(
                    _PARAMS + "alert_suppression.missing_fields_strategy",
                    FieldIssueKind.INVALID_RULE_PARAMETER,
                )
        elif rule_type is RuleType.THRESHOLD and (
            fields := self.field_names(_PARAMS + "threshold.field")
        ):
            source = KeySource.THRESHOLD
            terms = {}
            for name, value in self.threshold_terms():
                terms.setdefault(name, []).append(value)
        elif rule_id in self.context.grouping.rules:
            source = KeySource.CONFIG
            fields = list(self.context.grouping.rules[rule_id].key_fields)
        else:
            source = KeySource.GENERIC
            fields = list(GENERIC_KEY_FIELDS)

        key_values: list[KeyValue] = []
        for name in fields:
            raw = terms[name] if terms is not None and name in terms else values(self.source, name)
            value, issues = canon_values(name, raw)
            for kind in issues:
                self.issue(name, kind)
            key_values.append(value)

        singleton: SingletonReason | None = None
        if all(value is None for value in key_values):
            singleton = SingletonReason.ALL_NULL
        elif strategy == "doNotSuppress" and any(value is None for value in key_values):
            singleton = SingletonReason.MISSING_FIELD
        canonical = None
        if singleton is None:
            pairs = sorted(zip(fields, key_values, strict=True), key=lambda pair: pair[0])
            canonical = canonical_json([[name, value] for name, value in pairs])
        return GroupKey(
            source=source,
            fields=tuple(fields),
            values=tuple(key_values),
            missing_fields_strategy=strategy,
            singleton=singleton,
            canonical=canonical,
        )

    def entities(self) -> tuple[Entity, ...]:
        out: list[Entity] = []
        reporters = {
            str(v).strip().lower()
            for f in REPORTER_FIELDS
            for v in values(self.source, f)
            if isinstance(v, str) and v.strip()
        }
        for kind, name in ENTITY_FIELDS:
            seen: set[str] = set()
            for raw in values(self.source, name):
                value, issues = canon_values(name, [raw])
                for issue in issues:
                    self.issue(name, issue)
                if value is None or issues or isinstance(value, tuple):
                    continue
                text = value if isinstance(value, str) else canonical_json(value)
                if text in seen or (kind == "host" and text.lower() in reporters):
                    continue
                if len(seen) == MAX_ENTITY_VALUES:
                    self.issue(name, FieldIssueKind.TOO_MANY_VALUES)
                    break
                seen.add(text)
                out.append(Entity(kind=kind, field=name, value=text))
        return tuple(out)
