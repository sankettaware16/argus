"""Provenance, facts, checks and observations of report@2. Pure.

**Provenance** of an evidence request: its opaque id, the query and one line a person reads, e.g.
``E3 · proxy.host@1 · squid, 09 Oct 10:00-13:00 UTC · aggregation · complete · 0.6 s``. **Facts**:
each signal, note step and alert fact in ARGUS's own words, with the E-ids it comes from, how it
leans and whether log content reaches it. **Checks**: what each request came to; "nothing found"
needs a known signal that says so (a failed, skipped or lagging check is never negative).
**Observations**: what stored answers hold that no signal shows, for people only. Untrusted strings
from evidence never enter a sentence of this module: they are ``Value``s beside it, capped."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from math import inf
from typing import Any

from argus import site
from argus.context import batch1, display, notes, proxy
from argus.context.evidence import COMPLETE, canonical
from argus.gateway.templates import REGISTRY, Family
from argus.normalize.fields import values as field_values
from argus.reference.ti import indicators_of
from argus.report.model import Check, Fact, Gap, Leaning, Outcome, Provenance, Value
from argus.site import Words

VALUE_CHARS = 200  # an untrusted value as shown
LABEL_CHARS = 60  # a value's label: ARGUS's word for it, never an untrusted value
SUBJECT_CHARS = 120  # what a request asked about, as its provenance shows it
WINDOW = frozenset({"start", "end"})  # parameters that are the window, not the subject
DASH = "\u2013"  # between the two ends of a window
TOP = 10  # values per observation
# The floor's signals (assess.engine.floor): unknown, each blocks a benign proposal.
FLOOR = (
    "ti.listed",
    "ti.listed_remote",
    "web.successes_after",
    "ports.risky",
    "proxy.regularity",
    "proxy.hosts_to_destination",
)
# The intel module cites every evidence row of a run (a log check's too: context.intel), but
# these signals read only these templates' rows (or none: ARGUS's own store). A fact shows the
# E-ids of what it reads, and only that decides whether log content reaches it.
READS = {
    "ti.listed": frozenset({"ti.lookup"}),
    "ti.listed_remote": frozenset({"ti.lookup"}),
    "ti.values": frozenset[str](),
    "same_ioc.investigations": frozenset[str](),
    "alerts.cadence_cv": frozenset[str](),
}
BEACON = 0.3  # proxy.regularity below this is regular, like a beacon (assess.engine.BEACON)
RARE = 1  # a destination at most this many internal hosts reach (assess.engine.RARE)

# Why something could not be told, in plain words: signals' unknown reasons and evidence
# statuses. No code ever reaches a reviewer.
REASONS = {
    "ingest_not_verified": "a zero from the logs is not trusted until ARGUS measures how far"
    " their ingest has got",
    "partial_coverage": "the answer was cut, so only part of it is known",
    "source_not_checked": "a threat list was not checked for every indicator",
    "no_sources": "no threat-intel source is configured for this site",
    "source_stale": "a threat list is out of date (its newest entry is over 7 days old)",
    "values_cut": "not every indicator could be looked up",
    "no_indicators": "there was nothing to look up",
    "no_evidence": "no check was made",
    "no_value": "the answer held no value",
    "too_few_alerts": "too few alerts to measure",
    "no_fields": "the alerts do not carry the fields it needs",
    "supernode_entities": "an entity is shared by very many investigations, so they are"
    " not counted",
    "timeout": "the SIEM did not answer in time",
    "failed": "the check failed",
    "skipped_budget": "ARGUS's SIEM budget for it was used up",
    "deferred": "the SIEM was busy or paused, so the check waits",
    "source_lag": "the logs for that time had not arrived yet",
    "source_expired": "the logs for that time are no longer kept",
    "unsupported_value": "the value is too long to search for",
    "unavailable": "the SIEM was not available",
    "missing": "nothing was stored for it",
}
COVERAGE = {
    "pack_budget": "the investigation's own budget of checks was used up",
    "rederive": "a re-derivation never asks the SIEM",
    "context_partial": "ARGUS put off its SIEM checks for up to a day",
    "purged": "its log rows were deleted after ARGUS's retention period, so it is not asked again",
}
# Who can resolve what ARGUS could not tell.
RESOLVERS = {
    "ingest_not_verified": "ARGUS, once it measures log ingest (watermarks)",
    "source_not_checked": "ARGUS, with the live threat-list lookup",
    "source_stale": "an admin, by refreshing the threat-list feed",
    "no_sources": "an admin, by naming a threat-intel source (site.ti_sources)",
    "timeout": "ARGUS, by checking again",
    "failed": "ARGUS, by checking again",
    "skipped_budget": "ARGUS, by checking again when its budget allows",
    "deferred": "ARGUS, once the SIEM is back to normal",
    "source_lag": "ARGUS, by checking again later",
    "unavailable": "ARGUS, once the SIEM is back",
    "source_expired": "nobody: the logs are gone",
}
PERSON = "a person, from the alerts and the SIEM"
# The evidence templates in plain words.
CHECKS = Words(
    {
        "proxy.host": "the host's proxy traffic",
        "proxy.destination": "which {own:hosts} reached the destination through the proxy",
        "web.followups": "the client's successful web answers after the first alert",
        "proxy.pair": "how regularly the host reached the destination through the proxy",
        "proxy.contact": "which {own:hosts} reached the destination through the proxy that day",
        "dns.host_domains": "which names the client looked up in DNS",
        "web.path_outcomes": "whether the attacked paths got a successful answer",
        "logs.source_events": "the log events behind the alert",
    }
)
# The same checks about another subject than the one ARGUS's signals read (a second request
# of a template: an investigator's ask about another host, client or indicator).
CHECKS_OTHER = Words(
    {
        "proxy.host": "another {own:host}'s proxy traffic",
        "proxy.destination": "which {own:hosts} reached another destination through the proxy",
        "web.followups": "another client's successful web answers after the first alert",
        "proxy.pair": "how regularly another host reached a destination through the proxy",
        "proxy.contact": "which {own:hosts} reached another destination through the proxy",
        "dns.host_domains": "which names another client looked up in DNS",
        "web.path_outcomes": "whether another client's attacked paths got a successful answer",
        "logs.source_events": "the log events behind another alert",
    }
)
# Who asked a check that gives a reason for it (evidence_requests.reason).
ASKED_BY = {"wave": "by ARGUS's wave", "person": "at a person's request"}
# Where a fact without an E-id comes from, when it is not the stored alerts.
SOURCES = {"same_ioc.investigations": "ARGUS's other investigations"}
STORE = "ARGUS's stored threat-list answers"  # the mirrors, the lookup sources' 24 h cache
TI_COUNTS = frozenset({"ti.listed", "ti.listed_remote"})
# The note capabilities no log answers (context.notes.CAPABILITIES); any other is log content.
NOT_LOGS = frozenset({"reputation"})


@dataclass(frozen=True)
class EvidenceRow:
    """One stored evidence row (the ``evidence`` table)."""

    task_key: str
    version: int
    template: str
    template_version: int
    params: Mapping[str, Any]
    status: str
    coverage: Mapping[str, Any]
    row_count: int | None = None
    truncated: bool = False
    snapshot: Any = None
    result_hash: str | None = None
    took_ms: int | None = None
    source_watermark: datetime | None = None
    reused_from_version: int | None = None
    error: str | None = None
    collected_at: datetime | None = None
    purged: bool = False  # the retention purge removed its snapshot

    def ref(self) -> dict[str, Any]:
        """The graph's reference to it (``context.store.ref_of``, without ``reused``)."""
        ref: dict[str, Any] = {
            "task_key": self.task_key,
            "template": f"{self.template}@{self.template_version}",
            "status": self.status,
            "coverage": dict(self.coverage or {}),
            "row_count": self.row_count,
            "truncated": bool(self.truncated),
            "result_hash": self.result_hash,
        }
        if batch1.is_batch1(ref):  # the five templates' readings need their parameters
            ref["params"] = dict(self.params or {})
        return ref


def as_of(
    rows: Sequence[EvidenceRow],
    refs: Sequence[Mapping[str, Any]],
    version: int,
    until: datetime | None,
) -> list[EvidenceRow]:
    """A version's evidence as an assessment that ended at ``until`` had it: the rows stored
    by then; for a check the dossier lists whose row changed later (a failed answer retried
    in place, or a purged one) the dossier's own record of it, with the stored answer's data
    only when it is the same answer. ``until`` None: every row."""
    kept = {
        r.task_key: r
        for r in rows
        if until is None or (r.collected_at is not None and r.collected_at <= until)
    }
    stored = {r.task_key: r for r in rows}
    for ref in refs:
        key = str(ref.get("task_key"))
        if key in kept:
            continue
        name, _, number = str(ref.get("template") or "").rpartition("@")
        later = stored.get(key)
        same = (
            later is not None
            and later.result_hash is not None
            and later.result_hash == ref.get("result_hash")
            and later.status == ref.get("status")
        )
        kept[key] = EvidenceRow(
            task_key=key,
            version=version,
            template=name,
            template_version=int(number) if number.isdigit() else 0,
            params=later.params if later is not None else {},
            status=str(ref.get("status")),
            coverage=dict(ref.get("coverage") or {}),
            row_count=ref.get("row_count"),
            truncated=bool(ref.get("truncated")),
            snapshot=later.snapshot if same and later is not None else None,
            result_hash=ref.get("result_hash"),
            took_ms=later.took_ms if same and later is not None else None,
            source_watermark=later.source_watermark if same and later is not None else None,
        )
    return [kept[k] for k in sorted(kept)]


@dataclass(frozen=True)
class RequestRow:
    """One ``evidence_requests`` row."""

    eid: int
    task_key: str
    template: str
    template_version: int
    origin: str
    reason: str | None = None
    first_version: int = 0
    created_at: datetime | None = None

    @property
    def label(self) -> str:
        return f"E{self.eid}"


@dataclass(frozen=True)
class LedgerRow:
    """The request ledger's row that answered an evidence row (``siem_requests``)."""

    task_key: str
    at: datetime
    indices: tuple[str, ...]
    outcome: str
    took_ms: int
    attempts: int


def rows(n: int) -> str:
    return f"{n} row" if n == 1 else f"{n} rows"


def seconds(ms: int) -> str:
    """Server time as a person reads it: milliseconds below a second."""
    return f"{ms} ms" if ms < 1000 else f"{ms / 1000:.1f} s"


def cap(value: Any, chars: int = VALUE_CHARS) -> str:
    text = str(value)
    return text if len(text) <= chars else text[: chars - 1] + "…"


def subject_of(params: Mapping[str, Any] | None) -> str | None:
    """What a request asked about, as a person reads it (untrusted: shown capped)."""
    if not isinstance(params, Mapping):
        return None
    ip = params.get("ip")
    if isinstance(ip, str) and ip:
        return cap(ip, SUBJECT_CHARS)
    values = params.get("values")
    if isinstance(values, list | tuple) and values:
        shown = [str(v) for v in values[:3]]
        more = len(values) - len(shown)
        return cap(", ".join(shown) + (f" and {more} more" if more > 0 else ""), SUBJECT_CHARS)
    return None


def identity(params: Mapping[str, Any] | None) -> str:
    """A request's subject as data: its parameters without the window."""
    if not isinstance(params, Mapping):
        return ""
    try:
        return canonical({k: v for k, v in params.items() if k not in WINDOW})
    except (TypeError, ValueError):
        return repr(sorted(params.items(), key=lambda kv: str(kv[0])))


def plain(code: str | None, default: str = "it could not be told") -> str:
    return REASONS.get(code or "", default)


def who(code: str | None) -> str:
    return RESOLVERS.get(code or "", PERSON)


@dataclass(frozen=True)
class Query:
    family: str
    source: str | None
    start: datetime | None
    end: datetime | None


def query_of(template: str, version: int, params: Mapping[str, Any] | None) -> Query:
    """What a stored request read, from its template's plan (the registered version only)."""
    cls = REGISTRY.get(template)
    if cls is None or cls.version != version:
        return Query("unknown", None, None, None)
    family = cls.family.value
    if params is None:
        return Query(family, None, None, None)
    try:
        plan = cls().plan(cls.params_model.model_validate_json(canonical(dict(params))))
    except Exception:  # stored parameters that no longer validate: no window
        return Query(family, None, None, None)
    if plan.window is not None:
        return Query(family, plan.window.source, plan.window.start, plan.window.end)
    source = ", ".join(plan.names) if plan.names else plan.source
    return Query(family, source, None, None)


def is_log(template: str, version: int) -> bool:
    """A log template's answer is log content; a template this version does not know counts
    as one (hidden when unsure)."""
    found = query_of(template, version, None).family
    return found in (Family.LOG.value, "unknown")


def _utc(at: datetime) -> datetime:
    return at.astimezone(UTC)


def span(start: datetime | None, end: datetime | None) -> str:
    """``09 Oct 10:00-13:00 UTC``; across days ``09 Oct 23:00 - 10 Oct 01:00 UTC`` (en
    dashes)."""
    if start is None or end is None:
        return ""
    a, b = _utc(start), _utc(end)
    if a.date() == b.date() or (b - a <= timedelta(days=1) and b.time() == datetime.min.time()):
        tail = "24:00" if b.date() != a.date() else b.strftime("%H:%M")
        return f"{a:%d %b %H:%M}{DASH}{tail} UTC"
    return f"{a:%d %b %H:%M} {DASH} {b:%d %b %H:%M} UTC"


def _complete(row: EvidenceRow) -> bool:
    return not row.truncated and not row.coverage


def provenance(
    request: RequestRow, row: EvidenceRow | None, ledger: LedgerRow | None = None
) -> Provenance:
    q = query_of(request.template, request.template_version, row.params if row else None)
    log = q.family in (Family.LOG.value, "unknown")
    status = row.status if row is not None else "missing"
    subject = subject_of(row.params if row is not None else None)
    parts = [request.label, f"{request.template}@{request.template_version}"]
    if subject:
        parts.append(f"about {subject}")
    where = ", ".join(p for p in (q.source, span(q.start, q.end)) if p)
    if where:
        parts.append(where)
    if row is not None and row.status in COMPLETE:
        aggregated = isinstance(row.snapshot, Mapping) and row.snapshot.get("aggregations")
        if aggregated:
            parts.append("aggregation")
        else:
            least = "" if not row.coverage.get("total") else "at least "
            parts.append(f"{least}{rows(row.row_count or 0)}")
        if _complete(row):
            parts.append("complete")
        else:
            parts.append("partial: cut at the row limit" if row.truncated
                         else "partial: the total is a lower bound")  # fmt: skip
        if row.source_watermark is not None:
            parts.append(f"logs to {_utc(row.source_watermark):%H:%M} UTC")
        elif log:
            parts.append("log ingest not measured")
        if row.took_ms is not None:
            parts.append(seconds(row.took_ms))
        if row.reused_from_version is not None:
            parts.append(f"copied from version {row.reused_from_version}")
    else:
        word = "not run" if status in ("skipped_budget", "deferred", "missing") else "failed"
        parts.append(f"{word}: {why_not(row)}")
    if request.reason and request.origin in ASKED_BY:  # the wave's and a person's reasons
        parts.append(f"asked {ASKED_BY[request.origin]}: {cap(request.reason, 200)}")
    return Provenance(
        eid=request.label,
        template=f"{request.template}@{request.template_version}",
        origin=request.origin,  # type: ignore[arg-type]
        reason=request.reason,
        subject=subject,
        family=q.family,
        source=q.source,
        window_start=q.start,
        window_end=q.end,
        indices=ledger.indices if ledger is not None else (),
        status=status,
        rows=row.row_count if row is not None else None,
        truncated=bool(row.truncated) if row is not None else False,
        exact=not (row.coverage.get("total") if row is not None else False),
        server_ms=row.took_ms if row is not None else None,
        result_hash=row.result_hash if row is not None else None,
        watermark=row.source_watermark if row is not None else None,
        collected_at=row.collected_at if row is not None else None,
        version=row.version if row is not None else None,
        reused_from_version=row.reused_from_version if row is not None else None,
        attempts=ledger.attempts if ledger is not None else None,
        line=" · ".join(parts),
        from_logs=log,
    )


def lookups_fresh(body: Mapping[str, Any]) -> bool | None:
    """Whether the answers of the looked-up threat-intel sources for the investigation's
    indicators are fresh, a live lookup counting as a check (the threat-intel module's own
    reading); None without indicators or without a looked-up source."""
    from argus.context.intel import _source_state  # the module's reading, not a copy of it

    pack = (body.get("context") or {}).get("pack") or {}
    answers = (pack.get("ti") or {}).get("answers") or []
    lookups = site.active().ti_lookups
    if not answers or not lookups:
        return None
    return all(_source_state(answers, s.index, remote_checked=True) == "fresh" for s in lookups)


def ti_where(row: EvidenceRow | None) -> str:
    """The threat-intel source(s) a stored ``ti.lookup`` asked, by index; a request that names
    none means the site's first ``ioc`` one; else "the threat lists"."""
    version = row.template_version if row is not None else 1
    found = query_of("ti.lookup", version, row.params if row is not None else None).source
    return found or "the threat lists"


def why_not(row: EvidenceRow | None) -> str:
    """Why a request has no complete answer."""
    if row is None:
        return plain("missing")
    reason = (row.coverage or {}).get("reason")
    if isinstance(reason, str) and reason in COVERAGE:
        return COVERAGE[reason]
    if (row.coverage or {}).get("unstorable"):
        return "the answer could not be stored"
    return plain(row.status, "the check did not complete")


# For an empty answer, the signal whose known value says "none" (a count of what the template
# finds). A template without one never says "nothing found"; a log zero is not known until
# ingest is measured (evidence.from_logs), and a threat list must be fresh.
NEGATIVE = {
    "ti.lookup": "ti.listed_remote",
    "proxy.host": "proxy.destinations",
    "proxy.destination": "proxy.hosts_to_destination",
    "web.followups": "web.successes_after",
}
# Counts whose known 0 is a check's "nothing found", not a finding of its own.
NONE_COUNTS = frozenset({*NEGATIVE.values(), "ti.listed"})
FAILURES = frozenset(
    {"timeout", "failed", "skipped_budget", "deferred", "source_lag", "source_expired",
     "unsupported_value"}
)  # fmt: skip


def outcome_of(
    row: EvidenceRow | None,
    citing: Sequence[Mapping[str, Any]],
    log: bool,
    template: str,
    keys: Keys,
    fresh: bool | None = None,
) -> tuple[Outcome, str | None]:
    """What a request came to. ``citing``: the signals that read it; ``fresh``: whether the
    threat list it looked in is fresh (a lookup). "Nothing found" only when the template's own
    count is known to be 0: a failed, skipped or lagging check, or a zero ARGUS cannot
    trust, is never negative."""
    if row is None or row.status in ("skipped_budget", "deferred"):
        return "not_run", why_not(row)
    if row.status in ("timeout", "failed"):
        return "failed", why_not(row)
    if row.status not in COMPLETE:  # lag, expired, an unsearchable value
        return "could_not_tell", why_not(row)
    if row.status == "ok":
        return "found", None
    name = NEGATIVE.get(template)
    signal = next((s for s in citing if s.get("name") == name), None) if name else None
    if signal is None:
        return "could_not_tell", plain("ingest_not_verified") if log else "no signal reads it"
    if signal.get("status") != "known":
        return "could_not_tell", unknown_why(signal, keys)[0]
    if template == "ti.lookup" and fresh is not True:
        return "could_not_tell", plain("source_stale" if fresh is False else "source_not_checked")
    return "nothing_found", None


def check(
    request: RequestRow,
    row: EvidenceRow | None,
    citing: Sequence[Mapping[str, Any]],
    prov: Provenance,
    keys: Keys,
    fresh: bool | None = None,
    other: bool = False,
) -> Check:
    """``other``: a request about another subject than the one ARGUS's signals read."""
    outcome, why = outcome_of(row, citing, prov.from_logs, request.template, keys, fresh)
    words = CHECKS_OTHER if other else CHECKS
    what = words.get(request.template, f"the {request.template} check")
    if request.template == "ti.lookup":
        what = f"{'more indicators' if other else 'the indicators'} on {ti_where(row)}"
    if outcome == "found":
        assert row is not None
        aggregated = isinstance(row.snapshot, Mapping) and row.snapshot.get("aggregations")
        n = row.row_count or 0
        got = "an answer" if aggregated else f"{'at least ' if not prov.exact else ''}{rows(n)}"
        sentence = f"Checked {what}: found {got}."
    elif outcome == "nothing_found":
        sentence = f"Checked {what}: nothing found."
    elif outcome == "could_not_tell":
        sentence = f"Checked {what}: could not tell, because {why}."
    elif outcome == "failed":
        sentence = f"Could not check {what}: {why}."
    else:
        sentence = f"Did not check {what}: {why}."
    return Check(
        eid=request.label,
        template=f"{request.template}@{request.template_version}",
        origin=request.origin,  # type: ignore[arg-type]
        outcome=outcome,
        sentence=sentence,
        why=why,
        from_logs=prov.from_logs,
        server_ms=row.took_ms if row is not None else None,
        line=prov.line,
    )


def label(name: str) -> str:
    """A signal's label (the display registry's, ``config/signals.yaml``)."""
    entry = display.entry(name)
    part = name.rsplit(".", 1)[-1]
    return entry.title(part) if entry else name


def leaning(signal: Mapping[str, Any]) -> Leaning:
    """How a known signal bears on "a real threat" (the floor's reading): a reason to
    look is suspicious, its known absence reassuring; everything else is neutral."""
    if signal.get("status") != "known":
        return "neutral"
    name, value = str(signal.get("name")), signal.get("value")
    if isinstance(value, bool) or not isinstance(value, int | float):
        return "neutral"
    if name in ("ti.listed", "ports.risky"):  # 0 known: every list fresh, every port shown
        if value > 0:
            return "suspicious"
        lower = signal.get("completeness") == "lower_bound"
        return "neutral" if lower else "reassuring"
    if name in ("ti.listed_remote", "web.successes_after", "same_ioc.investigations"):
        return "suspicious" if value > 0 else "neutral"  # their 0 says nothing of freshness
    if name == "proxy.regularity":
        return "suspicious" if value < BEACON else "reassuring"
    if name == "proxy.hosts_to_destination":
        return "suspicious" if value <= RARE else "reassuring"
    return "neutral"


@dataclass(frozen=True)
class Keys:
    """What the facts of one report know about its task keys."""

    eid: Mapping[str, str]  # task key -> E-id
    template: Mapping[str, str]  # task key -> template name
    logs: frozenset[str]  # the task keys of log templates
    status: Mapping[str, str] = field(default_factory=dict)  # task key -> evidence status
    # a complete threat-list lookup's task key -> the investigation's indicators it lists
    holds: Mapping[str, frozenset[str]] = field(default_factory=dict)
    local: tuple[str, ...] = ()  # the threat lists ARGUS's stored answers find a hit in

    def eids(self, keys: Iterable[str]) -> tuple[str, ...]:
        found = {self.eid[k] for k in keys if k in self.eid}
        return tuple(sorted(found, key=lambda e: int(e[1:])))


def reads(signal: Mapping[str, Any], keys: Keys) -> list[str]:
    """The evidence a signal reads: the task keys it cites, those of the templates it reads
    for the intel module's signals (``READS``)."""
    cited = [str(k) for k in signal.get("evidence") or []]
    only = READS.get(str(signal.get("name")))
    return cited if only is None else [k for k in cited if keys.template.get(k) in only]


def unknown_why(signal: Mapping[str, Any], keys: Keys) -> tuple[str, list[str]]:
    """Why a signal is unknown, and the checks to blame when a check's failure is the reason:
    the intel module waits for every check of the run, so another check's failure can make a
    threat-list reading unknown (said so, with that check's E-id)."""
    code = str(signal.get("unknown_reason") or "")
    if code not in FAILURES:
        return plain(code), []
    cited = [str(k) for k in signal.get("evidence") or []]
    blamed = [k for k in cited if keys.status.get(k) == code]
    own = set(reads(signal, keys))
    if not blamed or set(blamed) <= own:
        return plain(code), blamed
    return f"{plain(code)} for {', '.join(keys.eids(blamed))}, and this reading waits for" \
        " every check of the investigation", blamed  # fmt: skip


def _positive(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and value > 0


def signal_fact(signal: Mapping[str, Any], keys: Keys) -> Fact:
    name = str(signal.get("name"))
    read = reads(signal, keys)
    known = signal.get("status") == "known"
    why, blamed = (None, []) if known else unknown_why(signal, keys)
    sentence = display.sentence(signal) if known else f"{label(name)}: could not tell."
    source = SOURCES.get(name)
    if known and name in TI_COUNTS and _positive(signal.get("value")):
        # a hit traces to the lookups that list an indicator and to ARGUS's stored answers,
        # never to a lookup that found nothing
        read = [k for k in read if keys.holds.get(k)]
        if name == "ti.listed" and keys.local:
            source = f"{STORE} ({', '.join(keys.local)})"
    return Fact(
        key=f"signal:{name}",
        kind="signal",
        name=name,
        sentence=sentence,
        status="known" if known else "unknown",
        why=why,
        eids=keys.eids([*read, *blamed]),
        source=source,
        from_logs=any(k in keys.logs for k in read),
        leaning=leaning(signal),
    )


# A note step's capability and the signals that answer it (context.generic: the modules'
# answers come from these signals).
CAPABILITY_SIGNALS = {
    "reputation": ("ti.listed",),
    "prevalence": ("proxy.hosts_to_destination",),
    "timeline": ("proxy.busy_slots", "proxy.regularity"),
    "log_pivot": ("proxy.destinations", "web.successes_after"),
}
STEP_WORDS = {
    "answered": "answered",
    "deferred": "not checked yet",
    "manual": "for a person",
    "unknown": "no data",
}


def step_fact(step: Mapping[str, Any], signals: Mapping[str, Fact]) -> Fact:
    """A note step's outcome. Its E-ids come from the signals behind the answers its question
    needs; it is log content when any capability it needs is answered from logs, whatever
    its status (whether a log answer came is content too)."""
    number = step.get("number")
    status = str(step.get("status"))
    needed = notes.needs(str(step.get("text") or ""))
    behind = [signals[n] for c in needed for n in CAPABILITY_SIGNALS.get(c, ()) if n in signals]
    used = [f for f in behind if f.status == "known"] if status in ("answered", "deferred") else []
    eids = tuple(sorted({e for f in used for e in f.eids}, key=lambda e: int(e[1:])))
    return Fact(
        key=f"step:{number}",
        kind="step",
        name=f"step {number}",
        sentence=f"Step {number}, {STEP_WORDS.get(status, status)}: {step.get('sentence')}",
        status="known" if status == "answered" else "unknown",
        why=None if status == "answered" else STEP_WORDS.get(status, status),
        eids=eids,
        from_logs=any(c not in NOT_LOGS for c in needed) or any(f.from_logs for f in used),
        text=cap(step.get("text") or "", 600),
    )


def signal_gap(signal: Mapping[str, Any], fact: Fact) -> Gap | None:
    """An unknown signal is a gap: what could not be told, why, and who can resolve it."""
    if fact.status == "known":
        return None
    code = str(signal.get("unknown_reason") or "")
    return Gap(
        key=fact.key,
        what=f"{label(fact.name)}: could not tell.",
        why=fact.why or plain(code),
        who=who(code),
        floor=fact.name in FLOOR,
        eids=fact.eids,
        from_logs=fact.from_logs,
    )


def step_gap(step: Mapping[str, Any], fact: Fact) -> Gap | None:
    """A note step still waiting for a check, or without data in the alerts, is a gap; a
    step for a person is an action, not a gap."""
    status = str(step.get("status"))
    if status == "deferred":
        needs = sorted({notes.CAPABILITIES[n] for n in step.get("needs") or []
                        if n in notes.CAPABILITIES})  # fmt: skip
        what = " and ".join(needs) or "a check ARGUS does not make yet"
        return Gap(key=fact.key, what=f"Step {step.get('number')} of the rule's note.",
                   why="it needs " + what, who="ARGUS, once it can make " + what,
                   eids=fact.eids, from_logs=fact.from_logs)  # fmt: skip
    if status == "unknown":
        return Gap(key=fact.key, what=f"Step {step.get('number')} of the rule's note.",
                   why="no alert carries the fields it names", who=PERSON,
                   eids=fact.eids, from_logs=fact.from_logs)  # fmt: skip
    return None


def alert_facts(facts: Mapping[str, Any]) -> list[Fact]:
    """What the stored alerts themselves say that bears on a verdict."""
    out = []
    severity = str(facts.get("severity") or "").lower()
    if severity:
        out.append(
            Fact(
                key="alert:severity",
                kind="alert",
                name="severity",
                sentence=f"The rule rates it {severity}.",
                status="known",
                leaning="suspicious" if severity in ("high", "critical") else "neutral",
            )
        )
    return out


def _value(label_: str, value: Any, count: Any = None) -> Value:
    n = count if isinstance(count, int) and not isinstance(count, bool) else None
    return Value(label=cap(label_, LABEL_CHARS), text=cap(value), count=n)


def _count(bucket: Mapping[str, Any]) -> int | float:
    """A bucket's document count, 0 unless it is a finite number (a damaged snapshot)."""
    n = bucket.get("doc_count")
    if isinstance(n, bool) or not isinstance(n, int | float):
        return 0
    return n if n == n and abs(n) != inf else 0


def _buckets(aggs: Mapping[str, Any], name: str) -> list[Mapping[str, Any]]:
    part = aggs.get(name)
    buckets = part.get("buckets") if isinstance(part, Mapping) else None
    return [b for b in buckets if isinstance(b, Mapping)] if isinstance(buckets, list) else []


def _number(aggs: Mapping[str, Any], name: str) -> int | float | None:
    part = aggs.get(name)
    value = part.get("value") if isinstance(part, Mapping) else None
    ok = isinstance(value, int | float) and not isinstance(value, bool)
    return value if ok else None


LATEST = datetime(9000, 1, 1, tzinfo=UTC)  # a later stored time is damaged: never shown


def _ms_time(key: Any) -> datetime | None:
    if isinstance(key, bool) or not isinstance(key, int | float):
        return None
    try:
        at = datetime.fromtimestamp(key / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    return at if at < LATEST else None


def _when(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    at = at if at.tzinfo is not None else at.replace(tzinfo=UTC)
    try:
        return at if at < LATEST else None
    except OverflowError:
        return None


def _proxy_host(
    base: str, eids: tuple[str, ...], aggs: Mapping[str, Any], other: bool = False
) -> list[Fact]:
    out = []
    who = f"Another {site.own('host')}" if other else "The host"
    destinations = _buckets(aggs, "destinations")[:TOP]
    if destinations:
        out.append(Fact(
            key=f"{base}:destinations", kind="observation", name="proxy.host destinations",
            sentence=f"{who}'s most frequent destinations through the proxy"
                     f" ({len(destinations)} shown).",
            status="known", eids=eids, from_logs=True,
            values=tuple(_value("destination", b.get("key"), b.get("doc_count"))
                         for b in destinations),
        ))  # fmt: skip
    answers = [*_buckets(aggs, "statuses")[:TOP], *_buckets(aggs, "actions")[:TOP]]
    if answers:
        out.append(Fact(
            key=f"{base}:answers", kind="observation", name="proxy.host answers",
            sentence=f"{who}'s answers from the proxy, and what the proxy did with them.",
            status="known", eids=eids, from_logs=True,
            values=tuple(_value("answer", b.get("key"), b.get("doc_count")) for b in answers),
        ))  # fmt: skip
    timeline: list[dict[str, Any]] = [
        {"key": b.get("key"), "doc_count": _count(b)} for b in _buckets(aggs, "timeline")
    ]
    busy = [b for b in timeline if b["doc_count"] > 0]
    first = _ms_time(busy[0].get("key")) if busy else None
    last = _ms_time(busy[-1].get("key")) if busy else None
    if first is not None and last is not None:
        slots, regular = proxy.cadence(timeline)
        how = "" if regular is None else f", regularity {regular} (0 = perfectly even)"
        try:
            until: datetime | None = last + timedelta(minutes=10)
        except OverflowError:
            until = None
        out.append(Fact(
            key=f"{base}:activity", kind="observation", name="proxy.host activity",
            sentence=f"{who}'s proxy traffic ran in {slots} ten-minute periods{how}.",
            status="known", eids=eids, from_logs=True, at=first, until=until,
            when=f"{who}'s proxy traffic in the window read",
        ))  # fmt: skip
    return out


def _proxy_destination(
    base: str, eids: tuple[str, ...], aggs: Mapping[str, Any], other: bool = False
) -> list[Fact]:
    out = []
    where = "another destination" if other else "the destination"
    hosts = _buckets(aggs, "hosts")[:TOP]
    count = _number(aggs, "host_count")
    if hosts:
        finite = count is not None and count == count and abs(count) != inf
        many = f"{int(count)} " if finite and count is not None else ""
        out.append(Fact(
            key=f"{base}:hosts", kind="observation", name="proxy.destination hosts",
            sentence=f"The {many}{site.own('hosts')} that reached {where} through the proxy"
                     f" ({len(hosts)} shown).",
            status="known", eids=eids, from_logs=True,
            values=tuple(_value("host", b.get("key"), b.get("doc_count")) for b in hosts),
        ))  # fmt: skip
    urls = _buckets(aggs, "urls")[:TOP]
    if urls:
        out.append(Fact(
            key=f"{base}:urls", kind="observation", name="proxy.destination urls",
            sentence=f"The most requested addresses at {where} ({len(urls)} shown).",
            status="known", eids=eids, from_logs=True,
            values=tuple(_value("URL", b.get("key"), b.get("doc_count")) for b in urls),
        ))  # fmt: skip
    return out


def _rows(snapshot: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    rows = snapshot.get("rows")
    out = []
    for r in rows if isinstance(rows, list) else []:
        source = r.get("_source") if isinstance(r, Mapping) else None
        if isinstance(source, Mapping):
            out.append(source)
    return out


def _first(doc: Mapping[str, Any], path: str) -> Any:
    found = field_values(doc, path)
    return found[0] if found else None


def _web_followups(
    base: str, eids: tuple[str, ...], snapshot: Mapping[str, Any], other: bool = False
) -> list[Fact]:
    rows = _rows(snapshot)
    if not rows:
        return []
    who = "Another client" if other else "The client"
    times = [t for t in (_when(_first(r, "@timestamp")) for r in rows) if t is not None]
    shown = []
    for r in rows[:TOP]:
        method = _first(r, "http.request.method")
        site, path = _first(r, "url.domain"), _first(r, "url.path")
        status = _first(r, "http.response.status_code")
        text = " ".join(str(v) for v in (status, method, site, path) if v is not None)
        shown.append(_value("answer", text))
    return [
        Fact(
            key=f"{base}:successes",
            kind="observation",
            name="web.followups successes",
            sentence=f"{who} got {len(rows)} successful (2xx) answers after the first"
            f" alert ({len(shown)} shown).",
            status="known",
            eids=eids,
            from_logs=True,
            values=tuple(shown),
            at=min(times) if times else None,
            until=max(times) if times else None,
            when=f"{who}'s successful answers after the first alert",
        )
    ]


def _ti_lookup(
    base: str, eids: tuple[str, ...], snapshot: Mapping[str, Any], other: bool = False,
    where: str = "the threat lists",
) -> list[Fact]:  # fmt: skip
    found = [i for r in _rows(snapshot) for i in indicators_of(r)]
    if not found:
        return []
    seen = [i.last_seen for i in found if i.last_seen is not None]
    shown = tuple(
        _value(f"listed {i.kind}", i.value + (f" ({i.description})" if i.description else ""))
        for i in found[:TOP]
    )
    return [
        Fact(
            key=f"{base}:listed",
            kind="observation",
            name="ti.lookup listed",
            sentence=f"{where} lists {len(found)} of the indicators looked up.",
            status="known",
            eids=eids,
            from_logs=False,
            leaning="suspicious",
            values=shown,
            at=max(seen) if seen else None,
            when=f"{where}'s latest sighting of a listed indicator",
        )
    ]


Observer = Callable[[str, tuple[str, ...], Mapping[str, Any], bool], list[Fact]]
OBSERVERS: dict[str, tuple[str, Observer]] = {
    "proxy.host": ("aggregations", _proxy_host),
    "proxy.destination": ("aggregations", _proxy_destination),
    "web.followups": ("snapshot", _web_followups),
    "ti.lookup": ("snapshot", _ti_lookup),
}


def observations(request: RequestRow, row: EvidenceRow, other: bool = False) -> list[Fact]:
    """What a complete stored answer holds beyond its signals; nothing for a template
    without an observer, an answer that is not complete, or one too damaged to read (the
    observation is dropped, never the report). ``other``: the request asked about another
    subject than the one ARGUS's signals read."""
    if row.status not in COMPLETE or not isinstance(row.snapshot, Mapping):
        return []
    found = OBSERVERS.get(request.template)
    cls = REGISTRY.get(request.template)
    if found is None or cls is None or cls.version != request.template_version:
        return []
    kind, observe = found
    base = f"obs:{request.label}"
    eids = (request.label,)
    data = row.snapshot.get("aggregations") if kind == "aggregations" else row.snapshot
    if not isinstance(data, Mapping):
        return []
    try:
        if request.template == "ti.lookup":  # the sentence names the source it asked
            return _ti_lookup(base, eids, data, other, ti_where(row))
        return observe(base, eids, data, other)
    except Exception:  # a damaged stored answer: no observation from it
        return []
