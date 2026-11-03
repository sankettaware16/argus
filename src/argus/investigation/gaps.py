"""Finding the gaps in a dossier, ranked. Pure: the same inputs always give the same list.

Most important first: unknown floor signals (what blocks a benign proposal), deferred note steps,
unknown steps, unknown signals, low confidence, conflicts (a threat and a calming signal) and scope
after a verified true positive. A gap says which templates could answer it (``closers``, found by
what they answer and the rule's own indices, never its name), which were already asked
(``exhausted``) and, when none can be asked, why (``blocker``).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from argus.context import notes
from argus.context.evidence import COMPLETE
from argus.investigation import catalogue
from argus.report import facts as fx

LOW = 0.6  # an assessor's confidence below this is a gap
VERIFIED = 0.8  # a true positive this sure (or a person's) is verified
# Why a signal is unknown and asking again can change it: nothing was asked, or the SIEM did
# not answer in time, was busy, or the logs had not arrived. Every other reason stays whatever
# the check says (a zero from the logs, a cut answer, a stale list, a field no alert has).
RETRY = frozenset(
    {"no_evidence", "timeout", "failed", "skipped_budget", "deferred", "source_lag",
     "unavailable", "source_not_checked"}
)  # fmt: skip
EVENT_RULES = ("query", "saved_query", "eql", "new_terms", "threat_match")  # one event each


class Kind(StrEnum):
    FLOOR = "floor_signal"
    DEFERRED = "deferred_step"
    UNKNOWN_STEP = "unknown_step"
    SIGNAL = "unknown_signal"
    CONFIDENCE = "low_confidence"
    CONFLICT = "conflict"
    SCOPE = "scope"


ORDER = tuple(Kind)


@dataclass(frozen=True)
class Profile:
    """What the gap detector needs of the rule besides the dossier: its type and its own
    indices (never its name)."""

    rule_type: str | None = None
    indices: tuple[str, ...] = ()

    @property
    def sources(self) -> frozenset[str]:
        return catalogue.sources_of(self.indices)


@dataclass(frozen=True)
class Assessed:
    """An assessor's answer about the dossier, if there is one."""

    outcome: str | None = None  # None: no decision
    confidence: float | None = None
    assessor: str | None = None
    reasons: tuple[str, ...] = ()
    by_person: bool = False  # a person's own verdict


@dataclass(frozen=True)
class Gap:
    kind: Kind
    key: str  # stable: signal:<name>, step:<n>, confidence, conflict, scope
    rank: int  # 1 is first
    what: str  # a plain sentence
    why: str
    closers: tuple[str, ...]  # templates that could answer it, best first (the rule's sources)
    exhausted: tuple[str, ...]  # closers already asked, with a stored answer
    blocker: str | None  # why no check can close it now; None: closable
    floor: bool = False  # it blocks a benign proposal

    @property
    def closable(self) -> bool:
        return self.blocker is None

    @property
    def open(self) -> tuple[str, ...]:
        """The closers still to ask."""
        return tuple(c for c in self.closers if c not in self.exhausted)


def _list(value: Any) -> list[Any]:
    """A stored list, or nothing: a damaged body never breaks the ranking."""
    return value if isinstance(value, list) else []


def _signals(body: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    out: dict[str, Mapping[str, Any]] = {}
    for s in [*_list(body.get("local_signals")), *_list(body.get("signals"))]:
        if isinstance(s, Mapping) and isinstance(s.get("name"), str):
            out[s["name"]] = s
    return out


def _number(step: Mapping[str, Any]) -> int:
    number = step.get("number")
    return number if isinstance(number, int) and not isinstance(number, bool) else 0


def _steps(body: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    report = body.get("report")
    steps = report.get("steps") if isinstance(report, Mapping) else None
    found = [s for s in steps if isinstance(s, Mapping)] if isinstance(steps, list) else []
    return sorted(found, key=_number)


def asked(body: Mapping[str, Any]) -> dict[str, str]:
    """Each template the dossier lists evidence of, with its best status (a stored answer
    beats a failure)."""
    best: dict[str, str] = {}
    for ref in _list(body.get("evidence")):
        if not isinstance(ref, Mapping):
            continue
        name = str(ref.get("template") or "").rpartition("@")[0]
        status = str(ref.get("status") or "")
        if name and (name not in best or (status in COMPLETE and best[name] not in COMPLETE)):
            best[name] = status
    return best


def _exhausted(closers: Sequence[str], done: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(c for c in closers if done.get(c) in COMPLETE)


def _gap(
    kind: Kind, key: str, what: str, why: str, closers: Sequence[str], done: Mapping[str, str],
    blocker: str | None, floor: bool = False,
) -> Gap:  # fmt: skip
    """A gap with its blocker: the given one, else (none to ask) why nothing can be asked."""
    spent = _exhausted(closers, done)
    if blocker is None and not closers:
        blocker = "the rule reads no log that could answer it"
    elif blocker is None and len(spent) == len(closers):
        blocker = "it was asked already and the answer did not settle it"
    return Gap(kind, key, 0, what, why, tuple(closers), spent, blocker, floor)


def _signal_gap(name: str, s: Mapping[str, Any], profile: Profile, done: Mapping[str, str]) -> Gap:
    code = str(s.get("unknown_reason") or "")
    closers = catalogue.closers(f"signal:{name}", profile.sources)
    floor = name in fx.FLOOR
    blocker = None
    if code not in RETRY:
        blocker = fx.plain(code)
    elif not catalogue.closers(f"signal:{name}", frozenset(catalogue.log_sources())):
        blocker = "no check ARGUS can make answers it"
    return _gap(Kind.FLOOR if floor else Kind.SIGNAL, f"signal:{name}",
                f"{fx.label(name)}: could not tell.", fx.plain(code), closers, done, blocker,
                floor)  # fmt: skip


def _deferred(step: Mapping[str, Any], profile: Profile, done: Mapping[str, str]) -> Gap:
    needs = [str(n) for n in _list(step.get("needs"))]
    words = " and ".join(sorted({notes.CAPABILITIES.get(n, n) for n in needs}))
    found: list[str] = []
    for need in needs:
        for template in catalogue.closers(f"capability:{need}", profile.sources):
            if template not in found:
                found.append(template)
    ordered = sorted(found, key=lambda t: (catalogue.CHECKS[t].weight, t))
    return _gap(Kind.DEFERRED, f"step:{step.get('number')}",
                f"Step {step.get('number')} of the rule's note.", f"it needs {words}", ordered,
                done, None)  # fmt: skip


def _unknown_step(step: Mapping[str, Any], profile: Profile, done: Mapping[str, str]) -> Gap:
    n = step.get("number")
    what, why = f"Step {n} of the rule's note.", "no alert carries the fields it names"
    if profile.rule_type in ("threshold", "esql"):
        # an aggregated alert has no event of its own: the rows behind it have the fields
        closers = catalogue.closers("capability:source_events", profile.sources)
        return _gap(Kind.UNKNOWN_STEP, f"step:{n}", what, why, closers, done, None)
    if profile.rule_type in EVENT_RULES:
        why += "; its events' ancestors are in endpoint logs ARGUS has no check for"
        blocker = "ARGUS has no check for the events before this one yet"
    else:
        blocker = "the rule's type is not known, so ARGUS cannot tell where to look"
    return _gap(Kind.UNKNOWN_STEP, f"step:{n}", what, why, (), done, blocker)


def _confidence(a: Assessed, profile: Profile, done: Mapping[str, str]) -> Gap | None:
    if a.outcome is None:
        return None
    unsure = a.outcome == "inconclusive" or (a.confidence is not None and a.confidence < LOW)
    if not unsure:
        return None
    who = fx.cap(a.assessor or "the assessor", 40)
    if a.outcome == "inconclusive":
        what, why = f"{who} could not decide.", "what it was shown was not enough"
    else:
        what = f"{who} is not sure of its answer ({a.confidence:.2f})."
        why = "it had little evidence to go on"
    closers = catalogue.available(catalogue.INDEPENDENT, profile.sources)
    return _gap(Kind.CONFIDENCE, "confidence", what, why, closers, done, None)


def _conflict(
    sig: Mapping[str, Mapping[str, Any]], a: Assessed | None, profile: Profile,
    done: Mapping[str, str],
) -> Gap | None:  # fmt: skip
    lean = {n: fx.leaning(s) for n, s in sig.items()}
    threat = sorted(n for n, v in lean.items() if v == "suspicious")
    calm = sorted(n for n, v in lean.items() if v == "reassuring")
    disagree = a is not None and any("keys disagree" in r for r in a.reasons)
    if not (threat and calm) and not disagree:
        return None
    if threat and calm:
        what = (f"{fx.label(threat[0])} points to a threat, and {fx.label(calm[0])} points"
                " away from one.")  # fmt: skip
        why = "the evidence disagrees with itself"
    else:
        what, why = "What ARGUS learned from earlier reviews disagrees.", "its keys point both ways"
    closers = catalogue.available(catalogue.INDEPENDENT, profile.sources)
    return _gap(Kind.CONFLICT, "conflict", what, why, closers, done, None)


def _scope(
    sig: Mapping[str, Mapping[str, Any]], a: Assessed | None, profile: Profile,
    done: Mapping[str, str],
) -> Gap | None:  # fmt: skip
    if a is None or a.outcome != "true_positive":
        return None
    if not (a.by_person or (a.confidence is not None and a.confidence >= VERIFIED)):
        return None
    reach = sig.get("contact.hosts", {}).get("status") == "known"
    going = sig.get("pair.still_active", {}).get("status") == "known" or "proxy.pair" in done
    if reach and going:
        return None
    closers = catalogue.available(catalogue.SCOPE, profile.sources)
    return _gap(
        Kind.SCOPE,
        "scope",
        "Who else is affected, and whether it is still going on.",
        "the incident is confirmed; its reach is not known",
        closers,
        done,
        None,
    )


def find(
    body: Mapping[str, Any], profile: Profile, assessed: Assessed | None = None
) -> tuple[Gap, ...]:
    """The gaps of a dossier body, ranked (1 is the most important). ``assessed`` is the
    assessor's answer about it, if any (for low confidence, conflicts and scope)."""
    sig = _signals(body)
    done = asked(body)
    groups: dict[Kind, list[Gap]] = {k: [] for k in Kind}
    unknown = {n: s for n, s in sig.items() if s.get("status") != "known"
               and not n.startswith("steps.")}  # fmt: skip
    for name in [n for n in fx.FLOOR if n in unknown]:
        groups[Kind.FLOOR].append(_signal_gap(name, unknown[name], profile, done))
    for step in _steps(body):
        status = str(step.get("status"))
        if status == "deferred":
            groups[Kind.DEFERRED].append(_deferred(step, profile, done))
        elif status == "unknown":
            groups[Kind.UNKNOWN_STEP].append(_unknown_step(step, profile, done))
    for name in sorted(n for n in unknown if n not in fx.FLOOR):
        groups[Kind.SIGNAL].append(_signal_gap(name, unknown[name], profile, done))
    extra = (
        (Kind.CONFIDENCE, None if assessed is None else _confidence(assessed, profile, done)),
        (Kind.CONFLICT, _conflict(sig, assessed, profile, done)),
        (Kind.SCOPE, _scope(sig, assessed, profile, done)),
    )
    for kind, gap in extra:
        if gap is not None:
            groups[kind].append(gap)
    ranked = [g for kind in ORDER for g in groups[kind]]
    return tuple(_ranked(g, i) for i, g in enumerate(ranked, start=1))


def _ranked(gap: Gap, rank: int) -> Gap:
    return Gap(gap.kind, gap.key, rank, gap.what, gap.why, gap.closers, gap.exhausted,
               gap.blocker, gap.floor)  # fmt: skip
