"""From gaps to checks (Q-F3, plan §7.3 point 3): which requests a wave would send, in which
order, within a wave's caps, and what it leaves alone and why. Pure: the same gaps, material,
admissions and stored answers always give the same plan, and a plan made from a wave's own
results asks nothing more.

For each closable gap, best first, the first of its closers that can be asked is chosen: the
template must be switched on, its request buildable from the dossier, admitted by the rules
that need the database (the prevalence gate, the daily cap, quiet hours, health: ``admission``),
and not tried a moment ago and failed. An answer already stored for the same request is
**reused** (nothing is sent: it costs nothing and counts toward no cap). Sends are held to the
caps in rank order (requests, heavy requests); what does not fit is left with its reason.
Server time is a cap the executor keeps as answers arrive (a request's time is known only then).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal

from argus.context.batch1 import Refusal
from argus.context.evidence import COMPLETE
from argus.context.packs import TaskSpec
from argus.investigation import catalogue
from argus.investigation.gaps import Gap, Kind
from argus.report import facts as fx

RETRY_AFTER = timedelta(minutes=30)  # a check that failed is not asked again sooner
REASON_CHARS = 200  # evidence_requests.reason
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass(frozen=True)
class Caps:
    """What one wave may send: requests, heavy ones among them, and SIEM server time (kept by
    the executor as answers arrive)."""

    requests: int = 4
    heavy: int = 2
    server_ms: int = 4_000


@dataclass(frozen=True)
class Seen:
    """What the investigation already holds for a request (any version): its status and when."""

    status: str
    at: datetime | None = None


@dataclass(frozen=True)
class Candidate:
    template: str
    task: TaskSpec | Refusal  # the request, or why it cannot be built
    keys: tuple[str, ...]  # the open gaps it could close, best first
    rank: int  # the best of their ranks


Mode = Literal["send", "reuse", "skip"]


@dataclass(frozen=True)
class Planned:
    template: str
    mode: Mode
    task: TaskSpec | None
    task_key: str | None
    keys: tuple[str, ...]  # the gaps it is asked for
    rank: int
    reason: str  # what a person reads beside the check: the gaps it is asked for
    why_not: str | None  # when skipped: plain words
    heavy: bool

    @property
    def sends(self) -> bool:
        return self.mode == "send"


@dataclass(frozen=True)
class Plan:
    gaps: tuple[Gap, ...]
    checks: tuple[Planned, ...]  # reuse and send in the order to go, then the skipped
    left: tuple[tuple[str, str], ...]  # (gap key, why no check was planned for it)

    @property
    def sends(self) -> tuple[Planned, ...]:
        return tuple(c for c in self.checks if c.mode == "send")

    @property
    def reuses(self) -> tuple[Planned, ...]:
        return tuple(c for c in self.checks if c.mode == "reuse")


def candidates(
    gaps: Sequence[Gap], material: catalogue.Material, switches: catalogue.Switches
) -> list[Candidate]:
    """The requests every closable gap's open closers would make, one per template."""
    by: dict[str, list[Gap]] = {}
    for gap in gaps:
        if gap.closable:
            for template in gap.open:
                by.setdefault(template, []).append(gap)
    out = []
    for template in sorted(by, key=lambda t: (min(g.rank for g in by[t]), t)):
        wanted = by[template]
        task: TaskSpec | Refusal = Refusal("off")
        if switches.on(template):
            try:
                task = catalogue.build(template, material)
            except (KeyError, TypeError, ValueError, AttributeError):  # a damaged stored body
                task = Refusal("no_subject", "the dossier's data could not be read")
        out.append(Candidate(template, task, tuple(g.key for g in wanted),
                             min(g.rank for g in wanted)))  # fmt: skip
    return out


def task_key(task: TaskSpec) -> str:
    return str(task.ref()["task_key"])


def _reason(keys: Sequence[str], gaps: Mapping[str, Gap], template: str) -> str:
    said = "; ".join(gaps[k].what.rstrip(".") for k in keys if k in gaps)
    return fx.cap(f"{catalogue.CHECKS[template].said} — for: {said}", REASON_CHARS)


def choose(
    gaps: Sequence[Gap],
    cands: Sequence[Candidate],
    admission: Mapping[str, Refusal | None],
    seen: Mapping[str, Seen],
    caps: Caps,
    now: datetime,
) -> Plan:
    """The plan: ``admission`` maps a request's task key to the rule that would refuse it now
    (None or missing: admitted); ``seen`` maps a task key to the answer the investigation holds."""
    by_key = {g.key: g for g in gaps}
    cand = {c.template: c for c in cands}
    chosen: dict[str, Planned] = {}
    skipped: dict[str, Planned] = {}
    left: list[tuple[str, str]] = []
    sends = heavy = 0
    for gap in gaps:
        if not gap.closable:
            continue
        if any(t in chosen for t in gap.open):  # an earlier gap's check answers this one too
            continue
        why: list[str] = []
        for template in gap.open:
            c = cand.get(template)
            if c is None:
                continue
            words = catalogue.CHECKS[template].said
            if isinstance(c.task, Refusal):
                why.append(f"{words}: {c.task.sentence}")
                continue
            key = task_key(c.task)
            hold = seen.get(key)
            refused = admission.get(key)
            is_heavy = catalogue.is_heavy(template)
            reason = _reason(c.keys, by_key, template)
            if hold is not None and hold.status in COMPLETE:
                chosen[template] = Planned(template, "reuse", c.task, key, c.keys, c.rank,
                                           reason, None, is_heavy)  # fmt: skip
                break
            if hold is not None and hold.at is not None and now - hold.at < RETRY_AFTER:
                why.append(f"{words}: tried a moment ago and failed")
            elif refused is not None:
                why.append(f"{words}: {refused.sentence}")
            elif sends + 1 > caps.requests:
                why.append(f"{words}: this wave's request limit")
            elif is_heavy and heavy + 1 > caps.heavy:
                why.append(f"{words}: this wave's limit of heavy requests")
            else:
                sends += 1
                heavy += is_heavy
                chosen[template] = Planned(template, "send", c.task, key, c.keys, c.rank,
                                           reason, None, is_heavy)  # fmt: skip
                break
        else:
            left.append((gap.key, "; ".join(why) or "no request could be built for it"))
            for template in gap.open:
                c = cand.get(template)
                if c is not None and template not in skipped:
                    words = catalogue.CHECKS[template].said
                    task = c.task if isinstance(c.task, TaskSpec) else None
                    skipped[template] = Planned(
                        template, "skip", task, None if task is None else task_key(task),
                        c.keys, c.rank, _reason(c.keys, by_key, template),
                        next((w for w in why if w.startswith(words)), "no request"),
                        catalogue.is_heavy(template),
                    )  # fmt: skip
    ordered = sorted(chosen.values(), key=lambda p: (p.rank, catalogue.CHECKS[p.template].weight,
                                                      p.template))  # fmt: skip
    rest = sorted((p for t, p in skipped.items() if t not in chosen),
                  key=lambda p: (p.rank, p.template))  # fmt: skip
    return Plan(tuple(gaps), (*ordered, *rest), tuple(left))


def priority(gaps: Sequence[Gap], severity: str | None) -> tuple[int, int, int, int, int]:
    """Which undecided investigation a wave takes first (plan §7.3 coverage): one with a
    closable floor gap, then the higher severity, then a threat-intel gap, a beacon gap, a gap
    about successes after an attack. Smaller goes first."""
    closable = [g for g in gaps if g.closable]

    def has(name: str) -> int:
        return 0 if any(g.key == f"signal:{name}" for g in closable) else 1

    return (
        0 if any(g.kind is Kind.FLOOR for g in closable) else 1,
        SEVERITY.get(str(severity or "").lower(), len(SEVERITY)),
        min(has("ti.listed"), has("ti.listed_remote")),
        has("proxy.regularity"),
        has("web.successes_after"),
    )
