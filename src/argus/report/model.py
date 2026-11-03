"""The report@2 contract: frozen, no unknown fields, every list a tuple.

Sentences are ARGUS's wording but may quote a value; ``Value.text``, ``Cite.quote``, a step's
``text`` and ``Summary.text`` (the model's explanation) are untrusted, and a page shows every text
as untrusted text. Times are UTC. ``from_logs`` marks everything derived from log content, so a
person without log access in ELK sees "Hidden: needs log access in ELK." instead
(``render.hide_logs``)."""

from __future__ import annotations

from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict

FORMAT: Final = "report@2"
HIDDEN = "Hidden: needs log access in ELK."

Origin = Literal["pack", "agent", "wave", "person", "watch"]
# "hidden": a log check's result, for a person without log access (render.hide_logs)
Outcome = Literal["found", "nothing_found", "could_not_tell", "failed", "not_run", "hidden"]
Leaning = Literal["suspicious", "reassuring", "neutral"]
Stance = Literal["supports", "contradicts", "neutral"]
FactKind = Literal["signal", "observation", "step", "alert"]
ItemKind = Literal[
    "new", "nothing_found", "could_not_tell", "failed", "not_checked", "still_open", "hidden"
]
Grade = Literal["strong", "moderate", "weak"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Value(_Model):
    """An untrusted value (from logs, alerts or a threat list) shown beside ARGUS's sentence,
    never inside it."""

    label: str
    text: str
    count: int | None = None


class Provenance(_Model):
    """Where one evidence request's answer came from: the query and what it returned."""

    eid: str  # E3: opaque, unique within the investigation
    template: str  # proxy.host@1
    origin: Origin
    reason: str | None = None
    subject: str | None = None  # what it asked about (an address, indicators): untrusted
    family: str  # log, alerts, ti, cluster; unknown: a template this version no longer has
    source: str | None = None  # a log source (squid) or a threat-intel index
    window_start: datetime | None = None
    window_end: datetime | None = None
    indices: tuple[str, ...] = ()  # what the request read (the ledger), when known
    status: str  # the evidence row's: ok, empty, timeout, ...; "missing": no row
    rows: int | None = None
    truncated: bool = False
    exact: bool = True  # the total was exact, not a lower bound
    server_ms: int | None = None
    result_hash: str | None = None
    watermark: datetime | None = None  # the source's ingest watermark, when measured
    collected_at: datetime | None = None
    version: int | None = None  # the investigation version of the evidence row
    reused_from_version: int | None = None
    attempts: int | None = None  # of the ledger row that answered it
    line: str  # E3 · proxy.host@1 · about 10.20.3.4 · squid, 09 Oct 03:30-08:30 UTC · ...
    from_logs: bool


class Fact(_Model):
    key: str  # stable identity: signal:<name>, step:<n>, obs:<eid>:<part>, alert:<part>
    kind: FactKind
    name: str
    sentence: str
    status: Literal["known", "unknown"]
    why: str | None = None  # unknown: why, in plain words
    eids: tuple[str, ...] = ()  # the evidence requests it comes from (none: the stored alerts)
    source: str | None = None  # a store of ARGUS's it comes from (a threat-list answer, ...)
    from_logs: bool = False
    leaning: Leaning = "neutral"
    values: tuple[Value, ...] = ()
    text: str | None = None  # a step's own text (untrusted: the rule's note)
    at: datetime | None = None  # when it happened, for the timeline
    until: datetime | None = None
    when: str | None = None  # what ``at`` (and ``until``) mark, as the timeline says it


class Check(_Model):
    """One evidence request and what it came to."""

    eid: str
    template: str
    origin: Origin
    outcome: Outcome
    sentence: str
    why: str | None = None
    from_logs: bool
    server_ms: int | None = None
    line: str


class Change(_Model):
    """A signal or a step that changed between two views."""

    key: str
    name: str
    before: str | None  # its sentence before (None: it did not exist)
    after: str
    eids: tuple[str, ...] = ()
    from_logs: bool = False


class Gap(_Model):
    """Something ARGUS could not tell, and who can resolve it."""

    key: str
    what: str
    why: str
    who: str
    floor: bool = False  # it blocks a benign proposal (the floor)
    eids: tuple[str, ...] = ()
    from_logs: bool = False


class WhatsNew(_Model):
    """A pure diff of two views of a dossier (``diff.diff``): empty for a view and itself."""

    new_facts: tuple[Fact, ...] = ()
    now_known: tuple[Change, ...] = ()
    changed: tuple[Change, ...] = ()
    steps_answered: tuple[Change, ...] = ()
    gaps_closed: tuple[Gap, ...] = ()
    gaps_opened: tuple[Gap, ...] = ()
    checks: tuple[Check, ...] = ()

    def empty(self) -> bool:
        return not any(
            (
                self.new_facts,
                self.now_known,
                self.changed,
                self.steps_answered,
                self.gaps_closed,
                self.gaps_opened,
                self.checks,
            )
        )


class Item(_Model):
    """One line of "What ARGUS found with extra SIEM queries"."""

    kind: ItemKind
    sentence: str
    eids: tuple[str, ...] = ()
    from_logs: bool = False
    values: tuple[Value, ...] = ()
    note: str | None = None  # the check's short provenance


class Found(_Model):
    """What every SIEM query of this investigation version found, against the alerts alone."""

    checks: int
    server_ms: int
    items: tuple[Item, ...]
    new: WhatsNew


class Cite(_Model):
    quote: str  # untrusted: the model's quote of what it read
    eids: tuple[str, ...] = ()


class Summary(_Model):
    """The model's explanation, only where an agent assessed."""

    text: str  # untrusted: model text, revealed
    cites: tuple[Cite, ...]
    checked: bool  # every quote was found in what the model read
    note: str


class Verdict(_Model):
    status: str  # proposed, no_decision, queued, running, failed; none: not assessed
    outcome: str | None = None
    assessor: str | None = None
    source: str  # the decision engine, the AI investigator, nobody yet
    decided_by: str | None = None
    model_confidence: float | None = None  # only a model's
    why: tuple[str, ...] = ()
    at: datetime | None = None


class Strength(_Model):
    """How much the evidence holds, apart from any confidence: numbers by code."""

    grade: Grade
    floor_known: int
    floor_total: int
    checks_complete: int
    checks_total: int
    steps_answered: int
    steps_total: int
    alerts_read: int
    alerts_total: int
    reasons: tuple[str, ...]


class Event(_Model):
    at: datetime
    until: datetime | None = None
    kind: Literal["alert", "fact", "check", "verdict"] = "fact"  # a fact's times are its data's
    sentence: str
    eids: tuple[str, ...] = ()
    from_logs: bool = False
    values: tuple[Value, ...] = ()


class Row(_Model):
    """A line of the evidence table: a known fact and how it bears on the verdict."""

    fact: Fact
    stance: Stance


class FactRef(_Model):
    key: str
    text: str
    eids: tuple[str, ...] = ()
    from_logs: bool = False


class Hypothesis(_Model):
    name: str
    by: Literal["argus", "model"]
    support: tuple[FactRef, ...] = ()
    against: tuple[FactRef, ...] = ()


class Action(_Model):
    text: str
    who: str
    why: str | None = None


class Cost(_Model):
    siem_requests: int  # requests this version's checks sent (not reused, not skipped)
    siem_server_ms: int
    reused: int  # answers copied from an earlier version, no request
    model_calls: int = 0
    model_cost_usd: float = 0.0
    models: tuple[str, ...] = ()
    seconds: float | None = None


class Report(_Model):
    format: Literal["report@2"] = FORMAT
    investigation_id: str
    version: int
    pack: str
    dossier_hash: str
    assessment_id: int | None = None
    recomputed: bool  # the pack recomputed both views; else the stored dossier was used
    note: str | None = None
    summary: Summary | None = None
    verdict: Verdict
    strength: Strength
    found: Found
    timeline: tuple[Event, ...]
    relative_to: str  # the outcome the evidence table and stances are read against
    evidence: tuple[Row, ...]
    hypotheses: tuple[Hypothesis, ...]
    unknowns: tuple[Gap, ...]
    actions: tuple[Action, ...]
    cost: Cost
    provenance: tuple[Provenance, ...]
    hidden: int = 0  # log checks whose results are hidden for lack of log access
