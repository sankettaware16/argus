"""The incident report's contract: ``incident-report@1``.

A report is a structured, versioned object, stored whole (``incident_reports.body``) and served by
``/api/v1``: summary, ARGUS's verdict with its confidence, timeline, actors and affected assets,
evidence (each line with the exact query behind it), hypotheses, indicators and recommended
actions. Rendering it is a function of this object and nothing else. The model keeps the rules
itself, so a stored report can be trusted: counts, times and lists come from code (a
:class:`ReportFact` carries its figures; :func:`check` refuses a sentence that cites nothing, cites
a missing fact or writes a number no cited fact writes); every evidence line has a query; times are
UTC and timezone-aware; text from logs or alerts is untrusted and capped."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Final, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

SCHEMA: Final = "incident-report@1"
WRITER: Final = "incident-writer@4"  # the writer's version: a new one is a new report
HIDDEN: Final = "Hidden: needs log access in ELK."

# The web's Outcome order: typing caches equal Literals as one, so a second order flips the spec.
Outcome = Literal[
    "benign_expected", "benign_policy", "rule_false_positive", "true_positive", "inconclusive"
]
OUTCOMES: Final[tuple[str, ...]] = (
    "true_positive", "benign_expected", "benign_policy", "rule_false_positive", "inconclusive",
)  # fmt: skip
Standing = Literal["ongoing", "quiet", "unknown"]
FactKind = Literal["alerts", "entity", "evidence", "intel", "notice", "case", "verdict", "action"]
VerdictKind = Literal["person", "proposal", "reading", "case", "none"]
HypothesisStatus = Literal["kept", "ruled_out", "open"]
QueryKind = Literal["alerts", "logs", "intel"]
Language = Literal["kql", "esql"]

TEXT = 600  # a sentence of code's wording
UNTRUSTED = 300  # a value that came from logs or alerts, as stored


class _M(BaseModel):
    # serving: a field with a default is still always there in an answer (the client reads it so)
    model_config = ConfigDict(
        extra="forbid", frozen=True, json_schema_serialization_defaults_required=True
    )


class ReportFact(_M):
    """One verified fact: a sentence written by code from stored data, with the figures it
    states (``numbers``) so a check can hold any sentence that cites it to them. ``source`` says
    where ARGUS read it; ``from_logs`` marks a fact derived from log content (an account without
    log access sees it hidden). ``safe`` is the same fact without a campus address, host or
    account, the only form a model is ever shown (None: it cannot be said without one)."""

    id: str = Field(pattern=r"^F[0-9]{1,5}$")
    kind: FactKind
    text: str = Field(min_length=1, max_length=TEXT)
    source: str = Field(min_length=1, max_length=200)
    numbers: tuple[float, ...] = ()
    from_logs: bool = False
    safe: str | None = Field(default=None, max_length=TEXT)


class ReportSentence(_M):
    """A sentence of the narrative with the facts it rests on. ``by`` is ``code`` (the
    deterministic writer) or ``model`` (words a model chose, after the citation checks)."""

    text: str = Field(min_length=1, max_length=TEXT)
    cites: tuple[str, ...] = Field(default=(), max_length=12)
    by: Literal["code", "model"] = "code"


class ReportQuery(_M):
    """The exact query behind a line of evidence, read-only. ``text`` is KQL (``language`` kql)
    or ES|QL; ``url`` opens it in Discover over the same time range. ``template`` names the
    ARGUS check that ran it (``proxy.pair@1``; ``alerts`` for the stored alerts)."""

    kind: QueryKind
    language: Language
    index: str = Field(max_length=200)
    text: str = Field(max_length=4000)
    other: str | None = Field(default=None, max_length=4000)  # the same query in the other language
    time_from: AwareDatetime
    time_to: AwareDatetime
    url: str = Field(max_length=8000)
    template: str = Field(max_length=100)


class ReportDetail(_M):
    """A deciding value of an evidence line's stored answer (a URL without its query string, a
    kind of log event, the requests' rhythm): untrusted text from the logs, capped, and how many
    requests or rows of the answer it counts (None: not a count)."""

    text: str = Field(min_length=1, max_length=UNTRUSTED)
    count: int | None = Field(default=None, ge=0)


class ReportEvidenceLine(_M):
    id: str = Field(pattern=r"^E[0-9]{1,5}$")
    fact: str = Field(pattern=r"^F[0-9]{1,5}$")  # the fact that says what it showed
    title: str = Field(max_length=200)
    source: str = Field(max_length=200)
    status: str = Field(max_length=40)  # ok, empty, timeout, failed, ...: how the check ended
    count: int | None = None  # the check's row count, when it had one
    at: AwareDatetime | None = None  # when ARGUS ran it
    query: ReportQuery
    from_logs: bool = False
    # the values the check asked about (an address, a host, a destination, the values of a
    # threat-list look-up): they name the line, so two lines of one check are told apart
    asked: tuple[str, ...] = Field(default=(), max_length=12)
    # what the stored answer showed that decides the case (``details``, at most six), under
    # ARGUS's own label for them; read from the logs, so hidden with the line's count
    shows: str | None = Field(default=None, max_length=200)
    details: tuple[ReportDetail, ...] = Field(default=(), max_length=6)


class ReportHeader(_M):
    # any prefix: the site's (``site.incident_id_prefix``) is applied where the ID is made, and a
    # report keeps the ID it was made with; the database check allows the same shape
    incident_id: str = Field(pattern=r"^[A-Z][A-Z0-9-]{0,15}-[0-9]{4}-[0-9]{4}-[0-9]{2}$")
    title: str = Field(max_length=300)  # "<incident id> · what happened"
    case_number: int
    case_id: str
    case_state: str
    severity: str
    opened_in: str = Field(max_length=160)  # "suspected by ARGUS" / "confirmed by a person"
    detected_by: str = Field(max_length=500)
    first_alert_at: AwareDatetime | None
    last_alert_at: AwareDatetime | None
    tags: tuple[str, ...] = ()  # the Kibana case's key:value tags
    # when the first and the newest alert were made (their own @timestamp, which the live
    # charts plot): a rule's lookback or a late run makes them later than the events; None in a
    # report written before they were kept
    first_detected_at: AwareDatetime | None = None
    last_detected_at: AwareDatetime | None = None
    # the certainty word that leads ARGUS's title (naming v2), so Kibana's title can leave it
    # out (only confirmed cases go there); None: a person's title, or none
    certainty: str | None = Field(default=None, max_length=40)


class ReportNotice(_M):
    """AR4b's notice state of the case (D-169): the owner was told, the alerts since."""

    notified_at: AwareDatetime
    told: tuple[str, ...] = ()
    blocked_at: AwareDatetime | None = None
    alerts_since: int = 0
    last_alert_at: AwareDatetime | None = None
    still_active: bool = False
    changes: int = 0  # changes since the notice that nobody has reviewed
    line: str = Field(max_length=500)


class ReportSummary(_M):
    headline: str = Field(max_length=400)
    standing: Standing
    standing_words: str = Field(max_length=300)
    sentences: tuple[
        ReportSentence, ...
    ]  # code's wording: always there, the whole summary without prose
    notice: ReportNotice | None = None
    prose: tuple[ReportSentence, ...] = ()  # a model's wording of the same facts, after the checks
    prose_note: str | None = Field(
        default=None, max_length=300
    )  # why the model's text was not used


class ReportVerdict(_M):
    outcome: Outcome | None
    words: str = Field(max_length=300)
    kind: VerdictKind
    confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_words: str | None = Field(default=None, max_length=60)
    source: str = Field(max_length=200)
    sentences: tuple[ReportSentence, ...] = ()
    # the case's investigations people reviewed (a person's verdict rests on them) and all its
    # investigations: a verdict is the case's only when every one was reviewed; 0 and 0 in a
    # report written before they were kept
    reviewed: int = Field(default=0, ge=0)
    investigations: int = Field(default=0, ge=0)


class ReportPhase(_M):
    name: str = Field(max_length=300)
    start: AwareDatetime
    end: AwareDatetime
    alerts: int
    sentence: ReportSentence


class ReportDayRow(_M):
    day: str = Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")  # a local day
    counts: tuple[int, ...]  # one for each column of the timeline
    total: int


class ReportTimeline(_M):
    first_seen: AwareDatetime | None
    last_seen: AwareDatetime | None
    dwell_seconds: int | None
    dwell_words: str | None = Field(default=None, max_length=100)
    phases: tuple[ReportPhase, ...] = ()
    columns: tuple[str, ...] = ()  # what the day table counts (rule names; "other")
    days: tuple[ReportDayRow, ...] = ()
    alerts: int = 0
    notes: tuple[ReportSentence, ...] = ()


class ReportActor(_M):
    value: str = Field(max_length=200)
    kind: Literal["ip", "host", "user"]
    role: str = Field(max_length=40)  # scout, collector, prober, beacon source, ...
    role_words: str = Field(max_length=400)
    inside: bool  # an internal address
    network: str | None = Field(default=None, max_length=200)
    country: str | None = Field(default=None, max_length=100)
    user_agents: tuple[str, ...] = ()
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    alerts: int = 0
    requests: int | None = None
    sentence: ReportSentence | None = None
    # what ARGUS holds about an outside address: on the local threat lists, what outside
    # services say, and whether the web server gave it successful (2xx) answers (None: no web
    # check or alert shows it) and for which paths (read from the logs: hidden without log access)
    listed: bool = False
    intel: str | None = Field(default=None, max_length=300)
    answered: int | None = None
    answered_exact: bool = True  # False: the count was read from a sample that hit its cap (20+)
    served: tuple[str, ...] = Field(default=(), max_length=5)


class ReportTarget(_M):
    """A campus web site or host that outside actors went against (D-240): where the alerts say
    the attack was aimed, with the alerts that named it and, when a stored web check or an alert's
    own record shows it, the successful (2xx) answers it gave and the paths they were for."""

    kind: Literal["site", "host"]
    value: str = Field(max_length=300)
    label: str | None = Field(default=None, max_length=200)  # a host: the place the asset map names
    alerts: int = 0
    actors: int = 0  # outside addresses of the case that went against it
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None
    answered: int | None = None
    answered_exact: bool = True
    served: tuple[str, ...] = Field(default=(), max_length=5)
    # an investigation behind ``alerts`` names another target of the same kind too, so its
    # alerts are counted under both: the counts of such targets overlap and add up to more
    shared: bool = False


class ReportAsset(_M):
    kind: Literal["device", "host", "directory", "account"]
    value: str = Field(max_length=300)
    label: str | None = Field(default=None, max_length=200)  # the domain it reached, the site, ...
    alerts: int = 0
    days: int = 0  # local days with an alert
    first_seen: AwareDatetime | None = None
    last_seen: AwareDatetime | None = None


UsersState = Literal["likely", "possible", "shared", "none_seen", "unknown"]


class ReportAccount(_M):
    """One account's sign-ins from a device (AR6, D-216). Personal data from the SSO logs:
    ``name`` is untrusted text and an account without log access never sees it (``view.hide_logs``
    drops the accounts)."""

    name: str = Field(min_length=1, max_length=300)
    device: str = Field(max_length=100)
    first_seen: AwareDatetime
    last_seen: AwareDatetime
    signins: int = 0
    failed: int = 0
    days: int = 0  # UTC days with a sign-in
    browsers: tuple[str, ...] = ()  # "Chrome on Windows"


class ReportDeviceUsers(_M):
    """Who used one of the case's devices: the state, in a sentence that cites a fact read from the
    logs, and the accounts it names (likely: one; possible: several; unknown: those seen so far)."""

    device: str = Field(max_length=100)
    state: UsersState
    sentence: ReportSentence
    accounts: tuple[ReportAccount, ...] = ()
    account_count: int = 0
    at_least: bool = False


class ReportSignin(_M):
    """A timeline entry: one account's sign-ins from one device on one day, as context."""

    at: AwareDatetime
    until: AwareDatetime | None = None
    device: str = Field(max_length=100)
    text: str = Field(max_length=600)


class ReportUsers(_M):
    """The accounts that signed in from the case's devices (AR6, D-216): the SSO logs' answer to
    "who was behind this address", a lead and not proof. Empty when the sign-in lookups are off or
    the case has no internal device."""

    lead: str = Field(default="", max_length=300)
    devices: tuple[ReportDeviceUsers, ...] = ()
    devices_total: int = 0
    signins: tuple[ReportSignin, ...] = ()


class ReportHypothesis(_M):
    name: str = Field(max_length=300)
    status: HypothesisStatus
    by: Literal["argus", "investigator"]
    why: tuple[ReportSentence, ...] = ()


class ReportIndicator(_M):
    kind: str = Field(max_length=20)
    value: str = Field(max_length=512)
    role: str = Field(max_length=20)  # actor, c2, indicator (the case's own)
    role_words: str = Field(max_length=100)
    source: str = Field(max_length=40)
    evidence: str = Field(max_length=500)


class ReportActionLine(_M):
    id: str = Field(max_length=100)  # the catalogue's id; "reminder.<kind>" for a reminder
    title: str = Field(max_length=200)
    say: str = Field(max_length=400)
    owner: str = Field(max_length=100)
    state: str = Field(max_length=30)
    family: str | None = Field(default=None, max_length=100)
    rank: int = 0


class ReportActions(_M):
    lines: tuple[ReportActionLine, ...] = ()
    close_when: ReportSentence | None = None
    note: str | None = Field(default=None, max_length=400)


class ReportMeta(_M):
    schema_version: Literal["incident-report@1"] = SCHEMA
    writer: str = Field(default=WRITER, max_length=40)
    as_at: AwareDatetime
    catalogue_version: int | None = None
    alerts_read: int = 0
    alerts_total: int = 0
    limits: tuple[str, ...] = ()  # what was cut or could not be read, in words
    # the fields a chart may split on (``glance.CHART_FIELDS``) that most of the alerts read
    # hold; None: not known (no alert was read, or the report was written before it was kept)
    carried: tuple[str, ...] | None = None


class IncidentReport(_M):
    header: ReportHeader
    summary: ReportSummary
    verdict: ReportVerdict
    timeline: ReportTimeline
    actors: tuple[ReportActor, ...] = ()
    outsiders_total: int = 0  # the outside addresses among all the actors (actors lists 25)
    assets: tuple[ReportAsset, ...] = ()
    assets_total: int = 0
    targets: tuple[ReportTarget, ...] = ()
    targets_total: int = 0
    users: ReportUsers = ReportUsers()
    evidence: tuple[ReportEvidenceLine, ...] = ()
    hypotheses: tuple[ReportHypothesis, ...] = ()
    indicators: tuple[ReportIndicator, ...] = ()
    indicators_total: int = 0
    actions: ReportActions = ReportActions()
    queries: tuple[ReportQuery, ...] = ()  # the checks a person runs to verify it, deduplicated
    out_of_scope: tuple[ReportSentence, ...] = ()
    facts: tuple[ReportFact, ...] = ()
    meta: ReportMeta

    @model_validator(mode="after")
    def _facts_hold(self) -> IncidentReport:
        problems = check(self)
        if problems:
            raise ValueError("; ".join(problems[:5]))
        return self


def sentences_of(report: IncidentReport) -> list[tuple[str, ReportSentence]]:
    """Every narrative sentence of the report with the part it belongs to."""
    out: list[tuple[str, ReportSentence]] = [("summary", s) for s in report.summary.sentences]
    out += [("summary", s) for s in report.summary.prose]
    out += [("verdict", s) for s in report.verdict.sentences]
    out += [("timeline", s) for s in report.timeline.notes]
    out += [("timeline", p.sentence) for p in report.timeline.phases]
    out += [("actors", a.sentence) for a in report.actors if a.sentence is not None]
    for h in report.hypotheses:
        out += [("hypotheses", s) for s in h.why]
    if report.actions.close_when is not None:
        out.append(("actions", report.actions.close_when))
    out += [("accounts", d.sentence) for d in report.users.devices]
    out += [("out_of_scope", s) for s in report.out_of_scope]
    return out


_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def digits_of(text: str) -> set[str]:
    """The numbers a text writes in digits (thousands commas dropped)."""
    return set(_NUMBER.findall(text.replace(",", "")))


def check(report: IncidentReport) -> list[str]:
    """What is wrong with the report's citations (empty: sound). A sentence cites at least one
    fact, every cited fact exists and states every number the sentence writes, an evidence
    line's fact exists and its query reads forward in time, and fact ids are unique."""
    problems: list[str] = []
    ids = [f.id for f in report.facts]
    if len(set(ids)) != len(ids):
        problems.append("a fact id is used twice")
    known = {f.id: f for f in report.facts}
    for part, sentence in sentences_of(report):
        if not sentence.cites:
            problems.append(f"a {part} sentence cites no fact")
        missing = [c for c in sentence.cites if c not in known]
        if missing:
            problems.append(f"a {part} sentence cites {missing[0]}, which is not a fact")
            continue
        held = set().union(*(digits_of(known[c].text) for c in sentence.cites), set())
        stray = digits_of(sentence.text) - held
        if stray:
            problems.append(f"a {part} sentence writes {min(stray)}, which its facts do not")
    lines = [e.id for e in report.evidence]
    if len(set(lines)) != len(lines):
        problems.append("an evidence line id is used twice")
    for line in report.evidence:
        if line.fact not in known:
            problems.append(f"{line.id} names {line.fact}, which is not a fact")
        if line.query.time_to < line.query.time_from:
            problems.append(f"{line.id}'s query ends before it starts")
    return problems


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False, default=_default)  # fmt: skip


def _default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"cannot serialise {type(value).__name__}")


def _hash(report: IncidentReport, *, users: bool, title: bool = True) -> str:
    body = report.model_dump(mode="json")
    meta = dict(body["meta"])
    meta.pop("as_at", None)
    body["meta"] = meta
    if not users:
        body.pop("users", None)
    for line in body.get("evidence") or []:  # a line without details hashes as one made before
        if not line.get("details") and line.get("shows") is None:
            line.pop("details", None)
            line.pop("shows", None)
    summary = dict(body["summary"])
    summary["prose"] = []
    summary["prose_note"] = None
    if not title:  # the case's title is a name for what the report says, not a fact of it
        header = dict(body["header"])
        header["title"] = header["incident_id"]
        header.pop("certainty", None)
        body["header"] = header
        summary["headline"] = ""
    body["summary"] = summary
    return hashlib.sha256(canonical(body).encode("utf-8")).hexdigest()


def content_hash(report: IncidentReport) -> str:
    """What the report says, without when it was made and without a model's wording: two
    reports of the same evidence have the same hash, so the same case yields the same report until
    its evidence changes. The prose is left out (words a model chose are not evidence). A report
    without accounts hashes as one made before the accounts existed."""
    return _hash(report, users=bool(report.users.devices))


def core_hash(report: IncidentReport) -> str:
    """The hash of the report without its accounts (``users``) and without the case's title (the
    header's title, its certainty word, and the headline that repeats it): two versions that
    differ only in who signed in from the case's devices, or in how the case is named, have the
    same core. A person's confirm of a report holds for a later version with the same core: the
    accounts are leads read from the logs, and a retitle (naming v2) renames what the person
    confirmed, it does not change it."""
    return _hash(report, users=False, title=False)
