"""The still-active watch at work: the daily run, the quiet-window finder and the status a person
reads (rules: :mod:`argus.cases.watch`, :mod:`argus.cases.membership`). A run (:func:`run`) covers
every watched case in this order: (1) membership, under the opener's lock: investigations that
strongly match join an open case, move a contained one back to open, or open a suspected case that
follows a closed one; (2) ARGUS's own alerts per finished UTC day; (3) the proxy logs in mode ``on``
(one ``proxy.contact`` request per address and day, oldest first, within the cap; what was cut off
stays *not checked* and is asked again); (4) reactions to contact seen after containment or closure.
Every step is idempotent (answers are keyed by case, day, source and address and never replaced);
one run at a time; one case's failure is a problem in the report."""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any, Protocol

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

from argus.assets import load_asset_map
from argus.assets.classify import IpClassifier
from argus.cases import known, knownrun, membership, opener, watch
from argus.cases.machine import AfterClosure, CaseRefused, Link, NewActivity, Open
from argus.cases.membership import Shared
from argus.cases.model import Actor, Case, Indicator, Member, QuietWindow, Severity, max_severity
from argus.cases.service import CaseService
from argus.context import batch1, beacon
from argus.context.packs import TaskSpec
from argus.db.audit import record_audit
from argus.freshness import shadow as fshadow
from argus.freshness import store as fstore
from argus.freshness.model import Check
from argus.freshness.reader import policy_of
from argus.gateway import errors
from argus.gateway.gateway import Gateway
from argus.gateway.health import HealthConfig
from argus.gateway.templates import Purpose

log = logging.getLogger("argus.cases.watch")

ACTOR = Actor.argus("watch")
COMPONENT = "investigation"  # the kill switch of the investigation lane
SCAN_LIMIT = 2000  # investigations one scan reads, the newest first
MAX_SUGGESTIONS = 20  # suggestions one run makes for one case
CHUNK = 100  # members one change adds
LOCK_KEY = int.from_bytes(b"ARGUSWCH", "big")  # one run of the watch at a time
# Refusals that end the run's questions for now: the same would follow for every other one.
RUN_LEVEL = frozenset(
    {"stopped", "deferred", "breaker_open", "skipped_budget", "deadline_passed", "off",
     "quiet_hours", "not_normal", "daily_cap"}
)  # fmt: skip


@dataclass(frozen=True)
class Answer:
    """What asking the SIEM came to: the answer, or the reason it was not asked (a code of
    :func:`argus.cases.watch.refusal_words`); ``sent``: a request left, so it counts against
    the case's cap for the day even if it failed."""

    asked_at: datetime
    body: Any = None
    refused: str | None = None
    sent: bool = False


class Asker(Protocol):
    async def ask(self, task: TaskSpec) -> Answer: ...


class GatewayAsker:
    """Asks through the Elastic Gateway in the investigation lane: NORMAL health
    only, never in the quiet hours (checked again whenever the gateway waits), the template's
    own prevalence gate and daily cap (:func:`argus.context.batch1.admit`), the lane's server
    time and heavy-request allowance, and the ``investigation`` kill switch."""

    def __init__(
        self,
        gateway: Gateway,
        engine: AsyncEngine,
        *,
        enabled: Iterable[str],
        history: timedelta,
        is_campus: Callable[[str], bool],
        health_config: HealthConfig | None = None,
        reservations: batch1.Reservations = batch1.RESERVED,
        timeout: timedelta = timedelta(seconds=60),
    ) -> None:
        self.gateway = gateway
        self.engine = engine
        self.enabled = frozenset(enabled)
        self.history = history
        self.is_campus = is_campus
        self.health_config = health_config
        self.reservations = reservations
        self.timeout = timeout

    async def ask(self, task: TaskSpec) -> Answer:
        name = type(task.template).name
        timeout_ms = int(type(task.template).timeout.total_seconds() * 1000)
        asked_at = self.gateway.clock()
        async with self.reservations.lock(name):
            now = self.gateway.clock()
            async with self.engine.connect() as conn:
                refused = await batch1.admit(
                    conn, self.gateway.state, task, enabled=self.enabled, now=now,
                    history=self.history, is_campus=self.is_campus,
                    health_config=self.health_config, reservations=self.reservations,
                )  # fmt: skip
            if refused is not None:
                return Answer(asked_at, refused=refused.code)
            token = self.reservations.take(name, now, timeout_ms)
        try:
            result = await self.gateway.run(
                task.template, task.params, purpose=Purpose.INVESTIGATE, component=COMPONENT,
                deadline=now + self.timeout,
                check=batch1.send_check(self.gateway.state, self.health_config),
            )  # fmt: skip
        except errors.SourceMissingError as exc:
            # expired: ILM deleted the day (final); missing: a data stream or alias that is not
            # there (not final); not ready: the day's index is not made yet
            return Answer(asked_at, refused=exc.reason if exc.reason in (
                "source_expired", "source_missing") else "deferred")  # fmt: skip
        except errors.StoppedError:
            return Answer(asked_at, refused="stopped")
        except errors.BreakerOpenError:
            return Answer(asked_at, refused="breaker_open")
        except errors.BudgetExhaustedError:
            return Answer(asked_at, refused="skipped_budget")
        except errors.DeadlinePassedError:
            return Answer(asked_at, refused="deadline_passed")
        except errors.DeferredError:
            return Answer(asked_at, refused="deferred")
        except (errors.TemplateRejectedError, errors.UnsupportedValueError):
            return Answer(asked_at, refused="rejected")
        except errors.RefusedError:
            return Answer(asked_at, refused="deferred")
        except errors.TransportFailedError as exc:
            return Answer(asked_at, refused="failed", sent=exc.reached)
        except errors.GatewayError:
            return Answer(asked_at, refused="failed", sent=True)
        finally:
            self.reservations.release(token)
        return Answer(asked_at, body=result.body, sent=True)


@dataclass(frozen=True)
class Context:
    """What a run needs. ``asker`` None is mode ``local``: ARGUS's own alerts only."""

    classifier: IpClassifier
    shared: Shared
    policy: fshadow.Policy
    history: timedelta
    asker: Asker | None = None
    pair: bool = False  # proxy.pair is switched on (describes the rhythm of contact seen)
    # the notified cases' rules: which asset-map site types are organisation-managed machines
    rules: known.Rules = field(default_factory=known.Rules)

    def is_campus(self, value: str) -> bool:
        return self.classifier.classify(value).ip_class in opener.CAMPUS


def context_for(settings: Any, asker: Asker | None = None) -> Context:
    """A run's context from the settings: the asset map's classes, the shared-infrastructure
    list, the freshness policy (``freshness.*``), ``history.window`` and whether ``proxy.pair``
    is on."""
    return Context(
        IpClassifier(load_asset_map(settings.assets.map_path), settings.site.own_networks),
        membership.load_shared(),
        policy_of(settings),
        settings.history.window,
        asker,
        "proxy.pair" in settings.enrichment.templates,
        knownrun.rules_of(settings.notified),
    )


@dataclass
class CaseReport:
    number: int
    state: str
    joined: int = 0
    suggested: int = 0
    followed: int = 0
    rows: dict[str, int] = field(default_factory=dict)
    asked: int = 0
    cut_off: int = 0
    events: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)  # "not checked: <reason>" and the like

    def row(self, outcome: str) -> None:
        self.rows[outcome] = self.rows.get(outcome, 0) + 1


@dataclass
class Report:
    mode: str
    cases: list[CaseReport] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    def case(self, number: int) -> CaseReport:
        return next(c for c in self.cases if c.number == number)

    @property
    def asked(self) -> int:
        return sum(c.asked for c in self.cases)


@dataclass(frozen=True)
class WatchedCase:
    id: uuid.UUID
    number: int
    state: str
    opened_at: datetime
    closed_at: datetime | None


async def watched(conn: AsyncConnection, now: datetime) -> list[WatchedCase]:
    """Confirmed cases that are not closed, and cases closed as remediated within the watch."""
    rows = await conn.execute(
        text(
            "SELECT id, number, state, opened_at, closed_at FROM cases"
            " WHERE opened_at IS NOT NULL AND merged_into_id IS NULL AND (state IN ('open',"
            " 'assigned', 'contained') OR (state = 'closed' AND closure_reason = ANY(:reasons)"
            " AND closed_at >= :since)) ORDER BY number"
        ),
        {"reasons": sorted(watch.WATCHED_REASONS), "since": now - watch.WATCH_AFTER_CLOSURE},
    )
    return [WatchedCase(r.id, int(r.number), r.state, r.opened_at, r.closed_at) for r in rows]


async def contained_at(conn: AsyncConnection, case_id: uuid.UUID) -> datetime | None:
    """When the case was last contained (the time the person's command carried), or None."""
    at = (
        await conn.execute(
            text(
                "SELECT coalesce(CAST(details ->> 'at' AS timestamptz), occurred_at) FROM"
                " case_events WHERE case_id = :c AND kind = 'contained'"
                " ORDER BY case_version DESC LIMIT 1"
            ),
            {"c": case_id},
        )
    ).scalar_one_or_none()
    return at


async def reference_time(conn: AsyncConnection, case: WatchedCase) -> datetime:
    """When activity starts to be news: a contained case's containment, a closed case's
    closure, otherwise the case's opening."""
    if case.state == "closed" and case.closed_at is not None:
        return case.closed_at
    if case.state == "contained":
        at = await contained_at(conn, case.id)
        if at is not None:
            return at
    return case.opened_at


@dataclass(frozen=True)
class Hit:
    observed: opener.Observed
    match: membership.Match


@dataclass
class Scan:
    """What new investigations mean for the watched cases. ``joins``: the case each joins;
    ``follows``: closed cases they follow; ``activity``: every case a hit matches strongly (or
    through its own actor, however common), whoever owns the investigation: the case's address
    alerted; ``suggestions``: matches that join nothing; ``too_common``: the cases that hold a
    c2 or indicator found in 50 or more investigations, whose activity cannot be searched."""

    cases: list[WatchedCase] = field(default_factory=list)
    refs: dict[uuid.UUID, datetime] = field(default_factory=dict)
    joins: dict[uuid.UUID, list[Hit]] = field(default_factory=dict)
    follows: dict[uuid.UUID, list[Hit]] = field(default_factory=dict)
    activity: dict[uuid.UUID, list[Hit]] = field(default_factory=dict)
    suggestions: list[tuple[uuid.UUID, membership.Suggested]] = field(default_factory=list)
    too_common: dict[uuid.UUID, tuple[tuple[str, str], ...]] = field(default_factory=dict)


# Investigations that have one of the keys, and who owns them: an investigation in a case is no
# join candidate but its alerts are activity for every case it matches. A person's benign review
# excludes an investigation only while it is current (its version is the investigation's).
_CANDIDATES = text(
    "SELECT i.id, ARRAY(SELECT m.case_id FROM case_members m WHERE m.investigation_id = i.id"
    " AND m.removed_at IS NULL) AS owners FROM investigations i WHERE i.last_event_at > :since"
    " AND EXISTS (SELECT 1 FROM investigation_entities e WHERE e.investigation_id = i.id AND"
    " (e.kind, e.value) IN (SELECT k, v FROM unnest(CAST(:kinds AS text[]),"
    " CAST(:values AS text[])) AS u(k, v))) AND NOT EXISTS (SELECT 1 FROM review_state s JOIN"
    " users u ON u.id = s.user_id WHERE s.investigation_id = i.id AND s.version = i.version AND"
    " s.action = 'reviewed' AND s.outcome IN ('benign_expected', 'benign_policy',"
    " 'rule_false_positive') AND u.username <> 'argus-assistant' AND u.kind = 'person')"
    " ORDER BY i.last_event_at DESC, i.id LIMIT :limit"
)


def _strongest(
    seen: opener.Observed, item: opener.Indexed, shared: Shared
) -> membership.Match | None:
    """The key by which ``seen`` is activity of the case: a strong match, or the case's own
    actor even when that host or account is in very many investigations (it is still the
    case's actor, and its alerts count)."""
    found = membership.keys(seen, item.indicators, shared)
    for match in found:
        if match.strong or (match.link == "actor" and match.shared == membership.SHARED_COMMON):
            return match
    return None


async def scan(
    conn: AsyncConnection, ctx: Context, now: datetime, *, only: uuid.UUID | None = None
) -> Scan:
    """Read-only: which investigations match which watched cases, and what that means. Joining
    is for investigations in no case and not judged benign by a person; **activity** is every
    investigation that matches a case (strongly, or through the case's own actor), in a case
    or not. ``only``: the matches that concern one case (the others are still read, so a tie
    is seen as one)."""
    out = Scan(cases=await watched(conn, now))
    by_id = {c.id: c for c in out.cases}
    indexed: dict[uuid.UUID, opener.Indexed] = {}
    for item in await opener.index(conn, now):
        if isinstance(item.ref, uuid.UUID) and item.ref in by_id:
            indexed[item.ref] = item
    if not indexed or (only is not None and only not in indexed):
        return out
    out.refs = {c.id: await reference_time(conn, c) for c in out.cases}
    mine = [i for ref, i in indexed.items() if only is None or ref == only]
    wanted = {key for i in indexed.values() for key in i.indicators}
    shared = ctx.shared.with_common(
        ctx.shared.common | await membership.common_values(conn, wanted, now - ctx.history)
    )
    for item in mine:
        crowded = tuple(
            sorted(
                k for k, role in item.indicators.items() if role != "actor" and k in shared.common
            )
        )
        if crowded:
            assert isinstance(item.ref, uuid.UUID)
            out.too_common[item.ref] = crowded
    # a case's own actors are always searched; any other key found in very many investigations
    # finds nothing worth a case (and the case cannot be called quiet, see Scan.too_common)
    own = {
        key
        for i in mine
        for key, role in i.indicators.items()
        if role == "actor" or key not in shared.common
    }
    if not own:
        return out
    found = (
        await conn.execute(
            _CANDIDATES,
            {
                "since": min(out.refs[i.ref] for i in mine),  # type: ignore[index]
                "kinds": [k for k, _ in sorted(own)],
                "values": [v for _, v in sorted(own)],
                "limit": SCAN_LIMIT,
            },
        )
    ).all()
    joinable = [i for i in indexed.values() if i.state in ("open", "assigned", "contained")]
    closed = [i for i in indexed.values() if i.state == "closed"]
    for investigation_id, owners in found:
        seen = await opener.observe(conn, investigation_id, ctx.classifier)
        if seen is None or seen.last_event_at is None:
            continue
        after = seen.last_event_at
        for item in mine:  # activity: whoever owns the investigation
            ref = item.ref
            assert isinstance(ref, uuid.UUID)
            if after > out.refs[ref] and (match := _strongest(seen, item, shared)) is not None:
                out.activity.setdefault(ref, []).append(Hit(seen, match))
        if owners:  # in a case already: no join, no suggestion
            continue
        live = [i for i in joinable if after > out.refs[i.ref]]  # type: ignore[index]
        resolution = membership.resolve(seen, live, shared)
        for suggestion in resolution.suggest:
            ref = suggestion.case.ref
            if not isinstance(ref, uuid.UUID):
                continue
            if suggestion.match.shared != membership.SHARED_COMMON:  # that one is only noise
                out.suggestions.append((investigation_id, suggestion))
        if resolution.join is not None:
            ref = resolution.join.case.ref
            assert isinstance(ref, uuid.UUID)
            out.joins.setdefault(ref, []).append(Hit(seen, resolution.join.match))
            continue
        if resolution.ambiguous:
            continue
        parents = []
        for item in closed:
            if after <= out.refs[item.ref]:  # type: ignore[index]
                continue
            strong = [m for m in membership.keys(seen, item.indicators, shared) if m.strong]
            if strong:
                parents.append((item, Hit(seen, strong[0])))
        if parents:
            first, hit = min(parents, key=lambda p: p[0].number)
            assert isinstance(first.ref, uuid.UUID)
            out.follows.setdefault(first.ref, []).append(hit)
    if only is not None:
        out.joins = {k: v for k, v in out.joins.items() if k == only}
        out.follows = {k: v for k, v in out.follows.items() if k == only}
        out.activity = {k: v for k, v in out.activity.items() if k == only}
        out.too_common = {k: v for k, v in out.too_common.items() if k == only}
        out.suggestions = [(i, x) for i, x in out.suggestions if x.case.ref == only]
    return out


def _members(hits: Sequence[Hit]) -> tuple[Member, ...]:
    return tuple(Member(h.observed.investigation_id, h.match.link, h.match.value) for h in hits)


def _marks(hits: Sequence[Hit]) -> tuple[Indicator, ...]:
    """A joined investigation's own actors become indicators when it joined through a c2 or
    another indicator (hosts reaching one C2); never more than its actors."""
    marks: dict[tuple[str, str], Indicator] = {}
    for hit in hits:
        if hit.match.link != "actor":
            for actor in hit.observed.actors:
                marks.setdefault((actor.kind, actor.value), actor)
    return tuple(marks.values())


def _severity(hits: Sequence[Hit]) -> Severity:
    return max_severity(*(h.observed.severity for h in hits))


def _entry(report: dict[uuid.UUID, CaseReport], case_id: uuid.UUID) -> CaseReport:
    return report.get(case_id) or CaseReport(0, "?")


async def apply_scan(
    conn: AsyncConnection, found: Scan, report: dict[uuid.UUID, CaseReport]
) -> None:
    """Make the joins, the followers and the suggestions of ``found`` (under the opener's lock,
    in the caller's transaction)."""
    service = await CaseService.start(conn)
    for case_id, hits in sorted(found.joins.items(), key=lambda item: str(item[0])):
        for start in range(0, len(hits), CHUNK):
            part = hits[start : start + CHUNK]
            case = await service.get(case_id, lock=True)
            if case is None or case.state not in ("open", "assigned", "contained"):
                break
            part = [h for h in part if h.observed.investigation_id not in case.members]
            if not part:
                continue
            try:
                async with conn.begin_nested():
                    if case.state == "contained":
                        summary = f"{len(part)} new investigation(s) match this case's addresses"
                        await service.apply(ACTOR, case_id, NewActivity(
                            summary, _members(part), _marks(part), _severity(part)),
                            expected_version=None)  # fmt: skip
                        _entry(report, case_id).events.append(
                            "new activity: the case is open again"
                        )
                    else:
                        await service.apply(ACTOR, case_id, Link(
                            _members(part), _marks(part), _severity(part)),
                            expected_version=None)  # fmt: skip
            except CaseRefused as exc:
                _entry(report, case_id).notes.append(f"not joined: {exc.message}")
                continue
            _entry(report, case_id).joined += len(part)
    for parent_id, hits in sorted(found.follows.items(), key=lambda item: str(item[0])):
        await _follow(conn, service, parent_id, hits, report)
    by_investigation: dict[uuid.UUID, list[membership.Suggested]] = {}
    left: dict[object, int] = {}
    for investigation_id, suggestion in found.suggestions:
        left.setdefault(suggestion.case.ref, MAX_SUGGESTIONS)
        if left[suggestion.case.ref] > 0:  # a content-delivery address would suggest everything
            left[suggestion.case.ref] -= 1
            by_investigation.setdefault(investigation_id, []).append(suggestion)
    for investigation_id, suggestions in by_investigation.items():
        for ref in await opener.suggest(conn, investigation_id, suggestions):
            _entry(report, ref).suggested += 1


async def _follow(
    conn: AsyncConnection,
    service: CaseService,
    parent_id: uuid.UUID,
    hits: Sequence[Hit],
    report: dict[uuid.UUID, CaseReport],
) -> None:
    """Activity after a closure: a suspected case that follows the closed one (never a reopen).
    Later activity joins the follower while it lives."""
    parent = await service.get(parent_id, lock=True)
    if parent is None or parent.state != "closed":
        return
    hits = [h for h in hits if h.observed.investigation_id not in parent.members]
    child_id = (
        await conn.execute(
            text(
                "SELECT id FROM cases WHERE parent_case_id = :p AND state <> 'closed'"
                " ORDER BY number LIMIT 1"
            ),
            {"p": parent_id},
        )
    ).scalar_one_or_none()
    try:
        async with conn.begin_nested():
            if child_id is None:
                if await opener.created_last_hour(conn) >= opener.MAX_NEW_PER_HOUR:
                    _entry(report, parent_id).notes.append(
                        f"activity after closure waits: over {opener.MAX_NEW_PER_HOUR} new cases"
                        " an hour"
                    )
                    return
                first, rest = hits[:1], list(hits[1:])
                if not first:
                    return
                opened = await service.open(ACTOR, Open(
                    f"Activity after case {parent.number} was closed", _severity(hits), "watch",
                    _members(first), (*_marks(first), *_own_marks(first)), suspected=True,
                    parent_case_id=parent_id))  # fmt: skip
                child_id = opened.case.id
                await service.apply(ACTOR, parent_id, AfterClosure(child_id),
                                    expected_version=None)  # fmt: skip
                hits = rest
                _entry(report, parent_id).followed += len(first)
                _entry(report, parent_id).events.append(
                    f"activity after closure: suspected case {opened.case.number} follows it"
                )
            for start in range(0, len(hits), CHUNK):
                part = hits[start : start + CHUNK]
                child = await service.get(child_id, lock=True)
                if child is None or child.state == "closed":
                    break
                part = [h for h in part if h.observed.investigation_id not in child.members]
                if not part:
                    continue
                command = (
                    NewActivity(f"{len(part)} more investigation(s) after closure", _members(part),
                                _marks(part), _severity(part))
                    if child.state == "contained"
                    else Link(_members(part), (*_marks(part), *_own_marks(part)),
                              _severity(part))
                )  # fmt: skip
                await service.apply(ACTOR, child_id, command, expected_version=None)
                _entry(report, parent_id).followed += len(part)
    except CaseRefused as exc:
        _entry(report, parent_id).notes.append(
            f"activity after closure not recorded: {exc.message}"
        )


def _own_marks(hits: Sequence[Hit]) -> tuple[Indicator, ...]:
    """What lets later activity find the follower: the investigation's actors and the value it
    matched the closed case through."""
    marks: dict[tuple[str, str], Indicator] = {}
    for hit in hits:
        for actor in hit.observed.actors:
            marks.setdefault((actor.kind, actor.value), actor)
        if hit.match.link != "actor":
            marks.setdefault(
                (hit.match.kind, hit.match.value),
                Indicator(hit.match.kind, hit.match.value, hit.match.link, "investigation"),  # type: ignore[arg-type]
            )
    return tuple(marks.values())


_ALERT_DAYS = text(
    "SELECT (COALESCE(a.event_time, a.detected_at) AT TIME ZONE 'UTC')::date AS day,"
    " count(*) AS n, max(COALESCE(a.event_time, a.detected_at)) AS last"
    " FROM investigation_alerts l JOIN alert_records a ON a.alert_id = l.alert_id"
    " WHERE l.investigation_id = ANY(:ids) AND COALESCE(a.event_time, a.detected_at) >= :since"
    " GROUP BY 1 ORDER BY 1"
)


async def alert_activity(
    conn: AsyncConnection, case_id: uuid.UUID, extra: Iterable[uuid.UUID], since: datetime
) -> dict[date, tuple[int, datetime]]:
    """Per UTC day since ``since``: the alerts of the case's members (and of the investigations
    that strongly match it without joining) and the newest one's time."""
    ids = set(
        (
            await conn.execute(
                text(
                    "SELECT investigation_id FROM case_members WHERE case_id = :c"
                    " AND removed_at IS NULL"
                ),
                {"c": case_id},
            )
        ).scalars()
    )
    ids |= set(extra)
    if not ids:
        return {}
    rows = await conn.execute(_ALERT_DAYS, {"ids": sorted(ids), "since": since})
    return {r.day: (int(r.n), r.last) for r in rows}


async def _coverage(
    conn: AsyncConnection, first: datetime, now: datetime
) -> tuple[datetime | None, list[tuple[str, datetime, datetime | None]]]:
    live = (
        await conn.execute(text("SELECT at FROM collector_cursors WHERE name = 'live'"))
    ).scalar_one_or_none()
    gaps = (
        await conn.execute(
            text(
                "SELECT kind, start_at, end_at FROM coverage_gaps WHERE start_at < :now"
                " AND (end_at IS NULL OR end_at > :first)"
            ),
            {"first": first, "now": now},
        )
    ).all()
    return live, [(g.kind, g.start_at, g.end_at) for g in gaps]


_PUT = text(
    "INSERT INTO case_watch_checks (case_id, day, source, subject, part, outcome, reason,"
    " window_start, window_end, asked_at, asked_on, requests, attempts, detail) VALUES (:case,"
    " :day, :source, :subject, :part, :outcome, :reason, :ws, :we, :asked_at, :asked_on,"
    " :requests, 1, CAST(:detail AS jsonb)) ON CONFLICT (case_id, day, source, subject, part)"
    " DO UPDATE SET outcome = EXCLUDED.outcome, reason = EXCLUDED.reason, window_start ="
    " EXCLUDED.window_start, window_end = EXCLUDED.window_end, asked_at ="
    " COALESCE(EXCLUDED.asked_at, case_watch_checks.asked_at), asked_on = CASE WHEN"
    " EXCLUDED.requests > 0 THEN EXCLUDED.asked_on ELSE case_watch_checks.asked_on END,"
    " requests = CASE WHEN EXCLUDED.requests = 0 THEN case_watch_checks.requests WHEN"
    " case_watch_checks.asked_on = EXCLUDED.asked_on THEN least(case_watch_checks.requests +"
    " EXCLUDED.requests, :cap) ELSE EXCLUDED.requests END, attempts ="
    " case_watch_checks.attempts + 1, detail = EXCLUDED.detail, checked_at = now() WHERE"
    " case_watch_checks.outcome = 'not_checked' RETURNING outcome"
)


async def put(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    day: date,
    source: str,
    subject: str,
    part: int,
    judged: watch.Judged,
    window: tuple[datetime, datetime],
    *,
    asked_at: datetime | None = None,
    sent: int = 0,
    today: date | None = None,
) -> bool:
    """Record one answer. A decided one stays as it is (False); only a ``not_checked`` answer
    is replaced, by the next try's."""
    reason = None if judged.reason is None else judged.reason[:300]
    result = await conn.execute(
        _PUT,
        {
            "case": case_id, "day": day, "source": source, "subject": subject, "part": part,
            "outcome": judged.outcome, "reason": reason, "ws": window[0], "we": window[1],
            "asked_at": asked_at, "asked_on": today if sent else None, "requests": sent,
            "cap": watch.MAX_REQUESTS_A_DAY,
            "detail": json.dumps(judged.detail, default=str),
        },
    )  # fmt: skip
    return result.first() is not None


async def alerts_check(
    conn: AsyncConnection,
    case: WatchedCase,
    found: Scan,
    now: datetime,
    report: CaseReport,
) -> dict[date, datetime]:
    """ARGUS's own alerts per finished day (and today, if active). Returns each active day's
    newest alert. A contained or closed case is looked at on every day since its reference time
    (up to the 14 days the watch lasts after a closure), however long the watch was down; an
    open one on the last :data:`~argus.cases.watch.BACKLOG_DAYS`."""
    after = case.state in ("contained", "closed")
    first = watch.utc_day(found.refs[case.id])
    since = watch.day_window(first)[0]
    extra = {h.observed.investigation_id for h in found.activity.get(case.id, ())}
    if case.state == "closed":  # activity after closure lives in the cases that follow it
        extra |= set(
            (
                await conn.execute(
                    text(
                        "SELECT m.investigation_id FROM case_members m JOIN cases c ON"
                        " c.id = m.case_id WHERE c.parent_case_id = :p AND m.removed_at IS NULL"
                    ),
                    {"p": case.id},
                )
            ).scalars()
        )
    activity = await alert_activity(conn, case.id, extra, since)
    live, gaps = await _coverage(conn, since, now)
    today = watch.utc_day(now)
    crowded = found.too_common.get(case.id)
    backlog = watch.WATCH_AFTER_CLOSURE.days if after else watch.BACKLOG_DAYS
    active: dict[date, datetime] = {}
    for day in [*watch.complete_days(first, now, backlog=backlog), today]:
        window = watch.day_window(day)
        if day in activity:
            count, last = activity[day]
            judged = watch.Judged("active", None, {"alerts": count, "last": last.isoformat()})
            active[day] = last
        elif day >= today:
            continue  # today is not over: only activity is news
        else:
            unseen = watch.coverage_reason(window[0], window[1], live, gaps)
            if unseen is None and crowded is not None:
                judged = watch.Judged("unverified", watch.TOO_COMMON, {})
            elif unseen is None:
                judged = watch.Judged("quiet", None, {})
            elif unseen[0]:
                judged = watch.Judged("unverified", unseen[1], {})
            else:
                report.notes.append(f"not checked: {unseen[1]} ({day})")
                continue
        if await put(conn, case.id, day, watch.ALERTS, "", 0, judged, window):
            report.row(judged.outcome)
    return active


async def _decided(
    conn: AsyncConnection, case_id: uuid.UUID, first: date
) -> dict[tuple[date, str, str, int], str]:
    rows = await conn.execute(
        text(
            "SELECT day, source, subject, part, outcome FROM case_watch_checks"
            " WHERE case_id = :c AND day >= :first"
        ),
        {"c": case_id, "first": first},
    )
    return {(r.day, r.source, r.subject, r.part): r.outcome for r in rows}


async def spent_today(conn: AsyncConnection, case_id: uuid.UUID, today: date) -> int:
    spent = (
        await conn.execute(
            text(
                "SELECT coalesce(sum(requests), 0) FROM case_watch_checks"
                " WHERE case_id = :c AND asked_on = :d"
            ),
            {"c": case_id, "d": today},
        )
    ).scalar_one()
    return int(spent)


async def case_indicators(conn: AsyncConnection, case_id: uuid.UUID) -> list[tuple[str, str, str]]:
    rows = await conn.execute(
        text(
            "SELECT kind, value, role FROM case_indicators WHERE case_id = :c"
            " AND removed_at IS NULL"
        ),
        {"c": case_id},
    )
    return [(r.kind, r.value, r.role) for r in rows]


async def verify_zero(
    conn: AsyncConnection, ctx: Context, params: beacon.ContactParams, asked_at: datetime
) -> Check:
    """The verdict for a ``proxy.contact`` search that found nothing: the search was whole,
    and the readings prove the proxy logs complete across its window, from before it was sent."""
    row = {
        "template": beacon.ProxyContact.name,
        "template_version": beacon.ProxyContact.version,
        "params": params.model_dump(mode="json"),
        "status": "empty",
        "truncated": False,
        "coverage": {},
        "asked_at": asked_at,
    }
    window = fshadow.window_of(row)
    assert window is not None
    readings = await fstore.readings(conn, window.source, window.start - ctx.policy.gap, asked_at)
    verdict = fshadow.judge_ref(
        "watch", row, {window.source: readings}, ctx.policy, ctx.policy.bridge
    )
    return verdict.check


async def logs_check(
    engine: AsyncEngine,
    ctx: Context,
    case: WatchedCase,
    skip_days: set[date],
    now: datetime,
    report: CaseReport,
) -> dict[date, tuple[datetime | None, list[str], str]]:
    """The proxy-log questions of one case that are open, the oldest day first, within the cap.
    Returns the days contact was seen, with the newest contact and the hosts."""
    assert ctx.asker is not None
    today = watch.utc_day(now)
    first = watch.utc_day(case.opened_at if case.state != "closed" else (case.closed_at or now))
    seen: dict[date, tuple[datetime | None, list[str], str]] = {}
    async with engine.connect() as conn:
        wanted = watch.subjects(
            await case_indicators(conn, case.id), ctx.is_campus, ctx.shared.reason
        )
        decided = {
            key for key, outcome in (await _decided(conn, case.id, first)).items()
            if outcome != "not_checked"
        }  # fmt: skip
        spent = await spent_today(conn, case.id, today)
    cap = watch.cap_for(len(wanted))
    asks, cut = watch.plan_asks(
        wanted, watch.complete_days(first, now), decided, skip_days, spent, cap=cap
    )
    report.cut_off = len(cut)
    cap_words = (
        f"cut off: this case has asked its {cap} proxy-log questions for"
        " today (it keeps 'cannot verify yet' and is asked again at the next run)"
    )
    for ask in cut:
        judged = watch.Judged("not_checked", cap_words, {})
        await _record(engine, case, ask, judged, report)
    stop: str | None = None
    for ask in asks:
        if stop is not None:  # the same would follow for every other question
            judged = watch.Judged("not_checked", watch.refusal_words(stop), {})
            await _record(engine, case, ask, judged, report)
            continue
        window = watch.log_window(ask.day)
        try:
            params = beacon.ContactParams(
                destination=ask.subject.destination, hosts=ask.subject.hosts,
                start=window[0], end=window[1],
            )  # fmt: skip
        except (ValidationError, ValueError):
            judged = watch.Judged("unverified", watch.refusal_words("rejected"), {})
            await _record(engine, case, ask, judged, report)
            continue
        answer = await ctx.asker.ask(TaskSpec(beacon.ProxyContact(), params))
        report.asked += int(answer.sent)
        if answer.refused is not None:
            final = answer.refused in watch.FINAL_REFUSALS
            judged = watch.Judged(
                "unverified" if final else "not_checked", watch.refusal_words(answer.refused), {}
            )
            if answer.refused in RUN_LEVEL:
                stop = answer.refused
        else:
            reading = watch.read_contact(answer.body)
            check = None
            if reading.complete and reading.requests == 0 and ctx.policy.mode == "on":
                async with engine.connect() as conn:
                    check = await verify_zero(conn, ctx, params, answer.asked_at)
            judged = watch.judge_contact(reading, check, zeros_on=ctx.policy.mode == "on")
            if judged.outcome == "active":
                seen[ask.day] = (reading.last, list(reading.hosts), ask.subject.destination)
        await _record(engine, case, ask, judged, report, asked_at=answer.asked_at,
                      sent=int(answer.sent), today=today)  # fmt: skip
    if ctx.pair and seen:
        await _describe(engine, ctx, case, seen, now, report, cap)
    return seen


async def _record(
    engine: AsyncEngine,
    case: WatchedCase,
    ask: watch.Ask,
    judged: watch.Judged,
    report: CaseReport,
    *,
    asked_at: datetime | None = None,
    sent: int = 0,
    today: date | None = None,
) -> None:
    judged = replace(judged, detail={**judged.detail, "watched": list(ask.subject.hosts)})
    async with engine.begin() as conn:
        written = await put(
            conn, case.id, ask.day, watch.CONTACT, ask.subject.destination, ask.subject.part,
            judged, watch.log_window(ask.day), asked_at=asked_at, sent=sent, today=today,
        )  # fmt: skip
    if written:
        report.row(judged.outcome)
        if judged.outcome == "not_checked":
            report.notes.append(f"not checked: {judged.reason} ({ask.day})")


async def _describe(
    engine: AsyncEngine,
    ctx: Context,
    case: WatchedCase,
    seen: dict[date, tuple[datetime | None, list[str], str]],
    now: datetime,
    report: CaseReport,
    cap: int,
) -> None:
    """When contact was seen, and the case's cap has room: one ``proxy.pair`` request for the
    newest day's first host reads its rhythm over the last 6 hours of contact (period, jitter,
    still active)."""
    assert ctx.asker is not None
    today = watch.utc_day(now)
    day = max(seen)
    last, hosts, destination = seen[day]
    if last is None or not hosts:
        return
    async with engine.connect() as conn:
        spent = await spent_today(conn, case.id, today)
    if spent >= cap:
        return
    host = hosts[0]
    window = watch.log_window(day)
    end = min(last + timedelta(minutes=1), window[1])
    start = max(end - watch.PAIR_WINDOW, window[0])
    try:
        params = beacon.PairParams(host=host, destination=destination, start=start, end=end)
    except (ValidationError, ValueError):
        return
    answer = await ctx.asker.ask(TaskSpec(beacon.ProxyPair(), params))
    report.asked += int(answer.sent)
    if not answer.sent:
        return  # a description is only a bonus: nothing left, so nothing is counted or asked again
    subject = f"{host}>{destination}"
    detail: dict[str, Any] = {}
    judged = watch.Judged("unverified", watch.refusal_words(answer.refused or "failed"), detail)
    if answer.refused is None:
        aggs = (answer.body or {}).get("aggregations") if isinstance(answer.body, dict) else None
        try:
            got = beacon.cadence(aggs, start, end)
        except (ValueError, TypeError, ArithmeticError, OSError):
            judged = watch.Judged("unverified", watch.MALFORMED, detail)
        else:
            detail.update({"beats": got.beats, "requests": got.requests})
            if got.period is not None:
                detail["period_s"] = int(got.period.total_seconds())
                detail["still_active"] = bool(got.still_active)
            judged = watch.Judged("active" if got.beats else "quiet", None, detail)
    # a search that left counts against the day's cap, whatever came back
    async with engine.begin() as conn:
        await put(conn, case.id, day, watch.PAIR, subject, 0, judged, (start, end),
                  asked_at=answer.asked_at, sent=1, today=today)  # fmt: skip


async def react(
    engine: AsyncEngine,
    case: WatchedCase,
    ref: datetime,
    alert_last: datetime | None,
    log_last: datetime | None,
    report: CaseReport,
) -> None:
    """Alerts or contact after a containment or a closure that no investigation carried into a
    case (member alerts, contact in the logs): a contained case returns to open; a closed one is
    noted (once), never reopened."""
    last = max((t for t in (alert_last, log_last) if t is not None and t > ref), default=None)
    if last is None:
        return
    where = "ARGUS's alerts" if last == alert_last else "the proxy logs"
    async with engine.begin() as conn:
        await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                           {"k": opener.OPENER_LOCK_KEY})  # fmt: skip
        service = await CaseService.start(conn)
        current = await service.get(case.id, lock=True)
        if current is None:
            return
        try:
            async with conn.begin_nested():
                if current.state == "contained":
                    await service.apply(
                        ACTOR, case.id,
                        NewActivity(f"activity after containment, seen in {where}"),
                        expected_version=None,
                    )  # fmt: skip
                    report.events.append("new activity: the case is open again")
                    report.state = "open"
                elif current.state == "closed" and not await _noted(conn, case.id):
                    await service.apply(
                        ACTOR, case.id,
                        AfterClosure(summary=f"Activity after closure, seen in {where}"),
                        expected_version=None,
                    )  # fmt: skip
                    report.events.append("activity after closure noted on the closed case")
        except CaseRefused as exc:
            report.notes.append(f"activity not recorded: {exc.message}")


async def _noted(conn: AsyncConnection, case_id: uuid.UUID) -> bool:
    found = (
        await conn.execute(
            text(
                "SELECT 1 FROM case_events WHERE case_id = :c AND kind ="
                " 'activity_after_closure' LIMIT 1"
            ),
            {"c": case_id},
        )
    ).first()
    return found is not None


async def run(
    engine: AsyncEngine,
    ctx: Context,
    *,
    now: datetime,
    apply: bool = True,
    mode: str | None = None,
) -> Report:
    """One run of the watch (see the module's docstring). ``apply=False`` reads and plans only:
    no case changes, no answers stored, nothing asked. ``mode`` names the run in its report
    (default: "local" without an asker, else "on")."""
    report = Report(mode or ("local" if ctx.asker is None else "on"))
    if not apply:
        return await _run(engine, ctx, now, False, report)
    # One run at a time: the cap would not hold otherwise. The lock is a session lock on a
    # connection of its own in AUTOCOMMIT: no transaction sits idle for the length of the run
    # (the engine ends sessions idle in a transaction after 60 s, and the lock with them).
    async with engine.connect() as lock:
        lock = await lock.execution_options(isolation_level="AUTOCOMMIT")
        got = (
            await lock.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": LOCK_KEY})
        ).scalar()
        if not got:
            report.problems.append("another run of the watch is in progress: nothing was done")
            return report
        try:
            return await _run(engine, ctx, now, True, report)
        finally:
            await _unlock(lock)


async def _unlock(lock: AsyncConnection) -> None:
    """Release the run's lock, best effort: a lost connection has lost the lock with it, and a
    finished run is never failed (its report is written) by the lock's release. A connection
    that could not say it released the lock is thrown away, which ends the session and the
    lock."""
    try:
        await lock.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": LOCK_KEY})
    except Exception as exc:
        log.warning("watch lock release failed: %s", type(exc).__name__)
        try:
            await lock.invalidate()
        except Exception as again:
            log.warning("watch lock connection not discarded: %s", type(again).__name__)


async def _run(
    engine: AsyncEngine, ctx: Context, now: datetime, apply: bool, report: Report
) -> Report:
    async with engine.connect() as conn:
        planned = await scan(conn, ctx, now)
    cases = {c.id: CaseReport(c.number, c.state) for c in planned.cases}
    if not apply:
        for case_id, hits in planned.joins.items():
            cases[case_id].joined = len(hits)
        for case_id, hits in planned.follows.items():
            cases[case_id].followed = len(hits)
        for _, suggestion in planned.suggestions:
            ref = suggestion.case.ref
            if isinstance(ref, uuid.UUID) and ref in cases:
                cases[ref].suggested += 1
        report.cases = list(cases.values())
        return report
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT pg_advisory_xact_lock(:k)"),
                               {"k": opener.OPENER_LOCK_KEY})  # fmt: skip
            await apply_scan(conn, await scan(conn, ctx, now), cases)
    except Exception as exc:
        report.problems.append(f"membership: {type(exc).__name__}")
        log.warning("watch membership failed: %s", type(exc).__name__)
    try:
        async with engine.connect() as conn:
            current = await scan(conn, ctx, now)  # fresh states, and the activity not joined
        for case in current.cases:
            entry = cases.setdefault(case.id, CaseReport(case.number, case.state))
            entry.state = case.state
            try:
                await _watch_case(engine, ctx, case, current, now, entry)
            except Exception as exc:  # one case's failure leaves the others to run
                report.problems.append(f"case {case.number}: {type(exc).__name__}")
                log.warning("watch of case %s failed: %s", case.number, type(exc).__name__)
        report.cases = [cases[c.id] for c in current.cases if c.id in cases]
    except Exception as exc:  # the audit row below says the run happened, whatever came of it
        report.problems.append(f"scan: {type(exc).__name__}")
        log.warning("watch scan failed: %s", type(exc).__name__)
        report.cases = list(cases.values())
    async with engine.begin() as conn:
        session = AsyncSession(bind=conn)
        try:
            await record_audit(
                session, actor=ACTOR.name, action="watch.run", target_type="cases",
                details={"mode": report.mode, "cases": len(report.cases),
                         "asked": report.asked, "problems": len(report.problems)},
            )  # fmt: skip
        finally:
            await session.close()
    return report


async def _watch_case(
    engine: AsyncEngine, ctx: Context, case: WatchedCase, found: Scan, now: datetime,
    entry: CaseReport,
) -> None:  # fmt: skip
    ref = found.refs[case.id]
    async with engine.begin() as conn:
        active = await alerts_check(conn, case, found, now, entry)
    log_last: datetime | None = None
    if ctx.asker is not None:
        seen = await logs_check(engine, ctx, case, set(active), now, entry)
        log_last = max((v[0] for v in seen.values() if v[0] is not None), default=None)
    alert_last = max(active.values(), default=None)
    if case.state in ("contained", "closed"):
        await react(engine, case, ref, alert_last, log_last, entry)
    elif entry.state in ("open", "assigned"):
        async with engine.connect() as conn:
            current = await CaseService.start(conn)
            held = await current.get(case.id)
            window = None if held is None else await Finder(conn, ctx, lambda: now)(held)
        if window is not None and window.verified:
            entry.events.append(
                f"quiet for 72 hours: a person may contain it (with their attestation): "
                f"{window.reason}"
            )


async def rows(conn: AsyncConnection, case_id: uuid.UUID, since: date) -> list[watch.Row]:
    found = await conn.execute(
        text(
            "SELECT day, source, subject, part, outcome, reason, detail FROM case_watch_checks"
            " WHERE case_id = :c AND day >= :since ORDER BY day, source, subject, part"
        ),
        {"c": case_id, "since": since},
    )
    return [watch.Row(r.day, r.source, r.subject, r.part, r.outcome, r.reason, r.detail)
            for r in found]  # fmt: skip


class Finder:
    """Says whether a case was verifiably quiet for 72 hours (``CaseService``'s
    ``quiet_windows``): the stored answers of the last three whole days, checked once more
    against the database as it is now (a late alert, an investigation not yet joined)."""

    def __init__(self, conn: AsyncConnection, ctx: Context,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:  # fmt: skip
        self.conn = conn
        self.ctx = ctx
        self.clock = clock

    async def __call__(self, case: Case) -> QuietWindow:
        now = self.clock()
        today = watch.utc_day(now)
        window_start = today - timedelta(days=watch.QUIET_DAYS)
        stored = await rows(self.conn, case.id, window_start)
        wanted = watch.subjects(
            ((i.kind, i.value, i.role) for i in case.indicators), self.ctx.is_campus,
            self.ctx.shared.reason,
        )  # fmt: skip
        found = await scan(self.conn, self.ctx, now, only=case.id)
        extra = {h.observed.investigation_id for h in found.activity.get(case.id, ())}
        since = watch.day_window(window_start)[0]
        days = set(await alert_activity(self.conn, case.id, extra, since))
        crowded = case.id in found.too_common
        window = watch.quiet_window(
            stored, wanted, today, zeros_on=self.ctx.policy.mode == "on", alert_days=days,
            blocked=watch.TOO_COMMON if crowded else None,
        )  # fmt: skip
        if window.verified and case.state == "contained":
            # a closure rests on days observed after the containment: the window must end after it
            contained = await contained_at(self.conn, case.id)
            if contained is not None and watch.day_window(today)[0] <= contained:
                when = f"{contained:%Y-%m-%d %H:%M}"
                return QuietWindow(
                    False,
                    f"the quiet window ends before the case was contained ({when} UTC): the days"
                    " since are not over yet",
                )
        return window


async def last_run(conn: AsyncConnection) -> datetime | None:
    """When the watch last ran (its audit row), or None."""
    at = (
        await conn.execute(
            text("SELECT max(occurred_at) FROM audit_events WHERE action = 'watch.run'")
        )
    ).scalar_one_or_none()
    return at


async def status(
    conn: AsyncConnection, ctx: Context, case_id: uuid.UUID, now: datetime
) -> list[str]:
    """What the watch can say about one case, in plain words: when the watch last ran, the
    answers of the last days (a question left open says "not checked: <reason>"), the suspected
    cases that follow it, and whether it is verifiably quiet for 72 hours."""
    today = watch.utc_day(now)
    service = await CaseService.start(conn)
    case = await service.get(case_id)
    if case is None:
        return []
    wanted = watch.subjects(
        ((i.kind, i.value, i.role) for i in case.indicators), ctx.is_campus, ctx.shared.reason
    )
    since = today - timedelta(days=watch.BACKLOG_DAYS)
    lines = [watch.last_run_words(await last_run(conn), now)]
    lines += watch.status_lines(await rows(conn, case_id, since), wanted)
    followers = await conn.execute(
        text("SELECT number, state FROM cases WHERE parent_case_id = :c ORDER BY number"),
        {"c": case_id},
    )
    lines += [f"followed by case {r.number} ({r.state})" for r in followers]
    window = await Finder(conn, ctx, lambda: now)(case)
    verdict = "yes" if window.verified else "no"
    lines.append(f"quiet for 72 hours: {verdict}: {window.reason}")
    return lines
