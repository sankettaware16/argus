"""One read-back cycle, and the loop that runs one every 10, 20 or 60 minutes.

Every request is a read template of the Kibana lane or the Elasticsearch gateway's
``alerts.case_links``: the lane's budget, health gating, kill switches, breakers and ledger apply,
and nothing is retried (a cycle that cannot finish ends ``partial`` or ``failed``). A cycle: (1)
``kibana.status`` hourly; (2) the change poll, ``cases.find`` of ARGUS's and the case team's cases,
down to the last complete cycle's start less an overlap; (3) the listing of open and in-progress
cases, whose id set against the mirror finds new cases (adopted only through a sent create or open
step) and missing ones (deleted only after ``cases.get`` answers 404), plus a cheap probe of the
closed cases; (4) the user actions of each changed case, classified and kept in one transaction per
case; (5) hourly, a bounded rotating slice of alert changes. The poll's start moves only after a
complete cycle, so nothing is skipped; an alarm pauses every write class **before** its finding is
kept, and only for a new finding."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from argus import site
from argus.gateway import health as health_core
from argus.gateway.builtin import AlertCaseLinks, CaseLinksParams
from argus.gateway.errors import (
    BreakerOpenError,
    BudgetExhaustedError,
    DeadlinePassedError,
    DeferredError,
    GatewayError,
    StoppedError,
)
from argus.gateway.gateway import Gateway, utcnow
from argus.gateway.health import HealthConfig, HealthState
from argus.gateway.kibana import writes
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaAuthError,
    KibanaForbiddenError,
    KibanaNotFoundError,
    KibanaOverloadedError,
    KibanaServerError,
    KibanaStoppedError,
    UnknownOutcomeError,
)
from argus.gateway.kibana.gateway import KibanaGateway, KResult, Store
from argus.gateway.kibana.templates import (
    MAX_PAGE_DEPTH,
    CaseGet,
    CasePageParams,
    CaseParams,
    CasesFind,
    CaseUserActions,
    FindParams,
    KibanaStatus,
    KibanaTemplate,
    NoParams,
)
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.templates import Purpose
from argus.kibana_sync import classify
from argus.kibana_sync.classify import Intervals
from argus.kibana_sync.model import (
    AlertLink,
    Finding,
    KAction,
    KCase,
    Kind,
    Mirror,
    Severity,
    TeamPost,
    parse_action,
    parse_case,
    parse_links,
    untrusted,
)
from argus.kibana_sync.store import CycleRecord, PeopleCase, SyncStore, mirrored_by_case
from argus.observability.redaction import redact_text

log = logging.getLogger("argus.kibana_sync")

COMPONENT = "kibana-sync"
PAUSED_BY_ALARM = "a reconciliation alarm (argus kibana sync status)"
ALL_CLASSES = (WriteClass.W1, WriteClass.W2, WriteClass.W3, WriteClass.WA)
LINKS_BATCH = 100  # alerts.case_links takes at most 100 ids
MAX_PEOPLE_GETS = 20  # people's cases read per discovery
MAX_CYCLE = timedelta(minutes=55)  # hourly in DEGRADED, where the lane has a tenth


@dataclass(frozen=True)
class SyncConfig:
    author: str = "argus"  # kibana.service_user: who ARGUS is in Kibana
    team: tuple[str, ...] = ()  # the case team's Kibana users (case_team.users())
    intervals: Intervals = field(default_factory=Intervals)
    overlap: timedelta = timedelta(minutes=2)
    per_page: int = 100
    status_every: timedelta = timedelta(hours=1)
    discovery_every: timedelta = timedelta(hours=1)
    discovery_calls: int = 3
    diff_calls: int = 5  # searches of the alerts on ARGUS's cases per discovery (a rotating slice)
    clock_alarm: timedelta = timedelta(seconds=30)
    window: timedelta = timedelta(days=5)  # history.window: the known alerts discovery checks
    closed_every: timedelta = timedelta(days=1)  # the listing of closed cases
    component: str = COMPONENT

    @property
    def identities(self) -> frozenset[str]:
        """Every Kibana username that is ARGUS: the service user and the case team's."""
        return frozenset((self.author, *self.team))

    @property
    def reporters(self) -> str | tuple[str, ...]:
        """The ``reporters`` of every find: the service user alone, or with the case team's."""
        names = tuple(dict.fromkeys((self.author, *self.team)))
        return names if len(names) > 1 else self.author

    @property
    def settle(self) -> timedelta:
        """A case changed less than this ago is read again at the next cycle: its user action
        may not be searchable yet (Kibana writes the case, then the action)."""
        return 2 * self.overlap


class IncompleteError(Exception):
    """A step could not finish: the cycle ends partial (budget, health, deadline)."""


@dataclass
class _Run:
    started: datetime
    deadline: datetime
    reads: int = 0
    offset_ms: int | None = None
    findings: int = 0
    changed: int = 0
    failed: list[str] = field(default_factory=list)  # cases that could not be kept
    processed: set[str] = field(default_factory=set)  # Kibana ids read this cycle
    synced: dict[str, datetime] = field(default_factory=dict)  # Sync alerts on: last change
    detail: dict[str, Any] = field(default_factory=dict)


class Syncer:
    def __init__(
        self,
        kibana: KibanaGateway,
        store: SyncStore,
        lane: Store,
        *,
        es: Gateway | None = None,
        config: SyncConfig | None = None,
        health_config: HealthConfig | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        after_cycle: Callable[[datetime], Awaitable[None]] | None = None,
    ) -> None:
        self.kibana = kibana
        self.after_cycle = after_cycle  # reads the case team's cases for a person's verdict
        self.store = store
        self.lane = lane  # GatewayState and KibanaState: health, switches, pauses
        self.es = es
        self.config = config or SyncConfig()
        self.team = frozenset(self.config.team) - {self.config.author}
        self.health_config = health_config or HealthConfig()
        self.clock = clock
        self.sleep = sleep
        # the closed total and the mirror's closed count a closed listing last settled
        self._closed_seen: tuple[int, int] | None = None

    async def health(self) -> HealthState:
        memory = health_core.effective(await self.lane.health(), self.clock(), self.health_config)
        state: HealthState = memory.state
        return state

    async def next_wait(self) -> timedelta | None:
        """How long until the next cycle; None while no cycle may run (STOP, a switch)."""
        switches = await self.lane.switches()
        if switches.blocks("kibana"):
            return None
        return classify.interval(await self.health(), self.config.intervals)

    async def run(
        self, *, cycles: int | None = None, idle: timedelta = timedelta(minutes=1)
    ) -> int:
        """Cycles until ``cycles`` ran (None: for ever). In STOP or under the ``kibana`` or
        global switch no cycle runs: the loop looks again after ``idle``."""
        done = 0
        while cycles is None or done < cycles:
            wait = await self.next_wait()
            if wait is None:
                await self.sleep(idle.total_seconds())
                continue
            started = self.clock()
            await self.cycle(deadline=started + min(wait - timedelta(seconds=30), MAX_CYCLE))
            done += 1
            left = (started + wait - self.clock()).total_seconds()
            if cycles is None or done < cycles:
                await self.sleep(max(left, 1.0))
        return done

    async def cycle(self, *, deadline: datetime) -> CycleRecord:
        run = _Run(started=self.clock(), deadline=deadline)
        health = (await self.health()).value
        outcome, reason = "complete", None
        try:
            await self._steps(run)
            if run.failed:
                outcome = "partial"
                reason = f"{len(run.failed)} case(s) could not be kept (see the findings)"
        except IncompleteError as exc:
            outcome, reason = "partial", str(exc)
        except (KibanaAuthError, KibanaForbiddenError, KibanaStoppedError) as exc:
            outcome, reason = "failed", f"kibana_stopped: {type(exc).__name__}"
        except UnknownOutcomeError as exc:
            outcome, reason = "failed", f"kibana_unreachable: {exc.reason}"
        except (KibanaServerError, KibanaOverloadedError, BreakerOpenError) as exc:
            outcome, reason = "failed", f"kibana_trouble: {type(exc).__name__}"
        except StoppedError as exc:
            outcome, reason = "failed", f"stopped: {exc}"
        except AnswerMismatchError as exc:
            outcome, reason = "failed", "answer_unexpected"
            run.findings += await self.store.add_findings(
                [
                    Finding(
                        Kind.ANSWER_UNEXPECTED,
                        f"answer:{run.started:%Y-%m-%dT%H}",
                        details={"what": untrusted(str(exc))},
                    )
                ],
                self.clock(),
            )
        except GatewayError as exc:
            outcome, reason = "failed", f"{type(exc).__name__}: {exc.reason}"
        except Exception as exc:  # a bug or the database: recorded, the loop goes on
            outcome, reason = "failed", redact_text(f"{type(exc).__name__}: {exc}")[:300]
            log.exception("kibana sync cycle failed")
        now = self.clock()
        state = await self.store.state()
        if outcome == "complete":
            state = replace(
                state,
                changes_from=self._kibana_time(run.started, run.offset_ms) - self.config.overlap,
                last_complete_at=now,
            )
        state = replace(state, last_cycle_at=now)
        if run.offset_ms is not None:
            state = replace(state, clock_offset_ms=run.offset_ms, clock_checked_at=now)
            if classify.clock_alarm(run.offset_ms, self.config.clock_alarm):
                run.findings += await self.store.add_findings(
                    [
                        Finding(
                            Kind.CLOCK_OFFSET,
                            f"clock:{now:%Y-%m-%dT%H}",
                            details={"offset_ms": run.offset_ms},
                        )
                    ],
                    now,
                )
        await self.store.save_state(state)
        poll = classify.interval(HealthState(health), self.config.intervals)
        bound = classify.staleness_bound(poll or self.config.intervals.normal, self.config.overlap)
        listed_each_cycle = [
            m for m in (await self.store.mirrors()).values() if m.status != "closed"
        ]
        stale = classify.staleness(listed_each_cycle, now, bound)
        if stale.stale:
            run.detail["stale_cases"] = list(stale.stale_cases)
        record = CycleRecord(
            started_at=run.started,
            finished_at=max(now, run.started),
            outcome=outcome,
            reason=reason,
            health=health,
            reads=run.reads,
            changed=run.changed,
            findings=run.findings,
            oldest_read_s=stale.oldest_s,
            stale=stale.stale,
            clock_offset_ms=run.offset_ms,
            detail=run.detail,
        )
        await self.store.record_cycle(record)
        if self.after_cycle is not None and outcome != "failed":
            try:  # never part of the cycle: what it does is its own, and a failure is only logged
                await self.after_cycle(deadline)
            except Exception:
                log.exception("the step after the sync cycle failed")
        return record

    @staticmethod
    def _kibana_time(at: datetime, offset_ms: int | None) -> datetime:
        return at + timedelta(milliseconds=offset_ms or 0)

    async def _pause_all(self, reason: str) -> None:
        def change(state: writes.KibanaLaneState) -> tuple[None, writes.KibanaLaneState]:
            for cls in ALL_CLASSES:
                state = writes.pause(state, cls, reason)
            return None, state

        await self.lane.kibana_change(change)

    async def _read(self, run: _Run, template: KibanaTemplate, params: Any) -> KResult:
        try:
            result = await self.kibana.read(
                template, params, component=self.config.component, deadline=run.deadline
            )
        except (BudgetExhaustedError, DeadlinePassedError, DeferredError) as exc:
            raise IncompleteError(f"{type(exc).__name__}: {exc}") from None
        run.reads += 1
        received = self.clock()  # the exchange itself, not the lane's wait before it
        sent = received - timedelta(milliseconds=result.elapsed_ms)
        offset = classify.clock_offset_ms(result.date, sent, received)
        if offset is not None:
            run.offset_ms = offset
        return result

    async def _search(self, run: _Run, params: CaseLinksParams) -> Any:
        assert self.es is not None
        try:
            result = await self.es.run(
                AlertCaseLinks(),
                params,
                purpose=Purpose.KIBANA_READ,
                component=self.config.component,
                deadline=run.deadline,
            )
        except (BudgetExhaustedError, DeadlinePassedError, DeferredError) as exc:
            raise IncompleteError(f"{type(exc).__name__}: {exc}") from None
        run.reads += 1
        return result.body

    async def _steps(self, run: _Run) -> None:
        state = await self.store.state()
        now = self.clock()
        quiet = classify.quiet_hours(now)
        if state.last_status_at is None or now - state.last_status_at >= self.config.status_every:
            status = await self._read(run, KibanaStatus(), NoParams())
            run.detail["kibana"] = {"version": status.body[0], "level": status.body[1]}
            await self.store.save_state(replace(state, last_status_at=now))
        polled = await self._change_poll(run, state.changes_from)
        listed: dict[str, KCase] = {}
        complete = True
        for status_ in ("open", "in-progress"):
            part, done = await self._listing(run, status_)
            listed.update(part)
            complete = complete and done
        await self._reconcile(run, polled, listed, complete, frozenset(("open", "in-progress")))
        state = await self.store.state()
        closed_due = state.last_closed_listing_at is None or (
            now - state.last_closed_listing_at >= self.config.closed_every
        )
        if quiet:
            quiet_hours = site.quiet_hours()
            run.detail["quiet"] = (
                "no closed listing and no discovery from"
                f" {quiet_hours.start} to {quiet_hours.end} UTC"
            )
        elif closed_due or await self._closed_moved(run):
            part, done = await self._listing(run, "closed")
            await self._reconcile(run, {}, part, done, frozenset(("closed",)))
            if done:
                self._closed_seen = (len(part), self._closed_count(await self.store.mirrors()))
                state = replace(await self.store.state(), last_closed_listing_at=now)
                await self.store.save_state(state)
        due = state.last_discovery_at is None or (
            self.clock() - state.last_discovery_at >= self.config.discovery_every
        )
        if due and self.es is not None and not quiet:
            await self._discovery(run)

    @staticmethod
    def _closed_count(mirrors: Mapping[str, Mirror]) -> int:
        return sum(1 for m in mirrors.values() if m.active and m.status == "closed")

    async def _closed_moved(self, run: _Run) -> bool:
        """One ``cases.find`` of one closed case of ``argus``: its ``total`` against the
        mirror's closed cases. A closed case someone deleted (or closed or reopened without
        the poll seeing it) moves the two apart, and only then are all closed cases listed.
        A difference a listing already looked at (a case of ARGUS's the mirror cannot hold)
        is not looked at again until one of the two numbers moves."""
        params = FindParams(
            reporters=self.config.reporters,
            status="closed",
            sort_field="createdAt",
            sort_order="asc",
            page=1,
            per_page=1,
        )
        total = (await self._read(run, CasesFind(), params)).body["total"]
        mine = self._closed_count(await self.store.mirrors())
        run.detail["closed"] = [total, mine]
        return bool(total != mine and (total, mine) != self._closed_seen)

    async def _change_poll(self, run: _Run, since: datetime | None) -> dict[str, KCase]:
        """``argus``'s cases changed since ``since``, newest first (none before the first
        complete cycle: the listing reads them all)."""
        found: dict[str, KCase] = {}
        if since is None:
            return found
        per = self.config.per_page
        page = 1
        while page * per <= MAX_PAGE_DEPTH:
            params = FindParams(
                reporters=self.config.reporters,
                sort_field="updatedAt",
                sort_order="desc",
                page=page,
                per_page=per,
            )
            body = (await self._read(run, CasesFind(), params)).body
            cases = [parse_case(c) for c in body["cases"]]
            fresh = [c for c in cases if c.updated_at is not None and c.updated_at >= since]
            found.update((c.id, c) for c in fresh)
            if len(fresh) < len(cases) or len(cases) < per or page * per >= body["total"]:
                break
            page += 1
        run.detail["polled"] = len(found)
        return found

    async def _listing(self, run: _Run, status: str) -> tuple[dict[str, KCase], bool]:
        """Every case of ``argus`` with ``status``, oldest first; complete unless Kibana's
        paging depth ends it. Open and in-progress cases are listed every cycle, closed ones
        once a day (``closed_every``). Paging drift
        (a case made, deleted or moved between pages) is noted: no deletion is taken from a
        listing without a get."""
        per = self.config.per_page
        listed: dict[str, KCase] = {}
        totals: set[int] = set()
        page = 1
        while True:
            if page * per > MAX_PAGE_DEPTH:
                run.detail["listing"] = "too deep"
                return listed, False
            params = FindParams(
                reporters=self.config.reporters,
                status=status,  # type: ignore[arg-type]
                sort_field="createdAt",
                sort_order="asc",
                page=page,
                per_page=per,
            )
            body = (await self._read(run, CasesFind(), params)).body
            totals.add(body["total"])
            cases = [parse_case(c) for c in body["cases"]]
            listed.update((c.id, c) for c in cases)
            if len(cases) < per or page * per >= body["total"]:
                break
            page += 1
        if len(totals) > 1:
            run.detail[f"drift_{status}"] = sorted(totals)
        run.detail[f"listed_{status}"] = len(listed)
        return listed, True

    async def _reconcile(
        self,
        run: _Run,
        polled: Mapping[str, KCase],
        listed: Mapping[str, KCase],
        complete: bool,
        statuses: frozenset[str],
    ) -> None:
        mirrors = await self.store.mirrors()
        seen = {**polled, **listed}
        # mirrors missing from complete listings of their status: deleted only on a 404
        if complete:
            listed_mirrors = [m for m in mirrors.values() if m.status in statuses]
            for mirror in classify.deletion_candidates(listed_mirrors, seen):
                try:
                    case = await self._confirm_deleted(run, mirror)
                except (IncompleteError, GatewayError):
                    raise
                except Exception as exc:  # the database refused it: a finding, the next one
                    await self._case_failed(run, mirror.kibana_case_id, "", exc, mirror.case_id)
                    continue
                if case is not None:
                    seen[mirror.kibana_case_id] = case
                    run.detail["hidden"] = run.detail.get("hidden", 0) + 1
        changed = [
            case
            for kid, case in seen.items()
            if kid not in mirrors
            or (mirrors[kid].active and mirrors[kid].kibana_version != case.version)
        ]
        unchanged = [
            kid
            for kid, case in seen.items()
            if kid in mirrors
            and mirrors[kid].active
            and mirrors[kid].kibana_version == case.version
        ]
        await self.store.touch(unchanged, self.clock())
        changed.sort(key=lambda c: (c.changed_at, c.id))  # oldest change first: no starvation
        await self._changed(run, changed, mirrors)

    async def _confirm_deleted(self, run: _Run, mirror: Mirror) -> KCase | None:
        """``cases.get`` of a mirror's case: a 404 records "deleted in Kibana" (None), else the
        case as it is (a listing can lag or page: a missing id alone never counts)."""
        try:
            got = await self._read(run, CaseGet(), CaseParams(case_id=mirror.kibana_case_id))
        except KibanaNotFoundError:
            gone, finding = classify.deleted(mirror, self.clock())
            run.findings += await self.store.apply(
                gone, [finding], new=False, found_at=self.clock()
            )
            run.detail["deleted"] = run.detail.get("deleted", 0) + 1
            return None
        return parse_case(got.body)

    async def _changed(self, run: _Run, cases: list[KCase], mirrors: dict[str, Mirror]) -> None:
        new_ids = [c for c in cases if c.id not in mirrors]
        tagged = [u for c in new_ids for u in c.argus_case_ids() if c.created_by not in self.team]
        known = await self.store.sent_creates(sorted(set(tagged), key=str))
        team_new = [c for c in new_ids if c.created_by in self.team]
        posts = (
            await self.store.team_posts(
                sorted(c.id for c in team_new), sorted({t for c in team_new for t in c.tags})
            )
            if team_new
            else []
        )
        by_case = mirrored_by_case(mirrors.values())
        for case in cases:
            if case.id in run.processed:
                continue  # read earlier this cycle (held for another look at the next)
            mirror = mirrors.get(case.id)
            try:
                await self._one(run, case, mirror, known, by_case, posts)
            except (IncompleteError, GatewayError):
                raise  # the cycle ends: the lane, Kibana or the answer, not this case
            except Exception as exc:  # the database refused this case, or a bug: the rest go on
                await self._case_failed(
                    run, case.id, case.version, exc, None if mirror is None else mirror.case_id
                )

    async def _one(
        self,
        run: _Run,
        case: KCase,
        mirror: Mirror | None,
        known: Mapping[uuid.UUID, int],
        by_case: dict[uuid.UUID, str],
        posts: Sequence[TeamPost] = (),
    ) -> None:
        new = mirror is None
        if mirror is None:
            if case.created_by in self.team:
                adoption = classify.adopt_team(case, posts=posts, mirrored=by_case)
            else:
                adoption = classify.adopt(case, known=known, mirrored=by_case)
            if adoption.case_id is None:
                if adoption.pause_all:
                    await self._alarm(adoption.findings)
                run.findings += await self.store.add_findings(adoption.findings, self.clock())
                return
            mirror = classify.new_mirror(adoption.case_id, case, self.clock())
        try:
            actions, rewound = await self._actions(run, case.id, mirror.actions_seen)
        except KibanaNotFoundError:  # deleted since it was listed
            run.detail["vanished"] = run.detail.get("vanished", 0) + 1
            if not new:  # a mirrored case: confirmed by a get and recorded at once
                await self._confirm_deleted(run, mirror)
            return
        findings: list[Finding] = []
        if rewound:
            findings.append(
                Finding(
                    Kind.ACTIONS_REWOUND,
                    f"rewound:{case.id}:{case.version}",
                    case.id,
                    mirror.case_id,
                    {"seen": mirror.actions_seen},
                )
            )
            mirror = replace(mirror, actions_seen=0, argus_actions={}, unexplained={})
        sent = (await self.store.sent_writes([mirror.case_id]))[mirror.case_id]
        now = self.clock()
        outcome = classify.classify_case(
            mirror,
            case,
            actions,
            sent,
            author=self.config.author,
            now=now,
            kibana_now=self._kibana_time(now, run.offset_ms),
            complete=True,
            settle=self.config.settle,
            team=self.team,
        )
        if outcome.pause_all:
            await self._alarm(outcome.findings)
        run.findings += await self.store.apply(
            outcome.mirror, [*findings, *outcome.findings], new=new, found_at=now
        )
        run.changed += 1
        run.processed.add(case.id)
        by_case[mirror.case_id] = case.id
        if case.sync_alerts:
            run.synced[case.id] = case.changed_at

    async def _alarm(self, findings: Iterable[Finding]) -> None:
        """Pause every write class when one of these alarms has not been kept yet: before the
        finding is kept, so a crash between the two cannot lose the pause, and only for a new
        finding, so a pause the owner lifted is not applied again for an old one."""
        keys = [f.dedupe_key for f in findings if f.severity is Severity.ALARM]
        if keys and await self.store.unseen_keys(keys):
            await self._pause_all(PAUSED_BY_ALARM)

    async def _case_failed(
        self, run: _Run, kid: str, version: str, exc: Exception, case_id: uuid.UUID | None
    ) -> None:
        """A case the read-back could not keep (the database refused it, a bug): a finding,
        the cycle ends ``partial`` and goes on with the other cases."""
        log.error("kibana sync: case %s could not be kept", kid, exc_info=exc)
        run.failed.append(kid)
        what = redact_text(f"{type(exc).__name__}: {exc}")
        run.findings += await self.store.add_findings(
            [
                Finding(
                    Kind.ANSWER_UNEXPECTED,
                    f"case-failed:{kid}:{version}",
                    kid,
                    case_id,
                    {"problem": "the read-back could not keep the case", "error": untrusted(what)},
                )
            ],
            self.clock(),
        )

    async def _actions(self, run: _Run, case_id: str, seen: int) -> tuple[list[KAction], bool]:
        """The case's user actions after the first ``seen``, oldest first; ``rewound`` when
        Kibana now holds fewer than were read (then all of them, from the start)."""
        per = self.config.per_page
        page, skip = seen // per + 1, seen % per
        actions: list[KAction] = []
        rewound = False
        while True:
            if page * per > MAX_PAGE_DEPTH:
                raise IncompleteError(f"case {case_id} has more user actions than Kibana pages")
            params = CasePageParams(case_id=case_id, page=page, per_page=per, sort_order="asc")
            body = (await self._read(run, CaseUserActions(), params)).body
            total = body["total"]
            if total < seen and not rewound:
                rewound, seen, page, skip, actions = True, 0, 1, 0, []
                continue
            items = [parse_action(a) for a in body["userActions"]]
            actions += items[skip:]
            skip = 0
            if not items or page * per >= total:
                break
            page += 1
        return actions, rewound

    async def _discovery(self, run: _Run) -> None:
        """Alert changes on ARGUS's cases, then people's cases holding known alerts: a few
        searches of 100 alerts each, a rotating window, so the read load is the same however
        many alerts the cases hold."""
        mirrors = await self.store.mirrors()
        state = await self.store.state()
        horizon = self.clock() - self.config.window
        # the alert diff is ARGUS's own writer's: the people on a case-team incident triage its
        # alerts in Kibana as part of the work, which is no unexplained change
        live = {
            m.kibana_case_id: (m.kibana_case_id, m.case_id)
            for m in mirrors.values()
            if m.active
            and m.created_by not in self.team
            and (m.status != "closed" or (m.kibana_updated_at or m.kibana_created_at) >= horizon)
        }
        synced = {
            m.kibana_case_id: m.kibana_updated_at
            for m in mirrors.values()
            if m.active and m.sync_alerts and m.kibana_updated_at is not None
        } | run.synced
        checked_to = self._kibana_time(self.clock(), run.offset_ms)
        links, diff_cursor = await self._diff_links(run, sorted(live), state.diff_cursor)
        alert_ids = sorted({link.alert_id for link in links})
        explained = await self.store.explained_alerts(alert_ids)
        previous = await self.store.alert_states(alert_ids)
        outcome = classify.classify_alerts(
            links,
            previous=previous,
            explained=explained,
            author=self.config.author,
            case_of=live,
            now=self.clock(),
            synced=synced,
            slack=self.config.overlap,
        )
        if outcome.pause_all:
            await self._pause_all(PAUSED_BY_ALARM)  # first: the baselines and findings are one
        run.findings += await self.store.record_alerts(
            outcome.states, outcome.findings, self.clock()
        )
        cursor = state.discovery_cursor
        since = self.clock() - self.config.window
        people: dict[str, set[str]] = {}
        for _ in range(self.config.discovery_calls):
            batch = await self.store.known_alerts(cursor, since, LINKS_BATCH)
            if not batch:
                cursor = None
                break
            for link in await self._links(run, alert_ids=tuple(a for a, _ in batch)):
                for kid in link.case_ids:
                    if kid not in mirrors:
                        people.setdefault(kid, set()).add(link.alert_id)
            cursor = batch[-1][1] if len(batch) == LINKS_BATCH else None
            if cursor is None:
                break
        await self._people(run, people)
        await self.store.save_state(
            replace(
                await self.store.state(),
                last_discovery_at=self.clock(),
                discovery_cursor=cursor,
                diff_cursor=diff_cursor,
                alerts_checked_to=checked_to,
            )
        )
        run.detail["discovery"] = {
            "alert_links": len(links),
            "people_cases": len(people),
            "live_cases": len(live),
        }

    async def _diff_links(
        self, run: _Run, ids: list[str], cursor: str | None
    ) -> tuple[list[AlertLink], str]:
        """The next slice of the alerts on ``ids`` (ARGUS's cases still of interest): at most
        ``diff_calls`` searches of 100, from where the last discovery stopped, over batches of
        100 cases; a sweep that reaches the end starts over at the next discovery. Returns the
        alerts and the place to go on from."""
        batches = [tuple(ids[i : i + LINKS_BATCH]) for i in range(0, len(ids), LINKS_BATCH)]
        batch, after = _decode_diff(cursor)
        if batch >= len(batches):
            batch, after = 0, None
        links: list[AlertLink] = []
        for _ in range(self.config.diff_calls):
            if batch >= len(batches):
                break
            params = CaseLinksParams(
                case_ids=batches[batch], alert_ids=None, size=LINKS_BATCH, after=after
            )
            page, last = parse_links(await self._search(run, params))
            links += page
            if len(page) < LINKS_BATCH or last is None:
                batch, after = batch + 1, None
            else:
                after = last
        if batch >= len(batches):
            batch, after = 0, None
        run.detail["diff_at"] = [batch, bool(after)]
        return links, _encode_diff(batch, after)

    async def _links(
        self,
        run: _Run,
        *,
        alert_ids: tuple[str, ...],
    ) -> list[AlertLink]:
        found: list[AlertLink] = []
        after: tuple[str | int, ...] | None = None
        while True:
            params = CaseLinksParams(alert_ids=alert_ids, size=LINKS_BATCH, after=after)
            page, after = parse_links(await self._search(run, params))
            found += page
            if len(page) < LINKS_BATCH or after is None:
                return found

    async def _people(self, run: _Run, people: Mapping[str, Iterable[str]]) -> None:
        known = await self.store.people_cases()
        gets = 0
        for kid in sorted(people):
            alerts = tuple(
                sorted(set(people[kid]) | set(known[kid].known_alerts if kid in known else ()))
            )
            if kid in known and set(alerts) <= set(known[kid].known_alerts):
                continue  # nothing new on it
            if gets >= MAX_PEOPLE_GETS:
                run.detail["people_later"] = run.detail.get("people_later", 0) + 1
                continue  # the next discovery reads the rest
            gets += 1
            try:
                got = await self._read(run, CaseGet(), CaseParams(case_id=kid))
            except KibanaNotFoundError:
                continue
            case = parse_case(got.body)
            if case.created_by in self.config.identities:
                continue  # one of ARGUS's (or the case team's): the listing reconciles it
            now = self.clock()
            finding = Finding(
                Kind.PEOPLE_CASE,
                f"people:{case.id}",
                case.id,
                None,
                {
                    "title": untrusted(case.title),
                    "by": untrusted(case.created_by),
                    "alerts": len(alerts),
                },
            )
            try:
                # the finding first: a crash between the two leaves the case to be read again,
                # never a case kept without its finding
                run.findings += await self.store.add_findings([finding], now)
                await self.store.save_people_case(
                    PeopleCase(
                        case.id,
                        untrusted(case.title),
                        case.status,
                        case.created_by,
                        case.tags[:50],
                        alerts[:200],
                        case.updated_at,
                        now,
                    ),
                    now,
                )
            except Exception as exc:  # the database refused this one: a finding, the next
                await self._case_failed(run, case.id, case.version, exc, None)


def _encode_diff(batch: int, after: tuple[str | int, ...] | None) -> str:
    return json.dumps({"batch": batch, "after": None if after is None else list(after)})


def _decode_diff(cursor: str | None) -> tuple[int, tuple[str | int, ...] | None]:
    try:
        data = json.loads(cursor) if cursor else {}
        batch, after = data.get("batch", 0), data.get("after")
        if isinstance(batch, int) and not isinstance(batch, bool) and batch >= 0:
            if after is None:
                return batch, None
            if isinstance(after, list) and len(after) == 2:
                return batch, (after[0], after[1])
    except (ValueError, AttributeError):
        pass
    return 0, None
