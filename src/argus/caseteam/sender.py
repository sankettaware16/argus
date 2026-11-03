"""The case team's poster: the plan for a case in, the six users' requests out.

For each case: (1) **prepare** (no writes): the stored report, the person's decision, what the case
holds, the plan, the policy's decision and anything that stops it (a missing key, a text the
guardian refuses); the dry run, preview, API and case page show exactly this; (2) **persist** the
plan as ``planned`` rows (a plan nothing was sent for is replaced when the report changed); (3)
**send** step by step, once each, by its author's key through the Kibana lane (class WC).
**Resuming** is the same walk: a step left ``sending`` or in doubt (``ambiguous``) is **looked for
in Kibana before anything is sent again**, at 2, 5, 15 and 30 minutes, then waits for a person
(``resend``); the step in doubt holds the ones after it. Runs are bounded: one advisory lock, one
Kibana write run, the lane's cap of case writes. Nothing is sent to a placeholder, retried inside a
step, edited, deleted or sent twice (a tag call only adds to a set, so it may be sent again)."""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, time, timedelta
from typing import Any

from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.cases.signing import Verifier
from argus.caseteam import approvals, guard, plan, policy, render, store, visual
from argus.caseteam.model import (
    DONE_STATES,
    EDIT_KINDS,
    OPEN_STATES,
    PERSON_EDIT,
    Author,
    Plan,
    Step,
    text_hash,
)
from argus.caseteam.store import PostRow, StepRow
from argus.gateway.builtin import AlertCaseLinks, CaseLinksParams
from argus.gateway.errors import GatewayError, RefusedError
from argus.gateway.gateway import utcnow
from argus.gateway.kibana import models
from argus.gateway.kibana.errors import (
    AnswerMismatchError,
    KibanaConflictError,
    KibanaResponseError,
    UnknownOutcomeError,
    WriteRefusedError,
)
from argus.gateway.kibana.gateway import KibanaGateway, WriteContext, WriteRun, build_final
from argus.gateway.kibana.templates import (
    CaseComments,
    CaseGet,
    CasePageParams,
    CaseParams,
    CasesFind,
    CaseUserActions,
    FindParams,
)
from argus.gateway.kibana.validator import KFinal
from argus.gateway.kibana.writes import WriteClass
from argus.gateway.templates import Purpose
from argus.incident import model as m
from argus.incident import store as incident_store
from argus.writer.render import clean

log = logging.getLogger("argus.caseteam")

COMPONENT = "caseteam"
WRITE_DEADLINE = timedelta(minutes=5)
READ_DEADLINE = timedelta(minutes=2)
CASE_GAP_WAIT = 3.1  # case writes are 3 s apart
GAP_WAITS = 20  # gaps waited out for one step: a run keeps sending while the lane admits
POSTPONE = timedelta(minutes=2)  # a look that could not be made is tried again after this
TAG_RETRY = timedelta(minutes=10)  # a tag call that met version conflicts is tried once more then
_HOLDING: ContextVar[bool] = ContextVar("case_team_lock_held", default=False)
# why an attach is skipped under Sync alerts
SYNC_NOT_OPEN = (
    "Sync alerts is on and the case is not open: the attach would change the alerts' status"
)

ALL_USERS = frozenset(a.value for a in Author)


class RunStopped(Exception):  # noqa: N818 - a stop, not a failure
    """The run ends here: the lane refused, a step is in doubt, a person must decide."""


class EditConflict(Exception):  # noqa: N818 - Kibana's 409 on an edit: read again, once
    """Kibana refused an edit because the case or comment changed since ARGUS read it."""


@dataclass
class _Session:
    """What one run of the poster shares between its cases: the Kibana write run (so the lane's
    per-run cap counts the whole run, not each case) and the case writes this run has sent (the
    poster's own count, which a restarted write run cannot reset)."""

    run: WriteRun | None = None
    writes: int = 0


@dataclass(frozen=True)
class PostConfig:
    """The settings the poster reads (``case_team``, and the addresses its links use)."""

    post: bool = False
    auto: bool = True
    auto_min_confidence: float = 0.8
    per_day: int = 5
    canary: int = 1
    max_alerts: int = 500
    alerts_per_call: int = 100
    alert_pause: timedelta = timedelta(seconds=3)  # the least between two alert calls
    min_update_gap: timedelta = timedelta(hours=6)
    look: int = 40
    link_base: str = "https://argus.example"
    kibana_prefixes: tuple[str, ...] = ()
    space: str = field(default_factory=lambda: site.active().space)
    keys: frozenset[str] | None = None
    """The users whose key is installed in *this* process. Only the writer holds them (custody);
    None: this process does not check (a preview, the web), the writer does before it posts."""

    def has_key(self, user: str) -> bool:
        return self.keys is None or user in self.keys

    @property
    def context(self) -> render.Context:
        return render.Context(self.link_base, self.kibana_prefixes)

    @property
    def target(self) -> plan.Target:
        return plan.Target(self.space)


@dataclass
class Prepared:
    """What a case would do now (:meth:`Poster.prepare`); nothing was written."""

    case_id: uuid.UUID
    number: int
    state: str
    stored: incident_store.Stored | None
    post: PostRow | None
    rows: list[StepRow]  # the live generation's rows, as persisted
    plan: Plan | None  # the plan the decision is about (the persisted one while in progress)
    decision: policy.Decision
    facts: policy.Facts | None = None
    approval: str | None = None  # why the canary approval does not stand (None: it does)
    problems: list[str] = field(default_factory=list)  # what stops sending, in words
    notes: list[str] = field(default_factory=list)  # what a person should know, not a stop
    open_done: bool = False
    in_progress: bool = False

    @property
    def ready(self) -> bool:
        """Whether a run would write something to Kibana now."""
        return self.decision.acts and not self.problems


@dataclass
class PostReport:
    case_id: uuid.UUID
    number: int
    decision: policy.Decision
    sent: int = 0
    verified: int = 0
    ambiguous: int = 0
    held: list[str] = field(default_factory=list)
    stopped: str | None = None
    note: str | None = None

    def lines(self) -> list[str]:
        out = [
            f"case {self.number}: {self.decision.action}"
            + (f" ({self.decision.why})" if self.decision.why else "")
        ]
        if self.sent or self.verified or self.ambiguous:
            out.append(f"  {self.sent} sent, {self.verified} confirmed, {self.ambiguous} in doubt")
        out += [f"  held: {why}" for why in self.held]
        if self.stopped:
            out.append(f"  stopped: {self.stopped}")
        if self.note:
            out.append(f"  {self.note}")
        return out


@dataclass
class RefreshReport:
    """What ``argus case team refresh`` would do (or did) to a posted case."""

    number: int
    plan: Plan | None = None
    problems: list[str] = field(default_factory=list)
    planned: bool = False  # the steps were written (``apply``); the next run sends them

    def lines(self) -> list[str]:
        out = [f"case {self.number}: refresh"]
        out += [f"  cannot refresh: {why}" for why in self.problems]
        if self.plan is not None and not self.problems:
            if not self.plan.steps:
                out.append("  nothing differs: the case in Kibana already reads as the report says")
            else:
                out.append(f"  plan {self.plan.plan_hash[:16]}: {len(self.plan.steps)} edits")
            for n, step in enumerate(self.plan.steps, 1):
                size = f", {len(step.text)} characters" if step.text else ""
                out.append(f"  {n:>2}. {step.describe()}{size}  [{step.key}]")
            if self.planned:
                out.append("  planned: the case team's next run sends these (a person's edit in")
                out.append("  Kibana is never overwritten: that edit is left and said)")
            elif self.plan.steps:
                out.append("  dry run: nothing was planned (add --apply to plan these)")
        return out


async def _person_core(
    conn: AsyncConnection,
    case_id: uuid.UUID,
    decided: store.PersonDecision | None,
    newest: incident_store.Stored,
) -> str | None:
    """The hash, without the accounts, of the report version a person decided on: None
    when nobody did or that version cannot be read."""
    if decided is None:
        return None
    if decided.version == newest.version:
        return m.core_hash(newest.report)
    older = await incident_store.version(conn, case_id, decided.version)
    return None if older is None else m.core_hash(older.report)


def _ist_day(now: datetime) -> tuple[datetime, datetime]:
    zone = site.zone()
    local = now.astimezone(zone)
    start = datetime.combine(local.date(), time(0), zone)
    return start.astimezone(UTC), (start + timedelta(days=1)).astimezone(UTC)


def _generations(rows: list[StepRow]) -> dict[int, list[StepRow]]:
    out: dict[int, list[StepRow]] = {}
    for r in rows:
        if r.state != "superseded":
            out.setdefault(r.gen, []).append(r)
    return out


class Preparer:
    """What a case would do now (no writes, no Kibana lane): the dry run that the CLI's preview,
    the API and the case page show, and the first half of every post."""

    def __init__(
        self,
        config: PostConfig,
        verifier: Verifier | None = None,
        clock: Callable[[], datetime] = utcnow,
    ) -> None:
        self.config = config
        self.verifier = verifier
        self.clock = clock

    async def prepare(self, conn: AsyncConnection, case_id: uuid.UUID) -> Prepared:
        cfg, now = self.config, self.clock()
        case = await store.case_row(conn, case_id)
        if case is None:
            raise LookupError(f"no case {case_id}")
        stored = await incident_store.latest(conn, case_id)
        post = await store.post_of(conn, case_id)
        gens = _generations(await store.steps_of(conn, case_id))
        live_gen = max(gens) if gens else 0
        live = gens.get(live_gen, [])
        open_row = next((r for rows in gens.values() for r in rows if r.kind == "open"), None)
        open_gen = [] if open_row is None else gens[open_row.gen]
        open_done = bool(
            open_row is not None
            and post is not None
            and post.kibana_case_id is not None
            and all(r.state in DONE_STATES for r in open_gen)
        )
        unfinished = any(r.state not in DONE_STATES for r in live)
        # a refresh a person planned is finished before anything else is planned: a newer
        # report does not replace it
        refreshing = any(r.kind in ("redescribe", "edit_comment") for r in live)
        in_progress = unfinished and (refreshing or any(r.sent_count > 0 for r in live))
        prep = Prepared(
            case_id,
            int(case.number),
            str(case.state),
            stored,
            post,
            live,
            None,
            policy.Decision("none", "ARGUS has not written this case's report yet"),
            open_done=open_done,
            in_progress=in_progress,
        )
        if stored is None:
            return prep
        report = stored.report
        ctx = cfg.context
        if in_progress:
            prep.plan = store.plan_of(
                live, report.header.incident_id, post.kibana_case_id if post else None
            )
        else:
            found = await store.alerts_of(conn, case_id, cfg.max_alerts)
            alerts = [plan.AlertRef(a, i) for a, i in found if cfg.target.concrete(i)]
            if len(alerts) < len(found):  # an alias or another space's index cannot be attached
                prep.notes.append(
                    f"{len(found) - len(alerts)} alerts are left out: their index is not one of"
                    " the space's concrete alert indices"
                )
            posted = await store.posted_state(conn, case_id) if open_done else None
            if posted is not None:
                prep.plan = plan.update_plan(
                    report,
                    stored.version,
                    alerts,
                    ctx,
                    posted,
                    max_alerts=cfg.max_alerts,
                    target=cfg.target,
                    per_call=cfg.alerts_per_call,
                )
                if not cfg.has_key(Author.VISUALISER.value):  # a round has no use for it
                    steps = tuple(s for s in prep.plan.steps if s.author is not Author.VISUALISER)
                    prep.plan = replace(prep.plan, steps=steps)
                last_round = None if post is None else post.last_round_at
                if last_round is not None and now - last_round < cfg.min_update_gap:
                    # the round has to wait, but a title that moved does not
                    titles = tuple(s for s in prep.plan.steps if s.kind == "retitle")
                    if titles:
                        prep.plan = replace(prep.plan, steps=titles)
            else:
                prep.plan = plan.first_plan(
                    report, stored.version, alerts, ctx, cfg.target, cfg.alerts_per_call
                )
        decided = await store.person_decision(conn, case_id)
        day_start, day_end = _ist_day(now)
        total = await store.opened_total(conn)
        facts = policy.Facts(
            post=cfg.post,
            case_state=prep.state,
            report=report,
            version=stored.version,
            person=None if decided is None else decided.decision,  # type: ignore[arg-type]
            person_outcome=None if decided is None else decided.outcome,
            person_version=None if decided is None else decided.version,
            core=m.core_hash(report),
            person_core=await _person_core(conn, case_id, decided, stored),
            open_done=open_done,
            last_version=None if post is None else post.last_version,
            last_round_at=None if post is None else post.last_round_at,
            in_progress=in_progress,
            opened_today=await store.opened_between(conn, day_start, day_end),
            opened_total=total,
            approved=False,
            has_news=bool(prep.plan.steps) and open_done,
            edits_only=bool(prep.plan.steps) and all(s.kind in EDIT_KINDS for s in prep.plan.steps),
            now=now,
            auto_min_confidence=cfg.auto_min_confidence,
            auto=cfg.auto,
            per_day=cfg.per_day,
            canary=cfg.canary,
            min_update_gap=cfg.min_update_gap,
        )
        needs_approval = not open_done and not in_progress and total < cfg.canary
        if needs_approval:
            prep.approval = await approvals.problem(
                conn, self.verifier, case_id, prep.plan.plan_hash, now
            )
            facts = replace(facts, approved=prep.approval is None)
        prep.facts = facts
        prep.decision = policy.decide(facts)
        self._check(prep)
        return prep

    def _check(self, prep: Prepared) -> None:
        """What stops a plan from being sent, found before anything is: a key that is not
        installed (fail closed: a case is never half-posted for want of one user's key) and a
        text the guardian refuses."""
        if prep.plan is None:
            return
        optional = Author.VISUALISER.value  # its step is skipped, never a stop
        missing = sorted(
            a for a in prep.plan.authors() if a != optional and not self.config.has_key(a)
        )
        if missing:
            prep.problems.append("no key is installed for " + ", ".join(missing))
        if optional in prep.plan.authors() and not self.config.has_key(optional):
            prep.notes.append(f"{visual.TITLE} is skipped: {visual.SKIPPED}")
        allowed = self.config.context.allowed
        for step in prep.plan.steps:
            if step.text is None:
                continue
            try:
                guard.check(step.text, allowed)
            except guard.GuardRefusal as refusal:
                prep.problems.append(f"the guardian refuses {step.key}: {refusal}")
        if prep.stored is not None and not self.config.link_base:
            prep.problems.append("web.public_url is not set")

    def requests(self, prep: Prepared) -> list[dict[str, Any]]:
        """Each step's exact request as it would go (method, path, content type, body); a file's
        body is described, not printed."""
        if prep.plan is None or prep.stored is None:
            return []
        kibana_id = None if prep.post is None else prep.post.kibana_case_id
        out: list[dict[str, Any]] = []
        for s in prep.plan.steps:
            template, params = plan.request_of(s, kibana_id, prep.stored.report)
            final = build_final(template, params, self.config.space, self.config.target.prefix)
            out.append(describe_request(s, final))
        return out


class Poster:
    def __init__(
        self,
        engine: AsyncEngine,
        gateway: KibanaGateway | None,
        config: PostConfig,
        *,
        verifier: Verifier | None = None,
        clock: Callable[[], datetime] = utcnow,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        wait_for_gaps: bool = False,
    ) -> None:
        self.engine = engine
        self._gateway = gateway  # None: a poster that only prepares (the preview)
        self.config = config
        self.verifier = verifier
        self.clock = clock
        self.sleep = sleep
        self.wait_for_gaps = wait_for_gaps  # a run waits out the 3 s case and the alert gaps
        self.preparer = Preparer(config, verifier, clock)
        self._session = _Session()

    @property
    def gateway(self) -> KibanaGateway:
        if self._gateway is None:
            raise RunStopped("this poster has no Kibana lane (a preview only prepares)")
        return self._gateway

    async def prepare(self, conn: AsyncConnection, case_id: uuid.UUID) -> Prepared:
        return await self.preparer.prepare(conn, case_id)

    def requests(self, prep: Prepared) -> list[dict[str, Any]]:
        return self.preparer.requests(prep)

    @asynccontextmanager
    async def _exclusive(self) -> AsyncIterator[bool]:
        """One case-team run at a time, across processes (a session-level advisory lock): True
        when this call holds it (a call made while its own task already holds it, as a pass's
        cases do, holds it too), False when another run does. The writes of one run share one
        Kibana write run and one count against the lane's per-run cap (:class:`_Session`)."""
        if _HOLDING.get():
            yield True
            return
        async with self.engine.connect() as lock:
            got = bool(
                (
                    await lock.execute(
                        text("SELECT pg_try_advisory_lock(:k)"), {"k": store.LOCK_KEY}
                    )
                ).scalar_one()
            )
            # the lock is the session's: end the transaction, or the connection idles in it for
            # the whole run (the lane's waits) and the server's idle-in-transaction limit ends it
            await lock.commit()
            token = _HOLDING.set(got)
            self._session = _Session()
            try:
                yield got
            finally:
                _HOLDING.reset(token)
                self._session = _Session()
                if got:
                    await lock.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": store.LOCK_KEY})
                await lock.commit()

    async def run_case(
        self, case_id: uuid.UUID, *, by: str = "argus:caseteam", only_resume: bool = False
    ) -> PostReport:
        async with self._exclusive() as got:
            if not got:
                async with self.engine.connect() as conn:
                    number = await store.case_row(conn, case_id)
                held = policy.Decision("none", "another case team run holds the lock")
                busy = PostReport(case_id, 0 if number is None else int(number.number), held)
                busy.stopped = "another case team run is in progress: nothing was done"
                return busy
            try:
                return await self._run_case(case_id, by=by, only_resume=only_resume)
            finally:
                await self._examined(case_id)

    async def _examined(self, case_id: uuid.UUID) -> None:
        """The poster looked at this case: it goes to the back of the rotation."""
        try:
            async with self.engine.begin() as conn:
                await store.touch_examined(conn, case_id, self.clock())
        except Exception:  # the rotation is a convenience: never part of a post
            log.warning("could not record the look at case %s", case_id)

    async def _run_case(
        self, case_id: uuid.UUID, *, by: str, only_resume: bool = False
    ) -> PostReport:
        async with self.engine.connect() as conn:
            prep = await self.prepare(conn, case_id)
        report = PostReport(case_id, prep.number, prep.decision)
        d = prep.decision
        try:
            if d.acts and not (only_resume and d.action != "resume"):
                if prep.problems:
                    report.held += prep.problems
                else:
                    await self._carry_out(prep, report, by)
            else:
                report.note = d.why
            if prep.stored is not None:  # (each checks that the Kibana case exists by now)
                await self._closings(case_id, prep, report)
                await self._notes(case_id, prep, report)
        except RunStopped as stop:
            report.stopped = str(stop)
        return report

    async def run_pass(
        self, *, by: str = "argus:caseteam", limit: int | None = None
    ) -> list[PostReport]:
        """One pass: the unfinished posts first, then the cases that could qualify (picked in
        SQL, the least recently examined first), within the lane's caps."""
        async with self._exclusive() as got:
            if not got:
                return []
            async with self.engine.connect() as conn:
                ids = await store.candidates(
                    conn,
                    limit or self.config.look,
                    self.config.auto_min_confidence if self.config.auto else None,
                )
            reports: list[PostReport] = []
            for case_id in ids:
                rep = await self.run_case(case_id, by=by)
                reports.append(rep)
                if rep.stopped and rep.stopped.startswith(("Kibana", "the lane")):
                    break  # Kibana is not ready (or this run's cap is reached): the rest wait
            return reports

    async def _persist(self, prep: Prepared) -> list[StepRow]:
        """The plan as rows: a generation nothing was sent for is replaced when it changed."""
        assert prep.plan is not None
        assert prep.stored is not None
        if prep.in_progress:
            return prep.rows
        want = prep.plan
        async with self.engine.begin() as conn:
            await store.ensure_post(conn, prep.case_id, want.incident_id)
            gens = _generations(await store.steps_of(conn, prep.case_id))
            live_gen = max(gens) if gens else 0
            live = gens.get(live_gen, [])
            if live and any(r.state not in DONE_STATES for r in live):
                same = (
                    store.plan_of(live, want.incident_id, want.kibana_case_id).plan_hash
                    == want.plan_hash
                )
                if same:
                    return live
                await store.supersede_planned(conn, prep.case_id, live_gen, "the report changed")
            gen = await store.latest_gen(conn, prep.case_id) + 1
            await store.write_generation(conn, prep.case_id, replace(want, gen=gen))
            return await store.steps_of(conn, prep.case_id, gen)

    async def _carry_out(self, prep: Prepared, report: PostReport, by: str) -> None:
        assert prep.stored is not None
        assert prep.plan is not None
        rows = await self._persist(prep)
        await self._walk(prep.case_id, rows[0].gen, prep.stored, report, by)

    async def _walk(
        self,
        case_id: uuid.UUID,
        gen: int,
        stored: incident_store.Stored,
        report: PostReport,
        by: str,
    ) -> None:
        """Send a generation's steps in order, resuming where it left off."""
        incident_id = stored.report.header.incident_id
        for _ in range(500):  # a generation has a few dozen steps; this only ends a bug
            async with self.engine.connect() as conn:
                post = await store.post_of(conn, case_id)
                rows = await store.steps_of(conn, case_id, gen)
                version = rows[0].report_version if rows else stored.version
                at = (
                    stored
                    if version == stored.version
                    else await incident_store.version(conn, case_id, version)
                )
            if post is None or at is None or not rows:
                raise RunStopped("the post or its report is gone")
            nxt = next((r for r in rows if r.state not in DONE_STATES), None)
            if nxt is None:
                await self._finish(post, rows, at, report)
                return
            if nxt.state in ("sending", "ambiguous"):
                if await self._resolve(nxt, post, at.report, report):
                    continue
                raise RunStopped(f"{nxt.key} is in doubt: {nxt.state_reason or 'waiting'}")
            if nxt.state in ("resend", "failed", "held"):
                raise RunStopped(f"{nxt.key} waits for a person ({nxt.state}: {nxt.state_reason})")
            if nxt.kind == "open" and not await self._approved(case_id, rows, post, report):
                raise RunStopped("the first sequence needs a person's approval (canary)")
            await self._send(nxt, post, at.report, report, incident_id)
        raise RunStopped("too many steps in one generation")

    async def _approved(
        self, case_id: uuid.UUID, rows: list[StepRow], post: PostRow, report: PostReport
    ) -> bool:
        """The canary: the first ``canary`` cases are sent only with a person's approval of
        exactly this plan (and the rows still hash as they did when it was planned)."""
        async with self.engine.connect() as conn:
            total = await store.opened_total(conn)
            already = post.opened_at is not None
            if already or total >= self.config.canary:
                return True
            why = await approvals.problem(
                conn,
                self.verifier,
                case_id,
                store.plan_of(rows, post.incident_id, None).plan_hash,
                self.clock(),
            )
        if why is not None:
            report.held.append(f"canary: {why}")
            return False
        return True

    async def _start_run(self, *, fresh: bool = False) -> WriteRun:
        """The Kibana write run of this poster run (one for every case it posts, so the lane's
        cap on a run's writes bounds the run); ``fresh``: the lane found it stale."""
        session = self._session
        if session.run is not None and not fresh:
            return session.run
        try:
            session.run = await self.gateway.start_run(
                component=COMPONENT, deadline=self.clock() + READ_DEADLINE
            )
        except (GatewayError, KibanaResponseError, WriteRefusedError) as exc:
            raise RunStopped(f"Kibana is not ready for writes ({_why(exc)})") from None
        return session.run

    def _room_in_run(self, step: Step) -> None:
        """The lane's cap on a run's case writes, kept here too as the run's own count (a write
        run restarted because it went stale starts the lane's count again; this one does not).
        A tag call is an alert write, not a case write: the lane does not count it either."""
        cap = self.gateway.caps.team_per_run
        if step.kind != "tag" and self._session.writes >= cap:
            raise RunStopped(
                f"the lane: run_cap, this run's {cap} case writes are sent; the rest waits for"
                " the next run"
            )

    async def _send(
        self,
        row: StepRow,
        post: PostRow,
        rep: m.IncidentReport,
        report: PostReport,
        incident_id: str,
    ) -> None:
        step = row.step()
        if step.author is Author.VISUALISER and not self.config.has_key(step.author.value):
            #  the seventh user is optional: without its key the step is skipped, not failed
            await self._mark(row, "skipped", visual.SKIPPED, ("planned",))
            said = f"{row.key}: {visual.SKIPPED}"
            report.note = f"{report.note}; {said}" if report.note else said
            return
        if step.kind != "open" and post.kibana_case_id is None:
            # a request built without the case's id would go to a placeholder: never sent
            why = "the Kibana case does not exist yet: nothing is sent to a placeholder"
            report.held.append(f"{row.key}: {why}")
            raise RunStopped(f"{row.key}: {why}")
        left: frozenset[str] = frozenset()
        if step.kind == "attach":
            seen = await self._attach_view(row, post, report)
            if seen is None:  # skipped: nothing to send (Sync alerts is on)
                return
            step, left = seen
        try:
            template, params = plan.request_of(step, post.kibana_case_id, rep)
            if step.text is not None:
                guard.check(step.text, self.config.context.allowed)
        except (ValueError, guard.GuardRefusal) as exc:
            await self._mark(row, "held", f"not sent: {exc}", ("planned", "resend"))
            report.held.append(f"{row.key}: {exc}")
            raise RunStopped(f"{row.key} was held: {exc}") from None
        if not self.config.has_key(step.author.value):
            report.held.append(f"{row.key}: no key is installed for {step.author.value}")
            raise RunStopped(f"no key is installed for {step.author.value}")
        if (
            step.kind == "open"
            and row.sent_count == 0
            and await self._adopt_existing(row, post, step, report)
        ):
            return
        if step.kind in EDIT_KINDS:
            await self._send_edit(row, post, step, rep, report)
            return
        if step.kind == "tag":  # the tags follow the attached alerts
            tagged = await self._tag_view(row, params, report)
            if tagged is None:
                return
            params = tagged
        result = await self._write_step(row, step, template, params, report)
        ids = _ids_of(step, result.body)
        if left:
            ids["left_out"] = sorted(left)
        if step.kind == "tag":
            ids, retry = await self._tag_result(row, params, result.body, ids, report)
            if retry:
                return
        async with self.engine.begin() as conn:
            if step.kind == "open":
                await store.set_kibana_case(conn, row.case_id, str(ids["case"]), self.clock())
            await store.settle(
                conn, row.id, "verified", only_from=["sending"], now=self.clock(), ids=ids
            )
        report.verified += 1
        if step.kind == "open":
            await self._read_back_open(row, str(ids["case"]), step, report, incident_id)

    async def _tag_view(
        self, row: StepRow, params: BaseModel, report: PostReport
    ) -> BaseModel | None:
        """A tag step tags what its attach step attached: nothing when that attach was skipped
        (the step is skipped with the same reason), and never the alerts the attach left out
        under Sync alerts. None when nothing is left to tag."""
        number = row.key.rsplit(":", 1)[-1]
        async with self.engine.connect() as conn:
            rows = await store.steps_of(conn, row.case_id)
        mates = [r for r in rows if r.gen == row.gen and r.key == f"attach:{number}"]
        if not mates:
            return params
        mate = mates[0]
        why = mate.state_reason or SYNC_NOT_OPEN
        if mate.state == "skipped":
            await self._mark(row, "skipped", why, ("planned",))
            said = f"{row.key}: {why}"
            report.note = f"{report.note}; {said}" if report.note else said
            return None
        left = store.left_out_of(mate)
        if not left:
            return params
        ids = tuple(a for a in getattr(params, "ids", ()) if a not in left)
        if not ids:
            await self._mark(
                row, "skipped", "every alert of the batch was left unattached", ("planned",)
            )
            return None
        return params.model_copy(update={"ids": ids})

    async def _attach_view(
        self, row: StepRow, post: PostRow, report: PostReport
    ) -> tuple[Step, frozenset[str]] | None:
        """The attach as it is to be sent (:func:`store.attach_view`), after one read of the case.
        With Sync alerts off nothing changes. With it on, Kibana sets each attached alert to the
        case's status: a case that is not open would change them all (the step is skipped, and
        said), an open case only re-opens an alert a person closed, so the alerts ARGUS records as
        not open are left out of the call. None: the step was skipped. Otherwise the step to send
        and the alerts left out of it (also kept in its ``kibana_ids``)."""
        kid = post.kibana_case_id
        assert kid is not None
        try:
            case = await self._read(CaseGet(), CaseParams(case_id=kid))
            sync = case["settings"].get("syncAlerts")
            status = case["status"]
        except (GatewayError, KibanaResponseError, KeyError, ValueError, AttributeError) as exc:
            raise RunStopped(f"{row.key}: Kibana could not be read ({_why(exc)})") from None
        async with self.engine.connect() as conn:
            rows = await store.steps_of(conn, row.case_id, row.gen)
        mine = next((r for r in rows if r.id == row.id), row)
        step = store.attach_view(rows, mine)
        left = store.left_out_of(mine)
        if sync is False:
            return step, left
        ours = [str(a) for a, _ in step.payload["alerts"]]
        if status != "open":
            closed, why = set(ours), SYNC_NOT_OPEN
        else:
            async with self.engine.connect() as conn:
                closed = await store.not_open_alerts(conn, ours)
            why = f"{len(closed)} closed alerts left unattached: Sync alerts is on"
        if not closed:
            return step, left
        empty = len(closed) == len(ours)
        async with self.engine.begin() as conn:
            moved = await store.leave_out_alerts(
                conn, row.id, sorted(left | closed), why, skip=empty
            )
        if not moved:
            raise RunStopped(f"{row.key}: the step moved while Sync alerts was read")
        report.note = (report.note + "; " if report.note else "") + f"{row.key}: {why}"
        if empty:
            return None
        async with self.engine.connect() as conn:
            rows = await store.steps_of(conn, row.case_id, row.gen)
        mine = next((r for r in rows if r.id == row.id), row)
        return store.attach_view(rows, mine), store.left_out_of(mine)

    async def _read_live(self, step: Step, kid: str) -> dict[str, str] | None:
        """What Kibana holds now for the thing an edit sets: the case's title, description and
        version, or the comment's text, version and author; None when the comment is not on the
        case. A read that fails stops the run (nothing is changed)."""
        try:
            if step.kind != "edit_comment":
                case = await self._read(CaseGet(), CaseParams(case_id=kid))
                return {
                    "title": str(case.get("title") or ""),
                    "description": str(case.get("description") or ""),
                    "version": str(case["version"]),
                }
            wanted = str(step.payload["comment_id"])
            for page in range(1, 11):
                answer = await self._read(
                    CaseComments(), CasePageParams(case_id=kid, page=page, per_page=100)
                )
                for c in answer["comments"]:
                    if c.get("id") == wanted:
                        by = c.get("created_by") or {}
                        return {
                            "text": str(c.get("comment") or ""),
                            "version": str(c.get("version") or ""),
                            "author": str(by.get("username") or ""),
                        }
                if page * 100 >= int(answer["total"]):
                    return None
        except (GatewayError, KibanaResponseError, KeyError, ValueError) as exc:
            raise RunStopped(f"{step.kind}: Kibana could not be read ({_why(exc)})") from None
        return None

    @staticmethod
    def _judge(step: Step, live: dict[str, str] | None) -> tuple[str, str]:
        """What to do with an edit given what Kibana holds: ``done`` (it already reads as the edit
        wants), ``person`` (it is neither what ARGUS last wrote nor what it wants: a person
        changed it, and ARGUS never overwrites that), ``gone`` (the comment is not there) or
        ``send``. This is also what makes an edit safe to do again after a doubt: it is read
        first, and sent only if Kibana still holds what ARGUS wrote before."""
        if live is None:
            return "gone", "the comment is not on the Kibana case"
        if step.kind == "retitle":
            now, want, was = live["title"], str(step.payload["title"]), step.payload.get("was")
            if now == want:
                return "done", "the title already reads so"
            if was is not None and now != was:
                return "person", PERSON_EDIT
            return "send", ""
        if step.kind == "redescribe":
            now = live["description"]
            if now == step.text:
                return "done", "the description already reads so"
            if text_hash(now) != step.payload.get("was_hash"):
                return "person", PERSON_EDIT
            return "send", ""
        if live["author"] != step.author.value:
            return "gone", f"the comment was not written by {step.author.value}"
        if live["text"] == step.text:
            return "done", "the comment already reads so"
        if text_hash(live["text"]) != step.payload.get("was_hash"):
            return "person", PERSON_EDIT
        return "send", ""

    async def _send_edit(
        self, row: StepRow, post: PostRow, step: Step, rep: m.IncidentReport, report: PostReport
    ) -> None:
        """An edit in place: read what Kibana holds, decide (:meth:`_judge`), and send the one
        PATCH against the version just read. A version conflict reads again and tries once more;
        if the case moved again the step waits for the next run. Nothing is ever sent over a
        person's change, and an edit Kibana already shows is only recorded."""
        kid = post.kibana_case_id
        assert kid is not None
        for _ in range(2):
            live = await self._read_live(step, kid)
            verdict, why = self._judge(step, live)
            now = self.clock()
            if verdict in ("done", "person", "gone"):
                to = "verified" if verdict == "done" else "skipped"
                async with self.engine.begin() as conn:
                    await store.settle(
                        conn,
                        row.id,
                        to,
                        only_from=["planned", "resend", "ambiguous"],
                        now=now,
                        reason=why,
                        ids=None if live is None else {"version": live.get("version", "")},
                    )
                if verdict == "done":
                    report.verified += 1
                else:
                    report.note = (report.note + "; " if report.note else "") + f"{row.key}: {why}"
                return
            assert live is not None
            template, params = plan.request_of(step, kid, rep, live["version"])
            try:
                result = await self._write_step(row, step, template, params, report)
            except EditConflict:
                continue
            ids = _ids_of(step, result.body)
            async with self.engine.begin() as conn:
                await store.settle(
                    conn, row.id, "verified", only_from=["sending"], now=self.clock(), ids=ids
                )
            report.verified += 1
            return
        raise RunStopped(f"{row.key}: Kibana changed again while it was edited; the next run tries")

    async def _write_step(
        self, row: StepRow, step: Step, template: Any, params: Any, report: PostReport
    ) -> Any:
        """Send one step's request once through the Kibana lane (waiting out the case and alert
        gaps, starting the write run again if it went stale), recording ``sending`` at the last
        moment; what comes back is the template's checked answer. An answer that says the write
        may have landed puts the step in doubt; an edit that met a version conflict (409: Kibana
        changed nothing) goes back to ``planned`` and :class:`EditConflict` is raised."""
        self._room_in_run(step)
        run = await self._start_run()
        context = WriteContext(
            WriteClass.WC, f"team:{row.id}", self.gateway.payload_hash(template, params)
        )
        committed = False

        async def commit_sending() -> None:
            nonlocal committed
            async with self.engine.begin() as conn:
                await store.begin_sending(conn, row.id, self.clock())
            committed = True
            report.sent += 1  # a request that leaves now: counted whatever comes back
            if step.kind != "tag":
                self._session.writes += 1

        waits = restarts = 0
        while True:
            try:
                result = await self.gateway.write(
                    template,
                    params,
                    run=run,
                    context=context,
                    component=COMPONENT,
                    deadline=self.clock() + WRITE_DEADLINE,
                    before_send=commit_sending,
                )
            except store.StateMovedError as moved:
                report.held.append(f"{row.key}: {moved}")
                raise RunStopped(str(moved)) from None
            except WriteRefusedError as refusal:
                if refusal.reason == "case_gap" and waits < GAP_WAITS:
                    waits += 1
                    await self.sleep(CASE_GAP_WAIT)
                    continue
                if refusal.reason == "alert_gap" and self.wait_for_gaps and waits < GAP_WAITS:
                    waits += 1
                    await self.sleep(self.config.alert_pause.total_seconds() + 1.0)
                    continue
                if refusal.reason == "run_stale" and restarts < 2:
                    restarts += 1
                    run = await self._start_run(fresh=True)
                    continue
                raise RunStopped(f"the lane: {refusal.reason}") from None
            except RefusedError as refusal:
                if committed:
                    await self._after_error(row, KibanaResponseError(str(refusal)), report)
                    raise RunStopped(f"refused after sending ({refusal})") from None
                raise RunStopped(f"the lane: {_why(refusal)}") from None
            except KibanaConflictError as conflict:
                if committed and step.kind in EDIT_KINDS:  # Kibana changed nothing: read again
                    await self._mark(
                        row, "planned", "the case changed meanwhile (409): read again", ("sending",)
                    )
                    raise EditConflict(row.key) from None
                if not committed:
                    raise RunStopped(f"Kibana: {_why(conflict)}") from None
                await self._after_error(row, conflict, report)
                raise RunStopped(f"{row.key}: {_why(conflict)}") from None
            except KibanaResponseError as exc:
                if not committed:
                    raise RunStopped(f"Kibana: {_why(exc)}") from None
                await self._after_error(row, exc, report)
                raise RunStopped(f"{row.key}: {_why(exc)}") from None
            return result

    async def _tag_result(
        self,
        row: StepRow,
        params: Any,
        body: Any,
        ids: dict[str, Any],
        report: PostReport,
    ) -> tuple[dict[str, Any], bool]:
        """What a tag call's answer says (Kibana's update report): every named alert tagged, or
        some are not. An alert that no longer exists (the alerts index dropped it) is found out
        and left out of the plan from here on, with a note on the case. An alert rewritten
        meanwhile (a version conflict) is tried once more by a later pass; if it conflicts
        again it is left and said. Neither holds the case: the steps after go on.
        Returns the ids to record and whether the call was put back for a later pass."""
        tagged = models.tag_report(body, params)
        if tagged.complete:
            return ids, False
        out: dict[str, Any] = {**ids, "gone_count": tagged.gone, "conflicts": tagged.conflicts}
        if tagged.gone:
            out["gone"] = sorted(await self._gone(params.ids))
        if tagged.conflicts and "conflicts" not in row.kibana_ids:  # the first time it met one
            now = self.clock()
            async with self.engine.begin() as conn:
                await store.settle(
                    conn,
                    row.id,
                    "ambiguous",
                    only_from=["sending"],
                    now=now,
                    ids=out,
                    reason=(
                        f"{tagged.conflicts} alerts were being rewritten (version conflicts):"
                        " the call is tried once more by a later pass"
                    ),
                    next_lookup_at=now + TAG_RETRY,
                    lookups=0,
                )
            report.note = (report.note + "; " if report.note else "") + (
                f"{row.key}: version conflicts, tried again later"
            )
            return out, True
        if tagged.conflicts:
            out["untagged"] = tagged.conflicts
        return out, False

    async def _gone(self, alert_ids: Sequence[str]) -> set[str]:
        """Which of these alerts the alerts index no longer holds with the case on them, asked of
        Elasticsearch through the gateway (the sync's read: ``alerts.case_links``, the Kibana
        read lane). Empty when it could not be asked: the count the tag call gave stands."""
        es = self.gateway.es_gateway
        if es is None:
            return set()
        try:
            answer = await es.run(
                AlertCaseLinks(),
                CaseLinksParams(alert_ids=tuple(alert_ids), size=100),
                purpose=Purpose.KIBANA_READ,
                component=COMPONENT,
                deadline=self.clock() + READ_DEADLINE,
            )
        except (GatewayError, KibanaResponseError, ValueError):
            return set()
        present = {h.get("_id") for h in answer.body["hits"]["hits"]}
        return {a for a in alert_ids if a not in present}

    async def _mark(self, row: StepRow, to: str, why: str, only_from: tuple[str, ...]) -> None:
        async with self.engine.begin() as conn:
            await store.settle(conn, row.id, to, only_from=only_from, now=self.clock(), reason=why)

    async def _after_error(
        self, row: StepRow, exc: KibanaResponseError, report: PostReport
    ) -> None:
        """Map an answer to a sent write onto the step's states. Nothing is sent again."""
        now = self.clock()
        why = f"{exc.reason}: {_why(exc)}"
        if exc.maybe_applied or isinstance(exc, UnknownOutcomeError | AnswerMismatchError):
            if isinstance(exc, UnknownOutcomeError) and not exc.reached:
                why = "no connection to Kibana was made, so the write cannot have landed"
            async with self.engine.begin() as conn:
                await store.settle(
                    conn,
                    row.id,
                    "ambiguous",
                    only_from=["sending"],
                    now=now,
                    reason=why,
                    next_lookup_at=now + store.LOOKUP_AFTER[0],
                    lookups=0,
                )
            report.ambiguous += 1
            return
        await self._mark(row, "failed", why, ("sending",))
        report.held.append(f"{row.key}: {why}")

    async def _resolve(
        self, row: StepRow, post: PostRow, rep: m.IncidentReport, report: PostReport
    ) -> bool:
        """A step left ``sending`` or ``ambiguous``: look for it before anything is sent again.
        True when it is settled (found, or a tag call put back to be sent), False when it must
        wait (a look is not due, or it is a person's to decide)."""
        now = self.clock()
        if row.state == "sending":  # the run ended mid-send: the request may have left
            due = (row.sent_at or now) + store.LOOKUP_AFTER[0]
            await self._mark_ambiguous(row, "the run ended while this was being sent", due, 0)
            row = _reload(row, state="ambiguous", next_lookup_at=due, lookups=0)
        if row.kind == "tag" or row.kind in EDIT_KINDS:
            # a set: sending it again changes nothing. An edit is read first and sent only if
            # Kibana still holds what ARGUS wrote before, so a late landing shows as "done"
            if row.next_lookup_at is not None and now < row.next_lookup_at:
                return False  # a call that met version conflicts is tried again then
            why = (
                "tags are added to a set: sent again, nothing doubles"
                if row.kind == "tag"
                else "an edit sets a value: Kibana is read again before anything is sent"
            )
            await self._mark(row, "planned", why, ("ambiguous",))
            return True
        if row.next_lookup_at is not None and now < row.next_lookup_at:
            return False
        found, ids = await self._look(row, post, rep)
        if found is None:  # Kibana could not be asked: not counted
            async with self.engine.begin() as conn:
                await store.settle(
                    conn,
                    row.id,
                    "ambiguous",
                    only_from=["ambiguous"],
                    now=now,
                    next_lookup_at=now + POSTPONE,
                    reason="Kibana could not be asked yet",
                )
            return False
        if found:
            async with self.engine.begin() as conn:
                if row.kind == "open" and "case" in ids:
                    await store.set_kibana_case(conn, row.case_id, str(ids["case"]), now)
                await store.settle(
                    conn,
                    row.id,
                    "verified",
                    only_from=["ambiguous"],
                    now=now,
                    ids=ids,
                    reason="found in Kibana by the look",
                )
            report.verified += 1
            return True
        looked = row.lookups + 1
        if looked >= len(store.LOOKUP_AFTER):
            await self._mark(
                row,
                "resend",
                "not found in Kibana after four looks: a person decides",
                ("ambiguous",),
            )
            report.held.append(f"{row.key}: not found after four looks (resend needs a person)")
            return False
        async with self.engine.begin() as conn:
            await store.settle(
                conn,
                row.id,
                "ambiguous",
                only_from=["ambiguous"],
                now=now,
                next_lookup_at=(row.sent_at or now) + store.LOOKUP_AFTER[looked],
                lookups=looked,
                reason=f"not found at look {looked} of {len(store.LOOKUP_AFTER)}",
            )
        return False

    async def _mark_ambiguous(self, row: StepRow, why: str, due: datetime, looks: int) -> None:
        async with self.engine.begin() as conn:
            await store.settle(
                conn,
                row.id,
                "ambiguous",
                only_from=["sending"],
                now=self.clock(),
                reason=why,
                next_lookup_at=due,
                lookups=looks,
            )

    async def housekeeping(self, report: PostReport | None = None) -> int:
        """Look for every step in doubt whose look is due (a pass starts with this): the writes
        that were left in doubt by an earlier run are settled before new ones are planned. Under
        the case team's lock like every run: a second run looking at the same step would count
        its looks twice."""
        async with self._exclusive() as got:
            if not got:
                return 0
            return await self._housekeeping(report)

    async def _housekeeping(self, report: PostReport | None) -> int:
        done = 0
        async with self.engine.connect() as conn:
            ids = [
                int(r.id)
                for r in await conn.execute(
                    text(
                        "SELECT id FROM case_team_steps WHERE state IN ('sending', 'ambiguous')"
                        " ORDER BY id"
                    )
                )
            ]
        for step_id in ids:
            async with self.engine.connect() as conn:
                row = await store.step_by_id(conn, step_id)
                if row is None:
                    continue
                post = await store.post_of(conn, row.case_id)
                stored = await incident_store.version(conn, row.case_id, row.report_version)
            if post is None or stored is None:
                continue
            rep = report or PostReport(row.case_id, 0, policy.Decision("none", ""))
            if await self._resolve(row, post, stored.report, rep):
                done += 1
        return done

    async def _read(self, template: Any, params: Any) -> Any:
        result = await self.gateway.read(
            template, params, component=COMPONENT, deadline=self.clock() + READ_DEADLINE
        )
        return result.body

    async def _look(
        self, row: StepRow, post: PostRow, rep: m.IncidentReport
    ) -> tuple[bool | None, dict[str, Any]]:
        """Whether Kibana holds the step now; (None, {}) when it could not be asked."""
        try:
            step = row.step()
            if row.kind == "open":
                found = await self._find_case(post.incident_id)
                match = [c for c in found if c["created_by"].get("username") == models.TEAM_LEAD]
                match = [c for c in match if c.get("title") == (row.payload or {}).get("title")]
                return (True, {"case": match[0]["id"]}) if match else (False, {})
            kid = post.kibana_case_id
            if kid is None:
                return None, {}
            if row.kind == "comment":
                for page in range(1, 6):
                    answer = await self._read(
                        CaseComments(), CasePageParams(case_id=kid, page=page, per_page=100)
                    )
                    for c in answer["comments"]:
                        by = c.get("created_by") or {}
                        if (
                            c.get("type") == "user"
                            and c.get("comment") == step.text
                            and by.get("username") == step.author.value
                        ):
                            return True, {"comment": c.get("id")}
                    if page * 100 >= int(answer["total"]):
                        break
                return False, {}
            if row.kind == "attach":
                async with self.engine.connect() as conn:
                    rows = await store.steps_of(conn, row.case_id, row.gen)
                mine = next((r for r in rows if r.id == row.id), row)
                left = store.left_out_of(mine)
                wanted = int(store.attach_view(rows, mine).payload["expect_total"])
                case = await self._read(CaseGet(), CaseParams(case_id=kid))
                total = case.get("totalAlerts")
                ok = isinstance(total, int) and total >= wanted
                return ok, {"alerts_total": total, **({"left_out": sorted(left)} if left else {})}
            if row.kind == "file":
                return await self._find_file(kid, str(row.payload["name"]))
        except (GatewayError, KibanaResponseError, KeyError, ValueError):
            return None, {}
        return None, {}

    async def _find_case(self, incident_id: str) -> list[dict[str, Any]]:
        answer = await self._read(
            CasesFind(),
            FindParams(tags=(incident_id,), sort_field="createdAt", sort_order="desc", per_page=20),
        )
        return [dict(c) for c in answer["cases"]]

    async def _find_file(self, kid: str, name: str) -> tuple[bool, dict[str, Any]]:
        stem = name.rsplit(".", 1)[0]
        for page in range(1, 6):
            answer = await self._read(
                CaseUserActions(), CasePageParams(case_id=kid, page=page, per_page=100)
            )
            for action in answer["userActions"]:
                payload = action.get("payload") if isinstance(action, dict) else None
                comment = payload.get("comment") if isinstance(payload, dict) else None
                if not isinstance(comment, dict) or comment.get("type") != "externalReference":
                    continue
                meta = comment.get("externalReferenceMetadata")
                files = meta.get("files", []) if isinstance(meta, dict) else []
                if any(isinstance(f, dict) and f.get("name") in (stem, name) for f in files):
                    return True, {"file": name}
            if page * 100 >= int(answer["total"]):
                break
        return False, {}

    async def _adopt_existing(
        self, row: StepRow, post: PostRow, step: Step, report: PostReport
    ) -> bool:
        """Before the first create: a case already carrying this incident ID is never made again.
        The lead's own earlier create is adopted; anyone else's is a reason to stop."""
        try:
            found = await self._find_case(post.incident_id)
        except (GatewayError, KibanaResponseError) as exc:
            raise RunStopped(f"Kibana could not be asked first ({_why(exc)})") from None
        if not found:
            return False
        mine = [
            c
            for c in found
            if c["created_by"].get("username") == models.TEAM_LEAD
            and c.get("title") == step.payload.get("title")
            and c.get("description") == step.text
        ]
        if mine:
            kid = str(mine[0]["id"])
            async with self.engine.begin() as conn:
                await store.set_kibana_case(conn, row.case_id, kid, self.clock())
                await store.settle(
                    conn,
                    row.id,
                    "verified",
                    only_from=["planned"],
                    now=self.clock(),
                    ids={"case": kid},
                    reason="the lead's case was already there",
                )
            report.verified += 1
            return True
        who = found[0]["created_by"].get("username", "someone")
        why = f"a Kibana case already carries {post.incident_id} (made by {clean(who, 40)})"
        await self._mark(row, "held", why, ("planned",))
        async with self.engine.begin() as conn:
            await store.hold_post(conn, row.case_id, why)
        report.held.append(why)
        raise RunStopped(why)

    async def _read_back_open(
        self, row: StepRow, kid: str, step: Step, report: PostReport, incident_id: str
    ) -> None:
        """The case, read again after the create: what Kibana holds is what the lead sent."""
        try:
            case = await self._read(CaseGet(), CaseParams(case_id=kid))
        except (GatewayError, KibanaResponseError):
            return  # the answer to the create was already checked field by field
        wanted = set(step.payload.get("tags", ()))
        problems = []  # Sync alerts on is a person's setting, not a problem
        if not wanted <= set(case["tags"]):
            problems.append("the tags are not as sent")
        if case.get("description") != step.text:
            problems.append("the description is not as sent")
        if problems:
            why = "read back after the create: " + ", ".join(problems)
            async with self.engine.begin() as conn:
                await store.hold_post(conn, row.case_id, why)
            report.held.append(why)

    async def _finish(
        self, post: PostRow, rows: list[StepRow], stored: incident_store.Stored, report: PostReport
    ) -> None:
        """A generation went through: remember the version, and read the case back once. A
        generation of only edits (a retitle, or a refresh) is not an update round: the report's
        newer lines, files and verdict still wait for theirs. A refresh may add a comment for a
        part that now needs one more (its step carries the ``refresh`` flag); that is still a
        refresh and moves neither the version nor the round's time."""
        if not all(r.kind in EDIT_KINDS or r.payload.get(plan.REFRESH) is True for r in rows):
            async with self.engine.begin() as conn:
                await store.finish_generation(conn, post.case_id, stored.version, self.clock())
        kid = post.kibana_case_id
        if kid is None:
            return
        try:
            case = await self._read(CaseGet(), CaseParams(case_id=kid))
            comments: list[dict[str, Any]] = []
            for page in range(1, 6):
                answer = await self._read(
                    CaseComments(), CasePageParams(case_id=kid, page=page, per_page=100)
                )
                comments += [dict(c) for c in answer["comments"]]
                if page * 100 >= int(answer["total"]):
                    break
        except (GatewayError, KibanaResponseError):
            return
        have = {(c.get("comment"), (c.get("created_by") or {}).get("username")) for c in comments}
        missing = [
            r.key
            for r in rows
            if r.kind == "comment" and r.state != "skipped" and (r.text_body, r.author) not in have
        ]
        if missing:
            why = "read back at the end: missing comment " + ", ".join(missing[:5])
            async with self.engine.begin() as conn:
                await store.hold_post(conn, post.case_id, why)
            report.held.append(why)
        if case.get("status") == "closed":
            report.note = "the case is closed in Kibana"

    async def _closings(self, case_id: uuid.UUID, prep: Prepared, report: PostReport) -> None:
        """For each person's verdict read from a comment, the lead's note: what the review path
        did with it (a label written, an earlier review kept, nothing new) and that closing stays
        a person's approval. When people's newest verdicts disagree, one note says so."""
        assert prep.stored is not None
        if prep.state == "closed" or not self.config.post:
            return
        async with self.engine.connect() as conn:
            recorded = await store.recorded_verdicts(conn, case_id)
            have = await self._live_steps(conn, case_id)
            posted = await store.posted_state(conn, case_id)
            who = await store.names(conn, [v.user_id for v in recorded if v.user_id is not None])
        if posted is None:
            return
        ctx = self.config.context
        for v in recorded:
            key = plan.closing_key(v.ref)
            if v.verdict is None or await self._unfinished(case_id, prep, report, have.get(key)):
                continue
            if key in have:
                continue
            text_ = render.closing_comment(
                ctx,
                str(case_id),
                who=who.get(v.user_id or 0, v.author),
                outcome=v.verdict,
                effect=render.effect_of(v.counts),
            )
            await self._say(case_id, prep, posted, report, key, text_)
        newest: dict[int, store.SeenRow] = {}
        for v in recorded:  # in the order they were written: the last of each person is theirs
            if v.user_id is not None and v.verdict is not None:
                newest[v.user_id] = v
        if len({v.verdict for v in newest.values()}) > 1:
            key = plan.conflict_key([(u, str(v.verdict)) for u, v in newest.items()])
            if not await self._unfinished(case_id, prep, report, have.get(key)) and key not in have:
                said = [
                    (who.get(u, v.author), str(v.verdict))
                    for u, v in sorted(newest.items(), key=lambda kv: kv[1].written_at)
                ]
                text_ = render.conflict_comment(ctx, str(case_id), said)
                await self._say(case_id, prep, posted, report, key, text_)

    async def _notes(self, case_id: uuid.UUID, prep: Prepared, report: PostReport) -> None:
        """A tag call that could not tag every alert it named (gone from the alerts index, or
        rewritten again and again) is said on the case once; the call itself is done."""
        assert prep.stored is not None
        if prep.state == "closed" or not self.config.post:
            return
        async with self.engine.connect() as conn:
            rows = [r for r in await store.steps_of(conn, case_id) if r.kind == "tag"]
            have = await self._live_steps(conn, case_id)
            posted = await store.posted_state(conn, case_id)
        if posted is None:
            return
        for r in rows:
            gone = int(r.kibana_ids.get("gone_count") or 0)
            untagged = int(r.kibana_ids.get("untagged") or 0)
            key = plan.untagged_key(r.id)
            if r.state != "verified" or not (gone or untagged):
                continue
            if await self._unfinished(case_id, prep, report, have.get(key)) or key in have:
                continue
            text_ = render.untagged_comment(
                self.config.context,
                str(case_id),
                named=len(r.payload.get("ids", ())),
                gone=gone,
                untagged=untagged,
            )
            await self._say(case_id, prep, posted, report, key, text_)

    @staticmethod
    async def _live_steps(conn: AsyncConnection, case_id: uuid.UUID) -> dict[str, StepRow]:
        """The step of each key that still counts: one a newer report's plan stepped aside
        (``superseded``) does not say it was done, so the note it held is planned again."""
        return {r.key: r for r in await store.steps_of(conn, case_id) if r.state != "superseded"}

    async def _unfinished(
        self, case_id: uuid.UUID, prep: Prepared, report: PostReport, row: StepRow | None
    ) -> bool:
        """A note that was planned and not finished (a refused window, a lane that was not
        ready) is finished first, whatever else is true; True when this call walked it."""
        if row is None or row.state in ("verified", "skipped"):
            return False
        assert prep.stored is not None
        await self._walk(case_id, row.gen, prep.stored, report, "argus:caseteam")
        return True

    async def _say(
        self,
        case_id: uuid.UUID,
        prep: Prepared,
        posted: plan.Posted,
        report: PostReport,
        key: str,
        text_: str,
    ) -> None:
        """One comment by the lead, as a generation of its own."""
        assert prep.stored is not None
        if not self.config.has_key("argus-lead"):
            report.held.append("no key is installed for argus-lead")
            return
        note = plan.note_plan(
            prep.stored.report,
            prep.stored.version,
            posted,
            key=key,
            text=text_,
            target=self.config.target,
        )
        sub = Prepared(
            case_id,
            prep.number,
            prep.state,
            prep.stored,
            prep.post,
            [],
            note,
            policy.Decision("update", "a note from the lead"),
            open_done=True,
        )
        gen = (await self._persist_extra(sub))[0].gen
        await self._walk(case_id, gen, prep.stored, report, "argus:caseteam")

    async def _persist_extra(self, prep: Prepared) -> list[StepRow]:
        assert prep.plan is not None
        async with self.engine.begin() as conn:
            gen = await store.latest_gen(conn, prep.case_id) + 1
            await store.write_generation(conn, prep.case_id, replace(prep.plan, gen=gen))
            return await store.steps_of(conn, prep.case_id, gen)

    async def refresh(self, case_id: uuid.UUID, *, apply: bool = False) -> RefreshReport:
        """A person's decision to correct a posted case in place: its title, description
        and comments as the newest report renders them, wherever they differ from what ARGUS last
        wrote. A dry run says what would change; ``apply`` writes the steps as ``planned`` rows (to
        ARGUS's database only) and the case team's next run sends them. Refused while the case is
        not in Kibana or any of its steps is still open (finish or skip those first)."""
        async with self.engine.connect() as conn:
            case = await store.case_row(conn, case_id)
            if case is None:
                raise LookupError(f"no case {case_id}")
            found = RefreshReport(int(case.number))
            stored = await incident_store.latest(conn, case_id)
            rows = await store.steps_of(conn, case_id)
            posted = await store.posted_state(conn, case_id)
        if stored is None:
            found.problems.append("ARGUS has not written this case's report yet")
        if posted is None:
            found.problems.append("the case is not in Kibana")
        open_steps = [r for r in rows if r.state in OPEN_STATES]
        if open_steps:
            found.problems.append(
                f"{len(open_steps)} steps are still open (argus case team status): finish or skip"
                " them first"
            )
        if found.problems or stored is None or posted is None:
            return found
        found.plan = plan.refresh_plan(
            stored.report, stored.version, self.config.context, posted, target=self.config.target
        )
        for step in found.plan.steps:
            if not self.config.has_key(step.author.value):
                found.problems.append(f"no key is installed for {step.author.value}")
            try:
                if step.text is not None:
                    guard.check(step.text, self.config.context.allowed)
                plan.request_of(step, posted.kibana_case_id, stored.report)
            except (ValueError, guard.GuardRefusal) as exc:
                found.problems.append(f"{step.key}: {exc}")
        if not apply or found.problems or not found.plan.steps:
            return found
        async with self._exclusive() as got:
            if not got:
                found.problems.append("another case team run is in progress: try again shortly")
                return found
            async with self.engine.begin() as conn:
                gen = await store.latest_gen(conn, case_id) + 1
                await store.write_generation(conn, case_id, replace(found.plan, gen=gen))
        found.planned = True
        return found

    async def resend(self, step_id: int, *, by: str) -> bool:
        """A person's decision on a step the four looks did not find: send it once more. Only
        ``resend`` steps (and a ``held`` create, for a case someone else made by hand once the
        team has renamed it: the create looks for the incident ID again before it sends); the
        lane's checks still apply."""
        async with self.engine.begin() as conn:
            row = await store.step_by_id(conn, step_id)
            if row is None or not (
                row.state == "resend" or (row.state == "held" and row.kind == "open")
            ):
                return False
            return await store.settle(
                conn,
                step_id,
                "planned",
                only_from=["resend", "held"],
                now=self.clock(),
                reason=f"{by} decided to send it again",
            )

    async def skip(self, step_id: int, *, by: str, reason: str) -> bool:
        """A person decides a step in doubt, failed or held is not wanted (or was done by hand in
        Kibana): it is never sent, and the steps after it go on. **Refused while the Kibana case
        does not exist** (``ValueError`` says so): the steps after it would have no case to go to,
        and nothing is ever sent to a placeholder."""
        async with self.engine.begin() as conn:
            row = await store.step_by_id(conn, step_id)
            if row is None:
                return False
            post = await store.post_of(conn, row.case_id)
            if post is None or post.kibana_case_id is None:
                raise ValueError(
                    "the Kibana case does not exist yet, so nothing after this step could be sent"
                    " (see the runbook for a case someone made by hand)"
                )
            return await store.settle(
                conn,
                step_id,
                "skipped",
                only_from=["ambiguous", "resend", "failed", "held", "planned"],
                now=self.clock(),
                reason=f"{by}: {reason}",
            )


def _why(exc: BaseException) -> str:
    return clean(f"{type(exc).__name__}: {exc}", 160)


def _reload(row: StepRow, **changes: Any) -> StepRow:
    return replace(row, **changes)


def _ids_of(step: Step, body: Any) -> dict[str, Any]:
    """The Kibana ids that came back, for the record."""
    if step.kind == "open":
        return {"case": str(body["id"]), "version": str(body.get("version", ""))}
    if step.kind == "comment":
        for c in reversed(body.get("comments") or []):
            if c.get("comment") == step.text:
                return {"comment": c.get("id")}
        return {}
    if step.kind in ("retitle", "redescribe"):  # the checked answer: the one case, not the list
        return {"case": str(body["id"]), "version": str(body.get("version", ""))}
    if step.kind == "edit_comment":
        wanted = step.payload["comment_id"]
        for c in body.get("comments") or []:
            if c.get("id") == wanted:
                return {"comment": wanted, "version": str(c.get("version", ""))}
        return {"comment": wanted}
    if step.kind == "attach":
        return {"alerts_total": body.get("totalAlerts")}
    if step.kind == "tag":
        return {"updated": body.get("updated")}
    return {"total_comment": body.get("totalComment")}


def describe_request(step: Step, final: KFinal) -> dict[str, Any]:
    """A step's request for a person: the method and path, the author, and the body (a file's
    is its name and size, never its bytes)."""
    body: str
    if step.kind == "file":
        body = (
            f"{step.payload['name']} ({step.payload['mime']}, {step.payload['size']} bytes,"
            f" sha-256 {str(step.payload['sha256'])[:16]})"
        )
    else:
        body = "" if final.body is None else final.body.decode("ascii", "replace")
    return {
        "key": step.key,
        "author": step.author.value,
        "method": final.method,
        "path": final.path,
        "content_type": final.content_type,
        "body": body,
        "text": step.text,
    }


OPEN = OPEN_STATES
