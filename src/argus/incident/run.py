"""Writing the incident reports in the assessment pass, or on its own.

Each pass looks at the active cases, the ones ARGUS looked at least recently first, and writes a
report for those with none or whose evidence changed (a cheap signal read in one statement,
:func:`argus.incident.gather.signals`); a report that says the same as the newest version is not
stored. A case is not written again within ``incident.min_interval``, and a pass writes at most
``incident.per_pass``. **A failure is reported and never stops the pass**: the case keeps its last
report and is tried again later. Only ARGUS's own database is read; a model is asked only for the
summary's prose (:mod:`argus.incident.prose`) and the analyst brief (:mod:`argus.incident.brief`),
and its words are kept only after code's checks."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus import site
from argus.assets.classify import IpClassifier
from argus.db.errors import DB_ERRORS, short_db_error
from argus.incident import brief, build, discover, gather, prose, scene, store
from argus.incident import model as m
from argus.observability.redaction import redact_text
from argus.reporter.build import snapshot
from argus.signins import view as signin_view

log = logging.getLogger("argus.incident")
RETRY_AFTER = timedelta(hours=1)  # a failed case is tried again no sooner than this
ProseFn = Callable[[m.IncidentReport], Awaitable[prose.Improved]]
BriefFn = Callable[[m.IncidentReport, m.ReportBrief | None], Awaitable[brief.Improved]]


@dataclass
class Done:
    said: list[str] = field(default_factory=list)
    warned: list[str] = field(default_factory=list)
    looked: int = 0
    written: int = 0
    unchanged: int = 0
    waiting: int = 0
    failed: int = 0

    def line(self) -> str:
        return (f"incident reports: looked {self.looked}, written {self.written}, unchanged"
                f" {self.unchanged}, waiting {self.waiting}, failed {self.failed}")  # fmt: skip


def why(exc: BaseException) -> str:
    """One redacted line for a failure: the database's own words for a database error, the type
    and message for anything else (a case the writer could not read is a bug to see, not hide)."""
    if isinstance(exc, DB_ERRORS):
        return short_db_error(exc)
    return redact_text(f"{type(exc).__name__}: {' '.join(str(exc).split())[:300]}")


def discover_config(settings: Any) -> discover.Config:
    """The query links' settings: the Kibana address people open, the space, the log prefix and
    the data views (none of it a secret)."""
    kibana = settings.incident.kibana_url or settings.kibana.url or discover.Config().kibana_url
    return discover.Config(
        kibana_url=kibana, base_path=settings.kibana.base_path, space=site.active().space,
        views=settings.incident.views,
    )  # fmt: skip


def context_for(
    settings: Any, now: datetime, classifier: IpClassifier | None = None
) -> build.Context:
    """The writer's context from the settings; the responder's catalogue when it can be read."""
    from argus.responder import store as responder_store
    from argus.responder.catalogue import CatalogueError

    catalogue = None
    try:
        catalogue = responder_store.current()
    except (CatalogueError, OSError):
        catalogue = None  # the report is written without advice and says so (a limit)
    reading = None
    if settings.signins.enabled and classifier is not None:  # the accounts of the devices
        reading = signin_view.reading_of(settings, classifier)
    from argus.cases import titling

    try:
        own_domains = titling.default_own_domains()
    except (OSError, ValueError):
        own_domains = ()  # the report is written without the sites' names
    return build.Context(
        cfg=discover_config(settings), as_at=now, classifier=classifier, catalogue=catalogue,
        active_days=settings.notified.active_days, quiet_days=settings.notified.quiet_days,
        signins=reading, own_domains=own_domains,
    )  # fmt: skip


def key_of(signal: gather.Signal, ctx: build.Context) -> str:
    """What a case's check stores: the evidence signal, whether it is still going on (time makes
    it quiet with nothing else changing), and the writer's version (a new writer rewrites)."""
    standing = scene.standing(signal.last_alert, ctx)
    return f"{signal.text}|{standing}|{m.WRITER}|{ctx.catalogue.version if ctx.catalogue else 0}"


async def users_of(
    conn: AsyncConnection, facts: gather.CaseFacts, ctx: build.Context
) -> signin_view.Users:
    """Who signed in from the case's devices, from the stored sightings: the
    devices on the source side of the member investigations' alerts, each over the alerts of its
    own investigations. The page's card reads the same way."""
    assert ctx.signins is not None
    return await signin_view.for_case(conn, ctx.signins, facts.case.id, ctx.as_at)


@dataclass(frozen=True)
class Made:
    report: m.IncidentReport
    case_version: int
    by: str | None  # the model that wrote the summary's prose


@dataclass(frozen=True)
class Briefer:
    """The analyst brief's writer (``incident.brief``): ``write`` words a report's brief given the
    version before's, ``scope`` says for which cases (``confirmed``: those a person confirmed;
    ``all``), ``close`` ends its transport."""

    write: BriefFn
    scope: str
    close: Callable[[], Awaitable[None]] | None = None

    def wants(self, case: Any) -> bool:
        return self.scope == "all" or case.opened_at is not None


def briefer_for(settings: Any, privacy: Any, db: AsyncEngine) -> tuple[Briefer | None, str | None]:
    """The brief's writer through the LLM gateway, or None with why not (off, or no model can
    be reached: the reports keep code's text). Never raises."""
    scope = settings.incident.brief
    if scope == "off":
        return None, None
    from argus.llm.providers import Tier, load_config
    from argus.llm.service import build_gateway
    from argus.llm.wire import HttpxLlmTransport

    try:
        llm = load_config()
        transport = HttpxLlmTransport(llm)
        gateway = build_gateway(db, llm, transport)
    except Exception as exc:  # no keys, no providers file: no brief, nothing else changes
        return None, f"incident reports: no model for the brief ({type(exc).__name__})"
    purpose = llm.purposes.get(brief.TASK)
    tier = purpose.tier if purpose is not None and purpose.tier is not None else Tier.LARGE
    keep = settings.incident.brief_every

    async def write(report: m.IncidentReport, before: m.ReportBrief | None) -> brief.Improved:
        return await brief.improve(report, privacy, gateway.complete, previous=before, tier=tier,
                                   keep=keep)  # fmt: skip

    return Briefer(write, scope, transport.aclose), None


async def make(
    db: AsyncEngine, case_id: uuid.UUID, ctx: build.Context, *, prose_fn: ProseFn | None = None,
    briefer: Briefer | None = None,
) -> Made | None:  # fmt: skip
    """The case's report as it reads now (nothing is written): None when there is no such case.
    One read-only snapshot, so the parts agree; the models, when asked, come after it."""
    before = None
    async with snapshot(db) as conn:
        facts = await gather.gather(conn, case_id, ctx.as_at)
        if facts is not None and ctx.signins is not None:
            facts = replace(facts, users=await users_of(conn, facts, ctx))
        if facts is not None and briefer is not None:
            before = await store.latest(conn, case_id)
    if facts is None:
        return None
    report = build.build(facts, ctx)
    by = None
    if prose_fn is not None:
        improved = await prose_fn(report)
        report, by = improved.report, improved.by
    if briefer is not None and briefer.wants(facts.case):
        kept = None if before is None else before.report.brief
        report = (await briefer.write(report, kept)).report
    return Made(report, facts.case.version, by)


async def write(
    db: AsyncEngine, made: Made, key: str, at: datetime
) -> tuple[store.Stored | None, bool]:
    """Store ``made`` as the next version unless it says what the newest says, and record the
    look. Returns the current version and whether it is new."""
    case_id = uuid.UUID(made.report.header.case_id)
    async with db.begin() as conn:
        stored, new = await store.save(conn, made.report, case_version=made.case_version,
                                       prose_by=made.by)  # fmt: skip
        await store.put_check(conn, case_id, key, at,
                              report_id=None if stored is None else stored.id)  # fmt: skip
    return stored, new


async def _failed(db: AsyncEngine, case_id: uuid.UUID, key: str, at: datetime, why: str) -> None:
    try:
        async with db.begin() as conn:
            await store.put_check(conn, case_id, key, at, failure=why)
    except Exception:  # even recording the failure must not stop the pass
        log.warning("could not record the failure of case %s", case_id)


async def run_pass(
    db: AsyncEngine, settings: Any, now: datetime, *, classifier: IpClassifier | None = None,
    prose_fn: ProseFn | None = None, briefer: Briefer | None = None,
) -> Done:  # fmt: skip
    """One pass: look at up to ``incident.look`` active cases and write up to
    ``incident.per_pass`` reports. Nothing it meets stops it."""
    done = Done()
    cfg = settings.incident
    if not cfg.enabled or cfg.per_pass == 0:
        return done
    try:
        ctx = context_for(settings, now, classifier)
        async with db.connect() as conn:
            cases = await store.candidates(conn, cfg.look)
            signals = await gather.signals(conn, [c for c, _ in cases])
    except Exception as exc:  # the list itself could not be read: said, and the next pass tries
        done.warned.append(f"incident reports: {why(exc)}")
        return done
    for case_id, check in cases:
        signal = signals.get(case_id)
        if signal is None:
            continue
        done.looked += 1
        key = key_of(signal, ctx)
        if (
            check is not None
            and check.signal == key
            and (check.failure is None or now - (check.failed_at or now) < RETRY_AFTER)
        ):
            done.unchanged += 1
            try:
                async with db.begin() as conn:
                    await store.put_check(conn, case_id, key, now, failure=check.failure)
            except Exception as exc:
                done.warned.append(f"incident report, case {case_id}: {why(exc)}")
            continue
        if done.written + done.failed >= cfg.per_pass:
            continue  # the cap: the rest keep their place in the order for the next pass
        try:
            async with db.connect() as conn:
                newest = await store.latest(conn, case_id)
        except Exception as exc:
            done.failed += 1
            done.warned.append(f"incident report, case {case_id}: {why(exc)}")
            continue
        if newest is not None and now - newest.generated_at < cfg.min_interval:
            done.waiting += 1
            continue
        try:
            made = await make(db, case_id, ctx, prose_fn=prose_fn, briefer=briefer)
            if made is None:
                continue
            _, new = await write(db, made, key, now)
        except Exception as exc:  # a failure is said and the pass goes on
            done.failed += 1
            reason = why(exc)[:500]
            done.warned.append(f"incident report, case {case_id}: {reason}")
            await _failed(db, case_id, key, now, reason)
            continue
        if new:
            done.written += 1
        else:
            done.unchanged += 1
    done.said.append(done.line())
    return done
