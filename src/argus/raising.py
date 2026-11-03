"""AR2b's steps of an assessment pass (D-160): store the flags of new dossiers, then suggest
cases from evidence across investigations. With outside threat intel (AR3, D-165) the pass also
looks up the external destinations of beacon-flagged investigations at VirusTotal (a few a pass,
within a daily budget) and adds the flag "flagged by outside threat intel" to the investigations
whose destination it flags. AR2c (D-168) adds the families: the registered parents of many names
that many campus devices reach, looked up once each, with the flags a flagged parent, its
operator and a rare campaign shape give (``argus.campaigns``). AR4b (D-169) adds the known
infections: for each case whose owner was told, the investigations of its devices are counted
(and kept out of Needs attention and the AI queue) or, when something changed since the notice,
raised with the reason (``argus.cases.knownrun``).

This sits beside the packages that build what a model sees (``assess``, ``agent``, ``llm``,
``context``, ``tuning``), not in them: those never import the case record (a test holds it, plan
Q-B3: notes are for people only), and the suggester is a case writer. ``argus assess run`` calls
:func:`run` every pass; the case step runs at most every :data:`SUGGEST_EVERY`. Case titles (D-230)
are made again from the cases' facts in the same pass, at most that often too
(``argus.cases.titling``): ARGUS's own titles only.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import raised
from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClassifier
from argus.campaigns import lookups as campaign_lookups
from argus.campaigns.analysis import Campaign
from argus.cases import knownrun, suggest, titling
from argus.cases.membership import NO_SHARED, Shared, load_shared
from argus.outside import prefetch
from argus.outside.eligible import Eligibility
from argus.outside.providers import HttpxTransport
from argus.outside.read import View
from argus.outside.service import Outside

SUGGEST_EVERY = timedelta(minutes=15)
HISTORY = timedelta(days=5)  # ``history.window``'s default; the caller passes the configured one


@dataclass
class Done:
    said: list[str] = field(default_factory=list)  # lines for the log
    warned: list[str] = field(default_factory=list)  # lines for the error stream
    suggested_at: datetime | None = None  # when the case step last ran
    titled_at: datetime | None = None  # when the titles were last refreshed
    campaigns: tuple[Campaign, ...] = ()  # what the family step found this pass (AR2c)


async def run(
    db: AsyncEngine,
    classifier: IpClassifier | None,
    now: datetime,
    *,
    suggesting: bool,
    last: datetime | None,
    outside: Outside | None = None,
    shared: Shared = NO_SHARED,
    window: timedelta = HISTORY,
    resolvers: Sequence[IPNetwork] = (),
    offers_per_hour: int = suggest.MAX_OFFERS_PER_HOUR,
    known: knownrun.Context | None = None,
    titles: titling.Context | None = None,
    titled_last: datetime | None = None,
) -> Done:
    """Read the evidence of new dossiers (every pass; with ``outside``, the cached outside
    answers too), look up beacon destinations and add what they flag (AR3), then suggest cases
    (when ``suggesting`` and the last time was :data:`SUGGEST_EVERY` ago). A failure is said and
    never stops the pass: the next one tries again."""
    done = Done(suggested_at=last, titled_at=titled_last)
    view = outside.view if outside is not None else None
    try:
        async with db.begin() as conn:
            counts = await raised.evaluate(conn, now, view=view)
        done.said.append("raised: " + " ".join(f"{k} {v}" for k, v in counts.items()))
        if outside is not None and view is not None:
            await _outside(db, outside, shared, classifier, now, done, window, resolvers)
        if known is not None:
            await _known(db, known, now, done)
        if suggesting and classifier is not None and (last is None or now - last >= SUGGEST_EVERY):
            report = await suggest.run(db, classifier=classifier, dry_run=False,
                                       campaigns=done.campaigns,
                                       offers_per_hour=offers_per_hour)  # fmt: skip
            done.suggested_at = now
            applied = suggest.words(report.applied) if report.applied else "none"
            done.said.append(f"cases: {applied}")
            done.warned.extend(f"cases: skipped {skipped}" for skipped in report.skipped)
        if titles is not None and (titled_last is None or now - titled_last >= SUGGEST_EVERY):
            await _titles(db, titles, now, done)
    except Exception as exc:
        failed = type(exc).__name__
        done.warned.append(f"warning: raising or suggesting failed ({failed}); retrying")
    return done


async def _titles(db: AsyncEngine, ctx: titling.Context, now: datetime, done: Done) -> None:
    """Case titles (D-230): ARGUS's own titles made again from the case's facts, changed when they
    differ (a person's title is never touched). A failure is said and the pass goes on."""
    try:
        report = await titling.refresh(db, ctx)
    except Exception as exc:
        done.warned.append(f"warning: case titles failed ({type(exc).__name__}); retrying")
        return
    done.titled_at = now
    if report.changes or report.skipped:
        done.said.append(report.line())
    done.warned.extend(f"warning: case titles: {problem}" for problem in report.skipped)


async def _known(db: AsyncEngine, ctx: knownrun.Context, now: datetime, done: Done) -> None:
    """AR4b's part of a pass (D-169): decide the investigations of the notified cases' devices,
    note a moved address, suggest the reminders. A failure is said and the case step goes on."""
    try:
        report = await knownrun.run(db, ctx, now)
    except Exception as exc:
        done.warned.append(f"warning: known infections failed ({type(exc).__name__}); retrying")
        return
    if report.cases:
        done.said.append(report.line())
    done.warned.extend(f"warning: known infections: {problem}" for problem in report.problems)


async def _outside(
    db: AsyncEngine, outside: Outside, shared: Shared, classifier: IpClassifier | None,
    now: datetime, done: Done, window: timedelta, resolvers: Sequence[IPNetwork] = (),
) -> None:  # fmt: skip
    """AR3's and AR2c's part of a pass: the family look-ups and their flags, the beacon look-ups,
    then the flags they give, then the cache's upkeep. A failure of the family step is said and
    never stops AR3's part (a schema that is not upgraded yet, a bad window), and a failure of
    that part is said and the case step goes on."""
    try:
        if classifier is not None:
            families, found = await campaign_lookups.run(
                db, outside, shared, classifier, now, window=window, resolvers=resolvers
            )
            done.campaigns = found.campaigns
            done.said.append(families.line())
    except Exception as exc:
        done.warned.append(f"warning: campaign look-ups failed ({type(exc).__name__}); retrying")
    try:
        report = await prefetch.run(db, outside, shared, now)
        if not report.off:
            done.said.append(report.line())
        async with db.begin() as conn:
            changed = await raised.refresh_outside(conn, now, outside.view)
        if changed:
            done.said.append(f"raised: {changed} flagged by outside threat intel")
        await outside.prune()
    except Exception as exc:
        done.warned.append(f"warning: outside threat intel failed ({type(exc).__name__}); retrying")


def titles_for(settings: Any, privacy: Any) -> titling.Context | None:
    """What the case titles' refresh needs (D-230): the asset map's classes and the campus domains,
    or None when ``cases.retitle`` is off. Built here, beside the case record, for the same reason
    as :func:`outside_for`: ``assess`` never imports it."""
    if not settings.cases.retitle:
        return None
    return titling.Context(getattr(privacy, "classifier", None), tuple(privacy.campus.domains))


def known_for(
    settings: Any, privacy: Any, shared: Shared, view: View | None
) -> knownrun.Context | None:
    """The known infections' context (AR4b, D-169), the one builder for ``argus assess run`` and
    ``argus case known run`` (D-181): the asset map's classes, the shared list, the rules from
    ``notified``, the outside cache's view and the check that keeps campus names out of a case's
    destinations. None without the asset map (the privacy layer needs it too)."""
    classifier = getattr(privacy, "classifier", None)
    if classifier is None:
        return None
    eligible = Eligibility(classifier, privacy.campus, privacy.campus_for)
    return knownrun.context_for(settings, classifier, shared=shared, view=view, eligible=eligible)


def outside_for(
    settings: Any, privacy: Any, db: AsyncEngine
) -> tuple[Outside, Shared, Callable[[], Awaitable[None]]]:
    """Outside threat intel for ``argus assess run`` (AR3, D-165): the lookup service (a source
    without a key is off), the shared-infrastructure list the beacon look-ups skip, and the
    function that closes its client. Each key is read from the settings here only, and no request
    is made until a lookup is asked. Built here, beside the case record, because the shared list
    is the case code's (``assess`` never imports it)."""
    transport = HttpxTransport()
    shared = load_shared()
    outside = Outside(
        db, settings.outside, transport,
        Eligibility(privacy.classifier, privacy.campus, privacy.campus_for),
        parent_ok=lambda parent: shared.reason("domain", parent) is None,
    )  # fmt: skip
    return outside, shared, transport.aclose
