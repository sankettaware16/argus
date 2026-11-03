"""The family look-ups and the flags a campaign gives (AR2c, D-168, D-170): one step of an
assessment pass.

A campaign shows in no single investigation, so the step reads the whole window: the families of
domain names (``families``), what the outside cache already says about each parent, and the
addresses VirusTotal flags. It then, within a small daily budget (``outside.families_per_day``,
VirusTotal requests with the purpose ``families``), asks VirusTotal about the largest families
that no answer covers yet: their registered parent once (popularity, age, registrar, name servers,
addresses, engines) and then, for a family that is rare or detected (a popular one is not worth the
request), the first public address the parent points at (its network). Nothing campus is ever
sent: the parent is checked by ``Eligibility`` against the campus view of every
investigation that holds a name under it (as the beacon look-ups do), shared infrastructure is
never asked, and an answer already cached costs no request. With the answers in the cache,
``analysis.analyse`` says which investigations are detections of a flagged parent, tied to its
operator, or part of a rare campaign shape, and :func:`apply` adds those flags to the stored
evidence (``investigation_raises``) of the unreviewed investigations, where the pages and the
investigator's queue read them.

Without a VirusTotal key, or with ``families_per_day`` 0, nothing is asked, but the flags still
follow whatever the cache holds (a detection that an earlier look-up, the beacon prefetch or a
person's question left there).
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.assess import raised
from argus.assets.assetmap import IPNetwork
from argus.assets.classify import IpClassifier
from argus.campaigns import analysis, load
from argus.campaigns.families import Family, candidates, families_of
from argus.cases.membership import Shared
from argus.llm.detect import Campus
from argus.outside import facts, prefetch, service, store
from argus.outside.eligible import Eligibility
from argus.outside.read import View
from argus.outside.service import Outside

log = logging.getLogger("argus.campaigns")

BATCH = 2  # VirusTotal requests one pass may spend on families (3 a minute is its limit)
MAX_HOLDERS = 500  # investigations whose campus view a parent is checked against

# the flags a campaign gives, in the order they are written
FLAGS = (raised.OUTSIDE, raised.OPERATOR, raised.CAMPAIGN)


@dataclass
class Report:
    off: str = ""  # why nothing was asked: no key, switched off, budget spent
    asked: int = 0  # requests that reached VirusTotal
    found: int = 0
    not_found: int = 0
    failed: int = 0
    stopped: str = ""  # a limit or a stop ended the pass early
    campaigns: int = 0
    flagged: dict[str, int] = field(default_factory=dict)  # flag -> investigations changed

    def line(self) -> str:
        said = f"campaigns: {self.campaigns} found"
        if self.off:
            said += f" (look-ups off: {self.off})"
        else:
            said += (
                f"; looked up {self.asked} (found {self.found}, no record {self.not_found},"
                f" failed {self.failed})"
            )
        if self.stopped:
            said += f"; {self.stopped}"
        changed = {k: n for k, n in self.flagged.items() if n}
        if changed:
            said += "; flagged " + ", ".join(f"{n} {k}" for k, n in changed.items())
        return said


def usable_parent(outside: Outside, shared: Shared) -> Callable[[str], bool]:
    """Whether a parent may be asked about outside: a public name that holds no campus identifier
    and is not shared infrastructure (many customers behind one name)."""
    return lambda parent: (
        outside.eligibility.check("domain", parent) is None
        and shared.reason("domain", parent) is None
    )


def usable_address(outside: Outside, shared: Shared) -> Callable[[str], bool]:
    return lambda a: outside.eligibility.check("ip", a) is None and shared.reason("ip", a) is None


async def cleared(
    conn: AsyncConnection, outside: Outside, parent: str, holders: set[uuid.UUID]
) -> tuple[bool, Campus | None]:  # fmt: skip
    """Whether ``parent`` may go out for the investigations that hold a name under it, and the
    campus view to ask under (the first holder's). It may not when the campus view of any holder
    (its host and user names, as the privacy layer scrubs them) finds a campus name in it."""
    first: Campus | None = None
    for holder in sorted(holders)[:MAX_HOLDERS]:
        view = await prefetch.campus_of(conn, holder, outside)
        eligibility = outside.eligibility if view is None else outside.eligibility.with_campus(view)
        if eligibility.check("domain", parent) is not None:
            return False, None
        if first is None:
            first = view
    return True, first


def _tally(report: Report, got: service.Outcome) -> bool:
    """Count one look-up in the report; whether the pass can go on."""
    if got.status == service.FETCHED:
        report.asked += 1
        report.found += got.answer_status == facts.FOUND
        report.not_found += got.answer_status == facts.NOT_FOUND
    elif got.status == service.FAILED:
        report.asked += 1
        report.failed += 1
    elif got.status == service.BLOCKED:
        report.stopped = got.reason
        return False
    return True


def order_of(world: analysis.World, family: Family) -> tuple[int, int, int, str]:
    """The order candidates are looked at in (D-174): a family the cache already reads as rare or
    detected first (its address is the one request missing), the ones nobody has looked at next,
    popular ones last (nothing is missing for them), each widest first."""
    reading = world.readings.get(family.parent)
    rank = 1 if reading is None else 2 if reading.popular else 0
    return rank, -len(family.hosts), -len(family.names), family.parent


async def look_up(
    db: AsyncEngine, outside: Outside, shared: Shared, world: analysis.World, report: Report,
    found: Mapping[str, Family] | None = None,
) -> None:  # fmt: skip
    """Ask VirusTotal about the largest families the cache does not cover, at most :data:`BATCH`
    requests, within today's family budget. The address of a family's parent is asked only when
    the family is rare or detected (a popular site's network tells nothing). ``found``: the
    families, when the caller has them already."""
    s = outside.settings
    if found is None:
        found = await asyncio.to_thread(families_of, world.sightings)
    parent_ok, address_ok = usable_parent(outside, shared), usable_address(outside, shared)
    threshold = outside.view.threshold
    spent = 0
    async with db.connect() as conn:
        used = await store.used_today(conn, facts.VIRUSTOTAL, "families", outside.clock())
    room = s.families_per_day - used  # when it is spent, no candidate's campus view is prepared

    async def ask(kind: str, value: str, campus: Campus | None = None) -> service.Outcome:
        nonlocal spent
        got = await outside.lookup(
            facts.VIRUSTOTAL, kind, value, purpose="families", day_cap=s.families_per_day,
            campus=campus, fresh=analysis.current if kind == "domain" else None,
        )  # fmt: skip
        if got.status in (service.FETCHED, service.FAILED):
            spent += 1
        return got

    for family in sorted(candidates(found), key=lambda f: order_of(world, f)):
        if spent >= BATCH:
            break
        if room - spent <= 0:
            report.stopped = "today's budget for families is spent"
            return
        parent = family.parent
        if not parent_ok(parent):
            continue
        reading = world.readings.get(parent)
        if reading is None:
            if outside.failed_lately(facts.VIRUSTOTAL, "domain", parent):
                continue
            async with db.connect() as conn:
                ok, campus = await cleared(conn, outside, parent, set(family.investigations))
            if not ok:
                continue
            got = await ask("domain", parent, campus)
            if not _tally(report, got):
                return
            if not got.has_answer:
                continue
            reading = analysis.reading_of(got.answer_status or "", got.answer)
        if reading.address is not None or spent >= BATCH or room - spent <= 0:
            continue
        if not (reading.unranked or (reading.detected(threshold) and not reading.popular)):
            continue  # a popular (or unreadable) family's network is not worth a request
        address = load.first_address(reading.addresses, address_ok)
        if address is None or outside.failed_lately(facts.VIRUSTOTAL, "ip", address):
            continue
        if not _tally(report, await ask("ip", address)):
            return


async def evaluate(
    db: AsyncEngine, now: datetime, *, window: timedelta, classifier: IpClassifier,
    view: View, eligibility: Eligibility, shared: Shared, resolvers: Sequence[IPNetwork] = (),
) -> tuple[analysis.World, analysis.Result]:  # fmt: skip
    """The world of the window as the stored data and the cache show it, and what it says
    (nothing is asked). The analysis runs off the event loop: a busy window holds tens of
    thousands of names."""

    def address_ok(a: str) -> bool:
        return eligibility.check("ip", a) is None and shared.reason("ip", a) is None

    def parent_ok(p: str) -> bool:
        return eligibility.check("domain", p) is None

    async with db.connect() as conn:
        world = await load.world(conn, now, window=window, classifier=classifier, view=view,
                                 allowed=address_ok, resolvers=resolvers)  # fmt: skip
    result = await asyncio.to_thread(analysis.analyse, world, shared=shared, now=now,
                                     usable=parent_ok)  # fmt: skip
    return world, result


async def apply(
    db: AsyncEngine, now: datetime, result: analysis.Result
) -> dict[str, int]:  # fmt: skip
    """Add the flags of ``result`` to the stored evidence of the unreviewed investigations that
    lack them. Returns, by flag, how many investigations were changed."""
    changed: dict[str, int] = {}
    async with db.begin() as conn:
        for flag in FLAGS:
            changed[flag] = await raised.add_flag(conn, now, flag, result.flags.get(flag, ()))
    return changed


async def run(
    db: AsyncEngine, outside: Outside, shared: Shared, classifier: IpClassifier, now: datetime,
    *, window: timedelta, resolvers: Sequence[IPNetwork] = (),
) -> tuple[Report, analysis.Result]:  # fmt: skip
    """One pass: read the window, look up what is missing (within the budget), say what the
    answers show and add the flags. Returns the report and what the analysis found (the
    campaigns the suggester reads)."""
    s = outside.settings
    report = Report()
    if not outside.on(facts.VIRUSTOTAL):
        report.off = "no VirusTotal key"
    elif s.families_per_day <= 0:
        report.off = "switched off"
    view = outside.view
    eligibility = outside.eligibility
    world, result = await evaluate(db, now, window=window, classifier=classifier, view=view,
                                   eligibility=eligibility, shared=shared,
                                   resolvers=resolvers)  # fmt: skip
    if not report.off:
        await look_up(db, outside, shared, world, report, result.families)
        if report.asked:  # the cache has something new: read it again
            world, result = await evaluate(db, now, window=window, classifier=classifier,
                                           view=view, eligibility=eligibility, shared=shared,
                                           resolvers=resolvers)  # fmt: skip
    report.campaigns = len(result.campaigns)
    report.flagged = await apply(db, now, result)
    return report, result


__all__ = ["Report", "apply", "evaluate", "look_up", "run"]
