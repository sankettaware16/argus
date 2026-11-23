"""Inbound exposure (P4-F E3), pure: for an inbound attack the organisation's own **site** is the
thing at risk and the outside address a threat; what the checking lane found turns into facts on it.

- **The site** of an inbound alert group: the own target its alerts name; failing that, the
  sites of its own stored web evidence (the client's 2xx answers, ``web.followups``); failing
  that, the hourly batched lookup's answer for its source and day (``web.source_sites``).
- **The facts** of an outside address on a site, from the stored checks. Nothing is verified
  without the site's soft-404 check (``web.catchall``) within a day, and a 2xx is verified only
  when its body is not the site's catch-all, not-found, home or commonest page, nor (within a
  few bytes, or less the path it echoed) what another file got from the site in any check of
  those days. A file is **served** when its verified 2xx is not tiny and another file's 2xx
  was there to compare it with (never from a rule's name); a **bulk take** is many distinct
  paths and body sizes under one sensitive prefix, under which a file was verified; the rare
  paths that **got through** are those with a verified 2xx. Two addresses that got through on
  the same rare paths of one site **share** them.
- **Lane L5**: a site with a served file, a bulk take or shared rare paths is a possible
  incident; a site that gave a 2xx it has not verified is a checking candidate (its gray band);
  plain scanning stays in the digest with its counts.

The facts reach the engine as signals of the alert group (``exposure.served``,
``exposure.bulk_take``, ``exposure.shared_paths``), so they become evidence observations on its
site with the engine's own scoring; ``lanes`` then puts the site in L5.
"""

from __future__ import annotations

import contextlib
import ipaddress
import uuid
from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from argus.context.paths import COMMON_PATHS, POSSIBLE, SUCCESS, same_file
from argus.normalize.fields import values
from argus.risk import webchecks
from argus.risk.config import Exposure, Sensitive
from argus.risk.observe import ObjectRef
from argus.risk.score import Verdict
from argus.site import Role, fields_for

SIGNALS = {"served": "exposure.served", "bulk_take": "exposure.bulk_take",
           "shared_paths": "exposure.shared_paths"}  # fmt: skip
LANE = "exposure"
MAX_SITES = 16
PUBLIC_DIRS = frozenset({".well-known"})


# --------------------------------------------------------------------------- paths


def _segments(path: str) -> list[str]:
    clean = unquote(path.split("?", 1)[0].split("#", 1)[0], errors="replace").strip().lower()
    return [s for s in clean.split("/") if s]


def hidden(segment: str) -> bool:
    return segment.startswith(".") and segment not in (".", "..") and segment not in PUBLIC_DIRS


def sensitive(path: str, rules: Sensitive) -> bool:
    """A path a site should not serve to the world (see ``config.Sensitive``)."""
    if path in COMMON_PATHS:
        return False
    parts = _segments(path)
    if not parts:
        return False
    if rules.hidden and any(hidden(p) for p in parts):
        return True
    last = parts[-1]
    if last in rules.names:
        return True
    return "." in last and last.rsplit(".", 1)[1] in rules.extensions


def prefix(path: str) -> str | None:
    """The path up to its first hidden directory (``/~u/.git/objects/ab`` -> ``/~u/.git/``);
    None when no directory of it is hidden."""
    parts = _segments(path)
    for i, part in enumerate(parts[:-1]):
        if hidden(part):
            return "/" + "/".join(parts[: i + 1]) + "/"
    return None


def followup_rows(snapshot: Any) -> list[tuple[str, str, int | None]]:
    """(site, path, status) of a stored ``web.followups`` answer (the client's 2xx answers)."""
    rows = snapshot.get("rows") if isinstance(snapshot, Mapping) else None
    if not isinstance(rows, list):
        return []
    f = fields_for(Role.WEB)
    out = []
    for row in rows:
        doc = row.get("_source") if isinstance(row, Mapping) else None
        if not isinstance(doc, Mapping):
            continue
        sites = [v for v in values(doc, f.source("domain")) if isinstance(v, str) and v.strip()]
        paths = [v for v in values(doc, f.source("url_path")) if isinstance(v, str) and v]
        codes = [v for v in values(doc, f.source("status_code"))
                 if isinstance(v, int) and not isinstance(v, bool)]  # fmt: skip
        if sites and paths:
            out.append(
                (sites[0].strip().lower()[:600], paths[0][:2048], codes[0] if codes else None)
            )
    return out


def is_outside(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- facts


@dataclass(frozen=True)
class CheckRow:
    """One stored check (``exposure_checks``)."""

    kind: str
    source: str | None
    site: str | None
    day: date
    verdict: str
    facts: Mapping[str, Any]
    checked_at: datetime


@dataclass(frozen=True)
class PairFacts:
    """What the checks found for one outside address on one site."""

    source: str
    site: str
    served: tuple[str, ...] = ()
    bulk: int = 0  # distinct paths of a bulk take (0: none)
    bulk_prefix: str | None = None
    through: tuple[str, ...] = ()  # paths with a verified 2xx (not the catch-all page)
    shared: tuple[str, ...] = ()  # rare paths another address got through on too
    soft_404: bool | None = None  # the site's catch-all check, when there is one
    checked: tuple[str, ...] = ()  # the kinds of check that answered
    at: datetime | None = None  # when the newest of its checks answered

    @property
    def signals(self) -> dict[str, int]:
        out = {}
        if self.served:
            out[SIGNALS["served"]] = len(self.served)
        if self.bulk:
            out[SIGNALS["bulk_take"]] = self.bulk
        if self.shared:
            out[SIGNALS["shared_paths"]] = len(self.shared)
        return out


def catchall_of(facts: Mapping[str, Any]) -> webchecks.Catchall:
    """A stored catch-all check as the reader made it."""

    def sizes(node: Any) -> dict[int, int]:
        out = {}
        for k, v in (node or {}).items() if isinstance(node, Mapping) else ():
            try:
                out[int(k)] = int(v)
            except (TypeError, ValueError):
                continue
        return out

    answered = {str(p): sizes(s) for p, s in (facts.get("answered") or {}).items()}
    catch = tuple((str(p), int(s)) for p, s in facts.get("catch") or []
                  if isinstance(s, int) and not isinstance(s, bool))  # fmt: skip
    return webchecks.Catchall(
        int(facts.get("requests") or 0), answered, sizes(facts.get("not_found")), catch,
        tuple(str(p) for p in facts.get("served") or []), sizes(facts.get("pages")),
    )  # fmt: skip


def bulk_of(facts: Mapping[str, Any], config: Exposure) -> tuple[int, str | None]:
    """(distinct paths, prefix) of a bulk take from a stored take check, or (0, None)."""
    paths = int(facts.get("paths") or 0)
    sizes = int(facts.get("sizes") or 0)
    top = [(str(p), int(n)) for p, n in facts.get("top") or []]
    if paths < config.bulk.paths or sizes < config.bulk.sizes or not top:
        return 0, None
    under: dict[str, int] = defaultdict(int)
    for path, _ in top:
        found = prefix(path)
        if found is not None:
            under[found] += 1
    if not under:
        return 0, None
    best = max(sorted(under), key=lambda k: under[k])
    if under[best] < config.bulk.share * len(top):
        return 0, None
    return paths, best


def _nearest(rows: Sequence[CheckRow], day: date) -> CheckRow | None:
    """The newest catch-all check of a site within a day of ``day``."""
    near = [r for r in rows if abs((r.day - day).days) <= 1 and r.verdict != "unknown"]
    return max(near, key=lambda r: r.checked_at, default=None)


def _sizes(item: Mapping[str, Any]) -> list[int]:
    out = []
    for s in item.get("sizes") or {}:
        with contextlib.suppress(TypeError, ValueError):
            out.append(int(s))
    return out


class _Answers:
    """Every 2xx answer (day, path, body size) of each site from the stored checks (each paths
    check's and each soft-404 check's): what one answer is compared with."""

    def __init__(self, paths: Iterable[CheckRow], catch: Mapping[str, Sequence[CheckRow]]) -> None:
        self.by_site: dict[str, list[tuple[date, str, int]]] = defaultdict(list)
        for r in paths:
            for item in r.facts.get("paths") or []:
                path = str(item.get("path") or "") if isinstance(item, Mapping) else ""
                if path and r.site:
                    self.by_site[r.site] += [(r.day, path, s) for s in _sizes(item)]
        for site, rows in catch.items():
            for r in rows:
                if r.verdict != "unknown":
                    found = catchall_of(r.facts).answered
                    self.by_site[site] += [(r.day, p, s) for p, sz in found.items() for s in sz]

    def near(self, site: str, day: date) -> list[tuple[str, int]]:
        return [(p, s) for d, p, s in self.by_site.get(site, ()) if abs((d - day).days) <= 1]


def _compared(page: webchecks.Catchall, others: Sequence[tuple[str, int]]) -> bool:
    """Whether two different files got a 2xx from the site (else nothing was compared)."""
    return len(page.files | {same_file(p) for p, _ in others}) >= 2


def derive(rows: Iterable[CheckRow], config: Exposure) -> dict[tuple[str, str], PairFacts]:
    """Every (outside address, site) pair's facts from the stored checks (see the module)."""
    catch: dict[str, list[CheckRow]] = defaultdict(list)
    paths: list[CheckRow] = []
    takes: list[CheckRow] = []
    for r in rows:
        if r.kind == "catchall" and r.site:
            catch[r.site].append(r)
        elif r.kind == "paths" and r.site and r.source:
            paths.append(r)
        elif r.kind == "take" and r.site and r.source:
            takes.append(r)
    answers = _Answers(paths, catch)
    out: dict[tuple[str, str], PairFacts] = {}
    rare: dict[tuple[str, str], set[str]] = defaultdict(set)
    for r in sorted(paths, key=lambda r: r.checked_at):
        assert r.source is not None
        assert r.site is not None
        c = _nearest(catch.get(r.site, []), r.day)
        page = catchall_of(c.facts) if c is not None else None
        others = answers.near(r.site, r.day)
        served: set[str] = set()
        through: set[str] = set()
        for item in r.facts.get("paths") or []:
            path = str(item.get("path") or "")
            if page is None or item.get("outcome") not in (SUCCESS, POSSIBLE) or not path:
                continue  # no soft-404 check: a 2xx stays unverified (the gray band)
            good = [s for s in _sizes(item) if not page.is_catch_all(path, s, others)]
            if not good:
                continue  # every 2xx it got was the catch-all page, or had no size
            through.add(path)
            if (
                page.requests
                and any(s >= config.served_min_bytes for s in good)
                and (_compared(page, others) or item.get("outcome") == SUCCESS)
            ):
                served.add(path)
        rare[(r.source, r.site)].update(str(p) for p in r.facts.get("rare") or [])
        key = (r.source, r.site)
        held = out.get(key, PairFacts(r.source, r.site))
        out[key] = replace(
            held,
            served=tuple(sorted(set(held.served) | served)),
            through=tuple(sorted(set(held.through) | through)),
            soft_404=(page.soft_404 if page is not None else held.soft_404),
            checked=tuple(sorted({*held.checked, "paths", *(("catchall",) if page else ())})),
            at=max(filter(None, (held.at, r.checked_at, c.checked_at if c else None))),
        )  # fmt: skip
    for r in sorted(takes, key=lambda r: r.checked_at):
        assert r.source is not None
        assert r.site is not None
        count, where = bulk_of(r.facts, config)
        c = _nearest(catch.get(r.site, []), r.day)
        if count and not _verified_under(c, where, answers.near(r.site, r.day)):
            count, where = 0, None  # many 2xx, but none shown unlike the catch-all page
        key = (r.source, r.site)
        held = out.get(key, PairFacts(r.source, r.site))
        out[key] = replace(
            held, bulk=max(held.bulk, count), bulk_prefix=held.bulk_prefix or where,
            checked=tuple(sorted({*held.checked, "take"})),
            at=max(filter(None, (held.at, r.checked_at))),
        )  # fmt: skip
    by_site: dict[str, list[PairFacts]] = defaultdict(list)
    for facts in out.values():
        by_site[facts.site].append(facts)
    for site, pairs in by_site.items():
        for a in pairs:
            mine = {same_file(p) for p in a.through}
            shared: set[str] = set()
            for b in pairs:
                if b.source == a.source:
                    continue
                rare_files = {same_file(p) for p in rare[(a.source, site)] | rare[(b.source, site)]}
                common = mine & {same_file(p) for p in b.through} & rare_files
                if len(common) >= config.shared.paths:
                    shared |= common
            if shared:
                out[(a.source, site)] = replace(a, shared=tuple(sorted(shared)))
    return out


def _verified_under(c: CheckRow | None, where: str | None,
                    others: Sequence[tuple[str, int]]) -> bool:  # fmt: skip
    """Whether the site's soft-404 check is there, compared two files, and a 2xx under the
    take's prefix (``where``) was not its catch-all page: a page that echoes the path, or whose
    size a nonce moves, gives a wordlist scanner many paths and sizes too."""
    if c is None or where is None:
        return False
    page = catchall_of(c.facts)
    if not _compared(page, others):
        return False
    found = [*((p, s) for p, sz in page.answered.items() for s in sz), *others]
    return any(prefix(p) == where and not page.is_catch_all(p, s, others) for p, s in found)


def rare_paths(seen: Mapping[str, set[str]], config: Exposure) -> frozenset[str]:
    """The paths (as files) at most ``rare_sources`` outside addresses got a 2xx for (``seen``:
    file -> addresses)."""
    return frozenset(p for p, who in seen.items() if 0 < len(who) <= config.shared.rare_sources)


# --------------------------------------------------------------------------- a group's sites


@dataclass(frozen=True)
class GroupSites:
    """What the exposure step adds to an alert group: the sites it reached (when its alerts
    name none) and the facts of its source on them, as signals."""

    sites: tuple[str, ...] = ()
    signals: Mapping[str, int] = field(default_factory=dict)
    origin: str = ""  # "evidence", "lookup", "" (none)


def group_sites(
    sources: Sequence[str], day: date, named: Sequence[str],
    evidence: Sequence[tuple[str, str, int | None]],
    lookups: Mapping[tuple[str, date], Sequence[Mapping[str, Any]]],
    facts: Mapping[tuple[str, str], PairFacts], window: timedelta,
) -> GroupSites:  # fmt: skip
    """An inbound group's sites and facts. ``sources``: its outside actor addresses; ``named``:
    the sites its alerts name (url.domain); ``evidence``: its stored 2xx answers (site, path,
    status); ``lookups``: the batched lookup's sites by (source, day); ``facts``: the checks'
    facts of the window. Where its source has decisive facts on some sites, the group's sites
    are those: the others gave it nothing that was proven."""
    sites: list[str] = []
    origin = ""
    for site, _, _ in evidence:
        if site not in sites:
            sites.append(site)
    if sites:
        origin = "evidence"
    else:
        for src in sources:
            for hit in lookups.get((src, day), ()):
                site = str(hit.get("site") or "")
                if site and site not in sites:
                    sites.append(site)
        origin = "lookup" if sites else ""
    known = [s.strip().lower() for s in named if isinstance(s, str) and s.strip()]
    candidates = list(dict.fromkeys([*known, *sites]))
    best: dict[str, int] = {}
    decisive: list[str] = []
    for src in sources:
        for site in candidates:
            pair = facts.get((src, site))
            if pair is None:
                continue
            got = pair.signals
            if got:
                decisive.append(site)
            for name, n in got.items():
                best[name] = max(best.get(name, 0), n)
    if decisive:
        sites = [s for s in sites if s in decisive] or sites
    return GroupSites(tuple(sites[:MAX_SITES]), best, origin)


# --------------------------------------------------------------------------- the lane


def lanes(
    verdicts: Mapping[ObjectRef, Verdict], config: Exposure,
) -> dict[ObjectRef, Verdict]:  # fmt: skip
    """L5 on the own sites: a site whose 7-day window holds a lane kind's evidence (a served
    file, a bulk take, shared rare paths) is in the exposure lane; one that gave a 2xx it has not
    verified (the ``success`` kind) is a checking candidate (gray). Other objects unchanged."""
    out = dict(verdicts)
    wanted = {f"ev:{k}" for k in config.lane_kinds}
    for ref, v in verdicts.items():
        if ref.kind != "site" or v.held != "target":
            continue
        sources = {c.source for c in v.window("7d").contributions}
        if sources & wanted:
            out[ref] = replace(v, lanes=(LANE,), gray=(), held="lane")  # type: ignore[arg-type]
        elif "ev:success" in sources:
            out[ref] = replace(v, gray=(LANE,))  # type: ignore[arg-type]
    return out


def lane_sources(v: Verdict, sources_of: Mapping[uuid.UUID, Collection[str]],
                 config: Exposure) -> frozenset[str]:  # fmt: skip
    """The outside addresses whose checked facts put a site in L5: those of the alert groups of
    its 7-day window's lane kinds (``sources_of``: an alert group's outside addresses)."""
    wanted = {f"ev:{k}" for k in config.lane_kinds}
    out: set[str] = set()
    for c in v.window("7d").contributions:
        if c.source in wanted:
            out.update(sources_of.get(c.group, ()))
    return frozenset(out)


def folded(
    entering: Sequence[ObjectRef], held: Iterable[ObjectRef], verdicts: Mapping[ObjectRef, Verdict],
    sources_of: Mapping[uuid.UUID, Collection[str]], config: Exposure,
) -> set[ObjectRef]:  # fmt: skip
    """The sites of ``entering`` (in L5 now, each a new item otherwise; in this order) that an
    outside address puts in L5 that also put another site there: one held in L5 already
    (``held``) or one that entered before it. The same attack is one item; the rescore and the
    replay both fold (the incident joins its sites in E2)."""
    seen: set[str] = set()
    for ref in held:
        v = verdicts.get(ref)
        if v is not None and LANE in v.lanes:
            seen |= lane_sources(v, sources_of, config)
    out: set[ObjectRef] = set()
    for ref in entering:
        v = verdicts.get(ref)
        if v is None or LANE not in v.lanes:
            continue
        mine = lane_sources(v, sources_of, config)
        if mine & seen:
            out.add(ref)
        seen |= mine
    return out


# --------------------------------------------------------------------------- the digest's counts


@dataclass(frozen=True)
class Scanning:
    """Plain scanning of one day, in counts: what the digest says instead of an item."""

    sources: int
    sites: int
    groups: int
    got_2xx: int  # outside addresses with a 2xx that was not verified
    catch_all_sites: int  # sites whose 2xx answers were their catch-all page


def scanning(
    groups: Iterable[tuple[str, Sequence[str], bool]], soft_404: Iterable[str],
) -> Scanning:  # fmt: skip
    """``groups``: (source, sites, got a 2xx) of the day's inbound groups outside L5."""
    sources: set[str] = set()
    sites: set[str] = set()
    ok: set[str] = set()
    n = 0
    for source, where, got in groups:
        n += 1
        sources.add(source)
        sites.update(where)
        if got:
            ok.add(source)
    return Scanning(len(sources), len(sites), n, len(ok), len(set(soft_404) & sites))
