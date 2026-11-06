"""Where a case's outside actors went and what they got.

A case of outside addresses probing internal web servers has no affected *device*, so it needs the
internal targets (the sites and hosts the alerts say were aimed at) and, for each outside actor,
what ARGUS holds about it. Everything is read from what ARGUS already stores for the case; nothing
asks the SIEM, and a count no stored record shows is ``None`` ("not checked"), never zero."""

from __future__ import annotations

import uuid
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from argus import site as profile
from argus.assets.classify import IpClassifier
from argus.incident import evidence
from argus.incident import model as m
from argus.incident.scene import Scene, campus, is_ip
from argus.normalize.fields import values
from argus.responder.facts import answered_by_alert, outcomes_of

MAX_TARGETS = 20
SHOWN_PATHS = 5
ASKED = 6  # values a line names
_ASKED_KEYS: Mapping[str, tuple[str, ...]] = {
    "proxy.host": ("host", "ip"),
    "proxy.destination": ("ip", "destination"),
    "proxy.pair": ("host", "destination"),
    "proxy.contact": ("destination",),
    "dns.host_domains": ("host", "ip"),
    "web.followups": ("ip",),
    "web.path_outcomes": ("ip", "site"),
    "logs.source_events": ("ip", "host"),
}


def asked(template: str, params: Mapping[str, Any]) -> tuple[str, ...]:
    """The values a stored check asked about, as short text: the address, host or destination of
    a log check, the values of a threat-list look-up."""
    if template == "ti.lookup":
        given = params.get("values")
        found = [str(v) for v in given] if isinstance(given, list | tuple) else []
    else:
        found = [str(params[k]) for k in _ASKED_KEYS.get(template, ()) if params.get(k)]
    return tuple(dict.fromkeys(v[:100] for v in found if v.strip()))[:ASKED]


@dataclass
class Answers:
    """The successful (2xx) answers the stored records show, by outside address and by site."""

    ip_paths: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    ip_count: dict[str, int] = field(default_factory=dict)
    ip_checked: set[str] = field(default_factory=set)
    ip_cut: set[str] = field(default_factory=set)  # a stored sample that hit its cap (20+)
    site_paths: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    site_checked: set[str] = field(default_factory=set)
    site_cut: set[str] = field(default_factory=set)

    def of_ip(self, ip: str) -> tuple[int | None, tuple[str, ...], bool]:
        """(count, paths, exact): the count is a lower bound when the sample behind it was cut."""
        if ip not in self.ip_checked:
            return None, (), True
        paths = self.ip_paths.get(ip, set())
        return max(self.ip_count.get(ip, 0), len(paths)), shown(paths), ip not in self.ip_cut

    def of_site(self, site: str) -> tuple[int | None, tuple[str, ...], bool]:
        if site not in self.site_checked:
            return None, (), True
        paths = self.site_paths.get(site, set())
        return len(paths), shown(paths), site not in self.site_cut


def _sample_cut(params: Mapping[str, Any], snapshot: Any, total: int) -> bool:
    """Whether a stored ``web.followups`` answer was cut short: it asks for a sample of ``size``
    rows and does not count the rest (``track_total_hits: false``), so a sample that is full may
    be only part of the client's answers; a stored answer that says its rows are not complete is
    cut too."""
    from argus.context import web

    size = params.get("size")
    limit = size if isinstance(size, int) and not isinstance(size, bool) and size > 0 else web.ROWS
    complete = snapshot.get("rows_complete") if isinstance(snapshot, Mapping) else None
    return complete is False or total >= limit


def shown(paths: Iterable[str]) -> tuple[str, ...]:
    """At most :data:`SHOWN_PATHS` paths, the ones an attack looks for first."""
    from argus.context import web

    ranked = sorted(set(paths), key=lambda p: (not web.categories([web.decode(p)]), p))
    return tuple(p[:200] for p in ranked[:SHOWN_PATHS])


def answers(scene: Scene) -> Answers:
    """What the case's stored web checks and alerts show about successful answers."""
    from argus.context import paths as outcome

    out = Answers()
    for row in scene.f.evidence:
        ip = str(row.params.get("ip") or "")
        if row.template == "web.followups" and row.snapshot is not None:
            total = evidence.rows_total(row.snapshot) or 0
            cut = _sample_cut(row.params, row.snapshot, total)
            out.ip_checked.add(ip)
            out.ip_count[ip] = max(out.ip_count.get(ip, 0), total)
            if cut:
                out.ip_cut.add(ip)
            hits = row.snapshot.get("rows") if isinstance(row.snapshot, Mapping) else None
            for hit in hits if isinstance(hits, list) else []:
                source = hit.get("_source") if isinstance(hit, Mapping) else None
                if not isinstance(source, Mapping) or not _ok(source):
                    continue
                for path in [str(v) for v in values(source, "url.path")][:5]:
                    out.ip_paths[ip].add(path)
                    for site in values(source, "url.domain"):
                        out.site_paths[str(site).lower()].add(path)
                        out.site_checked.add(str(site).lower())
                        if cut:
                            out.site_cut.add(str(site).lower())
        elif row.template == "web.path_outcomes":
            site = str(row.params.get("site") or "").lower()
            asked_ = row.params.get("paths")
            served = [
                o.path
                for o in outcomes_of(row.snapshot, asked_ if isinstance(asked_, list) else [])
                if o.outcome == outcome.SUCCESS
            ]
            out.ip_checked.add(ip)
            out.ip_paths[ip].update(served)
            if site:
                out.site_checked.add(site)
                out.site_paths[site].update(served)
    for doc in scene.f.docs:  # an alert that records its own answer
        recorded = answered_by_alert({k: list(v) for k, v in doc.fields.items()})
        status = doc.fields.get("http.response.status_code")
        for ip in doc.fields.get("source.ip", ()):
            if status:
                out.ip_checked.add(ip)
            out.ip_paths[ip].update(recorded)
        for site in doc.fields.get("url.domain", ()):
            if status:
                out.site_checked.add(site.lower())
            out.site_paths[site.lower()].update(recorded)
    return out


def _ok(source: Mapping[str, Any]) -> bool:
    for v in values(source, "http.response.status_code"):
        try:
            if 200 <= int(str(v)) < 300:
                return True
        except ValueError:
            continue
    return False


def intel_words(scene: Scene, ip: str) -> str | None:
    """What the outside services ARGUS cached say about an address (VirusTotal, Shodan, Censys),
    in the words the indicator list uses; None when none answered."""
    from argus.outside import facts as outside_facts

    parts: list[str] = []
    for source in (outside_facts.VIRUSTOTAL, outside_facts.SHODAN, outside_facts.CENSYS):
        found = next(
            (o for o in scene.f.outside if o.source == source and o.kind == "ip" and o.value == ip),
            None,
        )
        if found is not None:
            parts.append(
                outside_facts.describe(
                    {
                        "source": found.source,
                        "kind": found.kind,
                        "value": found.value,
                        "status": found.status,
                        "answer": found.answer,
                    }
                )
            )
    return "; ".join(parts)[:300] or None


def _place(classifier: IpClassifier | None, ip: str) -> str | None:
    """The place the asset map names an address in (building, else department)."""
    if classifier is None:
        return None
    match = classifier.classify(ip).asset
    for entry in () if match is None else match.entries:
        for key in ("site.building", "site.department"):
            value = entry.fields.get(key)
            if value and all(c.isalnum() or c in " -_.,&()" for c in value):
                return value[:80]
    return None


def is_campus_domain(name: str, domains: Iterable[str]) -> bool:
    low = name.lower().rstrip(".")
    return any(low == d or low.endswith("." + d) for d in domains)


def targets(scene: Scene) -> tuple[tuple[m.ReportTarget, ...], int]:
    """The internal sites and hosts the case's outside actors went against: the internal domains the
    investigations name, the sites and internal destination addresses of the alerts whose source is
    an outside address. None for a case that has no outside actor."""
    if not scene.outsiders:
        return (), 0
    found: dict[tuple[str, str], set[uuid.UUID]] = defaultdict(set)
    for x in scene.f.members:
        for kind, value in scene.entity_of[x.id]:
            if kind == "domain" and is_campus_domain(value, scene.ctx.campus_domains):
                found[("site", value.lower())].add(x.id)
    classifier = scene.ctx.classifier
    for doc in scene.f.docs:
        sources = doc.fields.get("source.ip", ())
        if not sources or any(campus(s, classifier) for s in sources):
            continue  # only an outside address aiming at the internal network makes a target
        for site in doc.fields.get("url.domain", ()):
            if not is_ip(site):
                found[("site", site.lower())].add(doc.investigation_id)
        for ip in doc.fields.get("destination.ip", ()):
            if campus(ip, classifier):
                found[("host", ip)].add(doc.investigation_id)
    ans = answers(scene)
    outsiders = set(scene.outsiders)
    names: dict[tuple[str, uuid.UUID], int] = defaultdict(int)  # targets of a kind it names
    for (kind, _), ids in found.items():
        for i in ids:
            names[(kind, i)] += 1
    rows: list[m.ReportTarget] = []
    for (kind, value), ids in found.items():
        named = [scene.members[i] for i in ids if i in scene.members]
        if not named:
            continue
        firsts = [x.first for x in named if x.first]
        lasts = [x.last for x in named if x.last]
        answered, served, exact = ans.of_site(value) if kind == "site" else (None, (), True)
        rows.append(
            m.ReportTarget(
                kind="site" if kind == "site" else "host",
                value=value[:300],
                label=_place(classifier, value) if kind == "host" else None,
                alerts=sum(x.alerts for x in named),
                actors=len({v for x in named for _, v in scene.entity_of[x.id] if v in outsiders}),
                first_seen=_extreme(min, firsts),
                last_seen=_extreme(max, lasts),
                answered=answered,
                answered_exact=exact,
                served=served,
                shared=any(names[(kind, x.id)] > 1 for x in named),
            )
        )
    rows.sort(key=lambda t: (-t.alerts, t.kind, t.value))
    if len(rows) > MAX_TARGETS:
        scene.limits.append(
            f"{MAX_TARGETS} of the case's {len(rows)} {profile.own('targets')} are listed"
        )
    return tuple(rows[:MAX_TARGETS]), len(rows)


def _extreme(pick: Any, items: list[datetime]) -> datetime | None:
    return pick(items) if items else None
