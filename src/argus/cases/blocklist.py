"""A case's ready block list: the domains, their registered parents and the addresses of a case
that the organisation can block at the network for everyone, with the outside evidence for each
(VirusTotal engines, network owner, registration day). Only the case's own public addresses and
valid names go in, never an internal address, a hash or anything in shared infrastructure (blocking
it would cut off everybody). Nothing is asked of an outside source. Exports: CSV and plain text."""

from __future__ import annotations

import csv
import io
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Text, bindparam, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.assets.classify import IpClass, IpClassifier
from argus.cases import known
from argus.cases.membership import NO_SHARED, Shared
from argus.outside import facts

MAX_ENTRIES = 500
COLUMNS = (
    "type", "value", "kind", "engines_flagging", "engines_total", "owner", "registered",
    "first_seen_on_campus", "campus_devices", "evidence_checked",
)  # fmt: skip


@dataclass(frozen=True)
class Entry:
    """One thing to block: a domain, a registered parent (every name under it) or an address."""

    type: str  # "domain", "family" or "address"
    value: str
    flagging: int | None = None  # VirusTotal engines that call it malicious
    engines: int | None = None
    owner: str | None = None  # the network's owner, for an address
    registered: str | None = None  # the day a domain was registered
    first_seen: datetime | None = None  # first alert of the case's investigations that hold it
    devices: int = 0  # internal devices of the case that reached it
    checked: datetime | None = None  # when the outside answer was fetched

    @property
    def evidence(self) -> str:
        if self.flagging is None or not self.engines:
            return "no outside record yet"
        return f"{self.flagging} of {self.engines} engines flag it"


@dataclass(frozen=True)
class Blocklist:
    case_number: int
    title: str
    entries: tuple[Entry, ...]
    skipped: int = 0  # shared infrastructure left out
    notified_at: datetime | None = None
    blocked_at: datetime | None = None
    cut: bool = False  # the list was cut at MAX_ENTRIES


_INDICATORS = text(
    "SELECT kind, value FROM case_indicators WHERE case_id = :c AND removed_at IS NULL"
    " AND role IN ('c2', 'indicator') AND kind IN ('ip', 'domain') ORDER BY kind, value"
)
_ANSWERS = text(
    "SELECT kind, indicator, answer, fetched_at FROM outside_lookups WHERE source = 'virustotal'"
    " AND status = 'found' AND ((kind = 'ip' AND indicator = ANY(:ips))"
    " OR (kind = 'domain' AND indicator = ANY(:domains)))"
).bindparams(bindparam("ips", type_=ARRAY(Text)), bindparam("domains", type_=ARRAY(Text)))
_SEEN = text(
    "SELECT e.value, min(i.first_event_at) AS first, count(DISTINCT d.value) AS devices"
    " FROM case_members m JOIN investigations i ON i.id = m.investigation_id"
    " JOIN investigation_entities e ON e.investigation_id = i.id"
    " LEFT JOIN investigation_entities d ON d.investigation_id = i.id AND d.kind = 'ip'"
    " AND d.value = ANY(:devices)"
    " WHERE m.case_id = :c AND m.removed_at IS NULL AND e.kind IN ('ip', 'domain')"
    " GROUP BY e.value"
).bindparams(bindparam("devices", type_=ARRAY(Text)))
_CASE = text("SELECT number, title, notified_at, blocked_at FROM cases WHERE id = :c")
_DEVICES = text(
    "SELECT value FROM case_indicators WHERE case_id = :c AND removed_at IS NULL"
    " AND role = 'actor' AND kind = 'ip'"
)


def _family_seen(
    seen: Mapping[str, tuple[datetime | None, int]], parent: str
) -> tuple[datetime | None, int]:
    """First seen and devices over a parent and every name under it."""
    firsts = [
        f for name, (f, _) in seen.items() if (name == parent or name.endswith("." + parent)) and f
    ]
    devices = max(
        (n for name, (_, n) in seen.items() if name == parent or name.endswith("." + parent)),
        default=0,
    )
    return (min(firsts) if firsts else None, devices)


@dataclass(frozen=True)
class Chosen:
    """What of a case's indicators the list holds: the registered parents, the names under no
    parent held, the public addresses, and how many were shared infrastructure."""

    parents: tuple[str, ...]
    domains: tuple[str, ...]
    ips: tuple[str, ...]
    skipped: int = 0

    @property
    def total(self) -> int:
        return (
            len(self.parents)
            + len([d for d in self.domains if d not in self.parents])
            + len(self.ips)
        )


def choose(
    marks: Iterable[tuple[str, str]], shared: Shared, classifier: IpClassifier | None = None
) -> Chosen:
    """The indicators a block list may hold: a public address (the classifier says so, not
    an internal, private, loopback or special address) or a valid domain name, not in shared
    infrastructure. A hash, a URL and anything that is not an address or a name are no block."""
    classes = classifier or IpClassifier(None, ())
    kept: list[tuple[str, str]] = []
    skipped = 0
    for kind, value in marks:
        canonical = facts.canonical(kind, value) if kind in ("ip", "domain") else None
        if canonical is None or canonical != value:
            continue
        if kind == "ip" and classes.classify(value).ip_class is not IpClass.PUBLIC:
            continue
        if shared.reason(kind, value) is not None:
            skipped += 1
            continue
        kept.append((kind, value))
    parents = sorted({p for kind, v in kept if kind == "domain" and (p := known.parent_of(v))})
    parents = [p for p in parents if shared.reason("domain", p) is None]
    domains = sorted({v for k, v in kept if k == "domain"})
    ips = sorted({v for k, v in kept if k == "ip"})
    return Chosen(tuple(parents), tuple(domains), tuple(ips), skipped)


async def count(
    conn: AsyncConnection, case_id: uuid.UUID, shared: Shared = NO_SHARED,
    classifier: IpClassifier | None = None,
) -> int:  # fmt: skip
    """How many entries the case's block list holds, without building it (the case page only
    counts: one read of the case's indicators)."""
    marks = [(str(r.kind), str(r.value)) for r in await conn.execute(_INDICATORS, {"c": case_id})]
    return min(choose(marks, shared, classifier).total, MAX_ENTRIES)


async def build(
    conn: AsyncConnection, case_id: uuid.UUID, shared: Shared = NO_SHARED,
    classifier: IpClassifier | None = None,
) -> Blocklist | None:  # fmt: skip
    """The case's block list, or None for no such case."""
    case = (await conn.execute(_CASE, {"c": case_id})).first()
    if case is None:
        return None
    marks = [(str(r.kind), str(r.value)) for r in await conn.execute(_INDICATORS, {"c": case_id})]
    devices = [str(r.value) for r in await conn.execute(_DEVICES, {"c": case_id})]
    chosen = choose(marks, shared, classifier)
    skipped, parents, domains, ips = (
        chosen.skipped, list(chosen.parents), list(chosen.domains), list(chosen.ips),
    )  # fmt: skip
    answers: dict[tuple[str, str], tuple[Mapping[str, Any], datetime]] = {}
    for r in await conn.execute(_ANSWERS, {"ips": ips, "domains": sorted({*domains, *parents})}):
        answers[(str(r.kind), str(r.indicator))] = (r.answer, r.fetched_at)
    seen = {
        str(r.value): (r.first, int(r.devices))
        for r in await conn.execute(_SEEN, {"c": case_id, "devices": devices})
    }

    def entry(type_: str, kind: str, value: str, family: bool = False) -> Entry:
        answer, fetched = answers.get((kind, value), ({}, None))
        first, count = _family_seen(seen, value) if family else seen.get(value, (None, 0))
        return Entry(
            type_, value, facts.number(answer.get("malicious")) if answer else None,
            facts.number(answer.get("engines")) if answer else None,
            facts.clean(answer.get("owner")) if answer else None,
            answer.get("created") if answer and isinstance(answer.get("created"), str) else None,
            first, count, fetched,
        )  # fmt: skip

    entries = [entry("family", "domain", p, family=True) for p in parents]
    entries += [entry("domain", "domain", d) for d in domains if d not in parents]
    entries += [entry("address", "ip", a) for a in ips]
    cut = len(entries) > MAX_ENTRIES
    return Blocklist(
        int(case.number), case.title, tuple(entries[:MAX_ENTRIES]), skipped,
        case.notified_at, case.blocked_at, cut,
    )  # fmt: skip


BOM = "\ufeff"  # a spreadsheet opens a UTF-8 file with it as UTF-8, else in a legacy code page


def to_csv(blocklist: Blocklist, *, bom: bool = False) -> str:
    """The list as CSV for a spreadsheet (one row for each thing to block). ``bom``: with a byte
    order mark, as the download has it (Excel reads a name with non-ASCII letters right only when
    the file has one); the terminal's copy has none, for pipes and tools that do not expect it."""
    out = io.StringIO()
    if bom:
        out.write(BOM)
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    for e in blocklist.entries:
        writer.writerow([
            e.type, _safe(e.value), "registered domain (every name under it)" if e.type == "family"
            else e.type, "" if e.flagging is None else e.flagging,
            "" if e.engines is None else e.engines, _safe(e.owner or ""), e.registered or "",
            "" if e.first_seen is None else f"{e.first_seen:%Y-%m-%d}", e.devices,
            "" if e.checked is None else f"{e.checked:%Y-%m-%d}",
        ])  # fmt: skip
    return out.getvalue()


def _safe(value: str) -> str:
    """A cell that a spreadsheet will not read as a formula."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


safe_cell = _safe  # the incident report's CSVs neutralise a cell the same way


def to_text(blocklist: Blocklist, stamp: Any = None) -> str:
    """The list as plain text, in the shape of an e-mail to the head of cybersecurity."""
    day = stamp or (lambda moment: f"{moment:%d %b %Y}")
    lines = [
        f"Subject: Please block these at the network (ARGUS case {blocklist.case_number})",
        "",
        "To the head of cybersecurity,",
        "",
        f"ARGUS case {blocklist.case_number} ({blocklist.title}) concerns devices on"
        f" {site.where()} that are infected and keep contacting the servers below.",
    ]
    if blocklist.notified_at is not None:
        lines.append(
            f"The owners were told on {day(blocklist.notified_at)} and the alerts continue; the"
            " devices are personal and cannot be forced clean."
        )
    if blocklist.blocked_at is not None:
        lines.append(f"A block was recorded on {day(blocklist.blocked_at)}.")
    lines += [
        "A block at DNS, the firewall or the web proxy protects every device without touching"
        " anyone's laptop.",
        "",
    ]
    for title, wanted in (
        ("Registered domains (block every name under them)", "family"),
        ("Domain names", "domain"),
        ("Addresses", "address"),
    ):
        group = [e for e in blocklist.entries if e.type == wanted]
        if not group:
            continue
        lines.append(title + ":")
        for e in group:
            facts_ = [e.evidence]
            if e.owner:
                facts_.append(f"network: {e.owner}")
            if e.registered:
                facts_.append(f"registered {e.registered}")
            if e.first_seen is not None:
                facts_.append(f"first seen on {site.where()} {day(e.first_seen)}")
            if e.devices:
                facts_.append(f"{e.devices} {site.own('device' if e.devices == 1 else 'devices')}")
            lines.append(f"  {e.value}  ({'; '.join(facts_)})")
        lines.append("")
    if blocklist.skipped:
        lines.append(
            f"Left out: {blocklist.skipped} shared address(es) or name(s) (content-delivery or"
            " cloud services), because blocking them would cut off everybody."
        )
    if blocklist.cut:
        lines.append(f"The list is cut at {MAX_ENTRIES} entries.")
    team = site.organisation().short_name
    lines += ["", "Regards,", f"ARGUS (the first-line analyst of the {team})", ""]
    return "\n".join(lines)
