"""Telling what a family of indices is: pure functions from names and mappings to a role, a
confidence and the evidence, for ``argus discover``.

A role's score is the points of its name hints and of its field hints. Evidence only adds, and a
confidence never falls as the score rises. A role is proposed only when its score reaches
``MIN_SCORE``; the best role wins and a role within ``RIVAL_GAP`` is reported as a rival.
Nothing here talks to Elasticsearch.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from typing import Any, Final

from argus.site import FIELD_ROLES, LOG_ROLES, Role, family_pattern_ok, index_name_ok

# Points for a word in a name (the words are the lower-case alphanumeric runs of the name).
NAME_HINTS: Final[Mapping[Role, Mapping[str, int]]] = {
    Role.PROXY: {
        "squid": 4, "bluecoat": 4, "zscaler": 4, "proxy": 2, "forcepoint": 2, "websense": 2,
        "iboss": 2, "netskope": 2, "forward": 1, "webgateway": 3,
    },
    Role.WEB: {
        "nginx": 4, "apache": 4, "httpd": 4, "iis": 4, "traefik": 4, "caddy": 4, "haproxy": 3,
        "modsecurity": 2, "waf": 1, "access": 1, "web": 1,
    },
    Role.DNS: {
        "dns": 3, "unbound": 4, "coredns": 4, "pihole": 4, "dnsmasq": 4, "bind": 2, "named": 2,
        "resolver": 1,
    },
    Role.AUTH: {
        "sso": 3, "saml": 2, "okta": 4, "keycloak": 4, "signin": 3, "authentication": 3,
        "idp": 3, "login": 2, "auth": 2, "radius": 2, "entra": 2, "oauth": 2, "ldap": 1,
        "azure": 1,
    },
    Role.MAIL: {
        "postfix": 4, "exim": 4, "dovecot": 4, "sendmail": 4, "smtp": 3, "mail": 2, "imap": 2,
        "pop3": 2, "exchange": 1,
    },
}  # fmt: skip
# Points for a well-known field the mapping has (the names are ECS's).
FIELD_HINTS: Final[Mapping[Role, Mapping[str, int]]] = {
    Role.PROXY: {
        "url.original": 2, "destination.ip": 2, "destination.bytes": 2, "source.ip": 1,
        "http.response.status_code": 1, "http.request.method": 1, "event.action": 1,
    },
    Role.WEB: {
        "url.path": 3, "url.domain": 2, "user_agent.original": 2, "http.response.body.bytes": 2,
        "http.request.method": 1, "http.response.status_code": 1, "source.ip": 1,
    },
    Role.DNS: {
        "dns.question.name": 4, "dns.question.type": 2, "dns.response_code": 2, "source.ip": 1,
        "client.ip": 1,
    },
    Role.AUTH: {
        "user.name": 2, "event.outcome": 2, "event.action": 1, "source.ip": 1,
        "user_agent.original": 1,
    },
    Role.MAIL: {
        "email.from.address": 3, "email.to.address": 3, "email.message_id": 2, "source.ip": 1,
    },
}  # fmt: skip
MIN_SCORE: Final = 4  # a role below this is not proposed
NAME_ONLY_SCORE: Final = 3  # ... unless its name alone reaches this: one strong product word
HIGH_SCORE: Final = 9
MEDIUM_SCORE: Final = 6
RIVAL_GAP: Final = 1  # a role this close to the best one is a rival
_WORDS = re.compile(r"[^a-z0-9]+")


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


RANK: Final = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


def words(name: str) -> frozenset[str]:
    """The lower-case alphanumeric words of an index, alias or data stream name."""
    return frozenset(w for w in _WORDS.split(name.lower()) if w)


@dataclass(frozen=True)
class Score:
    """A role's points and the hints that gave them."""

    role: Role
    name_points: int = 0
    field_points: int = 0
    name_hits: tuple[str, ...] = ()
    field_hits: tuple[str, ...] = ()

    @property
    def total(self) -> int:
        return self.name_points + self.field_points


def score(role: Role, name_words: Iterable[str], present: Iterable[str]) -> Score:
    """A role's score for the words of a name and the well-known fields a mapping has."""
    have_words = set(name_words)
    have_fields = set(present)
    name_hits = tuple(sorted(w for w in NAME_HINTS.get(role, {}) if w in have_words))
    field_hits = tuple(sorted(f for f in FIELD_HINTS.get(role, {}) if f in have_fields))
    return Score(
        role,
        sum(NAME_HINTS[role][w] for w in name_hits),
        sum(FIELD_HINTS[role][f] for f in field_hits),
        name_hits,
        field_hits,
    )


def confidence_of(total: int, name_points: int, field_points: int) -> Confidence:
    """High when the name and the fields agree and the score is large; medium for a good score;
    low for one that only just reaches ``MIN_SCORE``. Never falls as any argument rises."""
    if total >= HIGH_SCORE and name_points >= 2 and field_points >= 4:
        return Confidence.HIGH
    if total >= MEDIUM_SCORE:
        return Confidence.MEDIUM
    return Confidence.LOW


@dataclass(frozen=True)
class Verdict:
    """What a family looks like: the best role, how sure, the rivals and the evidence."""

    role: Role | None
    confidence: Confidence
    best: Score | None
    rivals: tuple[Score, ...] = ()
    evidence: tuple[str, ...] = ()


def qualifies(s: Score) -> bool:
    """Whether a role's score is enough to propose it: ``MIN_SCORE`` points in all, or a name
    that alone gives ``NAME_ONLY_SCORE`` (one strong product word; a low-confidence proposal).
    The name's points count whether or not the mapping was read, so reading a mapping can add
    to a proposal and never remove one."""
    return s.total >= MIN_SCORE or s.name_points >= NAME_ONLY_SCORE


def classify(name: str, present: Iterable[str]) -> Verdict:
    """The role of a family from its name and the fields it maps (none when its mapping was
    not read). ``role`` is None when no role ``qualifies``."""
    scores = sorted(
        (score(role, words(name), present) for role in LOG_ROLES if role is not Role.OTHER),
        key=lambda s: (-s.total, list(Role).index(s.role)),
    )
    top = next((s for s in scores if qualifies(s)), None)
    if top is None:
        return Verdict(None, Confidence.LOW, scores[0] if scores[0].total else None)
    rivals = tuple(
        s for s in scores if s is not top and qualifies(s) and top.total - s.total <= RIVAL_GAP
    )
    confidence = confidence_of(top.total, top.name_points, top.field_points)
    return Verdict(top.role, confidence, top, rivals, evidence_of(top, rivals))


def evidence_of(top: Score, rivals: Sequence[Score]) -> tuple[str, ...]:
    lines = []
    if top.name_hits:
        lines.append(f"the name has {', '.join(top.name_hits)} ({top.name_points} points)")
    if top.field_hits:
        lines.append(f"the mapping has {', '.join(top.field_hits)} ({top.field_points} points)")
    for rival in rivals:
        lines.append(f"also looks like {rival.role.value} ({rival.total} points): check it")
    return tuple(lines)


# ----------------------------------------------------------------------------- threat intel
# Words of a threat-intel index's name (the ECS fields alone prove nothing: a full ECS template
# maps ``threat.indicator.*`` in every index it covers). An ``ioc_value`` field is proof alone.
TI_WORDS: Final = frozenset(
    {
        "ti", "threat", "threats", "intel", "ioc", "iocs", "indicator", "indicators", "feed",
        "feeds", "misp", "otx", "cti", "opencti", "threatintel",
    }
)  # fmt: skip
_TI_GROUP = re.compile(r"^(?P<type>logs|metrics)-ti_[a-z0-9._+-]+$")


def ti_named(name: str) -> bool:
    return bool(words(name) & TI_WORDS)


def ti_group(pattern: str) -> str | None:
    """The pattern of the family of data streams Elastic's Threat Intel integration writes
    (``logs-ti_<feed>.<dataset>-<namespace>``): one source covers them all."""
    match = _TI_GROUP.match(pattern)
    return f"{match['type']}-ti_*" if match else None


@dataclass(frozen=True)
class TiVerdict:
    """What a mapping says a threat-intel index is: its schema (None: not usable as one) and why."""

    schema: str | None
    evidence: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


def ti_verdict(name: str, mapped: Mapping[str, Typed]) -> TiVerdict | None:
    """Whether an index with this name and mapping is a threat-intel source: ``ioc`` when it maps
    ``ioc_value``, ``ecs`` when it maps ``threat.indicator.type`` and its name has a threat-intel
    word. None when it looks like neither."""
    value = mapped.get("ioc_value")
    if value is not None:
        if value.type == "text" and value.keyword:
            return TiVerdict("ioc", ("the mapping has ioc_value (text with a keyword sub-field)",))
        return TiVerdict(
            None,
            notes=("ioc_value is not text with a keyword sub-field: ARGUS asks ioc_value.keyword",),
        )
    if "threat.indicator.type" in mapped and ti_named(name):
        return TiVerdict(
            "ecs",
            ("the mapping has threat.indicator.type", "the name has a threat-intel word"),
        )
    return None


# ----------------------------------------------------------------------------- the listing

_DAILY = re.compile(r"^(?P<prefix>.*[-._])(?P<day>\d{4}\.\d{2}\.\d{2})$", re.ASCII)
# a weekly (Logstash's xxxx.ww: 2026.45) or monthly (2026.11) index: the prefix's numbers above 12
# say weeks
_PERIOD = re.compile(r"^(?P<prefix>.*[-._])(?P<year>\d{4})\.(?P<n>\d{2})$", re.ASCII)
_BACKING_DAY = re.compile(r"(\d{4}\.\d{2}\.\d{2})", re.ASCII)


def period_day(year: int, n: int, weekly: bool) -> str | None:
    """The first day (``YYYY.MM.DD``) of ISO week ``n`` or of month ``n`` of ``year``."""
    try:
        first = date.fromisocalendar(year, n, 1) if weekly else date(year, n, 1)
    except ValueError:
        return None
    return first.strftime("%Y.%m.%d")


def valid_day(text: str) -> bool:
    """Whether ``YYYY.MM.DD`` is a day of the calendar (``2026.13.45`` and year 0000 are not)."""
    try:
        year, month, day = (int(p) for p in text.split("."))
        date(year, month, day)
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class Candidate:
    """A set of indices that could be one family: daily indices of one prefix, one data stream
    or one alias."""

    pattern: str  # the family's pattern: 'prefix-*' (dated) or the exact name
    kind: str  # "daily" (dated indices: by day, week or month), "stream" or "alias"
    indices: tuple[str, ...] = ()  # the dated indices, oldest first
    backing: tuple[str, ...] = ()  # a data stream's backing indices, oldest first
    time_field: str | None = None  # a data stream's timestamp field, as the listing says it
    period: str = "day"  # a dated family's: "day", "week" or "month"

    @property
    def sample(self) -> str | None:
        """The index (or stream) whose mapping is asked: a daily family's newest index, a data
        stream's newest backing index, an alias itself."""
        if self.kind == "daily":
            return self.indices[-1] if self.indices else None
        if self.kind == "stream":
            return self.backing[-1] if self.backing else self.pattern
        return self.pattern

    @property
    def days(self) -> tuple[str, ...]:
        """The days (``YYYY.MM.DD``) the family's indices carry, oldest first; a text that is
        no day of the calendar is not one."""
        if self.kind == "daily" and self.period != "day":
            found = {d for i in self.indices if (m := _PERIOD.match(i)) and (d := period_day(
                int(m["year"]), int(m["n"]), self.period == "week"))}  # fmt: skip
        elif self.kind == "daily":
            found = {m["day"] for i in self.indices if (m := _DAILY.match(i))}
        else:
            found = {d for b in self.backing for d in _BACKING_DAY.findall(b)}
        return tuple(sorted(d for d in found if valid_day(d)))


def candidates(listing: Mapping[str, Any], skipped: list[str] | None = None) -> list[Candidate]:
    """Group a listing (``discover.indices`` data answer) into candidate families: data streams
    and aliases by name, other indices by the prefix before their ``YYYY.MM.DD``. A name no
    family could be made of is left out and, when ``skipped`` is given, added to it:
    Elasticsearch allows characters a family pattern does not (``@``, ``=``, a letter with an
    accent), and a ``YYYY.MM.DD`` may name no day (``2026.13.45``)."""

    def leave(name: str) -> None:
        if skipped is not None and name not in skipped:
            skipped.append(name)

    found: list[Candidate] = []
    in_stream: set[str] = set()
    for stream in listing.get("data_streams") or []:
        if not isinstance(stream, Mapping):
            continue
        name = stream.get("name")
        if not isinstance(name, str) or name.startswith("."):
            continue
        backing = tuple(b for b in stream.get("backing_indices") or [] if isinstance(b, str))
        in_stream.update(backing)
        if not family_pattern_ok(name):
            leave(name)
            continue
        field_ = stream.get("timestamp_field")
        found.append(
            Candidate(
                name,
                "stream",
                backing=tuple(b for b in backing if index_name_ok(b)),
                time_field=field_ if isinstance(field_, str) else None,
            )
        )
    daily: dict[str, list[str]] = {}
    periodic: dict[str, list[str]] = {}
    for index in listing.get("indices") or []:
        name = index.get("name") if isinstance(index, Mapping) else None
        if (
            not isinstance(name, str)
            or name.startswith(".")
            or name in in_stream
            or (isinstance(index, Mapping) and index.get("data_stream"))
        ):
            continue
        match = _DAILY.match(name)
        if match:
            if not valid_day(match["day"]) or not family_pattern_ok(match["prefix"] + "*"):
                leave(name)
                continue
            daily.setdefault(match["prefix"], []).append(name)
            continue
        period = _PERIOD.match(name)
        if period is None:
            continue
        if not 1 <= int(period["n"]) <= 53 or not family_pattern_ok(period["prefix"] + "*"):
            leave(name)
            continue
        periodic.setdefault(period["prefix"], []).append(name)
    for prefix, names in sorted(daily.items()):
        found.append(Candidate(prefix + "*", "daily", indices=tuple(sorted(names))))
    for prefix, names in sorted(periodic.items()):
        if prefix in daily:
            continue  # the same prefix by day: its daily indices stand for the family
        numbers = [int(m["n"]) for n in names if (m := _PERIOD.match(n))]
        weekly = any(n > 12 for n in numbers)
        if not weekly and any(n == 0 for n in numbers):
            continue
        found.append(Candidate(prefix + "*", "daily", indices=tuple(sorted(names)),
                               period="week" if weekly else "month"))  # fmt: skip
    for alias in listing.get("aliases") or []:
        name = alias.get("name") if isinstance(alias, Mapping) else None
        if isinstance(name, str) and not name.startswith("."):
            if family_pattern_ok(name):
                found.append(Candidate(name, "alias"))
            else:
                leave(name)
    return found


def name_score(candidate: Candidate) -> int:
    """The best name-hint points of a candidate over the roles (for choosing what to examine);
    a threat-intel name counts as a strong hint."""
    w = words(candidate.pattern)
    best = max((score(role, w, ()).name_points for role in NAME_HINTS), default=0)
    return max(best, NAME_ONLY_SCORE + 1 if w & TI_WORDS else 0)


def collapse_ti(found: Sequence[Candidate]) -> list[Candidate]:
    """The candidates to examine: of the data streams of one threat-intel integration only the
    first (one mapping speaks for the group, ``ti_group``)."""
    seen: set[str] = set()
    out = []
    for candidate in found:
        group = ti_group(candidate.pattern) if candidate.kind == "stream" else None
        if group is not None:
            if group in seen:
                continue
            seen.add(group)
        out.append(candidate)
    return out


@dataclass(frozen=True)
class Typed:
    """How a field is mapped: its type, whether it has a ``keyword`` sub-field, and the
    ``ignore_above`` of its keyword where the mapping gives one."""

    type: str
    keyword: bool = False
    ignore_above: int | None = None


TIME_CANDIDATES: Final = ("@timestamp", "event.created", "timestamp", "event.ingested")


def time_field(candidate: Candidate, mapped: Mapping[str, Typed]) -> tuple[str, str]:
    """(the event time field, why): the data stream's own, else the first date field among
    the usual ones, else ``@timestamp`` with the reason it is a guess."""
    if candidate.time_field:
        return candidate.time_field, "the data stream's timestamp field"
    for name in TIME_CANDIDATES:
        found = mapped.get(name)
        if found is not None and found.type in ("date", "date_nanos"):
            return name, f"{name} is mapped as {found.type}"
    return "@timestamp", "no date field among the usual ones was found: @timestamp is a guess"


# The field roles the evidence modules filter or aggregate on (a document returns the rest).
QUERIED: Final[Mapping[Role, frozenset[str]]] = {
    Role.PROXY: frozenset({"url", "action"}),
    Role.WEB: frozenset({"domain"}),
    Role.DNS: frozenset({"query_name", "query_type", "response_code"}),
    Role.AUTH: frozenset({"user_name", "action", "outcome", "user_agent"}),
}


def field_names(role: Role, mapped: Mapping[str, Typed]) -> tuple[dict[str, str], list[str]]:
    """(the ``fields`` entries that differ from the ECS names, notes) for a role: a queried text
    field with a keyword sub-field is queried as ``<name>.keyword``; one without cannot be
    aggregated."""
    entries: dict[str, str] = {}
    notes: list[str] = []
    for logical, ecs in FIELD_ROLES[role].items():
        typed = mapped.get(ecs)
        queried = logical in QUERIED.get(role, frozenset())
        if typed is None:
            notes.append(f"{ecs} ({logical}) is not mapped")
        elif typed.type == "text" and typed.keyword and queried:
            entries[logical] = f"{ecs}.keyword"
        elif typed.type == "text" and not typed.keyword and queried:
            notes.append(
                f"{ecs} ({logical}) is text with no keyword sub-field: it cannot be queried"
            )
    return entries, notes


@dataclass(frozen=True)
class Retention:
    """What the indices say about how long a family keeps its data."""

    days_kept: int | None = None  # newest day - oldest day + 1
    oldest: str | None = None
    newest: str | None = None
    delete_after: str | None = None  # the ILM delete phase's min_age, when readable
    note: str = field(default="")


def retention_of(candidate: Candidate, delete_after: str | None = None) -> Retention:
    days = candidate.days
    if not days:
        return Retention(delete_after=delete_after, note="no dated index to count days from")

    def parse(text: str) -> date:  # ``days`` holds days of the calendar only
        year, month, day = (int(p) for p in text.split("."))
        return date(year, month, day)

    first, last = parse(days[0]), parse(days[-1])
    return Retention(
        days_kept=(last - first).days + 1,
        oldest=days[0],
        newest=days[-1],
        delete_after=delete_after,
    )
