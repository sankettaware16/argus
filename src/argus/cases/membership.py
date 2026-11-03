"""Which investigations belong to a case (Q-C2, plan §5 and §7.1, DQ4): deterministic, never by
model similarity, stricter for content-delivery networks and clouds, and never silent when a
match is ambiguous.

An investigation **matches** a case through a key they share:

* an *actor*: one of the investigation's actors (a campus host, an account, an attacker's
  address: identity fields only, see :mod:`argus.cases.opener`) is an actor of the case;
* a *c2* or other *indicator*: an address or name the investigation involves is one the case
  holds as such.

A match is **strong** (the investigation may join) unless the shared value is **shared
infrastructure**: an address in a content-delivery or cloud network, a name on one of their
services, or a value that appears in very many unrelated investigations
(:data:`COMMON_INVESTIGATIONS`, the prevalence gate's own limit). Such a match is **weak**: the
address says nothing about who is behind it, so the investigation is only *suggested* to the
case, with the reason, and a person decides.

:func:`resolve` picks what to do with all the cases an investigation matches:

* one case holds the strongest strong match (``actor`` before ``c2`` before ``indicator``): join it;
* two or more cases hold equally strong matches: **ambiguous**, join none, suggest them all;
* only weak matches: join none, suggest them.

Whatever is not joined but matched is a *suggestion* (``tie``, ``shared`` or ``also``). The
result does not depend on the order the cases are given in.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.assets.assetmap import IPNetwork, parse_address
from argus.cases.model import Indicator
from argus.config.errors import ConfigError
from argus.config.sources import read_yaml_file

# The repo's config directory, wherever the command is run from (as the other config files).
SHARED_PATH = Path(__file__).resolve().parents[3] / "config" / "shared_infrastructure.yaml"
COMMON_INVESTIGATIONS = 50  # the prevalence gate's limit (batch1.INVESTIGATIONS_LIMIT)
LINK_ORDER = {"actor": 0, "c2": 1, "indicator": 2}
LinkName = Literal["actor", "c2", "indicator"]
SuggestionKind = Literal["shared", "tie", "also"]

SHARED_ADDRESS = "an address in a content-delivery or cloud network"
SHARED_NAME = "a name on a content-delivery or cloud service"
SHARED_COMMON = "a value that appears in very many unrelated investigations"
SHARED_NETWORK = "a large hosting or cloud provider"


class Facts(Protocol):
    """What an investigation shows: who acted, and everything it involves."""

    @property
    def actors(self) -> Sequence[Indicator]: ...

    @property
    def entities(self) -> Collection[tuple[str, str]]: ...


class CaseKeys(Protocol):
    """A case that can take a join: its reference, number, state and what it holds."""

    @property
    def ref(self) -> uuid.UUID | str: ...

    @property
    def number(self) -> int: ...

    @property
    def state(self) -> str: ...

    @property
    def indicators(self) -> Mapping[tuple[str, str], str]: ...


# --------------------------------------------------------------------------- shared infrastructure


class _SharedFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = Field(default=1, ge=1, le=1)
    networks: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    autonomous_systems: tuple[int, ...] = ()

    @field_validator("autonomous_systems")
    @classmethod
    def _systems(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        for item in value:
            if not 0 < item < 2**32:
                raise ValueError(f"{item!r} is not an autonomous system number")
        return value

    @field_validator("networks")
    @classmethod
    def _networks(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            ipaddress.ip_network(item, strict=True)
        return value

    @field_validator("domains")
    @classmethod
    def _domains(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for item in value:
            if not _is_domain_suffix(_name(item)):
                raise ValueError(f"{item!r} is not a domain name")
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> _SharedFile:
        if not self.networks and not self.domains and not self.autonomous_systems:
            raise ValueError(
                "it lists no network and no domain (and no autonomous system), so the rule"
                " would not apply"
            )
        return self


def _is_domain_suffix(value: str) -> bool:
    labels = value.split(".")
    return len(labels) >= 2 and all(
        label and len(label) <= 63 and label.replace("-", "").isalnum() for label in labels
    )


def _name(value: str) -> str:
    return value.strip().rstrip(".").lower()


@dataclass(frozen=True)
class Shared:
    """Shared infrastructure: network ranges, domain suffixes, the autonomous systems of the big
    hosting and cloud providers (many unrelated customers behind one number: D-174), and the
    values seen in very many investigations (``common``, found in the database, see
    :func:`common_values`)."""

    networks: tuple[IPNetwork, ...] = ()
    domains: frozenset[str] = frozenset()
    common: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    autonomous_systems: frozenset[int] = frozenset()

    def reason(self, kind: str, value: str) -> str | None:
        """Why ``value`` says nothing about who is behind it, or None when it does."""
        if (kind, value) in self.common:
            return SHARED_COMMON
        if kind == "ip":
            address = parse_address(value)
            if address is not None and any(
                address.version == n.version and address in n for n in self.networks
            ):
                return SHARED_ADDRESS
        elif kind == "domain":
            name = _name(value)
            if any(name == d or name.endswith("." + d) for d in self.domains):
                return SHARED_NAME
        elif kind == "as" and value.isdigit() and int(value) in self.autonomous_systems:
            return SHARED_NETWORK
        return None

    def with_common(self, common: Iterable[tuple[str, str]]) -> Shared:
        return Shared(self.networks, self.domains, frozenset(common), self.autonomous_systems)


NO_SHARED = Shared()


def load_shared(path: Path | None = None) -> Shared:
    """``config/shared_infrastructure.yaml`` (of the repo, not of the working directory). A
    missing, invalid or empty file is an error: without the list the CDN and cloud rule would
    silently not apply."""
    path = SHARED_PATH if path is None else path
    if not path.exists():
        raise ConfigError(f"{path} is missing: it lists the shared addresses cases never join by")
    data, _ = read_yaml_file(path)
    try:
        parsed = _SharedFile.model_validate(data)
    except (ValidationError, ValueError) as exc:
        raise ConfigError(f"invalid shared infrastructure file {path}: {exc}") from None
    return Shared(
        tuple(ipaddress.ip_network(n, strict=True) for n in parsed.networks),
        frozenset(_name(d) for d in parsed.domains),
        autonomous_systems=frozenset(parsed.autonomous_systems),
    )


async def common_values(
    conn: AsyncConnection, keys: Iterable[tuple[str, str]], since: Any
) -> frozenset[tuple[str, str]]:
    """Which of ``keys`` (kind, value) appear in :data:`COMMON_INVESTIGATIONS` or more
    investigations whose activity reaches into ``since`` (the prevalence gate's own measure)."""
    wanted = sorted(set(keys))
    if not wanted:
        return frozenset()
    rows = await conn.execute(
        text(
            "SELECT e.kind, e.value FROM investigation_entities e"
            " JOIN investigations i ON i.id = e.investigation_id"
            " WHERE (e.kind, e.value) IN (SELECT k, v FROM unnest(CAST(:kinds AS text[]),"
            " CAST(:values AS text[])) AS u(k, v)) AND i.last_event_at >= :since"
            " GROUP BY e.kind, e.value HAVING count(DISTINCT e.investigation_id) >= :limit"
        ),
        {
            "kinds": [k for k, _ in wanted],
            "values": [v for _, v in wanted],
            "since": since,
            "limit": COMMON_INVESTIGATIONS,
        },
    )
    return frozenset((str(k), str(v)) for k, v in rows)


# --------------------------------------------------------------------------- matching


@dataclass(frozen=True)
class Match:
    """One key an investigation and a case share. ``shared``: why the key is weak, if it is."""

    link: LinkName
    kind: str
    value: str
    shared: str | None = None

    @property
    def strong(self) -> bool:
        return self.shared is None

    @property
    def rank(self) -> tuple[bool, int, str, str]:
        """Strong before weak, then actor before c2 before indicator, then by value."""
        return (not self.strong, LINK_ORDER[self.link], self.kind, self.value)

    def words(self) -> str:
        return f"the same {self.link} {self.value}" + (
            f" ({self.shared})" if self.shared is not None else ""
        )


def keys(facts: Facts, indicators: Mapping[tuple[str, str], str], shared: Shared) -> list[Match]:
    """Every key ``facts`` shares with a case's ``indicators`` ((kind, value): role)."""
    found: dict[tuple[str, str, str], Match] = {}
    for actor in facts.actors:
        if indicators.get((actor.kind, actor.value)) == "actor":
            found[("actor", actor.kind, actor.value)] = Match(
                "actor", actor.kind, actor.value, shared.reason(actor.kind, actor.value)
            )
    for kind, value in sorted(facts.entities):
        role = indicators.get((kind, value))
        if role in ("c2", "indicator"):
            assert role is not None
            found[(role, kind, value)] = Match(
                role,  # type: ignore[arg-type]
                kind,
                value,
                shared.reason(kind, value),
            )
    return sorted(found.values(), key=lambda m: m.rank)


@dataclass(frozen=True)
class Pick:
    """A case and the key it is matched by (its best one)."""

    case: CaseKeys
    match: Match


@dataclass(frozen=True)
class Suggested:
    """A case an investigation matches but does not join, and why."""

    case: CaseKeys
    match: Match
    kind: SuggestionKind

    def words(self) -> str:
        why = {
            "shared": "shared infrastructure, not enough on its own",
            "tie": "matches other cases just as well",
            "also": "a weaker match than the case it joins",
        }[self.kind]
        return f"case {self.case.number}: {self.match.words()}: {why}"


@dataclass(frozen=True)
class Resolution:
    join: Pick | None
    suggest: tuple[Suggested, ...] = ()

    @property
    def ambiguous(self) -> bool:
        return self.join is None and any(s.kind == "tie" for s in self.suggest)


def resolve(facts: Facts, cases: Iterable[CaseKeys], shared: Shared) -> Resolution:
    """The case ``facts`` joins, if exactly one holds the strongest strong match, and the cases
    it is suggested to instead. Closed cases are never joined: callers pass the cases that can
    take a join."""
    picks = []
    for case in sorted(cases, key=lambda c: c.number):
        if case.state == "closed":
            continue
        matches = keys(facts, case.indicators, shared)
        if matches:
            picks.append(Pick(case, matches[0]))
    strong = [p for p in picks if p.match.strong]
    weak = [Suggested(p.case, p.match, "shared") for p in picks if not p.match.strong]
    if not strong:
        return Resolution(None, tuple(weak))
    best = min(LINK_ORDER[p.match.link] for p in strong)
    tops = [p for p in strong if LINK_ORDER[p.match.link] == best]
    rest = [p for p in strong if LINK_ORDER[p.match.link] != best]
    if len(tops) == 1:
        also = tuple(Suggested(p.case, p.match, "also") for p in rest)
        return Resolution(tops[0], (*also, *weak))
    tied = tuple(Suggested(p.case, p.match, "tie") for p in tops)
    also = tuple(Suggested(p.case, p.match, "also") for p in rest)
    return Resolution(None, (*tied, *also, *weak))
