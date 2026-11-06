"""Made-up engine incidents for the incident-title tests: devices in private campus ranges, outside
things in TEST-NET (RFC 5737) and ``example`` names, sites under ``example.edu``. Nothing here is a
real alert, address or site."""

from __future__ import annotations

import itertools
import uuid
from collections.abc import Iterable, Mapping, Sequence

from argus.assets import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.risk.exposure import PairFacts
from argus.risk.observe import ObjectRef
from argus.risk.titles import GroupFacts, IncidentFacts, LinkFacts, place_of

ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - {name: H4, range: 10.20.4.0/24,
     fields: {site.type: switch, site.zone: hostel, site.building: Hostel 4}}
  - {name: H9, range: 10.20.9.0/24,
     fields: {site.type: gateway, site.zone: hostel, site.building: Hostel 9}}
  - {name: CSE, range: 10.30.6.0/24,
     fields: {site.type: lab, site.zone: department, site.department: Dept North}}
  - {name: Misc, range: 10.40.0.0/16, fields: {site.type: switch}}
"""
)
CLASSIFIER = IpClassifier(ASSETS)


def dev(address: str, day: str | None = None) -> ObjectRef:
    return ObjectRef("device", f"ip:{address}" + (f"@{day}" if day else ""))


def host(name: str) -> ObjectRef:
    return ObjectRef("device", f"host:{name}")


def site(name: str) -> ObjectRef:
    return ObjectRef("site", f"domain:{name}")


_COUNT = iter(range(1, 1 << 30))


def grp(
    objects: Mapping[ObjectRef, Iterable[str]] | Iterable[ObjectRef], *,
    threats: Iterable[str] = (), actors: Iterable[str] = (), paths: Iterable[str] = (),
    rule: str = "Proxy rule", answered: Iterable[tuple[str, str]] = (),
    checks: Iterable[str] = (),
) -> GroupFacts:  # fmt: skip
    """An alert group observed on ``objects`` (ref -> its evidence kinds), naming the outside
    ``threats`` (an address or a domain name), outside ``actors`` and attacked ``paths``."""
    seen = objects if isinstance(objects, Mapping) else dict.fromkeys(objects, ())
    entities = [("ip" if t[0].isdigit() else "domain", t, "threat") for t in threats]
    entities += [("ip", a, "actor") for a in actors]
    entities += [("url_pattern", p, "threat") for p in paths]
    return GroupFacts(
        uuid.UUID(int=next(_COUNT)), rule, {r: frozenset(k) for r, k in seen.items()},
        tuple(entities), tuple(answered), frozenset(checks),
    )  # fmt: skip


def chain(refs: Sequence[ObjectRef], via: str, value: str) -> list[LinkFacts]:
    return [LinkFacts(a, b, via, value) for a, b in itertools.pairwise(refs)]


def incident(
    groups: Iterable[GroupFacts], *, links: Iterable[LinkFacts] = (),
    flags: Mapping[str, str] | None = None, vt: Mapping[str, int] | None = None,
    labels: Mapping[str, Sequence[str]] | None = None, others: Mapping[str, int] | None = None,
    follows: int = 0, exposure: Iterable[PairFacts] = (),
    catch_all: Iterable[tuple[str, str]] = (), objects: Iterable[ObjectRef] = (),
) -> IncidentFacts:  # fmt: skip
    """An incident holding every object its groups were observed on (and ``objects``), with the
    asset map's places of its addresses."""
    held = list(groups)
    refs = dict.fromkeys([*(r for g in held for r in g.objects), *objects])
    places = {
        r.key[3:].split("@", 1)[0]: place_of(r.key[3:].split("@", 1)[0], CLASSIFIER)
        for r in refs if r.kind == "device" and r.key.startswith("ip:")
    }  # fmt: skip
    return IncidentFacts(
        objects={r: ("affected" if r.kind == "site" else "actor") for r in refs},
        groups=tuple(held), links=tuple(links), flags=dict(flags or {}), vt=dict(vt or {}),
        labels={k: tuple(v) for k, v in (labels or {}).items()}, others=dict(others or {}),
        follows=follows, places=places, exposure=tuple(exposure),
        catch_all=frozenset(catch_all),
    )  # fmt: skip
