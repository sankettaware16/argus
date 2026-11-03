"""What kind of address an IP is, for context and for the by-host views.

Order: the asset map (most specific network), the campus public prefixes, private space
(RFC 1918, IPv6 ULA), special-purpose space (loopback, link-local, multicast, reserved,
documentation, CGNAT, ...), and otherwise public. Without an imported asset map the lookup is
``no_map``: "not in the asset map" is then unknown, never a negative (D-023).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from argus.assets.assetmap import AssetMap, AssetMatch, IPNetwork, parse_address

_INTERNAL = tuple(
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
)


class IpClass(StrEnum):
    ASSET = "asset"  # inside a network of the asset map
    CAMPUS = "campus"  # a campus public prefix, not in the asset map
    INTERNAL = "internal"  # private space, not in the asset map
    PUBLIC = "public"
    SPECIAL = "special"  # loopback, link-local, multicast, reserved, documentation, shared, ...
    INVALID = "invalid"  # not an IP address


class AssetLookup(StrEnum):
    MATCHED = "matched"
    NOT_FOUND = "not_found"
    NO_MAP = "no_map"  # no asset map imported: unknown
    NOT_APPLICABLE = "not_applicable"  # not an IP address


@dataclass(frozen=True, slots=True)
class IpClassification:
    address: str | None  # canonical text; None if not an address
    ip_class: IpClass
    lookup: AssetLookup
    asset: AssetMatch | None


class IpClassifier:
    def __init__(self, assets: AssetMap | None, campus_prefixes: Sequence[IPNetwork] = ()) -> None:
        self.assets = assets
        self.campus_prefixes = tuple(campus_prefixes)

    def classify(self, value: Any) -> IpClassification:
        ip = parse_address(value)
        if ip is None:
            return IpClassification(None, IpClass.INVALID, AssetLookup.NOT_APPLICABLE, None)
        if self.assets is None:
            lookup, match = AssetLookup.NO_MAP, None
        else:
            match = self.assets.match(ip)
            lookup = AssetLookup.MATCHED if match is not None else AssetLookup.NOT_FOUND
        if match is not None:
            ip_class = IpClass.ASSET
        elif any(ip.version == n.version and ip in n for n in self.campus_prefixes):
            ip_class = IpClass.CAMPUS
        elif any(ip.version == n.version and ip in n for n in _INTERNAL):
            ip_class = IpClass.INTERNAL
        elif (
            ip.is_global
            and not ip.is_multicast
            and not ip.is_reserved
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_unspecified
        ):
            ip_class = IpClass.PUBLIC
        else:
            ip_class = IpClass.SPECIAL
        return IpClassification(str(ip), ip_class, lookup, match)
