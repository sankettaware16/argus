"""The campus asset map: validated loading and longest-prefix matching.

The file (``assets.map_path``, by default ``data/assets/asset_map.yaml``; imported by the operator
with ``argus assets import``, D-032)::

    defaults: {site.organization: ...}        # applied to every entry
    networks:
      - name: ...
        range: 10.1.2.0/24                    # or ranges: [..., ...]; a bare address is a /32
        fields: {site.zone: ..., site.building: ...}

Names and ranges identify campus networks, so no error message ever contains a value from the
file: problems are reported by entry number and key only.

Matching returns the most specific network containing an address. The map nests (a /16 holding
/24s holding /32s) and can list one network twice with different labels; then the match carries
every entry for it, in file order, and says it is ambiguous rather than picking one.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import yaml
from yaml.nodes import MappingNode, Node

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

MAX_MAP_BYTES = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_RANGES_PER_ENTRY = 256
MAX_TEXT = 256
MAX_YAML_DEPTH = 8
_FIELD_NAME = re.compile(r"site\.[a-z][a-z0-9_]{0,63}")
_ENTRY_KEYS = frozenset({"name", "range", "ranges", "fields"})


class AssetMapError(ValueError):
    """The asset map is invalid. The message never contains a value from the file."""


@dataclass(frozen=True, slots=True)
class AssetEntry:
    position: int  # 1-based entry number in the file
    name: str
    fields: Mapping[str, str]  # defaults merged in, the entry's own fields win
    networks: tuple[IPNetwork, ...]


@dataclass(frozen=True, slots=True)
class AssetMatch:
    network: IPNetwork
    entries: tuple[AssetEntry, ...]  # every entry listing this network, in file order

    @property
    def ambiguous(self) -> bool:
        return len(self.entries) > 1


class _Loader(yaml.SafeLoader):
    """SafeLoader without aliases, anchors or merge keys, with unique keys and a depth cap."""

    def __init__(self, stream: str) -> None:
        self._depth = 0
        super().__init__(stream)

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
            raise yaml.YAMLError(f"anchors and aliases are not allowed (line {_line(event)})")
        self._depth += 1
        try:
            if self._depth > MAX_YAML_DEPTH:
                raise yaml.YAMLError(f"nesting is too deep (line {_line(event)})")
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.YAMLError(f"merge keys are not allowed (line {_line(key_node)})")
            if key_node.value in seen:
                raise yaml.YAMLError(f"duplicate key (line {_line(key_node)})")
            seen.add(key_node.value)
        return super().construct_mapping(node, deep=deep)


def _line(item: Any) -> int:
    mark = getattr(item, "start_mark", None)
    return mark.line + 1 if mark is not None else 0


def _text(value: Any, where: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise AssetMapError(f"{where} must be text")
    text = str(value).strip()
    if not text or len(text) > MAX_TEXT or not text.isprintable():
        raise AssetMapError(f"{where} must be 1-{MAX_TEXT} printable characters")
    return text


def _fields(value: Any, where: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise AssetMapError(f"{where} must be a mapping of site.* fields")
    out: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not _FIELD_NAME.fullmatch(key):
            raise AssetMapError(f"{where}: field names must look like site.<name>")
        out[key] = _text(item, f"{where} {key}")
    return out


def _network(value: Any, where: str) -> IPNetwork:
    if not isinstance(value, str):
        raise AssetMapError(f"{where}: a range must be text")
    try:
        network = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError:
        raise AssetMapError(
            f"{where}: a range is not an IP network (or has host bits set)"
        ) from None
    if isinstance(network, ipaddress.IPv6Network) and network.network_address.ipv4_mapped:
        raise AssetMapError(f"{where}: write IPv4 ranges as IPv4, not IPv4-mapped IPv6")
    return network


def parse_asset_map(raw: bytes) -> AssetMap:
    """Validate the file's bytes and build the map. Raises :class:`AssetMapError`."""
    if len(raw) > MAX_MAP_BYTES:
        raise AssetMapError(f"the asset map is larger than {MAX_MAP_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AssetMapError("the asset map is not UTF-8 text") from None
    loader: _Loader | None = None
    try:
        loader = _Loader(text)  # the reader checks the characters here already
        data = loader.get_single_data()
    except yaml.YAMLError as exc:
        # PyYAML's own messages can quote the text; keep only our messages and positions.
        mark = getattr(exc, "problem_mark", None)
        detail = str(exc) if type(exc) is yaml.YAMLError else "invalid YAML"
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise AssetMapError(f"the asset map is not valid YAML: {detail}{where}") from None
    finally:
        if loader is not None:
            loader.dispose()
    if not isinstance(data, dict) or set(data) - {"defaults", "networks"}:
        raise AssetMapError("the asset map must be a mapping with 'defaults' and 'networks' only")
    defaults = _fields(data.get("defaults"), "defaults")
    networks = data.get("networks")
    if not isinstance(networks, list) or not networks:
        raise AssetMapError("'networks' must be a non-empty list")
    if len(networks) > MAX_ENTRIES:
        raise AssetMapError(f"more than {MAX_ENTRIES} entries")
    entries: list[AssetEntry] = []
    for position, item in enumerate(networks, start=1):
        where = f"entry #{position}"
        if not isinstance(item, dict):
            raise AssetMapError(f"{where} must be a mapping")
        unknown = set(item) - _ENTRY_KEYS
        if unknown:
            raise AssetMapError(
                f"{where}: unknown keys (allowed: {', '.join(sorted(_ENTRY_KEYS))})"
            )
        ranges: list[Any] = []
        if "range" in item:
            ranges.append(item["range"])
        if "ranges" in item:
            if not isinstance(item["ranges"], list):
                raise AssetMapError(f"{where}: 'ranges' must be a list")
            ranges.extend(item["ranges"])
        if not ranges:
            raise AssetMapError(f"{where} has no range")
        if len(ranges) > MAX_RANGES_PER_ENTRY:
            raise AssetMapError(f"{where} has more than {MAX_RANGES_PER_ENTRY} ranges")
        nets = tuple(dict.fromkeys(_network(r, where) for r in ranges))
        own = _fields(item.get("fields"), where)
        entries.append(
            AssetEntry(
                position=position,
                name=_text(item.get("name"), f"{where} name"),
                fields={**defaults, **own},
                networks=nets,
            )
        )
    return AssetMap(entries, hashlib.sha256(raw).hexdigest())


class AssetMap:
    """Longest-prefix match over the map's networks: one dict lookup per prefix length used."""

    def __init__(self, entries: list[AssetEntry], sha256: str) -> None:
        self.entries = tuple(entries)
        self.sha256 = sha256
        by_network: dict[IPNetwork, list[AssetEntry]] = {}
        for entry in self.entries:
            for network in entry.networks:
                by_network.setdefault(network, []).append(entry)
        self.network_count = len(by_network)
        self.duplicate_networks = sum(1 for listed in by_network.values() if len(listed) > 1)
        # version -> [(prefix length, mask, {network int: match})], longest prefix first
        tables: dict[int, dict[int, dict[int, AssetMatch]]] = {4: {}, 6: {}}
        for network, listed in by_network.items():
            level = tables[network.version].setdefault(network.prefixlen, {})
            level[int(network.network_address)] = AssetMatch(network, tuple(listed))
        self._levels: dict[int, tuple[tuple[int, dict[int, AssetMatch]], ...]] = {}
        for version, levels in tables.items():
            bits = 32 if version == 4 else 128
            full = (1 << bits) - 1
            self._levels[version] = tuple(
                ((full >> (bits - length)) << (bits - length), levels[length])
                for length in sorted(levels, reverse=True)
            )

    def match(self, address: IPAddress | str) -> AssetMatch | None:
        """The most specific network holding ``address`` (IPv4-mapped IPv6 is unwrapped)."""
        ip = parse_address(address)
        if ip is None:
            return None
        value = int(ip)
        for mask, level in self._levels[ip.version]:
            found = level.get(value & mask)
            if found is not None:
                return found
        return None


def parse_address(address: IPAddress | str | Any) -> IPAddress | None:
    if isinstance(address, str):
        if len(address) > 64:
            return None
        try:
            address = ipaddress.ip_address(address.strip())
        except ValueError:
            return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return address.ipv4_mapped
        if address.scope_id is not None:  # fe80::1%eth0: the zone is not part of the address
            return ipaddress.IPv6Address(int(address))
        return address
    if isinstance(address, ipaddress.IPv4Address):
        return address
    return None
