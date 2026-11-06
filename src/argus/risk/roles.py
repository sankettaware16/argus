"""Entity roles (E0): who acted, what was at risk on campus, and what outside thing was involved,
from ECS field namespaces and address classes only (never a rule's name).

- **actor**: the side that acted (``source.*``, ``client.*``, ``user.*``, a campus sender);
- **target**: a campus thing acted on (an internal destination address, a campus domain or
  recipient, the host of an inbound event);
- **threat**: an outside thing involved (a public destination, an outside domain or sender, a
  URL pattern, a file hash). Threat objects never accrue incident risk; later they link campus
  objects (E2);
- **other**: anything else (special addresses, an outbound event's own host).

The fields are the normalizer's seven plus the ones the plan adds: ``client.ip``,
``source.user.name``, ``user.email``, ``email.*`` addresses, ``url.path`` (as a pattern: its first
two segments and its extension) and file hashes."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from argus.assets.classify import IpClass, IpClassifier

Kind = Literal["ip", "domain", "host", "user", "email", "url_pattern", "hash"]
Role = Literal["actor", "target", "threat", "other"]
Direction = Literal["outbound", "inbound", "lateral", "unknown"]
KINDS: tuple[Kind, ...] = ("ip", "domain", "host", "user", "email", "url_pattern", "hash")
ROLES: tuple[Role, ...] = ("actor", "target", "threat", "other")
DIRECTIONS: tuple[Direction, ...] = ("outbound", "inbound", "lateral", "unknown")

FIELDS: tuple[tuple[Kind, str], ...] = (
    ("ip", "source.ip"),
    ("ip", "client.ip"),
    ("ip", "destination.ip"),
    ("ip", "server.ip"),
    ("domain", "url.domain"),
    ("domain", "destination.domain"),
    ("domain", "server.domain"),
    ("domain", "dns.question.name"),
    ("host", "host.name"),
    ("user", "user.name"),
    ("user", "source.user.name"),
    ("user", "destination.user.name"),
    ("email", "user.email"),
    ("email", "email.from.address"),
    ("email", "email.sender.address"),
    ("email", "email.to.address"),
    ("url_pattern", "url.path"),
    ("hash", "file.hash.sha256"),
    ("hash", "file.hash.sha1"),
    ("hash", "file.hash.md5"),
)
FIELD_KIND = {field: kind for kind, field in FIELDS}
ACTOR_NAMESPACES = frozenset({"source", "client", "user"})  # who acted (ECS)
CAMPUS_CLASSES = frozenset({IpClass.ASSET, IpClass.CAMPUS, IpClass.INTERNAL})
MAX_VALUES = 16  # per field, as the normalizer
MAX_VALUE = 512
# Values many unrelated actors share; never an account (compared in lower case).
GENERIC_ACCOUNTS = frozenset(
    {
        "-", "admin", "administrator", "anonymous", "default", "ftp", "guest", "localhost",
        "n/a", "none", "nobody", "null", "oracle", "pi", "postgres", "root", "sa", "system",
        "test", "ubuntu", "unknown", "user", "www-data", "mailer-daemon", "postmaster",
        "noreply", "no-reply",
    }
)  # fmt: skip
_HASH = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$")
_EXTENSION = re.compile(r"\.([a-z0-9]{1,8})$")
_DIGITS = re.compile(r"[0-9]{4,}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True, order=True)
class RoleEntity:
    kind: Kind
    value: str
    role: Role
    field: str


def url_pattern(path: str) -> str | None:
    """A URL path reduced to a pattern: lower case, no query, its first two segments, ``*`` when
    there were more, and the last segment's extension (``/wp-content/plugins/*.php``). Long
    numbers become ``{n}``. None for an empty value."""
    clean = path.split("?", 1)[0].split("#", 1)[0].strip().lower()
    if not clean:
        return None
    parts = [p for p in (_CONTROL.sub("", seg).strip() for seg in clean.split("/")) if p]
    if not parts:
        return "/"
    head = "/" + "/".join(_DIGITS.sub("{n}", p) for p in parts[:2])
    if len(parts) > 2:
        found = _EXTENSION.search(parts[-1])
        head += "/*" + ("." + found.group(1) if found else "")
    return head[:200]


def campus_domain(value: str, domains: Iterable[str]) -> bool:
    name = value.strip().rstrip(".").lower()
    return any(name == d or name.endswith("." + d) for d in domains)


def account(value: str) -> str | None:
    """An account name as an object key (lower case), or None for a generic or unusable one."""
    name = value.strip().lower()
    if not name or len(name) > 256 or name in GENERIC_ACCOUNTS:
        return None
    local = name.split("@", 1)[0]
    return None if local in GENERIC_ACCOUNTS else name


def _values(raw: Sequence[object]) -> list[str]:
    out: list[str] = []
    for value in raw:
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            continue
        text = str(value).strip()
        if text and len(text) <= MAX_VALUE and text not in out:
            out.append(text)
        if len(out) >= MAX_VALUES:
            break
    return out


def direction(actor_classes: Iterable[IpClass], target_classes: Iterable[IpClass]) -> Direction:
    """Outbound: a campus actor and no campus target; lateral: campus to campus; inbound: an
    outside actor; unknown: no actor address."""
    actors = set(actor_classes)
    if not actors & (CAMPUS_CLASSES | {IpClass.PUBLIC}):
        return "unknown"
    if actors & CAMPUS_CLASSES:
        return "lateral" if set(target_classes) & CAMPUS_CLASSES else "outbound"
    return "inbound"


def roles(
    fields: Mapping[str, Sequence[object]], classifier: IpClassifier,
    campus_domains: Sequence[str],
) -> tuple[Direction, tuple[RoleEntity, ...]]:  # fmt: skip
    """The group's direction and its entities with their roles. ``fields``: each ECS field's
    values across the group's alerts (actor key values included)."""
    out: set[RoleEntity] = set()
    actor_classes: list[IpClass] = []
    target_classes: list[IpClass] = []
    for kind, field in FIELDS:
        if kind != "ip":
            continue
        actor_side = field.split(".", 1)[0] in ACTOR_NAMESPACES
        for value in _values(fields.get(field, ())):
            found = classifier.classify(value)
            if found.address is None:
                continue
            (actor_classes if actor_side else target_classes).append(found.ip_class)
    way = direction(actor_classes, target_classes)
    for kind, field in FIELDS:
        namespace = field.split(".", 1)[0]
        for value in _values(fields.get(field, ())):
            entity = _entity(kind, field, namespace, value, way, classifier, campus_domains)
            if entity is not None:
                out.add(entity)
    return way, tuple(sorted(out))


def _entity(
    kind: Kind, field: str, namespace: str, value: str, way: Direction,
    classifier: IpClassifier, campus_domains: Sequence[str],
) -> RoleEntity | None:  # fmt: skip
    role: Role
    if kind == "ip":
        found = classifier.classify(value)
        if found.address is None:
            return None
        value = found.address
        if namespace in ACTOR_NAMESPACES:
            role = "actor" if found.ip_class in CAMPUS_CLASSES | {IpClass.PUBLIC} else "other"
        elif found.ip_class in CAMPUS_CLASSES:
            role = "target"
        elif found.ip_class is IpClass.PUBLIC:
            role = "threat"
        else:
            role = "other"
    elif kind == "domain":
        value = value.strip().rstrip(".").strip().lower()
        if not value:  # the root ('.') or dots only: no name
            return None
        role = "target" if campus_domain(value, campus_domains) else "threat"
    elif kind == "host":
        value = value.strip().lower()
        # ECS host: where the event happened; the campus server of an inbound event (an
        # outbound event's host is often the device that logged it)
        role = "target" if way == "inbound" else "other"
    elif kind == "user":
        name = account(value)
        if name is None:
            return None
        value = name
        # an inbound event's account is the one tried (brute force), not who acted
        role = "target" if field.startswith("destination.") or way == "inbound" else "actor"
    elif kind == "email":
        name = account(value)
        if name is None or "@" not in name:
            return None
        value = name
        domain = name.rsplit("@", 1)[1]
        campus = campus_domain(domain, campus_domains)
        if field == "email.to.address":
            role = "target" if campus else "threat"
        elif field == "user.email":
            role = "actor"
        else:
            role = "actor" if campus else "threat"
    elif kind == "url_pattern":
        pattern = url_pattern(value)
        if pattern is None:
            return None
        value, role = pattern, "threat"
    else:
        value = value.strip().lower()
        if not _HASH.fullmatch(value):
            return None
        role = "threat"
    return RoleEntity(kind, value[:MAX_VALUE], role, field)
