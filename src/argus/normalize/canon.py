"""Canonical field values for group keys, entities and fingerprints (plan §7.1).

IPs go through :mod:`ipaddress` (IPv4-mapped IPv6 unwrapped), domains are lowercased, IDNA
encoded and lose a trailing dot, ports become integers, arrays are sorted and made unique, and
empty becomes null. A value that is not what its field promises (``source.ip: "n/a"``) is kept
in a stable text form and reported as a field issue, so it still groups deterministically.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import unicodedata
from collections.abc import Iterable
from typing import Any, Literal

from argus.normalize.fields import field_kind_name
from argus.normalize.model import FieldIssueKind, KeyValue, Scalar

MAX_KEY_STRING = 512  # longer strings are replaced by their digest
MAX_KEY_VALUES = 64  # distinct values kept per key field
_MAX_IP_TEXT = 64
_PORT = re.compile(r"[0-9]{1,5}")
_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")
_DOMAIN_FIELDS = frozenset({"dns.question.name"})
_DOMAIN_LEAVES = frozenset({"domain", "registered_domain", "subdomain"})

FieldKind = Literal["ip", "port", "domain", "other"]
Canon = tuple[Scalar | None, FieldIssueKind | None]


def canonical_json(value: Any) -> str:
    """Stable text of a JSON value: sorted keys, no spaces, ASCII only (lone surrogates become
    escapes instead of failing), and ``NaN``/``Infinity`` kept distinct from the strings."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(*parts: Any) -> str:
    return hashlib.sha256(canonical_json(list(parts)).encode("ascii")).hexdigest()


def field_kind(field: str) -> FieldKind:
    name = field_kind_name(field)
    leaf = name.rsplit(".", 1)[-1]
    if leaf == "ip":
        return "ip"
    if leaf == "port":
        return "port"
    if leaf in _DOMAIN_LEAVES or name in _DOMAIN_FIELDS:
        return "domain"
    return "other"


def _long(text: str) -> Canon:
    return "sha256:" + digest(text), FieldIssueKind.VALUE_TOO_LONG


def _text(text: str) -> Canon:
    """A string as a key value: too long or unstorable ones become their digest."""
    if len(text) > MAX_KEY_STRING:
        return _long(text)
    if _UNSTORABLE.search(text):
        return "sha256:" + digest(text), FieldIssueKind.UNSTORABLE_TEXT
    return text, None


def canon_scalar(value: Any) -> Canon:
    if value is None or isinstance(value, bool | int):
        return value, None
    if isinstance(value, str):
        return _text(value) if value else (None, None)
    if isinstance(value, float):
        return (value, None) if math.isfinite(value) else (repr(value), FieldIssueKind.NOT_SCALAR)
    # An object (the path ends at a JSON object) or anything else: a stable digest.
    return "json:" + digest(value), FieldIssueKind.NOT_SCALAR


def canon_ip(value: Any) -> Canon:
    if not isinstance(value, str):
        return _invalid(value, FieldIssueKind.INVALID_IP)
    text = value.strip()
    if not text:
        return None, None
    if len(text) <= _MAX_IP_TEXT:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            pass
        else:
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
                return str(address.ipv4_mapped), None
            return str(address), None
    return _invalid(value, FieldIssueKind.INVALID_IP)


def canon_port(value: Any) -> Canon:
    if isinstance(value, bool):
        return _invalid(value, FieldIssueKind.INVALID_PORT)
    number: int | None = None
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None
        if _PORT.fullmatch(text):
            number = int(text)
    if number is not None and 0 <= number <= 65535:
        return number, None
    return _invalid(value, FieldIssueKind.INVALID_PORT)


def canon_domain(value: Any) -> Canon:
    if not isinstance(value, str):
        return _invalid(value, FieldIssueKind.INVALID_DOMAIN)
    text = value.strip().rstrip(".")
    if not text:
        return None, None
    if len(text) > MAX_KEY_STRING or _UNSTORABLE.search(text):
        return _text(text)
    if text.isascii():
        return text.lower(), None
    labels: list[str] = []
    for label in text.split("."):
        if label.isascii():
            labels.append(label.lower())
            continue
        try:
            labels.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            return unicodedata.normalize("NFC", text).lower(), FieldIssueKind.INVALID_DOMAIN
    return ".".join(labels), None


def _invalid(value: Any, issue: FieldIssueKind) -> Canon:
    canonical, own_issue = canon_scalar(value)
    if canonical is None:
        return None, None
    return canonical, own_issue or issue


_CANON = {"ip": canon_ip, "port": canon_port, "domain": canon_domain, "other": canon_scalar}


def canon_values(field: str, raw: Iterable[Any]) -> tuple[KeyValue, tuple[FieldIssueKind, ...]]:
    """The canonical value of a field's values: null, one scalar, or a sorted unique tuple."""
    canon = _CANON[field_kind(field)]
    issues: set[FieldIssueKind] = set()
    seen: dict[str, Scalar] = {}
    for item in raw:
        value, issue = canon(item)
        if issue is not None:
            issues.add(issue)
        if value is not None:
            seen.setdefault(canonical_json(value), value)
    ordered = [seen[key] for key in sorted(seen)]
    if len(ordered) > MAX_KEY_VALUES:
        ordered = ordered[:MAX_KEY_VALUES]
        issues.add(FieldIssueKind.TOO_MANY_VALUES)
    result: KeyValue = None if not ordered else ordered[0] if len(ordered) == 1 else tuple(ordered)
    return result, tuple(sorted(issues))
