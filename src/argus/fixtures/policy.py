"""Fixture sanitization policy (``config/fixtures.yaml``)."""

from __future__ import annotations

import contextlib
import hashlib
import re
import unicodedata
from collections.abc import Hashable
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode, Node

from argus.fixtures.ipmap import allocate_sites
from argus.fixtures.tokens import normalize_domain

FIELD_KINDS = ("host", "user", "email", "place", "org", "domain", "id")

# Account, machine and Windows realm names that identify no one: kept verbatim, never denylisted.
DEFAULT_KEEP_NAMES = (
    "admin",
    "administrator",
    "anonymous",
    "apache",
    "builtin",
    "centos",
    "daemon",
    "debian",
    "default",
    "ec2-user",
    "font driver host",
    "guest",
    "local service",
    "localhost",
    "mysql",
    "network service",
    "nginx",
    "nobody",
    "nt authority",
    "nt service",
    "postgres",
    "public",
    "root",
    "squid",
    "system",
    "test",
    "ubuntu",
    "user",
    "window manager",
    "workgroup",
    "www-data",
)


class FixturePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: int = 1
    site_prefixes: tuple[str, ...] = ()
    campus_domains: tuple[str, ...] = ()
    campus_replacement: str = "univ.example"
    keep_domains: tuple[str, ...] = ()
    keep_names: tuple[str, ...] = DEFAULT_KEEP_NAMES
    literals: dict[str, str] = Field(default_factory=dict)
    # Paths relative to a document's _source; an entry with "*" is a pattern (fnmatch, "*" also
    # crosses dots), tried after every exact path, in policy order.
    fields: dict[str, tuple[str, ...]] = Field(default_factory=dict)
    denylist_extra: tuple[str, ...] = ()
    drop_top_level: tuple[str, ...] = ("fields", "_score", "_ignored", "highlight", "sort")

    def model_post_init(self, __context: object) -> None:
        unknown = set(self.fields) - set(FIELD_KINDS)
        if unknown:
            raise ValueError(f"unknown field kinds {sorted(unknown)}; allowed: {FIELD_KINDS}")
        self.field_kinds()
        _check_patterns(self.field_patterns())
        if any(not key.strip() for key in self.literals):
            raise ValueError("a literal must not be blank")
        _check_domains(self.campus_domains, self.keep_domains, self.campus_replacement)
        _check_keep_lists(self)
        allocate_sites(self.site_prefixes)  # raises IPMapError (a ValueError) for a bad prefix

    def field_kinds(self) -> dict[str, str]:
        """Exact field paths and their kind; a path under two kinds is an error."""
        mapping: dict[str, str] = {}
        for kind, paths in self.fields.items():
            for path in paths:
                if "*" in path:
                    continue
                if path in mapping and mapping[path] != kind:
                    raise ValueError(f"field {path} has two kinds: {mapping[path]} and {kind}")
                mapping[path] = kind
        return mapping

    def field_patterns(self) -> tuple[tuple[str, str], ...]:
        """(pattern, kind) for the entries with a ``*``, in policy order."""
        return tuple(
            (path, kind) for kind, paths in self.fields.items() for path in paths if "*" in path
        )

    def kind_of(self, path: str) -> str | None:
        exact = self.field_kinds().get(path)
        if exact is not None:
            return exact
        return next(
            (kind for pattern, kind in self.field_patterns() if fnmatchcase(path, pattern)), None
        )


_RESERVED_TLDS = ("example", "invalid", "test", "localhost")
_LDH_NAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]+")
_CANARY_FIELDS = ("message", "@timestamp", "event.original", "x", "a.b.c")
_MIN_TERM = 3  # as DomainMapper: shorter organisation names and literals are not looked for inside


def _norm(domain: str) -> str:
    return normalize_domain(domain)


def _squash(text: str) -> str:
    """As the sanitizer compares names: NFKC, case-folded, letters and digits only, any script
    (``Example-University`` and ``example university`` are one name)."""
    return "".join(c for c in unicodedata.normalize("NFKC", text).casefold() if c.isalnum())


def _decoded(domain: str) -> str:
    """A domain with its punycode labels decoded, as the sanitizer looks for names in it."""
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            with contextlib.suppress(UnicodeError, ValueError):
                label = label[4:].encode("ascii").decode("punycode")
        labels.append(label)
    return ".".join(labels)


def _check_patterns(patterns: tuple[tuple[str, str], ...]) -> None:
    """One kind per pattern (compared with ``*`` runs collapsed), and no pattern that also matches
    fields no policy means (``*``, ``[!.]*``): each is tried on canary field names."""
    kinds: dict[str, str] = {}
    for pattern, kind in patterns:
        collapsed = re.sub(r"\*+", "*", pattern)
        if kinds.setdefault(collapsed, kind) != kind:
            raise ValueError(
                f"field pattern {pattern} has two kinds: {kinds[collapsed]} and {kind}"
            )
        if any(fnmatchcase(canary, pattern) for canary in _CANARY_FIELDS):
            raise ValueError(f"field pattern {pattern!r} would also match unrelated fields")


def _check_keep_lists(policy: FixturePolicy) -> None:
    """The keep lists keep things verbatim: no keep name or keep domain may hold an
    organisation name or a literal (compared as the sanitizer compares them: squashed, decoded,
    by containment), and no literal may be a kept domain (the text and the domain fields would
    then disagree)."""
    campus = [_norm(c) for c in policy.campus_domains]
    terms: set[str] = set()
    for domain in campus:
        for form in (domain, _decoded(domain)):
            terms |= {_squash(form.split(".")[0]), _squash(form)}
    terms |= {_squash(literal) for literal in policy.literals}
    terms = {t for t in terms if len(t) >= _MIN_TERM}
    for name in policy.keep_names:
        if any(t in _squash(name) for t in terms):
            raise ValueError(f"keep name {name!r} holds a campus name or a literal")
    for kept in (_norm(k) for k in policy.keep_domains):
        if any(t in _squash(_decoded(kept)) for t in terms):
            raise ValueError(f"keep domain {kept} holds a campus name or a literal")
        for literal in policy.literals:
            with contextlib.suppress(UnicodeError):
                text = _norm(literal)
                if _under(text, kept):
                    raise ValueError(f"literal {literal!r} is a kept domain ({kept})")


def _under(name: str, parent: str) -> bool:
    return name == parent or name.endswith("." + parent)


def _check_domains(campus: tuple[str, ...], keep: tuple[str, ...], replacement: str) -> None:
    campus_names = [_norm(c) for c in campus]
    for c in campus_names:
        for other in campus_names:
            if c != other and _under(c, other):
                raise ValueError(f"campus domain {c} is inside campus domain {other}; list {other}")
        for k in (_norm(k) for k in keep):
            if _under(k, c) or _under(c, k):
                raise ValueError(f"keep domain {k} overlaps campus domain {c}")
        if _under(_norm(replacement), c):
            raise ValueError(f"campus_replacement {replacement} is inside campus domain {c}")
    # The replacement is written as it is, so it must already be a plain lower-case host name.
    if not _LDH_NAME.fullmatch(replacement) or replacement.rsplit(".", 1)[1] not in _RESERVED_TLDS:
        raise ValueError(
            f"campus_replacement {replacement!r} must be a lower-case host name under a reserved "
            f"TLD ({', '.join('.' + t for t in _RESERVED_TLDS)}), e.g. univ.example"
        )


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that refuses a key repeated in one mapping (YAML 1.2 requires unique keys)."""

    def construct_mapping(self, node: Node, deep: bool = False) -> dict[Hashable, Any]:
        if isinstance(node, MappingNode):
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in seen
                except TypeError:
                    continue  # an unhashable key: the base constructor reports it
                if duplicate:
                    raise ConstructorError(
                        None, None, f"duplicate key {key!r}", key_node.start_mark
                    )
                seen.add(key)
        return super().construct_mapping(node, deep=deep)  # type: ignore[arg-type]


def _mapping(path: Path, raw: bytes) -> dict[str, Any]:
    data = yaml.load(raw, Loader=_UniqueKeyLoader) or {}  # noqa: S506 - a SafeLoader subclass
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a mapping")
    return data


def load_policy(path: Path, overlay: Path | None = None) -> tuple[FixturePolicy, str]:
    """The policy and the sha256 of its file (recorded in fixture manifests). ``overlay``, when
    the file exists, is laid over it key by key (the organisation's own names and ranges, kept
    out of the shipped file); the hash then covers both files."""
    raw = path.read_bytes()
    data = _mapping(path, raw)
    if overlay is not None and overlay.is_file():
        extra = overlay.read_bytes()
        data.update(_mapping(overlay, extra))
        raw += b"\0" + extra
    return FixturePolicy.model_validate(data), hashlib.sha256(raw).hexdigest()
