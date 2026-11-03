"""Turn real SIEM documents into shareable test fixtures (R2, D-030, D-041).

Two passes over a corpus:

1. ``harvest`` reads every document and records each identifier it can find, with its pseudonym:
   values of the identifier fields named in the policy (and the parts of qualified values: the
   account of ``user@realm``, ``user+tag@realm`` or ``DOMAIN\\user``, the host of a machine
   account ``HOST$``, the first label of a host FQDN), and everything the text detectors find in
   any string or mapping key (IPs, URL hosts and users, e-mails and their local parts, campus
   domains, reverse-DNS names, LDAP domains, HTTP credentials, ``field: value`` pairs and value
   lists of identifier fields). The raw identifiers form the leak-scan denylist.
2. ``sanitize`` rewrites each document: identifier fields through their mapper, every other string
   through the text pass (spans found by the detectors on the original text are replaced once; the
   untouched text in between gets the dictionary of harvested names and ids, then the policy
   literals). Numbers, booleans, timestamps, paths and attack strings are kept.

Where a document names the field of a value instead of nesting it, the value takes that field's
kind: ``{"field"/"key": f, "value"/"values"/"params"/"query": v}`` objects (threshold terms,
Kibana filter pills), mapping keys that are field paths (Query DSL ``term``/``match``, a hit's
``fields``, ``.keyword`` sub-fields) and the bucket keys of a ``terms`` aggregation whose request
names the field.

Identity rules: names (hosts, users, places, organisations) are case-insensitive, so every case
variant of one name gets one pseudonym; a value seen under several kinds is written in free text
with the pseudonym of the highest-priority kind, whatever the document order. Ids are
case-sensitive. A short host name and the first label of its FQDN share one label token.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import Any
from urllib.parse import unquote

from argus.fixtures.ipmap import IPMapper, format_ip
from argus.fixtures.policy import FixturePolicy
from argus.fixtures.tokens import DomainMapper, Tokenizer

SANITIZER_VERSION = "2.3.0"  # 2.3.0: R2 gate (escape letters, IPv6 spellings, DOMAIN\HOST$)

_PCT = r"(?<=%[0-9A-Fa-f]{2})"  # just after a %XX escape: a URL-encoded boundary
# Just after a literal \t, \n, ... escape (JSON inside a log line), but not inside a Windows
# path (C:\Users\tarun, D:\backup): the backslash must follow a non-word character that is not
# a drive's colon, or another escape.
_ESC = (
    r"(?:(?<=[^\w\\]\\[tnrbf])(?<![^\w][A-Za-z]:\\[tnrbf])(?<!^[A-Za-z]:\\[tnrbf])"  # not D:\b
    r"|(?<=\\[tnrbf]\\[tnrbf])|(?<=^\\[tnrbf]))"
)
# Not on the letter of such an escape: in "mail:\nalice@x" the e-mail starts after the n.
_NOT_ESCAPE_LETTER = r"(?![tnrbf]" + _ESC + ")"
_URL = re.compile(
    r"(?i)(?:(?<![\w.+-])" + _NOT_ESCAPE_LETTER + "|" + _PCT + "|" + _ESC + r")"
    r"([a-z][a-z0-9+.\-]{1,15}(?:://|%3a%2f%2f))"
    r"(?:([^\s/@:?#'\"<>%]+)(?::([^\s/@?#'\"<>]*))?@)?"  # optional user[:password]@
    r"(\[[0-9a-f:.]+\]|[\w-]+(?:\.[\w-]+)*)"  # host (no trailing dot or punctuation)
)
_EMAIL = re.compile(
    r"(?:(?<![\w.+%-])" + _NOT_ESCAPE_LETTER + "|" + _PCT + "|" + _ESC + r")"
    r"((?:[A-Za-z0-9._+-]|%2[BbEeDd]|%5[Ff]){1,64})"
    r"(@|%40)"
    r"([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?![\w-])"
)
_DISPLAY_EMAIL = re.compile(r"\s*\"?([^\"<]*?)\"?\s*<([^<>\s]+)>\s*")
_AUTH = re.compile(
    r"(?i)(?<![\w-])(basic|bearer|negotiate|ntlm|apikey|token)(\s+|%20|\+)([A-Za-z0-9+/=._~-]{8,})"
)
_DIGEST = re.compile(
    r"(?i)(?<![\w-])(digest)(\s+|%20|\+)((?:[a-z]+=(?:\"[^\"]*\"|[^,\s\"]*)(?:\s*,\s*)?)+)"
)
_DIGEST_PARAM = re.compile(r"(?i)([a-z]+)=(\"[^\"]*\"|[^,\s\"]*)")
_DIGEST_SECRETS = frozenset({"response", "cnonce", "nonce", "opaque"})
_IPV4 = re.compile(
    r"(?:(?<![0-9.])|" + _PCT + r")([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/([0-9]{1,2})(?![0-9]))?"
    r"(?![0-9])(?!\.[0-9](?![0-9]{0,4}(?![\w.])))"  # "a.b.c.d.e" is not an address, ".port" is
)
_IPV6 = re.compile(
    r"(?:(?<![\w:.])|(?<=[A-Za-z]:)|(?<=[Ii][Pp][Vv]6:)|" + _PCT + r")"
    r"([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,8}(?:\.[0-9]{1,3}){0,3})"  # 1:2:3:4:5:6:7::
    r"(?:/([0-9]{1,3}))?(?![\w:])"
)
_DASHED_V4 = re.compile(  # ip-10-1-2-3, dump_10_1_2_3: one separator throughout
    r"(?<![0-9.])(?<![0-9][-_])([0-9]{1,3})([-_])([0-9]{1,3})\2([0-9]{1,3})\2([0-9]{1,3})"
    r"(?![-_]?[0-9])"
)
_REVERSE_V4 = re.compile(r"(?i)(?<![\w.-])((?:[0-9]{1,3}\.){1,4})(in-addr\.arpa)(?![\w-])")
_REVERSE_V6 = re.compile(r"(?i)(?<![\w.-])((?:[0-9a-f]\.){1,32})(ip6\.arpa)(?![\w-])")
_DN = re.compile(r"(?i)(?<![\w-])DC=[\w-]+(?:\s*,\s*DC=[\w-]+)+")
_DN_LABEL = re.compile(r"(?i)DC=([\w-]+)")
_HOME = re.compile(r"(?i)(?:[\\/]Users[\\/]|/home/|/~)([^\\/\s:*?\"'<>|,;]+)")
# Fields that hold local filesystem paths or command lines (ECS file.*, process.*, dll.*, ...).
_FILESYSTEM_FIELD = re.compile(r"(?:^|\.)(?:file|process|dll|winlog|powershell|registry)\.")
_WILDCARD = re.compile(r"[*?]")
_QUOTED = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"
_LIST = r"\((?:[^()\"']|" + _QUOTED + r")*\)"
_ONE_VALUE = _QUOTED + r"|[^\s()\"',;\]}]+"
_LIST_ITEM = re.compile(_QUOTED + r"|[^\s(),\"']+")
# A field and a value in a query: KQL/Lucene ``f: v``, ES|QL ``f == v``/``f != v``/``f IN (…)``,
# EQL ``f in~ (…)``/``f like~ v``. The field's kind (patterns included) decides; no kind, no span.
_FIELD_PAIR = re.compile(
    r"(?<![\w.@])([A-Za-z_@][\w@]*(?:\.[\w@]+)*)"
    r"(\s*(?:!=|==|=|:)\s*|\s+(?i:not\s+)?(?i:in|r?like)~?\s+)"
    r"(" + _LIST + "|" + _ONE_VALUE + ")"
)
_VERSION_LIKE = re.compile(r"[0-9]+\.0\.0\.0")
_DIGITS = re.compile(r"[0-9]+")
_WORD_RUN = re.compile(r"[\w-]+")
_DICT_START = re.compile(r"(?:(?<![\w.-])|" + _PCT + "|" + _ESC + r")(?=[\w-])")
_NAME_KINDS = ("email", "user", "host", "domain", "place", "org")  # free-text priority
_REWRITABLE_KEY_KINDS = frozenset({"email", "user", "host"})
_SHORT_EXACT = 2  # names this short are matched in their own case only (department codes)
_SEPARATORS = r"(?:[\s_.+-]|%20)*"
_FIELD_NAME = re.compile(r"[a-z0-9_@.]+")  # every ECS and Kibana field-name segment fits
_VALUE_KEYS = frozenset({"value", "values", "params", "query", "include", "exclude"})
_TERMS_AGGREGATIONS = ("terms", "significant_terms", "rare_terms")


@dataclass(frozen=True)
class _Aggregations:
    """Context of an ``aggs``/``aggregations`` mapping: each named aggregation's key kinds."""


@dataclass(frozen=True)
class _Aggregation:
    keys: Any  # the kind of a bucket key: a kind, a tuple (multi_terms), a dict (composite)


@dataclass(frozen=True)
class _Bucket:
    keys: Any


@dataclass(frozen=True)
class _QueryText:
    """A ``query_string``/``multi_match`` query over fields of one kind: mapped term by term."""

    kind: str


Kind = str | tuple[Any, ...] | dict[str, Any] | _Aggregations | _Aggregation | _Bucket | _QueryText
Context = Callable[[Mapping[Any, Any], str, Kind | None], dict[Any, Kind]]


class SanitizerError(ValueError):
    """The input cannot be sanitized safely (refused, never partly processed)."""


def walk_strings(node: Any, path: str = "") -> Iterator[tuple[str, str]]:
    """(dotted path, string) for every string value; list items keep their parent's path."""
    for item_path, value, is_key, _kind in _walk(node, path):
        if not is_key and isinstance(value, str):
            yield item_path, value


def _walk(
    node: Any, path: str = "", context: Context | None = None
) -> Iterator[tuple[str, Any, bool, Kind | None]]:
    """Every string (value or mapping key) with its path, iteratively (no recursion limit):
    (path, string, is_key, the kind its context gives it or None)."""
    stack: list[tuple[Any, str, Kind | None]] = [(node, path, None)]
    while stack:
        current, current_path, kind = stack.pop()
        if isinstance(current, str):
            yield current_path, current, False, kind
        elif isinstance(current, Mapping):
            kinds = context(current, current_path, kind) if context else {}
            children = []
            for key, value in current.items():
                if isinstance(key, str):
                    yield current_path, key, True, None
                child = f"{current_path}.{key}" if current_path else str(key)
                children.append((value, child, kinds.get(key)))
            stack.extend(reversed(children))
        elif isinstance(current, list | tuple):
            stack.extend(
                (item, current_path, _item_kind(kind, i))
                for i, item in reversed(list(enumerate(current)))
            )


def _item_kind(kind: Kind | None, index: int) -> Kind | None:
    """A list item's kind: by position for a positional (multi_terms) kind, else the list's."""
    if isinstance(kind, tuple):
        return kind[index] if index < len(kind) else None
    return kind


class _Literals:
    """Policy literals: whole words; case-insensitive (for 4+ characters) and with any run of
    spaces, ``_``, ``.``, ``+``, ``-`` or ``%20`` where the literal has a space."""

    def __init__(self, literals: Mapping[str, str]) -> None:
        self._exact = dict(literals)
        self._groups: dict[str, list[tuple[str, str]]] = {}
        for key, replacement in sorted(literals.items()):
            self._groups.setdefault(_squash(key), []).append((key, replacement))
        parts = []
        for key in sorted(literals, key=lambda k: (-len(k), k)):
            body = _SEPARATORS.join(re.escape(word) for word in key.split())
            parts.append(body if len(key) < 4 else f"(?i:{body})")
        self.pattern = (
            re.compile(
                r"(?:(?<![A-Za-z0-9])|"
                + _PCT
                + "|"
                + _ESC
                + r")(?:"
                + "|".join(parts)
                + r")(?![A-Za-z0-9])"
            )
            if parts
            else None
        )

    def replace(self, text: str) -> str:
        return self.pattern.sub(self._replacement, text) if self.pattern else text

    def lookup(self, text: str) -> str | None:
        if text in self._exact:
            return self._exact[text]
        group = self._groups.get(_squash(text))
        if not group:
            return None
        replacement = group[0][1]
        if text.isupper():
            return replacement.upper()
        if text.islower():
            return replacement.lower()
        return replacement

    def _replacement(self, match: re.Match[str]) -> str:
        found = self.lookup(match.group(0))
        return found if found is not None else match.group(0)


class Sanitizer:
    def __init__(self, policy: FixturePolicy, key: bytes) -> None:
        self.policy = policy
        self.tokens = Tokenizer(key)
        self.ips = IPMapper(key, policy.site_prefixes)
        self.domains = DomainMapper(
            self.tokens,
            policy.campus_domains,
            policy.keep_domains,
            policy.campus_replacement,
            sensitive_terms=policy.literals,
        )
        self._kinds = policy.field_kinds()
        self._patterns = policy.field_patterns()
        self._kind_cache: dict[str, str | None] = {}
        self._keep_names = {name.lower() for name in policy.keep_names}
        self._literals = _Literals(policy.literals)
        self.harvested: set[str] = set()  # every raw identifier seen (leak-scan denylist)
        self.pseudonyms: set[str] = set()  # every value written in place of an identifier
        self.unchanged: set[str] = set()  # identifiers deliberately kept (loopback, vendor domains)
        self._candidates: dict[str, dict[str, str]] = {}  # lower-cased name -> {kind: pseudonym}
        self._spellings: dict[str, set[str]] = {}  # lower-cased name -> spellings seen
        self._short: dict[str, dict[str, str]] = {}  # 2-character name -> {kind: pseudonym}
        self.ids: dict[str, str] = {}  # ids, case-sensitive
        self.dictionary: dict[str, str] = {}  # lower-cased name -> its free-text pseudonym
        self._exact: dict[str, str] = {}  # ids and 2-character names, in their own case
        self._index: dict[str, list[int]] = {}  # first word (lower case) -> entry lengths
        self._structural: set[str] = set()  # keys that hold objects or lists: never renamed
        self._seen: set[tuple[str, str]] = set()
        self._seen_text: set[str] = set()
        self._path_words = {w.lower() for p, _ in self._patterns for w in p.split(".")} | {
            w.lower() for p in self._kinds for w in p.split(".")
        }
        domain_names = sorted({*self.domains.campus, *self.domains.keep}, key=len, reverse=True)
        self._domain_re = (
            re.compile(
                r"(?i)(?:(?<![\w.%-])(?<!%[0-9A-Fa-f])"
                + _NOT_ESCAPE_LETTER
                + "|"
                + _PCT
                + "|"
                + _ESC
                # a leading dot after a wildcard, '=', a quote, a space or the start (*.x, .x)
                + r"|(?<=[*=\s\"'(,:]\.)|(?<=^\.)"
                + r")((?:[\w-]+\.)*(?:"
                + "|".join(re.escape(d) for d in domain_names)
                + r"))(?![\w-])"
            )
            if domain_names
            else None
        )
        self._aggregations: dict[str, Any] = {}

    # ------------------------------------------------------------------ harvesting

    def harvest(self, docs: Iterable[Any]) -> None:
        # What harvesting finds depends only on the string (and its kind), so each distinct one
        # is looked at once: corpus documents repeat most of their strings.
        for doc in docs:
            self._aggregations = self._aggregation_fields(doc)
            for path, value, is_key, context_kind in _walk(doc, context=self._context):
                if not is_key:
                    for kind, part in self._typed_parts(context_kind, path, value):
                        if part.strip() and (kind, part) not in self._seen:
                            self._seen.add((kind, part))
                            self._harvest_field(kind, part)
                    if _FILESYSTEM_FIELD.search(path) and ("~", value) not in self._seen:
                        self._seen.add(("~", value))
                        self._harvest_homes(value)
                if value not in self._seen_text:
                    self._seen_text.add(value)
                    self._harvest_text(value)
            self._structural.update(_structural_keys(doc))
        self._rebuild()

    def _typed_parts(
        self, context_kind: Kind | None, path: str, value: str
    ) -> list[tuple[str, str]]:
        """(kind, value) for what a string holds: one value of its context's or its path's kind,
        the ``|``-joined values of a multi_terms key, the terms of a typed query, the name-like
        fragments of a wildcard value; [] if it is free text."""
        if isinstance(context_kind, tuple):
            parts = value.split("|")
            return [(k, p) for k, p in zip(context_kind, parts, strict=False) if isinstance(k, str)]
        if isinstance(context_kind, _QueryText):
            return [(context_kind.kind, v) for v in self._query_values(f"({value})")]
        if isinstance(context_kind, str):
            if _WILDCARD.search(value):
                return [(context_kind, v) for v in self._query_values(value)]
            return [(context_kind, value)]
        kind = self._kind(path)
        return [(kind, value)] if kind is not None else []

    def add_names(self, names: Iterable[str], kind: str = "place") -> None:
        """Names known from outside the corpus (the asset map): replaced wherever they appear."""
        for name in names:
            if name.strip():
                self._harvest_field(kind, name.strip())
        self._rebuild()

    def _harvest_field(self, kind: str, value: str) -> None:
        self._remember(kind, value, self._map_field(kind, value))
        if kind == "id" or _as_ip(value) is not None:
            return
        email = _EMAIL.fullmatch(value)
        if email and kind in ("user", "email", "host"):
            self._harvest_email(email.group(1), email.group(3))
        display = _DISPLAY_EMAIL.fullmatch(value) if kind == "email" else None
        if display and display.group(1).strip():
            self._remember("user", display.group(1).strip(), self._user(display.group(1).strip()))
        inner = _EMAIL.fullmatch(display.group(2)) if display else None
        if inner:
            self._harvest_email(inner.group(1), inner.group(3))
        if kind == "user":
            realm, sep, account = value.partition("\\")
            if sep and account:
                self._remember("user", account, self._user(account))
            if sep and realm:
                self._remember("host", realm, self._realm(realm))
            machine = account if sep else value  # HOST$ or DOMAIN\HOST$
            if machine.endswith("$") and len(machine) > 1:
                self._remember("host", machine[:-1], self.domains.label(machine[:-1]))
        if kind == "host" and "." in value.strip(".") and not email:
            first = value.split(".")[0]
            if len(first) >= 4 and re.search(r"[0-9_-]", first):
                self._remember("host", first, self.domains.label(first))

    def _harvest_email(self, local: str, domain: str) -> None:
        local = unquote(local)  # ravi.k%2Bnews is the account ravi.k with the tag news
        self._remember("email", f"{local}@{domain}", self._map_email(local, domain))
        self._remember("user", local, self._local_part(local))
        base, plus, _tag = local.partition("+")
        if plus and base:
            self._remember("user", base, self._user(base))
        if _as_ip(domain) is None:
            self._remember("domain", domain, self.domains.map(domain))

    def _harvest_text(self, text: str) -> None:
        for start, end, replacement in self._detect(text):
            raw = text[start:end]
            self._remember("span", raw, replacement)
        for m in _URL.finditer(text):
            host, user = m.group(4).strip("[]"), m.group(2)
            if _as_ip(host) is None:
                self._remember("domain", host, self.domains.map(host))
            if user:
                self._remember("user", user, self._user(user))
        for m in _EMAIL.finditer(text):
            self._harvest_email(m.group(1), m.group(3))
        for m in _IPV4.finditer(text):
            ip = _parse_v4(m.group(1))
            bare = m.group(2) is None  # a CIDR's network address is not an address on its own
            if ip is not None and bare and not self._version_like(text, m.start(), m.group(1)):
                self._remember("span", str(ip), format_ip(self.ips.map_address(ip)))
        for m in _AUTH.finditer(text):
            account = _basic_account(m.group(1), m.group(3))
            if account:
                self._remember("user", account, self._user(account))
        for m in _DIGEST.finditer(text):
            for name, value in _DIGEST_PARAM.findall(m.group(3)):
                if name.lower() == "username" and _unquote(value).strip():
                    self._remember("user", _unquote(value), self._user(_unquote(value)))
        for m in _FIELD_PAIR.finditer(text):
            kind = self._field_kind(m.group(1).removesuffix(".keyword"))
            if kind is not None:
                for value in self._query_values(m.group(3)):
                    self._harvest_field(kind, value)

    def _harvest_homes(self, path: str) -> None:
        """Account names in home-directory paths, only from filesystem-path fields: in URLs and
        web paths a ``/home/<x>`` is what a scanner probes for, not an account."""
        for m in _HOME.finditer(path):
            name = m.group(1)
            if len(name) >= 2 and name[0].isalnum():
                self._remember("user", name, self._user(name))

    def _remember(self, kind: str, raw: str, pseudonym: str) -> None:
        same = _norm(raw) == pseudonym if kind in ("domain", "host") else raw == pseudonym
        if same or (kind == "span" and raw.lower() == pseudonym.lower()):  # only case changed
            self.unchanged.add(raw)
            return
        self.harvested.add(raw)
        self.pseudonyms.add(pseudonym)
        if kind == "id":
            # A short id ("1", "7") would rewrite every such number in free text.
            if len(raw) >= 8 and _dictionary_worthy(raw):
                self.ids.setdefault(raw, pseudonym)
        elif kind in _NAME_KINDS and _dictionary_worthy(raw) and not _has_ip_form(raw):
            if len(raw) <= _SHORT_EXACT:
                self._short.setdefault(raw, {}).setdefault(kind, pseudonym)
            else:
                self._candidates.setdefault(raw.lower(), {}).setdefault(kind, pseudonym)
                self._spellings.setdefault(raw.lower(), set()).add(raw)

    def _rebuild(self) -> None:
        """The free-text dictionary: for each name the pseudonym of its highest-priority kind,
        whatever the order it was seen in; indexed by first word for a linear-time pass."""
        self.dictionary = {
            name: kinds[_priority(kinds)] for name, kinds in sorted(self._candidates.items())
        }
        short = {raw: kinds[_priority(kinds)] for raw, kinds in sorted(self._short.items())}
        self._exact = {**short, **self.ids}  # an id wins over a 2-character name
        index: dict[str, set[int]] = {}
        spellings = [*self._exact, *(s for group in self._spellings.values() for s in group)]
        for spelling in (*spellings, *self.dictionary):
            run = _WORD_RUN.match(spelling)
            if run is not None:
                index.setdefault(run.group(0).lower(), set()).add(len(spelling))
        self._index = {word: sorted(lengths, reverse=True) for word, lengths in index.items()}

    # ------------------------------------------------------------------ context kinds

    def _context(
        self, node: Mapping[Any, Any], path: str, inherited: Kind | None
    ) -> dict[Any, Kind]:
        """The kind each child of ``node`` takes from where it sits, not from its own path."""
        if isinstance(inherited, _Aggregations):  # name -> one aggregation's result or request
            return {
                name: _Aggregation(keys)
                for name in node
                if isinstance(name, str) and (keys := self._aggregation_keys(name)) is not None
            }
        if isinstance(inherited, _Aggregation):
            kinds: dict[Any, Kind] = {"buckets": _Bucket(inherited.keys)}
            if isinstance(inherited.keys, dict):
                kinds["after_key"] = inherited.keys  # composite: a key object to resume from
            return kinds
        if isinstance(inherited, _Bucket):
            kinds = {"key": inherited.keys}
            if isinstance(inherited.keys, str | tuple):
                kinds["key_as_string"] = inherited.keys
            kinds.update(self._nested_aggregations(node))  # sub-aggregations inside a bucket
            return kinds
        if isinstance(inherited, dict):  # a composite key object: source name -> kind
            return {key: inherited[key] for key in node if key in inherited}
        named = None
        if node.get("type") not in ("mapping", "exists"):  # field NAMES, not values
            for name_key in ("field", "key"):
                name = node.get(name_key)
                if isinstance(name, str) and named is None:
                    named = self._field_kind(name.removesuffix(".keyword"))
        query_kind = self._query_fields_kind(node)
        in_sort = path.rsplit(".", 1)[-1] == "sort"  # {"host.name": "asc"} is an order
        kinds = {}
        for key, value in node.items():
            if not isinstance(key, str):
                continue
            if key == "query" and query_kind is not None:
                kinds[key] = _QueryText(query_kind)
            elif key in _VALUE_KEYS and isinstance(inherited, str):
                kinds[key] = inherited
            elif key in _VALUE_KEYS and named is not None:
                kinds[key] = named
            elif key in ("aggs", "aggregations") and isinstance(value, Mapping):
                kinds[key] = _Aggregations()
            elif not in_sort:
                field_kind = self._field_kind(key.removesuffix(".keyword"))
                if field_kind is not None:
                    kinds[key] = field_kind
        return kinds

    def _nested_aggregations(self, node: Mapping[Any, Any]) -> dict[Any, Kind]:
        return {
            name: _Aggregation(keys)
            for name in node
            if isinstance(name, str)
            and name in self._aggregations
            and (keys := self._aggregation_keys(name)) is not None
        }

    def _aggregation_keys(self, name: str) -> Any:
        """The kind of an aggregation's bucket keys: by the request's field(s), else by its name
        when the name is a field (``host.name``); None if it has none."""
        spec = self._aggregations.get(name, name)
        if isinstance(spec, str):
            return self._field_kind(spec.removesuffix(".keyword"))
        if isinstance(spec, tuple):
            kinds = tuple(
                None if f is None else self._field_kind(f.removesuffix(".keyword")) for f in spec
            )
            return kinds if any(kinds) else None
        kinds_by_source = {
            source: kind
            for source, field in spec.items()
            if (kind := self._field_kind(field.removesuffix(".keyword"))) is not None
        }
        return kinds_by_source or None

    def _query_fields_kind(self, node: Mapping[Any, Any]) -> str | None:
        """``query_string``/``multi_match``: the one kind of all the query's ``fields``."""
        fields = node.get("fields")
        if not isinstance(node.get("query"), str) or not isinstance(fields, list) or not fields:
            return None
        kinds = {
            self._field_kind(f.split("^")[0].removesuffix(".keyword"))
            for f in fields
            if isinstance(f, str)
        }
        return kinds.pop() if len(kinds) == 1 and None not in kinds else None

    @staticmethod
    def _aggregation_fields(doc: Any) -> dict[str, Any]:
        """Aggregations a document's requests name (a cassette holds request and response): name
        -> field (terms), tuple of fields (multi_terms) or {source: field} (composite)."""
        found: dict[str, Any] = {}
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, Mapping):
                for key, value in node.items():
                    if key in ("aggs", "aggregations") and isinstance(value, Mapping):
                        for name, spec in value.items():
                            fields = _aggregation_spec(spec)
                            if fields is not None:
                                found[str(name)] = fields
                    stack.append(value)
            elif isinstance(node, list | tuple):
                stack.extend(node)
        return found

    # ------------------------------------------------------------------ sanitizing

    def sanitize(self, doc: Any) -> Any:
        if isinstance(doc, Mapping) and "_source" in doc:
            drop = set(self.policy.drop_top_level)
            doc = {k: v for k, v in doc.items() if k not in drop}
        self._aggregations = self._aggregation_fields(doc)
        return self._transform(doc)

    def _transform(self, root: Any) -> Any:
        """Rebuild ``root`` with every string mapped, iteratively (no recursion limit)."""
        holder: list[Any] = [None]
        stack: list[tuple[Any, str, Any, Any, Kind | None]] = [(root, "", holder, 0, None)]
        while stack:
            node, path, parent, slot, context_kind = stack.pop()
            if isinstance(node, str):
                parent[slot] = self._map_string(context_kind, path, node)
            elif isinstance(node, Mapping):
                out: dict[Any, Any] = {}
                kinds = self._context(node, path, context_kind)
                for key, value in node.items():
                    new_key = self._map_key(key) if isinstance(key, str) else key
                    if new_key in out:
                        raise SanitizerError("two mapping keys map to one pseudonym")
                    out[new_key] = None
                    child = f"{path}.{key}" if path else str(key)
                    stack.append((value, child, out, new_key, kinds.get(key)))
                parent[slot] = out
            elif isinstance(node, list | tuple):
                items: list[Any] = [None] * len(node)
                for index, item in enumerate(node):
                    stack.append((item, path, items, index, _item_kind(context_kind, index)))
                parent[slot] = items
            else:
                parent[slot] = node
        return holder[0]

    def _map_string(self, context_kind: Kind | None, path: str, value: str) -> str:
        if isinstance(context_kind, tuple):  # a multi_terms key_as_string: "host|user"
            kinds = list(context_kind)
            return "|".join(
                self._map_field(k, part)
                if isinstance(k, str) and part.strip()
                else self.map_text(part)
                for k, part in zip(
                    kinds + [None] * (value.count("|") + 1 - len(kinds)),
                    value.split("|"),
                    strict=False,
                )
            )
        if isinstance(context_kind, _QueryText):
            return self._map_query_value(context_kind.kind, f"({value})")[1:-1]
        if isinstance(context_kind, str):
            if _WILDCARD.search(value):  # a DSL wildcard/prefix: by fragments, as in KQL
                return self._map_query_value(context_kind, value)
            return self._map_field(context_kind, value)
        kind = self._kind(path)
        return self._map_field(kind, value) if kind else self.map_text(value)

    def map_text(self, text: str) -> str:
        whole = _as_ip(text)
        if whole is not None:
            return format_ip(self.ips.map_address(whole))
        return self._map_spans(text, self._map_plain)

    def _map_key(self, key: str) -> str:
        """Mapping keys are structure: detected spans (addresses, e-mails, domains) change, and so
        does a key that is a whole harvested id, or a whole harvested name used as a key
        (``LAB-PC-07``, or ``kiosk7`` under ``labels``). A key shaped like a field name changes only
        if it is a harvested host, user or e-mail, never holds an object or a list, and is no
        segment of a policy field path: ``meta`` stays ``meta`` even if a department is META."""
        if key in self.ids:
            return self.ids[key]
        lower = key.lower()
        whole = (
            self.dictionary.get(lower)
            if len(key) > _SHORT_EXACT and not _has_ip_form(key)
            else None
        )
        if whole is not None and _FIELD_NAME.fullmatch(key):
            kinds = self._candidates.get(lower, {})
            renamable = bool(kinds.keys() & _REWRITABLE_KEY_KINDS)
            if not renamable or key in self._structural or lower in self._path_words:
                whole = None
        if whole is not None:
            return whole
        mapped_ip = _as_ip(key)
        if mapped_ip is not None:
            return format_ip(self.ips.map_address(mapped_ip))
        return self._map_spans(key, lambda gap: gap)

    def _map_spans(self, text: str, plain: Callable[[str], str]) -> str:
        out: list[str] = []
        pos = 0
        for start, end, replacement in self._detect(text):
            out.append(plain(text[pos:start]))
            out.append(replacement)
            pos = end
        out.append(plain(text[pos:]))
        return "".join(out)

    # ------------------------------------------------------------------ field mappers

    def _kind(self, path: str) -> str | None:
        """Field kind for a dotted path; a document may sit under ``_source`` at any depth."""
        cached = self._kind_cache.get(path, "?")
        if cached != "?":
            return cached
        segments = path.split(".")
        if segments[-1] == "_id":
            kind: str | None = "id"
        else:
            if "_source" in segments:
                last = len(segments) - 1 - segments[::-1].index("_source")
                path = ".".join(segments[last + 1 :])
            kind = self._field_kind(path)
        self._kind_cache[".".join(segments)] = kind
        return kind

    def _field_kind(self, field: str) -> str | None:
        exact = self._kinds.get(field)
        if exact is not None:
            return exact
        return next((kind for pattern, kind in self._patterns if fnmatchcase(field, pattern)), None)

    def _map_field(self, kind: str, value: str) -> str:
        if not value.strip():
            return value
        if kind == "id":
            return self.tokens.opaque_id(value)
        ip = _as_ip(value)
        if ip is not None:
            return format_ip(self.ips.map_address(ip))
        if kind == "email":
            return self._map_email_value(value)
        if kind == "user":
            email = _EMAIL.fullmatch(value)
            if email:
                return self._map_email(email.group(1), email.group(3), email.group(2))
            realm, sep, account = value.partition("\\")
            if sep and realm and account:
                return f"{self._realm(realm)}\\{self._user(account)}"
            return self._user(value)
        if kind in ("host", "domain"):
            if value.lower() in self._keep_names:
                return value
            if _whole_ip_form(value):  # a PTR name or a padded address: as in text
                return self.map_text(value)
            return self._map_host_name(value)
        if kind == "org":
            literal = self._literals.lookup(value)
            if literal is not None:
                return literal
            return self.tokens.token("org", value.lower(), "org-")
        return self.tokens.token("place", value.lower(), "pl-")

    def _map_host_name(self, value: str) -> str:
        """A host name; a label carrying a class or site address quad (``ip-10-1-2-3``) keeps
        its mapped quad, as in text, and every other label is mapped as the domain mapper does."""
        labels = value.split(".")
        for index, label in enumerate(labels):
            m = _DASHED_V4.search(label)
            dashed = self._map_dashed(m) if m is not None else None
            if m is None or dashed is None:
                continue
            mapped = self.domains.map(value).split(".")
            if len(mapped) != len(labels):  # a campus suffix changed the label count
                mapped = [self.domains.label(lb) for lb in labels]
            mapped[index] = label[: m.start()] + dashed + label[m.end() :]
            return ".".join(mapped)
        return self.domains.map(value)

    def _user(self, name: str) -> str:
        if name.lower() in self._keep_names:
            return name
        return self.tokens.token("user", name.lower(), "u-")

    def _realm(self, realm: str) -> str:
        """A Windows realm (``DOMAIN`` of ``DOMAIN\\user``); well-known ones are kept."""
        return realm if realm.lower() in self._keep_names else self.domains.label(realm)

    def _local_part(self, local: str) -> str:
        """``alice+lists`` keeps the account's own pseudonym and tokens the tag."""
        base, plus, tag = local.partition("+")
        if plus and base and tag:
            return f"{self._user(base)}+{self.tokens.token('tag', tag.lower(), '', 6)}"
        return self._user(local)

    def _map_email(self, local: str, domain: str, separator: str = "@") -> str:
        local = unquote(local)
        ip = _as_ip(domain)
        mapped = format_ip(self.ips.map_address(ip)) if ip is not None else self.domains.map(domain)
        return f"{self._local_part(local)}{separator}{mapped}"

    def _map_email_value(self, value: str) -> str:
        email = _EMAIL.fullmatch(value)
        if email:
            return self._map_email(email.group(1), email.group(3), email.group(2))
        display = _DISPLAY_EMAIL.fullmatch(value)
        if display:
            inner = _EMAIL.fullmatch(display.group(2))
            if inner:
                name = display.group(1).strip()
                mapped = self._map_email(inner.group(1), inner.group(3), inner.group(2))
                return f"{self._user(name)} <{mapped}>" if name else f"<{mapped}>"
        if "@" not in value and " " not in value.strip():
            return self._user(value)  # a bare login name in an e-mail field
        return self.map_text(value)

    # ------------------------------------------------------------------ rule queries

    def _query_values(self, value: str) -> Iterator[str]:
        """The values of a ``field: value`` pair: each item of a list, wildcard fragments that
        look like names (``svc-backup-07*``), never a bare pattern (``*``, ``lab-*``)."""
        items = (
            [m.group(0) for m in _LIST_ITEM.finditer(value[1:-1])]
            if value.startswith("(")
            else [value]
        )
        for item in items:
            if item.lower() in ("or", "and", "not"):
                continue
            inner = _unquote(item)
            if _WILDCARD.search(inner):
                yield from (f for f in _WILDCARD.split(inner) if _name_like(f))
            elif inner.strip():
                yield inner

    def _map_query_value(self, kind: str, value: str) -> str:
        if value.startswith("("):
            return (
                "("
                + _LIST_ITEM.sub(
                    lambda m: (
                        m.group(0)
                        if m.group(0).lower() in ("or", "and", "not")
                        else self._map_query_value(kind, m.group(0))
                    ),
                    value[1:-1],
                )
                + ")"
            )
        inner = _unquote(value)
        quote = value[0] if inner != value else ""
        if _WILDCARD.search(inner):
            mapped = re.sub(
                r"[^*?]+",
                lambda m: self._map_fragment(kind, m.group(0)),
                inner,
            )
        else:
            mapped = self._map_field(kind, inner) if inner.strip() else inner
        return quote + mapped + quote

    def _map_fragment(self, kind: str, fragment: str) -> str:
        if not _name_like(fragment):
            return self.map_text(fragment)  # .campus.ac.in of *.campus.ac.in, an address
        core = fragment.strip("-_.")
        start = fragment.index(core)
        return fragment[:start] + self._map_field(kind, core) + fragment[start + len(core) :]

    # ------------------------------------------------------------------ text pass

    def _detect(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping (start, end, replacement) spans found on the ORIGINAL text."""
        found: list[tuple[int, int, str]] = []
        found.extend((m.start(), m.end(), self._map_url(m)) for m in _URL.finditer(text))
        found.extend(
            (m.start(), m.end(), self._map_email(m.group(1), m.group(3), m.group(2)))
            for m in _EMAIL.finditer(text)
        )
        found.extend(
            (m.start(), m.end(), m.group(1) + m.group(2) + "REDACTED")
            for m in _AUTH.finditer(text)
            if _credential(m.group(1), m.group(3))  # not "basic authentication"
        )
        found.extend(
            (m.start(), m.end(), m.group(1) + m.group(2) + self._map_digest(m.group(3)))
            for m in _DIGEST.finditer(text)
        )
        for m in _REVERSE_V4.finditer(text):
            reverse = self._map_reverse_v4(m.group(1), m.group(2))
            if reverse is not None:
                found.append((m.start(), m.end(), reverse))
        for m in _REVERSE_V6.finditer(text):
            reverse = self._map_reverse_v6(m.group(1), m.group(2))
            if reverse is not None:
                found.append((m.start(), m.end(), reverse))
        for m in _IPV6.finditer(text):
            mapped = self._map_ip_token(m.group(1), m.group(2))
            if mapped is not None:
                found.append((m.start(), m.end(), mapped))
        for m in _IPV4.finditer(text):
            if self._version_like(text, m.start(), m.group(1)):
                continue
            mapped = self._map_ip_token(m.group(1), m.group(2))
            if mapped is not None:
                found.append((m.start(), m.end(), mapped))
        for m in _DASHED_V4.finditer(text):
            dashed = self._map_dashed(m)
            if dashed is not None:
                found.append((m.start(), m.end(), dashed))
        for m in _DN.finditer(text):
            found.append((m.start(), m.end(), self._map_dn(m.group(0))))
        if self._domain_re is not None:
            found.extend(
                (m.start(1), m.end(1), self.domains.map(m.group(1)))
                for m in self._domain_re.finditer(text)
            )
        for m in _FIELD_PAIR.finditer(text):
            kind = self._field_kind(m.group(1).removesuffix(".keyword"))
            if kind is not None:
                mapped = self._map_query_value(kind, m.group(3))
                found.append((m.start(), m.end(), m.group(1) + m.group(2) + mapped))
        accepted: list[tuple[int, int, str]] = []
        last_end = -1
        for start, end, replacement in sorted(found, key=lambda s: (s[0], -(s[1] - s[0]))):
            if start >= last_end:
                accepted.append((start, end, replacement))
                last_end = end
        return accepted

    def _map_url(self, m: re.Match[str]) -> str:
        scheme, user, password, host = m.group(1), m.group(2), m.group(3), m.group(4)
        userinfo = ""
        if user is not None:
            userinfo = self._user(user)
            if password is not None:
                userinfo += ":REDACTED"
            userinfo += "@"
        bracketed = host.startswith("[")
        ip = _as_ip(host.strip("[]"))
        if ip is not None:
            mapped = format_ip(self.ips.map_address(ip))
            new_host = f"[{mapped}]" if bracketed else mapped
        else:
            new_host = self.domains.map(host)
        return f"{scheme}{userinfo}{new_host}"

    def _map_ip_token(self, address: str, prefixlen: str | None) -> str | None:
        ip = _as_ip(address) or _parse_v4(address)
        if ip is None:
            return None
        mapped = format_ip(self.ips.map_address(ip))
        if ip.version == 4 and str(ip) != address:  # zero-padded: keep the padding's widths
            mapped = _pad_like(address, mapped)
        if prefixlen is None:
            return mapped
        try:
            net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False)
        except ValueError:
            return f"{mapped}/{prefixlen}"
        if net.network_address != ip or (address != str(ip) and ip.version == 4):
            return f"{mapped}/{prefixlen}"  # interface notation (10.1.2.3/24) keeps its host
        region = self.ips.region(ip)
        if region == "public":
            return f"{mapped}/{prefixlen}"
        if net.prefixlen == 0 or region == "keep":
            return str(net)
        try:
            return str(self.ips.map_network(net))
        except ValueError:
            # Membership cannot be preserved (cross-region): never leak, just map the address.
            return f"{mapped}/{prefixlen}"

    def _map_dashed(self, m: re.Match[str]) -> str | None:
        ip = _parse_v4(".".join((m.group(1), m.group(3), m.group(4), m.group(5))))
        if ip is None or not self.ips.region(ip).startswith(("class:", "site:")):
            return None
        return format_ip(self.ips.map_address(ip)).replace(".", m.group(2))

    def _map_digest(self, params: str) -> str:
        """Digest credentials: the user name gets its pseudonym, the secrets are redacted, the
        rest (realm, uri, ...) goes through the text pass."""

        def one(m: re.Match[str]) -> str:
            name, value = m.group(1), m.group(2)
            quote = '"' if value.startswith('"') else ""
            inner = _unquote(value)
            if name.lower() == "username":
                mapped = self._user(inner) if inner.strip() else inner
            elif name.lower() in _DIGEST_SECRETS:
                mapped = "REDACTED"
            else:
                mapped = self.map_text(inner)
            return f"{name}={quote}{mapped}{quote}"

        return _DIGEST_PARAM.sub(one, params)

    def _map_reverse_v4(self, octets_text: str, suffix: str) -> str | None:
        octets = octets_text.rstrip(".").split(".")[::-1]
        if any(int(o) > 255 for o in octets):
            return None
        octets = [str(int(o)) for o in octets]  # 07.2.1.10 is 10.1.2.7
        if len(octets) == 4:
            mapped = format_ip(self.ips.map_address(ipaddress.IPv4Address(".".join(octets))))
            forward = mapped.split(".")
        else:
            network = ".".join(octets + ["0"] * (4 - len(octets)))
            mapped_net = self._map_ip_token(network, str(8 * len(octets)))
            if mapped_net is None:
                return None
            forward = mapped_net.split("/")[0].split(".")[: len(octets)]
        return ".".join(reversed(forward)) + "." + suffix

    def _map_reverse_v6(self, nibbles_text: str, suffix: str) -> str | None:
        nibbles = nibbles_text.rstrip(".").split(".")[::-1]
        count = len(nibbles)
        value = int("".join(nibbles).ljust(32, "0"), 16)
        address = ipaddress.IPv6Address(value)
        if count == 32:
            mapped = self.ips.map_address(address)
        else:
            mapped_net = self._map_ip_token(str(address), str(4 * count))
            if mapped_net is None:
                return None
            mapped = ipaddress.ip_address(mapped_net.split("/")[0])
        forward = f"{int(mapped):032x}"[:count]
        return ".".join(reversed(forward)) + "." + suffix

    def _map_dn(self, text: str) -> str:
        domain = ".".join(_DN_LABEL.findall(text))
        return ",".join(f"DC={label}" for label in self.domains.map(domain).split("."))

    @staticmethod
    def _version_like(text: str, start: int, token: str) -> bool:
        """``Chrome/154.0.0.0``: a product/version pair, not an address."""
        return (
            start >= 2
            and text[start - 1] == "/"
            and text[start - 2].isalpha()
            and _VERSION_LIKE.fullmatch(token) is not None
        )

    def _map_plain(self, text: str) -> str:
        if not text:
            return text
        if self._index:
            text = self._replace_names(text)
        return self._literals.replace(text)

    def _replace_names(self, text: str) -> str:
        """Harvested names and ids, leftmost-longest, between the dictionary's boundaries: not
        inside a word, a dotted name or a dashed compound (``lab-pc`` stays inside ``lab-pc-07``),
        but right after a ``%XX`` or ``\\t``-style escape. One lookup per word start."""
        out: list[str] = []
        pos = 0
        size = len(text)
        for start_match in _DICT_START.finditer(text):
            start = start_match.start()
            if start < pos:
                continue
            run = _WORD_RUN.match(text, start)
            lengths = self._index.get(run.group(0).lower()) if run is not None else None
            if not lengths:
                continue
            for length in lengths:
                end = start + length
                if end > size or (end < size and _word_char(text[end])):
                    continue
                replacement = self._entry(text[start:end])
                if replacement is not None:
                    out.append(text[pos:start])
                    out.append(replacement)
                    pos = end
                    break
        out.append(text[pos:])
        return "".join(out)

    def _entry(self, found: str) -> str | None:
        if found in self._exact:
            return self._exact[found]
        pseudonym = self.dictionary.get(found.lower())
        if pseudonym is None:
            return None
        literal = self._literals.lookup(found)  # a harvested value that is a literal keeps its case
        return literal if literal is not None else pseudonym


def _aggregation_spec(spec: Any) -> Any:
    """What an aggregation request keys its buckets by: a field (terms), a tuple of fields
    (multi_terms), {source: field} (composite); None for any other aggregation."""
    if not isinstance(spec, Mapping):
        return None
    for name in _TERMS_AGGREGATIONS:
        terms = spec.get(name)
        if isinstance(terms, Mapping) and isinstance(terms.get("field"), str):
            return terms["field"]
    multi = spec.get("multi_terms")
    if isinstance(multi, Mapping) and isinstance(multi.get("terms"), list):
        fields = tuple(  # a script term keeps its place: the keys are positional
            t["field"] if isinstance(t, Mapping) and isinstance(t.get("field"), str) else None
            for t in multi["terms"]
        )
        return fields if any(f is not None for f in fields) else None
    composite = spec.get("composite")
    if isinstance(composite, Mapping) and isinstance(composite.get("sources"), list):
        by_source: dict[str, str] = {}
        for source in composite["sources"]:
            for name, body in source.items() if isinstance(source, Mapping) else ():
                terms = body.get("terms") if isinstance(body, Mapping) else None
                if isinstance(terms, Mapping) and isinstance(terms.get("field"), str):
                    by_source[str(name)] = terms["field"]
        return by_source or None
    return None


def _priority(kinds: Mapping[str, str]) -> str:
    return next(k for k in _NAME_KINDS if k in kinds)


def _word_char(char: str) -> bool:
    return char.isalnum() or char in "_-"


def _structural_keys(doc: Any) -> set[str]:
    """Mapping keys whose value is an object or a list: structure, never a name used as a key."""
    found: set[str] = set()
    stack = [doc]
    while stack:
        node = stack.pop()
        if isinstance(node, Mapping):
            for key, value in node.items():
                if isinstance(value, Mapping | list | tuple):
                    if isinstance(key, str):
                        found.add(key)
                    stack.append(value)
        elif isinstance(node, list | tuple):
            stack.extend(node)
    return found


def _basic_account(scheme: str, token: str) -> str | None:
    """The account of an HTTP Basic credential (``base64(user:password)``)."""
    if scheme.lower() != "basic":
        return None
    try:
        decoded = base64.b64decode(token + "=" * (-len(token) % 4), validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    account, sep, _password = decoded.partition(":")
    return account if sep and account and account.isprintable() else None


def _name_like(fragment: str) -> bool:
    """A wildcard fragment that names something (``svc-backup-07``), not a pattern (``lab-``)."""
    core = fragment.strip("-_.")
    return len(core) >= 4 and re.search(r"[0-9_-]", core) is not None


def _whole_ip_form(value: str) -> bool:
    """A whole value that is an address in another form: a PTR name or a padded address."""
    return (
        _REVERSE_V4.fullmatch(value) is not None
        or _REVERSE_V6.fullmatch(value) is not None
        or _parse_v4(value) is not None
    )


def _has_ip_form(value: str) -> bool:
    """A value that holds an address form the text pass maps on its own (so it is not a name:
    its case variants would get different pseudonyms)."""
    return _whole_ip_form(value) or _DASHED_V4.search(value) is not None


def _credential(scheme: str, token: str) -> bool:
    """A token that looks like a credential, not a word: a Basic ``user:password``, or anything
    with a digit or base64/JWT punctuation."""
    if scheme.lower() == "basic" and _basic_account(scheme, token):
        return True
    return re.search(r"[0-9+/=._-]", token) is not None


def _dictionary_worthy(raw: str) -> bool:
    """Short numbers (uids, ports, byte counts) are not names: replacing them in free text would
    rewrite timestamps and sizes. Long numbers (roll numbers) are."""
    stripped = raw.strip()
    if len(stripped) < 2:
        return False
    return not (_DIGITS.fullmatch(stripped) and len(stripped) < 6)


def _squash(text: str) -> str:
    return re.sub(r"(?:[\s_.+-]|%20)+", "", text).casefold()


def _norm(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_v4(text: str) -> ipaddress.IPv4Address | None:
    """Dotted IPv4, leading zeros allowed (``010.001.002.003`` is 10.1.2.3 in logs)."""
    parts = text.split(".")
    if len(parts) != 4 or not all(
        p.isascii() and p.isdigit() and len(p) <= 3 and int(p) <= 255 for p in parts
    ):
        return None
    return ipaddress.IPv4Address(".".join(str(int(p)) for p in parts))


def _pad_like(original: str, mapped: str) -> str:
    widths = [len(p) for p in original.split(".")]
    return ".".join(o.zfill(w) for o, w in zip(mapped.split("."), widths, strict=True))


def _as_ip(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not text or len(text) > 45 or "%" in text or not (":" in text or text[:1].isdigit()):
        return None
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None
