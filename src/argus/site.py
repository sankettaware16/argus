"""The site profile: everything about one organisation's Elastic that is not code. Log families
(role, pattern, time field, field names), the Kibana space, versions, licence, time zone and
words live in the ``site`` section of the settings; ``argus discover`` proposes it, and the
neutral defaults work on an Elastic with nothing configured. The loaded section becomes the
process's active site (``activate``, called by ``load_settings``); everything else asks
``active()``. Tests use ``using``."""

from __future__ import annotations

import fnmatch
import logging
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, time, timedelta
from enum import StrEnum
from ipaddress import IPv4Network, IPv6Network
from typing import Annotated, Any, Final, Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class Role(StrEnum):
    """What a family of logs is. The evidence modules pick their family by role."""

    ALERTS = "alerts"  # the Security alerts index: named by ``site.alerts_index``, not a family
    PROXY = "proxy"  # forward proxy: who reached which outside destination
    WEB = "web"  # web servers: requests to the hosted sites
    DNS = "dns"  # resolver queries
    AUTH = "auth"  # sign-ins
    MAIL = "mail"
    OTHER = "other"


LOG_ROLES: Final = tuple(role for role in Role if role is not Role.ALERTS)

# The field roles each family role's evidence modules use, with the name they have in ECS. A
# site's ``fields`` overrides some of them. "client_ip_alt" is a second field the client may be
# in (a resolver's logs fill ``source.ip`` or ``client.ip``).
FIELD_ROLES: Final[Mapping[Role, Mapping[str, str]]] = {
    Role.PROXY: {
        "client_ip": "source.ip",
        "server_ip": "destination.ip",
        "server_port": "destination.port",
        "bytes": "destination.bytes",
        "url": "url.original",
        "method": "http.request.method",
        "status_code": "http.response.status_code",
        "action": "event.action",
    },
    Role.WEB: {
        "client_ip": "source.ip",
        "domain": "url.domain",
        "url_path": "url.path",
        "method": "http.request.method",
        "status_code": "http.response.status_code",
        "bytes": "http.response.body.bytes",
        "user_agent": "user_agent.original",
    },
    Role.DNS: {
        "client_ip": "source.ip",
        "client_ip_alt": "client.ip",
        "query_name": "dns.question.name",
        "query_type": "dns.question.type",
        "response_code": "dns.response_code",
    },
    Role.AUTH: {
        "client_ip": "source.ip",
        "user_name": "user.name",
        "action": "event.action",
        "outcome": "event.outcome",
        "user_agent": "user_agent.original",
    },
    Role.MAIL: {"client_ip": "source.ip"},
    Role.OTHER: {"client_ip": "source.ip"},
    Role.ALERTS: {},
}
# The Elasticsearch type of each field role in a family's mapping when the site says nothing
# else ("text+keyword" is a text field with a ``.keyword`` sub-field of ``ignore_above``): the
# types the evidence templates were written against (ECS fields as a Logstash pipeline maps them).
FIELD_TYPES: Final[Mapping[Role, Mapping[str, str]]] = {
    Role.PROXY: {
        "client_ip": "ip", "server_ip": "ip", "server_port": "long", "bytes": "long",
        "url": "text+keyword", "method": "text+keyword", "status_code": "integer",
        "action": "text+keyword",
    },
    Role.WEB: {
        "client_ip": "ip", "domain": "text+keyword", "url_path": "keyword",
        "method": "text+keyword", "status_code": "integer", "bytes": "long",
        "user_agent": "text+keyword",
    },
    Role.DNS: {
        "client_ip": "ip", "client_ip_alt": "ip", "query_name": "text+keyword",
        "query_type": "text+keyword", "response_code": "text+keyword",
    },
    Role.AUTH: {
        "client_ip": "ip", "user_name": "text+keyword", "action": "text+keyword",
        "outcome": "text+keyword", "user_agent": "text+keyword",
    },
    Role.MAIL: {"client_ip": "ip"},
    Role.OTHER: {"client_ip": "ip"},
    Role.ALERTS: {},
}  # fmt: skip
MAPPING_TYPES: Final = frozenset(
    {"date", "ip", "long", "integer", "float", "double", "boolean", "keyword", "text",
     "text+keyword"}
)  # fmt: skip
DEFAULT_IGNORE_ABOVE: Final = 256
MIN_IGNORE_ABOVE: Final = 32  # a family that indexes less than this cannot be searched at all
DEFAULT_TIME_FIELD: Final = "@timestamp"
KEYWORD_SUFFIX: Final = ".keyword"
# The only fields ``argus discover`` asks Elasticsearch how they are mapped: the fields above,
# the event time candidates, and the few that say what kind of log an index holds.
DISCOVERY_FIELDS: Final = (
    frozenset(name for names in FIELD_ROLES.values() for name in names.values())
    | frozenset(
        {
            "@timestamp", "timestamp", "event.created", "event.ingested", "event.category",
            "event.dataset", "event.module", "event.type", "data_stream.dataset",
            "email.from.address", "email.to.address", "email.message_id",
            "threat.indicator.type", "threat.indicator.ip", "ioc_value", "ioc_type",
        }
    )
)  # fmt: skip

NAME_PATTERN: Final = r"^[a-z][a-z0-9_]{0,31}$"
_FIELD_NAME = re.compile(r"[A-Za-z@_][A-Za-z0-9@._-]{0,127}")
# A family's pattern starts with a letter or digit: a name that starts with "." is a hidden or
# system index (``.ds-*``, ``.security-*``, ``.kibana-*``) and is never a log family.
_DAILY = re.compile(r"[a-z0-9][a-z0-9._+-]{0,200}[-._]\*")
_EXACT = re.compile(r"[a-z0-9][a-z0-9._+-]{0,254}")
_ALERTS_NAME = re.compile(r"[a-z0-9.][a-z0-9._+-]{0,254}")  # the alerts alias starts with "."
_MAPPED_INDEX = re.compile(r"(?:\.ds-)?[a-z0-9][a-z0-9._+-]{0,250}")  # discovery reads one
_CHECKED = re.compile(r"[a-z0-9][a-z0-9._+*-]{0,254}")  # a privilege check's index pattern
_SPACE = re.compile(r"[a-z0-9_-]{1,64}")
_SAMPLE_DAYS: Final = ("2026.01.01", "2026.06.15", "2026.12.28")
_TOKEN = re.compile(r"[^a-z0-9]+")


def _items(value: Any) -> Any:
    """A comma-separated string as its items (an environment variable holds one string)."""
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return value


_DAY_START = re.compile(r"[0-9.]*")
log = logging.getLogger("argus.site")
_NUMBER = r"(0|[1-9][0-9]*)"  # ASCII digits, no leading zero: ``8.19.012`` is no version
_VERSION = re.compile(
    rf"{_NUMBER}(?:\.{_NUMBER})?(?:\.{_NUMBER})?(?:-([0-9A-Za-z][0-9A-Za-z.-]*))?"
    r"(?:\+[0-9A-Za-z.-]+)?",
    re.ASCII,
)
_COMPARATOR = re.compile(rf"(>=|<=|==|!=|>|<)\s*({_NUMBER}(?:\.{_NUMBER}){{0,2}})", re.ASCII)

ALERTS_INDEX_DEFAULT: Final = ".alerts-security.alerts-{space}"
INCIDENT_PREFIX_PATTERN: Final = r"^[A-Z]([A-Z0-9-]{0,14}[A-Z0-9])?$"
INCIDENT_ID_TAIL: Final = "-[0-9]{4}-[0-9]{4}-[0-9]{2}"  # -YYYY-MMDD-NN


class SiteError(ValueError):
    """The site profile does not allow what was asked (no such family, an unknown field role)."""


def strip_keyword(field: str) -> str:
    """The field a document returns for a ``.keyword`` sub-field: the name without the suffix."""
    return field.removesuffix(KEYWORD_SUFFIX)


# --------------------------------------------------------------------------- versions


@dataclass(frozen=True)
class VersionRange:
    """Versions a product may be: comparators joined by commas (``>=8.0,<10``); ``*`` is any
    version. A version is up to three numbers (``8.19.12``; ``9`` is 9.0.0) compared number by
    number, with an optional ``-pre-release`` and ``+build`` suffix; text that is no version
    (``8.19.12.1``, ``8.19.012``, ``8.19.12abc``) is never allowed. A pre-release
    (``8.19.12-SNAPSHOT``) compares as its numbers but never sits on a bound: it is not equal to
    the release, and ``>=9.0.0`` / ``<=9.0.0`` need it strictly above / below 9.0.0."""

    text: str
    bounds: tuple[tuple[str, tuple[int, int, int]], ...]

    @classmethod
    def parse(cls, text: str) -> VersionRange:
        spec = text.strip()
        if spec == "*":
            return cls(spec, ())
        bounds: list[tuple[str, tuple[int, int, int]]] = []
        for part in spec.split(","):
            match = _COMPARATOR.fullmatch(part.strip())
            if match is None:
                raise ValueError(
                    f"a version range is comparators such as '>=8.0,<10' or '*', not {text[:40]!r}"
                )
            version = parse_version(match[2])
            assert version is not None
            bounds.append((match[1], version))
        return cls(spec, tuple(bounds))

    def allows(self, version: str) -> bool:
        """Whether a product's version text (``8.19.12``, ``9.0.0-SNAPSHOT``) is in the range;
        a text that is no version is never allowed."""
        found = _read_version(version)
        if found is None:
            return False
        parsed, pre = found
        for op, bound in self.bounds:
            if pre:  # a pre-release is never on a bound
                holds = {
                    ">=": parsed > bound,
                    ">": parsed > bound,
                    "<=": parsed < bound,
                    "<": parsed < bound,
                    "==": False,
                    "!=": True,
                }[op]
            else:
                holds = {
                    ">=": parsed >= bound,
                    ">": parsed > bound,
                    "<=": parsed <= bound,
                    "<": parsed < bound,
                    "==": parsed == bound,
                    "!=": parsed != bound,
                }[op]
            if not holds:
                return False
        return True

    def __str__(self) -> str:
        return self.text

    def describe(self) -> str:
        """For a message: "the pinned 8.19.12" for one exact version, else "in the range ..."."""
        if len(self.bounds) == 1 and self.bounds[0][0] == "==":
            return "the pinned " + self.text.removeprefix("==").strip()
        return f"in the range {self.text}"


def _read_version(text: str) -> tuple[tuple[int, int, int], bool] | None:
    """(the three numbers, whether it is a pre-release) of a version text; None if it is none.
    The whole text must be the version: ASCII digits, up to three numbers, no leading zeros."""
    match = _VERSION.fullmatch(text.strip())
    if match is None:
        return None
    numbers = (int(match[1]), int(match[2] or 0), int(match[3] or 0))
    return numbers, match[4] is not None


def parse_version(text: str) -> tuple[int, int, int] | None:
    """``8.19.12`` as (8, 19, 12); missing parts are 0 and a ``-SNAPSHOT``/``+build`` suffix is
    ignored (``VersionRange.allows`` knows a pre-release). None when the text is no version."""
    found = _read_version(text)
    return None if found is None else found[0]


def _version_range(value: str) -> str:
    VersionRange.parse(value)
    return value


VersionSpec = Annotated[str, AfterValidator(_version_range)]


# --------------------------------------------------------------------------- licence


@dataclass(frozen=True)
class LicenceFacts:
    """What the Elasticsearch licence allows ARGUS to rely on. Writes (cases, tags, alert
    status) are allowed on every level of an active licence: the cases ARGUS writes need no paid
    feature (it never sends assignees, custom fields or a category). The features only a paid
    level has are switched on when the licence has them: case sub-feature privileges (roles that
    split cases into create, update, reopen) and case assignment. A licence that is not
    ``active`` (expired, invalid) allows reads only."""

    level: str
    status: str

    @property
    def active(self) -> bool:
        return self.status == "active"

    @property
    def writes_allowed(self) -> bool:
        return self.active

    @property
    def paid(self) -> bool:
        return self.active and self.level in PAID_LEVELS

    @property
    def sub_feature_privileges(self) -> bool:
        return self.paid

    @property
    def case_assignment(self) -> bool:
        return self.paid


# Platinum and above (a trial has every feature of Enterprise for its duration)
PAID_LEVELS: Final = frozenset({"platinum", "enterprise", "trial"})


# --------------------------------------------------------------------------- families


class Fields:
    """The field names of one family, by field role."""

    def __init__(self, role: Role, names: Mapping[str, str], time: str) -> None:
        self.role = role
        self._names = dict(names)
        self.time = time

    def __call__(self, logical: str) -> str:
        """The name the family queries for ``logical`` (a term, an aggregation, a sort)."""
        try:
            return self._names[logical]
        except KeyError:
            raise SiteError(f"{self.role.value} families have no field role {logical!r}") from None

    def source(self, logical: str) -> str:
        """The path a returned document holds ``logical`` under (no ``.keyword``)."""
        return strip_keyword(self(logical))

    def __repr__(self) -> str:
        return f"Fields({self.role.value}, {self._names}, time={self.time!r})"


def default_fields(role: Role) -> Fields:
    return Fields(role, FIELD_ROLES[role], DEFAULT_TIME_FIELD)


def _field_name(value: str) -> str:
    if not _FIELD_NAME.fullmatch(value):
        raise ValueError(f"{value[:40]!r} is not a field name")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LogFamily(_Model):
    """One family of log indices ARGUS may read."""

    name: str = Field(pattern=NAME_PATTERN, default="")
    role: Role
    pattern: str
    time_field: Annotated[str, AfterValidator(_field_name)] = DEFAULT_TIME_FIELD
    fields: dict[str, Annotated[str, AfterValidator(_field_name)]] = {}
    watch: bool = True
    """False: a template may read the family, but the health probe and the freshness reader do
    not watch it (the sign-in logs, which are read once a day)."""
    types: dict[str, str] = {}
    """The Elasticsearch type of a document field (its path without ``.keyword``) where it is not
    the one ``FIELD_TYPES`` gives its field role: ``keyword`` for what an Elastic Agent maps as a
    plain keyword, for example. One of ``MAPPING_TYPES``."""
    ignore_above: int = Field(default=DEFAULT_IGNORE_ABOVE, ge=MIN_IGNORE_ABOVE, le=32766)
    """The ``ignore_above`` of the family's keyword fields: a value longer than this is not
    indexed, so a request never carries one."""

    def __hash__(self) -> int:  # pydantic's own cannot hash the ``fields`` dict
        extra = tuple(sorted(self.fields.items()))
        types = tuple(sorted(self.types.items()))
        return hash(
            (self.name, self.role, self.pattern, self.time_field, self.watch, extra, types,
             self.ignore_above)
        )  # fmt: skip

    @model_validator(mode="before")
    @classmethod
    def _name_defaults_to_role(cls, data: Any) -> Any:
        if isinstance(data, dict) and not data.get("name") and data.get("role") is not None:
            return {**data, "name": str(Role(data["role"]).value)}
        return data

    @field_validator("pattern")
    @classmethod
    def _pattern(cls, value: str) -> str:
        if value.endswith("*"):
            if not _DAILY.fullmatch(value) or value.count("*") != 1:
                raise ValueError(
                    "a daily pattern starts with a lowercase letter or digit, uses only"
                    " lowercase letters, digits and . _ + - and ends in '-*', '.*' or '_*'"
                    " (no other wildcard), e.g. 'app-logs-nginx-*'"
                )
        elif not _EXACT.fullmatch(value):
            raise ValueError(
                "a pattern without '*' names one data stream or alias: it starts with a"
                " lowercase letter or digit and uses only lowercase letters, digits and . _ + -"
            )
        return value

    @model_validator(mode="after")
    def _checked(self) -> LogFamily:
        if self.role is Role.ALERTS:
            raise ValueError("the alerts index is site.alerts_index, not a log family")
        known = FIELD_ROLES[self.role]
        unknown = sorted(set(self.fields) - set(known))
        if unknown:
            raise ValueError(
                f"{self.role.value} families have no field role {', '.join(unknown)};"
                f" the roles are {', '.join(known)}"
            )
        bad = sorted(t for t in self.types.values() if t not in MAPPING_TYPES)
        if bad or not all(_FIELD_NAME.fullmatch(path) for path in self.types):
            raise ValueError(
                "types maps a field path to one of " + ", ".join(sorted(MAPPING_TYPES))
            )
        used = {strip_keyword(name) for name in self.field_names().values()}
        unused = sorted(
            path for path in self.types if path not in used or path.endswith(".keyword")
        )
        if unused or self.time_field in self.types:
            raise ValueError(
                "types names a field of the family's fields (a path without .keyword, not the"
                f" time field); {', '.join(unused or [self.time_field])} is none"
            )
        return self

    # ---- naming

    @property
    def daily(self) -> bool:
        """Daily indices ``<prefix>YYYY.MM.DD`` (the pattern ends in ``*``); else one stream."""
        return self.pattern.endswith("*")

    @property
    def prefix(self) -> str:
        """A daily family's index prefix (the pattern without its ``*``)."""
        if not self.daily:
            raise SiteError(f"{self.name} is a data stream, not daily indices")
        return self.pattern[:-1]

    def owns_index(self, name: str) -> bool:
        """Whether an index name belongs to this family (a daily index, the stream or one of
        its backing indices)."""
        if self.daily:
            return name.startswith(self.prefix)
        return name == self.pattern or name.startswith(f".ds-{self.pattern}-")

    def sample_names(self) -> tuple[str, ...]:
        """Concrete index names the family can have, for matching a rule's index pattern."""
        if self.daily:
            return tuple(self.prefix + day for day in _SAMPLE_DAYS)
        return (self.pattern, f".ds-{self.pattern}-2026.01.01-000001")

    @property
    def dataset(self) -> str:
        """What a rule's index entry must name to be about this family and not a wider set: a
        daily family's whole prefix (``acme-logs-squid-``), a data stream's name without
        its namespace (``logs-nginx.access-`` for ``logs-nginx.access-default``)."""
        if self.daily:
            return self.prefix
        head, dash, _ = self.pattern.rpartition("-")
        return head + dash if dash else self.pattern

    def covers(self, entry: str) -> bool:
        """Whether a rule's index entry (a name or a pattern, ``a,b`` lists allowed) reads this
        family and names its dataset: ``logs-nginx.access-*`` and ``logs-nginx.access-default``
        for the stream ``logs-nginx.access-default``, ``acme-logs-squid-*`` for the daily
        family of that prefix. An entry that is wider (``logs-*``, ``acme-logs-*``) does not:
        a rule that reads everything names no family."""
        dataset = self.dataset
        for part in entry.lower().split(","):
            name = part.strip().removeprefix(".ds-")
            if not name or name.startswith("-") or not name.startswith(dataset):
                continue
            if "*" not in name:  # one index: a day's index, the stream, a backing index
                if fnmatch.fnmatchcase(name, self.pattern) or fnmatch.fnmatchcase(
                    name, f"{self.pattern}-*"
                ):
                    return True
                continue
            glob = re.compile(".*".join(re.escape(piece) for piece in name.split("*")))
            if any(glob.fullmatch(sample) for sample in self.sample_names()):
                return True
        return False

    def probe_name(self, day: str) -> str:
        """The name the health probe asks about on ``day`` (``YYYY.MM.DD``)."""
        return self.prefix + day if self.daily else self.pattern

    # ---- fields

    def field_names(self) -> Mapping[str, str]:
        return {**FIELD_ROLES[self.role], **self.fields}

    def resolved(self) -> Fields:
        return Fields(self.role, self.field_names(), self.time_field)

    def value_limit(self, field: str) -> int | None:
        """The longest string value Elasticsearch indexes in ``field`` (a name as this family
        queries it) of this family: ``ignore_above`` for a ``.keyword`` sub-field and for a field
        whose type is ``keyword`` (by ``types`` or the field role's default). None: the family has
        no such field, or it is not a keyword (an address, a number, a time, analysed text)."""
        kind = self.field_types().get(strip_keyword(field))
        if kind is None:
            return None
        return self.ignore_above if field.endswith(KEYWORD_SUFFIX) or kind == "keyword" else None

    def field_types(self) -> dict[str, str]:
        """Each field the evidence templates use, by document path (no ``.keyword``), with its
        mapping type: the time field is a date, the rest by ``types`` or ``FIELD_TYPES``."""
        out = {self.time_field: "date"}
        for logical, name in self.field_names().items():
            path = strip_keyword(name)
            out.setdefault(
                path, self.types.get(path) or FIELD_TYPES[self.role].get(logical, "keyword")
            )
        return out


def names_family(index: str, family: LogFamily) -> bool:
    """Whether a rule's index entry (``kibana.alert.rule.indices``) reads this family: the entry
    covers only this family's indices, or it spells the family's name as a word
    (``acme-logs-squid*``, ``logs-squid.access-default``). An entry that covers more
    (``acme-logs-*``) names no family."""
    text = str(index).lower()
    if family.covers(text):
        return True
    return family.name in _TOKEN.split(text)


def family_pattern_ok(pattern: str) -> bool:
    """Whether a log family can have this pattern (``LogFamily`` accepts it): what an index,
    alias or data stream name must be for ``argus discover`` to propose it. Elasticsearch
    allows more (``@``, ``=``, accented letters, a leading ``_``), these are left out."""
    if pattern.endswith("*"):
        return bool(_DAILY.fullmatch(pattern)) and pattern.count("*") == 1
    return bool(_EXACT.fullmatch(pattern))


def index_name_ok(name: str) -> bool:
    """Whether a concrete index (a day's index, a data stream's ``.ds-`` backing index) can be
    named in a discovery mapping read."""
    return bool(_MAPPED_INDEX.fullmatch(name))


# --------------------------------------------------------------------------- the site


_ZONE_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_+/-]{0,63}")  # also what SQL may carry (``zone_sql``)
_HHMM = r"^([01][0-9]|2[0-3]):[0-5][0-9]$"
_PLAIN_TEXT = r"^[^\x00-\x1f\x7f-\x9f\u2028\u2029]+$"  # no control or line-separator characters
_LOWER_WORDS = r"^[a-z][a-z ,'-]*[a-z]$"  # plain lower-case words, for the middle of a sentence
_NOUN = r"^[a-z](?:[A-Za-z0-9 '-]*[A-Za-z0-9])?$"  # one noun phrase, no markup, no braces


# Names the tz database holds that Python and PostgreSQL read differently: a file of the machine
# (``localtime``), a rule set (``posixrules``), a test zone, and the four old region abbreviations
# that PostgreSQL's ``AT TIME ZONE`` reads as fixed offsets (the SQL days would drift an hour in
# summer from the investigation days). Name the region instead: Europe/Berlin, not CET.
_NOT_A_REGION = frozenset({"localtime", "posixrules", "Factory", "CET", "EET", "MET", "WET"})


def _registrable(domains: tuple[str, ...]) -> tuple[str, ...]:
    from argus.outside import psl

    shared = [d for d in domains if psl.registered_parent(d) is None]
    if shared:
        raise ValueError(
            f"{', '.join(shared)}: a public suffix that every organisation shares, not a domain of"
            " your own (give the whole domain, e.g. example.ac.in: its subdomains are included)"
        )
    return domains


def _zone(name: str) -> str:
    if name in _NOT_A_REGION:
        raise ValueError(
            f"{name!r} is not a region of the IANA database: name the region, such as"
            " Europe/Berlin or America/New_York"
        )
    if not _ZONE_NAME.fullmatch(name):
        raise ValueError(f"{name[:40]!r} is not a time zone of the IANA database")
    try:
        ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError, OSError):
        raise ValueError(f"{name[:40]!r} is not a time zone of the IANA database") from None
    return name


def _space(value: str) -> str:
    if not _SPACE.fullmatch(value):
        raise ValueError("a Kibana space id is lowercase letters, digits, _ and -")
    return value


class KibanaFeatures(_Model):
    """The ids of Kibana's Security and Cases features, which the capability map names in its
    ``ui:`` actions. They change between Kibana versions (``siemV2`` and
    ``securitySolutionCasesV3`` in 8.19); ``argus discover`` reads them from Kibana's features
    list (``feature_ids``), these are the defaults."""

    security: str = Field(default="siemV2", pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
    cases: str = Field(default="securitySolutionCasesV3", pattern=r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")


_SECURITY_FEATURE = re.compile(r"siem(?:V(\d{1,3}))?")
_CASES_FEATURE = re.compile(r"securitySolutionCases(?:V(\d{1,3}))?")


def feature_ids(answer: Any) -> KibanaFeatures:
    """The Security and Cases feature ids in the answer of Kibana's ``GET api/features`` (a list
    of features with an ``id``): the highest ``V<n>`` of ``siem`` and ``securitySolutionCases``
    (no suffix counts as 0). One the list does not have keeps its default."""
    ids = [
        item["id"]
        for item in (answer if isinstance(answer, list) else [])
        if isinstance(item, Mapping) and isinstance(item.get("id"), str)
    ]

    def newest(pattern: re.Pattern[str], default: str) -> str:
        found = [(int(m[1] or 0), i) for i in ids if (m := pattern.fullmatch(i))]
        return max(found)[1] if found else default

    defaults = KibanaFeatures()
    return KibanaFeatures(
        security=newest(_SECURITY_FEATURE, defaults.security),
        cases=newest(_CASES_FEATURE, defaults.cases),
    )


def _minutes(moment: time) -> int:
    return moment.hour * 60 + moment.minute


def _clock(minutes: int) -> time:
    return time(minutes // 60, minutes % 60)


MAX_TI_SOURCES: Final = 8
TI_SCHEMAS: Final = ("ecs", "ioc")  # threat.indicator.* (ECS) or ioc_type / ioc_value / ...
TI_MODES: Final = ("mirror", "lookup")  # one complete bounded read, or per value


class TiSource(_Model):
    """One threat-intel source: an index or index pattern, how its documents are written
    (``schema``: ``ecs`` = ECS ``threat.indicator.*`` as Elastic's Threat Intel integration
    writes it, ``ioc`` = ``ioc_type`` / ``ioc_value`` / ``intel_source`` rows) and how ARGUS
    reads it (``mode``: ``mirror`` = the whole index in one complete bounded read, kept in
    ARGUS's store; ``lookup`` = the values asked about, per request, cached for a day). The
    source's id everywhere (stored rows, freshness, evidence, sentences) is its index."""

    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    index: str = Field(pattern=f"^{_CHECKED.pattern}$")
    schema_: Literal["ecs", "ioc"] = Field(alias="schema")
    mode: Literal["mirror", "lookup"]


class Organisation(_Model):
    """Who ARGUS works for, as the pages, the PDF footer and the block-list sign-off say it."""

    name: str = Field(default="your organisation", min_length=1, max_length=80, pattern=_PLAIN_TEXT)
    """The organisation's name ("Example University")."""
    short_name: str = Field(default="SOC", min_length=1, max_length=40, pattern=_PLAIN_TEXT)
    """The name of its security team ("ACME SOC")."""
    kind: str = Field(default="organisation", pattern=_LOWER_WORDS, max_length=40)
    """What kind of organisation it is, as a lower-case noun ("university"): "a university
    network" in the prompts a model reads, "University-managed" on a case page."""
    units: str = Field(default="department, team or lab", pattern=_LOWER_WORDS, max_length=60)
    """Who an owner may be told through, as "a, b or c" ("department, hostel or lab")."""
    reviewers: str = Field(default="analysts", pattern=_LOWER_WORDS, max_length=60)
    """Who reads ARGUS's reports ("research and teaching assistants")."""


class QuietHours(_Model):
    """A daily UTC window in which ARGUS asks the SIEM for nothing that is optional: the time
    its indices are created and old ones deleted. ``start`` equal to ``end`` is no window; an
    ``end`` before ``start`` is a window that crosses midnight."""

    start: str = Field(default="00:00", pattern=_HHMM)
    end: str = Field(default="01:30", pattern=_HHMM)

    @field_validator("start", "end", mode="before")
    @classmethod
    def _quoted(cls, value: Any) -> Any:
        if not isinstance(value, str):  # YAML reads an unquoted 22:00 as the number 1320
            raise ValueError('write the time in quotes, as "22:00"')
        return value

    @property
    def none(self) -> bool:
        return self.start == self.end

    @property
    def start_time(self) -> time:
        return time.fromisoformat(self.start)

    @property
    def end_time(self) -> time:
        return time.fromisoformat(self.end)

    @property
    def length(self) -> timedelta:
        """How long the window lasts (zero for none; across midnight it is counted over it)."""
        if self.none:
            return timedelta(0)
        gap = _minutes(self.end_time) - _minutes(self.start_time)
        return timedelta(minutes=gap if gap > 0 else gap + 24 * 60)

    def holds_time(self, moment: time) -> bool:
        """Whether a time of day (UTC) is inside the window."""
        if self.none:
            return False
        now, start, end = _minutes(moment), _minutes(self.start_time), _minutes(self.end_time)
        return start <= now < end if start < end else (now >= start or now < end)

    def holds(self, at: datetime) -> bool:
        """Whether the moment ``at`` (any zone) is inside the window."""
        return self.holds_time(at.astimezone(UTC).time())

    def overlaps(self, start: time, end: time) -> bool:
        """Whether the daily interval [start, end) (UTC; ``end`` equal to or before ``start`` runs
        past midnight) shares a minute with the window."""
        if self.none:
            return False
        first, last = _minutes(start), _minutes(end)
        span = last - first if last > first else last - first + 24 * 60
        return any(self.holds_time(_clock((first + n) % (24 * 60))) for n in range(span))

    def next_end(self, now: datetime) -> datetime:
        """The first moment after ``now`` at which the window is over (``now`` itself when it is
        not inside it)."""
        if not self.holds(now):
            return now
        at = now.astimezone(UTC)
        end = datetime.combine(at.date(), self.end_time, UTC)
        return end if end > at else end + timedelta(days=1)

    def words(self, lead: timedelta = timedelta(0)) -> str:
        """The window in a sentence: "00:00 to 01:30 UTC"; with a ``lead`` it begins that long
        before ("23:40 to 01:30 UTC" for a session of 20 minutes that must end before it)."""
        if self.none:
            return "no quiet hours"
        begin = (_minutes(self.start_time) - round(lead.total_seconds() / 60)) % (24 * 60)
        return f"{_clock(begin):%H:%M} to {self.end} UTC"

    def __str__(self) -> str:
        return "no quiet hours" if self.none else f"{self.start}-{self.end} UTC"


class SiteSettings(_Model):
    """Everything about this organisation's Elastic and words (``site`` in the settings)."""

    families: tuple[LogFamily, ...] = ()
    """The log families ARGUS may read; none until one is configured (``argus discover``)."""
    space: Annotated[str, AfterValidator(_space)] = "default"
    """The Kibana space that holds the Security alerts."""
    alerts_index: str = ALERTS_INDEX_DEFAULT
    """The alerts index (alias) of that space; ``{space}`` is the space id."""
    log_patterns: tuple[Annotated[str, Field(pattern=f"^{_CHECKED.pattern}$")], ...] = ()
    """The index patterns the self-test and the ``see_logs`` capability check ``read`` on. Left
    out: each family's own pattern. Give them when one wider pattern is what the key is granted
    (``acme-logs-*``)."""
    ti_sources: tuple[TiSource, ...] = Field(default=(), max_length=MAX_TI_SOURCES)
    """The threat-intel sources ARGUS may read, each an index (or index pattern) with its schema
    and mode; the self-test requires ``read`` on each. None by default: a site without one has
    threat intel off, and ARGUS says so wherever it reports intel."""
    elastic_versions: VersionSpec = ">=8.0,<10"
    """Elasticsearch versions ARGUS is run against (the self-test refuses others)."""
    kibana_versions: VersionSpec = ">=8.0,<10"
    """Kibana versions ARGUS writes to (a write run refuses others)."""
    kibana_features: KibanaFeatures = KibanaFeatures()
    """Kibana's Security and Cases feature ids (``argus discover`` reads them from Kibana)."""
    own_networks: Annotated[tuple[IPv4Network | IPv6Network, ...], BeforeValidator(_items)] = ()
    """The organisation's public networks (private ranges are always its own)."""
    own_domains: Annotated[
        tuple[Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{0,252}$")], ...],
        BeforeValidator(_items),
        AfterValidator(_registrable),
    ] = ()
    """The organisation's own domains (``example.org``, ``example.ac.in``): each covers every
    name under it (``mail.example.org``). A public suffix every organisation shares (``in``,
    ``ac.in``, ``co.uk``) is refused: it would make the whole suffix "ours"."""
    incident_id_prefix: str = Field(default="IR", pattern=INCIDENT_PREFIX_PATTERN)
    """The prefix of incident case ids: ``<prefix>-YYYY-MMDD-NN``. Capital letters, digits and
    ``-`` (not at the end), at most 16 characters: the database check allows that."""
    timezone: Annotated[str, AfterValidator(_zone)] = "UTC"
    """The zone people read times and days in. It is also the zone of the investigation day
    (an investigation id depends on it): choose it once, before the first alert is stored."""
    timezone_label: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9+:-]{0,11}$")
    """How a time in that zone is labelled ("IST"). Left out, the zone's offset at the moment
    shown ("UTC-05:00" in winter, "UTC-04:00" in summer, "UTC" at none), the same on every page."""
    own_network_noun: str = Field(default="your network", pattern=_NOUN, max_length=40)
    """The word for the organisation's own network in sentences ("campus", "the plant"): letters,
    digits, spaces, hyphens and apostrophes, beginning with a lower-case letter (it is used in the
    middle of a sentence). A noun that needs "the" carries it ("the plant"); one used after "on"
    ("on campus") is written as it reads there."""
    organisation: Organisation = Organisation()
    quiet_hours: QuietHours = QuietHours()

    @model_validator(mode="after")
    def _sources_unique(self) -> SiteSettings:
        names = [source.index for source in self.ti_sources]
        repeated = sorted({n for n in names if names.count(n) > 1})
        if repeated:
            raise ValueError(
                "two threat-intel sources share an index (" + ", ".join(repeated) + ")"
            )
        return self

    @model_validator(mode="after")
    def _families_unique(self) -> SiteSettings:
        names = [family.name for family in self.families]
        repeated = sorted({n for n in names if names.count(n) > 1})
        if repeated:
            raise ValueError(
                "two families share a name (" + ", ".join(repeated) + "): give each its own"
                " 'name' when a role has more than one"
            )
        if "{space}" not in self.alerts_index and "{" in self.alerts_index:
            raise ValueError("alerts_index may only use {space}")
        if not _ALERTS_NAME.fullmatch(self.alerts_index_name):
            raise ValueError("alerts_index must be an index or alias name")
        return self

    # ---- the alerts index

    def alerts_index_of(self, space: str) -> str:
        return self.alerts_index.replace("{space}", space)

    def alerts_backing_of(self, space: str) -> str:
        """The prefix of a space's alerts backing indices (``.internal.<alias>-000001``)."""
        name = self.alerts_index_of(space)
        return f".internal{name}-" if name.startswith(".") else f".internal.{name}-"

    @property
    def alerts_index_name(self) -> str:
        return self.alerts_index_of(self.space)

    @property
    def alerts_backing_prefix(self) -> str:
        return self.alerts_backing_of(self.space)

    # ---- threat-intel sources

    @property
    def ti_indices(self) -> tuple[str, ...]:
        """The indices (or patterns) of the threat-intel sources: what the gateway may read."""
        return tuple(source.index for source in self.ti_sources)

    @property
    def ti_mirrors(self) -> tuple[TiSource, ...]:
        """The sources read whole into ARGUS's own store."""
        return tuple(s for s in self.ti_sources if s.mode == "mirror")

    @property
    def ti_lookups(self) -> tuple[TiSource, ...]:
        """The sources asked per value."""
        return tuple(s for s in self.ti_sources if s.mode == "lookup")

    def ti_source(self, index: str) -> TiSource | None:
        return next((s for s in self.ti_sources if s.index == index), None)

    @property
    def ti_default_lookup(self) -> TiSource | None:
        """The lookup source a stored ``ti.lookup`` request without an index meant: the first
        ``ioc`` one (those requests were written when the site had exactly one)."""
        return next((s for s in self.ti_lookups if s.schema_ == "ioc"), None)

    # ---- families

    def family(self, name: str) -> LogFamily | None:
        return next((f for f in self.families if f.name == name), None)

    def of_role(self, role: Role) -> tuple[LogFamily, ...]:
        return tuple(f for f in self.families if f.role is role)

    @property
    def watched_sources(self) -> tuple[str, ...]:
        """The families the health probe and the freshness reader watch, in order."""
        return tuple(f.name for f in self.families if f.watch)

    @property
    def all_sources(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.families)

    @property
    def checked_log_patterns(self) -> tuple[str, ...]:
        """The index patterns the privilege checks (the self-test, ``see_logs``) ask ``read``
        on: ``log_patterns`` when the site gives them, else every family's own pattern. None
        when the site has neither: nothing is asked of logs it does not read."""
        if self.log_patterns:
            return self.log_patterns
        return tuple(dict.fromkeys(f.pattern for f in self.families))

    @property
    def elastic_range(self) -> VersionRange:
        return VersionRange.parse(self.elastic_versions)

    @property
    def kibana_range(self) -> VersionRange:
        return VersionRange.parse(self.kibana_versions)


# --------------------------------------------------------------------------- the active site

_ACTIVE: SiteSettings = SiteSettings()


def active() -> SiteSettings:
    """The site profile of this process (the neutral defaults until ``activate``)."""
    return _ACTIVE


def activate(site: SiteSettings) -> None:
    """Make ``site`` the process's site profile (``load_settings`` does, once)."""
    global _ACTIVE
    _ACTIVE = site


@contextmanager
def using(site: SiteSettings) -> Iterator[SiteSettings]:
    """``site`` is the active one inside the block (tests)."""
    global _ACTIVE
    before = _ACTIVE
    _ACTIVE = site
    try:
        yield site
    finally:
        _ACTIVE = before


# --------------------------------------------------------------------------- time and words


def zone() -> ZoneInfo:
    return ZoneInfo(_ACTIVE.timezone)


def zone_name() -> str:
    return _ACTIVE.timezone


# Instants through 2026 at which the database's reading of the zone is compared with Python's:
# winter, summer and the weeks around both hemispheres' clock changes.
ZONE_PROBES: Final = tuple(
    datetime(2026, month, day, 12, tzinfo=UTC)
    for month, day in (
        (1, 15), (3, 15), (4, 15), (6, 15), (7, 15), (9, 15), (10, 15), (11, 15), (12, 15),
    )
)  # fmt: skip


def zone_disagreements(name: str, readings: Iterable[tuple[datetime, datetime]]) -> list[str]:
    """The instants at which the database's local time (``instant AT TIME ZONE name``, a time
    without zone) is not what ``zoneinfo`` says: the SQL report days and the investigation days
    would then count different days. ``readings``: (instant, the database's local time)."""
    zone_info = ZoneInfo(name)
    return [
        f"{at:%Y-%m-%d} (database {theirs:%H:%M}, Python {at.astimezone(zone_info):%H:%M})"
        for at, theirs in readings
        if at.astimezone(zone_info).replace(tzinfo=None) != theirs.replace(tzinfo=None)
    ]


def zone_sql() -> str:
    """The zone as a quoted SQL literal for ``AT TIME ZONE`` (the name is checked at load: it
    holds letters, digits and ``_ + / -`` only)."""
    return "'" + _ACTIVE.timezone + "'"


def zone_label(moment: datetime | None = None) -> str:
    """How a time in the site's zone is labelled: ``site.timezone_label`` if given
    ("IST"), else the zone's offset at ``moment`` (now if none): ``UTC`` at none, ``UTC+05:30``,
    ``UTC-04:00``. The offset, not the tz database's abbreviation (CEST, JST, EDT), because the
    browser's locale data names the same zone differently (``GMT+2``) and the page, the PDF and
    the Kibana text must read one way (``lib/site.ts`` has the same rule)."""
    if _ACTIVE.timezone_label is not None:
        return _ACTIVE.timezone_label
    offset = (moment or datetime.now(UTC)).astimezone(zone()).utcoffset()
    minutes = round(offset.total_seconds() / 60) if offset is not None else 0
    if minutes == 0:
        return "UTC"
    sign = "+" if minutes > 0 else "-"
    hours, minutes = divmod(abs(minutes), 60)
    return f"UTC{sign}{hours:02d}:{minutes:02d}"


def incident_prefix() -> str:
    return _ACTIVE.incident_id_prefix


def incident_id_regex() -> re.Pattern[str]:
    """What an incident ID of this site looks like: ``<prefix>-YYYY-MMDD-NN``."""
    return re.compile(re.escape(_ACTIVE.incident_id_prefix) + INCIDENT_ID_TAIL)


_DETERMINERS = ("the ", "your ", "our ", "my ")
_AN = re.compile(r"(?:[aeio]|u(?!ni(?!n)|se|su|ti|r[aiu])|hour|honest|honou?r|heir)", re.I)
_A = re.compile(r"(?:eu|one\b|once\b)", re.I)


def article(word: str) -> str:
    """``a`` or ``an`` before ``word`` by its sound: an office, an hour; a university, a unit, a
    European, a one-way."""
    return "an" if _AN.match(word) and not _A.match(word) else "a"


def noun() -> str:
    """The word for the organisation's own network as a modifier: "campus" in "a campus device"
    ("your network" by default, "plant" for "the plant")."""
    word = _ACTIVE.own_network_noun
    return word[4:] if word.lower().startswith("the ") else word


def the_noun() -> str:
    """With "the": "the campus"; a noun that begins with the, your, our or my is used as it
    stands ("your network")."""
    word = _ACTIVE.own_network_noun
    return word if word.lower().startswith(_DETERMINERS) else f"the {word}"


def a_noun() -> str:
    """With "a": "a campus", "an office network"; none before the, your, our or my."""
    word = _ACTIVE.own_network_noun
    if word.lower().startswith(_DETERMINERS):
        return word
    return f"{article(word)} {word}"


def noun_capital() -> str:
    """``noun()`` with a capital first letter, for the start of a sentence or a heading."""
    word = noun()
    return word[:1].upper() + word[1:]


def own(thing: str) -> str:
    """``thing`` that belongs to the organisation's own network: "campus device", "device
    of your network" (a noun that begins with your, our or my), "office network device"."""
    word = _ACTIVE.own_network_noun
    if word.lower().startswith(("your ", "our ", "my ")):
        return f"{thing} of {word}"
    return f"{noun()} {thing}"


def a_own_or(thing: str, *others: str) -> str:
    """``thing`` of the organisation's own network or of another kind, as one phrase: "a campus,
    private or special-use address"; "an address in your network, or a private or
    special-use one" (a noun that begins with the, your, our or my)."""
    word = _ACTIVE.own_network_noun
    if not word.lower().startswith(_DETERMINERS):
        adjectives = [noun(), *others]
        listed = ", ".join(adjectives[:-1]) + f" or {adjectives[-1]}"
        return f"{article(adjectives[0])} {listed} {thing}"
    head = thing if thing == "one" else f"{article(thing)} {thing}"
    return f"{head} in {word}, or {article(others[0])} {' or '.join(others)} one"


def where() -> str:
    """The word as the site gave it, for "on campus", "on the plant", "on your network":
    no "the" is added, so a noun that needs one ("the plant") carries it in its setting."""
    return _ACTIVE.own_network_noun


def a_own(thing: str) -> str:
    """``own(thing)`` with its article: "a campus device", "an office network device", "a
    device of your network"."""
    phrase = own(thing)
    return f"{article(phrase)} {phrase}"


def _up(text: str) -> str:
    return text[:1].upper() + text[1:]


_SAY = re.compile(
    r"\{(A_own|a_own|Own|own|The|the|Noun|noun|where|source|team|org|logs|quiet|a_kind|Kind|kind"
    r"|units|units2|reviewers)(?::([^{}]*))?\}"
)


def say(text: str) -> str:
    """``text`` with the site's words put in for the tokens a module writes its sentences with, so
    a sentence held as data still follows the site: ``{own:host}`` / ``{a_own:host}`` (a campus
    host), ``{the}``, ``{noun}``, ``{where}`` (the word as given), ``{source:proxy}`` (the name of
    the site's family of that role), ``{team}``, ``{org}``, ``{kind}``, ``{units}``,
    ``{reviewers}``, ``{logs}`` and ``{quiet}``; capitalised forms start a sentence. Text without
    a token is returned as it is."""

    def put(match: re.Match[str]) -> str:
        kind, arg = match[1], match[2] or ""
        if not arg and kind in ("own", "a_own", "A_own", "Own", "source"):
            return match[0]  # these take a thing or a role
        if kind == "own":
            return own(arg)
        if kind == "Own":
            return _up(own(arg))
        if kind == "where":
            return where()
        if kind == "a_own":
            return a_own(arg)
        if kind == "A_own":
            return _up(a_own(arg))
        if kind == "the":
            return the_noun()
        if kind == "The":
            return _up(the_noun())
        if kind == "noun":
            return noun()
        if kind == "Noun":
            return noun_capital()
        if kind == "team":
            return _ACTIVE.organisation.short_name
        if kind == "org":
            return _ACTIVE.organisation.name
        if kind == "kind":
            return _ACTIVE.organisation.kind
        if kind == "Kind":
            return _up(_ACTIVE.organisation.kind)
        if kind == "a_kind":
            return f"{article(_ACTIVE.organisation.kind)} {_ACTIVE.organisation.kind}"
        if kind == "units":
            return _ACTIVE.organisation.units
        if kind == "units2":  # the first two: "department or hostel"
            first = re.split(r",\s*|\s+or\s+", _ACTIVE.organisation.units)[:2]
            return " or ".join(first)
        if kind == "reviewers":
            return _ACTIVE.organisation.reviewers
        if kind == "quiet":
            quiet = _ACTIVE.quiet_hours
            return "no hour" if quiet.none else f"{quiet.start} and {quiet.end} UTC"
        if kind == "logs":
            return ", ".join(_ACTIVE.checked_log_patterns) or "the log indices"
        return source_for(Role(arg))

    return _SAY.sub(put, text)


class Words(Mapping[str, str]):
    """A table of sentences that are written with ``say`` tokens and read through ``say``, so the
    words of the active site come out on every lookup."""

    def __init__(self, raw: Mapping[str, str]) -> None:
        self._raw = dict(raw)

    def __getitem__(self, key: str) -> str:
        return say(self._raw[key])

    def __iter__(self) -> Iterator[str]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)


def organisation() -> Organisation:
    return _ACTIVE.organisation


def own_domains(*more: Iterable[str]) -> tuple[str, ...]:
    """The organisation's own domain suffixes, lower case and without dots at the ends:
    ``site.own_domains`` first, then any in ``more`` (an older setting that still names some), each
    once."""
    found: dict[str, None] = {}
    for domains in (_ACTIVE.own_domains, *more):
        for domain in domains:
            if cleaned := domain.strip().lower().strip(".").strip():
                found.setdefault(cleaned)
    return tuple(found)


def own_networks() -> tuple[IPv4Network | IPv6Network, ...]:
    return _ACTIVE.own_networks


def quiet_hours() -> QuietHours:
    return _ACTIVE.quiet_hours


def in_quiet_hours(at: datetime) -> bool:
    """Whether ``at`` is inside the site's quiet hours (default 00:00-01:30 UTC)."""
    return _ACTIVE.quiet_hours.holds(at)


def _wild(pattern: str) -> re.Pattern[str]:
    """An index expression as Elasticsearch reads it: ``*`` is the only wildcard."""
    return re.compile(".*".join(re.escape(part) for part in pattern.split("*")))


def _covers(family: LogFamily, pattern: str) -> bool:
    """Whether the index expression ``pattern`` covers an index of the family (for example
    ``acme-logs-squid-2026.10.09``): ``acme-logs-*``, ``acme-*`` and ``*`` cover
    every family; ``acme-logs-squid-*`` covers the squid family's alone."""
    wild = _wild(pattern)
    names = list(family.sample_names())
    if family.daily and pattern.startswith(family.prefix):
        # a pattern that fixes part of the day: try its own
        tail = pattern[len(family.prefix) :]
        names += [
            family.prefix + t
            for t in (tail.replace("*", ""), tail.replace("*", "0"))
            if _DAY_START.fullmatch(t)
        ]
    return any(wild.fullmatch(name) for name in names)


def rule_families(
    indices: Sequence[str], known: Sequence[str] | None = None
) -> tuple[LogFamily, ...]:
    """The log families a rule reads, from its own indices (``kibana.alert.rule.indices``), in
    the site's order. An entry may list indices (``a,b``), and a name may be a pattern: a family
    counts when the pattern covers one of its indices (``acme-logs-*`` reads them all), or when it
    is a whole word of the name (``logs-squid.access-default``).
    ``-pattern`` leaves out what it covers, as Elasticsearch reads it. ``known``: the family
    names to consider (default: the watched ones, the families the investigation can name)."""
    profile = active()
    wanted = profile.watched_sources if known is None else known
    families = [f for f in profile.families if f.name in wanted]
    found: set[str] = set()
    for entry in indices:
        for part in str(entry).lower().split(","):
            name = part.strip()
            if not name:
                continue
            if name.startswith("-"):
                found -= {f.name for f in families if _covers(f, name[1:])}
                continue
            words = {w for w in _TOKEN.split(name) if w}
            found |= {f.name for f in families if f.name in words or _covers(f, name)}
    return tuple(f for f in families if f.name in found)


def family_of_rule(role: Role, indices: Sequence[str] | None) -> LogFamily | None:
    """The family of ``role`` that a rule's indices point at: the first one an index entry names
    (as ``reads`` does: the entry covers only that family or spells its name), else the first
    among those the rule's patterns cover (as the investigation's catalogue reads the rule).
    None when the rule points at none of them."""
    families = active().of_role(role)
    if not indices or not families:
        return None
    for family in families:
        if any(names_family(entry, family) for entry in indices):
            return family
    covered = {f.name for f in rule_families(indices, known=[f.name for f in families])}
    return next((f for f in families if f.name in covered), None)


def source_for(role: Role, indices: Sequence[str] | None = None) -> str:
    """The source key of the family of ``role`` a rule reads (``indices``: its
    ``kibana.alert.rule.indices``); the first family with ``role`` when the rule points at none
    (or ``indices`` is not given); the role's own name when the site has none (a request for it
    is then refused by the gateway: not a log source)."""
    families = active().of_role(role)
    if not families:
        return role.value
    return (family_of_rule(role, indices) or families[0]).name


def source_param(role: Role, indices: Sequence[str] | None) -> str | None:
    """The ``source`` an evidence request carries for a rule's ``indices``: None while the site
    has at most one family of ``role`` (the request is what it always was, its key unchanged);
    with two or more, the family's name, written into the request so the stored evidence says
    which log was read. A rule that points at none of them reads the first, and says so."""
    families = active().of_role(role)
    if len(families) < 2:
        return None
    named = family_of_rule(role, indices)
    if named is None:
        log.warning(
            "the rule's indices name none of this site's %s families: reading %s, the first",
            role.value,
            families[0].name,
        )
        return families[0].name
    return named.name


def fields_for(role: Role, source: str | None = None) -> Fields:
    """The field names of the family ``source`` when it is a family of ``role``, else of the
    first family with ``role`` (ECS names when the site has none)."""
    families = active().of_role(role)
    for family in families:
        if family.name == source:
            return family.resolved()
    return families[0].resolved() if families else default_fields(role)


def all_fields(role: Role) -> tuple[Fields, ...]:
    """The field names of every family with ``role`` (ECS names when the site has none): what
    a template's allowlists hold, since one template reads any of them."""
    families = active().of_role(role)
    return tuple(f.resolved() for f in families) or (default_fields(role),)


def keyword_chars(source: str | None = None) -> int:
    """The longest value a keyword field of the family ``source`` indexes (``ignore_above``); for
    no family named, the smallest of the site's (256 when it has none)."""
    families = active().families
    if source is not None:
        family = active().family(source)
        if family is not None:
            return family.ignore_above
    return min((f.ignore_above for f in families), default=DEFAULT_IGNORE_ABOVE)


def value_limit(indices: Iterable[str], field: str) -> int | None:
    """The longest string value indexed in ``field`` of the families the index names belong to (the
    smallest where the request reads two); None when none of those families has such a keyword
    field (the caller applies Elasticsearch's own defaults then)."""
    limits = []
    for name in indices:
        source = source_of_index(name)
        family = active().family(source) if source is not None else None
        limit = family.value_limit(field) if family is not None else None
        if limit is not None:
            limits.append(limit)
    return min(limits) if limits else None


def fields_of(source: str) -> Fields:
    family = active().family(source)
    if family is None:
        raise SiteError(f"{source[:40]} is not a log family of this site")
    return family.resolved()


def reads(indices: Sequence[str], role: Role) -> bool:
    """Whether a rule (its ``kibana.alert.rule.indices``) reads a family of ``role``."""
    return any(names_family(i, f) for f in active().of_role(role) for i in indices)


def roles_read(indices: Sequence[str], among: Sequence[Role]) -> list[Role]:
    """The roles among ``among`` a rule reads, in the order given."""
    return [role for role in among if reads(indices, role)]


def source_of_index(name: str) -> str | None:
    """The source key of the family an index name (a daily index, a stream or a backing
    index) belongs to."""
    for family in active().families:
        if family.owns_index(name):
            return family.name
        if family.daily and name.startswith(f".ds-{family.prefix}"):
            return family.name
    return None
