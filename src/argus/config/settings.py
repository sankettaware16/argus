"""Typed ARGUS settings. Sources, highest priority first: keyword arguments to
:func:`load_settings`, systemd's credential directory (``$CREDENTIALS_DIRECTORY``), environment
variables ``ARGUS_<SECTION>__<KEY>``, the ``.env`` file, the YAML file (``config/argus.yaml`` or
``$ARGUS_CONFIG``), then the defaults below. Unknown names are errors everywhere, and errors name
the setting and where it was set, never its value (:mod:`argus.config.sources`). Under custody
(``custody.role``) secrets come only from the credential directory (:data:`CUSTODY_SECRETS`)."""

from __future__ import annotations

import difflib
import getpass
import os
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import date, time, timedelta
from ipaddress import IPv4Network, IPv6Network
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Any, Literal, get_args

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PrivateAttr,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.fields import FieldInfo
from pydantic_core import InitErrorDetails, PydanticCustomError
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict
from sqlalchemy import URL

from argus.config.durations import Duration, bounded_duration
from argus.config.errors import ConfigError, safe, show_name
from argus.config.sources import (
    CONFIG_ENV_VAR,
    CREDENTIALS_ENV_VAR,
    Layer,
    credentials_layer,
    dotenv_layer,
    environment_layer,
    overrides_layer,
    section_model,
    yaml_layer,
)
from argus.notices.address import parse_address, parse_host
from argus.site import SiteSettings, activate

__all__ = [
    "CONFIG_ENV_VAR",
    "CUSTODY_SECRETS",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_ENV_FILE",
    "MAX_NAME_BYTES",
    "ConfigError",
    "CustodyRole",
    "CustodySettings",
    "DatabaseRole",
    "DatabaseSettings",
    "HistorySettings",
    "LoggingSettings",
    "Settings",
    "load_settings",
    "resolve_config_path",
    "secret_settings",
    "usable_password",
]

DEFAULT_CONFIG_PATH = Path("config/argus.yaml")
DEFAULT_ENV_FILE = Path(".env")
MAX_RECIPIENTS = 20
MAX_NAME_BYTES = 63  # PostgreSQL silently truncates a longer database or role name
_MAX_REPORTED_PROBLEMS = 50


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HistorySettings(_Section):
    window: Annotated[Duration, bounded_duration(timedelta(hours=1), timedelta(days=365))] = (
        timedelta(days=5)
    )
    """How far back ARGUS looks: backfill depth and entity-history lookback."""


class MemorySettings(_Section):
    window: Annotated[Duration, bounded_duration(timedelta(days=1), timedelta(days=3650))] = (
        timedelta(days=90)
    )
    """How long ARGUS keeps alerts, entity facts and baselines locally: an
    investigation older than this, with its alerts, reviews and dossiers, is removed by the
    purge unless a hold keeps it. Never shorter than ``history.window`` in effect: the
    purge keeps at least what the collector may read again."""


class RetentionSettings(_Section):
    """How long personal data is kept before the purge removes it. Each period is at least
    ``history.window`` in effect, so the collector never reads back what the purge took. Audit
    events and case records are not purged; open cases, pending approvals and the gold set are
    held."""

    raw_source: Annotated[Duration, bounded_duration(timedelta(days=1), timedelta(days=365))] = (
        timedelta(days=30)
    )
    """An alert's raw ``_source`` as the SIEM stored it (its normalized form stays until
    ``memory.window``)."""
    evidence: Annotated[Duration, bounded_duration(timedelta(days=1), timedelta(days=3650))] = (
        timedelta(days=90)
    )
    """An evidence snapshot (the log rows a query returned), counted from the investigation's
    newest review; what the query was and what it found stay."""
    quarantine: Annotated[Duration, bounded_duration(timedelta(days=1), timedelta(days=365))] = (
        timedelta(days=30)
    )
    """A quarantined alert's raw ``_source`` (its reason names a field, never a value)."""
    app_logs: Annotated[Duration, bounded_duration(timedelta(days=1), timedelta(days=365))] = (
        timedelta(days=14)
    )
    """ARGUS's own logs. They go to the systemd journal, which only root can trim: the purge
    reports this period and a root step sets it (docs/runbooks/retention.md)."""
    scheduled: bool = False
    """Whether ``argus purge run --apply --scheduled`` (argus-purge.timer) may delete: the
    schedule is a separate approval from the first purge. Off until then."""


def _check_name(name: str) -> str:
    """A database or role name: not blank, and short enough that PostgreSQL keeps all of it."""
    if not name.strip():
        raise ValueError("must not be blank")
    if "\x00" in name:
        raise ValueError("must not contain a NUL character")
    try:
        size = len(name.encode())
    except UnicodeEncodeError:  # e.g. undecodable bytes in an environment variable
        raise ValueError("must be valid UTF-8 text") from None
    if size > MAX_NAME_BYTES:
        raise ValueError(
            f"must be at most {MAX_NAME_BYTES} bytes in UTF-8 (PostgreSQL cuts longer names short)"
        )
    return name


_Name = Annotated[str, AfterValidator(_check_name)]


def _check_host(host: str) -> str:
    """No NUL: libpq would cut the host there."""
    if "\x00" in host:
        raise ValueError("must not contain a NUL character")
    return host


def usable_password(value: str) -> None:
    """ValueError (naming no value) unless libpq can take ``value`` as a password.

    libpq reads a password as a C string, so a NUL would silently cut it short (and drop every
    connection parameter written after it), and it sends UTF-8.
    """
    if "\x00" in value:
        raise ValueError("must not contain a NUL character (libpq would cut the password there)")
    try:
        value.encode()
    except UnicodeEncodeError:
        raise ValueError("must be valid UTF-8 text") from None


def _check_password(value: SecretStr | None) -> SecretStr | None:
    if value is not None:
        usable_password(value.get_secret_value())
    return value


_Password = Annotated[SecretStr | None, AfterValidator(_check_password)]


DatabaseRole = Literal["app", "api", "owner", "writer"]
"""Who connects: ``app`` is the runtime role ARGUS runs as; ``api`` the web's own login
(used by ``argus web`` when ``web.database_role`` says so); ``writer`` the case writer's own
login (it alone may make the outbox moves); ``owner`` owns the schema and runs the
``argus db`` commands (bootstrap, migrations)."""


class DatabaseSettings(_Section):
    host: Annotated[str, AfterValidator(_check_host)] = Field(default="127.0.0.1", min_length=1)
    port: int = Field(default=55432, ge=1, le=65535)
    name: _Name = "argus"
    user: _Name = "argus_app"
    """Runtime login role: no superuser, owns nothing, only the privileges migrations grant."""
    password: _Password = None
    owner_user: _Name = "argus"
    """Owns ARGUS's tables and runs ``argus db``; on the local Docker server, its superuser."""
    owner_password: _Password = None
    api_user: _Name = "argus_api"
    """The web's own login: a member of ``argus_web`` only, with exactly the grants the
    web needs. ``argus db bootstrap`` makes it once ``api_password`` is set."""
    api_password: _Password = None
    writer_user: _Name = "argus_writer_app"
    """The case writer's own login: a member of ``argus_writer`` only (not of
    ``argus_runtime``), the one login that may move Kibana outbox rows to sending,
    sent and verified. ``argus db bootstrap`` makes it once ``writer_password`` is set."""
    writer_password: _Password = None
    pool_size: int = Field(default=5, ge=1, le=50)
    max_overflow: int = Field(default=5, ge=0, le=50)
    connect_timeout: Annotated[
        Duration, bounded_duration(timedelta(seconds=1), timedelta(seconds=60))
    ] = timedelta(seconds=5)
    statement_timeout: Annotated[
        Duration, bounded_duration(timedelta(seconds=1), timedelta(minutes=10))
    ] = timedelta(seconds=30)

    @model_validator(mode="after")
    def _separate_roles(self) -> DatabaseSettings:
        if self.user == self.owner_user:
            raise ValueError(
                "user and owner_user must be different roles: ARGUS must not run as the role"
                " that owns its tables (D-029)"
            )
        if self.api_user in (self.user, self.owner_user):
            raise ValueError(
                "api_user must be a role of its own, neither user nor owner_user: the web logs"
                " in with only the grants it needs (Q-A2)"
            )
        if self.writer_user in (self.user, self.owner_user, self.api_user):
            raise ValueError(
                "writer_user must be a role of its own: the writer logs in with the grants only"
                " it may hold (Q-D4)"
            )
        return self

    def url(self, *, database: str | None = None, role: DatabaseRole = "app") -> URL:
        """SQLAlchemy URL for the async psycopg driver, logging in as ``role``.

        ``database`` replaces the configured name. Raises ConfigError without that role's
        password, or when the database name is blank or too long for PostgreSQL: an empty
        override is an error, never the configured database.
        """
        name = self.name if database is None else database
        try:
            _check_name(name)
        except ValueError as exc:
            raise ConfigError(f"database name {exc}") from None
        if role == "owner":
            user, password = self.owner_user, self.owner_password
            missing = (
                "database owner password is not set; put ARGUS_DATABASE__OWNER_PASSWORD in .env"
                " (only the `argus db` commands need it)"
            )
        elif role == "api":
            user, password = self.api_user, self.api_password
            missing = (
                "the web's database password is not set; put ARGUS_DATABASE__API_PASSWORD in"
                " .env and run `argus db bootstrap` (it makes the login)"
            )
        elif role == "writer":
            user, password = self.writer_user, self.writer_password
            missing = (
                "the writer's database password is not set; put ARGUS_DATABASE__WRITER_PASSWORD"
                " in the writer's credentials and run `argus db bootstrap` (it makes the login)"
            )
        else:
            user, password = self.user, self.password
            missing = "database password is not set; put ARGUS_DATABASE__PASSWORD in .env"
        if password is None or not password.get_secret_value():
            raise ConfigError(missing)
        try:  # again here: model_copy(update=...) skips the field validators
            usable_password(password.get_secret_value())
        except ValueError as exc:
            field = {
                "owner": "owner_password",
                "api": "api_password",
                "writer": "writer_password",
            }.get(role, "password")
            raise ConfigError(f"database.{field} {exc}") from None
        return URL.create(
            drivername="postgresql+psycopg",
            username=user,
            password=password.get_secret_value(),
            host=self.host,
            port=self.port,
            database=name,
        )


class AssetsSettings(_Section):
    map_path: Path = Path("data/assets/asset_map.yaml")
    """The imported asset map (``argus assets import``); local only, never committed."""
    campus_prefixes: tuple[IPv4Network | IPv6Network, ...] = ()
    """Deprecated, the older name of ``site.own_networks``: its networks join the
    site's, so an install that sets this (the YAML, ``ARGUS_ASSETS__CAMPUS_PREFIXES``) goes on
    working; new ones set ``site.own_networks``."""


def _check_https(url: str) -> str:
    if not re.fullmatch(r"https://[A-Za-z0-9.\-\[\]:]{1,253}(:[0-9]{1,5})?", url):
        raise ValueError("must be https://host[:port] with no path, user or query")
    return url


def _check_https_or_none(url: str | None) -> str | None:
    return None if url is None else _check_https(url)


class SiemBudgetSettings(_Section):
    """The load budget, counted in Elasticsearch server time."""

    took_per_minute_ms: int = Field(default=3_000, ge=100, le=60_000)
    burst_ms: int = Field(default=3_000, ge=100, le=60_000)
    took_per_day_ms: int = Field(default=3_600_000, ge=60_000, le=86_400_000)
    concurrency: int = Field(default=2, ge=1, le=4)
    heavy_concurrency: int = Field(default=1, ge=1, le=2)
    heavy_per_minute: int = Field(default=6, ge=1, le=60)
    heavy_per_day: int = Field(default=2_000, ge=1, le=20_000)
    probes_per_minute: int = Field(default=12, ge=1, le=60)


class SiemHealthSettings(_Section):
    """Starting thresholds of the health state machine."""

    disk_caution: float = Field(default=85.0, gt=0, lt=100)
    disk_degraded: float = Field(default=90.0, gt=0, lt=100)
    disk_stop: float = Field(default=95.0, gt=0, le=100)
    heap_caution: float = Field(default=85.0, gt=0, le=100)
    load_caution: float = Field(default=16.0, gt=0, le=1024)
    ingest_lag_degraded: Annotated[
        Duration, bounded_duration(timedelta(minutes=1), timedelta(hours=24))
    ] = timedelta(minutes=15)

    @model_validator(mode="after")
    def _ordered(self) -> SiemHealthSettings:
        if not self.disk_caution < self.disk_degraded < self.disk_stop:
            raise ValueError("disk thresholds must rise: caution < degraded < stop")
        return self


class LaneSettings(_Section):
    """One lane's own allowance, instead of its share of the ceiling."""

    per_minute_ms: int = Field(ge=0, le=60_000)
    per_day_ms: int = Field(ge=0, le=86_400_000)
    heavy_per_day: int = Field(default=0, ge=0, le=20_000)
    concurrency: int = Field(default=1, ge=1, le=4)
    per_minute_requests: int | None = Field(default=None, ge=1, le=600)
    burst_ms: int | None = Field(default=None, ge=1, le=600_000)
    """Server time the bucket may spend at once at NORMAL (None: a minute's share)."""


class SiemLanesSettings(_Section):
    """The lane budgets: each lane a sub-allowance of the ceiling (``siem.budget``). A lane left
    out keeps its default share of the ceiling; the lanes together never exceed it (checked)."""

    collector: LaneSettings | None = None
    investigation: LaneSettings | None = None
    freshness: LaneSettings | None = None
    kibana_read: LaneSettings | None = None
    kibana_write: LaneSettings | None = None
    identity: LaneSettings | None = None
    measurement: LaneSettings | None = None


class SiemSettings(_Section):
    """The production SIEM, reached only through the Elastic Gateway. Which indices
    it holds, the Kibana space and the versions are the ``site`` section."""

    url: Annotated[str | None, AfterValidator(_check_https_or_none)] = None
    """The SIEM's Elasticsearch address (``https://host:9200``); none until it is set: ARGUS
    has no default address and sends nothing without one (``address``)."""
    ca_file: Path = Path("data/certs/siem-ca.crt")
    """The SIEM's CA certificate, pinned."""
    api_key: SecretStr | None = None
    """The read-only ``argus_reader`` API key (encoded form); only in ``.env``."""
    api_key_expires: date | None = None
    """When ``api_key`` expires (UTC day), as its creation recorded it: ``argus doctor`` warns
    30 days ahead. Elasticsearch is never asked: doctor sends no request."""
    writer_api_key: SecretStr | None = None  # write-back only; none until approved
    writer_api_key_expires: date | None = None
    """When ``writer_api_key`` expires (writer keys live 30 days)."""
    budget: SiemBudgetSettings = SiemBudgetSettings()
    health: SiemHealthSettings = SiemHealthSettings()
    lanes: SiemLanesSettings = SiemLanesSettings()

    @property
    def shown_url(self) -> str:
        return self.url or "(siem.url is not set)"

    def address(self) -> str:
        """The Elasticsearch address; ConfigError when none is set (nothing is sent then)."""
        if self.url is None:
            raise ConfigError("siem.url is not configured (siem: url: in the settings file)")
        return self.url

    def ceiling(self) -> Any:
        """The load ceiling as the gateway's budget takes it (``argus.gateway.budget``)."""
        from argus.gateway.budget import BudgetConfig  # light: no settings, no database

        b = self.budget
        return BudgetConfig(
            took_per_minute_ms=b.took_per_minute_ms,
            burst_ms=b.burst_ms,
            took_per_day_ms=b.took_per_day_ms,
            concurrency=b.concurrency,
            heavy_concurrency=b.heavy_concurrency,
            heavy_per_minute=b.heavy_per_minute,
            heavy_per_day=b.heavy_per_day,
            probes_per_minute=b.probes_per_minute,
        )

    def lane_specs(self) -> dict[str, Any]:
        """The lanes set in ``siem.lanes`` (by name), as the gateway's lanes take them."""
        from argus.gateway.lanes import LaneSpec

        out: dict[str, Any] = {}
        for name in SiemLanesSettings.model_fields:
            given = getattr(self.lanes, name)
            if given is not None:
                out[name] = LaneSpec(
                    per_minute_ms=given.per_minute_ms,
                    per_day_ms=given.per_day_ms,
                    heavy_per_day=given.heavy_per_day,
                    concurrency=given.concurrency,
                    per_minute_requests=given.per_minute_requests,
                    burst_ms=given.burst_ms,
                )
        return out

    @model_validator(mode="after")
    def _lanes_fit(self) -> SiemSettings:
        from argus.gateway.lanes import plan_from

        plan_from(self.ceiling(), self.lane_specs())  # ValueError if they exceed the ceiling
        return self


def _items(value: Any) -> Any:
    """A comma-separated string as its items (an environment variable holds one string)."""
    if isinstance(value, str):
        return tuple(part.strip() for part in value.split(",") if part.strip())
    return value


LOOPBACK = ("127.0.0.1", "localhost")  # IPv4: Starlette's host check cannot read [::1]
# A host name or IPv4 address in links: what ``argus.notices.render`` writes into a link.
_LINK_HOST = r"[a-z0-9][a-z0-9.-]{0,252}"


def _public_url(value: str | None) -> str | None:
    """The address people's links use (``/go/...`` deep links): a scheme and a host name with an
    optional port, nothing else; http only for the loopback."""
    if value is None:
        return None
    from urllib.parse import urlsplit

    parts = urlsplit(value)
    try:
        port = parts.port
    except ValueError:
        raise ValueError("public_url: a port is a number from 1 to 65535") from None
    host = parts.hostname or ""
    if (
        port == 0
        or parts.scheme not in ("http", "https")
        or not re.fullmatch(_LINK_HOST, host)
        or parts.username is not None
        or parts.password is not None
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
        or value != value.strip()
    ):
        raise ValueError("public_url is a scheme and a host name only, e.g. https://argus.example")
    if parts.scheme == "http" and host not in LOOPBACK:
        raise ValueError("public_url uses https unless it is the loopback (DQ29)")
    return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")


class WebSettings(_Section):
    """The Inbox. The loopback by default; another address only with TLS, the host names
    browsers use, and the networks clients may come from. Sessions end after ``session_idle``
    without a person's request (background polls do not count) and ``session_absolute`` after
    sign-in at most."""

    host: str = "127.0.0.1"
    port: int = Field(default=8765, ge=1024, le=65535)
    session_idle: Annotated[Duration, bounded_duration(timedelta(minutes=5), timedelta(days=7))] = (
        timedelta(minutes=30)
    )
    session_absolute: Annotated[
        Duration, bounded_duration(timedelta(minutes=10), timedelta(days=7))
    ] = timedelta(hours=8)
    # the address in permanent links (``/go/case/<uuid>``); without it, links use the first
    # allowed host (or the loopback)
    public_url: Annotated[str | None, AfterValidator(_public_url)] = None
    tls_cert: Path | None = None
    tls_key: Path | None = None
    # from YAML a list; from the environment (the service unit) a comma-separated string
    allowed_hosts: Annotated[tuple[str, ...], BeforeValidator(_items)] = ()  # besides the loopback
    allowed_networks: Annotated[
        tuple[IPv4Network | IPv6Network, ...], BeforeValidator(_items)
    ] = ()  # the clients allowed besides the loopback
    database_role: Literal["app", "api"] = "app"
    """The login the web uses: ``api`` is its own (``database.api_user``), with only the
    grants the web needs; ``app`` the runtime login every other ARGUS process uses."""
    classic: Literal["primary", "fallback"] = "primary"
    """Which are the main pages: ``primary`` serves the classic pages at their addresses;
    ``fallback`` leads a classic page's address to the same page under ``/app`` (303), keeps the
    classic pages read-only at ``/classic`` (their forms are refused with a pointer to ``/app``)
    and opens a permanent link to an investigation in the app. Back to ``primary`` is the whole
    rollback."""
    spa_dir: Path | None = None
    """The folder the app at ``/app`` is served from: by default the build committed in
    the package (``argus/web/spa``); another folder only for a test or a deploy copy."""
    tls_pin_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    """The SHA-256 of the certificate the web serves (DER, lowercase hex). ``argus doctor``
    fails when the certificate no longer matches it: browsers would warn, and a person must never
    type a password past a certificate warning."""
    elk_signin: bool = False
    """ELK sign-in: people sign in with their own ELK account, checked against Elasticsearch.
    Off by default: local accounts stay (each local password is kept until its person's ELK
    sign-in has worked). Needs ``secret_file``, and TLS (or the loopback)."""
    secret_file: Path | None = None
    """The file holding the web's own secret (64 hex digits, mode 0600, ``argus sessions
    keygen``): with a session's token it keys the encrypted copy of a person's ELK credential,
    and it keys the HMAC of the names in the audit trail of failed sign-ins. Read by
    ``argus-web`` alone."""
    approval_key_file: Path | None = None
    """The key that signs approvals (``argus approvals keygen``; 64 hex digits, mode 0600), read
    by ``argus-web`` alone (the writer verifies with its own copy, ``kibana.writer.approval_keys``).
    Without it the approvals queue can be read but no decision is recorded."""
    failure_delay_s: float = Field(default=1.5, ge=0, le=10)
    """Seconds: every failed sign-in or step-up is answered this long after the request arrived,
    so the time never shows whether a name exists."""
    signin_delay_s: float = Field(default=1.0, ge=0, le=60)
    """Seconds: the first of the exponential waits between checks of one name from one client:
    after a second refusal the next check waits this long, then twice, four times as long (the
    fifth refusal locks the name)."""

    @field_validator("allowed_hosts")
    @classmethod
    def _hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # a host name has no case: production's unit names the machine with capitals
        value = tuple(host.lower() for host in value)
        for host in value:
            if re.fullmatch(_LINK_HOST, host) is None:
                raise ValueError(
                    "allowed_hosts: each is a host name or address, without a port"
                    " (links are written with it)"
                )
        return value

    @model_validator(mode="after")
    def _exposed_safely(self) -> WebSettings:
        if (self.tls_cert is None) != (self.tls_key is None):
            raise ValueError("tls_cert and tls_key go together")
        if self.elk_signin:
            if self.secret_file is None:
                raise ValueError("elk_signin needs web.secret_file (argus sessions keygen)")
            if self.host not in LOOPBACK and self.tls_cert is None:
                raise ValueError("elk_signin: an ELK password is typed only over TLS")
            if self.database_role != "api":
                raise ValueError(
                    "elk_signin needs web.database_role: api (only the web's own login may"
                    " create ELK accounts and sessions)"
                )
        if self.host not in LOOPBACK and (
            self.tls_cert is None or not self.allowed_hosts or not self.allowed_networks
        ):
            raise ValueError(
                "the web app listens on the loopback only unless it has TLS (tls_cert, tls_key),"
                " allowed_hosts and allowed_networks (D-104); reviewers can also use an SSH"
                " forward"
            )
        if self.public_url is not None:
            from urllib.parse import urlsplit

            host = urlsplit(self.public_url).hostname
            if host not in (*LOOPBACK, *self.allowed_hosts):
                raise ValueError(
                    "public_url's host must be the loopback or one of allowed_hosts (its links"
                    " must reach this server)"
                )
        return self

    @property
    def scheme(self) -> str:
        return "https" if self.tls_cert is not None else "http"

    @property
    def link_base(self) -> str:
        """Where permanent links point: ``public_url``, else this server's own address."""
        if self.public_url is not None:
            return self.public_url
        shown = self.allowed_hosts[0] if self.allowed_hosts else "127.0.0.1"
        default = 443 if self.scheme == "https" else 80
        return f"{self.scheme}://{shown}" + ("" if self.port == default else f":{self.port}")


class ReferenceSettings(_Section):
    """Reference data. The threat-intel sync reads the SIEM with read templates; off by default."""

    ti_sync: bool = False


class OutsideSettings(_Section):
    """Outside threat intel: VirusTotal for the reputation of a public address or name, Shodan and
    Censys for what a public server is. **A source without a key is off.** The keys are free
    personal ones, only in ``.env`` (``ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY``, ``..._SHODAN_API_KEY``,
    ``..._CENSYS_API_KEY``). Every limit is below its free plan's (a larger value is refused), and
    a source that answers 429 is stopped for the rest of its window. ``cache_window``,
    ``clean_cache_window`` and ``error_backoff`` set how long answers are kept and failures not
    retried; ``flag_threshold`` is the VirusTotal engines that make a detection; ``prefetch_*`` and
    ``families_per_day`` budget the daily look-ups, which share VirusTotal's day with the
    investigator; ``shodan_internetdb`` is the keyless fallback."""

    virustotal_api_key: SecretStr | None = None
    shodan_api_key: SecretStr | None = None
    censys_api_key: SecretStr | None = None
    virustotal_per_minute: int = Field(default=3, ge=1, le=4)  # below the plan's 4, not equal
    virustotal_per_day: int = Field(default=400, ge=1, le=500)
    shodan_per_minute: int = Field(default=30, ge=1, le=60)
    shodan_per_day: int = Field(default=200, ge=1, le=10_000)
    censys_per_day: int = Field(default=10, ge=1, le=1_000)
    censys_per_month: int = Field(default=50, ge=1, le=1_000)
    cache_window: Annotated[Duration, bounded_duration(timedelta(hours=1), timedelta(days=30))] = (
        timedelta(days=7)
    )
    clean_cache_window: Annotated[
        Duration, bounded_duration(timedelta(hours=1), timedelta(days=30))
    ] = timedelta(days=1)
    error_backoff: Annotated[
        Duration, bounded_duration(timedelta(minutes=1), timedelta(days=1))
    ] = timedelta(hours=6)
    timeout: Annotated[Duration, bounded_duration(timedelta(seconds=2), timedelta(seconds=60))] = (
        timedelta(seconds=20)
    )
    flag_threshold: int = Field(default=3, ge=1, le=50)
    prefetch: bool = True
    prefetch_per_day: int = Field(default=260, ge=0, le=500)
    prefetch_batch: int = Field(default=3, ge=1, le=4)
    families_per_day: int = Field(default=40, ge=0, le=200)
    shodan_internetdb: bool = True

    @model_validator(mode="after")
    def _clean_answers_do_not_outlast_detections(self) -> OutsideSettings:
        if self.clean_cache_window > self.cache_window:
            raise ValueError("clean_cache_window must not be longer than cache_window")
        return self

    def key_of(self, source: str) -> str | None:
        """The key of ``source`` (``virustotal``, ``shodan``, ``censys``), or None when it has
        none (blank counts as none): the source is off."""
        secret = getattr(self, f"{source}_api_key", None)
        value = secret.get_secret_value().strip() if isinstance(secret, SecretStr) else ""
        return value or None

    def enabled(self, source: str) -> bool:
        """Whether ``source`` can be asked: it has a key, or it is Shodan with the keyless
        InternetDB switched on."""
        return self.key_of(source) is not None or (source == "shodan" and self.shodan_internetdb)


BatchTemplate = Literal[
    "proxy.pair", "proxy.contact", "dns.host_domains", "web.path_outcomes", "logs.source_events"
]


class EnrichmentSettings(_Section):
    """Evidence from the SIEM's logs. Each template is off until switched on."""

    log_queries: bool = False  # the web follow-up search
    proxy_aggregations: bool = False  # the proxy aggregations
    # the evidence templates switched on; from YAML a list, from the environment a
    # comma-separated string
    templates: Annotated[tuple[BatchTemplate, ...], BeforeValidator(_items)] = ()


class InvestigationSettings(_Section):
    """Deep investigation. ``wave`` switches the deterministic wave on: for an undecided
    investigation with a closable gap, ARGUS asks the ranked checks through the investigation
    lane (NORMAL health only) before any model is asked. A person's "Check more" runs whatever
    this says (each check still obeys the lane and the switches). The item caps bound one wave."""

    wave: bool = False
    wave_per_day: int = Field(default=120, ge=1, le=1_000)  # waves a day at most
    item_requests: int = Field(default=4, ge=1, le=12)  # requests one wave may send
    item_heavy: int = Field(default=2, ge=0, le=6)  # of them heavy (log aggregations)
    item_server_ms: int = Field(default=4_000, ge=100, le=20_000)  # SIEM time one wave may spend


class KibanaSyncSettings(_Section):
    """The read-back and reconciliation (``argus kibana sync``): read-only, off by default; it
    runs only while ``kibana.enabled`` is true as well."""

    enabled: bool = False
    normal: Annotated[Duration, bounded_duration(timedelta(minutes=2), timedelta(hours=2))] = (
        timedelta(minutes=10)
    )
    """How often it polls in NORMAL health; CAUTION and DEGRADED below; never in STOP."""
    caution: Annotated[Duration, bounded_duration(timedelta(minutes=2), timedelta(hours=4))] = (
        timedelta(minutes=20)
    )
    degraded: Annotated[Duration, bounded_duration(timedelta(minutes=5), timedelta(hours=6))] = (
        timedelta(hours=1)
    )
    overlap: Annotated[Duration, bounded_duration(timedelta(0), timedelta(minutes=30))] = timedelta(
        minutes=2
    )
    """How far before the last poll's start each change poll reaches back: Kibana's find is not
    refreshed at once (``refresh: false``)."""
    per_page: int = Field(default=100, ge=1, le=100)
    discovery_every: Annotated[
        Duration, bounded_duration(timedelta(minutes=10), timedelta(days=1))
    ] = timedelta(hours=1)
    """People's cases holding ARGUS's alerts (``kibana.alert.case_ids``) and alert changes."""
    discovery_calls: int = Field(default=3, ge=0, le=20)
    """Searches of 100 known alerts each per discovery (a rotating window)."""
    diff_calls: int = Field(default=5, ge=1, le=20)
    """Searches of 100 alerts each per discovery for the status changes of the alerts on
    ARGUS's cases: a rotating slice, so the load does not grow with the alerts a case holds."""
    clock_alarm: Annotated[Duration, bounded_duration(timedelta(seconds=1), timedelta(hours=1))] = (
        timedelta(seconds=30)
    )
    """Kibana's clock (its Date header) further from ARGUS's than this raises an alarm."""
    team_cases: bool = True
    """Read the case team's cases back as well as the service user's: one find names every
    ARGUS identity as a reporter (``kibana.service_user`` and ``case_team.users()``), so a
    person's edit, close, reopen or delete of a case-team case reaches ARGUS. Costs no extra
    request per cycle; false for an installation without the case team."""


class KibanaWriterSettings(_Section):
    """The case writer: which classes ``argus writer run`` sends on a schedule (a class named
    here has finished its canary and ramp, and is switched on by a person), how often it looks
    (at most every 10 minutes), and the approval keys it verifies closures, resends and
    compensating writes with. Canaries and ramp steps run at the terminal (``argus kibana run``)
    with the class name typed, whatever is set here."""

    scheduled: Annotated[tuple[Literal["W1", "W2", "W3"], ...], BeforeValidator(_items)] = ()
    """Classes the service runs by itself; each must also be in ``kibana.write_classes``."""
    interval: Annotated[Duration, bounded_duration(timedelta(minutes=1), timedelta(minutes=10))] = (
        timedelta(minutes=10)
    )
    approval_keys: Annotated[tuple[Path, ...], BeforeValidator(_items)] = ()
    """The approval signing key files the writer verifies decisions with (``argus approvals
    keygen``; under custody the credential ``approval-signing.key``)."""


class KibanaSettings(_Section):
    """The Kibana lane: off by default; nothing is sent to Kibana while ``enabled`` is false (the
    Kibana versions it writes to are ``site.kibana_versions``). Writes need their class named in
    ``write_classes`` (none by default), the writer's key and a person present at each class's
    canary."""

    enabled: bool = False
    url: Annotated[str | None, AfterValidator(_check_https_or_none)] = None
    """Kibana's address (``https://host:5601``); none until it is set (``address``)."""
    ca_file: Path = Path("data/certs/siem-ca.crt")
    """The CA Kibana's certificate must chain to (the SIEM's CA, pinned)."""
    base_path: str = Field(default="", pattern=r"^(/[a-z0-9_-]{1,32}){0,3}$")
    """Kibana's ``server.basePath`` if one is set, e.g. ``/kibana``; else empty."""
    timeout: Annotated[Duration, bounded_duration(timedelta(seconds=1), timedelta(seconds=60))] = (
        timedelta(seconds=15)
    )
    reader_api_key: SecretStr | None = None
    """Cases Read only; in ``.env`` (ARGUS_KIBANA__READER_API_KEY)."""
    reader_api_key_expires: date | None = None
    cases_writer_api_key: SecretStr | None = None  # W1-W3; the writer's own credential
    cases_writer_api_key_expires: date | None = None
    alert_writer_api_key: SecretStr | None = None  # WA; the writer's own credential
    alert_writer_api_key_expires: date | None = None
    service_user: str = Field(default="argus", pattern=r"^[A-Za-z0-9_.@-]{1,64}$")
    """The ELK user that owns ARGUS's keys: every case ARGUS writes must show it as author."""
    write_classes: Annotated[
        tuple[Literal["W1", "W2", "W3", "WA", "WC"], ...], BeforeValidator(_items)
    ] = ()
    """The write classes switched on at this host, each typed by name: none by default. ``WC``
    is the case team's; it also needs ``case_team.post`` and the case team's keys."""
    write_window: tuple[str, str] = ("02:30", "17:30")
    """UTC; never the site's quiet hours (``site.quiet_hours``). It stays in UTC whatever the
    site's zone is."""
    accepted_residual: Annotated[tuple[str, ...], BeforeValidator(_items)] = ()
    """Privileges a key holds beyond its profile that a person accepted (the fallback cases
    writer's: api:rac, the alert updates, deleteCase); ``argus kibana selftest`` lists them
    instead of failing."""
    sync: KibanaSyncSettings = KibanaSyncSettings()
    """The read-back and reconciliation: off by default."""
    writer: KibanaWriterSettings = KibanaWriterSettings()
    """The case writer: nothing runs on a schedule by default."""

    @property
    def shown_url(self) -> str:
        return self.url or "(kibana.url is not set)"

    def address(self) -> str:
        if self.url is None:
            raise ConfigError("kibana.url is not configured (kibana: url: in the settings file)")
        return self.url

    @field_validator("write_window")
    @classmethod
    def _window(cls, value: tuple[str, str]) -> tuple[str, str]:
        for part in value:
            if not re.fullmatch(r"([01][0-9]|2[0-3]):[0-5][0-9]", part):
                raise ValueError("the write window is two UTC times HH:MM")
        if not value[0] < value[1]:
            raise ValueError("the write window starts before it ends, within one UTC day")
        return value

    @model_validator(mode="after")
    def _classes_have_keys(self) -> KibanaSettings:
        """A write class switched on needs its writer's key in the same (the writer's own)
        environment: W1-W3 the cases writer's, WA the alert writer's."""
        for classes, key, name in (
            ({"W1", "W2", "W3"}, self.cases_writer_api_key, "cases_writer_api_key"),
            ({"WA"}, self.alert_writer_api_key, "alert_writer_api_key"),
        ):
            on = sorted(classes & set(self.write_classes))
            if on and (key is None or not key.get_secret_value()):
                raise ValueError(f"write class {', '.join(on)} needs kibana.{name}")
        scheduled = sorted(set(self.writer.scheduled) - set(self.write_classes))
        if scheduled:
            raise ValueError(
                f"write class {', '.join(scheduled)} is scheduled but not switched on"
                " (kibana.write_classes)"
            )
        return self


class WritebackSettings(_Section):
    """Writing people's review results back to the alerts in Kibana: **off**. A real run also
    needs ``kibana.write_classes`` to name ``WA``, the alert writer's key
    (``kibana.alert_writer_api_key``, with a recorded expiry) and a person at a terminal who types
    the confirmation. The first run writes at most 5 alerts; after that a call names ``batch``
    alerts (at most 100), at least 60 s apart, inside the lane's daily alert-mutation cap."""

    enabled: bool = False
    batch: Annotated[int, Field(ge=1, le=100)] = 5
    """Alerts in one status call."""
    run_limit: Annotated[int, Field(ge=1, le=1000)] = 50
    """Alerts one terminal run writes at most (a call every 60 s: 50 alerts take 10 minutes)."""
    f1_audited: bool = False
    """Set once the audit of the freshness "nothing found" answers has passed: until then a
    benign verdict resting on one waits."""


class LoggingSettings(_Section):
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    format: Literal["console", "json"] = "console"


# The image docker-compose.yml pins for the db service (a test keeps the two equal): its
# pg_dump and pg_restore have the server's major version.
_PINNED_IMAGE = r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$"
POSTGRES_IMAGE = (
    "postgres:17-alpine@sha256:b0f9560a2de083e2cc7382e75f808c7381a32852a7ec49117deedb300e552b24"
)


class BackupSettings(_Section):
    """Backups of ARGUS's database: a nightly dump, a weekly restore drill and a dump
    before every migration. Dumps hold production data: they stay under ``data/`` (mode 0600,
    never committed)."""

    dir: Path = Path("data/backups")
    keep_nightly: int = Field(default=7, ge=1, le=90)
    keep_verified: int = Field(default=4, ge=1, le=52)
    """Dumps a restore drill proved, kept besides the newest nightly ones (weekly drills: a
    month of known-good restores)."""
    keep_migration: int = Field(default=5, ge=1, le=50)
    keep_manual: int = Field(default=5, ge=1, le=50)
    max_age: Annotated[Duration, bounded_duration(timedelta(days=8), timedelta(days=365))] = (
        timedelta(days=35)
    )
    """No dump older than this is kept, whatever its kind: dumps hold the raw alerts and
    snapshots the retention purge removes, on a disk without encryption. The one
    exception is the newest dump a drill restored (or, while none was, the newest dump): a
    backup to restore from is never lost to its age. At least the weekly drill's cycle."""
    before_migration: bool = False
    """``argus db upgrade`` and ``downgrade`` dump the database first and stop if that fails
    (``--no-backup`` skips it, for a person who decides so). Switched on in production's own
    .env (``ARGUS_BACKUP__BEFORE_MIGRATION=true``), never in config/argus.yaml, which every
    checkout and stream worktree loads."""
    tools: Literal["compose", "image"] = "image"
    """Where pg_dump and pg_restore run: ``image`` (the default) in a throwaway container of the
    pinned image on the host's network, with the owner's password from the environment;
    ``compose`` inside the db service's own container over its local socket. docker-compose.yml
    names its project ``argus``, so ``compose`` from any checkout reaches production's
    container: only production's .env may choose it."""
    image: str = Field(default=POSTGRES_IMAGE, pattern=_PINNED_IMAGE)
    """The image for ``image``: pinned by digest, as docker-compose.yml pins the server's."""


class SoakSettings(_Section):
    """The soak gate: ``argus soak phase3 --write`` saves each report under ``dir`` as
    ``<UTC timestamp>.json``. The folder holds counts and labels only (never a name or a value
    from the logs); it stays under ``data/`` and is never committed."""

    dir: Path = Path("data/gate/soak")


CustodyRole = Literal["svc", "web", "writer", "owner"]
"""The accounts of the custody layout: ``svc`` (system user ``argus-svc``: collector, worker,
assessments, soak samples, Kibana read-back), ``web`` (``argus-web``), ``writer``
(``argus-writer``: Kibana and alert writes) and ``owner`` (the owner's commands, started by
root through ``argus-owner``: migrations, bootstrap, backups, resumes)."""

# Which secret settings each account may hold. Every secret setting is named here (a test
# fails otherwise), so a new one gets an owner before it can be configured under custody.
CUSTODY_SECRETS: dict[str, frozenset[str]] = {
    # the Kibana reader key (Cases Read only) is loaded only by argus-kibana-sync
    # the notices' relay password is optional: a relay may need none
    # the outside threat-intel keys are optional: a source without a key is off
    "svc": frozenset(
        {
            "database.password",
            "siem.api_key",
            "kibana.reader_api_key",
            "notices.password",
            "outside.virustotal_api_key",
            "outside.shodan_api_key",
            "outside.censys_api_key",
        }
    ),
    "web": frozenset({"database.api_password"}),
    # the writer's own database login; the Kibana writer keys and the Kibana
    # reader key its write runs check Kibana with
    "writer": frozenset(
        {
            "database.writer_password",
            "siem.api_key",  # the licence and the alerts' case ids it reads and writes beside
            "siem.writer_api_key",
            "kibana.reader_api_key",
            "kibana.cases_writer_api_key",
            "kibana.alert_writer_api_key",
            # the case team's users: written only through the writer
            "case_team.lead_api_key",
            "case_team.evidence_api_key",
            "case_team.intel_api_key",
            "case_team.responder_api_key",
            "case_team.hunter_api_key",
            "case_team.reporter_api_key",
            "case_team.visualiser_api_key",  # optional (no key: no glance comment)
        }
    ),
    # bootstrap sets the logins' passwords; operator commands that read the SIEM use the reader
    # key, and `argus kibana selftest` the Kibana reader key (when present)
    "owner": frozenset(
        {
            "database.owner_password",
            "database.password",
            "database.api_password",
            "database.writer_password",
            "siem.api_key",
            "kibana.reader_api_key",
        }
    ),
}


class IdentitySettings(_Section):
    """The identity lane: a person's own ELK credential checked against the SIEM's Elasticsearch
    (``siem.url``, ``siem.ca_file``) on a lane of its own."""

    connect_timeout: Annotated[
        Duration, bounded_duration(timedelta(seconds=1), timedelta(seconds=3))
    ] = timedelta(seconds=3)
    timeout: Annotated[Duration, bounded_duration(timedelta(seconds=1), timedelta(seconds=5))] = (
        timedelta(seconds=5)
    )
    """The whole exchange of one check (3 s to connect, 5 s in all)."""
    admin_accounts: Literal["refuse", "without_custody"] = "refuse"
    """An account holding an admin privilege (``manage_security``, ``manage_api_key``,
    ``grant_api_key``, ``manage_service_account``, ``manage``) is refused, or let in without
    custody: ARGUS keeps no copy of its password. Superusers are refused either way."""
    refused_names: Annotated[
        tuple[Annotated[str, Field(min_length=1, max_length=507)], ...], BeforeValidator(_items)
    ] = ()
    """More names refused before any request, besides Elasticsearch's reserved users, ``argus``
    and ``kibana.service_user`` (test and canary accounts)."""

    @model_validator(mode="after")
    def _connect_within_total(self) -> IdentitySettings:
        if self.connect_timeout > self.timeout:
            raise ValueError("identity.connect_timeout is at most identity.timeout")
        return self


class CustodySettings(_Section):
    """The custody layout: set by each system unit, never by a person."""

    role: CustodyRole | None = None
    """The account this process runs as; None in the shared layout (every service a user
    unit of the operator, secrets in ``.env``)."""
    operator: Annotated[str, Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.@-]{0,63}$")] | None = None
    """The person who ran this command: ``argus-owner`` passes ``SUDO_USER`` in, since the
    process runs in a service account and the operating system would name that account. Taken
    only under custody (:func:`operator_of`)."""


# A value written into a unit as ``Environment=NAME=value`` without quotes: no space, quote,
# backslash, systemd specifier (%) or variable ($).
_UnitValue = Annotated[str, Field(min_length=1, max_length=512, pattern=r"^[^\s\"'\\%$]+$")]


def _absolute(value: Path | None) -> Path | None:
    if value is not None and not value.is_absolute():
        raise ValueError("must be an absolute path")
    return value


class UnitWebSettings(_Section):
    """The environment ``argus-web.service`` is rendered with: what the web unit gives the
    web on top of the settings files. A value left out drops its line from the unit (and the
    comment above a group whose lines all went). The values are checked as the web will read
    them (another address than the loopback needs TLS, host names and networks)."""

    host: _UnitValue | None = None
    tls_cert: _UnitValue | None = None
    tls_key: _UnitValue | None = None
    allowed_hosts: Annotated[tuple[_UnitValue, ...], BeforeValidator(_items)] = ()
    """As written in the unit (a host name keeps its capitals there; the web lowers them)."""
    allowed_networks: Annotated[tuple[_UnitValue, ...], BeforeValidator(_items)] = ()
    classic: Literal["primary", "fallback"] | None = "fallback"
    """``fallback``: people land on ``/app``; left out, the classic pages are the main ones."""
    public_url: _UnitValue | None = None
    approval_key_file: _UnitValue | None = None
    database_role: Literal["app", "api"] | None = None
    credentials: _UnitValue | None = None
    """The web's ``CREDENTIALS_DIRECTORY``: a folder holding its own login's password."""

    @model_validator(mode="after")
    def _as_the_web_reads_it(self) -> UnitWebSettings:
        WebSettings.model_validate(
            {
                "host": self.host or "127.0.0.1",
                "tls_cert": self.tls_cert,
                "tls_key": self.tls_key,
                "allowed_hosts": self.allowed_hosts,
                "allowed_networks": self.allowed_networks,
                "public_url": self.public_url,
                "classic": self.classic or "primary",
                "database_role": self.database_role or "app",
            }
        )
        return self

    def environment(self) -> dict[str, str]:
        """The unit's optional placeholders (``WEB_HOST`` ...) with their values; a value left
        out is not in the result."""
        values = {
            "HOST": self.host,
            "TLS_CERT": self.tls_cert,
            "TLS_KEY": self.tls_key,
            "ALLOWED_HOSTS": ",".join(self.allowed_hosts),
            "ALLOWED_NETWORKS": ",".join(self.allowed_networks),
            "CLASSIC": self.classic,
            "PUBLIC_URL": self.public_url,
            "APPROVAL_KEY_FILE": self.approval_key_file,
            "DATABASE_ROLE": self.database_role,
            "CREDENTIALS": self.credentials,
        }
        return {f"WEB_{name}": value for name, value in values.items() if value}


class UnitsSettings(_Section):
    """ARGUS's systemd user units as this installation renders them: the templates in
    ``deploy/systemd`` with the checkout they run, the uv that starts them and the web's
    environment. ``argus units install`` writes them; ``argus doctor`` compares the installed
    copies with them byte for byte."""

    root: Annotated[Path | None, AfterValidator(_absolute)] = None
    """The checkout the units run (``WorkingDirectory``); left out: this checkout."""
    uv: Annotated[Path | None, AfterValidator(_absolute)] = None
    """The uv the units start ARGUS with; left out: the uv running this command."""
    run: Annotated[tuple[str, ...] | None, BeforeValidator(_items)] = None
    """The units this installation runs (enabled): doctor fails while one of them is not, and
    while a unit kept for a production step is. Left out: the collector, the worker, the web
    and the assessments. Empty: none yet (``argus init`` without ``--start``)."""
    web: UnitWebSettings = UnitWebSettings()

    @field_validator("run")
    @classmethod
    def _known(cls, value: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if value is None:
            return None
        from argus.ops.units import MANIFEST, Role

        for name in value:
            if name not in MANIFEST:
                raise ValueError(f"{name} is not one of ARGUS's units")
            if MANIFEST[name][0] is Role.TRIGGERED:
                raise ValueError(f"{name} is started by its timer: list the timer")
        if len(set(value)) != len(value):
            raise ValueError("a unit is listed twice")
        return value


_LOG_SOURCE = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")]
_Margin = Annotated[Duration, bounded_duration(timedelta(seconds=10), timedelta(hours=6))]


class FreshnessSettings(_Section):
    """Watermarks and verified zeros. ``mode``: ``off`` (no readings), ``shadow`` (each source's
    watermark is read and the verdict a log zero would get is stored, never used or shown) or
    ``on`` (a log zero whose source the readings prove complete becomes "nothing found, logs
    complete to <time>"). ``margins``: each source's margin for late logs (see
    ``scripts/derive_margin.py``); a source without one never gets a verified zero. ``bridge``: how
    the daily quiet hours are crossed, ``none`` (a gap) or ``edges``."""

    mode: Literal["off", "shadow", "on"] = "off"
    interval: Annotated[Duration, bounded_duration(timedelta(minutes=1), timedelta(hours=1))] = (
        timedelta(minutes=5)
    )
    degraded_interval: Annotated[
        Duration, bounded_duration(timedelta(minutes=1), timedelta(hours=2))
    ] = timedelta(minutes=15)
    gap: Annotated[Duration, bounded_duration(timedelta(minutes=1), timedelta(minutes=10))] = (
        timedelta(minutes=10)  # no gap over 10 minutes
    )
    margins: dict[_LOG_SOURCE, _Margin] = Field(default_factory=dict)
    bridge: Literal["none", "edges"] = "none"

    @model_validator(mode="after")
    def _consistent(self) -> FreshnessSettings:
        if self.degraded_interval < self.interval:
            raise ValueError("freshness.degraded_interval is at least freshness.interval")
        if self.gap < self.interval:
            raise ValueError("freshness.gap is at least freshness.interval (else nothing passes)")
        if self.mode == "on" and not self.margins:
            raise ValueError("freshness.mode on needs the derived margins (freshness.margins)")
        return self


class CasesSettings(_Section):
    """The case lifecycle's daily work. ``watch``: ``off``, ``local`` (ARGUS's own alerts only: no
    request reaches the SIEM) or ``on`` (also the proxy logs, in the investigation lane; run once a
    day by ``argus case watch run``). ``suggest``: the assessment service suggests cases from
    evidence across investigations every 15 minutes, for a person to confirm (local reads only).
    ``offers_per_hour``: offers of a new device's investigations to an open case. ``retitle``:
    ARGUS's own case titles are made again from the facts (a person's title is never changed)."""

    watch: Literal["off", "local", "on"] = "off"
    suggest: bool = True
    offers_per_hour: int = Field(default=30, ge=0, le=500)
    retitle: bool = True


class CampaignsSettings(_Section):
    """Campaign analysis: devices that reach the same rare domains. ``resolvers``: the recursive
    DNS resolvers (addresses or networks). A resolver asks for every name its users ask for, so it
    is no device and must not join unrelated campaigns; set it to the addresses the DNS alerts show
    as the client, since nothing guesses them."""

    resolvers: tuple[IPv4Network | IPv6Network, ...] = ()


class NotifiedSettings(_Section):
    """The known infection of a case whose owner was told. Such a case is tracked quietly (its
    alerts are counted, not raised) and ARGUS speaks again only on change; days count from the
    notice. ``renotify_days`` and ``network_days``: still active this long, it suggests notifying
    again / network-side action. ``quiet_days``: no activity this long, it proposes closing.
    ``active_days``: what counts as still active. ``move_gap``, ``move_window`` and
    ``move_similarity``: the same indicators from a new address are the same device.
    ``volume_factor``, ``managed_types``, ``reopen_days``, ``per_pass``: see config/argus.yaml."""

    renotify_days: int = Field(default=7, ge=1, le=365)
    network_days: int = Field(default=21, ge=1, le=365)
    quiet_days: int = Field(default=14, ge=1, le=365)
    active_days: int = Field(default=3, ge=1, le=60)
    move_window: Annotated[Duration, bounded_duration(timedelta(hours=1), timedelta(days=14))] = (
        timedelta(hours=72)
    )
    move_gap: Annotated[Duration, bounded_duration(timedelta(0), timedelta(days=7))] = timedelta(
        hours=2
    )
    move_similarity: float = Field(default=0.8, gt=0, le=1)
    volume_factor: float = Field(default=10.0, gt=1, le=10_000)
    managed_types: Annotated[tuple[str, ...], BeforeValidator(_items)] = ("lab", "computer-room")
    reopen_days: int = Field(default=30, ge=1, le=365)
    per_pass: int = Field(default=500, ge=10, le=5000)

    @model_validator(mode="after")
    def _ordered(self) -> NotifiedSettings:
        if self.network_days < self.renotify_days:
            raise ValueError("notified.network_days is at least notified.renotify_days")
        if self.move_gap > self.move_window:
            raise ValueError("notified.move_gap is at most notified.move_window")
        return self


class IncidentSettings(_Section):
    """The incident report ARGUS writes for each suggested or open case from its own database
    (summary, verdict, timeline, actors, assets, evidence with the query behind each line,
    hypotheses, indicators, actions); a person confirms or rejects it. No request reaches the SIEM
    or Kibana. ``per_pass``, ``look`` and ``min_interval`` bound the work; ``prose`` lets a model
    word the summary from verified facts; ``kibana_url`` and ``data_views`` set where the evidence
    links open."""

    enabled: bool = True
    per_pass: int = Field(default=5, ge=0, le=100)
    look: int = Field(default=40, ge=1, le=1000)
    min_interval: Annotated[Duration, bounded_duration(timedelta(0), timedelta(days=1))] = (
        timedelta(minutes=30)
    )
    prose: bool = False
    kibana_url: str | None = None
    data_views: Annotated[tuple[str, ...], BeforeValidator(_items)] = ()

    @field_validator("kibana_url")
    @classmethod
    def _kibana(cls, value: str | None) -> str | None:
        return None if value is None else _public_url(value.rstrip("/"))

    @field_validator("data_views")
    @classmethod
    def _views(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        seen: set[str] = set()
        for pair in value:
            name, sep, ident = pair.partition("=")
            if not sep or not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
                raise ValueError("a data view is source=id (squid=..., dns=..., alerts=...)")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", ident):
                raise ValueError(f"the data view id of {name} is letters, digits, - and _")
            if name in seen:
                raise ValueError(f"data view {name} is given twice")
            seen.add(name)
        return value

    @property
    def views(self) -> dict[str, str]:
        return dict(pair.split("=", 1) for pair in self.data_views)


class CaseTeamSettings(_Section):
    """The case team: Kibana users (``argus-lead``, ``argus-evidence``, ``argus-intel``,
    ``argus-responder``, ``argus-hunter``, ``argus-reporter`` and the optional ``argus-visualiser``)
    post the incident case of ``incident-report@1``.

    **``post`` is off.** While it is off nothing is written to the SIEM: the rendering runs as a
    dry run (``argus case team preview <n>``). With it on, a case is opened when a person confirmed
    its report, or (``auto``) when ARGUS's verdict is a true positive of at least
    ``auto_min_confidence``; at most ``per_day`` a day, and each of the first ``canary`` cases
    needs a person's approval. ``max_alerts``, ``alerts_per_call`` and ``alert_pause`` bound the
    alerts attached to a case. The keys are secrets (environment or credential only, never YAML or
    ``.env``): ``<user>_api_key``, all expiring on ``keys_expire``; without the optional
    ``visualiser`` key the "Incident at a glance" comment is skipped."""

    post: bool = False
    auto: bool = True  # false: only a person's confirm opens a case
    auto_min_confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    per_day: int = Field(default=5, ge=0, le=50)
    canary: int = Field(default=1, ge=0, le=20)
    max_alerts: int = Field(default=500, ge=1, le=1_000)
    alerts_per_call: int = Field(default=100, ge=1, le=100)
    alert_pause: Annotated[
        Duration, bounded_duration(timedelta(seconds=1), timedelta(minutes=10))
    ] = timedelta(seconds=3)
    min_update_gap: Annotated[Duration, bounded_duration(timedelta(0), timedelta(days=7))] = (
        timedelta(hours=6)
    )
    look: int = Field(default=40, ge=1, le=500)
    lead_api_key: SecretStr | None = None
    evidence_api_key: SecretStr | None = None
    intel_api_key: SecretStr | None = None
    responder_api_key: SecretStr | None = None
    hunter_api_key: SecretStr | None = None
    reporter_api_key: SecretStr | None = None
    visualiser_api_key: SecretStr | None = None  # optional; WC does not need it
    keys_expire: date | None = None

    def _by_user(self) -> dict[str, SecretStr | None]:
        return {
            "argus-lead": self.lead_api_key,
            "argus-evidence": self.evidence_api_key,
            "argus-intel": self.intel_api_key,
            "argus-responder": self.responder_api_key,
            "argus-hunter": self.hunter_api_key,
            "argus-reporter": self.reporter_api_key,
            "argus-visualiser": self.visualiser_api_key,
        }

    def keys(self) -> dict[str, SecretStr]:
        return {
            user: key for user, key in self._by_user().items() if key and key.get_secret_value()
        }

    def users(self) -> tuple[str, ...]:
        """Every Kibana user of the case team, whether or not a key is installed here. The
        read-back (its own unit holds only the reader key) reads the cases they made and tells
        their actions from a person's by these names."""
        return tuple(self._by_user())


_RelayUser = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[\x21-\x7e]+$")]


SIGNIN_ACTIONS = (
    "user_login_success",
    "user_password_auth_success",
    "user_prompt_challenge_success",
    "user_authorize",
    "user_saml_authorize",
    "user_session_switch",
    "user_access_token_auth",
    "user_login_fail",
    "user_authorize_fail",
)


class SigninsSettings(_Section):
    """Who was behind an address: ARGUS reads the SSO sign-in logs for the internal addresses of
    its investigations and keeps the accounts that signed in from each address on each UTC day,
    because the logs themselves are kept only a few days. Off until switched on
    (``docs/runbooks/signins.md``). The other settings (request batching and pacing, retention)
    are described in config/argus.yaml."""

    enabled: bool = False
    actions: Annotated[tuple[str, ...], BeforeValidator(_items)] = SIGNIN_ACTIONS
    pad_hours: int = Field(default=2, ge=0, le=24)
    shared_accounts: int = Field(default=4, ge=2, le=50)
    batch: int = Field(default=200, ge=1, le=200)
    max_requests_per_pass: int = Field(default=6, ge=0, le=50)
    gap: Annotated[Duration, bounded_duration(timedelta(seconds=3), timedelta(minutes=10))] = (
        timedelta(seconds=3)
    )
    current_day_every: Annotated[
        Duration, bounded_duration(timedelta(minutes=10), timedelta(hours=24))
    ] = timedelta(hours=1)
    retention_days: int = Field(default=5, ge=1, le=60)
    keep_days: int = Field(default=180, ge=1, le=3650)
    final_after: Annotated[
        Duration, bounded_duration(timedelta(minutes=15), timedelta(hours=24))
    ] = timedelta(hours=3)

    @field_validator("actions")
    @classmethod
    def _actions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) > 40:
            raise ValueError("signins.actions names 1 to 40 event actions")
        for action in value:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", action):
                raise ValueError(f"{action!r} is not an event action (lower case, digits, _)")
        if len(set(value)) != len(value):
            raise ValueError("an action is named once")
        return value


class NoticesSettings(_Section):
    """Minimal notices: short e-mails that carry a link, a severity and a count (never a host,
    address, user or rule name) to the people named in ``recipients``, through your mail relay.
    Off until you approve the relay and the recipients; run by ``argus notices run``
    (``argus-notices.timer``). The relay's settings are flat (``relay_host``, ``relay_port``,
    ``relay_starttls``, ``relay_from``); ``password`` is a secret (environment or credential only);
    ``web_url`` is the address the links point to (default ``web.public_url``)."""

    enabled: bool = False
    relay_host: str | None = None
    relay_port: int = Field(default=25, ge=1, le=65535)
    relay_starttls: bool = True
    relay_from: str | None = None
    user: _RelayUser | None = None
    password: SecretStr | None = None
    recipients: Annotated[tuple[str, ...], BeforeValidator(_items)] = ()
    web_url: Annotated[str | None, AfterValidator(_public_url)] = None

    @field_validator("relay_host")
    @classmethod
    def _host(cls, value: str | None) -> str | None:
        return None if value is None else parse_host(value)

    @field_validator("relay_from")
    @classmethod
    def _from(cls, value: str | None) -> str | None:
        return None if value is None else parse_address(value)

    @field_validator("recipients")
    @classmethod
    def _recipients(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_RECIPIENTS:
            raise ValueError(f"at most {MAX_RECIPIENTS} recipients")
        for address in value:
            parse_address(address)
        if len(set(value)) != len(value):
            raise ValueError("a recipient is named once")
        return value

    @model_validator(mode="after")
    def _login(self) -> NoticesSettings:
        if self.user is not None and self.password is None:
            raise ValueError("a relay login needs its password (ARGUS_NOTICES__PASSWORD)")
        if (
            self.user is not None
            and not self.relay_starttls
            and self.relay_host not in (*LOOPBACK, "::1")
        ):
            raise ValueError(
                "a relay login is sent only over TLS (relay_starttls) or to the loopback"
            )
        return self

    @property
    def sends(self) -> bool:
        """Notices leave only when switched on, with a relay and at least one recipient."""
        return (
            self.enabled
            and bool(self.recipients)
            and self.relay_host is not None
            and self.relay_from is not None
        )

    def link_base(self, web: WebSettings) -> str:
        return self.web_url if self.web_url is not None else web.link_base


class Settings(BaseSettings):
    # No env_* options: ARGUS's own readers (argus.config.sources) handle the environment and .env.
    model_config = SettingsConfigDict(extra="forbid", frozen=True)

    environment: Literal["dev", "test", "prod"] = "dev"
    history: HistorySettings = HistorySettings()
    memory: MemorySettings = MemorySettings()
    retention: RetentionSettings = RetentionSettings()
    database: DatabaseSettings = DatabaseSettings()
    logging: LoggingSettings = LoggingSettings()
    assets: AssetsSettings = AssetsSettings()
    siem: SiemSettings = SiemSettings()
    site: SiteSettings = SiteSettings()
    web: WebSettings = WebSettings()
    reference: ReferenceSettings = ReferenceSettings()
    enrichment: EnrichmentSettings = EnrichmentSettings()
    outside: OutsideSettings = OutsideSettings()
    writeback: WritebackSettings = WritebackSettings()
    backup: BackupSettings = BackupSettings()
    soak: SoakSettings = SoakSettings()
    kibana: KibanaSettings = KibanaSettings()
    identity: IdentitySettings = IdentitySettings()
    custody: CustodySettings = CustodySettings()
    freshness: FreshnessSettings = FreshnessSettings()
    cases: CasesSettings = CasesSettings()
    campaigns: CampaignsSettings = CampaignsSettings()
    notified: NotifiedSettings = NotifiedSettings()
    incident: IncidentSettings = IncidentSettings()
    case_team: CaseTeamSettings = CaseTeamSettings()
    notices: NoticesSettings = NoticesSettings()
    signins: SigninsSettings = SigninsSettings()
    investigation: InvestigationSettings = InvestigationSettings()
    units: UnitsSettings = UnitsSettings()

    @model_validator(mode="after")
    def _write_window_is_outside_the_quiet_hours(self) -> Settings:
        """The Kibana write window never reaches into the site's quiet hours: the site and the
        window are separate sections, so this is checked here."""
        start, end = (time.fromisoformat(part) for part in self.kibana.write_window)
        if self.site.quiet_hours.overlaps(start, end):
            raise ValidationError.from_exception_data(  # located at the setting, not at <root>
                "Settings",
                [
                    InitErrorDetails(
                        type=PydanticCustomError(
                            "write_window_in_quiet_hours",
                            "must not reach into the quiet hours ({quiet})",
                            {"quiet": str(self.site.quiet_hours)},
                        ),
                        loc=("kibana", "write_window"),
                        input=list(self.kibana.write_window),
                    )
                ],
            )
        return self

    @model_validator(mode="after")
    def _own_networks_include_the_older_name(self) -> Settings:
        """``assets.campus_prefixes`` is the older name of ``site.own_networks``: the
        networks it lists join the site's, after them, so code reads one list. (Done in place:
        a validator that returns another instance is ignored by ``__init__``.)"""
        extra = [n for n in self.assets.campus_prefixes if n not in self.site.own_networks]
        if extra:
            merged = self.site.model_copy(
                update={"own_networks": (*self.site.own_networks, *extra)}
            )
            object.__setattr__(self, "site", merged)
        return self

    @model_validator(mode="after")
    def _case_team_has_its_keys(self) -> Settings:
        """The case team's class is switched on only with all its users' keys: a missing key would
        stop a case half-way, so the host refuses to start with it."""
        if "WC" in self.kibana.write_classes:
            missing = sorted(
                {
                    "argus-lead",
                    "argus-evidence",
                    "argus-intel",
                    "argus-responder",
                    "argus-hunter",
                    "argus-reporter",
                }
                - set(self.case_team.keys())
            )
            if missing:
                raise ValueError(
                    "write class WC needs the case team's keys (case_team.<user>_api_key): "
                    + ", ".join(missing)
                )
        return self

    # The files load_settings read (not settings: nothing can set them), so a check can look at
    # the files that were loaded (``argus doctor --config other.yaml``), not the defaults.
    _config_file: Path | None = PrivateAttr(default=None)
    _env_file: Path | None = PrivateAttr(default=None)

    @property
    def config_file(self) -> Path | None:
        """The YAML file load_settings read; None when these settings were built directly."""
        return self._config_file

    @property
    def env_file(self) -> Path | None:
        """The .env file load_settings was given (read if it existed); None otherwise."""
        return self._env_file

    if not TYPE_CHECKING:  # type checkers keep the typed __init__ of the pydantic mypy plugin

        def __init__(self, **values: Any) -> None:
            _reject_settings_options(values)
            super().__init__(**values)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # The environment and .env are read by argus.config.sources, not by pydantic-settings:
        # its readers silently skip misspelled ARGUS_ variables and malformed .env lines, and
        # report other tools' .env variables (or a secret pasted on its own line) by name.
        layers = _LAYERS.get()
        if layers is None:  # Settings(...) built directly: keyword arguments and environment
            environment = environment_layer(os.environ, settings_cls)
            if environment.problems:
                header = "invalid configuration (environment):"
                raise ConfigError(_report(header, environment.problems))
            layers = (environment.data,)
        return (init_settings, *(_LayerSource(settings_cls, data) for data in layers))

    def secret_values(self) -> list[str]:
        """Every configured secret, for log redaction: each SecretStr setting, found by walking
        the sections, so a secret added later is registered without anyone listing it."""
        return [secret.get_secret_value() for secret in _secrets(self) if secret.get_secret_value()]


def secret_settings(model: type[BaseModel] | None = None) -> list[str]:
    model = Settings if model is None else model
    names = []
    for name, info in model.model_fields.items():
        section = info.annotation
        if isinstance(section, type) and issubclass(section, BaseModel):
            names += [
                f"{name}.{key}"
                for key, field in section.model_fields.items()
                if field.annotation is SecretStr or SecretStr in get_args(field.annotation)
            ]
    return names


def _secrets(model: BaseModel) -> list[SecretStr]:
    """The SecretStr values of ``model`` and of its sections, in declaration order."""
    found: list[SecretStr] = []
    for name in type(model).model_fields:
        value = getattr(model, name)
        if isinstance(value, SecretStr):
            found.append(value)
        elif isinstance(value, BaseModel):
            found.extend(_secrets(value))
    return found


# --------------------------------------------------------------------------- sources

# Data of the environment, .env and YAML layers (highest priority first) while load_settings
# builds a Settings; pydantic-settings calls settings_customise_sources without arguments.
_LAYERS: ContextVar[tuple[Mapping[str, Any], ...] | None] = ContextVar(
    "argus_settings_layers", default=None
)


class _LayerSource(PydanticBaseSettingsSource):
    """Feeds one already-read layer into pydantic-settings, which merges them by priority."""

    def __init__(self, settings_cls: type[BaseSettings], data: Mapping[str, Any]) -> None:
        super().__init__(settings_cls)
        self._data = dict(data)

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        return self._data.get(field_name), field_name, False

    def __call__(self) -> dict[str, Any]:
        return dict(self._data)


@contextmanager
def _layers(*data: Mapping[str, Any]) -> Iterator[None]:
    token = _LAYERS.set(data)
    try:
        yield
    finally:
        _LAYERS.reset(token)


def _reject_settings_options(values: Mapping[str, Any]) -> None:
    """Refuse pydantic-settings options (``_env_file``, ...): ARGUS's sources would ignore them."""
    options = sorted(name for name in values if name.startswith("_"))
    if options:
        raise TypeError(
            f"Settings() got unexpected keyword arguments: {', '.join(options)}. No setting starts"
            " with '_', and pydantic-settings options such as _env_file are not supported:"
            " choose the files with load_settings(config_path, env_file=...)"
        )


def resolve_config_path(config_path: Path | None = None) -> Path:
    if config_path is not None:
        return config_path
    from_env = os.environ.get(CONFIG_ENV_VAR)
    return Path(from_env) if from_env else DEFAULT_CONFIG_PATH


def load_settings(
    config_path: Path | None = None,
    *,
    env_file: Path | None = DEFAULT_ENV_FILE,
    **overrides: Any,
) -> Settings:
    """Load settings from YAML + .env + environment (+ overrides). Raises ConfigError.

    A file that cannot be read or parsed stops loading at once. Otherwise every problem (unknown
    names, malformed sections, invalid values) is collected into one ConfigError, each naming
    the setting and the file line or variable that set it.
    """
    path = resolve_config_path(config_path)
    from_yaml = yaml_layer(path, Settings)
    from_local = local_file_layer(path)
    from_site = site_file_layer(path)
    from_dotenv = dotenv_layer(env_file, Settings)
    from_environment = environment_layer(os.environ, Settings)
    directory = os.environ.get(CREDENTIALS_ENV_VAR)
    from_credentials = credentials_layer(Path(directory) if directory else None, Settings)
    read = [
        layer
        for layer in (
            from_credentials,
            from_environment,
            from_dotenv,
            from_local,
            from_yaml,
            from_site,
        )
        if layer is not None
    ]
    problems = [problem for layer in reversed(read) for problem in layer.problems]
    try:
        with _layers(*(layer.data for layer in read)):
            settings = Settings(**overrides)
    except ValidationError as exc:
        problems.extend(_validation_problems(exc, [overrides_layer(overrides), *read]))
    else:
        others = [layer for layer in read if layer is not from_credentials]
        problems += custody_problems(settings, [overrides_layer(overrides), *others])
        if not problems:
            settings._config_file = path
            settings._env_file = env_file
            activate(settings.site)
            return settings
    env_file_read = env_file if from_dotenv is not None else None
    raise ConfigError(_report(_header(path, env_file_read), problems))


SITE_FILE = "site.yaml"
LOCAL_FILE = "local.yaml"


def local_file_layer(config_path: Path) -> Layer | None:
    """``local.yaml`` beside the config file, if there is one: this installation's own values
    (the SIEM's and Kibana's addresses, the key's expiry, the web's certificate pin), above the
    config file and below .env and the environment. Any section may be in it; an unknown
    name is an error, as in the config file."""
    local_path = config_path.parent / LOCAL_FILE
    if local_path == config_path or not local_path.is_file():
        return None
    return yaml_layer(local_path, Settings)


def site_file_layer(config_path: Path) -> Layer | None:
    """``site.yaml`` beside the config file, if there is one: what ``argus discover --write``
    wrote, below the config file in priority. It holds the ``site`` section and nothing else."""
    site_path = config_path.parent / SITE_FILE
    if site_path == config_path or not site_path.is_file():
        return None
    layer = yaml_layer(site_path, Settings)
    others = sorted(name for name in layer.data if name != "site")
    if others:
        layer.problems.append(
            f"{SITE_FILE} holds the 'site' section only, not {', '.join(map(show_name, others))}"
        )
        for name in others:
            del layer.data[name]
    return layer


def custody_problems(settings: Settings, others: Sequence[Layer]) -> list[str]:
    """Under custody (``custody.role`` set): a secret set anywhere but the credential directory
    (``others``: every other layer), a secret the account must not hold, and a web that would
    log in as the runtime login. Nothing in the shared layout. Names only, never values."""
    role = settings.custody.role
    if role is None:
        return []
    problems = []
    secrets = secret_settings()
    for layer in others:
        for setting in secrets:
            origin = layer.origins.get(tuple(setting.split(".")))
            if origin is not None:
                problems.append(
                    f"{setting} is set by {origin}: under custody (custody.role {role}) a secret"
                    " comes only from its credential (LoadCredential=, Q-A5)"
                )
    for setting in secrets:
        section, _, key = setting.partition(".")
        value = getattr(getattr(settings, section), key)
        if value is None or not value.get_secret_value() or setting in CUSTODY_SECRETS[role]:
            continue
        holders = sorted(name for name, held in CUSTODY_SECRETS.items() if setting in held)
        problems.append(
            f"{setting} is given to the {role} account, which must not hold it (Q-A5): only"
            f" {' and '.join(holders) or 'no account'} may"
        )
    if role == "web" and settings.web.database_role != "api":
        problems.append(
            "custody.role web: the web logs in with its own login under custody"
            " (web.database_role: api), never the runtime login"
        )
    return problems


def operator_of(settings: Settings) -> str:
    """Who is at the terminal, for the records a command makes (a run, a ramp step, a skip):
    under custody the person ``sudo argus-owner`` was run by, else the operating system's user
    (the service account is never the answer to "who did this")."""
    if settings.custody.role is not None and settings.custody.operator:
        return settings.custody.operator
    return getpass.getuser()


# --------------------------------------------------------------------------- error reports


def _header(path: Path, env_file: Path | None) -> str:
    if env_file is None:
        return f"invalid configuration ({safe(path)} and environment):"
    return f"invalid configuration ({safe(path)}, environment and {safe(env_file)}):"


def _report(header: str, problems: Sequence[str]) -> str:
    lines = [header, *(f"  - {problem}" for problem in problems[:_MAX_REPORTED_PROBLEMS])]
    if len(problems) > _MAX_REPORTED_PROBLEMS:  # e.g. the wrong file passed as the config
        lines.append(f"  - ... and {len(problems) - _MAX_REPORTED_PROBLEMS} more")
    return "\n".join(lines)


def _validation_problems(exc: ValidationError, layers: Sequence[Layer]) -> list[str]:
    problems = []
    for error in exc.errors(include_url=False, include_input=False, include_context=False):
        loc = error["loc"]
        if error["type"] == "extra_forbidden":
            message = _unknown_setting(loc)
        else:
            message = safe(error["msg"])
        origin = _origin(loc, layers)
        problems.append(f"{_location(loc)}: {message}" + (f" [{origin}]" if origin else ""))
    return problems


def _location(loc: tuple[int | str, ...]) -> str:
    """``history.window``; a part that is not a plain name is quoted, e.g. ``'history.window'``."""
    parts = (show_name(part) if isinstance(part, str) else str(part) for part in loc)
    return ".".join(parts) or "<root>"


def _unknown_setting(loc: tuple[int | str, ...]) -> str:
    name = loc[-1] if loc else ""
    if len(loc) == 1 and isinstance(name, str) and "." in name:
        return "unknown setting; nested settings are written as an indented section, not with dots"
    known: list[str] = []
    if len(loc) == 1:
        known = list(Settings.model_fields)
    elif len(loc) == 2 and (section := section_model(Settings, str(loc[0]))) is not None:
        known = list(section.model_fields)
    close = difflib.get_close_matches(str(name).lower(), known, n=1, cutoff=0.75)
    return "unknown setting (check the spelling)" + (f"; did you mean {close[0]}?" if close else "")


def _origin(loc: tuple[int | str, ...], layers: Sequence[Layer]) -> str | None:
    """Where the value at ``loc`` was set: the most specific path, then the highest priority."""
    keys = tuple(str(part) for part in loc)
    for end in range(len(keys), 0, -1):
        for layer in layers:
            origin = layer.origins.get(keys[:end])
            if origin is not None:
                return origin
    return None
