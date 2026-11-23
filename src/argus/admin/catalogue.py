"""What the app may change (D-327): every setting of the ``Settings`` model, typed from the model
itself, with the little the model cannot say kept here: the plain label, whether a section is
shown, how risky a change is (normal, sensitive, a write to the SIEM), the services that read it,
and where a setting lives when no file sets it yet. Pure: no file and no database is read here."""

from __future__ import annotations

import types
import typing
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import date, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal, get_args, get_origin

from pydantic import BaseModel, SecretStr
from pydantic.fields import FieldInfo

from argus.config.settings import Settings

Kind = Literal["bool", "int", "float", "text", "choice", "list", "duration", "date", "path",
               "secret", "map"]  # fmt: skip


class Risk(StrEnum):
    NORMAL = "normal"  # an administrator
    SENSITIVE = "sensitive"  # an administrator who confirmed their password in the last minutes
    SIEM_WRITE = "siem_write"  # that, and the words typed: it lets ARGUS write to the SIEM


# The long-running services; a timer's service reads its settings at its next run.
SERVICES = ("argus-web", "argus-collector", "argus-worker", "argus-assess", "argus-kibana-sync",
            "argus-writer")  # fmt: skip
_SIEM = ("argus-collector", "argus-worker", "argus-assess", "argus-kibana-sync", "argus-writer",
         "argus-web")  # fmt: skip


@dataclass(frozen=True)
class Section:
    label: str
    about: str
    restarts: tuple[str, ...] = SERVICES


# The sections the app shows, in its order. A section left out (the database's logins, the
# units' rendering, custody, the soak) stays a file's: the installer and the CLI own it.
SECTIONS: dict[str, Section] = {
    "site": Section("Organisation and data sources",
                    "Who runs ARGUS, the time zone, and which logs and Kibana space it reads."),
    "siem": Section("SIEM", "The Elasticsearch ARGUS reads alerts and logs from.", _SIEM),
    "kibana": Section("Kibana", "The Kibana ARGUS reads cases from and, when allowed, writes to.",
                      ("argus-kibana-sync", "argus-writer", "argus-web")),
    "web": Section("The web app", "Where people open ARGUS and how they sign in.", ("argus-web",)),
    "identity": Section("Sign-in through ELK", "People sign in with their ELK accounts.",
                        ("argus-web",)),
    "case_team": Section("Kibana cases", "How confirmed incidents become Kibana cases.",
                         ("argus-web",)),
    "risk": Section("Incident engine", "How alerts become possible incidents.", ("argus-web",)),
    "enrichment": Section("Evidence checks", "The SIEM checks ARGUS asks about an incident.",
                          ("argus-worker", "argus-collector")),
    "outside": Section("Outside sources", "VirusTotal, Shodan, Censys and other lookups.",
                       ("argus-worker", "argus-assess", "argus-web")),
    "directory": Section("Account directory",
                         "Who an account belongs to, from the organisation's own directory.",
                         ("argus-web",)),
    "cases": Section("Cases", "What a case needs before it closes.", ("argus-web",)),
    "notices": Section("Notices", "The short e-mails ARGUS sends.", ()),
    "notified": Section("Owner notices", "Notices to the owners of affected devices.", ()),
    "signins": Section("Sign-in records", "Who was behind an internal address.",
                       ("argus-worker", "argus-web")),
    "incident": Section("Incident reports", "How reports are written.", ("argus-worker",)),
    "investigation": Section("Investigations", "How deep an investigation goes.",
                             ("argus-worker",)),
    "freshness": Section("Freshness", "Checks that nothing was missed.", ("argus-collector",)),
    "history": Section("History", "How far back ARGUS looks."),
    "sla": Section("Response times",
                   "How long a person has to decide and to close an incident, by its priority:"
                   " what the dashboards measure against.", ("argus-web",)),
    "retention": Section("Retention", "How long ARGUS keeps what it stored.", ()),
    "backup": Section("Backups", "The nightly dump and the weekly restore drill.", ()),
    "writeback": Section("Write-back", "Writing reviews back to the SIEM.", _SIEM),
    "logging": Section("Logging", "How much the services log."),
    "assets": Section("Asset map", "The organisation's devices, networks and owners."),
    "campaigns": Section("Campaigns", "Grouping incidents into campaigns.", ("argus-worker",)),
}  # fmt: skip

SENSITIVE = frozenset({
    "siem.url", "siem.ca_file", "kibana.url", "kibana.ca_file", "kibana.enabled", "site.space",
    "web.allowed_hosts", "web.allowed_networks", "web.public_url", "web.elk_signin",
    "identity.admin_accounts", "assets.map_path",
})  # fmt: skip
SIEM_WRITE = frozenset({
    "kibana.write_classes", "case_team.post", "case_team.per_day", "case_team.auto",
    "case_team.canary", "case_team.auto_min_confidence", "writeback.enabled",
})  # fmt: skip
# Settings only one service reads, from its own file (local/<file>), when no other file sets them.
UNIT_FILES = {"case_team.post": "argus-writer.env", "case_team.per_day": "argus-writer.env",
              "kibana.write_classes": "argus-writer.env"}  # fmt: skip
# A setting the web unit is rendered with: changed with its ``units.web`` twin (D-327).
MIRRORS = {f"web.{name}": f"units.web.{name}"
           for name in ("host", "tls_cert", "tls_key", "allowed_hosts", "allowed_networks",
                        "public_url", "approval_key_file", "database_role")}  # fmt: skip
READ_ONLY = frozenset({"web.host", "web.port", "web.tls_cert", "web.tls_key", "web.spa_dir",
                       "web.switches_root", "web.database_role", "web.classic", "web.secret_file",
                       "web.approval_key_file", "web.tls_pin_sha256", "site.elastic_versions",
                       "site.kibana_versions", "kibana.writer.approval_keys"})  # fmt: skip
# The SIEM's load budget (D-022) is set in the files after a measurement, never from the app.
READ_ONLY_PREFIXES = ("siem.budget.", "siem.lanes.", "siem.health.", "site.kibana_features.")


@dataclass(frozen=True)
class Entry:
    key: str
    section: str
    label: str
    help: str
    kind: Kind
    risk: Risk
    editable: bool
    optional: bool  # it may be cleared (None)
    choices: tuple[str, ...] = ()
    minimum: float | None = None
    maximum: float | None = None
    default: Any = None  # as JSON; never a secret's
    restarts: tuple[str, ...] = ()
    unit_file: str | None = None
    mirror: str | None = None

    @property
    def secret(self) -> bool:
        return self.kind == "secret"


def _label(name: str) -> str:
    words = name.replace("_", " ").strip()
    for short, long in (("api key", "API key"), ("ca file", "CA certificate"), ("url", "URL"),
                        ("tls", "TLS"), ("ip", "IP"), ("llm", "AI")):  # fmt: skip
        words = words.replace(short, long)
    return words[:1].upper() + words[1:]


def _bare(annotation: Any) -> tuple[Any, bool, list[Any]]:
    """The type under ``Annotated`` and ``| None``, whether None is allowed, and the metadata."""
    meta: list[Any] = []
    optional = False
    while True:
        origin = get_origin(annotation)
        if origin is Annotated:
            annotation, *more = get_args(annotation)
            meta += more
        elif origin in (typing.Union, types.UnionType):
            rest = [a for a in get_args(annotation) if a is not type(None)]
            optional = optional or len(rest) < len(get_args(annotation))
            if len(rest) != 1:
                return annotation, optional, meta
            annotation = rest[0]
        else:
            return annotation, optional, meta


def _kind(annotation: Any, meta: list[Any]) -> tuple[Kind, tuple[str, ...]]:
    origin = get_origin(annotation)
    if annotation is bool:
        return "bool", ()
    if annotation is int:
        return "int", ()
    if annotation is float:
        return "float", ()
    if annotation is SecretStr:
        return "secret", ()
    if annotation is timedelta:
        return "duration", ()
    if annotation is date:
        return "date", ()
    if isinstance(annotation, type) and issubclass(annotation, Path):
        return "path", ()
    if origin is Literal:
        return "choice", tuple(str(a) for a in get_args(annotation))
    if isinstance(annotation, type) and issubclass(annotation, StrEnum):
        return "choice", tuple(m.value for m in annotation)
    if origin in (tuple, list, frozenset, set):
        return "list", ()
    if origin is dict or annotation is dict:
        return "map", ()
    return "text", ()


def _bounds(meta: list[Any]) -> tuple[float | None, float | None]:
    low = high = None
    for m in meta:
        for name in ("ge", "gt"):
            if isinstance(getattr(m, name, None), int | float):
                low = float(getattr(m, name))
        for name in ("le", "lt"):
            if isinstance(getattr(m, name, None), int | float):
                high = float(getattr(m, name))
    return low, high


def _json(value: Any) -> Any:
    if isinstance(value, SecretStr):
        return None
    if isinstance(value, timedelta):
        return int(value.total_seconds())
    if isinstance(value, date | Path):
        return str(value)
    if isinstance(value, tuple | list | frozenset | set):
        return [_json(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json(v) for k, v in value.items()}
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return str(value)  # an address, a network, an enum


def _entries(model: type[BaseModel], prefix: str, section: str) -> Iterator[Entry]:
    for name, info in model.model_fields.items():
        key = f"{prefix}{name}"
        annotation, optional, meta = _bare(info.annotation)
        meta += list(info.metadata)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            yield from _entries(annotation, f"{key}.", section)
            continue
        kind, choices = _kind(annotation, meta)
        low, high = _bounds(meta)
        risk = Risk.NORMAL
        if key in SIEM_WRITE:
            risk = Risk.SIEM_WRITE
        elif key in SENSITIVE or kind == "secret":
            risk = Risk.SENSITIVE
        yield Entry(
            key=key,
            section=section,
            label=_label(name),
            help=_help(info),
            kind=kind,
            risk=risk,
            editable=kind != "map"
            and key not in READ_ONLY
            and not key.startswith(READ_ONLY_PREFIXES),
            optional=optional,
            choices=choices,
            minimum=low,
            maximum=high,
            default=None if kind == "secret" else _json(_default(info)),
            restarts=SECTIONS[section].restarts,
            unit_file=UNIT_FILES.get(key),
            mirror=MIRRORS.get(key),
        )


def _help(info: FieldInfo) -> str:
    return " ".join((info.description or "").split())


def _default(info: FieldInfo) -> Any:
    if info.default_factory is not None:
        try:
            return info.default_factory()  # type: ignore[call-arg]
        except TypeError:
            return None
    return info.default


def catalogue() -> tuple[Entry, ...]:
    """Every setting the app shows, section by section in ``SECTIONS`` order."""
    out: list[Entry] = []
    for section in SECTIONS:
        field = Settings.model_fields.get(section)
        if field is None:
            continue
        annotation, _, _ = _bare(field.annotation)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            out += _entries(annotation, f"{section}.", section)
    return tuple(out)


def by_key() -> dict[str, Entry]:
    return {e.key: e for e in catalogue()}
