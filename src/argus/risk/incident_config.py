"""The linker's, the incident lifecycle's and identity's settings: ``config/risk-incidents.yaml``
(of the repo), read once and checked (unknown keys are errors). Every value is generic: entity
kinds, windows, caps and asset-map fields; no rule is named."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from argus.config.errors import ConfigError
from argus.config.sources import read_yaml_file

INCIDENTS_PATH = Path(__file__).resolve().parents[3] / "config" / "risk-incidents.yaml"
LinkKind = Literal["host", "account", "flagged", "rare", "bare_ip"]
LINK_KINDS: tuple[LinkKind, ...] = ("host", "account", "flagged", "rare", "bare_ip")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Window(_Model):
    hours: int = Field(ge=1, le=24 * 30)

    @property
    def span(self) -> timedelta:
        return timedelta(hours=self.hours)


class Reach(Window):
    max_reach: int = Field(ge=1, le=10_000)


class Account(Window):
    max_devices_a_day: int = Field(ge=1, le=50)


class Host(Window):
    max_addresses: int = Field(ge=1, le=100)


class Links(_Model):
    host: Host
    account: Account
    flagged: Reach
    rare: Reach
    bare_ip: Reach


class Caps(_Model):
    objects: int = Field(ge=2, le=1000)  # risk objects: devices, accounts and own sites
    campaign_objects: int = Field(ge=2, le=5000)
    groups: int = Field(ge=10, le=5000)


class Campaign(_Model):
    min_devices: int = Field(ge=2, le=100)
    hours: int = Field(ge=1, le=24 * 30)
    every_hours: int = Field(ge=1, le=24)


class Hubs(_Model):
    roles: tuple[str, ...]
    fan_in: int = Field(ge=10, le=100_000)
    fan_in_hours: int = Field(ge=1, le=24 * 30)


class Lifecycle(_Model):
    quiet_hours: int = Field(ge=1, le=24 * 30)
    stop_days: int = Field(ge=1, le=90)
    seal_days: int = Field(ge=1, le=365)


class Identity(_Model):
    role_fields: tuple[str, ...]
    addressing_field: str
    criticality_field: str
    unknown_addressing: Literal["static", "dynamic"]
    dynamic_roles: tuple[str, ...]
    shared_roles: tuple[str, ...]
    criticality: dict[str, float]

    @model_validator(mode="after")
    def _checked(self) -> Identity:
        for field in (*self.role_fields, self.addressing_field, self.criticality_field):
            if not field.startswith("site."):
                raise ValueError("identity fields are asset-map fields (site.<name>)")
        if any(not 0 < v <= 4 for v in self.criticality.values()):
            raise ValueError("a criticality is above 0 and at most 4")
        return self


class IncidentConfig(_Model):
    version: Literal[1]
    links: Links
    noisy_prevalence: float = Field(gt=0, le=1)
    flag_threats: int = Field(ge=1, le=10)
    pull_in: tuple[LinkKind, ...]
    depth: int = Field(ge=1, le=4)
    caps: Caps
    campaign: Campaign
    hubs: Hubs
    lifecycle: Lifecycle
    retro_days: int = Field(ge=1, le=90)
    keep_days: int = Field(ge=30, le=365)
    identity: Identity

    @model_validator(mode="after")
    def _complete(self) -> IncidentConfig:
        if self.caps.campaign_objects < self.caps.objects:
            raise ValueError("caps.campaign_objects is below caps.objects")
        if self.lifecycle.stop_days * 24 < self.lifecycle.quiet_hours:
            raise ValueError("lifecycle.stop_days is shorter than quiet_hours")
        return self


def parse(data: Mapping[str, Any], where: str = "incident config") -> IncidentConfig:
    try:
        return IncidentConfig.model_validate(data)
    except (ValidationError, ValueError) as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in (exc.errors() if isinstance(exc, ValidationError) else [])
        ) or str(exc)  # fmt: skip
        raise ConfigError(f"invalid {where}: {problems}") from None


@lru_cache(maxsize=4)
def load(path: Path | None = None) -> IncidentConfig:
    """The linker's settings; a missing or invalid file is an error."""
    path = INCIDENTS_PATH if path is None else path
    if not path.exists():
        raise ConfigError(f"{path} is missing: it holds the incident engine's links and caps")
    data, _ = read_yaml_file(path)
    return parse(data, str(path.name))
