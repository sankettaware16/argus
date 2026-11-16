"""The models of ``/api/v1/admin`` (P4-H, D-327): the Settings page and its saves."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field

from argus.web.v1.models import In, Out

SettingKey = Annotated[str, Field(pattern=r"^[a-z_]+(\.[a-z0-9_]+)+$", max_length=120)]
Kind = Literal["bool", "int", "float", "text", "choice", "list", "duration", "date", "path",
               "secret", "map"]  # fmt: skip
Risk = Literal["normal", "sensitive", "siem_write"]
SettingChangeState = Literal["pending", "applying", "applied", "refused", "rolled_back"]


class SettingOut(Out):
    key: str
    label: str
    help: str
    kind: Kind
    risk: Risk
    editable: bool
    optional: bool
    choices: list[str]
    minimum: float | None
    maximum: float | None
    default: Any = Field(json_schema_extra={"nullable": True})
    value: Any = Field(default=None, json_schema_extra={"nullable": True})
    """The value in effect (durations in seconds); never a key's."""
    is_set: bool | None = None
    """A key's only fact: whether one is set."""
    homes: list[str]
    """Where this host sets it ("set in the app", "in .env", ...); empty: the files' default."""
    in_app: bool


class SectionOut(Out):
    key: str
    label: str
    about: str
    settings: list[SettingOut]


class ApplierOut(Out):
    running: bool
    """argus-admin answered in the last two minutes: a save is applied within seconds."""
    last_seen: datetime | None


class SettingsOut(Out):
    sections: list[SectionOut]
    applier: ApplierOut
    problem: str | None
    """Why this host's settings do not load as they are, if they do not."""
    confirm_words: str
    """What a person types to save a change that lets ARGUS write to the SIEM."""
    setup_needed: bool
    """The SIEM is not set up yet: the app opens the first-time setup."""


class SettingChangeIn(In):
    key: SettingKey
    value: Any = Field(default=None, json_schema_extra={"nullable": True})
    """The new value (a duration as "5d"; a key as pasted). None clears an optional setting."""
    reset: bool = False
    """Back to the files' value (only a setting set in the app)."""


class SettingChangesIn(In):
    changes: Annotated[list[SettingChangeIn], Field(min_length=1, max_length=50)]
    confirm: Annotated[str | None, Field(max_length=100)] = None


class SettingChangeOut(Out):
    id: int
    key: str
    state: SettingChangeState
    outcome: str | None
    created_at: datetime
    finished_at: datetime | None
    by: str


class SettingChangesOut(Out):
    batch: uuid.UUID | None
    changes: list[SettingChangeOut]


class InspectIn(In):
    url: Annotated[str, Field(pattern=r"^https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/?$", max_length=300)]


class SetupIn(In):
    """The first-time setup's answers (``argus init``'s names: ``siem.url``, ``siem.trust``,
    ``siem.fingerprint``, ``organisation.name`` ...) and its keys, which are sealed at once."""

    answers: Annotated[dict[str, Any], Field(max_length=60)]
    keys: Annotated[
        dict[Literal["siem.api_key", "kibana.api_key"], Annotated[str, Field(max_length=8192)]],
        Field(max_length=2, default_factory=dict),
    ]


JobKind = Literal["inspect_tls", "setup"]
JobState = Literal["pending", "running", "done", "failed"]


class JobOut(Out):
    id: int
    kind: JobKind
    state: JobState
    result: dict[str, Any] | None
    created_at: datetime
    finished_at: datetime | None
