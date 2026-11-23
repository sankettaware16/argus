"""The models of ``/api/v1/admin`` (P4-H, D-327): the Settings page and its saves."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field

from argus.web.v1.models import In, Out

SettingKey = Annotated[str, Field(pattern=r"^[a-z_]+(\.[A-Za-z0-9_-]+)+$", max_length=120)]
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


SetupKey = Annotated[
    str,
    Field(pattern=r"^(siem\.api_key|kibana\.api_key|elastic\.admin_password"
                  r"|outside\.(virustotal|shodan|censys)_api_key|llm\.key\.[a-z][a-z0-9_]{0,63})$"),
]  # fmt: skip


class SetupIn(In):
    """The first-time setup's answers (``argus init``'s names: ``siem.url``, ``siem.trust``,
    ``siem.fingerprint``, ``organisation.name``, ``elastic.admin_user``, ``case_team.provision``
    ...) and its keys, each sealed at once: the SIEM's and Kibana's, an Elastic administrator's
    password (used once by init to make ARGUS's own keys and users, never stored), the
    threat-intel keys and the AI providers' (``llm.key.groq_api_key``), and an asset map."""

    answers: Annotated[dict[str, Any], Field(max_length=60)]
    keys: Annotated[
        dict[SetupKey, Annotated[str, Field(min_length=1, max_length=8192)]],
        Field(max_length=20, default_factory=dict),
    ]
    asset_map: Annotated[str | None, Field(max_length=5_000_000)] = None


JobKind = Literal["inspect_tls", "setup", "check", "assets", "llm_switch", "service"]
JobState = Literal["pending", "running", "done", "failed"]


class JobOut(Out):
    id: int
    kind: JobKind
    state: JobState
    result: dict[str, Any] | None
    created_at: datetime
    finished_at: datetime | None


TARGET = (r"^(siem|kibana:(reader|cases|alerts)|llm:[a-z][a-z0-9_-]{0,31}"
          r"|outside:(virustotal|shodan|censys)|directory)$")  # fmt: skip


class ConnectionCheckIn(In):
    target: Annotated[str, Field(pattern=TARGET)]
    """``siem``, ``kibana:reader|cases|alerts``, ``llm:<provider>`` or
    ``outside:virustotal|shodan|censys`` (one lookup of a public test address), ``directory``
    (whether the site's account directory accepts the saved session)."""


class AssetsIn(In):
    content: Annotated[str, Field(min_length=1, max_length=5_000_000)]
    """The asset map file's text (YAML), sealed at once."""


class LlmSwitchIn(In):
    stop: bool
    """True: no call to any model until resumed."""


class AiKeyOut(Out):
    name: str
    setting: str
    is_set: bool


class AiProviderOut(Out):
    name: str
    enabled: bool
    api: str
    trust: str
    paid: bool
    models: dict[str, str]
    keys: list[AiKeyOut]
    monthly_cap_usd: float | None
    daily_cap_usd: float | None
    month_usd: float
    today_usd: float
    calls_month: int
    ok_month: int
    alarm: str | None


class AiPurposeOut(Out):
    task: str
    label: str
    calls_per_day: int | None
    providers: list[str] | None
    tier: str | None
    calls_today: int


class AgentOut(Out):
    name: str
    kind: str | None = None
    version: str | None = None
    mission: str | None = None
    task: str | None = None
    tier: str | None = None
    tools: list[str] = Field(default_factory=list)
    specialists: list[str] = Field(default_factory=list)
    triggers: list[str] = Field(default_factory=list)
    on: bool = False
    enabled_version: str | None = None
    problem: str | None = None
    calls_month: int = 0


class TeamKeyOut(Out):
    user: str
    setting: str
    is_set: bool


class AiOut(Out):
    applier: ApplierOut
    problem: str | None
    """Why the AI's settings do not load on this host, if they do not."""
    stopped: bool
    """The kill switch: no call to any model until resumed."""
    any_key: bool
    """At least one switched-on provider has a key: the AI features can run."""
    monthly_cap_usd: float | None
    daily_cap_usd: float | None
    month_usd: float
    today_usd: float
    providers: list[AiProviderOut]
    purposes: list[AiPurposeOut]
    agents: list[AgentOut]
    readings_on: bool
    """``risk.reading``: ARGUS AI writes its reading of presented incidents."""
    team: list[TeamKeyOut]
    team_keys_expire: str | None
    settings: list[SettingOut]
    """The AI's settings (``llm.*``), saved like any setting through ``/admin/changes``."""


class AiDayOut(Out):
    day: str
    provider: str
    calls: int
    ok: int
    cost_usd: float
    tokens: int


class AiTaskUseOut(Out):
    task: str
    calls: int
    cost_usd: float


class SourceLimitOut(Out):
    window: str
    """``minute``, ``day`` or ``month``."""
    maximum: int


class SourceDayOut(Out):
    day: str
    requests: int


class SourceUseOut(Out):
    source: str
    key_set: bool
    enabled: bool
    today: int
    month: int
    answered_month: int
    limits: list[SourceLimitOut]
    days: list[SourceDayOut]


class UsageOut(Out):
    """What ARGUS spent and used: the AI's cost a day by provider (the last 31 days) and by task
    this month, the caps, and each threat-intel source's lookups against its free plan's limits."""

    monthly_cap_usd: float | None
    daily_cap_usd: float | None
    month_usd: float
    today_usd: float
    stopped: bool
    ai_days: list[AiDayOut]
    ai_tasks: list[AiTaskUseOut]
    sources: list[SourceUseOut]
    sources_at: datetime | None
    """When argus-admin last counted the sources' use (every five minutes)."""


class ServiceIn(In):
    unit: Annotated[str, Field(pattern=r"^argus-[a-z0-9-]+\.(service|timer)$", max_length=60)]
    action: Literal["on", "off", "restart"]
    confirm: Annotated[str | None, Field(max_length=100)] = None
    """The words, to switch on a unit that writes to the SIEM."""


class ServiceOut(Out):
    unit: str
    label: str
    core: bool
    """One of ARGUS's own services: it always runs (it may be restarted)."""
    switchable: bool
    on: bool
    """Meant to run on this installation (``units.run``)."""
    running: bool
    writes_siem: bool
    deletes: bool


class ServicesOut(Out):
    units: list[ServiceOut]
    at: datetime | None
    """When argus-admin last looked (every five minutes, and after each switch)."""
    confirm_words: str
