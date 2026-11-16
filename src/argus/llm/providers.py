"""The LLM gateway's configuration (``config/llm.yaml``) and its keys. Keys are read by name from
``keys_file`` into ``SecretStr`` and registered for log redaction; a missing key leaves its
provider out; only names are ever printed. Each provider has its own trust (``cloud`` or
``campus``: an on-premises model that must be on this machine, pinned, limited to named tasks and
capped per day), certificate, timeout, concurrency, task allowlist, probe, output mode, cost caps
and token estimate; each model its context and output limits."""

from __future__ import annotations

import ipaddress
import math
import os
import re
from datetime import datetime, time, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal
from urllib.parse import urlsplit

import yaml
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, SecretStr, model_validator

from argus import site
from argus.llm import budget
from argus.observability.redaction import register_secret

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PATH = ROOT / "config" / "llm.yaml"
_KEY_LINE = re.compile(r"^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$")
KEYS_CREDENTIAL = "llm-api-keys.env"  # deploy/custody: the svc account's LoadCredential=


class Tier(StrEnum):
    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


class Trust(StrEnum):
    CLOUD = "cloud"  # a provider on the internet: pseudonymized text only
    CAMPUS = "campus"  # a machine of the organisation: the privacy rules still apply


# The tasks a call may name (``Call.purpose``); a provider may serve only some of them.
# The helper tasks are what an on-premises model may earn, task by task, through an
# evaluation: specialists' notes, indicator extraction, triage hints and checked summaries.
HELPER_TASKS = frozenset({"notes", "extract", "triage", "summary"})
# ARGUS AI's reading of a presented incident (D-324): "story" (tier 2) and "opinion" (tier 3).
# Text only: they never change the queue.
READING_TASKS = frozenset({"story", "opinion"})
TASKS = frozenset({"assess", "evaluate", "ping", "tune"}) | HELPER_TASKS | READING_TASKS
EVALUATE = "evaluate"
PING = "ping"  # the connection test: a fixed text, no site data
# What a campus provider serves without a promotion: evaluation runs and the connection test.
UNPROMOTED = frozenset({EVALUATE, PING})
# Never on a campus provider: verdicts (floor signals, conflicts, true-positive advice) and
# rule tuning.
NEVER_ON_CAMPUS = frozenset({"assess", "tune"}) | READING_TASKS
_DECISION = r"^D-\d{3,}$"


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _https(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.query or parts.fragment:
        raise ValueError("a provider is reached over https, with no query or fragment")
    return url.rstrip("/")


class LimitsConfig(_Model):
    rpm: int | None = Field(default=None, ge=1)
    rpd: int | None = Field(default=None, ge=1)
    tpm: int | None = Field(default=None, ge=1)
    tpd: int | None = Field(default=None, ge=1)

    def limits(self) -> budget.Limits:
        return budget.Limits(self.rpm, self.rpd, self.tpm, self.tpd)


class ModelConfig(_Model):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    input_per_m: float = Field(default=0.0, ge=0)
    output_per_m: float = Field(default=0.0, ge=0)
    limits: LimitsConfig | None = None
    extra: dict[str, Any] = {}
    # The context window (prompt and answer together); None: not checked here.
    context_tokens: int | None = Field(default=None, ge=256)
    # Room for the reasoning a model writes before its answer, added to every call's cap: a
    # model that always thinks first counts the thinking against max_tokens.
    thinking_tokens: int = Field(default=0, ge=0, le=32768)
    max_output: int | None = Field(default=None, ge=16)  # the model's own cap, if any
    # The longest prompt sent, else None.
    max_prompt_tokens: int | None = Field(default=None, ge=64)
    # Measured speed: prompt tokens read and answer tokens written a second. Set, they
    # give each call a deadline from its size and judge slowness against them.
    read_tps: float | None = Field(default=None, gt=0)
    write_tps: float | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def _check(self) -> ModelConfig:
        if (self.read_tps is None) != (self.write_tps is None):
            raise ValueError("read_tps and write_tps are set together")
        return self

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (input_tokens * self.input_per_m + output_tokens * self.output_per_m) / 1e6

    def output_cap(self, wanted: int) -> int:
        """max_tokens for a call that wants ``wanted`` tokens of answer."""
        cap = wanted + self.thinking_tokens
        return cap if self.max_output is None else min(cap, self.max_output)

    def fits(self, body_bytes: int, max_tokens: int) -> bool:
        """Whether a body of this size and its answer fit the context (and the prompt is not
        above ``max_prompt_tokens``). Two bytes a token: a tighter estimate than the budget's
        one byte a token, since an overflow is only a refusal (llama-server's 400
        ``exceed_context_size_error``), never a cost."""
        prompt = prompt_tokens(body_bytes) + CONTEXT_OVERHEAD
        if self.max_prompt_tokens is not None and prompt > self.max_prompt_tokens:
            return False
        if self.context_tokens is None:
            return True
        return prompt + max_tokens <= self.context_tokens

    def expected_s(self, prompt: int, answer: int) -> float:
        """How long the model takes to read ``prompt`` tokens and write ``answer`` (its
        reasoning included) at its measured speed; 0 when its speed is not known."""
        if self.read_tps is None or self.write_tps is None:
            return 0.0
        return prompt / self.read_tps + answer / self.write_tps

    def deadline_s(self, body_bytes: int, max_tokens: int) -> float | None:
        """A call's deadline from its size: reading the prompt and writing the whole
        cap at the measured speed, with a margin; None when the speed is not known."""
        if self.read_tps is None:
            return None
        expected = self.expected_s(prompt_tokens(body_bytes), max_tokens)
        return expected * DEADLINE_MARGIN + DEADLINE_BASE_S


CONTEXT_OVERHEAD = 64  # the chat template's tokens around the messages, an upper bound
DEADLINE_MARGIN = 1.5  # a measured speed's room: another load on the machine, a long thought
DEADLINE_BASE_S = 15.0  # the connection (a tunnel, say), the template, the first token


def prompt_tokens(body_bytes: int) -> int:
    """A body's prompt tokens at two bytes a token (an estimate, high for prose)."""
    return math.ceil(body_bytes / 2)


MIDNIGHT = time(0, 0)


class PurposeConfig(_Model):
    """One task's own settings (``purposes`` in config/llm.yaml): ``calls_per_day``, its cap of
    attempts a UTC day over every provider (each provider tried counts one: it errs low);
    ``providers``, the only providers that serve it, in the order they are tried (None: every
    provider that serves it, in the configured order); ``tier``, the model size its caller asks
    for (None: the caller's own)."""

    calls_per_day: int | None = Field(default=None, ge=0)
    providers: tuple[str, ...] | None = Field(default=None, min_length=1)
    tier: Tier | None = None


class EvaluationConfig(_Model):
    """The evaluation budget: evaluation calls go at low priority, only inside the overnight
    window, and at most ``calls_per_day`` a UTC day per provider. The window lies in one UTC day,
    so that is a night's cap, and a run spreads over separate nights instead of using up one (it
    stops and resumes)."""

    window_utc: tuple[time, time] | None = None  # [start, end); end 00:00 means midnight
    calls_per_day: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def _check(self) -> EvaluationConfig:
        if self.window_utc is None:
            return self
        start, end = self.window_utc
        if start.tzinfo is not None or end.tzinfo is not None:
            raise ValueError('window_utc takes UTC times without an offset ("17:30")')
        # One UTC day, so calls_per_day is a night's cap; and never in the site's quiet hours.
        quiet = site.quiet_hours()
        if quiet.overlaps(start, end) or not (start < end or end == MIDNIGHT):
            raise ValueError(
                f'window_utc must lie between {quiet.end} and 24:00 UTC (end "00:00" for'
                f" midnight): the day cap counts per UTC day and the SIEM pauses {quiet}"
            )
        return self

    def opens(self, now: datetime) -> datetime | None:
        """None if an evaluation call may go now; else when the window next opens."""
        if self.window_utc is None:
            return None
        start, end = self.window_utc
        t = now.timetz().replace(tzinfo=None)
        if start <= t and (end == MIDNIGHT or t < end):
            return None
        at = datetime.combine(now.date(), start, now.tzinfo)
        return at if at > now else at + timedelta(days=1)


def _loopback(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Anthropic's Messages API: what a model's ``extra`` may not hold. The sampling settings are
# refused (400) on every model from API version 2026-10-21; the body's own fields are ARGUS's.
# Thinking turns off on Haiku only, and only at effort high or below (400 on Sonnet and Opus).
ANTHROPIC_SAMPLING = ("temperature", "top_p", "top_k")
ANTHROPIC_OWN = ("model", "max_tokens", "system", "messages", "stream")
ANTHROPIC_THINKING_EFFORTS = ("xhigh", "max")  # efforts at which thinking cannot be disabled


def _anthropic_extra(model: str, extra: dict[str, Any]) -> str | None:
    """Why ``extra`` cannot go into an Anthropic body, or None."""
    sampling = [k for k in ANTHROPIC_SAMPLING if k in extra]
    if sampling:
        return f"{', '.join(sampling)}: refused by the API (400 on every model)"
    own = [k for k in ANTHROPIC_OWN if k in extra]
    if own:
        return f"{', '.join(own)}: set by ARGUS, not by extra"
    output = extra.get("output_config")
    if output is not None and (not isinstance(output, dict) or "format" in output):
        return "output_config holds the effort only: the answer's format is set by ARGUS"
    thinking = extra.get("thinking")
    if isinstance(thinking, dict) and thinking.get("type") == "disabled":
        if "haiku" not in model.lower():
            return "only Haiku takes disabled thinking (400 on Sonnet and Opus): lower the effort"
        effort = (output or {}).get("effort")
        if effort in ANTHROPIC_THINKING_EFFORTS:
            return f"disabled thinking takes effort high or below (400 at {effort})"
    return None


class ProviderConfig(_Model):
    name: Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,31}$")]
    base_url: Annotated[str, AfterValidator(_https)]
    keys: tuple[Annotated[str, Field(pattern=r"^[A-Z][A-Z0-9_]*$")], ...] = Field(min_length=1)
    # The wire: OpenAI-compatible chat, or Anthropic's Messages API (sent with api_version)
    api: Literal["openai", "anthropic"] = "openai"
    api_version: Annotated[str, Field(pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")] = "2026-10-21"
    max_tokens_field: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"
    json_mode: bool = True  # OpenAI's json_object; no meaning for anthropic
    schema_output: bool = False  # it takes response_format json_schema when a call has one
    # json_schema only: a call without a schema never goes to it (no plain JSON mode)
    schema_required: bool = False
    enabled: bool = True
    models: dict[Tier, ModelConfig] = Field(min_length=1)
    limits: LimitsConfig | None = None
    trust: Trust = Trust.CLOUD
    ca_file: Path | None = None  # trust this certificate only (relative: to the repository)
    timeout_s: float = Field(default=60.0, gt=0, le=900)  # one call's deadline, at most
    concurrency: int | None = Field(default=None, ge=1, le=16)  # calls in flight, all processes
    tasks: tuple[str, ...] | None = None  # None: every task
    probe: bool = False  # ask GET /v1/models before calls (a machine that is sometimes off)
    slow_s: float = Field(default=120.0, gt=0)  # median latency above this: the model is slow
    # Each helper task a campus provider serves names the decision that promoted it.
    promoted: dict[str, Annotated[str, Field(pattern=_DECISION)]] = {}
    licence: Annotated[str, Field(pattern=_DECISION)] | None = None
    # Its own paid spend caps (USD), under the overall ones; None: the overall cap only.
    monthly_cap_usd: float | None = Field(default=None, ge=0)
    daily_cap_usd: float | None = Field(default=None, ge=0)
    # Body bytes a prompt token, for its rate limits (rpm/tpm/rpd/tpd) only; the cost reserved
    # stays one byte a token, an upper bound.
    bytes_per_token: float = Field(default=1.0, ge=1, le=4)

    @model_validator(mode="after")
    def _check(self) -> ProviderConfig:
        if self.schema_required and not self.schema_output:
            raise ValueError("schema_required needs schema_output")
        if self.api == "anthropic":
            if self.max_tokens_field != "max_tokens":
                raise ValueError("an anthropic provider takes max_tokens")
            for tier, model in self.models.items():
                why = _anthropic_extra(model.name, model.extra)
                if why is not None:
                    raise ValueError(f"{tier.value} model {model.name}: {why}")
        capped = self.monthly_cap_usd is not None or self.daily_cap_usd is not None
        if capped and not all(m.input_per_m > 0 or m.output_per_m > 0
                              for m in self.models.values()):  # fmt: skip
            # a model without a price is reserved at $0: the cap would never hold it
            raise ValueError("a provider with its own cost cap needs every model's price"
                             " (input_per_m, output_per_m)")  # fmt: skip
        if self.tasks is not None:
            unknown = sorted(set(self.tasks) - TASKS)
            if unknown or not self.tasks:
                raise ValueError(f"tasks must be some of {', '.join(sorted(TASKS))}")
        if self.trust is Trust.CAMPUS:
            if not _loopback(self.base_url):
                raise ValueError("a campus provider is reached on this machine (127.0.0.1)")
            if self.ca_file is None:
                raise ValueError("a campus provider needs its own certificate (ca_file)")
            if self.tasks is None:
                raise ValueError("a campus provider needs its task allowlist (tasks)")
            if not self._day_capped():
                raise ValueError("a campus provider needs a daily cap (limits.rpd)")
            never = sorted(set(self.tasks) & NEVER_ON_CAMPUS)
            if never:
                raise ValueError(f"a campus provider never serves {', '.join(never)} in Phase 3")
            unearned = sorted(set(self.tasks) - UNPROMOTED - set(self.promoted))
            if unearned:
                raise ValueError(
                    f"{', '.join(unearned)}: a campus provider serves a helper task only once a"
                    " decision promoted it (promoted: {task: D-NNN})"
                )
        if self.promoted:
            if self.trust is not Trust.CAMPUS:
                raise ValueError("promoted is for a campus provider's helper tasks")
            stray = sorted(set(self.promoted) - (set(self.tasks or ()) & HELPER_TASKS))
            if stray:
                raise ValueError(f"promoted names {', '.join(stray)}, not a helper task it serves")
            if self.licence is None:
                raise ValueError("a promotion needs the licence's confirmation (licence: D-NNN)")
        return self

    @property
    def paid(self) -> bool:
        return any(m.input_per_m > 0 or m.output_per_m > 0 for m in self.models.values())

    def caps(self) -> budget.Caps:
        return budget.Caps(self.monthly_cap_usd, self.daily_cap_usd)

    def _day_capped(self) -> bool:
        if self.limits is not None and self.limits.rpd is not None:
            return True
        return all(m.limits is not None and m.limits.rpd is not None for m in self.models.values())

    def serves(self, task: str) -> bool:
        return self.tasks is None or task in self.tasks

    def call_url(self) -> str:
        return f"{self.base_url}/{'messages' if self.api == 'anthropic' else 'chat/completions'}"

    def models_url(self) -> str:
        """The probe's model list: Anthropic's pages at 20 unless asked for more."""
        return f"{self.base_url}/models" + ("?limit=1000" if self.api == "anthropic" else "")

    def ca_path(self) -> Path | None:
        if self.ca_file is None:
            return None
        return self.ca_file if self.ca_file.is_absolute() else ROOT / self.ca_file

    def lease_for(self, timeout_s: float) -> timedelta:
        """How long a call's slot is held: its deadline and a minute, so a crashed holder's
        slot frees soon after its call would have ended."""
        return timedelta(seconds=timeout_s + 60)

    def buckets(self, tier: Tier) -> tuple[budget.Bucket, ...]:
        """Where a call to this tier counts: the provider's limits and the model's."""
        model = self.models[tier]
        out = []
        if self.limits is not None:
            out.append(budget.Bucket(self.name, self.limits.limits()))
        if model.limits is not None:
            out.append(budget.Bucket(f"{self.name}/{model.name}", model.limits.limits()))
        return tuple(out)


class LlmConfig(_Model):
    keys_file: Path | None = Path("reference/llm_api_keys.env")
    """The provider keys (``NAME=value`` lines, mode 0600); relative: to the repository. None:
    no keys file, so no model is called and ARGUS investigates deterministically."""
    monthly_cap_usd: float = Field(default=10.0, ge=0)
    daily_cap_usd: float | None = Field(default=None, ge=0)
    margin: float = Field(default=0.8, gt=0, le=1)
    shares: dict[budget.Priority, Annotated[float, Field(gt=0, le=1)]] = {
        budget.Priority.HIGH: 1.0,
        budget.Priority.NORMAL: 0.8,
        budget.Priority.LOW: 0.5,
    }
    providers: tuple[ProviderConfig, ...] = Field(min_length=1)
    evaluation: EvaluationConfig = EvaluationConfig()
    purposes: dict[str, PurposeConfig] = {}

    @model_validator(mode="after")
    def _check(self) -> LlmConfig:
        names = [p.name for p in self.providers]
        if len(set(names)) != len(names):
            raise ValueError("provider names must be unique")
        for task, purpose in self.purposes.items():
            if task not in TASKS:
                raise ValueError(f"purposes: {task!r} is not a task ({', '.join(sorted(TASKS))})")
            unknown = sorted(set(purpose.providers or ()) - set(names))
            if unknown:
                raise ValueError(f"purposes.{task}: no provider {', '.join(unknown)}")
            if purpose.providers is not None and len(set(purpose.providers)) != len(
                purpose.providers
            ):
                raise ValueError(f"purposes.{task}: a provider is named twice")
        if set(self.shares) != set(budget.Priority):
            raise ValueError(f"shares needs exactly {', '.join(budget.Priority)}")
        for p in self.providers:  # the overall caps are the ceiling over every paid provider
            if p.monthly_cap_usd is not None and p.monthly_cap_usd > self.monthly_cap_usd:
                raise ValueError(f"{p.name}: monthly_cap_usd is above the overall"
                                 f" monthly_cap_usd ({self.monthly_cap_usd})")  # fmt: skip
            daily = self.daily_cap_usd
            if p.daily_cap_usd is not None and daily is not None and p.daily_cap_usd > daily:
                raise ValueError(f"{p.name}: daily_cap_usd is above the overall daily_cap_usd"
                                 f" ({daily})")  # fmt: skip
        return self

    def budget_config(self) -> budget.Config:
        caps = {p.name: p.caps() for p in self.providers if p.caps() != budget.Caps()}
        return budget.Config(self.monthly_cap_usd, self.margin, dict(self.shares),
                             self.daily_cap_usd, caps)  # fmt: skip


def order_for(config: LlmConfig, task: str) -> tuple[ProviderConfig, ...]:
    """The providers ``task`` may go to, in the order they are tried: its ``purposes`` entry's
    list when it has one, else every provider in the configured order."""
    purpose = config.purposes.get(task)
    if purpose is None or purpose.providers is None:
        return config.providers
    by_name = {p.name: p for p in config.providers}
    return tuple(by_name[n] for n in purpose.providers if n in by_name)


def pinned(config: LlmConfig, name: str, *, allow_disabled: bool = False) -> LlmConfig:
    """``config`` with only the provider ``name`` (an evaluation or a test pins one). A
    disabled provider stays disabled unless ``allow_disabled`` (the person asked for it by
    name: a probe, a ping, an evaluation before it is switched on). Raises ValueError."""
    chosen = [p for p in config.providers if p.name == name]
    if not chosen:
        raise ValueError(f"no provider {name!r}")
    provider = chosen[0]
    if not provider.enabled:
        if not allow_disabled:
            raise ValueError(f"{name} is disabled in config/llm.yaml (--allow-disabled to use it)")
        provider = provider.model_copy(update={"enabled": True})
    return config.model_copy(update={"providers": (provider,)})


def callable_providers(config: LlmConfig) -> list[str]:
    """The enabled providers that have a key: none means no model can be called, and every
    feature that asks one is off."""
    names = {k for p in config.providers for k in p.keys}
    present = load_keys(config.keys_file, names)
    return [p.name for p in config.providers if p.enabled and any(k in present for k in p.keys)]


def models_of(config: LlmConfig) -> str:
    """Which providers and models a run may use, for evaluation keys."""
    return ";".join(f"{p.name}/{t.value}={m.name}" for p in config.providers
                    for t, m in sorted(p.models.items()))  # fmt: skip


LOCAL_OVERLAY = "llm.local.yaml"
_OVERLAY_KEYS = frozenset({"keys_file", "monthly_cap_usd", "daily_cap_usd", "provider_caps"})
_PROVIDER_CAPS = frozenset({"monthly_cap_usd", "daily_cap_usd"})


def load_config(path: Path = DEFAULT_PATH) -> LlmConfig:
    """``path``, with this installation's overlay laid over it when there is one:
    ``llm.local.yaml`` beside it (``argus init`` writes its ``keys_file``), which may also set this
    installation's budget: the overall caps and, under ``provider_caps``, a provider's own."""
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    overlay = path.with_name(LOCAL_OVERLAY)
    if overlay != path and overlay.is_file() and isinstance(data, dict):
        extra = yaml.safe_load(overlay.read_text(encoding="utf-8")) or {}
        if not isinstance(extra, dict) or set(extra) - _OVERLAY_KEYS:
            raise ValueError(f"{LOCAL_OVERLAY} may set {', '.join(sorted(_OVERLAY_KEYS))} only")
        caps = extra.pop("provider_caps", None) or {}
        data = {**data, **extra}
        if caps:
            data["providers"] = _with_caps(data.get("providers"), caps)
    return LlmConfig.model_validate(data)


def _with_caps(providers: Any, caps: Any) -> list[Any]:
    """The providers with the overlay's own caps set on the ones it names."""
    if not isinstance(caps, dict) or not isinstance(providers, list):
        raise ValueError(f"{LOCAL_OVERLAY}: provider_caps maps a provider's name to its caps")
    names = {p.get("name") for p in providers if isinstance(p, dict)}
    unknown = sorted(str(n) for n in caps if n not in names)
    if unknown:
        raise ValueError(
            f"{LOCAL_OVERLAY}: provider_caps names no such provider: {', '.join(unknown)}"
        )
    out = []
    for p in providers:
        own = caps.get(p.get("name")) if isinstance(p, dict) else None
        if own is None:
            out.append(p)
            continue
        if not isinstance(own, dict) or set(own) - _PROVIDER_CAPS:
            allowed = ", ".join(sorted(_PROVIDER_CAPS))
            raise ValueError(f"{LOCAL_OVERLAY}: provider_caps.{p['name']} sets {allowed} only")
        out.append({**p, **own})
    return out


def load_keys(path: Path | None, names: set[str]) -> dict[str, SecretStr]:
    """The named keys that ``path`` (relative: to the repository) holds with a value; the
    others are left out, unread; none when there is no keys file (None). With a credential
    directory (custody) the keys are its ``llm-api-keys.env`` instead, and none without
    one: never a file in a checkout."""
    credentials = os.environ.get("CREDENTIALS_DIRECTORY")
    if credentials:
        path = Path(credentials) / KEYS_CREDENTIAL
    elif path is None:
        return {}
    else:
        path = path if path.is_absolute() else ROOT / path
    if not path.is_file():
        return {}
    out: dict[str, SecretStr] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = _KEY_LINE.match(line)
        if m is None or m.group(1) not in names:
            continue
        value = m.group(2).strip("'\"")
        if value:
            register_secret(value)
            out[m.group(1)] = SecretStr(value)
    return out
