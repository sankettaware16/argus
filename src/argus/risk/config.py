"""The engine's settings: ``config/risk.yaml`` (of the repo, not of the working directory), read
once and checked (unknown keys are errors). Every value is generic: severities, dossier signals,
ATT&CK stages and thresholds; no rule is named."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import timedelta
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from argus.config.errors import ConfigError
from argus.config.sources import read_yaml_file

RISK_PATH = Path(__file__).resolve().parents[3] / "config" / "risk.yaml"
SEVERITIES = ("low", "medium", "high", "critical")
STAGES = ("recon", "access", "foothold", "actions")  # bit 0 .. bit 3 of a stage mask
WINDOWS = ("24h", "7d", "14d")
Stage = Literal["recon", "access", "foothold", "actions"]
Positive = Annotated[float, Field(gt=0)]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Bound(_Model):
    below: float | None = None
    at_most: float | None = None

    @model_validator(mode="after")
    def _one(self) -> Bound:
        if (self.below is None) == (self.at_most is None):
            raise ValueError("a bound is either 'below' or 'at_most'")
        return self


Test = Literal["positive", "true"] | Bound


def passes(test: Test, value: Any) -> bool:
    """Whether a signal's known value passes its test."""
    number = (
        value if isinstance(value, int | float) and not isinstance(value, bool) else None
    )  # fmt: skip
    if test == "true":
        return value is True or (number is not None and number > 0)
    if test == "positive":
        return number is not None and number > 0
    assert isinstance(test, Bound)
    if number is None:
        return False
    if test.below is not None:
        return number < test.below
    assert test.at_most is not None
    return number <= test.at_most


class EvidenceKind(_Model):
    kind: str = Field(pattern=r"^[a-z][a-z0-9_]{0,31}$")
    signals: dict[str, Test] = {}
    flags: tuple[str, ...] = ()
    feeds: dict[str, Literal["mirror", "lookup"]] = {}
    base: Positive
    stale_base: Positive | None = None
    stage: Stage | None = None
    strong: bool = False

    @field_validator("signals", mode="before")
    @classmethod
    def _tests(cls, value: Any) -> Any:
        if isinstance(value, Mapping):  # YAML's bare true is the "true" test
            return {k: ("true" if v is True else v) for k, v in value.items()}
        return value

    @model_validator(mode="after")
    def _checked(self) -> EvidenceKind:
        if not self.signals and not self.flags:
            raise ValueError(f"evidence kind {self.kind} reads no signal and no flag")
        unknown = sorted(set(self.feeds) - set(self.signals))
        if unknown:
            raise ValueError(f"evidence kind {self.kind}: feeds names no signal of it")
        if self.stale_base is not None and not self.feeds:
            raise ValueError(f"evidence kind {self.kind}: stale_base needs feeds")
        return self


class Persistence(_Model):
    base: Positive
    stage: Stage | None = None
    days: int = Field(ge=2, le=14)
    window_days: int = Field(ge=2, le=14)
    max_reach: int = Field(ge=1, le=100)


class Window(_Model):
    hours: int = Field(ge=1, le=24 * 30)
    half_life_hours: Positive

    @property
    def span(self) -> timedelta:
        return timedelta(hours=self.hours)


class Prevalence(_Model):
    k: Positive
    days: int = Field(ge=1, le=30)


class Probation(_Model):
    days: int = Field(ge=0, le=30)
    factor: float = Field(gt=0, le=1)
    reach: int = Field(ge=0, le=1000)


class Families(_Model):
    step: float = Field(ge=0, le=2)
    cap: int = Field(ge=1, le=10)


class Decisive(_Model):
    base: Positive
    with_sources: int = Field(ge=1, le=10)


class Burst(_Model):
    score: Positive
    sources: int = Field(ge=1, le=10)


class Slow(_Model):
    score: Positive
    active_days: int = Field(ge=1, le=7)
    families: int = Field(ge=2, le=10)
    stages: int = Field(ge=2, le=4)


class Lanes(_Model):
    decisive: Decisive
    burst: Burst
    slow: Slow


class Scale(_Model):
    min: Positive
    max: Positive


# --------------------------------------------------------------------------- exposure (E3)


class Sensitive(_Model):
    """A path a site should not serve to the world: a hidden segment (``/.git/``, ``/.env``;
    ``/.well-known/`` is public by design), a backup, dump, key or settings file by its
    extension, or a settings file by its name. Generic web knowledge; no rule is named."""

    hidden: bool = True
    extensions: tuple[str, ...] = ()
    names: tuple[str, ...] = ()


class Bulk(_Model):
    """A bulk take: one outside address got 2xx answers for at least ``paths`` distinct paths
    with at least ``sizes`` distinct body sizes, and ``share`` of its most frequent paths are
    under one sensitive prefix (``/.git/``)."""

    paths: int = Field(ge=2, le=10_000)
    sizes: int = Field(ge=2, le=1_000)
    share: float = Field(gt=0, le=1)


class Shared(_Model):
    """At least ``sources`` outside addresses each got through on at least ``paths`` of the same
    rare paths of one site; a path is rare when at most ``rare_sources`` outside addresses got a
    2xx for it on any own site in the window."""

    sources: int = Field(ge=2, le=50)
    paths: int = Field(ge=1, le=20)
    rare_sources: int = Field(ge=1, le=100)


class Exposure(_Model):
    """Inbound exposure (P4-F E3): the own site is the thing at risk, and the checking lane's
    few targeted checks tell a real leak from a soft-404. ``templates``: the checks the lane may
    send, each only after its first production run passed (none by default: nothing is sent)."""

    templates: tuple[str, ...] = ()
    lookup_every_minutes: int = Field(default=60, ge=10, le=24 * 60)
    lookup_hours: int = Field(default=48, ge=1, le=7 * 24)
    candidate_hours: int = Field(default=48, ge=1, le=7 * 24)
    pass_requests: int = Field(default=10, ge=1, le=50)
    day_ms: int = Field(default=600_000, ge=0, le=3_600_000)
    recheck_hours: int = Field(default=24, ge=1, le=7 * 24)
    take_hint: int = Field(default=5, ge=1, le=20)
    served_min_bytes: int = Field(default=16, ge=1, le=1_000_000)
    window_days: int = Field(default=7, ge=1, le=30)
    keep_days: int = Field(default=180, ge=30, le=400)
    lane_kinds: tuple[str, ...] = ("served", "bulk_take", "shared_paths")
    sensitive: Sensitive = Sensitive()
    bulk: Bulk = Bulk(paths=20, sizes=3, share=0.8)
    shared: Shared = Shared(sources=2, paths=2, rare_sources=6)


class Outbound(_Model):
    """The engine's own evidence for its outbound incidents (D-323): on the checking lane, for
    each presented incident of ``bands`` (top band first, newest material version first), once a
    material version, the checks that decide it: the device's timing to its destination
    (``proxy.pair``), how many internal devices reach that destination (``proxy.contact``) and,
    with no outside address to time, the device's lookups (``dns.host_domains``). Only the
    templates the evidence switch (``enrichment.templates``) holds are asked. At most
    ``pass_requests`` a pass and ``day_requests`` a day (each one heavy: the lane's heavy count
    holds them too), inside ``day_ms`` of the lane's server time a day; an answer about the same
    subject and day at most ``reuse_hours`` old is reused, not asked again; a check that could
    not answer is asked again after ``recheck_hours``."""

    bands: tuple[Literal["P1", "P2", "P3", "P4"], ...] = ("P1", "P2", "P3")
    pairs: int = Field(default=1, ge=1, le=3)
    pass_requests: int = Field(default=6, ge=0, le=30)
    day_requests: int = Field(default=48, ge=0, le=100)
    day_ms: int = Field(default=240_000, ge=0, le=600_000)
    pair_hours: int = Field(default=6, ge=1, le=12)
    reuse_hours: int = Field(default=6, ge=0, le=48)
    recheck_hours: int = Field(default=6, ge=1, le=7 * 24)
    keep_days: int = Field(default=180, ge=30, le=400)


class RiskConfig(_Model):
    version: Literal[1]
    severity_base: dict[Literal["low", "medium", "high", "critical"], Positive]
    default_risk_score: dict[Literal["low", "medium", "high", "critical"], Positive]
    risk_scale: Scale
    unknown_severity_base: Positive
    evidence: tuple[EvidenceKind, ...]
    persistence: Persistence
    feed_fresh_days: int = Field(ge=1, le=90)
    windows: dict[Literal["24h", "7d", "14d"], Window]
    prevalence: Prevalence
    probation: Probation
    families: Families
    lanes: Lanes
    gray_band: float = Field(gt=0, lt=1)
    item_quiet_days: int = Field(ge=1, le=30)
    keep_days: int = Field(ge=14, le=180)
    keep_crossings_days: int = Field(ge=14, le=365)
    max_actors: int = Field(ge=1, le=256)
    max_threats: int = Field(ge=1, le=50)
    digest_samples: int = Field(ge=0, le=20)
    exposure: Exposure = Exposure()
    outbound: Outbound = Outbound()

    @model_validator(mode="after")
    def _complete(self) -> RiskConfig:
        for name, table in (("severity_base", self.severity_base),
                            ("default_risk_score", self.default_risk_score)):  # fmt: skip
            missing = [s for s in SEVERITIES if s not in table]
            if missing:
                raise ValueError(f"{name} lacks {', '.join(missing)}")
        if set(self.windows) != set(WINDOWS):
            raise ValueError("windows are 24h, 7d and 14d")
        kinds = [e.kind for e in self.evidence]
        if len(set(kinds)) != len(kinds) or "persistence" in kinds:
            raise ValueError("evidence kinds are unique, and persistence is its own section")
        if self.risk_scale.min > self.risk_scale.max:
            raise ValueError("risk_scale.min is above its max")
        missing = sorted(set(self.exposure.lane_kinds) - set(kinds))
        if missing:
            raise ValueError(f"exposure.lane_kinds names no evidence kind: {', '.join(missing)}")
        return self

    def kind(self, name: str) -> EvidenceKind | None:
        return next((e for e in self.evidence if e.kind == name), None)


def stage_bit(stage: str | None) -> int:
    return 0 if stage is None else 1 << STAGES.index(stage)


def parse(data: Mapping[str, Any], where: str = "risk config") -> RiskConfig:
    try:
        return RiskConfig.model_validate(data)
    except (ValidationError, ValueError) as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
            for e in (exc.errors() if isinstance(exc, ValidationError) else [])
        ) or str(exc)  # fmt: skip
        raise ConfigError(f"invalid {where}: {problems}") from None


@lru_cache(maxsize=4)
def load(path: Path | None = None) -> RiskConfig:
    """The engine's settings; a missing or invalid file is an error."""
    path = RISK_PATH if path is None else path
    if not path.exists():
        raise ConfigError(f"{path} is missing: it holds the incident engine's weights and lanes")
    data, _ = read_yaml_file(path)
    return parse(data, str(path.name))
