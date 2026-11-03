"""Verified zeros in a dossier's signals (Q-F1): the verdict each log zero gets, stored in
shadow, used only once switched on.

A pack turns every 0 from a log search into "could not tell" (``evidence.from_logs``: reason
``ingest_not_verified``). Here, after the pack derived its signals, each such signal's
evidence is judged by the readings (``model.verify``) and the search's own completeness:

- ``off``: nothing is read or stored; the signals are as the pack derived them;
- ``shadow``: the verdict is stored (``freshness_shadow``), the signals are unchanged, so the
  dossier, its hash and every assessor's input stay byte-identical;
- ``on``: a signal whose every evidence row is verified becomes a known 0 and each row
  records how far its source was complete (``evidence.source_watermark``: "logs complete to
  <time>"); anything else stays "could not tell".

Any failure here leaves the signals as the pack derived them (could not tell): a verified zero
is never a guess, and the shadow never changes production.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any, Literal

from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncConnection

from argus.context.evidence import COMPLETE, SignalValue, canonical
from argus.freshness import store
from argus.freshness.model import GAP, Bridge, Check, Reading, could_not_tell, verify
from argus.gateway.templates import REGISTRY, Family, Window
from argus.observability.redaction import redact_text

log = logging.getLogger("argus.freshness")

LOG_ZERO = "ingest_not_verified"
Mode = Literal["off", "shadow", "on"]
MODES: tuple[Mode, ...] = ("off", "shadow", "on")


@dataclass(frozen=True)
class Policy:
    """What ``freshness.*`` says, as the graph and the reader use it."""

    mode: Mode = "off"
    margins: Mapping[str, timedelta] = field(default_factory=dict)
    gap: timedelta = GAP
    bridge: Bridge = "none"

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"unknown mode {self.mode!r}")
        if any(m < timedelta(0) for m in self.margins.values()):
            raise ValueError("a margin is never negative")

    def margins_s(self) -> dict[str, int]:
        return {s: int(m.total_seconds()) for s, m in sorted(self.margins.items())}


def window_of(row: Mapping[str, Any]) -> Window | None:
    """The log window an evidence row's search read, rebuilt from its template and
    parameters; None when it is not a log search the registry still knows."""
    cls = REGISTRY.get(str(row.get("template")))
    if cls is None or cls.version != row.get("template_version") or cls.family is not Family.LOG:
        return None
    try:
        params = cls.params_model.model_validate_json(canonical(row.get("params")))
        plan = cls().plan(params)
    except (ValidationError, TypeError, ValueError):
        return None
    return plan.window


def complete_search(row: Mapping[str, Any]) -> bool:
    """The search's own part of a verified zero: it answered in full."""
    return row.get("status") in COMPLETE and not row.get("truncated") and not row.get("coverage")


@dataclass(frozen=True)
class RefVerdict:
    task_key: str
    check: Check
    source: str | None = None
    window: Window | None = None
    asked_at: datetime | None = None

    def as_dict(self) -> dict[str, Any]:
        w = self.window
        return {
            "task_key": self.task_key,
            "source": self.source,
            "start": None if w is None else w.start.isoformat(),
            "end": None if w is None else w.end.isoformat(),
            "asked_at": None if self.asked_at is None else self.asked_at.isoformat(),
            "known": self.check.known,
            "reason": self.check.reason,
            "complete_to": None
            if self.check.complete_to is None
            else self.check.complete_to.isoformat(),
            "bridged": self.check.bridged,
        }


def judge_ref(
    key: str,
    row: Mapping[str, Any] | None,
    readings: Mapping[str, Sequence[Reading]],
    policy: Policy,
    bridge: Bridge,
) -> RefVerdict:
    if row is None:
        return RefVerdict(key, could_not_tell("not_log_search"))
    window = window_of(row)
    if window is None:
        return RefVerdict(key, could_not_tell("not_log_search"))
    asked = row.get("asked_at")
    if not complete_search(row):
        return RefVerdict(key, could_not_tell("search_incomplete"), window.source, window, asked)
    if not isinstance(asked, datetime):
        return RefVerdict(key, could_not_tell("not_asked"), window.source, window, None)
    check = verify(
        window.start,
        window.end,
        asked,
        readings.get(window.source, ()),
        policy.margins.get(window.source),
        gap=policy.gap,
        bridge=bridge,
    )
    return RefVerdict(key, check, window.source, window, asked)


@dataclass(frozen=True)
class SignalVerdict:
    signal: str
    refs: tuple[RefVerdict, ...]

    @property
    def known(self) -> bool:
        return bool(self.refs) and all(r.check.known for r in self.refs)

    @property
    def reason(self) -> str:
        if not self.refs:
            return "not_log_search"
        for ref in self.refs:
            if not ref.check.known:
                return ref.check.reason
        return "complete"

    @property
    def complete_to(self) -> datetime | None:
        if not self.known:
            return None
        marks = [r.check.complete_to for r in self.refs if r.check.complete_to is not None]
        return min(marks)


def judge(
    signal: SignalValue,
    rows: Mapping[str, Mapping[str, Any]],
    readings: Mapping[str, Sequence[Reading]],
    policy: Policy,
    bridge: Bridge,
) -> SignalVerdict:
    refs = tuple(
        judge_ref(key, rows.get(key), readings, policy, bridge) for key in sorted(signal.evidence)
    )
    return SignalVerdict(signal.name, refs)


def log_zeros(signals: Sequence[SignalValue]) -> list[SignalValue]:
    return [s for s in signals if s.status == "unknown" and s.unknown_reason == LOG_ZERO]


def known_zero(signal: SignalValue) -> SignalValue:
    """The pack's signal as a verified zero (from_logs turned exactly a 0 into unknown)."""
    return replace(signal, value=0, status="known", unknown_reason=None, completeness="exact")


async def _readings(
    conn: AsyncConnection, rows: Mapping[str, Mapping[str, Any]], gap: timedelta
) -> dict[str, list[Reading]]:
    spans: dict[str, tuple[datetime, datetime]] = {}
    for row in rows.values():
        window = window_of(row)
        asked = row.get("asked_at")
        if window is None or not isinstance(asked, datetime):
            continue
        low, high = spans.get(window.source, (window.start - gap, asked))
        spans[window.source] = (min(low, window.start - gap), max(high, asked))
    return {
        source: await store.readings(conn, source, low, high)
        for source, (low, high) in sorted(spans.items())
    }


async def apply(
    conn: AsyncConnection,
    policy: Policy,
    investigation_id: uuid.UUID,
    version: int,
    pack: str,
    signals: Sequence[SignalValue],
    now: datetime,
) -> list[SignalValue]:
    """The signals after the freshness verdicts (see the module's docstring)."""
    out = list(signals)
    if policy.mode == "off":
        return out
    zeros = log_zeros(out)
    if not zeros:
        return out
    try:
        keys = sorted({k for s in zeros for k in s.evidence})
        rows = await store.evidence(conn, investigation_id, version, keys)
        readings = await _readings(conn, rows, policy.gap)
        verdicts = {}
        shadow = []
        for signal in zeros:
            adopted = judge(signal, rows, readings, policy, policy.bridge)
            edged = judge(signal, rows, readings, policy, "edges")
            verdicts[signal.name] = adopted
            shadow.append(
                {
                    "inv": investigation_id,
                    "v": version,
                    "pack": pack,
                    "signal": signal.name,
                    "mode": policy.mode,
                    "verdict": "known_zero" if adopted.known else "could_not_tell",
                    "reason": adopted.reason,
                    "bridged": "known_zero" if edged.known else "could_not_tell",
                    "complete_to": edged.complete_to,
                    "refs": [r.as_dict() for r in edged.refs],
                    "margins": policy.margins_s(),
                    "at": now,
                }
            )
        async with conn.begin_nested():
            await store.write_shadow(conn, shadow)
            if policy.mode == "on":
                marks = {
                    r.task_key: r.check.complete_to
                    for v in verdicts.values()
                    if v.known
                    for r in v.refs
                    if r.check.complete_to is not None
                }
                await store.mark_watermarks(conn, investigation_id, version, marks)
    except Exception as exc:  # never a guess, never a changed production: could not tell
        log.warning(
            "freshness verdicts not applied: %s", redact_text(f"{type(exc).__name__}: {exc}")
        )
        return list(signals)
    if policy.mode != "on":
        return out
    return [known_zero(s) if s.name in verdicts and verdicts[s.name].known else s for s in out]
