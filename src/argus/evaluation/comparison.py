"""The privacy comparison (P2, D-078), run through the LLM gateway (P5).

Every answered gold item is rendered by each arm and assessed by one pinned model with one
prompt, at low priority (an evaluation never uses up the day). The person's labels are read
from the database and never sent. Answers are kept in a file under ``data/`` keyed by arm,
item, prompt, model tier and the exact text sent, so a run that stops (a budget, a cut)
resumes where it was, and a changed rendering is asked again. ``A-real`` is refused here:
it needs the user's second confirmation (D-078) and its own path.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from argus import site
from argus.llm import arms, budget, compare, prompts
from argus.llm.gateway import Call, Completion, NoCapacity, Refused
from argus.llm.privacy import Privacy
from argus.llm.providers import Tier

DEFAULT_ARMS = tuple(a for a in arms.ARMS if a not in arms.REAL_DATA)

_GOLD = """
SELECT DISTINCT ON (g.investigation_id) g.investigation_id, l.outcome, d.body
FROM gold_items g
JOIN gold_labels l ON l.set_name = g.set_name AND l.investigation_id = g.investigation_id
JOIN dossiers d ON d.investigation_id = g.investigation_id AND d.version = g.version
  AND d.pack = g.pack AND d.dossier_hash = g.dossier_hash
WHERE g.set_name = :s
ORDER BY g.investigation_id, l.id DESC
"""


@dataclass(frozen=True)
class GoldCase:
    investigation_id: uuid.UUID
    label: str  # the person's newest answer: never sent
    body: Mapping[str, Any]


async def gold_cases(conn: AsyncConnection, set_name: str = "v1") -> list[GoldCase]:
    rows = await conn.execute(text(_GOLD), {"s": set_name})
    return [GoldCase(i, o, b) for i, o, b in rows]


@dataclass
class Run:
    answers: dict[str, dict[str, compare.Answer]] = field(default_factory=dict)
    blocked: dict[str, list[str]] = field(default_factory=dict)  # the validator refused
    unusable: dict[str, list[str]] = field(default_factory=dict)  # no usable outcome
    calls: int = 0
    cost_usd: float = 0.0
    stopped: str | None = None  # why the run stopped early (it resumes from the cache)


def _key(arm: str, case: GoldCase, sent: str, prompt: str, tier: Tier, model: str = "") -> str:
    """The cached answer's key: the arm, the item, the prompt, the tier, the provider and
    model (``provider/model``, Q-G1: a different model is a different answer) and the text."""
    digest = hashlib.sha256(sent.encode()).hexdigest()[:16]
    pinned = f"|{model}" if model else ""
    return f"{arm}|{case.investigation_id}|{prompt}|{tier.value}{pinned}|{digest}"


def _load(path: Path) -> dict[str, dict[str, Any]]:
    if not path.is_file():
        return {}
    data: dict[str, dict[str, Any]] = json.loads(path.read_text(encoding="utf-8"))
    return data


def _save(path: Path, cache: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=".answers-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(cache, handle, indent=1, sort_keys=True)
        os.replace(name, path)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise


async def run(
    cases: Sequence[GoldCase],
    privacy: Privacy,
    complete: Callable[[Call], Awaitable[Completion]],
    cache_path: Path,
    arm_names: Sequence[str] = DEFAULT_ARMS,
    tier: Tier = Tier.SMALL,
    prompt: str = prompts.ASSESS_V1,
    max_wait_s: float = 120.0,
    sleep: Callable[[float], Awaitable[None]] | None = None,
    clock: Callable[[], float] = time.time,
    model: str = "",
) -> Run:
    """Item by item, every arm (so a partial run still compares like for like)."""
    refused = sorted(set(arm_names) & arms.REAL_DATA)
    if refused:
        what = ", ".join(refused)
        raise ValueError(f"{what} sends real {site.noun()} data: not from this runner")
    if sleep is None:
        import asyncio

        sleep = asyncio.sleep
    cache = _load(cache_path)
    out = Run({a: {} for a in arm_names}, {a: [] for a in arm_names}, {a: [] for a in arm_names})
    instructions = prompts.PROMPTS[prompt]
    for case in cases:
        iid = str(case.investigation_id)
        for arm in arm_names:
            request = arms.render(privacy, arm, [dict(case.body)])
            if not request.validate().allowed:
                out.blocked[arm].append(iid)
                continue
            key = _key(arm, case, request.text, prompt, tier, model)
            if key not in cache:
                call = Call(request, instructions, "evaluate", tier, budget.Priority.LOW,
                            max_output=800, schema=prompts.SCHEMAS.get(prompt))  # fmt: skip
                while True:
                    try:
                        start = clock()
                        done = await complete(call)
                        break
                    except NoCapacity as wait:
                        delay = wait.until.timestamp() - clock()
                        if delay > max_wait_s:
                            out.stopped = f"no capacity until {wait.until:%Y-%m-%d %H:%M} UTC"
                            return out
                        await sleep(max(delay, 1.0))
                    except Refused:
                        out.blocked[arm].append(iid)
                        done = None
                        break
                if done is None:
                    continue
                cache[key] = {
                    "text": done.text,
                    "tokens": done.input_tokens + done.output_tokens,
                    "seconds": round(clock() - start, 3),
                    "model": f"{done.provider}/{done.model}",
                }
                out.calls += 1
                out.cost_usd += done.cost_usd
                _save(cache_path, cache)
            entry = cache[key]
            parsed = prompts.parse(entry["text"])
            if parsed.outcome is None:
                out.unusable[arm].append(iid)
                continue
            out.answers[arm][iid] = compare.Answer(
                parsed.outcome, None, parsed.asks_withheld, entry["tokens"], entry["seconds"]
            )
    return out


def report(cases: Sequence[GoldCase], result: Run, reference: str = "A-fake") -> list[str]:
    """The comparison table and the decision of D-078, in plain lines."""
    gold = {str(c.investigation_id): c.label for c in cases}
    lines = [f"items with a person's answer: {len(gold)}; calls this run: {result.calls}"
             f" (${result.cost_usd:.4f})"]  # fmt: skip
    for arm in result.answers:
        extra = []
        if result.blocked.get(arm):
            extra.append(f"{len(result.blocked[arm])} blocked by the validator")
        if result.unusable.get(arm):
            extra.append(f"{len(result.unusable[arm])} unusable answers")
        if extra:
            lines.append(f"  {arm}: {', '.join(extra)}")
    if result.stopped:
        lines.append(f"stopped early: {result.stopped} (run again to resume)")
    answered = {a: v for a, v in result.answers.items() if v}
    if reference not in answered or "B" not in answered:
        lines.append("not enough answers to compare yet")
        return lines
    try:
        scores = compare.score(gold, answered, reference)
    except ValueError as exc:
        lines.append(f"cannot score: {exc}")
        return lines
    lines.append("arm        items  accuracy  TP recall  missed TP  agree w/ ref  McNemar p"
                 "  asks withheld  tokens")  # fmt: skip
    for name, s in scores.items():
        recall = "-" if s.recall is None else f"{s.recall:.0%}"
        lines.append(
            f"{name:10} {s.items:5}  {s.accuracy:8.0%}  {recall:>9}  {len(s.missed):9}"
            f"  {s.agreement:12.0%}  {s.mcnemar_p:9.3f}  {s.asked_withheld:13.0%}"
            f"  {s.tokens:6.0f}"
        )
    decision = compare.decide(scores, reference=reference)
    verdict = "KEEP the policy" if decision.keep else (
        f"LOOSEN {', '.join(decision.loosen)}" if decision.loosen else "ASK THE USER"
    )  # fmt: skip
    lines.append(f"decision (D-078): {verdict}: {decision.reason}")
    return lines
