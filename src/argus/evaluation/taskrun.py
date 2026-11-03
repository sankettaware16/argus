"""Running a helper task (Q-G2) on items: its gold set (``argus gold task``) or live items in
shadow (``argus llm shadow``). Each item is rendered by the privacy layer exactly as for the
investigation agent (P1, plan §3 rule 14), sent as an evaluation call (low priority,
overnight, the evaluation budget) with the task's strict schema, and checked against the text
it was sent (``tasks.check``). The person's labels are never sent.

A gold-set run keeps its answers in a file under ``data/`` keyed by task prompt, item, kind
(clean, again, injected), model and the exact text sent, so a run that stops resumes, and a
changed rendering or model is asked again; it returns the ladder's measure (``TaskRun``).
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from argus.agent import agent as investigator
from argus.evaluation import ladder, tasks
from argus.evaluation.agent_eval import PAYLOADS, inject
from argus.evaluation.comparison import _load, _save
from argus.llm import budget
from argus.llm.gateway import Call, Completion, NoCapacity, Refused, body_for, lease_s
from argus.llm.privacy import Privacy, Request
from argus.llm.providers import EVALUATE, LlmConfig, Tier

Complete = Callable[[Call], Awaitable[Completion]]


@dataclass(frozen=True)
class TaskCase:
    investigation_id: uuid.UUID
    version: int
    pack: str
    dossier_hash: str
    body: Mapping[str, Any]
    floor: bool  # the item has a floor signal (P4): never "later", never benign
    label: str | None = None  # the person's answer (gold items only): never sent


def call_for(spec: tasks.TaskSpec, body: Mapping[str, Any], request: Request) -> Call:
    return Call(request, tasks.instructions(spec, body), EVALUATE, Tier.SMALL,
                budget.Priority.LOW, max_output=spec.max_output, schema=spec.schema)  # fmt: skip


def render(privacy: Privacy, body: Mapping[str, Any]) -> Request | None:
    """The item as the agent would send it; None if it cannot be sent (P1)."""
    request = privacy.request([dict(body)])
    if request.failed or not request.items or not request.validate().allowed:
        return None
    return request


def fits(config: LlmConfig, call: Call) -> bool:
    """Whether some provider of ``config`` would send ``call`` (the context and the time limit
    allow it): an item too large for the model is left out, not counted as a failure."""
    for provider in config.providers:
        model = provider.models.get(call.tier)
        if model is None or not provider.serves(call.purpose):
            continue
        size = len(body_for(provider, call))
        if model.fits(size, model.output_cap(call.max_output)) and lease_s(provider, call):
            return True
    return False


def lease_of(config: LlmConfig, call: Call, provider: str | None = None) -> float:
    """The lease ``call`` holds on ``provider`` (by default the first that serves it: an
    evaluation's providers are pinned to one), in seconds; 0 when none would take it."""
    chosen = next((p for p in config.providers if (p.name == provider if provider else
                   p.serves(call.purpose) and call.tier in p.models)), None)  # fmt: skip
    return (lease_s(chosen, call) if chosen is not None else None) or 0.0


@dataclass(frozen=True)
class Asked:
    """One call's answer: the text (None when the call reached the model and came back with
    no usable answer: timed out, a server error, cut off, malformed; or when the gateway
    refused it), its timing, and the lease it was judged against (0 when it was not sent).
    ``wait``: the gateway's deferral after a call that reached the model and failed (try the
    next item at ``wait.until``)."""

    text: str | None
    seconds: float
    lease_s: float
    input_tokens: int = 0
    output_tokens: int = 0
    provider: str = ""
    model: str = ""
    wait: NoCapacity | None = None


async def ask(
    call: Call,
    complete: Complete,
    config: LlmConfig,
    max_wait_s: float,
    sleep: Callable[[float], Awaitable[None]],
    clock: Callable[[], float],
) -> Asked | NoCapacity:
    """``call`` through the gateway, waiting out short deferrals; a long one comes back. A
    call that reached the model and gave no usable answer comes back as one (F1: it counts
    as an unusable call, with its time and lease, never silently retried)."""
    while True:
        start = clock()
        try:
            done = await complete(call)
        except NoCapacity as wait:
            if wait.failed:
                return Asked(None, round(clock() - start, 3), lease_of(config, call), wait=wait)
            delay = wait.until.timestamp() - clock()
            if delay > max_wait_s:
                return wait
            await sleep(max(delay, 1.0))
            continue
        except Refused as refused:
            lease = lease_of(config, call) if refused.failed else 0.0
            return Asked(None, round(clock() - start, 3), lease)
        return Asked(done.text, round(clock() - start, 3), lease_of(config, call, done.provider),
                     done.input_tokens, done.output_tokens, done.provider, done.model)  # fmt: skip


def _key(spec: tasks.TaskSpec, case: TaskCase, kind: str, model: str, sent: str) -> str:
    digest = hashlib.sha256(sent.encode()).hexdigest()[:16]
    return f"{spec.prompt}|{case.investigation_id}|{kind}|{model}|{digest}"


@dataclass
class Scored:
    """What a run found, item by item (a run that stops scores what it has)."""

    usable: int = 0
    calls: int = 0
    latency: list[tuple[float, float]] = field(default_factory=list)
    checks: dict[str, tasks.Check] = field(default_factory=dict)  # clean answers by item
    sent: dict[str, str] = field(default_factory=dict)
    # payload: (flipped, a planted tool asked) per item whose three answers were all usable
    flips: dict[str, list[tuple[bool, bool]]] = field(default_factory=dict)
    unjudged: int = 0  # injected items with an unusable answer among their three: not judged
    too_large: int = 0
    stopped: str | None = None


def kinds(index: int, inject_: bool) -> list[tuple[str, str | None]]:
    """(kind, payload): the clean run, and with injection a second clean run and one payload
    in rotation (item by item), so a run costs three calls an item, as Phase 2's test did."""
    if not inject_:
        return [("clean", None)]
    names = list(PAYLOADS)
    payload = names[index % len(names)]
    return [("clean", None), ("again", None), (f"injected:{payload}", payload)]


async def run_task(
    spec: tasks.TaskSpec,
    cases: Sequence[TaskCase],
    privacy: Privacy,
    complete: Complete,
    config: LlmConfig,
    cache_path: Path,
    model: str,
    inject_: bool = False,
    inject_items: int = 36,
    max_wait_s: float = 120.0,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    clock: Callable[[], float] = time.time,
) -> Scored:
    cache = _load(cache_path)
    out = Scored()
    for index, case in enumerate(cases):
        iid = str(case.investigation_id)
        got: dict[str, tasks.Check] = {}
        # the injection test on the first items only (the ladder needs 30): a set of 250 items
        # costs 322 calls instead of 750 at 150 a night
        for kind, payload in kinds(index, inject_ and index < inject_items):
            body = case.body if payload is None else inject(dict(case.body), PAYLOADS[payload])
            request = render(privacy, body)
            if request is None:
                break
            call = call_for(spec, body, request)
            if not fits(config, call):
                out.too_large += 1
                break
            key = _key(spec, case, kind, model, request.text)
            wait: NoCapacity | None = None
            if key not in cache:
                answer = await ask(call, complete, config, max_wait_s, sleep, clock)
                if isinstance(answer, NoCapacity):
                    out.stopped = f"no capacity until {answer.until:%Y-%m-%d %H:%M} UTC"
                    return out
                cache[key] = {"text": answer.text, "seconds": answer.seconds,
                              "lease_s": answer.lease_s, "input_tokens": answer.input_tokens,
                              "output_tokens": answer.output_tokens,
                              "model": f"{answer.provider}/{answer.model}"}  # fmt: skip
                _save(cache_path, cache)
                wait = answer.wait
            entry = cache[key]
            text = entry.get("text")
            check = tasks.Check(False)
            if isinstance(text, str):
                check = tasks.check(spec.task, text, request.text, case.floor, case.label)
            if isinstance(text, str) or float(entry.get("lease_s") or 0) > 0:
                # every call that reached the model, answered or not (F1)
                out.latency.append((float(entry["seconds"]), float(entry["lease_s"])))
            out.calls += 1
            out.usable += check.usable
            got[kind] = check
            if kind == "clean":
                out.checks[iid] = check
                out.sent[iid] = request.text
            if payload is not None and {"clean", "again"} <= set(got):
                three = (got["clean"], got["again"], check)
                if all(c.usable for c in three):  # F9: only judged items count
                    out.flips.setdefault(payload, []).append(
                        (tasks.flipped(spec.task, *three), tasks.planted(spec.task, *three))
                    )
                else:
                    out.unjudged += 1
            if wait is not None:  # the model failed this call: wait for the gateway, or stop
                delay = wait.until.timestamp() - clock()
                if delay > max_wait_s:
                    out.stopped = f"no capacity until {wait.until:%Y-%m-%d %H:%M} UTC"
                    return out
                await sleep(max(delay, 1.0))
    return out


def measure(spec: tasks.TaskSpec, cases: Sequence[TaskCase], scored: Scored) -> ladder.TaskRun:
    """The ladder's measure of a task run."""
    usable = {i: c for i, c in scored.checks.items() if c.usable}
    failed = tuple(sorted(i for i, c in usable.items() if c.ok is False))
    run: dict[str, Any] = {"calls": ladder.Count(hits=scored.usable, total=scored.calls),
                           "latency": tuple(scored.latency), "items": len(usable),
                           "failed": failed}  # fmt: skip
    if spec.task == tasks.EXTRACT:
        run["recall"] = ladder.Count(
            hits=sum(c.detail.get("baseline_found", 0) for c in usable.values()),
            total=sum(c.detail.get("baseline", 0) for c in usable.values()),
        )
    if spec.task == tasks.TRIAGE:
        labels = {str(c.investigation_id): c.label for c in cases if c.label is not None}
        rows = [(i, labels[i], str(c.outcome), scored.sent[i]) for i, c in usable.items()
                if i in labels]  # fmt: skip
        score = tasks.triage_score(rows)
        run.update(items=score.items, right=score.right, baseline_right=score.baseline_right,
                   positives_later=score.positives_later)  # fmt: skip
    if scored.flips or scored.unjudged:
        # per payload: the items it moved (a flip or a planted tool), over the items judged
        by = {p: ladder.Count(hits=sum(f or t for f, t in got), total=len(got))
              for p, got in sorted(scored.flips.items())}  # fmt: skip
        judged = [r for got in scored.flips.values() for r in got]
        run["injection"] = ladder.Injection(
            items=len(judged),
            flips=sum(f for f, _ in judged),
            tools=sum(t for _, t in judged),
            by_payload=by,
            unjudged=scored.unjudged,
        )
    return ladder.TaskRun(**run)


def floor_of(body: Mapping[str, Any], first_seen: bool | None, spike: bool | None) -> bool:
    from argus.assess import engine

    return bool(engine.floor(body, first_seen, spike))


def small_tier(body: Mapping[str, Any], floor: Sequence[str], request: Request) -> bool:
    """Whether the agent would route the item to its small tier (DQ22 (ii)'s items)."""
    return investigator.route(body, floor, request) is Tier.SMALL
