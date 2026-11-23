"""The deterministic wave and the executor behind "Check more".

For an undecided investigation with a closable gap, and for a person's request, ARGUS asks the
ranked checks (``gaps``, ``plan``) through the investigation lane before any model is asked: each
check is a catalogue template the rule's own indices allow, sent by the same path every batch-1
request takes, recorded with its reason and an E-id. When something new was learned the
investigation gets one more dossier of the same version (ident ``<pack>+wave.<round>@<version>``).
Nothing here calls a model. A run the SIEM cannot serve goes back in the queue unstarted.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from argus.context import batch1, graph
from argus.context import store as context_store
from argus.context.bounds import quiet
from argus.context.evidence import (
    COMPLETE,
    PackBug,
    SourceUnavailable,
    content,
    extract,
    outcome_of,
    sha256,
)
from argus.context.packs import WAVE_IDENT, PackRegistry, TaskSpec, rebuild
from argus.freshness.shadow import Policy
from argus.gateway import health as health_core
from argus.gateway.errors import GatewayError, LaneBusyError
from argus.gateway.gateway import Gateway, Result, utcnow
from argus.gateway.health import HealthConfig, HealthState
from argus.gateway.state import GatewayState
from argus.gateway.templates import Purpose
from argus.investigation import catalogue, checks, store
from argus.investigation.catalogue import Material, Switches
from argus.investigation.gaps import Assessed, Gap, Profile, find
from argus.investigation.plan import Caps, Plan, Planned, candidates, choose, priority, task_key

log = logging.getLogger("argus.investigation")

COMPONENT = "investigation"  # the kill switch of the lane
PURPOSE = Purpose.INVESTIGATE
ASK_DEADLINE = timedelta(seconds=150)  # one request, budget waits included
HOLD = timedelta(minutes=2)  # how long a pass leaves the SIEM alone after a run-level stop
WAVE = "wave"
OWED_LOOK = 200  # undecided investigations looked at for those the wave still owes
POOL = 60  # undecided investigations a pass looks at to find the most important
ENGINE_TURN = 3  # a person's requests the pass starts before the engine's wave gets a turn
# batch-1 rules that say "not now" at the moment of sending: the run is over, not the check
RUN_LEVEL_RULES = frozenset({"quiet_hours", "not_normal"})


@dataclass
class Env:
    """What a wave needs besides the investigation: the database, the gateway (None for a dry
    run: nothing can be sent), the switches and the caps."""

    engine: AsyncEngine
    state: GatewayState
    gateway: Gateway | None
    packs: PackRegistry
    switches: Switches
    is_own: Callable[[str], bool]
    history: timedelta = timedelta(days=5)
    caps: Caps = field(default_factory=Caps)
    per_day: int = 120
    freshness: Policy | None = None
    health_config: HealthConfig | None = None
    clock: Callable[[], datetime] = utcnow
    # the investigation lane is in debt (or the SIEM said "not now") until then: a pass in this
    # process claims nothing before it
    hold_until: datetime | None = None


@dataclass(frozen=True)
class Prepared:
    current: store.Current
    profile: Profile
    assessed: Assessed | None
    gaps: tuple[Gap, ...]
    material: Material


async def prepare(
    env: Env, conn: AsyncConnection, investigation_id: uuid.UUID, now: datetime
) -> Prepared | None:
    """The newest dossier of an investigation, its rule's profile, the assessor's answer and
    the ranked gaps; None without a dossier at the current version."""
    cur = await store.current(conn, investigation_id)
    return None if cur is None else await prepare_from(env, conn, cur, now)


_LOOK = object()  # "find the assessor's answer in the database"


async def prepare_from(
    env: Env,
    conn: AsyncConnection,
    cur: store.Current,
    now: datetime,
    assessed: Assessed | object | None = _LOOK,
) -> Prepared:
    """The same for a given dossier. The gold measurement prepares the one it scored and passes
    ``assessed=None``: a person's answer is the answer key and must not choose the checks."""
    investigation_id = cur.investigation_id
    profile, normalized = await store.profile_of(conn, investigation_id, cur.body)
    if assessed is _LOOK:
        assessed = await store.assessed_of(conn, cur)
    assert assessed is None or isinstance(assessed, Assessed)
    pack = (cur.body.get("context") or {}).get("pack") or {}
    material = Material(cur.body.get("facts") or {}, pack, now, profile.rule_type, normalized)
    return Prepared(cur, profile, assessed, find(cur.body, profile, assessed), material)


# ----------------------------------------------------------------------------- admission


def _keys(task: TaskSpec) -> tuple[batch1.Key, ...]:
    """What the prevalence gate checks for the packs' own heavy templates when a wave or a
    person asks them: the internal host of a host search or a client's search, the destination of
    a destination search (batch-1 templates carry their own, ``batch1.keys``)."""
    name, ip = type(task.template).name, getattr(task.params, "ip", None)
    if not isinstance(ip, str):
        return ()
    if name == "proxy.destination":
        return (batch1.Key("destination", ip),)
    return (batch1.Key("host", ip),) if name in ("proxy.host", "web.followups") else ()


async def admit(
    env: Env, conn: AsyncConnection, task: TaskSpec, now: datetime
) -> batch1.Refusal | None:
    """The rule that would refuse this request now (None: it may go). A batch-1 template:
    ``batch1.admit`` (its switch, the quiet hours, NORMAL, the prevalence gate, its daily cap).
    The others (host, destination and follow-up searches, threat-list lookups): the quiet
    hours and NORMAL health, and, for the first three, the same prevalence gate and the same
    daily server-time cap per template: a wave never asks about a value
    ARGUS sees in 50 investigations, nor spends more than a template's 90 seconds a day."""
    name = type(task.template).name
    if name in batch1.TEMPLATES:
        return await batch1.admit(
            conn, env.state, task, enabled=env.switches.templates, now=now, history=env.history,
            is_own=env.is_own, health_config=env.health_config,
        )  # fmt: skip
    if quiet(now):
        return batch1.Refusal("quiet_hours")
    config = env.health_config or HealthConfig()
    memory = health_core.effective(await env.state.health(), now, config)
    if memory.state is not HealthState.NORMAL:
        return batch1.Refusal("not_normal", str(memory.state))
    for key in _keys(task):
        seen = await batch1.prevalence(conn, key, now - env.history, env.is_own)
        if batch1.too_common(key, seen):
            return batch1.Refusal("too_common", key.kind)
    if _keys(task) and await spent_in_lane(conn, name, now) >= batch1.DAILY_CAP_MS:
        return batch1.Refusal("daily_cap")
    return None


async def spent_in_lane(conn: AsyncConnection, name: str, now: datetime) -> int:
    """The server time the investigation lane spent on ``name`` today (UTC), from the gateway's
    ledger: the packs' own searches on the enrichment lane do not count against it."""
    day = now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0)
    spent = await conn.scalar(
        text(
            "SELECT coalesce(sum(took_ms), 0) FROM siem_requests"
            " WHERE template = :t AND lane = 'investigation' AND at >= :day"
        ),
        {"t": name, "day": day},
    )
    return int(spent or 0)


async def ready(env: Env, now: datetime) -> bool:
    """Whether a wave may start: not in the quiet hours, the investigation lane's kill switch
    (or the global one) not thrown, the SIEM NORMAL and the overload breaker closed."""
    if quiet(now):
        return False
    if (await env.state.switches()).blocks(COMPONENT):
        return False
    config = env.health_config or HealthConfig()
    memory = health_core.effective(await env.state.health(), now, config)
    if memory.state is not HealthState.NORMAL:
        return False
    closed, _ = await env.state.breaker_peek(now)
    return closed


# ----------------------------------------------------------------------------- planning


def _subject(params: Any) -> dict[str, Any]:
    """What a request is about: its parameters but for the times (the window follows the clock
    for an investigation that is still active)."""
    return {k: v for k, v in params.model_dump(mode="python").items()
            if not isinstance(v, date)}  # fmt: skip


async def retried(
    conn: AsyncConnection, investigation_id: uuid.UUID, version: int, task: TaskSpec
) -> TaskSpec:
    """``task``, but with the parameters of the request the investigation already asked about the
    same subject and got no answer to (a timeout, a deferral, a busy SIEM). The window of a request
    about a still-active investigation follows the clock, so asking again would be a request with a
    key of its own, whose answer the dossier (holding the failed answer under the old key) would
    never take. The same request again has the same key: the answer replaces the failed one."""
    name = type(task.template).name
    new = _subject(task.params)
    for row in await store.unanswered(conn, investigation_id, version, name):
        if row.task_key == task_key(task):
            return task
        try:
            template, params = rebuild(
                {"template": name, "version": row.template_version, "params": row.params,
                 "task_key": row.task_key}
            )  # fmt: skip
        except PackBug:
            continue
        if type(template) is type(task.template) and _subject(params) == new:
            return replace(task, params=params)
    return task


async def plan_wave(
    env: Env,
    conn: AsyncConnection,
    prep: Prepared,
    now: datetime,
    spent: Mapping[str, Any] | None = None,
) -> Plan:
    """What a wave would do for this investigation now; nothing is sent. ``spent``: what the
    wave's earlier runs already asked (it was put back; its caps hold for all its runs)."""
    inv, version = prep.current.investigation_id, prep.current.version
    cands = []
    for c in candidates(prep.gaps, prep.material, env.switches):
        if isinstance(c.task, TaskSpec):
            c = replace(c, task=await retried(conn, inv, version, c.task))
        cands.append(c)
    tasks = [c.task for c in cands if isinstance(c.task, TaskSpec)]
    admission = {task_key(t): await admit(env, conn, t, now) for t in tasks}
    seen = await store.seen_of(conn, inv, list(admission))
    before = spent or {}
    caps = replace(env.caps, requests=max(env.caps.requests - int(before.get("requests", 0)), 0),
                   heavy=max(env.caps.heavy - int(before.get("heavy", 0)), 0))  # fmt: skip
    plan = choose(prep.gaps, cands, admission, seen, caps, now)
    held = sorted({r.code for r in admission.values() if r is not None} & RUN_LEVEL_RULES)
    return replace(plan, waits=held[0]) if held else plan


async def plan_check(
    env: Env, conn: AsyncConnection, prep: Prepared, template: str, entity: str, now: datetime
) -> Plan:
    """What "Check more" would do: the one request, or why it is refused. A refusal of the
    moment (the quiet hours, the SIEM not NORMAL) sets ``waits``: the request waits, it is not
    refused."""
    words = catalogue.CHECKS[template].said if template in catalogue.CHECKS else template
    reason = f"{words} — a person asked"
    task = checks.build(template, entity, prep.material, env.switches, env.is_own)
    if isinstance(task, TaskSpec):
        task = await retried(conn, prep.current.investigation_id, prep.current.version, task)

    def skip(why: str, built: TaskSpec | None = None) -> Plan:
        return Plan(prep.gaps, (Planned(template, "skip", built, None if built is None
                                        else task_key(built), (), 0, reason, why,
                                        template in catalogue.CHECKS
                                        and catalogue.is_heavy(template)),), ())  # fmt: skip

    if isinstance(task, batch1.Refusal):
        return skip(task.detail or task.sentence)
    key = task_key(task)
    seen = (await store.seen_of(conn, prep.current.investigation_id, [key])).get(key)
    heavy = catalogue.is_heavy(template)
    if seen is not None and seen.status in COMPLETE:
        mode = Planned(template, "reuse", task, key, (), 0, reason, None, heavy)
        return Plan(prep.gaps, (mode,), ())
    refused = await admit(env, conn, task, now)
    if refused is not None:
        held = skip(refused.sentence, task)
        return replace(held, waits=refused.code) if refused.code in RUN_LEVEL_RULES else held
    return Plan(prep.gaps, (Planned(template, "send", task, key, (), 0, reason, None, heavy),), ())


# ----------------------------------------------------------------------------- asking


@dataclass(frozen=True)
class Asked:
    task_key: str
    eid: int
    sent: bool
    status: str
    took_ms: int = 0


class _Refused(Exception):  # noqa: N818 - the batch-1 rules said no at the moment of sending
    def __init__(self, refusal: batch1.Refusal) -> None:
        super().__init__(refusal.code)
        self.refusal = refusal


class LaneBusy(SourceUnavailable):
    """The investigation lane is in debt (a slow answer charged more than its minute's share)
    and pays it down at ``until``: nothing was sent, the run is over, the work is not lost."""

    def __init__(self, until: datetime | None) -> None:
        super().__init__("lane_busy")
        self.until = until


async def _dispatch(env: Env, task: TaskSpec, deadline: datetime) -> Result:
    """One request through the investigation lane (never the enrichment lane)."""
    assert env.gateway is not None
    if type(task.template).name in batch1.TEMPLATES:
        async with env.engine.connect() as conn:
            sent = await batch1.send(
                conn, env.gateway, task, enabled=env.switches.templates, history=env.history,
                is_own=env.is_own, deadline=deadline, health_config=env.health_config,
                purpose=PURPOSE, component=COMPONENT,
            )  # fmt: skip
        if isinstance(sent, batch1.Refusal):
            raise _Refused(sent)
        return sent
    return await env.gateway.run(
        task.template, task.params, purpose=PURPOSE, component=COMPONENT, deadline=deadline,
        check=batch1.send_check(env.state, env.health_config),
    )  # fmt: skip


async def ask(env: Env, inv: uuid.UUID, version: int, planned: Planned, origin: str) -> Asked:
    """One planned check, idempotently (as the graph's evidence step is): its E-id first; this
    version's stored answer, else an earlier version's (copied, no request), else the gateway;
    the answer is stored before this returns. Run-level unavailability (a deferral, a kill
    switch, an open breaker, the lane's debt) raises SourceUnavailable: nothing is stored for
    it, and the caller puts the work back."""
    assert planned.task is not None
    task = planned.task
    ref = task.ref()
    key = str(ref["task_key"])
    async with env.engine.begin() as conn:
        eids = await context_store.register_requests(conn, inv, version, [ref], origin,
                                                     env.clock(), planned.reason)  # fmt: skip
        row = await context_store.evidence_row(conn, inv, version, key)
        if row is not None and row["status"] in COMPLETE:
            return Asked(key, eids[key], False, str(row["status"]))
        earlier = await context_store.reusable(conn, inv, [key])
        if key in earlier and earlier[key] != version:
            copied = await context_store.copy_evidence(conn, inv, version, key, earlier[key],
                                                       env.clock())  # fmt: skip
            return Asked(key, eids[key], False, str(copied["status"]))
        purged = key not in earlier and await context_store.purged(conn, inv, key)
    record: dict[str, Any] = {
        "investigation_id": inv, "version": version, "task_key": key,
        "template": ref["template"], "template_version": ref["version"], "params": ref["params"],
        "coverage": {}, "source_watermark": None, "row_count": None, "truncated": False,
        "snapshot": None, "result_hash": None, "took_ms": None, "reused_from_version": None,
        "error": None, "asked_at": None,
    }  # fmt: skip
    sent = False
    if purged or planned.mode != "send":  # never asked again: unknown, never negative
        record.update(status="skipped_budget", coverage={"reason": "purged"})
    else:
        record["asked_at"] = env.clock()  # a verified zero needs a reading from before
        try:
            result = await _dispatch(env, task, env.clock() + ASK_DEADLINE)
            sent = True
        except _Refused as refused:  # a rule that needs the database said no at the last moment
            if refused.refusal.code in RUN_LEVEL_RULES:  # the SIEM left NORMAL, or the quiet hours
                raise SourceUnavailable(refused.refusal.code) from None
            record.update(status="deferred", coverage={"reason": "context_partial"},
                          error=refused.refusal.code)  # fmt: skip
        except LaneBusyError as exc:  # the lane's own debt is not the SIEM's timeout
            raise LaneBusy(exc.retry_at) from exc
        except GatewayError as exc:
            sent = True
            try:
                outcome = outcome_of(exc)  # raises for run-level unavailability
            except PackBug:  # a template the validator refused: never expected, counted
                log.error("the wave's %s request was rejected: %s", planned.template, exc)
                record.update(status="failed", error="rejected")
            else:
                record.update(status=outcome.status, coverage=outcome.coverage,
                              error=outcome.error)  # fmt: skip
        else:
            got = extract(result.body, max_rows=ref["max_rows"], max_bytes=ref["max_bytes"])
            record.update(
                status="ok" if got.has_data else "empty",
                coverage={} if got.exact_total else {"total": "lower_bound"},
                row_count=got.row_count, truncated=got.truncated, snapshot=got.snapshot,
                result_hash=got.result_hash, took_ms=result.took_ms,
            )  # fmt: skip
    record["collected_at"] = env.clock()
    async with env.engine.begin() as conn:
        stored = await context_store.write_evidence(conn, record)
    return Asked(key, eids[key], sent, str(stored["status"]), int(stored["took_ms"] or 0))


# ----------------------------------------------------------------------------- the dossier


def _name(ref: Mapping[str, Any]) -> str:
    return str(ref.get("template") or "").rpartition("@")[0]


def feed(
    base: Mapping[str, Mapping[str, Any]], new: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    """The evidence references the new dossier is derived from: the old ones, with each new one
    where the pack reads it. A pack reads one subject per template: a new reference of a
    template the dossier already has is taken only if it is the same request again (a retried
    or completed answer); an answer about another subject is a check of its own."""
    held = {_name(r) for r in base.values()}
    fed = {k: dict(r) for k, r in base.items()}
    for key, ref in new.items():
        if key in base or _name(ref) not in held:
            fed[key] = dict(ref)
    return dict(sorted(fed.items()))


def changed(base: Mapping[str, Mapping[str, Any]], fed: Mapping[str, Mapping[str, Any]]) -> bool:
    return {k: content(r) for k, r in base.items()} != {k: content(r) for k, r in fed.items()}


async def derive(
    env: Env, prep: Prepared, fed: Mapping[str, Any], asked: list[str], now: datetime
) -> tuple[Mapping[str, Any], list[Mapping[str, Any]]] | None:
    """The wave dossier for ``fed`` and its signals (None: the rounds are used up). Pure but
    for the freshness verdicts the pack's derivation stores."""
    cur = prep.current
    m = WAVE_IDENT.match(cur.pack)
    base = f"{m['name']}@{m['version']}" if m else cur.pack
    async with env.engine.connect() as conn:
        round_ = await store.next_round(conn, cur.investigation_id, cur.version, base)
    if round_ > store.MAX_ROUNDS:
        return None
    name, _, version = base.rpartition("@")
    body = cur.body
    state: dict[str, Any] = {
        "investigation_id": str(cur.investigation_id), "version": cur.version,
        "run_kind": "collect", "facts": body.get("facts") or {},
        "facts_version": body.get("facts_version", cur.version),
        "context": body.get("context") or {},
        "family": body.get("family", ""), "pack": f"{name}+wave.{round_}@{version}",
        "local_signals": body.get("local_signals") or [], "evidence": dict(fed),
        "signals": [], "report": {},
    }  # fmt: skip
    ctx = graph.Ctx(engine=env.engine, gateway=None, packs=env.packs, claim=None,
                    deadline=now, clock=env.clock, freshness=env.freshness)  # fmt: skip
    state.update(await graph.derive_signals(state, ctx))  # type: ignore[arg-type]
    dossier = graph.dossier_of(state)
    dossier["body"]["wave"] = {"round": round_, "of": cur.pack, "from": cur.dossier_hash,
                               "asked": sorted(asked)}  # fmt: skip
    dossier["hash"] = sha256(dossier["body"])
    return dossier, [*state["local_signals"], *state["signals"]]


async def leave_dossier(
    env: Env,
    prep: Prepared,
    fed: Mapping[str, Any],
    asked: list[str],
    now: datetime,
    keep: dict[str, Any] | None = None,
) -> str | None:
    """Derive and store the wave dossier; its ident, or None when the rounds are used up or
    the dossier it was derived from is no longer the newest (another writer left one meanwhile:
    its answers are folded in by the next wave, never overwritten). With ``keep`` (the gold
    measurement) nothing is stored: the derived body is put in ``keep["body"]``."""
    cur = prep.current
    got = await derive(env, prep, fed, asked, now)
    if got is None:
        return None
    dossier, signals = got
    if keep is not None:
        keep["body"] = dossier["body"]
        return str(dossier["pack"])
    async with env.engine.begin() as conn:
        await store.lock(conn, cur.investigation_id)
        newest = await store.current(conn, cur.investigation_id)
        if newest is None or newest.dossier_hash != cur.dossier_hash:
            return None
        # newer than the dossier it was derived from, whatever the clock says
        stamp = max(env.clock(), cur.created_at + timedelta(microseconds=1))
        await store.persist_dossier(
            conn, dossier, signals, stamp,
            {"round": dossier["body"]["wave"]["round"], "asked": len(asked)},
        )  # fmt: skip
    return str(dossier["pack"])


# ----------------------------------------------------------------------------- running


def _check_line(p: Planned, got: Asked | None, why: str | None) -> dict[str, Any]:
    line: dict[str, Any] = {"template": p.template, "mode": p.mode, "reason": p.reason,
                            "heavy": p.heavy}  # fmt: skip
    if got is not None:
        line.update(eid=f"E{got.eid}", status=got.status, sent=got.sent, server_ms=got.took_ms)
    if why:
        line["why_not"] = why
    return line


async def execute(
    env: Env,
    prep: Prepared,
    plan: Plan,
    origin: str,
    keep: dict[str, Any] | None = None,
    spent_before: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Run a plan: ask what it sends, reuse what is stored, and leave the new dossier if something
    was learned. Returns the request's record (what was asked, what it cost, the dossier left). The
    wave's caps (requests, heavy requests, server time; ``spent_before`` is what earlier runs used)
    hold as answers arrive. Run-level unavailability ends the run at once with ``later`` set and no
    dossier: the caller puts the work back and its next run reuses the stored answers."""
    cur = prep.current
    inv, version = cur.investigation_id, cur.version
    base = {str(r["task_key"]): dict(r) for r in cur.body.get("evidence") or []
            if isinstance(r, Mapping) and "task_key" in r}  # fmt: skip
    lines: list[dict[str, Any]] = []
    answered: list[str] = []
    before = spent_before or {}
    requests, heavy, spent = (int(before.get(k, 0)) for k in ("requests", "heavy", "server_ms"))
    stopped: str | None = None
    later: SourceUnavailable | None = None
    for p in plan.checks:
        if p.mode == "skip" or p.task is None:
            lines.append(_check_line(p, None, p.why_not))
            continue
        if later is not None:
            lines.append(_check_line(p, None, stopped))
            continue
        if p.mode == "send":
            if stopped is None and (
                requests >= env.caps.requests
                or spent >= env.caps.server_ms
                or (p.heavy and heavy >= env.caps.heavy)
            ):
                stopped = "this wave's limit of requests or SIEM time"
            if stopped is not None:
                lines.append(_check_line(p, None, stopped))
                continue
        try:
            got = await ask(env, inv, version, p, origin)
        except SourceUnavailable as exc:
            later = exc
            stopped = f"the SIEM is not available now ({exc.reason})"
            lines.append(_check_line(p, None, stopped))
            continue
        if got.sent:
            requests += 1
            heavy += p.heavy
            spent += got.took_ms
        answered.append(got.task_key)
        lines.append(_check_line(p, got, None))
    dossier = None
    if answered and later is None:
        async with env.engine.connect() as conn:
            new = await store.refs_at(conn, inv, version, answered)
        fed = feed(base, new)
        if changed(base, fed):
            dossier = await leave_dossier(env, prep, fed, answered, env.clock(), keep)
    return {
        "gaps": [{"key": g.key, "kind": g.kind.value, "rank": g.rank, "closable": g.closable,
                  "blocker": g.blocker} for g in plan.gaps[: store.OUTCOME_ITEMS]],
        "checks": lines[: store.OUTCOME_ITEMS],
        "left": [list(x) for x in plan.left[: store.OUTCOME_ITEMS]],
        "requests": requests, "heavy": heavy, "server_ms": spent,
        "stopped": stopped, "dossier": dossier,
        "later": None if later is None else {"reason": later.reason, "until": _until(later)},
    }  # fmt: skip


def _until(exc: SourceUnavailable) -> str | None:
    until = getattr(exc, "until", None)
    return until.isoformat() if isinstance(until, datetime) else None


async def run_request(env: Env, request: store.Request) -> tuple[str, dict[str, Any]]:
    """Run one claimed request: its status (``done``, ``refused`` or ``later``: the SIEM was
    not available, or the quiet hours began, put it back) and its record. Only a request that
    cannot be asked at all is refused."""
    now = env.clock()
    async with env.engine.connect() as conn:
        prep = await prepare(env, conn, request.investigation_id, now)
        if prep is None:
            return "refused", {"error": "ARGUS has not built this investigation's dossier yet"}
        if request.kind == WAVE and request.source == "engine":
            # the queue keeps a wave for hours: it is owed to an undecided, unreviewed item
            why = await store.withdrawn(conn, prep.current, request.version)
            if why is not None:
                return "refused", {"error": why}
        if request.kind == WAVE:
            plan = await plan_wave(env, conn, prep, now, request.progress)
        else:
            plan = await plan_check(env, conn, prep, request.template, request.entity, now)
    if plan.waits is not None:  # the SIEM left NORMAL, or the quiet hours began, since the claim
        kept = {k: (request.progress or {}).get(k, 0) for k in ("requests", "heavy", "server_ms")}
        return "later", {**kept, "later": {"reason": plan.waits, "until": None}, "checks": []}
    if request.kind != WAVE and plan.checks[0].mode == "skip":
        return "refused", {"error": plan.checks[0].why_not, "checks": []}
    origin = "wave" if request.source == "engine" else "person"
    outcome = await execute(env, prep, plan, origin, spent_before=request.progress)
    outcome["version"] = prep.current.version
    return ("done" if outcome["later"] is None else "later"), outcome


# ----------------------------------------------------------------------------- the service


async def _prepare_safely(
    env: Env, conn: AsyncConnection, investigation_id: uuid.UUID, now: datetime
) -> Prepared | None:
    """``prepare``, but one investigation's damaged data is skipped (and logged), never fatal
    to the choosing of the others."""
    try:
        return await prepare(env, conn, investigation_id, now)
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        log.warning(
            "investigation %s skipped by the wave: %s", investigation_id, type(exc).__name__
        )
        return None


def workable(env: Env, prep: Prepared) -> bool:
    """Whether a wave could ask anything for this investigation: a closable gap with a check
    that is switched on and can be built from the dossier."""
    return any(isinstance(c.task, TaskSpec)
               for c in candidates(prep.gaps, prep.material, env.switches))  # fmt: skip


async def select(env: Env, conn: AsyncConnection, now: datetime, room: int) -> list[Prepared]:
    """The undecided investigations a wave would take next, most important first: those it
    could ask something for, ordered by ``plan.priority`` (floor gaps, severity, threat intel,
    beacons, successes after an attack), then the newest. At most ``room``, chosen among the
    newest ``POOL`` undecided ones (never fewer than ``room`` allows for)."""
    scored = []
    for inv in await store.undecided(conn, max(4 * room + 20, POOL)):
        prep = await _prepare_safely(env, conn, inv, now)
        if prep is None or prep.current.reviewed or not workable(env, prep):
            continue
        if await store.open_for(conn, inv):
            continue
        newest = -prep.current.created_at.timestamp()
        scored.append((priority(prep.gaps, prep.current.severity), newest, str(inv), prep))
    scored.sort(key=lambda s: s[:3])
    return [s[3] for s in scored[:room]]


async def owed(env: Env, conn: AsyncConnection, now: datetime) -> set[uuid.UUID]:
    """The undecided investigations the wave still owes its checks: the AI investigator waits for
    these (deterministic checks come before any model is asked). While the day's waves are not used
    up: those with no wave yet or whose wave is queued or running; afterwards only those whose wave
    is open. Empty while a wave cannot run (the SIEM not NORMAL, the quiet hours, a kill switch, an
    open breaker): the model does not wait for an outage to end. A wave open for ``store.OWED_FOR``
    holds nobody any longer."""
    if not await ready(env, now):
        return set()
    capped = await store.waves_today(conn, now) >= env.per_day
    found = await store.undecided(conn, OWED_LOOK, "open" if capped else "owed",
                                  now - store.OWED_FOR)  # fmt: skip
    out = set()
    for inv in found:
        prep = await _prepare_safely(env, conn, inv, now)
        if prep is not None and not prep.current.reviewed and workable(env, prep):
            out.add(inv)
    return out


async def _engine_waves(
    env: Env, conn: AsyncConnection, owner: str, now: datetime, wave: bool, need: int,
    counts: dict[str, int],
) -> list[store.Request]:  # fmt: skip
    """Up to ``need`` of the engine's waves to run now: those put back or left over first, then
    (with ``wave`` on, within the day's cap) the most important undecided investigations, each
    queued only now, as it is claimed: the queue never holds a wave that will not run."""
    got = await store.claim(conn, owner, now, need, source="engine")
    if wave and len(got) < need:
        room = min(env.per_day - await store.waves_today(conn, now), need - len(got))
        if room > 0:
            ids = []
            for prep in await select(env, conn, now, room):
                cur = prep.current
                made = await store.enqueue(conn, cur.investigation_id, cur.version, WAVE,
                                           "engine", now)  # fmt: skip
                if made is not None:
                    ids.append(made)
            counts["queued"] += len(ids)
            if ids:
                got += await store.claim(conn, owner, now, len(ids), source="engine", only=ids)
    return got


async def run_pass(env: Env, owner: str, *, wave: bool, limit: int = 1) -> dict[str, int]:
    """One pass of the service: claim up to ``limit`` requests and run them (one by default: a wave
    takes minutes of the lane's time). A person's requests go first, but after three of them in a
    day for each of the engine's waves the engine has its turn; with ``wave`` on, the engine's next
    waves are the most important undecided investigations, within the day's cap. Nothing is claimed
    while the SIEM is not NORMAL, in the quiet hours, with the lane's kill switch thrown or the
    breaker open, or while the lane pays off a debt: requests wait (defer, never fail)."""
    counts = {"queued": 0, "done": 0, "refused": 0, "failed": 0, "waiting": 0}
    now = env.clock()
    if (env.hold_until is not None and now < env.hold_until) or not await ready(env, now):
        return counts
    async with env.engine.begin() as conn:
        persons, engine = await store.started_today(conn, now)
        sources = ("engine", "person") if persons >= ENGINE_TURN * (engine + 1) else (
            "person", "engine")  # fmt: skip
        claimed: list[store.Request] = []
        for source in sources:
            if len(claimed) >= limit:
                break
            need = limit - len(claimed)
            if source == "person":
                claimed += await store.claim(conn, owner, now, need, source="person")
            else:
                claimed += await _engine_waves(env, conn, owner, now, wave, need, counts)
    paused = False
    for request in claimed:
        if paused:  # the SIEM is not available: the rest go back untouched
            async with env.engine.begin() as conn:
                await store.requeue(conn, request.id, now, request.progress or None)
            counts["waiting"] += 1
            continue
        try:
            status, outcome = await run_request(env, request)
        except Exception as exc:  # one request's failure is recorded, never fatal
            log.warning("request %s failed: %s", request.id, type(exc).__name__)
            status, outcome = "failed", {"error": type(exc).__name__}
        if status == "later":
            paused = True
            until = (outcome.get("later") or {}).get("until")
            env.hold_until = datetime.fromisoformat(until) if until else env.clock() + HOLD
            progress = {k: outcome.get(k, 0) for k in ("requests", "heavy", "server_ms")}
            async with env.engine.begin() as conn:
                await store.requeue(conn, request.id, now, progress)
            counts["waiting"] += 1
            continue
        async with env.engine.begin() as conn:
            await store.finish(conn, request.id, status, outcome, env.clock())
        counts[status] += 1
    return counts
