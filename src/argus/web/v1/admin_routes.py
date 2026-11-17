"""``/api/v1/admin``: the app's Settings (P4-H, D-327).

``GET /admin/settings``: every setting the app shows, section by section, with the value in effect
on this host and where it is set (``argus-admin``'s snapshot; a key's only fact is whether one is
set). ``POST /admin/changes``: one save, applied together by ``argus-admin``; each value is checked
here first, a key is sealed with ``argus-admin``'s public key at once and never stored readable,
a sensitive setting needs a password confirmed in the last five minutes, one that lets ARGUS write
to the SIEM also the words typed. ``GET /admin/changes``: what became of a save (or the latest).
``GET /admin/ai`` (D-328): the AI providers, their keys (set or not), caps and spend, the kill
switch, the AI tasks and the agents; its settings (``llm.*``) are saved like any other. The jobs
argus-admin runs: a TLS inspection, the setup, a connection check, an asset map import and the
AI's kill switch. Every route needs the ``admin`` capability; the web writes no file of this host.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import text

from argus.admin import ai, catalogue, seal
from argus.admin.applier import RefusedError, aad, check_value, job_aad
from argus.admin.catalogue import Risk
from argus.admin.jobs import ASSET_MAP
from argus.web import auth
from argus.web.capabilities import Capability
from argus.web.deps import Conn, Refusal, Surface, need
from argus.web.v1 import admin_models as m

ADMIN = need(Capability.ADMIN, Surface.V1)
ADMIN_CHANGE = need(Capability.ADMIN, Surface.V1, csrf=True)
Admin = Annotated[auth.Reviewer, Depends(ADMIN)]
AdminChange = Annotated[auth.Reviewer, Depends(ADMIN_CHANGE)]
STEP_UP_VALID = timedelta(minutes=5)
ALIVE = timedelta(minutes=2)
CONFIRM_WORDS = "let ARGUS write to the SIEM"

_STATE = text("SELECT name, state, updated_at FROM admin_state")
_INSERT = text(
    "INSERT INTO admin_changes (batch, key, value, reset, risk, created_by, created_at,"
    " stepped_up_at) VALUES (:batch, :key, CAST(:value AS jsonb), :reset, :risk, :by, :at, :up)"
    " RETURNING id"
)
_SEAL = text("INSERT INTO admin_sealed (change_id, sealed) VALUES (:c, :s)")
_CHANGES = (
    "SELECT c.id, c.key, c.state, c.outcome, c.created_at, c.finished_at, u.username AS by"
    " FROM admin_changes c JOIN users u ON u.id = c.created_by"
)


def _refuse(status: int, code: str, detail: str) -> Refusal:
    return Refusal(status, code, detail, Surface.V1)


def install(
    router: APIRouter,
    *,
    clock: Callable[[], datetime],
    errors: Callable[..., dict[int | str, dict[str, Any]]],
) -> None:
    @router.get("/admin/settings", tags=["admin"], operation_id="getSettings",
                responses=errors(401, 403))  # fmt: skip
    async def get_settings(me: Admin, conn: Conn) -> m.SettingsOut:
        """Every setting the app shows, with its value here and where it is set."""
        state = {r.name: (r.state, r.updated_at) for r in await conn.execute(_STATE)}
        snap = state.get("snapshot", ({}, None))[0]
        known = snap.get("settings", {})
        beat = state.get("heartbeat", (None, None))[1]
        sections: list[m.SectionOut] = []
        for key, section in catalogue.SECTIONS.items():
            entries = [e for e in catalogue.catalogue() if e.section == key]
            sections.append(
                m.SectionOut(
                    key=key,
                    label=section.label,
                    about=section.about,
                    settings=[_out(e, known.get(e.key, {})) for e in entries],
                )
            )
        now = clock()
        return m.SettingsOut(
            sections=sections,
            applier=m.ApplierOut(running=beat is not None and now - beat <= ALIVE, last_seen=beat),
            problem=snap.get("problem"),
            confirm_words=CONFIRM_WORDS,
            setup_needed=setup_needed(known),
        )

    @router.post("/admin/changes", tags=["admin"], operation_id="saveSettings", status_code=202,
                 responses=errors(400, 401, 403, 422, 503))  # fmt: skip
    async def save_settings(
        body: m.SettingChangesIn, me: AdminChange, conn: Conn
    ) -> m.SettingChangesOut:
        """One save: checked here, applied together by argus-admin within seconds."""
        snap = (await conn.execute(text(
            "SELECT state FROM admin_state WHERE name = 'snapshot'"))).first()  # fmt: skip
        known = catalogue.by_key() | ai.entries((snap.state if snap else {}).get("llm") or {})
        keys = [c.key for c in body.changes]
        if len(set(keys)) != len(keys):
            raise _refuse(422, "invalid", "A setting is named twice in one save.")
        entries = []
        for change in body.changes:
            entry = known.get(change.key)
            if entry is None or not entry.editable:
                raise _refuse(422, "invalid", f"{change.key} is not a setting the app may change.")
            if change.reset and (change.value is not None or entry.secret):
                raise _refuse(422, "invalid", f"{entry.label}: a reset carries no value.")
            if entry.secret and not change.reset and not str(change.value or "").strip():
                raise _refuse(422, "invalid", f"{entry.label}: a key is replaced, never emptied.")
            if not change.reset:
                try:
                    check_value(entry, change.value)
                except RefusedError as exc:
                    raise _refuse(422, "invalid", f"{exc}.") from None
            entries.append(entry)
        now = clock()
        if any(e.risk is not Risk.NORMAL for e in entries) and (
            me.stepped_up_at is None or now - me.stepped_up_at > STEP_UP_VALID
        ):
            raise _refuse(
                403,
                "step_up_required",
                "Confirm your password again (within five minutes) to change this.",
            )
        words = " ".join((body.confirm or "").split()).lower()
        if any(e.risk is Risk.SIEM_WRITE for e in entries) and words != CONFIRM_WORDS.lower():
            raise _refuse(422, "invalid", f'Type "{CONFIRM_WORDS}" to save this change.')
        public = None
        if any(e.secret for e in entries):
            row = (await conn.execute(text(
                "SELECT state FROM admin_state WHERE name = 'seal'"))).first()  # fmt: skip
            if row is None:
                raise _refuse(
                    503,
                    "unavailable",
                    "argus-admin is not running here, so a key cannot be saved yet.",
                )
            public = row.state["public_key"]
        batch = uuid.uuid4()
        for change, entry in zip(body.changes, entries, strict=True):
            plain = None if entry.secret or change.reset else json.dumps(change.value)
            made = await conn.scalar(_INSERT, {
                "batch": batch, "key": entry.key, "value": plain, "reset": change.reset,
                "risk": entry.risk.value, "by": me.user_id, "at": now, "up": me.stepped_up_at,
            })  # fmt: skip
            if entry.secret and not change.reset:
                assert public is not None
                await conn.execute(_SEAL, {"c": made, "s": seal.seal(
                    public, str(change.value).strip(), aad(int(made)))})  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}", action="settings.save",
                         details={"batch": str(batch), "keys": keys})  # fmt: skip
        return await _changes(conn, batch)

    async def _start(conn: Any, me: auth.Reviewer, kind: str, params: dict[str, Any]) -> int:
        made = await conn.scalar(
            text("INSERT INTO admin_jobs (kind, params, created_by, created_at, stepped_up_at)"
                 " VALUES (:k, CAST(:p AS jsonb), :u, :at, :up) RETURNING id"),
            {"k": kind, "p": json.dumps(params), "u": me.user_id, "at": clock(),
             "up": me.stepped_up_at},
        )  # fmt: skip
        await auth.audit(conn, actor=f"user:{me.username}", action=f"admin_job.{kind}",
                         details={"job": int(made)})  # fmt: skip
        return int(made)

    @router.post("/admin/jobs/inspect-tls", tags=["admin"], operation_id="inspectTls",
                 status_code=202, responses=errors(400, 401, 403, 422))  # fmt: skip
    async def inspect_tls(body: m.InspectIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """The certificates an address presents, read by argus-admin (nothing is trusted)."""
        return await _job(conn, await _start(conn, me, "inspect_tls", {"url": body.url}))

    @router.post("/admin/jobs/setup", tags=["admin"], operation_id="startSetup",
                 status_code=202, responses=errors(400, 401, 403, 422, 503))  # fmt: skip
    async def start_setup(body: m.SetupIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """The first-time setup: argus-admin runs `argus init` with these answers and keys."""
        from argus.admin.jobs import ANSWERS

        if me.stepped_up_at is None or clock() - me.stepped_up_at > STEP_UP_VALID:
            raise _refuse(
                403,
                "step_up_required",
                "Confirm your password again (within five minutes) to run the setup.",
            )
        unknown = sorted(set(body.answers) - ANSWERS)
        if unknown:
            raise _refuse(422, "invalid", f"Not a setup answer: {', '.join(unknown)}.")
        public = None
        if body.keys or body.asset_map:
            row = (await conn.execute(text(
                "SELECT state FROM admin_state WHERE name = 'seal'"))).first()  # fmt: skip
            if row is None:
                raise _refuse(
                    503,
                    "unavailable",
                    "argus-admin is not running here, so the keys cannot be sent yet.",
                )
            public = row.state["public_key"]
        made = await _start(conn, me, "setup", {"answers": body.answers})
        secrets = {name: value.strip() for name, value in body.keys.items()}
        if body.asset_map:
            secrets[ASSET_MAP] = body.asset_map
        for name, value in secrets.items():
            assert public is not None
            await conn.execute(
                text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
                {"j": made, "n": name, "s": seal.seal(public, value, job_aad(made, name))},
            )  # fmt: skip
        return await _job(conn, made)

    async def _sealed_job(conn: Any, me: auth.Reviewer, kind: str, params: dict[str, Any],
                          secrets: dict[str, str]) -> m.JobOut:  # fmt: skip
        row = (await conn.execute(text(
            "SELECT state FROM admin_state WHERE name = 'seal'"))).first()  # fmt: skip
        if row is None:
            raise _refuse(503, "unavailable", "argus-admin is not running here yet.")
        public = row.state["public_key"]
        made = await _start(conn, me, kind, params)
        for name, value in secrets.items():
            await conn.execute(
                text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
                {"j": made, "n": name, "s": seal.seal(public, value, job_aad(made, name))},
            )  # fmt: skip
        return await _job(conn, made)

    @router.post("/admin/jobs/check", tags=["admin"], operation_id="startCheck",
                 status_code=202, responses=errors(400, 401, 403, 422))  # fmt: skip
    async def start_check(body: m.ConnectionCheckIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """A connection check run by argus-admin: the SIEM's key, a Kibana key or an AI provider
        (`argus siem selftest`, `argus kibana selftest`, `argus llm probe`: no prompt is sent)."""
        return await _job(conn, await _start(conn, me, "check", {"target": body.target}))

    @router.post("/admin/jobs/assets", tags=["admin"], operation_id="importAssets",
                 status_code=202, responses=errors(400, 401, 403, 422, 503))  # fmt: skip
    async def import_assets(body: m.AssetsIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """An uploaded asset map, sealed at once, imported by argus-admin (`argus assets
        import`); the services restart with it. Needs the password confirmed."""
        if me.stepped_up_at is None or clock() - me.stepped_up_at > STEP_UP_VALID:
            raise _refuse(
                403,
                "step_up_required",
                "Confirm your password again (within five minutes) to import an asset map.",
            )
        return await _sealed_job(conn, me, "assets", {"bytes": len(body.content.encode())},
                                 {ASSET_MAP: body.content})  # fmt: skip

    @router.post("/admin/jobs/llm-switch", tags=["admin"], operation_id="switchLlm",
                 status_code=202, responses=errors(400, 401, 403, 422))  # fmt: skip
    async def switch_llm(body: m.LlmSwitchIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """The AI's kill switch (as `argus llm stop` and `resume`), set by argus-admin."""
        return await _job(conn, await _start(conn, me, "llm_switch", {"stop": body.stop}))

    @router.get("/admin/ai", tags=["admin"], operation_id="getAi", responses=errors(401, 403))
    async def get_ai(me: Admin, conn: Conn) -> m.AiOut:
        """The AI providers, keys, caps and spend, the kill switch, the AI tasks and the agents."""
        return await ai_out(conn, clock())

    @router.post("/admin/jobs/service", tags=["admin"], operation_id="switchService",
                 status_code=202, responses=errors(400, 401, 403, 422))  # fmt: skip
    async def switch_service(body: m.ServiceIn, me: AdminChange, conn: Conn) -> m.JobOut:
        """A service or timer switched on or off, or a service restarted, by argus-admin. A
        switch needs the password confirmed; one that lets ARGUS write to the SIEM also the
        words typed."""
        from argus.admin import services

        try:
            services.check(body.unit, body.action)
        except ValueError as exc:
            raise _refuse(422, "invalid", f"{exc}.") from None
        if body.action != "restart" and (
            me.stepped_up_at is None or clock() - me.stepped_up_at > STEP_UP_VALID
        ):
            raise _refuse(
                403,
                "step_up_required",
                "Confirm your password again (within five minutes) to switch this.",
            )
        words = " ".join((body.confirm or "").split()).lower()
        if (
            body.action == "on"
            and body.unit in services.SIEM_WRITES
            and (words != CONFIRM_WORDS.lower())
        ):
            raise _refuse(422, "invalid", f'Type "{CONFIRM_WORDS}" to switch this on.')
        return await _job(
            conn, await _start(conn, me, "service", {"unit": body.unit, "action": body.action})
        )

    @router.get("/admin/services", tags=["admin"], operation_id="getServices",
                responses=errors(401, 403))  # fmt: skip
    async def get_services(me: Admin, conn: Conn) -> m.ServicesOut:
        """ARGUS's services and timers: what each does, whether it is on and running."""
        found = text("SELECT state, updated_at FROM admin_state WHERE name = 'services'")
        row = (await conn.execute(found)).first()
        units = [] if row is None else row.state.get("units", [])
        fields = m.ServiceOut.model_fields
        return m.ServicesOut(
            units=[m.ServiceOut(**{k: v for k, v in u.items() if k in fields}) for u in units],
            at=None if row is None else row.updated_at,
            confirm_words=CONFIRM_WORDS,
        )

    @router.get("/admin/usage", tags=["admin"], operation_id="getUsage", responses=errors(401, 403))
    async def get_usage(me: Admin, conn: Conn) -> m.UsageOut:
        """Costs and usage: the AI's spend a day and by task, the threat-intel lookups."""
        return await usage_out(conn, clock())

    @router.get("/admin/jobs/{job_id}", tags=["admin"], operation_id="getAdminJob",
                responses=errors(401, 403, 404, 422))  # fmt: skip
    async def get_job(job_id: Annotated[int, Path(ge=1, le=2**53)], me: Admin,
                      conn: Conn) -> m.JobOut:  # fmt: skip
        """What became of a job."""
        return await _job(conn, job_id)

    @router.get("/admin/changes", tags=["admin"], operation_id="getSettingChanges",
                responses=errors(401, 403, 422))  # fmt: skip
    async def get_changes(
        me: Admin, conn: Conn, batch: Annotated[uuid.UUID | None, Query()] = None
    ) -> m.SettingChangesOut:
        """What became of one save, or the latest fifty changes."""
        return await _changes(conn, batch)


async def setup_pending(conn: Any) -> bool:
    """Whether argus-admin runs here and the SIEM is not set up yet (the session says so)."""
    row = (await conn.execute(text(
        "SELECT state FROM admin_state WHERE name = 'snapshot'"))).first()  # fmt: skip
    return row is not None and setup_needed(row.state.get("settings", {}))


def setup_needed(known: dict[str, Any]) -> bool:
    """Whether this host still lacks the SIEM: its address or its read-only key."""
    url = known.get("siem.url", {}).get("value")
    key = known.get("siem.api_key", {}).get("set")
    return not url or not key


async def _job(conn: Any, job_id: int) -> m.JobOut:
    row = (await conn.execute(text(
        "SELECT id, kind, state, result, created_at, finished_at FROM admin_jobs WHERE id = :j"),
        {"j": job_id})).first()  # fmt: skip
    if row is None:
        raise _refuse(404, "not_found", "No such job.")
    return m.JobOut(**row._mapping)


async def _changes(conn: Any, batch: uuid.UUID | None) -> m.SettingChangesOut:
    where = " WHERE c.batch = :b ORDER BY c.id" if batch else " ORDER BY c.id DESC LIMIT 50"
    rows = await conn.execute(text(_CHANGES + where), {"b": batch})
    return m.SettingChangesOut(
        batch=batch, changes=[m.SettingChangeOut(**r._mapping) for r in rows]
    )


def _out(entry: catalogue.Entry, known: dict[str, Any]) -> m.SettingOut:
    return m.SettingOut(
        key=entry.key,
        label=entry.label,
        help=entry.help,
        kind=entry.kind,
        risk=entry.risk.value,
        editable=entry.editable,
        optional=entry.optional,
        choices=list(entry.choices),
        minimum=entry.minimum,
        maximum=entry.maximum,
        default=entry.default,
        value=None if entry.secret else known.get("value", entry.default),
        is_set=bool(known.get("set")) if entry.secret else None,
        homes=list(known.get("homes", [])),
        in_app=bool(known.get("in_app", False)),
    )


PURPOSE_LABELS = {
    "story": "ARGUS AI's reading of an incident: what happened, the case against it, next steps",
    "opinion": "A second opinion on P1 incidents",
}
TEAM_USERS = ("lead", "evidence", "intel", "responder", "hunter", "reporter", "visualiser")
_SPEND = text(
    "SELECT provider, count(*) AS calls, count(*) FILTER (WHERE outcome = 'ok') AS ok"
    " FROM llm_calls WHERE at >= date_trunc('month', now()) GROUP BY 1"
)
_TASKS = text(
    "SELECT purpose, count(*) FILTER (WHERE at >= date_trunc('day', now())) AS today,"
    " count(*) AS month FROM llm_calls WHERE at >= date_trunc('month', now()) GROUP BY 1"
)


async def ai_out(conn: Any, now: datetime) -> m.AiOut:
    from argus.llm import budget
    from argus.llm.store import read_state

    state = {r.name: (r.state, r.updated_at) for r in await conn.execute(_STATE)}
    snap = state.get("snapshot", ({}, None))[0]
    llm = snap.get("llm") or {}
    known = snap.get("settings", {})
    beat = state.get("heartbeat", (None, None))[1]
    gateway = await read_state(conn)
    calls = {r.provider: r for r in await conn.execute(_SPEND)}
    tasks = {r.purpose: r for r in await conn.execute(_TASKS)}
    entries = ai.entries(llm)
    in_app = set(llm.get("in_app", []))
    month, today = budget.spend(gateway, now)
    providers = []
    for p in llm.get("providers", []):
        p_month, p_today = budget.spend(gateway, now, p["name"])
        alarm = gateway.alarms.get(p["name"])
        used = calls.get(p["name"])
        providers.append(m.AiProviderOut(
            name=p["name"], enabled=p["enabled"], api=p["api"], trust=p["trust"], paid=p["paid"],
            models=p["models"], monthly_cap_usd=p["monthly_cap_usd"],
            daily_cap_usd=p["daily_cap_usd"], month_usd=p_month, today_usd=p_today,
            calls_month=used.calls if used else 0, ok_month=used.ok if used else 0,
            alarm=None if alarm is None else f"{alarm.kind}: {alarm.detail}"[:300],
            keys=[m.AiKeyOut(name=k["name"], setting=f"llm.keys.{k['name']}", is_set=k["set"])
                  for k in p["keys"]],
        ))  # fmt: skip
    purposes = [
        m.AiPurposeOut(task=task, label=PURPOSE_LABELS.get(task, task),
                       calls_per_day=own.get("calls_per_day"), providers=own.get("providers"),
                       tier=own.get("tier"),
                       calls_today=tasks[task].today if task in tasks else 0)
        for task, own in (llm.get("purposes") or {}).items()
    ]  # fmt: skip
    agents = [
        m.AgentOut(**{k: v for k, v in a.items() if k in m.AgentOut.model_fields},
                   calls_month=tasks[a["task"]].month if a.get("task") in tasks else 0)
        for a in snap.get("agents", [])
    ]  # fmt: skip
    team = [
        m.TeamKeyOut(user=f"argus-{u}", setting=f"case_team.{u}_api_key",
                     is_set=bool(known.get(f"case_team.{u}_api_key", {}).get("set")))
        for u in TEAM_USERS
    ]  # fmt: skip
    values = {"llm.monthly_cap_usd": llm.get("monthly_cap_usd"),
              "llm.daily_cap_usd": llm.get("daily_cap_usd")}  # fmt: skip
    for p in llm.get("providers", []):
        for name in ("enabled", "monthly_cap_usd", "daily_cap_usd"):
            values[f"llm.providers.{p['name']}.{name}"] = p.get(name)
    for task, own in (llm.get("purposes") or {}).items():
        for name in ("calls_per_day", "providers", "tier"):
            values[f"llm.purposes.{task}.{name}"] = own.get(name)
    keys_set = {f"llm.keys.{k['name']}": k["set"] for p in llm.get("providers", [])
                for k in p["keys"]}  # fmt: skip
    settings = [
        _out(e, {"value": values.get(e.key), "set": keys_set.get(e.key),
                 "in_app": e.key in in_app,
                 "homes": ["set in the app"] if e.key in in_app else []})
        for e in entries.values()
    ]  # fmt: skip
    expire = known.get("case_team.keys_expire", {}).get("value")
    any_key = any(p["enabled"] and any(k["set"] for k in p["keys"])
                  for p in llm.get("providers", []))  # fmt: skip
    return m.AiOut(
        applier=m.ApplierOut(running=beat is not None and now - beat <= ALIVE, last_seen=beat),
        problem=llm.get("problem") if llm else "argus-admin has not reported this host yet",
        stopped=gateway.stopped,
        any_key=any_key,
        monthly_cap_usd=llm.get("monthly_cap_usd"),
        daily_cap_usd=llm.get("daily_cap_usd"),
        month_usd=month,
        today_usd=today,
        providers=providers,
        purposes=purposes,
        agents=agents,
        readings_on=bool(known.get("risk.reading", {}).get("value")),
        team=team,
        team_keys_expire=None if expire is None else str(expire),
        settings=settings,
    )


_AI_DAYS = text(
    "SELECT to_char(date_trunc('day', at), 'YYYY-MM-DD') AS day, provider, count(*) AS calls,"
    " count(*) FILTER (WHERE outcome = 'ok') AS ok, coalesce(sum(cost_usd), 0) AS cost_usd,"
    " coalesce(sum(input_tokens + output_tokens), 0) AS tokens FROM llm_calls"
    " WHERE at >= :since GROUP BY 1, 2 ORDER BY 1, 2"
)
_AI_TASKS = text(
    "SELECT purpose AS task, count(*) AS calls, coalesce(sum(cost_usd), 0) AS cost_usd"
    " FROM llm_calls WHERE at >= date_trunc('month', CAST(:now AS timestamptz))"
    " GROUP BY 1 ORDER BY 3 DESC, 2 DESC"
)


async def usage_out(conn: Any, now: datetime) -> m.UsageOut:
    from argus.llm import budget
    from argus.llm.store import read_state

    state = {r.name: r.state for r in await conn.execute(_STATE)}
    llm = (state.get("snapshot") or {}).get("llm") or {}
    used = state.get("usage") or {}
    gateway = await read_state(conn)
    month, today = budget.spend(gateway, now)
    since = (now - timedelta(days=30)).replace(hour=0, minute=0, second=0, microsecond=0)
    days = [m.AiDayOut(day=r.day, provider=r.provider, calls=r.calls, ok=r.ok,
                       cost_usd=float(r.cost_usd), tokens=int(r.tokens))
            for r in await conn.execute(_AI_DAYS, {"since": since})]  # fmt: skip
    tasks = [m.AiTaskUseOut(task=r.task, calls=r.calls, cost_usd=float(r.cost_usd))
             for r in await conn.execute(_AI_TASKS, {"now": now})]  # fmt: skip
    at = used.get("at")
    fields = m.SourceUseOut.model_fields
    sources = [m.SourceUseOut(**{k: v for k, v in s.items() if k in fields})
               for s in used.get("sources", []) if isinstance(s, dict)]  # fmt: skip
    return m.UsageOut(
        monthly_cap_usd=llm.get("monthly_cap_usd"),
        daily_cap_usd=llm.get("daily_cap_usd"),
        month_usd=month,
        today_usd=today,
        stopped=gateway.stopped,
        ai_days=days,
        ai_tasks=tasks,
        sources=sources,
        sources_at=None if at is None else datetime.fromisoformat(at),
    )
