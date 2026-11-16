"""``/api/v1/admin``: the app's Settings (P4-H, D-327).

``GET /admin/settings``: every setting the app shows, section by section, with the value in effect
on this host and where it is set (``argus-admin``'s snapshot; a key's only fact is whether one is
set). ``POST /admin/changes``: one save, applied together by ``argus-admin``; each value is checked
here first, a key is sealed with ``argus-admin``'s public key at once and never stored readable,
a sensitive setting needs a password confirmed in the last five minutes, one that lets ARGUS write
to the SIEM also the words typed. ``GET /admin/changes``: what became of a save (or the latest).
Every route needs the ``admin`` capability; the web writes no file of this host.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy import text

from argus.admin import catalogue, seal
from argus.admin.applier import RefusedError, aad, check_value, job_aad
from argus.admin.catalogue import Risk
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
        known = catalogue.by_key()
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
        if body.keys:
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
        for name, value in body.keys.items():
            assert public is not None
            await conn.execute(
                text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
                {"j": made, "n": name, "s": seal.seal(public, value.strip(), job_aad(made, name))},
            )  # fmt: skip
        return await _job(conn, made)

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
