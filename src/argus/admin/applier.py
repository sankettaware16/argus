"""``argus-admin`` (D-327): the one process that writes what people changed in the app to this
host. It takes the oldest pending save (a batch), checks every value again (its type, the whole
configuration with the new files, the person's right to make it), writes the files, restarts the
services that read them and waits for them; a service that does not come up again puts every file
back. The outcome goes on each row. Its public key and a snapshot of where each setting is set go
to ``admin_state``, which the web reads: the web itself never reads a file of this host."""

from __future__ import annotations

import asyncio
import contextlib
import json
import shutil
import subprocess
import tempfile
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from pydantic import SecretStr, TypeAdapter, ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import ai, catalogue, homes, jobs, outside_check, seal, services
from argus.admin.catalogue import Entry, Risk
from argus.config.settings import ADMIN_FILE, ConfigError, Settings, load_settings
from argus.install import files
from argus.llm.providers import ADMIN_OVERLAY
from argus.web.capabilities import Capability

STEP_UP_VALID = timedelta(minutes=10)  # a sensitive change made this soon after the password
POLL = 2.0  # seconds between looks for a pending save
HEARTBEAT = timedelta(seconds=30)
USAGE_EVERY = timedelta(minutes=5)  # the threat-intel sources' use, for the app's cost page
SETTLE = 6.0  # seconds a restarted service is given before it is checked


class Services(Protocol):
    def active(self, unit: str) -> bool: ...
    def restart(self, units: Sequence[str]) -> None: ...
    def render_units(self) -> str | None: ...  # None, or why the units could not be rendered
    def switch(self, unit: str, on: bool) -> str | None: ...  # None, or why not


class Systemd:
    """This account's systemd user units."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _run(self, *argv: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(argv, capture_output=True, text=True, timeout=120, check=False)  # noqa: S603

    def active(self, unit: str) -> bool:
        return self._run("systemctl", "--user", "is-active", "--quiet", unit).returncode == 0

    def restart(self, units: Sequence[str]) -> None:
        if units:
            self._run("systemctl", "--user", "restart", *units)

    def switch(self, unit: str, on: bool) -> str | None:
        done = self._run("systemctl", "--user", "enable" if on else "disable", "--now", unit)
        return None if done.returncode == 0 else (done.stderr or done.stdout).strip()[-300:]

    def render_units(self) -> str | None:
        argus = shutil.which("argus") or str(self.root / ".venv" / "bin" / "argus")
        done = subprocess.run(  # noqa: S603
            [argus, "units", "install", "--apply", "--reload"],
            cwd=self.root, capture_output=True, text=True, timeout=120, check=False,
        )  # fmt: skip
        return None if done.returncode == 0 else (done.stderr or done.stdout).strip()[-300:]


@dataclass(frozen=True)
class Row:
    id: int
    batch: uuid.UUID
    key: str
    value: Any
    sealed: bytes | None
    reset: bool
    risk: str
    created_by: int
    created_at: datetime
    stepped_up_at: datetime | None


class RefusedError(Exception):
    """A save that is not applied; the message is for the person (never a secret)."""


_CLAIM = text(
    "UPDATE admin_changes SET state = 'applying' WHERE state = 'pending' AND batch ="
    " (SELECT batch FROM admin_changes WHERE state = 'pending' ORDER BY id LIMIT 1)"
    " RETURNING id, batch, key, value, reset, risk, created_by, created_at, stepped_up_at"
)
_SEALED = text("SELECT change_id, sealed FROM admin_sealed WHERE change_id = ANY(:ids)")
_CLAIM_JOB = text(
    "UPDATE admin_jobs SET state = 'running' WHERE id = (SELECT id FROM admin_jobs"
    " WHERE state = 'pending' ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED)"
    " RETURNING id, kind, params, created_by, created_at, stepped_up_at"
)
_JOB_SECRETS = text("SELECT name, sealed FROM admin_job_secrets WHERE job_id = :j")
_JOB_DONE = text(
    "UPDATE admin_jobs SET state = :s, result = CAST(:r AS jsonb), finished_at = :at WHERE id = :j"
)
_FINISH = text(
    "UPDATE admin_changes SET state = :state, outcome = :outcome, finished_at = :at"
    " WHERE batch = :batch AND state = 'applying'"
)
_PUBLISH = text(
    "INSERT INTO admin_state (name, state, updated_at) VALUES (:name, CAST(:state AS jsonb), :at)"
    " ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state, updated_at = EXCLUDED.updated_at"
)
# Local accounts hold their capabilities; an ELK account's come with its live session.
_CAN = text(
    "SELECT u.username, NOT u.disabled AND (:cap = ANY(u.capabilities) OR EXISTS (SELECT 1"
    " FROM user_sessions s WHERE s.user_id = u.id AND s.ended_at IS NULL AND s.expires_at > now()"
    " AND :cap = ANY(s.capabilities))) AS can FROM users u WHERE u.id = :u"
)


def _field(key: str) -> Any:
    section, *rest = key.split(".")
    model: Any = Settings
    info = None
    for part in [section, *rest]:
        info = model.model_fields[part]
        model = info.annotation
        while hasattr(model, "__args__") and not hasattr(model, "model_fields"):
            inner = [a for a in model.__args__ if hasattr(a, "model_fields")]
            if not inner:
                break
            model = inner[0]
    assert info is not None
    return info


def check_value(entry: Entry, value: Any) -> Any:
    """``value`` as the setting's own type takes it (None clears an optional one)."""
    if entry.section == ai.SECTION and not entry.secret:
        try:
            return ai.check(entry, value)
        except ValueError as exc:
            raise RefusedError(str(exc)) from None
    if value is None:
        if not entry.optional:
            raise RefusedError(f"{entry.label} cannot be empty")
        return None
    if entry.secret:
        if not isinstance(value, str) or not value.strip() or "\n" in value or len(value) > 8192:
            raise RefusedError(f"{entry.label}: one line, at most 8,192 characters")
        return value.strip()
    if entry.kind == "duration" and isinstance(value, int | float):
        value = homes.duration_text(value)
    info = _field(entry.key)
    try:
        checked = TypeAdapter(Annotated_of(info)).validate_python(value)
    except ValidationError as exc:
        why = "; ".join(e["msg"] for e in exc.errors()[:3])
        raise RefusedError(f"{entry.label}: {why}") from None
    return checked


def Annotated_of(info: Any) -> Any:  # noqa: N802 - a type expression
    from typing import Annotated

    return Annotated[info.annotation, *info.metadata] if info.metadata else info.annotation


def validate_files(root: Path, plan: homes.Plan) -> None:
    """The whole configuration as the services would load it with the new files."""
    with tempfile.TemporaryDirectory(prefix="argus-admin-") as tmp:
        scratch = Path(tmp)
        shutil.copytree(root / "config", scratch / "config", symlinks=False)
        if plan.admin:
            target = scratch / "config" / ADMIN_FILE
            files.write_public(target, homes.admin_text(files.read_yaml(target), plan.admin))
        env = scratch / ".env"
        if (root / ".env").is_file():
            shutil.copyfile(root / ".env", env)
        if Path(".env") in plan.env:
            files.update_env(env, plan.env[Path(".env")], replace=frozenset(plan.env[Path(".env")]))
        try:
            load_settings(scratch / "config" / "argus.yaml", env_file=env)
        except ConfigError as exc:
            lines = str(exc).replace(str(scratch), "").splitlines()
            raise RefusedError("the settings would not load: " + " ".join(lines)[:500]) from None
        if plan.llm:
            target = scratch / "config" / ADMIN_OVERLAY
            files.write_public(target, homes.admin_text(files.read_yaml(target), plan.llm))
            config, problem = ai.config_of(scratch)
            if config is None:
                said = str(problem).replace(str(scratch), "")
                raise RefusedError("the AI's settings would not load: " + said)


class Applier:
    def __init__(self, engine: AsyncEngine, root: Path, services: Services,
                 clock: Callable[[], datetime] = lambda: datetime.now(UTC),
                 settle: float = SETTLE, custody: bool = False,
                 argus: str | None = None) -> None:  # fmt: skip
        self.engine = engine
        self.root = root
        self.services = services
        self.clock = clock
        self.settle = settle
        self.custody = custody  # the files are root's: the custodian changes them
        self.argus = argus or shutil.which("argus") or str(root / ".venv" / "bin" / "argus")
        self.key = seal.load_or_create(root)
        self.beat: datetime | None = None
        self.used: datetime | None = None

    async def publish(self, name: str, state: Mapping[str, Any]) -> None:
        body = json.dumps(catalogue._json(dict(state)))
        async with self.engine.begin() as conn:
            await conn.execute(_PUBLISH, {"name": name, "state": body, "at": self.clock()})

    async def start(self) -> None:
        await self.publish("seal", {"public_key": seal.public_text(self.key), "version": 1})
        await self.publish("snapshot", snapshot(self.root))

    async def once(self) -> bool:
        """Apply the oldest pending save, if any; whether there was one."""
        now = self.clock()
        if self.beat is None or now - self.beat >= HEARTBEAT:
            await self.publish("heartbeat", {"at": now.isoformat()})
            self.beat = now
        if self.used is None or now - self.used >= USAGE_EVERY:
            await self.publish("usage", await outside_check.usage(self.engine, self.root, now))
            await self.publish("services", await asyncio.to_thread(self.services_state))
            self.used = now
        async with self.engine.begin() as conn:
            claimed = [dict(r._mapping) for r in await conn.execute(_CLAIM)]
            ids = [c["id"] for c in claimed]
            sealed = {r.change_id: r.sealed for r in await conn.execute(_SEALED, {"ids": ids})}
        rows = [Row(**c, sealed=sealed.get(c["id"])) for c in claimed]
        if not rows:
            return False
        state, outcome = await self.apply(rows)
        async with self.engine.begin() as conn:
            await conn.execute(_FINISH, {"state": state, "outcome": outcome[:600],
                                         "at": self.clock(), "batch": rows[0].batch})  # fmt: skip
            await _audit(conn, rows, state, outcome)
        await self.publish("snapshot", snapshot(self.root))
        return True

    async def apply(self, rows: Sequence[Row]) -> tuple[str, str]:
        if self.custody:
            return (
                "refused",
                "under custody the settings are the custodian's (docs/runbooks/custody.md)",
            )
        known = catalogue.by_key() | ai.entries(ai.snapshot(self.root))
        try:
            plans = [await self._plan(row, known.get(row.key)) for row in rows]
            plan = homes.merged(plans)
            validate_files(self.root, plan)
        except RefusedError as exc:
            return "refused", str(exc)
        entries = [known[r.key] for r in rows]
        restart = self._restarts(entries)  # the ones running now: each must run again after
        written = homes.write(self.root, plan)
        mirrored = any(e.mirror for e in entries)
        try:
            if mirrored and (why := self.services.render_units()):
                raise RefusedError(f"the services could not be rendered: {why}")
            await self._restart(restart)
            down = [u for u in restart if not self.services.active(u)]
            if down:
                raise RefusedError(f"{', '.join(down)} did not start with the new settings")
        except RefusedError as exc:
            homes.restore(self.root, written)
            if mirrored:
                self.services.render_units()
            await self._restart(restart)
            return "rolled_back", f"{exc}: the previous settings are back"
        said = ", ".join(e.label for e in entries[:5]) + (" …" if len(entries) > 5 else "")
        restarted = ", ".join(restart) or "none (read at the next run)"
        return "applied", f"{said}: applied; restarted: {restarted}"

    async def _plan(self, row: Row, entry: Entry | None) -> homes.Plan:
        if entry is None or not entry.editable:
            raise RefusedError(f"{row.key} is not a setting the app may change")
        if entry.risk.value != row.risk:
            raise RefusedError(f"{entry.label}: the save's risk does not match the setting's")
        await self._may(row, entry)
        own = ai.plan if entry.section == ai.SECTION else homes.plan
        if row.reset:
            if entry.secret:
                raise RefusedError(f"{entry.label}: a key is replaced, never reset")
            return own(self.root, entry, None, reset=True)
        value: Any = row.value
        if entry.secret:
            if row.sealed is None:
                raise RefusedError(f"{entry.label}: a key arrives sealed only")
            try:
                value = seal.open_sealed(self.key, row.sealed, aad(row.id))
            except seal.SealError:
                raise RefusedError(
                    f"{entry.label}: the key could not be opened (save it again)"
                ) from None
        elif row.sealed is not None:
            raise RefusedError(f"{entry.label}: not a key")
        checked = check_value(entry, value)
        return own(self.root, entry, _plain(checked))

    async def _may(self, row: Row, entry: Entry) -> None:
        async with self.engine.connect() as conn:
            found = (
                await conn.execute(_CAN, {"u": row.created_by, "cap": Capability.ADMIN.value})
            ).first()
        if found is None or not found.can:
            raise RefusedError("the person who saved it may not change settings (any more)")
        stale = row.stepped_up_at is None or row.created_at - row.stepped_up_at > STEP_UP_VALID
        if entry.risk is not Risk.NORMAL and stale:
            raise RefusedError(f"{entry.label}: needs the password confirmed first")

    def _restarts(self, entries: Sequence[Entry]) -> list[str]:
        return self._ordered({u for e in entries for u in e.restarts})

    def _ordered(self, wanted: set[str]) -> list[str]:
        order = [u for u in catalogue.SERVICES if u in wanted and u != "argus-web"]
        if "argus-web" in wanted:
            order.append("argus-web")  # last: the person's page reconnects
        return [u for u in order if self.services.active(u)]

    async def _restart(self, units: Sequence[str]) -> None:
        if units:
            self.services.restart(units)
            await asyncio.sleep(self.settle)

    async def job(self) -> bool:
        """Run the oldest pending job, if any; whether there was one."""
        async with self.engine.begin() as conn:
            found = (await conn.execute(_CLAIM_JOB)).first()
            if found is None:
                return False
            sealed = {r.name: r.sealed for r in await conn.execute(_JOB_SECRETS, {"j": found.id})}
        try:
            result = await self._run_job(found, sealed)
            state = "done"
        except (jobs.JobError, RefusedError) as exc:
            result, state = {"error": str(exc)[:500]}, "failed"
        async with self.engine.begin() as conn:
            done = {"j": found.id, "s": state, "r": json.dumps(result), "at": self.clock()}
            await conn.execute(_JOB_DONE, done)
            await conn.execute(text("DELETE FROM admin_job_secrets WHERE job_id = :j"),
                               {"j": found.id})  # fmt: skip
        if found.kind == "setup" and state == "done" and result.get("ok"):
            result["after"] = await self._after_setup(found.id, sealed)
            again = {"j": found.id, "s": state, "r": json.dumps(result), "at": self.clock()}
            async with self.engine.begin() as conn:
                await conn.execute(_JOB_DONE, again)
        if found.kind in ("setup", "assets") and state == "done" and result.get("ok"):
            await self._restart(self._ordered(set(catalogue.SERVICES)))  # all read them
            await self.publish("snapshot", snapshot(self.root))
        return True

    async def _run_job(self, found: Any, sealed: Mapping[str, bytes]) -> dict[str, Any]:
        if self.custody:
            raise RefusedError("under custody the setup is the custodian's")
        if found.kind == "inspect_tls":
            return await asyncio.to_thread(jobs.inspect_tls, found.params)
        # every other job is an administrator's; the setup and an asset map also a step-up
        async with self.engine.connect() as conn:
            row = (await conn.execute(_CAN, {"u": found.created_by,
                                             "cap": Capability.ADMIN.value})).first()  # fmt: skip
        if row is None or not row.can:
            raise RefusedError("the person who started it may not change settings (any more)")
        if found.kind == "check":
            target = str(found.params.get("target", ""))
            if target.startswith("outside:"):
                try:
                    return await outside_check.check(self.engine, self.root, target[8:],
                                                     self.clock())  # fmt: skip
                except ValueError as exc:
                    raise RefusedError(str(exc)) from None
            return await asyncio.to_thread(jobs.check, self.root, found.params, self.argus)
        if found.kind == "llm_switch":
            return await self._llm_switch(row.username, found.params)
        if found.kind == "service" and found.params.get("action") == "restart":
            return await self._service(found.params)
        if found.stepped_up_at is None or found.created_at - found.stepped_up_at > STEP_UP_VALID:
            raise RefusedError(f"the {_JOB_NAMES.get(found.kind, found.kind)} needs the password"
                               " confirmed first")  # fmt: skip
        try:
            opened = {name: seal.open_sealed(self.key, value, job_aad(found.id, name))
                      for name, value in sealed.items()}  # fmt: skip
        except seal.SealError:
            raise RefusedError("a key could not be opened (start it again)") from None
        if found.kind == "assets":
            return await asyncio.to_thread(jobs.assets, self.root, opened, self.argus)
        if found.kind == "service":
            return await self._service(found.params)
        if found.kind != "setup":
            raise RefusedError(f"not a job argus-admin runs: {found.kind}")
        return await asyncio.to_thread(jobs.setup, self.root, found.params, opened, self.argus)

    async def _service(self, params: Mapping[str, Any]) -> dict[str, Any]:
        """A service or timer switched on or off (``units.run`` in admin.yaml, then systemctl),
        or a service restarted; a switch that systemctl refuses puts admin.yaml back."""
        unit, action = str(params.get("unit", "")), str(params.get("action", ""))
        try:
            services.check(unit, action)
        except ValueError as exc:
            raise RefusedError(str(exc)) from None
        if action == "restart":
            await self._restart([unit])
            up = self.services.active(unit)
            await self.publish("services", self.services_state())
            return {"ok": up, "unit": unit, "action": action,
                    "output": [f"{unit} {'runs again' if up else 'did not start'}"]}  # fmt: skip
        try:
            run = load_settings(self.root / "config" / "argus.yaml",
                                env_file=self.root / ".env").units.run  # fmt: skip
        except ConfigError as exc:
            raise RefusedError(f"the settings do not load: {str(exc)[:200]}") from None
        plan = homes.Plan(admin={"units.run": services.run_after(run, unit, action == "on")})
        validate_files(self.root, plan)
        written = homes.write(self.root, plan)
        why = self.services.switch(unit, action == "on")
        if why is not None:
            homes.restore(self.root, written)
            raise RefusedError(f"systemd refused: {why}")
        await self.publish("services", self.services_state())
        await self.publish("snapshot", snapshot(self.root))
        said = "switched on and started" if action == "on" else "switched off and stopped"
        return {"ok": True, "unit": unit, "action": action, "output": [f"{unit} {said}"]}

    def services_state(self) -> dict[str, Any]:
        try:
            run = load_settings(self.root / "config" / "argus.yaml",
                                env_file=self.root / ".env").units.run  # fmt: skip
        except ConfigError:
            run = None
        return {"units": services.listing(run, self.services.active)}

    async def _after_setup(self, job_id: int, sealed: Mapping[str, bytes]) -> list[str]:
        """What the setup carried besides init's own keys, once init has run: the threat-intel
        and AI keys written where they live, then the asset map imported. Each line says what
        became of one; a key that cannot be stored is said, never raised (init is done)."""
        said: list[str] = []
        known = catalogue.by_key()
        for name in sorted(sealed):
            if name in jobs.SECRETS:
                continue
            try:
                value = seal.open_sealed(self.key, sealed[name], job_aad(job_id, name))
            except seal.SealError:
                said.append(f"{name}: could not be opened; add it again in the app")
                continue
            try:
                if name == jobs.ASSET_MAP:
                    done = await asyncio.to_thread(jobs.assets, self.root, {name: value},
                                                   self.argus)  # fmt: skip
                    said.append(
                        "asset map: "
                        + (
                            "imported"
                            if done["ok"]
                            else "not imported: " + " ".join(done["output"][-2:])
                        )
                    )
                    continue
                if (found := jobs.LLM_KEY.match(name)) is not None:
                    entry = ai.entries(ai.snapshot(self.root)).get(
                        f"llm.keys.{found.group(1).upper()}"
                    )
                    if entry is None:
                        said.append(f"{name}: no provider uses this key")
                        continue
                    plan = ai.plan(self.root, entry, check_value(entry, value))
                else:
                    entry = known[name]
                    plan = homes.plan(self.root, entry, check_value(entry, value))
                homes.write(self.root, plan)
                said.append(f"{entry.label}: stored")
            except (RefusedError, jobs.JobError, OSError) as exc:
                said.append(f"{name}: not stored ({exc})")
        await self.publish("snapshot", snapshot(self.root))
        return said

    async def _llm_switch(self, username: str, params: Mapping[str, Any]) -> dict[str, Any]:
        """The AI's kill switch, as ``argus llm stop`` and ``resume`` (audited)."""
        from argus.llm.store import PgLlmStore

        stop = params.get("stop")
        if not isinstance(stop, bool):
            raise RefusedError("stop: true or false")
        changed = await PgLlmStore(self.engine).set_stopped(
            stop, actor=f"user:{username}", reason="from the app"
        )
        return {"ok": True, "stopped": stop, "changed": changed}

    async def run(self, stop: asyncio.Event) -> None:
        await self.start()
        while not stop.is_set():
            if not await self.once() and not await self.job():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), POLL)


_JOB_NAMES = {"setup": "setup", "assets": "asset map import", "service": "switch"}


def aad(change_id: int) -> bytes:
    return f"admin_change:{change_id}".encode()


def job_aad(job_id: int, name: str) -> bytes:
    return f"admin_job:{job_id}:{name}".encode()


def _plain(value: Any) -> Any:
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, tuple | frozenset | set):
        return [_plain(v) for v in value]
    return value


def snapshot(root: Path) -> dict[str, Any]:
    """Where each setting is set here and its effective value (the shared configuration's; a
    secret only says whether it is set)."""
    try:
        settings = load_settings(root / "config" / "argus.yaml", env_file=root / ".env")
        problem = None
    except ConfigError as exc:
        settings, problem = None, str(exc)[:500]
    out: dict[str, Any] = {}
    for entry in catalogue.catalogue():
        found = homes.homes(root, entry)
        value: Any = None
        if settings is not None:
            value = settings
            for part in entry.key.split("."):
                value = getattr(value, part, None)
        item: dict[str, Any] = {"homes": [h.describe() for h in found],
                                "in_app": any(h.where == "admin" for h in found)}  # fmt: skip
        if entry.secret:
            item["set"] = value is not None or any(h.where != "admin" for h in found)
        else:
            item["value"] = catalogue._json(value)
        if entry.unit_file:
            unit_env = files.read_env(root / "local" / entry.unit_file)
            name = homes.env_name(entry.key)
            if name in unit_env:
                item["value"] = _unit_value(entry, unit_env[name])
        out[entry.key] = item
    return {"settings": out, "problem": problem, "llm": ai.snapshot(root),
            "agents": ai.agents(root)}  # fmt: skip


def _unit_value(entry: Entry, raw: str) -> Any:
    try:
        return catalogue._json(check_value(entry, raw))
    except RefusedError:
        return raw


async def _audit(conn: Any, rows: Sequence[Row], state: str, outcome: str) -> None:
    from argus.web.auth import audit

    name = await conn.scalar(text("SELECT username FROM users WHERE id = :u"),
                             {"u": rows[0].created_by})  # fmt: skip
    await audit(
        conn,
        actor=f"user:{name}",
        action="settings_change",
        outcome="success" if state == "applied" else "failure",
        details={
            "batch": str(rows[0].batch),
            "keys": [r.key for r in rows],
            "state": state,
            "outcome": outcome[:300],
        },
    )
