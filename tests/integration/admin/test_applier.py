"""argus-admin (D-327) on a throwaway database as the runtime login, on a copy of this checkout's
config in a temporary installation folder, with the services faked: a change is checked, written
where the setting lives, the services that read it restarted, and its outcome recorded; a
refused change writes nothing; a service that does not come up again puts every file back."""

from __future__ import annotations

import json
import shutil
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import applier, seal
from argus.install import files

pytestmark = pytest.mark.integration
REPO = Path(__file__).resolve().parents[3]
NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


class FakeServices:
    def __init__(
        self, up: Sequence[str] = ("argus-web", "argus-collector", "argus-worker")
    ) -> None:
        self.up = set(up)
        self.restarted: list[list[str]] = []
        self.rendered = 0
        self.fail: set[str] = set()
        self.switched: list[tuple[str, bool]] = []

    def active(self, unit: str) -> bool:  # a failing unit fails once it is restarted
        restarted = any(unit in units for units in self.restarted)
        return unit in self.up and not (unit in self.fail and restarted)

    def restart(self, units: Sequence[str]) -> None:
        self.restarted.append(list(units))

    def render_units(self) -> str | None:
        self.rendered += 1
        return None

    def switch(self, unit: str, on: bool) -> str | None:
        self.switched.append((unit, on))
        if unit in self.fail:
            return "Unit not found."
        (self.up.add if on else self.up.discard)(unit)
        return None


@pytest.fixture
def root(tmp_path: Path) -> Path:
    shutil.copytree(REPO / "config", tmp_path / "config")
    (tmp_path / "config" / "admin.yaml").unlink(missing_ok=True)
    (tmp_path / "local").mkdir()
    files.update_env(tmp_path / ".env", {"ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY": "old-vt"})
    files.update_env(tmp_path / "local" / "argus-writer.env", {"ARGUS_CASE_TEAM__POST": "false"})
    (tmp_path / "local" / "creds-sync").mkdir()
    files.write_private(tmp_path / "local" / "creds-sync" / "kibana.reader_api_key", "old-kb")
    return tmp_path


async def a_person(owner: AsyncEngine, caps: Sequence[str] = ("view", "admin")) -> int:
    async with owner.begin() as conn:
        return int(
            await conn.scalar(
                text(
                    "INSERT INTO users (username, display_name, password_hash, capabilities)"
                    " VALUES (:n, 'Mina', 'x', :c) RETURNING id"
                ),
                {"n": f"mina{uuid.uuid4().hex[:6]}", "c": list(caps)},
            )
        )


async def save(owner: AsyncEngine, who: int, changes: list[dict[str, Any]],
               stepped_up: bool = True) -> uuid.UUID:  # fmt: skip
    batch = uuid.uuid4()
    async with owner.begin() as conn:
        for c in changes:
            made = await conn.scalar(
                text(
                    "INSERT INTO admin_changes (batch, key, value, reset, risk, created_by,"
                    " created_at, stepped_up_at) VALUES (:b, :k, CAST(:v AS jsonb), :r, :risk,"
                    " :u, :at, :up) RETURNING id"
                ),
                {"b": batch, "k": c["key"], "v": json.dumps(c["value"]) if "value" in c else None,
                 "r": c.get("reset", False), "risk": c.get("risk", "normal"),
                 "u": who, "at": NOW, "up": NOW - timedelta(minutes=1) if stepped_up else None},
            )  # fmt: skip
            if "sealed" in c:
                await conn.execute(
                    text("INSERT INTO admin_sealed (change_id, sealed) VALUES (:c, :s)"),
                    {"c": made, "s": c["sealed"]},
                )
    return batch


async def outcome(owner: AsyncEngine, batch: uuid.UUID) -> list[tuple[str, str]]:
    async with owner.connect() as conn:
        rows = await conn.execute(
            text("SELECT state, outcome FROM admin_changes WHERE batch = :b ORDER BY id"),
            {"b": batch},
        )
        return [(r.state, r.outcome) for r in rows]


def make(app_engine: AsyncEngine, root: Path, services: FakeServices) -> applier.Applier:
    return applier.Applier(app_engine, root, services, clock=lambda: NOW, settle=0)


async def test_a_change_is_written_to_admin_yaml_and_its_services_restarted(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    services = FakeServices()
    a = make(app_engine, root, services)
    await a.start()
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [{"key": "history.window", "value": "7d"},
                                              {"key": "enrichment.templates",
                                               "value": ["proxy.pair"]}])  # fmt: skip
    assert await a.once()
    (state, said), _ = await outcome(migrated_engine, batch)
    assert state == "applied", said
    assert files.read_yaml(root / "config" / "admin.yaml") == {
        "history": {"window": "7d"},
        "enrichment": {"templates": ["proxy.pair"]},
    }
    assert services.restarted == [["argus-collector", "argus-worker", "argus-web"]]
    assert not (root / "config" / "local.yaml").read_text().count("window: 7d")  # git's untouched
    async with migrated_engine.connect() as conn:
        snap = await conn.scalar(text("SELECT state FROM admin_state WHERE name = 'snapshot'"))
        audit = await conn.scalar(
            text("SELECT details FROM audit_events WHERE action = 'settings_change'")
        )
    assert snap["settings"]["history.window"]["value"] == 7 * 86400
    assert snap["settings"]["history.window"]["in_app"] is True
    assert audit["keys"] == ["history.window", "enrichment.templates"]
    assert not await a.once()  # nothing pending


async def test_a_key_is_sealed_written_everywhere_it_is_set_and_never_in_admin_yaml(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = make(app_engine, root, FakeServices())
    await a.start()
    async with migrated_engine.connect() as conn:
        public = (await conn.scalar(
            text("SELECT state FROM admin_state WHERE name = 'seal'")))["public_key"]  # fmt: skip
    who = await a_person(migrated_engine)
    async with migrated_engine.connect() as conn:
        nxt = int(await conn.scalar(text(
            "SELECT coalesce(max(id), 0) + 1 FROM admin_changes")))  # fmt: skip
    batch = await save(migrated_engine, who, [
        {"key": "kibana.reader_api_key", "risk": "sensitive",
         "sealed": seal.seal(public, "new-kb", applier.aad(nxt))},
        {"key": "outside.virustotal_api_key", "risk": "sensitive",
         "sealed": seal.seal(public, "new-vt", applier.aad(nxt + 1))},
    ])  # fmt: skip
    assert await a.once()
    assert [s for s, _ in await outcome(migrated_engine, batch)] == ["applied", "applied"]
    assert (root / "local" / "creds-sync" / "kibana.reader_api_key").read_text() == "new-kb"
    assert files.read_env(root / ".env")["ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY"] == "new-vt"
    assert "ARGUS_KIBANA__READER_API_KEY" not in files.read_env(root / ".env")  # only its folder
    assert not (root / "config" / "admin.yaml").exists()
    assert oct((root / ".env").stat().st_mode & 0o777) == "0o600"
    async with migrated_engine.connect() as conn:
        snap = await conn.scalar(text("SELECT state FROM admin_state WHERE name = 'snapshot'"))
    assert snap["settings"]["outside.virustotal_api_key"] == {
        "homes": ["in .env"],
        "in_app": False,
        "set": True,
    }
    assert "new-vt" not in json.dumps(snap)


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"key": "history.window", "value": "5 days"}, "Window:"),
        ({"key": "siem.budget.burst_ms", "value": 5}, "not a setting the app may change"),
        ({"key": "nothing.here", "value": 1}, "not a setting the app may change"),
        ({"key": "siem.url", "value": "https://es:9200"}, "risk does not match"),
        ({"key": "outside.virustotal_api_key", "value": "plain", "risk": "sensitive"},
         "arrives sealed only"),
        ({"key": "history.window", "reset": True, "risk": "normal"}, None),
    ],
)  # fmt: skip
async def test_a_bad_change_is_refused_and_writes_nothing(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path,
    change: dict[str, Any], why: str | None,
) -> None:  # fmt: skip
    services = FakeServices()
    a = make(app_engine, root, services)
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [change])
    assert await a.once()
    ((state, said),) = await outcome(migrated_engine, batch)
    if why is None:  # a reset of a setting the app never set: nothing to undo, applied
        assert state == "applied"
        return
    assert state == "refused"
    assert why in said
    assert not (root / "config" / "admin.yaml").exists()
    assert services.restarted == []


async def test_only_an_administrator_and_a_sensitive_change_only_after_the_password(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = make(app_engine, root, FakeServices())
    viewer = await a_person(migrated_engine, ("view",))
    batch = await save(migrated_engine, viewer, [{"key": "history.window", "value": "7d"}])
    await a.once()
    assert "may not change settings" in (await outcome(migrated_engine, batch))[0][1]
    admin = await a_person(migrated_engine)
    batch = await save(migrated_engine, admin, [{"key": "siem.url", "risk": "sensitive",
                                                 "value": "https://es:9200"}],
                       stepped_up=False)  # fmt: skip
    await a.once()
    assert "needs the password confirmed first" in (await outcome(migrated_engine, batch))[0][1]


async def test_a_sealed_key_moved_to_another_change_cannot_be_opened(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = make(app_engine, root, FakeServices())
    await a.start()
    public = seal.public_text(a.key)
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [{"key": "outside.virustotal_api_key",
        "risk": "sensitive", "sealed": seal.seal(public, "x", applier.aad(999_999))}])  # fmt: skip
    await a.once()
    assert "could not be opened" in (await outcome(migrated_engine, batch))[0][1]
    assert files.read_env(root / ".env")["ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY"] == "old-vt"


async def test_a_service_that_does_not_come_back_puts_every_file_back(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    services = FakeServices()
    a = make(app_engine, root, services)
    who = await a_person(migrated_engine)
    services.fail = {"argus-web"}
    batch = await save(migrated_engine, who, [
        {"key": "web.public_url", "risk": "sensitive", "value": "https://127.0.0.1:8443"},
        {"key": "case_team.post", "risk": "siem_write", "value": True},
    ])  # fmt: skip
    await a.once()
    (state, said), _ = await outcome(migrated_engine, batch)
    assert state == "rolled_back", said
    assert "argus-web did not start" in said
    assert not (root / "config" / "admin.yaml").exists()
    assert files.read_env(root / "local" / "argus-writer.env") == {"ARGUS_CASE_TEAM__POST": "false"}
    assert services.rendered == 2  # the web's mirror: rendered with it, then again without


async def test_a_unit_scoped_switch_is_written_in_its_own_file(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = make(app_engine, root, FakeServices())
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [
        {"key": "case_team.post", "risk": "siem_write", "value": True}])  # fmt: skip
    await a.once()
    assert (await outcome(migrated_engine, batch))[0][0] == "applied"
    assert files.read_env(root / "local" / "argus-writer.env") == {"ARGUS_CASE_TEAM__POST": "true"}
    reset = await save(migrated_engine, who, [
        {"key": "case_team.post", "risk": "siem_write", "reset": True}])  # fmt: skip
    await a.once()
    assert (await outcome(migrated_engine, reset))[0][0] == "applied"
    assert files.read_yaml(root / "config" / "admin.yaml") == {}


async def test_under_custody_every_change_is_the_custodians(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = applier.Applier(app_engine, root, FakeServices(), clock=lambda: NOW, settle=0, custody=True)
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [{"key": "history.window", "value": "7d"}])
    await a.once()
    ((state, said),) = await outcome(migrated_engine, batch)
    assert (state, "custodian" in said) == ("refused", True)
    assert not (root / "config" / "admin.yaml").exists()
