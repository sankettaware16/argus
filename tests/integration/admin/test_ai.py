"""The AI's settings and the new jobs through argus-admin (D-328), on a throwaway database and a
copy of this checkout's config: a provider key is sealed and written to the keys file (the app's
own when none is configured, named in ``llm.admin.yaml``), switches and caps go to
``llm.admin.yaml`` and are checked with the whole LLM configuration, a reset returns to the files'
value; a connection check, an asset map import and the kill switch run for an administrator."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import ai, applier, seal
from argus.install import files
from tests.integration.admin.test_applier import NOW, FakeServices, a_person, outcome, save
from tests.integration.admin.test_jobs import job, start

pytestmark = pytest.mark.integration

STAND_IN = """#!/usr/bin/env bash
echo "$@" > "{out}/argv.txt"
if [ "$1" = assets ]; then cp "$3" "{out}/map.yaml"; stat -c %a "$3" > "{out}/mode.txt"; fi
echo "checked (api_key: sk-should-be-masked)"
[ "$1" != llm ]
"""


@pytest.fixture
def bare(root: Path) -> Path:
    """An installation without a keys file (the public tree's case)."""
    (root / "config" / "llm.local.yaml").unlink(missing_ok=True)
    (root / "config" / ai.ADMIN_OVERLAY).unlink(missing_ok=True)
    return root


def make(app_engine: AsyncEngine, root: Path, services: FakeServices,
         argus: str | None = None) -> applier.Applier:  # fmt: skip
    return applier.Applier(app_engine, root, services, clock=lambda: NOW, settle=0, argus=argus)


async def test_keys_switches_and_caps_from_the_app(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, bare: Path
) -> None:
    services = FakeServices()
    a = make(app_engine, bare, services)
    await a.start()
    who = await a_person(migrated_engine)
    batch = await save(migrated_engine, who, [
        {"key": "llm.keys.GROQ_API_KEY", "risk": "sensitive", "sealed": b""},
        {"key": "llm.providers.groq.enabled", "value": False},
        {"key": "llm.purposes.story.calls_per_day", "value": 4},
        {"key": "llm.monthly_cap_usd", "value": 12, "risk": "sensitive"},
    ])  # fmt: skip
    async with migrated_engine.begin() as conn:  # the key sealed for its own change
        made = await conn.scalar(text("SELECT id FROM admin_changes WHERE batch = :b ORDER BY id"
                                      " LIMIT 1"), {"b": batch})  # fmt: skip
        await conn.execute(
            text("UPDATE admin_sealed SET sealed = :s WHERE change_id = :c"),
            {"s": seal.seal(seal.public_text(a.key), "gsk-new", applier.aad(made)), "c": made},
        )
    assert await a.once()
    states = await outcome(migrated_engine, batch)
    assert {s for s, _ in states} == {"applied"}, states
    keys = bare / ai.APP_KEYS_FILE
    assert files.read_env(keys)["GROQ_API_KEY"] == "gsk-new"
    assert stat.S_IMODE(keys.stat().st_mode) == 0o600
    overlay = files.read_yaml(bare / "config" / ai.ADMIN_OVERLAY)
    assert overlay == {"keys_file": "local/llm-keys.env", "monthly_cap_usd": 12,
                       "provider_enabled": {"groq": False},
                       "purposes": {"story": {"calls_per_day": 4}}}  # fmt: skip
    assert "gsk-new" not in (bare / "config" / ai.ADMIN_OVERLAY).read_text()
    assert services.restarted == [["argus-web"]]
    async with migrated_engine.connect() as conn:
        snap = await conn.scalar(text("SELECT state FROM admin_state WHERE name = 'snapshot'"))
    groq = next(p for p in snap["llm"]["providers"] if p["name"] == "groq")
    assert groq["enabled"] is False
    assert groq["keys"] == [{"name": "GROQ_API_KEY", "set": True},
                            {"name": "GROQ_API_KEY_2", "set": False}]  # fmt: skip
    assert "llm.providers.groq.enabled" in snap["llm"]["in_app"]
    assert "gsk-new" not in json.dumps(snap)
    assert {a["name"] for a in snap["agents"]} >= {"investigator", "web", "proxy", "intel"}

    reset = await save(migrated_engine, who, [{"key": "llm.providers.groq.enabled",
                                               "reset": True}])  # fmt: skip
    assert await a.once()
    assert (await outcome(migrated_engine, reset))[0][0] == "applied"
    assert "provider_enabled" not in files.read_yaml(bare / "config" / ai.ADMIN_OVERLAY)


async def test_a_cap_the_whole_configuration_refuses_writes_nothing(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, bare: Path
) -> None:
    a = make(app_engine, bare, FakeServices())
    await a.start()
    who = await a_person(migrated_engine)
    batch = await save(
        migrated_engine,
        who,
        [{"key": "llm.providers.openai.monthly_cap_usd", "value": 100000, "risk": "sensitive"}],
    )
    assert await a.once()
    [(state, said)] = await outcome(migrated_engine, batch)
    assert state == "refused"
    assert "above the overall" in said
    assert not (bare / "config" / ai.ADMIN_OVERLAY).exists()
    for bad, why in (({"key": "llm.providers.nope.enabled", "value": True}, "not a setting"),
                     ({"key": "llm.providers.groq.enabled", "value": "yes"}, "on or off"),
                     ({"key": "llm.monthly_cap_usd", "value": 5}, "risk does not match"),
                     ({"key": "llm.purposes.story.providers", "value": ["groq", "groq"]},
                      "at most once")):  # fmt: skip
        batch = await save(migrated_engine, who, [bad])
        assert await a.once()
        [(state, said)] = await outcome(migrated_engine, batch)
        assert state == "refused", said
        assert why in said, said


async def test_a_key_goes_to_the_configured_keys_file(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    files.write_public(root / "config" / "llm.local.yaml", "keys_file: secrets/keys.env\n")
    a = make(app_engine, root, FakeServices())
    await a.start()
    who = await a_person(migrated_engine)
    batch = await save(
        migrated_engine,
        who,
        [{"key": "llm.keys.OPENAI_API_KEY", "risk": "sensitive", "sealed": b""}],
    )
    async with migrated_engine.begin() as conn:
        made = await conn.scalar(text("SELECT id FROM admin_changes WHERE batch = :b"),
                                 {"b": batch})  # fmt: skip
        await conn.execute(
            text("UPDATE admin_sealed SET sealed = :s WHERE change_id = :c"),
            {"s": seal.seal(seal.public_text(a.key), "sk-openai", applier.aad(made)), "c": made},
        )
    assert await a.once()
    assert (await outcome(migrated_engine, batch))[0][0] == "applied"
    assert files.read_env(root / "secrets" / "keys.env") == {"OPENAI_API_KEY": "sk-openai"}
    assert not (root / "config" / ai.ADMIN_OVERLAY).exists()


async def test_checks_an_asset_map_and_the_kill_switch(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path, tmp_path: Path
) -> None:
    out = tmp_path / "seen"
    out.mkdir()
    stand_in = tmp_path / "argus"
    stand_in.write_text(STAND_IN.format(out=out))
    stand_in.chmod(0o755)
    services = FakeServices()
    a = make(app_engine, root, services, argus=str(stand_in))
    await a.start()
    who = await a_person(migrated_engine)

    made = await start(migrated_engine, who, "check", {"target": "kibana:cases"}, False)
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert (state, result["ok"], result["target"]) == ("done", True, "kibana:cases")
    assert (out / "argv.txt").read_text().split() == ["kibana", "selftest", "--key", "cases"]
    assert "sk-should-be-masked" not in json.dumps(result)
    made = await start(migrated_engine, who, "check", {"target": "llm:groq"}, False)
    assert await a.job()
    assert (await job(migrated_engine, made)).result["ok"] is False  # the probe said no
    made = await start(migrated_engine, who, "check", {"target": "rm -rf"}, False)
    assert await a.job()
    assert (await job(migrated_engine, made)).state == "failed"

    made = await start(migrated_engine, who, "assets", {})
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
            {"j": made, "n": "assets.map", "s": seal.seal(seal.public_text(a.key),
             "networks: []\n", applier.job_aad(made, "assets.map"))},
        )  # fmt: skip
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert (state, result["ok"]) == ("done", True), result
    assert (out / "map.yaml").read_text() == "networks: []\n"
    assert (out / "mode.txt").read_text().strip() == "600"
    assert services.restarted == [["argus-collector", "argus-worker", "argus-web"]]
    unconfirmed = await start(migrated_engine, who, "assets", {}, stepped_up=False)
    assert await a.job()
    state, result = await job(migrated_engine, unconfirmed)
    assert state == "failed"
    assert "password" in result["error"]

    made = await start(migrated_engine, who, "llm_switch", {"stop": True}, False)
    assert await a.job()
    assert (await job(migrated_engine, made)).result == {"ok": True, "stopped": True,
                                                         "changed": True}  # fmt: skip
    async with migrated_engine.connect() as conn:
        gateway = await conn.scalar(text("SELECT state FROM llm_state WHERE name = 'gateway'"))
        audit = await conn.scalar(text("SELECT actor FROM audit_events WHERE action = 'llm.stop'"))
    assert gateway["stopped"] is True
    assert audit.startswith("user:mina")
    nobody = await a_person(migrated_engine, ("view",))
    made = await start(migrated_engine, nobody, "llm_switch", {"stop": False}, False)
    assert await a.job()
    assert (await job(migrated_engine, made)).state == "failed"


class FakeSource:
    def __init__(self, status: int, body: bytes) -> None:
        self.status, self.body, self.asked = status, body, []

    async def get(self, request: Any, timeout_s: float) -> Any:
        from argus.outside.providers import Reply

        self.asked.append(request.url)
        return Reply(self.status, self.body)


async def test_a_threat_intel_key_is_tested_within_its_limits_and_counted(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    from argus.admin import outside_check

    good = FakeSource(
        200,
        json.dumps(
            {
                "data": {
                    "id": "8.8.8.8",
                    "type": "ip_address",
                    "attributes": {"last_analysis_stats": {"malicious": 0, "harmless": 60}},
                }
            }
        ).encode(),
    )
    said = await outside_check.check(app_engine, root, "virustotal", NOW, good)
    assert said["ok"] is True, said
    assert good.asked == ["https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"]
    refused = await outside_check.check(app_engine, root, "virustotal", NOW, FakeSource(401, b""))
    assert refused["ok"] is False
    assert "refused the key" in refused["output"][0]
    with pytest.raises(ValueError, match="no key yet"):
        await outside_check.check(app_engine, root, "censys", NOW, good)
    for _ in range(3):  # the minute's limit (3) is spent by the tests: the next one waits
        await outside_check.check(app_engine, root, "virustotal", NOW, good)
    blocked = await outside_check.check(app_engine, root, "virustotal", NOW, good)
    assert blocked["ok"] is False
    assert "at its limit" in blocked["output"][0]
    used = await outside_check.usage(app_engine, root, NOW)
    vt = next(s for s in used["sources"] if s["source"] == "virustotal")
    assert (vt["key_set"], vt["today"], vt["today_by_purpose"]) == (True, 3, {"check": 3})
    assert {"window": "day", "maximum": 400} in vt["limits"]
    async with migrated_engine.connect() as conn:
        outcomes = [
            r[0]
            for r in await conn.execute(
                text("SELECT outcome FROM outside_requests WHERE purpose = 'check' ORDER BY id")
            )
        ]
    assert outcomes[:2] == ["ok", "error"]


async def test_argus_admin_publishes_the_sources_use(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    a = make(app_engine, root, FakeServices())
    await a.once()
    async with migrated_engine.connect() as conn:
        used = await conn.scalar(text("SELECT state FROM admin_state WHERE name = 'usage'"))
    assert [s["source"] for s in used["sources"]] == ["virustotal", "shodan", "censys"]


async def test_a_timer_is_switched_on_and_off_and_a_service_restarted(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, root: Path
) -> None:
    services = FakeServices()
    a = make(app_engine, root, services)
    await a.start()
    who = await a_person(migrated_engine)
    made = await start(migrated_engine, who, "service",
                       {"unit": "argus-notices.timer", "action": "on"})  # fmt: skip
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert (state, result["ok"]) == ("done", True), result
    run = files.read_yaml(root / "config" / "admin.yaml")["units"]["run"]
    assert "argus-notices.timer" in run
    assert "argus-web.service" in run
    assert services.switched == [("argus-notices.timer", True)]
    async with migrated_engine.connect() as conn:
        listed = await conn.scalar(text("SELECT state FROM admin_state WHERE name = 'services'"))
    notices = next(u for u in listed["units"] if u["unit"] == "argus-notices.timer")
    assert (notices["on"], notices["running"], notices["switchable"]) == (True, True, True)

    made = await start(migrated_engine, who, "service",
                       {"unit": "argus-notices.timer", "action": "off"})  # fmt: skip
    assert await a.job()
    assert (await job(migrated_engine, made)).state == "done"
    assert (
        "argus-notices.timer" not in files.read_yaml(root / "config" / "admin.yaml")["units"]["run"]
    )

    services.fail.add("argus-purge.timer")
    before = (root / "config" / "admin.yaml").read_text()
    made = await start(migrated_engine, who, "service",
                       {"unit": "argus-purge.timer", "action": "on"})  # fmt: skip
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert state == "failed"
    assert "systemd refused" in result["error"]
    assert (root / "config" / "admin.yaml").read_text() == before  # put back

    for params, stepped in (
        ({"unit": "argus-collector.service", "action": "off"}, True),
        ({"unit": "argus-admin.service", "action": "restart"}, False),
        ({"unit": "argus-notices.timer", "action": "on"}, False),
    ):
        made = await start(migrated_engine, who, "service", params, stepped)
        assert await a.job()
        assert (await job(migrated_engine, made)).state == "failed", params
    services.up.add("argus-worker.service")
    made = await start(
        migrated_engine,
        who,
        "service",
        {"unit": "argus-worker.service", "action": "restart"},
        False,
    )
    assert await a.job()
    done = await job(migrated_engine, made)
    assert done.result["ok"] is True, done
    assert services.restarted[-1] == ["argus-worker.service"]


PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
SETUP_STAND_IN = """#!/usr/bin/env bash
if [ "$1" = init ]; then
  cp "$3" "{out}/answers.yaml"
  pw=$(grep '^elastic.admin_password_file:' "$3" | cut -d' ' -f2)
  cp "$pw" "{out}/admin.txt"
  echo "init: done"
elif [ "$1" = assets ]; then
  cp "$3" "{out}/map.yaml"; echo "imported asset map: 3 entries"
fi
"""


async def test_the_setup_carries_every_key_and_the_asset_map(
    migrated_engine: AsyncEngine, app_engine: AsyncEngine, bare: Path, tmp_path: Path
) -> None:
    out = tmp_path / "seen"
    out.mkdir()
    stand_in = tmp_path / "argus"
    stand_in.write_text(SETUP_STAND_IN.format(out=out))
    stand_in.chmod(0o755)
    a = make(app_engine, bare, FakeServices(), argus=str(stand_in))
    await a.start()
    who = await a_person(migrated_engine)
    made = await start(migrated_engine, who, "setup", {"answers": {
        "siem.url": "https://es.example:9200/", "elastic.admin_user": "elastic",
        "case_team.provision": True,
        "siem.ca_pem": PEM}})  # fmt: skip
    secrets = {"elastic.admin_password": "admin-pw", "outside.virustotal_api_key": "vt-new",
               "llm.key.groq_api_key": "gsk-setup", "assets.map": "networks: []\n"}  # fmt: skip
    async with migrated_engine.begin() as conn:
        for name, value in secrets.items():
            await conn.execute(
                text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
                {"j": made, "n": name, "s": seal.seal(seal.public_text(a.key), value,
                                                      applier.job_aad(made, name))},
            )  # fmt: skip
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert (state, result["ok"]) == ("done", True), result
    assert (out / "admin.txt").read_text() == "admin-pw\n"
    seen = (out / "answers.yaml").read_text()
    assert "elastic.admin_user: elastic" in seen
    assert "siem.url: https://es.example:9200\n" in seen  # the trailing slash tidied
    assert "siem.trust: file" in seen
    assert "siem.ca_file: " in seen
    assert "ca_pem" not in seen
    assert "admin-pw" not in seen
    assert "vt-new" not in seen
    assert (out / "map.yaml").read_text() == "networks: []\n"
    assert files.read_env(bare / ".env")["ARGUS_OUTSIDE__VIRUSTOTAL_API_KEY"] == "vt-new"
    assert files.read_env(bare / ai.APP_KEYS_FILE)["GROQ_API_KEY"] == "gsk-setup"
    assert any("asset map: imported" in line for line in result["after"]), result
    assert "admin-pw" not in json.dumps(result)
    async with migrated_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM admin_job_secrets")) == 0
