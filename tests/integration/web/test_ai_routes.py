"""``/api/v1/admin/ai`` and the new jobs (D-328) on the web's own login: an administrator sees the
providers (keys only as set or not), the AI tasks, the agents and the case team's keys; the AI's
settings are saved like any other (a key sealed at once, after a step-up); a connection check,
the kill switch and an asset map import (sealed, after a step-up) start as jobs; the session says
when the setup is pending. Nobody else sees or starts anything."""

from __future__ import annotations

import json
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import seal
from tests.integration.web.conftest import NOW
from tests.integration.web.test_admin_routes import V1, admin, publish_seal, save, step_up
from tests.integration.web.test_routes_declared import client, signed

pytestmark = pytest.mark.integration

LLM = {
    "problem": None, "keys_file": None, "monthly_cap_usd": 40.0, "daily_cap_usd": None,
    "providers": [
        {"name": "groq", "enabled": True, "api": "openai", "base_url": "https://g.example/v1",
         "trust": "cloud", "paid": False, "models": {"small": "m-20b"}, "tasks": None,
         "keys": [{"name": "GROQ_API_KEY", "set": True}], "monthly_cap_usd": None,
         "daily_cap_usd": None},
        {"name": "openai", "enabled": False, "api": "openai", "base_url": "https://o.example/v1",
         "trust": "cloud", "paid": True, "models": {"medium": "m-mini"}, "tasks": None,
         "keys": [{"name": "OPENAI_API_KEY", "set": False}], "monthly_cap_usd": 20.0,
         "daily_cap_usd": 1.0},
    ],
    "purposes": {"story": {"calls_per_day": 15, "providers": ["openai"], "tier": "medium"}},
    "in_app": ["llm.providers.openai.enabled"],
}  # fmt: skip
AGENTS = [{"name": "investigator", "kind": "coordinator", "version": "coordinator@4",
           "mission": "Assess an investigation.", "task": "assess.coordinator", "tier": "medium",
           "tools": ["ti.lookup"], "specialists": ["web"], "triggers": ["person_request"],
           "on": True, "enabled_version": "coordinator@4", "problem": None}]  # fmt: skip


async def snapshot(seeded: AsyncEngine, settings: dict[str, Any] | None = None) -> None:
    state = {"settings": settings or {"siem.url": {"value": "https://es.example:9200"},
                                      "siem.api_key": {"set": True},
                                      "case_team.lead_api_key": {"set": True},
                                      "risk.reading": {"value": True}},
             "problem": None, "llm": LLM, "agents": AGENTS}  # fmt: skip
    async with seeded.begin() as conn:
        await conn.execute(
            text("INSERT INTO admin_state (name, state, updated_at) VALUES ('snapshot',"
                 " CAST(:s AS jsonb), :t) ON CONFLICT (name) DO UPDATE SET state = EXCLUDED.state"),
            {"s": json.dumps(state), "t": NOW},
        )  # fmt: skip


async def test_an_administrator_sees_the_providers_tasks_and_agents(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await snapshot(seeded)
    async with client(web_engine) as http:
        await signed(http, "asha")
        assert (await http.get(f"{V1}/ai")).status_code == 403
        await admin(seeded)
        got = await http.get(f"{V1}/ai")
    assert got.status_code == 200, got.text
    body = got.json()
    assert [p["name"] for p in body["providers"]] == ["groq", "openai"]
    assert body["providers"][0]["keys"] == [
        {"name": "GROQ_API_KEY", "setting": "llm.keys.GROQ_API_KEY", "is_set": True}
    ]
    assert body["any_key"] is True
    assert body["stopped"] is False
    assert body["purposes"][0]["task"] == "story"
    assert body["purposes"][0]["calls_today"] == 0
    assert body["agents"][0]["name"] == "investigator"
    assert body["agents"][0]["on"] is True
    assert body["readings_on"] is True
    assert body["team"][0] == {"user": "argus-lead", "setting": "case_team.lead_api_key",
                               "is_set": True}  # fmt: skip
    settings = {s["key"]: s for s in body["settings"]}
    assert settings["llm.providers.openai.enabled"]["value"] is False
    assert settings["llm.providers.openai.enabled"]["in_app"] is True
    assert settings["llm.keys.OPENAI_API_KEY"]["is_set"] is False
    assert settings["llm.keys.OPENAI_API_KEY"]["risk"] == "sensitive"
    assert settings["llm.purposes.story.providers"]["choices"] == ["groq", "openai"]


async def test_the_ais_settings_are_saved_like_any_and_a_key_sealed(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await snapshot(seeded)
    await admin(seeded)
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        on = await save(http, csrf, [{"key": "llm.providers.openai.enabled", "value": True}])
        assert on.status_code == 202, on.text
        for bad in (
            {"key": "llm.providers.nope.enabled", "value": True},
            {"key": "llm.providers.groq.enabled", "value": "yes"},
            {"key": "llm.purposes.story.providers", "value": ["mistral"]},
        ):
            got = await save(http, csrf, [bad])
            assert got.status_code == 422, (bad, got.text)
        key = {"key": "llm.keys.OPENAI_API_KEY", "value": "sk-openai-1"}
        assert (await save(http, csrf, [key])).json()["code"] == "step_up_required"
        await step_up(seeded)
        private = await publish_seal(seeded)
        made = await save(http, csrf, [key])
        assert made.status_code == 202, made.text
    async with seeded.connect() as conn:
        row = (await conn.execute(text(
            "SELECT c.id, c.value, s.sealed FROM admin_changes c JOIN admin_sealed s"
            " ON s.change_id = c.id WHERE c.key = 'llm.keys.OPENAI_API_KEY'"))).one()  # fmt: skip
    assert row.value is None
    assert seal.open_sealed(private, row.sealed, f"admin_change:{row.id}".encode()) == "sk-openai-1"


async def test_checks_the_kill_switch_and_an_asset_map_start_as_jobs(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        assert (await http.post(f"{V1}/jobs/check", headers=head,
                                json={"target": "siem"})).status_code == 403  # fmt: skip
        await admin(seeded)
        for target, status in (("siem", 202), ("kibana:cases", 202), ("llm:groq", 202),
                               ("kibana:root", 422), ("llm:../x", 422)):  # fmt: skip
            got = await http.post(f"{V1}/jobs/check", headers=head, json={"target": target})
            assert got.status_code == status, (target, got.text)
        stop = await http.post(f"{V1}/jobs/llm-switch", headers=head, json={"stop": True})
        assert (stop.status_code, stop.json()["kind"]) == (202, "llm_switch")
        upload = {"content": "networks:\n  - cidr: 10.0.0.0/8\n"}
        early = await http.post(f"{V1}/jobs/assets", headers=head, json=upload)
        assert early.json()["code"] == "step_up_required"
        await step_up(seeded)
        assert (await http.post(f"{V1}/jobs/assets", headers=head,
                                json=upload)).status_code == 503  # fmt: skip
        private = await publish_seal(seeded)
        made = await http.post(f"{V1}/jobs/assets", headers=head, json=upload)
        assert made.status_code == 202, made.text
    async with seeded.connect() as conn:
        sealed = await conn.scalar(text("SELECT sealed FROM admin_job_secrets"))
        params = await conn.scalar(text("SELECT params FROM admin_jobs WHERE kind = 'assets'"
                                        " ORDER BY id DESC LIMIT 1"))  # fmt: skip
    job_id = made.json()["id"]
    assert seal.open_sealed(private, sealed, f"admin_job:{job_id}:assets.map".encode()) == (
        upload["content"])  # fmt: skip
    assert "10.0.0.0" not in json.dumps(params)


async def test_the_session_says_when_the_setup_is_pending(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    async with client(web_engine) as http:
        await signed(http, "asha")
        assert (await http.get("/api/v1/session")).json()["setup_pending"] is False  # no admin
        await snapshot(seeded, {"siem.url": {"value": None}, "siem.api_key": {"set": False}})
        assert (await http.get("/api/v1/session")).json()["setup_pending"] is True
        await snapshot(seeded)
        assert (await http.get("/api/v1/session")).json()["setup_pending"] is False


async def test_costs_and_usage(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    await snapshot(seeded)
    used = {"at": NOW.isoformat(), "sources": [
        {"source": "virustotal", "key_set": True, "enabled": True, "today": 4, "month": 90,
         "answered_month": 88, "today_by_purpose": {"agent": 4},
         "limits": [{"window": "day", "maximum": 400}], "days": [{"day": "2026-10-09",
                                                                   "requests": 4}]}]}  # fmt: skip
    async with seeded.begin() as conn:
        await conn.execute(text("INSERT INTO admin_state (name, state, updated_at) VALUES"
                                " ('usage', CAST(:s AS jsonb), :t)"),
                           {"s": json.dumps(used), "t": NOW})  # fmt: skip
        await conn.execute(text(
            "INSERT INTO llm_calls (at, call_id, attempt, provider, model, tier, purpose,"
            " priority, outcome, input_tokens, output_tokens, cost_usd, latency_ms,"
            " request_bytes, request_sha256) VALUES (:at, gen_random_uuid(), 1, 'openai', 'm',"
            " 'medium', 'story', 'normal', 'ok', 1000, 200, 0.0123, 900, 10, repeat('a', 64))"),
            {"at": NOW})  # fmt: skip
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        assert (await http.get(f"{V1}/usage")).status_code == 403
        await admin(seeded)
        got = await http.get(f"{V1}/usage")
        for target in ("outside:virustotal", "outside:shodan"):
            assert (await http.post(f"{V1}/jobs/check", headers=head,
                                    json={"target": target})).status_code == 202  # fmt: skip
        assert (await http.post(f"{V1}/jobs/check", headers=head,
                                json={"target": "outside:other"})).status_code == 422  # fmt: skip
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["monthly_cap_usd"] == 40.0
    assert body["ai_days"][0]["provider"] == "openai"
    assert body["ai_days"][0]["tokens"] == 1200
    assert body["ai_tasks"] == [{"task": "story", "calls": 1, "cost_usd": 0.0123}]
    assert body["sources"][0]["today"] == 4
    assert body["sources"][0]["limits"][0]["maximum"] == 400


async def test_services_are_listed_and_switched_with_the_right_care(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    listed = {"units": [{"unit": "argus-notices.timer", "label": "Notices", "core": False,
                         "switchable": True, "on": False, "running": False,
                         "writes_siem": False, "deletes": False}]}  # fmt: skip
    async with seeded.begin() as conn:
        await conn.execute(text("INSERT INTO admin_state (name, state, updated_at) VALUES"
                                " ('services', CAST(:s AS jsonb), :t)"),
                           {"s": json.dumps(listed), "t": NOW})  # fmt: skip
    await admin(seeded)
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        got = await http.get(f"{V1}/services")
        assert got.json()["units"][0]["unit"] == "argus-notices.timer"

        async def switch(unit: str, action: str, confirm: str | None = None) -> Any:
            body = {"unit": unit, "action": action, "confirm": confirm}
            return await http.post(f"{V1}/jobs/service", headers=head, json=body)

        assert (await switch("argus-worker.service", "restart")).status_code == 202
        assert (await switch("argus-notices.timer", "on")).json()["code"] == "step_up_required"
        assert (await switch("argus-collector.service", "off")).status_code == 422
        assert (await switch("argus-admin.service", "restart")).status_code == 422
        await step_up(seeded)
        assert (await switch("argus-notices.timer", "on")).status_code == 202
        assert (await switch("argus-writer.service", "on")).status_code == 422  # no words
        from argus.web.v1.admin_routes import CONFIRM_WORDS

        assert (await switch("argus-writer.service", "on", CONFIRM_WORDS)).status_code == 202


async def test_the_setup_takes_the_admin_login_every_key_and_the_asset_map(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    private = await publish_seal(seeded)
    body = {"answers": {"siem.url": "https://es.example:9200", "elastic.admin_user": "elastic",
                        "case_team.provision": True},
            "keys": {"elastic.admin_password": "pw-1", "llm.key.groq_api_key": "gsk-1",
                     "outside.shodan_api_key": "sh-1"},
            "asset_map": "networks: []\n"}  # fmt: skip
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        await step_up(seeded)
        made = await http.post(f"{V1}/jobs/setup", headers=head, json=body)
        assert made.status_code == 202, made.text
        odd = {**body, "keys": {"llm.key.../x": "v"}}
        assert (await http.post(f"{V1}/jobs/setup", headers=head, json=odd)).status_code == 422
    job_id = made.json()["id"]
    async with seeded.connect() as conn:
        rows = {
            r.name: r.sealed
            for r in await conn.execute(
                text("SELECT name, sealed FROM admin_job_secrets WHERE job_id = :j"), {"j": job_id}
            )
        }
    assert set(rows) == {"elastic.admin_password", "llm.key.groq_api_key",
                         "outside.shodan_api_key", "assets.map"}  # fmt: skip
    opened = seal.open_sealed(private, rows["assets.map"],
                              f"admin_job:{job_id}:assets.map".encode())  # fmt: skip
    assert opened == "networks: []\n"
