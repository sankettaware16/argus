"""``/api/v1/admin`` (P4-H, D-327) on the web's own login: an administrator reads every setting
and saves changes; a value is checked before it is stored, a sensitive one needs the password
confirmed, a SIEM write also the words; a key is sealed at once and the web can never read it
back; nobody else may read or change anything here."""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import seal
from argus.web.v1.admin_routes import CONFIRM_WORDS
from tests.integration.web.conftest import NOW
from tests.integration.web.test_routes_declared import client, signed

pytestmark = pytest.mark.integration
V1 = "/api/v1/admin"


async def admin(seeded: AsyncEngine, who: str = "asha") -> None:
    async with seeded.begin() as conn:
        await conn.execute(text("UPDATE users SET capabilities = array_append(capabilities,"
                                " 'admin') WHERE username = :u"), {"u": who})  # fmt: skip


async def step_up(seeded: AsyncEngine, who: str = "asha") -> None:
    async with seeded.begin() as conn:
        await conn.execute(
            text("UPDATE user_sessions SET stepped_up_at = :t WHERE user_id ="
                 " (SELECT id FROM users WHERE username = :u)"),
            {"t": NOW - timedelta(minutes=1), "u": who},
        )  # fmt: skip


async def publish_seal(seeded: AsyncEngine) -> Any:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    key = X25519PrivateKey.generate()
    async with seeded.begin() as conn:
        await conn.execute(
            text("INSERT INTO admin_state (name, state, updated_at) VALUES ('seal',"
                 " CAST(:s AS jsonb), :t)"),
            {"s": json.dumps({"public_key": seal.public_text(key)}), "t": NOW},
        )  # fmt: skip
    return key


async def save(http: httpx.AsyncClient, csrf: str, changes: list[dict[str, Any]],
               confirm: str | None = None) -> httpx.Response:  # fmt: skip
    body: dict[str, Any] = {"changes": changes}
    if confirm is not None:
        body["confirm"] = confirm
    return await http.post(f"{V1}/changes", json=body, headers={"X-CSRF-Token": csrf})


async def test_an_administrator_reads_every_section_and_no_key(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        await signed(http, "asha")
        got = await http.get(f"{V1}/settings")
    assert got.status_code == 200, got.text
    body = got.json()
    keys = {s["key"]: s for sec in body["sections"] for s in sec["settings"]}
    assert keys["history.window"]["kind"] == "duration"
    assert keys["siem.api_key"]["kind"] == "secret"
    assert keys["siem.api_key"]["value"] is None
    assert keys["case_team.post"]["risk"] == "siem_write"
    assert keys["siem.budget.burst_ms"]["editable"] is False  # D-022: the files' only
    assert body["applier"] == {"running": False, "last_seen": None}
    assert body["confirm_words"] == CONFIRM_WORDS


async def test_a_save_is_checked_stored_and_followed(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        bad = await save(http, csrf, [{"key": "history.window", "value": "5 days"}])
        assert (bad.status_code, bad.json()["code"]) == (422, "invalid")
        for change in ({"key": "siem.budget.burst_ms", "value": 5},
                       {"key": "no.such", "value": 1}):  # fmt: skip
            assert (await save(http, csrf, [change])).status_code == 422
        twice = [{"key": "history.window", "value": "7d"}] * 2
        assert (await save(http, csrf, twice)).status_code == 422
        made = await save(http, csrf, [{"key": "history.window", "value": "7d"}])
        assert made.status_code == 202, made.text
        batch = made.json()["batch"]
        assert [(c["key"], c["state"], c["by"]) for c in made.json()["changes"]] == [
            ("history.window", "pending", "asha")
        ]
        again = await http.get(f"{V1}/changes", params={"batch": batch})
        assert again.json()["changes"][0]["state"] == "pending"
    async with seeded.connect() as conn:
        row = (await conn.execute(text("SELECT value, risk FROM admin_changes"))).one()
        audited = await conn.scalar(text(
            "SELECT count(*) FROM audit_events WHERE action = 'settings.save'"))  # fmt: skip
    assert (row.value, row.risk, audited) == ("7d", "normal", 1)


async def test_a_sensitive_change_needs_the_password_and_a_siem_write_the_words(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        url = [{"key": "siem.url", "value": "https://es.example:9200"}]
        assert (await save(http, csrf, url)).json()["code"] == "step_up_required"
        await step_up(seeded)
        assert (await save(http, csrf, url)).status_code == 202
        post = [{"key": "case_team.post", "value": True}]
        refused = await save(http, csrf, post, confirm="yes")
        assert refused.status_code == 422
        assert CONFIRM_WORDS in refused.json()["detail"]
        assert (await save(http, csrf, post, confirm=CONFIRM_WORDS.upper())).status_code == 202


async def test_a_key_is_sealed_at_once_and_never_readable_by_the_web(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        await step_up(seeded)
        key = [{"key": "outside.virustotal_api_key", "value": "vt-secret-123"}]
        empty = await save(http, csrf, [{"key": "outside.virustotal_api_key", "value": None}])
        assert (empty.status_code, "never emptied" in empty.json()["detail"]) == (422, True)
        nobody = await save(http, csrf, key)
        assert (nobody.status_code, nobody.json()["code"]) == (503, "unavailable")
        private = await publish_seal(seeded)
        made = await save(http, csrf, key)
        assert made.status_code == 202, made.text
        assert "vt-secret-123" not in made.text
    async with seeded.connect() as conn:
        change = (await conn.execute(text("SELECT id, value FROM admin_changes"))).one()
        sealed = await conn.scalar(text("SELECT sealed FROM admin_sealed"))
        dump = await conn.scalar(text("SELECT string_agg(details::text, '') FROM audit_events"))
    assert change.value is None
    assert seal.open_sealed(private, sealed, f"admin_change:{change.id}".encode()) == (
        "vt-secret-123")  # fmt: skip
    assert "vt-secret-123" not in (dump or "")
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with web_engine.connect() as conn:
            await conn.execute(text("SELECT sealed FROM admin_sealed"))


async def test_nobody_but_an_administrator(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    async with client(web_engine) as http:
        csrf = await signed(http, "asha")
        assert (await http.get(f"{V1}/settings")).status_code == 403
        assert (
            await save(http, csrf, [{"key": "history.window", "value": "7d"}])
        ).status_code == 403
        await admin(seeded)
        no_csrf = await http.post(f"{V1}/changes", json={"changes": [
            {"key": "history.window", "value": "7d"}]})  # fmt: skip
        assert no_csrf.status_code == 403
    async with seeded.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM admin_changes")) == 0


async def test_jobs_start_for_an_administrator_and_the_setup_seals_its_keys(
    seeded: AsyncEngine, web_engine: AsyncEngine
) -> None:
    await admin(seeded)
    async with client(web_engine) as http:
        head = {"X-CSRF-Token": await signed(http, "asha")}
        look = await http.post(f"{V1}/jobs/inspect-tls", headers=head,
                               json={"url": "https://es.example:9200"})  # fmt: skip
        assert (look.status_code, look.json()["state"]) == (202, "pending"), look.text
        assert (await http.get(f"{V1}/jobs/{look.json()['id']}")).json()["kind"] == "inspect_tls"
        assert (await http.post(f"{V1}/jobs/inspect-tls", headers=head,
                                json={"url": "http://x"})).status_code == 422  # fmt: skip
        body = {"answers": {"siem.url": "https://es.example:9200"},
                "keys": {"siem.api_key": "sk-setup-1"}}  # fmt: skip
        early = await http.post(f"{V1}/jobs/setup", headers=head, json=body)
        assert early.json()["code"] == "step_up_required"
        await step_up(seeded)
        odd = {"answers": {"database.password": "x"}}
        assert (await http.post(f"{V1}/jobs/setup", headers=head, json=odd)).status_code == 422
        private = await publish_seal(seeded)
        made = await http.post(f"{V1}/jobs/setup", headers=head, json=body)
        assert made.status_code == 202, made.text
    async with seeded.connect() as conn:
        sealed = await conn.scalar(text("SELECT sealed FROM admin_job_secrets"))
        params = await conn.scalar(text("SELECT params FROM admin_jobs WHERE kind = 'setup'"))
    job_id = made.json()["id"]
    assert seal.open_sealed(private, sealed, f"admin_job:{job_id}:siem.api_key".encode()) == (
        "sk-setup-1")  # fmt: skip
    assert "sk-setup-1" not in json.dumps(params)
