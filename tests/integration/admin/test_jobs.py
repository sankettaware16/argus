"""argus-admin's jobs (D-327): ``inspect_tls`` reads what an address presents and says why when it
cannot; ``setup`` runs ``argus init`` (here a stand-in that keeps what it was given) with the
answers and each key in a private file, deletes the sealed keys after, and runs only for an
administrator who confirmed their password."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.admin import applier, seal
from tests.integration.admin.test_applier import NOW, FakeServices, a_person

pytestmark = pytest.mark.integration

STAND_IN = """#!/usr/bin/env bash
answers="$3"
cp "$answers" "{out}/answers.yaml"
key=$(grep '^siem.api_key_file:' "$answers" | cut -d' ' -f2)
cp "$key" "{out}/key.txt"
stat -c %a "$key" > "{out}/mode.txt"
echo "init: done; ARGUS is set up (api_key: sk-should-be-masked)"
"""


async def start(owner: AsyncEngine, who: int, kind: str, params: dict[str, Any],
                stepped_up: bool = True) -> int:  # fmt: skip
    async with owner.begin() as conn:
        return int(await conn.scalar(
            text("INSERT INTO admin_jobs (kind, params, created_by, created_at, stepped_up_at)"
                 " VALUES (:k, CAST(:p AS jsonb), :u, :at, :up) RETURNING id"),
            {"k": kind, "p": json.dumps(params), "u": who, "at": NOW,
             "up": NOW - timedelta(minutes=1) if stepped_up else None},
        ))  # fmt: skip


async def job(owner: AsyncEngine, job_id: int) -> Any:
    async with owner.connect() as conn:
        return (await conn.execute(text("SELECT state, result FROM admin_jobs WHERE id = :j"),
                                   {"j": job_id})).one()  # fmt: skip


async def test_an_address_that_answers_nothing_is_a_failed_job_that_says_why(
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    root: Path,
) -> None:
    a = applier.Applier(app_engine, root, FakeServices(), clock=lambda: NOW, settle=0)
    who = await a_person(migrated_engine)
    made = await start(migrated_engine, who, "inspect_tls", {"url": "https://127.0.0.1:9"})
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert state == "failed"
    assert "could not be reached" in result["error"]
    bad = await start(migrated_engine, who, "inspect_tls", {"url": "http://plain:80"})
    await a.job()
    assert (await job(migrated_engine, bad)).result["error"].startswith("an https:// address")
    assert not await a.job()


async def test_the_setup_runs_init_with_its_answers_and_each_key_in_a_private_file(
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    root: Path,
    tmp_path: Path,
) -> None:
    out = tmp_path / "seen"
    out.mkdir()
    stand_in = tmp_path / "argus"
    stand_in.write_text(STAND_IN.format(out=out))
    stand_in.chmod(0o755)
    services = FakeServices()
    a = applier.Applier(app_engine, root, services, clock=lambda: NOW, settle=0,
                        argus=str(stand_in))  # fmt: skip
    await a.start()
    who = await a_person(migrated_engine)
    made = await start(migrated_engine, who, "setup", {"answers": {
        "siem.url": "https://es.example:9200", "siem.trust": "chain",
        "siem.fingerprint": "AB:CD", "organisation.name": "Example University"}})  # fmt: skip
    async with migrated_engine.begin() as conn:
        await conn.execute(
            text("INSERT INTO admin_job_secrets (job_id, name, sealed) VALUES (:j, :n, :s)"),
            {"j": made, "n": "siem.api_key", "s": seal.seal(
                seal.public_text(a.key), "sk-real-key", applier.job_aad(made, "siem.api_key"))},
        )  # fmt: skip
    assert await a.job()
    state, result = await job(migrated_engine, made)
    assert (state, result["ok"]) == ("done", True), result
    assert (out / "key.txt").read_text() == "sk-real-key\n"
    assert (out / "mode.txt").read_text().strip() == "600"
    seen = (out / "answers.yaml").read_text()
    assert "siem.url: https://es.example:9200" in seen
    assert "units.start: true" in seen
    assert "sk-real-key" not in seen
    assert "sk-should-be-masked" not in json.dumps(result)
    assert services.restarted == [["argus-collector", "argus-worker", "argus-web"]]
    async with migrated_engine.connect() as conn:
        assert await conn.scalar(text("SELECT count(*) FROM admin_job_secrets")) == 0


async def test_the_setup_needs_an_administrator_who_confirmed_and_known_answers_only(
    migrated_engine: AsyncEngine,
    app_engine: AsyncEngine,
    root: Path,
    tmp_path: Path,
) -> None:
    a = applier.Applier(app_engine, root, FakeServices(), clock=lambda: NOW, settle=0,
                        argus=str(tmp_path / "never-run"))  # fmt: skip
    admin = await a_person(migrated_engine)
    viewer = await a_person(migrated_engine, ("view",))
    for who, params, stepped, why in (
        (viewer, {"answers": {}}, True, "may not change settings"),
        (admin, {"answers": {}}, False, "password confirmed first"),
        (admin, {"answers": {"database.password": "x"}}, True, "not a setup answer"),
    ):  # fmt: skip
        made = await start(migrated_engine, admin if who == admin else who, "setup", params,
                           stepped_up=stepped)  # fmt: skip
        await a.job()
        state, result = await job(migrated_engine, made)
        assert (state, why in result["error"]) == ("failed", True), result
