"""P8 (D-091): assessments in the Inbox: the proposal and Accept on an investigation, the
proposals grouped by what decided them with an audit sample and a fenced group confirm, the
tuning reports, the metrics; hostile text stays text."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from datetime import date, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.assess import queue
from argus.web import assessed, queries
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, PASSWORD, SAME_ORIGIN
from tests.integration.web.test_gold import with_dossiers

pytestmark = pytest.mark.integration
H = "a" * 64
EVIL = "<script>window.__pwned=1</script>"


async def propose(engine: AsyncEngine, n: int, decided_by: str, outcome: str = "benign_expected",
                  start: int = 0) -> list[int]:  # fmt: skip
    async with engine.connect() as conn:
        found = (await queries.inbox(conn, "all"))[start : start + n]
    ids = []
    async with engine.begin() as conn:
        for k, inv in enumerate(found):
            assessor = decided_by.split("#")[0]
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, f"{k + start:064x}",
                                assessor, NOW)  # fmt: skip
            (job,) = await queue.claim(conn, "w", NOW, assessor)
            await queue.propose(conn, job, NOW, outcome, decided_by, [f"{EVIL} reason {k}"], 1.0)
            ids.append(job.assessment_id)
    return ids


async def signed_in(client: httpx.AsyncClient) -> None:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})


def flat(html: str) -> str:
    return " ".join(html.split())


def csrf(html: str) -> str:
    return html.split('name="csrf_token" value="')[1].split('"')[0]


def test_keys_and_sources() -> None:
    assert assessed.key_of("engine@1#abc: steps / r / 1:answered") == "steps / r / 1:answered"
    assert assessed.key_of("agent@1#openai/gpt-5.5") == "openai/gpt-5.5"
    assert assessed.key_of("engine@1") == "engine@1"
    assert assessed.key_of(None) == "-"
    assert assessed.source_of("agent@1") == "the AI investigator"
    assert assessed.source_of("engine@1") == "the decision engine"


async def test_the_investigators_proposals_are_grouped_by_rule_and_outcome(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    await with_dossiers(seeded, migrated_engine, 6)
    async with seeded.connect() as conn:
        found = (await queries.inbox(conn, "all"))[:6]
    async with migrated_engine.begin() as conn:  # two rules (by name, D-081)
        for k, inv in enumerate(found):
            await conn.execute(text("UPDATE investigations SET rule_name = :n WHERE id = :i"),
                               {"n": f"rule {k % 2}", "i": inv.id})  # fmt: skip
    rules = {"rule 0", "rule 1"}
    async with seeded.begin() as conn:
        for k, inv in enumerate(found):
            await queue.enqueue(conn, inv.id, inv.version, "generic@12", H, f"{k:064x}",
                                "agent@1", NOW)  # fmt: skip
            (job,) = await queue.claim(conn, "w", NOW, "agent@1")
            model = "agent@1#openai/a" if (k // 2) % 2 else "agent@1#openai/b"
            await queue.propose(conn, job, NOW, "true_positive", model, ["r"], 0.8)
    async with seeded.connect() as conn:
        groups = await assessed.proposals(conn, date(2026, 10, 9))
    assert {g.rule for g in groups} == rules
    assert sum(len(g.items) for g in groups) == 6
    for g in groups:
        assert {p.rule for p in g.items} == {g.rule}
        assert g.group == f"agent@1|{g.rule}|true_positive"
    mixed = [g for g in groups if len(g.models) == 2]
    assert mixed  # one rule's group holds both models' answers
    assert mixed[0].models == {"openai/a", "openai/b"}
    other = next(g for g in groups if g is not mixed[0])
    async with seeded.begin() as conn:
        users = (await conn.execute(text("SELECT id FROM users ORDER BY id"))).scalars().all()
        ids = [p.assessment_id for p in mixed[0].items] + [other.items[0].assessment_id]
        got = await assessed.confirm(conn, mixed[0].group, ids, users[0], "n")
    # a true positive starts an incident: never accepted with its group (P4-F U4), every one skipped
    assert got == (0, len(ids))


def test_group_of() -> None:
    assert assessed.group_of("engine@1", "engine@1#f: k", "r", "benign_expected") == "engine@1#f: k"
    assert assessed.group_of("engine@1", None, "r", "x") == "-"
    assert assessed.group_of("agent@1", "agent@1#m", "r", "true_positive") == (
        "agent@1|r|true_positive"
    )


@pytest.fixture
async def shipped_client(
    seeded: AsyncEngine, web_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[httpx.AsyncClient]:
    """The app with the shipped model gateway's caps: an installation's ``llm.local.yaml`` (a site's
    sets its own budget) is its own, so the shipped ``llm.yaml`` is read alone."""
    import argus.llm.providers as providers

    shipped = tmp_path / "llm.yaml"
    shipped.write_text(providers.DEFAULT_PATH.read_text(encoding="utf-8"), encoding="utf-8")
    load = providers.load_config
    monkeypatch.setattr(providers, "load_config", lambda *_, **__: load(shipped))
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url=BASE, headers=SAME_ORIGIN) as http:
        yield http


async def test_a_reviewed_investigation_can_still_be_asked_about(
    seeded: AsyncEngine, migrated_engine: AsyncEngine
) -> None:
    from argus.assess import runner
    from argus.llm.privacy import Privacy, load_policy
    from tests.integration.web.test_reviewed import decide
    from tests.unit.llm.conftest import ASSETS

    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        inv = (await queries.inbox(conn, "all"))[0]
    await decide(seeded, "asha", inv, action="reviewed", outcome="true_positive")
    privacy = Privacy.build(load_policy(), ASSETS)
    async with seeded.begin() as conn:
        assert await runner.schedule(conn, privacy, "agent@1", NOW) == 0  # never on its own
        assert await runner.request(conn, privacy, inv.id, "agent@1", NOW) == "queued"
        assert await runner.request(conn, privacy, inv.id, "agent@1", NOW) == "exists"
        assert await runner.request(conn, privacy, uuid.uuid4(), "agent@1", NOW) == "no dossier"


def test_plain_words_for_stored_sentences() -> None:
    from argus.web.app import plain

    assert plain("Not checked yet: needs the threat-intel pack (R11).") == (
        "Not checked yet: needs a threat-intelligence lookup."
    )
    assert plain("needs the proxy pack (R12) and the log pivots (R12, R13)") == (
        "needs proxy-log statistics and a search of the web and proxy logs"
    )
    assert plain("an unknown pack (R14) here") == "an unknown pack here"
    assert plain(5) == "5"


@pytest.mark.parametrize("mode", ["control", "agents 0444", "agents 0644", "config 0600"])
async def test_an_unsearchable_agents_directory_never_breaks_a_page(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mode: str,
    web_engine: AsyncEngine,
) -> None:
    """Q-H1: an agents directory that can be listed but not searched (``chmod 644`` on the
    directory), or a parent that cannot be searched: the investigation still answers 200 and
    /api/health says why the investigator is off (found in review: the page answered 500)."""
    import os

    from argus.agent import loader
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import copy
    from tests.unit.llm.conftest import ASSETS

    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    d = copy(tmp_path / "config" / "agents")
    target = d if mode.startswith("agents") else d.parent
    if mode != "control":
        target.chmod(int(mode.split()[1], 8))
    monkeypatch.setattr(loader, "DIRECTORY", d)
    try:
        await with_dossiers(seeded, migrated_engine, 1)
        async with seeded.connect() as conn:
            (a,) = (await queries.inbox(conn, "all"))[:1]
        app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                         privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
            await signed_in(http)
            assert (await http.get(f"/api/investigations/{a.id}")).status_code == 200
            api = (await http.get("/api/health")).json()["investigator"]
            if mode == "control":
                assert api == {
                    "ready": True,
                    "state": "ready",
                    "detail": "investigator"
                    " coordinator@4; web, proxy specialist@1; intel specialist@2",
                }
            else:
                reason = (
                    "intel.md: cannot be read (Permission denied)"
                    if mode.startswith("agents")
                    else "the agents directory cannot be read (Permission denied)"
                )
                assert api == {"ready": False, "state": "refused", "detail": reason}
    finally:
        target.chmod(0o755)


async def test_the_health_reads_name_a_refused_file(
    seeded: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    web_engine: AsyncEngine,
) -> None:
    """/api/health is where a person sees that the AI investigator is off, and why: the reason
    is the loader's."""
    from argus.agent import loader
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import FILES, copy, header

    d = copy(tmp_path / "agents")
    (d / "web.md").write_text(header(FILES["web"], "tier", "large"))
    (d / "<script>x.md").write_text("x\n")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        api = (await http.get("/api/health")).json()["investigator"]
        assert (api["ready"], api["state"]) == (False, "refused")
        assert "<script>x.md: code binds no agent" in api["detail"]
        (d / "<script>x.md").unlink()
        api = (await http.get("/api/health")).json()["investigator"]
        assert "web.md: tier large is above what code allows web (small)" in api["detail"]


async def test_a_stray_file_whose_name_is_not_utf8_never_breaks_the_health_read(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    web_engine: AsyncEngine,
) -> None:
    """R1 (second review): a stray file named with a byte that is not UTF-8 (an archive
    unpacked with Latin-1 names) turns the agent off as any stray file does; the health page
    and /api/health still answer 200 and name it in printable ASCII (they answered 500)."""
    import os

    from argus.agent import loader
    from argus.llm.privacy import Privacy, load_policy
    from argus.web.app import create_app
    from tests.unit.agent.test_loader import copy
    from tests.unit.llm.conftest import ASSETS

    d = copy(tmp_path / "agents")

    def stray(raw: bytes) -> None:
        with open(os.path.join(os.fsencode(d), raw), "wb") as f:
            f.write(b"x\n")

    stray(b"investigator\xe9.md")
    monkeypatch.setattr(loader, "DIRECTORY", d)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1),
                     privacy=Privacy.build(load_policy(), ASSETS))  # fmt: skip
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        assert (await http.get(f"/api/investigations/{a.id}")).status_code == 200
        api = await http.get("/api/health")
        assert api.status_code == 200
        reason = "investigator\\xe9.md: code binds no agent 'investigator\\xe9'"
        assert api.json()["investigator"] == {"ready": False, "state": "refused",
                                              "detail": reason}  # fmt: skip
        stray(b"a\rb.md")  # sorted first, so its reason is given
        api = await http.get("/api/health")
        assert api.json()["investigator"]["detail"] == "a\\x0db.md: code binds no agent 'a\\x0db'"


async def test_the_health_read_tells_switched_off_from_refused(
    seeded: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    web_engine: AsyncEngine,
) -> None:
    """R2 (second review): an investigator switched off in ARGUS's code is not a file to fix:
    /api/health says it is switched off, not that its files are refused."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED
    from argus.web.app import create_app

    real = loader.load
    monkeypatch.setattr(loader, "load", lambda directory=None, **kw: real(
        directory, enabled={**ENABLED, "investigator": None}))  # fmt: skip
    app = create_app(web_engine, clock=lambda: NOW + timedelta(hours=1))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://127.0.0.1:8765",
                                 headers={"Origin": "http://127.0.0.1:8765"}) as http:  # fmt: skip
        await signed_in(http)
        api = (await http.get("/api/health")).json()["investigator"]
    detail = "investigator.md: holds coordinator@4, but investigator is off" \
        " (argus.agent.registry.ENABLED)"  # fmt: skip
    assert api == {"ready": False, "state": "off", "detail": detail}


@pytest.mark.parametrize("why", ["refused file", "no person requests"])
async def test_the_api_v1_ask_needs_an_investigator_that_takes_a_persons_request(
    seeded: AsyncEngine,
    migrated_engine: AsyncEngine,
    web_engine: AsyncEngine,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    why: str,
) -> None:
    """Q-H1 x Q-A1 (found merging them): /api/v1's ask queues through ``runner.request``,
    which refuses agent@1 when its files are refused or its file drops ``person_request``.
    The answer is 503 "unavailable" (it was 202 "exists": already assessed, which nothing
    was), and nothing is queued or audited."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED, PINS, Pin
    from argus.llm.privacy import Privacy, load_policy
    from tests.integration.web.test_v1 import V1, app_client, signed
    from tests.unit.agent.test_loader import FILES, copy, header
    from tests.unit.llm.conftest import ASSETS

    d = copy(tmp_path / "agents")
    if why == "refused file":
        (d / "web.md").write_text(header(FILES["web"], "tools", "[web.followups, ti.lookup]"))
    else:
        edited = header(FILES["investigator"], "triggers", "[engine_no_decision]")
        (d / "investigator.md").write_text(header(edited, "version", "coordinator@4"))
        got = loader.read(d / "investigator.md")
        pin = Pin(got.file_sha256, got.prompt_sha256, "test")
        pins = {**PINS, "investigator": {"coordinator@4": pin}}
        enabled = {**ENABLED, "investigator": "coordinator@4"}
        real = loader.allows
        monkeypatch.setattr(loader, "allows", lambda trigger, directory=None, **kw: real(
            trigger, directory, pins=pins, enabled=enabled))  # fmt: skip
    monkeypatch.setattr(loader, "DIRECTORY", d)
    await with_dossiers(seeded, migrated_engine, 1)
    async with seeded.connect() as conn:
        (a,) = (await queries.inbox(conn, "all"))[:1]
    async with app_client(web_engine, privacy=Privacy.build(load_policy(), ASSETS)) as http:
        token = await signed(http)
        asked = await http.post(f"{V1}/investigations/{a.id}/assess", headers=token)
        assert (asked.status_code, asked.json()["code"]) == (503, "unavailable")
    async with seeded.connect() as conn:
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM assessments WHERE investigation_id = :i"), {"i": a.id}
            )
            == 0
        )
        assert (
            await conn.scalar(
                text("SELECT count(*) FROM audit_events WHERE action = 'assessment.request'")
            )
            == 0
        )
