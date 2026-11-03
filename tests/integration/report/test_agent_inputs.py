"""Q-F2's gate: agent@1's inputs stay byte-identical. Every model request agent@1 sends for the
synthetic day (``scenario``) is replayed from a strict cassette recorded on the commit before
Q-F2 (``RECORD_CASSETTES=agent1`` records it again: only on that base). A request that
differs by one byte has no recorded answer and the run fails; so do a changed dossier hash, a
changed view hash (what the privacy layer renders) or a changed verdict. The exact request
bodies are kept beside the cassette (``agent1_requests.json``), in the order sent, so a
difference shows as a diff."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import pytest
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.agent import service
from argus.agent.agent import Agent
from argus.assess.runner import view_hash
from argus.context.worker import Worker
from argus.llm.wire import CassetteMiss, LlmCassette, LlmReply, LlmWire
from tests.integration.report import scenario
from tests.unit.agent.parity import frozen

pytestmark = pytest.mark.integration

HERE = Path(__file__).resolve().parent / "cassettes"
CASSETTE = HERE / "agent1_inputs.json"
EXPECTED = HERE / "agent1_expected.json"
REQUESTS = HERE / "agent1_requests.json"
RECORD = os.environ.get("RECORD_CASSETTES") == "agent1"


class Tap:
    """Every request body, in the order sent, on its way to the cassette."""

    def __init__(self, inner: LlmCassette) -> None:
        self.inner = inner
        self.sent: list[Any] = []

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        digest = hashlib.sha256(wire.body).hexdigest()  # of the exact bytes
        self.sent.append({"sha256": digest, "body": json.loads(wire.body)})
        return await self.inner.send(wire, key)


async def run_day(engine: AsyncEngine, saver: AsyncPostgresSaver, cassette: Tap) -> Any:
    """The day through the worker, then agent@1 on every dossier; what it saw and said."""
    await scenario.prepare(engine)
    privacy = scenario.privacy()
    packs = scenario.packs(privacy)
    siem = scenario.FakeSiem()
    worker = Worker(engine, saver, packs=packs, gateway=siem, clock=lambda: scenario.LATER)
    while await worker.run_once(limit=10):
        pass
    rows = await scenario.dossiers(engine)
    fetch, snapshots = service.evidence(engine, siem, packs, lambda: scenario.LATER)
    llm = scenario.llm(cassette)
    # the cassette holds the prompts of Q-H1's files (coordinator@3, specialist@1), kept in the
    # parity recording's folder; AR3's coordinator@4 (D-165) adds two tools and so other bytes
    agent = Agent(privacy, llm.complete, packs, fetch, snapshots, privacy.classifier,
                  clock=lambda: scenario.LATER, monotonic=lambda: 0.0,
                  agents=frozen())  # fmt: skip
    verdicts = {}
    for row in rows:
        async with engine.connect() as conn:
            verdict = await agent.assess(conn, row.investigation_id, row.body)
        verdicts[scenario.rule_of(row)] = {
            "outcome": verdict.outcome,
            "decided_by": verdict.decided_by,
            "confidence": verdict.confidence,
            "reasons": verdict.reasons,
        }
    return {
        "dossiers": {scenario.rule_of(r): r.dossier_hash for r in rows},
        "views": {scenario.rule_of(r): view_hash(privacy, r.body) for r in rows},
        "verdicts": verdicts,
        "siem": sorted(f"{name} {params}" for name, params in siem.calls),
        "model_calls": len(llm.store.ledger),  # type: ignore[attr-defined]
    }


@pytest.mark.skipif(RECORD, reason="recording")
async def test_agent1_sends_byte_identical_requests(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver
) -> None:
    cassette = LlmCassette(CASSETTE)  # replay: strict, nothing is sent anywhere
    tap = Tap(cassette)
    got = await run_day(app_engine, saver, tap)
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    assert tap.sent == json.loads(REQUESTS.read_text(encoding="utf-8"))  # byte for byte, in order
    assert got["dossiers"] == expected["dossiers"]  # what the worker stores is unchanged
    assert got["views"] == expected["views"]  # what the privacy layer renders is unchanged
    assert got["siem"] == expected["siem"]  # the same evidence requests
    assert got["model_calls"] == expected["model_calls"] == len(cassette.entries)
    assert got["verdicts"] == expected["verdicts"]
    assert not cassette.changed


@pytest.mark.skipif(not RECORD, reason="records only with RECORD_CASSETTES=agent1")
async def test_record_agent1_requests(app_engine: AsyncEngine, saver: AsyncPostgresSaver) -> None:
    for path in (CASSETTE, EXPECTED, REQUESTS):
        path.unlink(missing_ok=True)
    cassette = LlmCassette(CASSETTE, "record", scenario.ScriptedModel())
    tap = Tap(cassette)
    got = await run_day(app_engine, saver, tap)
    cassette.save()
    EXPECTED.write_text(json.dumps(got, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    REQUESTS.write_text(json.dumps(tap.sent, indent=1, ensure_ascii=False) + "\n",
                        encoding="utf-8")  # fmt: skip
    assert got["model_calls"] == len(cassette.entries) > 0


@pytest.mark.skipif(RECORD, reason="recording")
async def test_the_replay_is_strict(
    app_engine: AsyncEngine, saver: AsyncPostgresSaver, tmp_path: Path
) -> None:
    """The control: without one recorded answer the day cannot be replayed (a request that
    changed would miss the same way)."""
    data = json.loads(CASSETTE.read_text(encoding="utf-8"))
    data["entries"].pop(sorted(data["entries"])[0])
    path = tmp_path / "short.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(CassetteMiss):
        await run_day(app_engine, saver, Tap(LlmCassette(path)))
