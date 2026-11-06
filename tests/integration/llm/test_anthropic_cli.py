"""Anthropic through ``argus llm`` and the Postgres ledger (P4-E1), against a throwaway database
and a fake transport: nothing reaches a model; every key is made up."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.llm import budget
from argus.llm.gateway import Call, LlmGateway
from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig
from argus.llm.store import PgLlmStore
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture
from tests.unit.llm.test_anthropic import (
    FREE,
    KEYS,
    THINKING,
    anthropic,
    config,
    failure,
    message,
)
from tests.unit.llm.test_anthropic import text as block
from tests.unit.llm.test_gateway import Clock, Fake
from tests.unit.llm.test_privacy import dossier

pytestmark = pytest.mark.integration

KEY = "made-up-anthropic-key-0007"


@pytest.fixture
def llm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, privacy: Privacy) -> Fake:
    keys = tmp_path / "keys.env"
    keys.write_text(f"ANTHROPIC_API_KEY={KEY}\n", encoding="utf-8")
    cfg = LlmConfig.model_validate({"keys_file": str(keys), "monthly_cap_usd": 5.0,
                                    "providers": [anthropic(), FREE]})  # fmt: skip

    class Transport(Fake):
        async def aclose(self) -> None:
            pass

    answer = message(THINKING, block('{"ok": true}'), usage={"input_tokens": 30,
                                                             "output_tokens": 6})  # fmt: skip
    shared: Any = Transport({"anthropic": [answer]})
    monkeypatch.setattr("argus.llm.cli.load_config", lambda: cfg)
    monkeypatch.setattr("argus.llm.cli.HttpxLlmTransport", lambda config: shared)
    monkeypatch.setattr("argus.llm.cli._privacy", lambda settings: privacy)
    return shared  # type: ignore[no-any-return]


def test_a_ping_and_the_status_through_anthropic(cli_env: Path, llm: Fake) -> None:  # noqa: F811
    config_args = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config_args)[0] == 0
    code, out = _invoke("llm", "ping", "--provider", "anthropic", *config_args)
    assert code == 0, out
    assert out == "anthropic claude-haiku-5-5: '{\"ok\": true}' (30+6 tokens, $0.000006, 80 ms)\n"
    (wire, key), = llm.sent  # fmt: skip
    assert (wire.url, key) == ("https://api.anthropic.com/v1/messages", KEY)
    body = json.loads(wire.body)
    assert body["max_tokens"] == 200 + 2048
    assert body["system"].startswith("This is a connection test")
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": {
        "type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"],
        "additionalProperties": False}}, "effort": "low"}  # fmt: skip
    code, out = _invoke("llm", "status", *config_args)
    assert code == 0
    lines = out.splitlines()
    assert ("- anthropic (cloud, every task): key present; small=claude-haiku-5-5,"
            " medium=claude-sonnet-5-5") in lines  # fmt: skip
    assert "this month: $0.000006 of $5.00" in lines
    assert f"  {'anthropic':12} {1:6} {1:6} {36:10} $0.000006" in lines
    assert KEY not in out


async def test_the_ledger_and_the_state_keep_anthropic_s_outcomes(
    app_engine: AsyncEngine, privacy: Privacy
) -> None:
    refused = message(block("{"), stop="refusal", details={
        "type": "refusal", "category": "cyber", "explanation": "Made-up explanation."})  # fmt: skip
    call = Call(privacy.request([dossier()]), "Assess the item. Answer in JSON.", "assess")
    store = PgLlmStore(app_engine)
    for reply in (refused, failure(402, "billing_error", "billing"),
                  failure(404, "not_found_error", "model: claude-haiku-5-5")):  # fmt: skip
        done = await LlmGateway(config(), KEYS, Fake({"anthropic": [reply]}), store,
                                Clock()).complete(call)  # fmt: skip
        assert done.provider == "free"
        await store.change(lambda s: (None, budget.State()))  # each run from a clean state
    async with app_engine.connect() as conn:
        rows = (await conn.execute(text(
            "SELECT provider, model, attempt, outcome, http_status FROM llm_calls ORDER BY id"
        ))).all()  # fmt: skip
        everything = str(
            (await conn.execute(text("SELECT row_to_json(c)::text FROM llm_calls c"))).all()
        )
    answered = ("free", "f-small", 2, "ok", 200)
    assert [tuple(r) for r in rows] == [
        ("anthropic", "claude-haiku-5-5", 1, "refused: cyber", 200), answered,
        ("anthropic", "claude-haiku-5-5", 1, "no_credit", 402), answered,
        ("anthropic", "claude-haiku-5-5", 1, "model_mismatch", 404), answered,
    ]  # fmt: skip
    for value in ("Made-up", "made-up-anthropic", "Assess the item"):
        assert value not in everything
    gw = LlmGateway(config(), KEYS, Fake({"anthropic": [failure(404, "not_found_error", "x")]}),
                    store, Clock())  # fmt: skip
    await gw.complete(call)
    alarm = (await PgLlmStore(app_engine).state()).alarms["anthropic"]  # shared, as it is stored
    assert (alarm.kind, alarm.detail) == ("model_mismatch",
                                          "claude-haiku-5-5 not found (404): the model name or"
                                          " base_url")  # fmt: skip
