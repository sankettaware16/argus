"""``argus llm`` against a throwaway database, with test keys and a fake provider; nothing
reaches a model."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.llm.privacy import Privacy
from argus.llm.providers import LlmConfig
from argus.llm.wire import LlmReply
from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture
from tests.unit.llm.test_gateway import Fake, config

pytestmark = pytest.mark.integration


@pytest.fixture
def llm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, privacy: Privacy) -> Fake:
    keys = tmp_path / "keys.env"
    keys.write_text("PAID_KEY=sk-test-paid-0000\n", encoding="utf-8")
    cfg: LlmConfig = config(keys_file=str(keys))
    fake = Fake({"paid": [LlmReply(429, b"{}", 1.0, "30")]})

    class Transport(Fake):
        async def aclose(self) -> None:
            pass

    shared: Any = Transport(fake.replies, fake.sent)
    monkeypatch.setattr("argus.llm.cli.load_config", lambda: cfg)
    monkeypatch.setattr("argus.llm.cli.HttpxLlmTransport", lambda config: shared)
    monkeypatch.setattr("argus.llm.cli._privacy", lambda settings: privacy)
    return shared  # type: ignore[no-any-return]


def test_stop_resume_status_and_ping(cli_env: Path, llm: Fake) -> None:  # noqa: F811
    config_args = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config_args)[0] == 0
    assert _invoke("llm", "stop", "--reason", "drill", *config_args) == (0, "LLM calls stopped\n")
    assert _invoke("llm", "stop", *config_args)[1] == "LLM calls were already stopped\n"
    code, out = _invoke("llm", "ping", *config_args)
    assert code == 0
    assert out.startswith("no capacity now")
    assert "stopped" in out
    assert llm.sent == []
    assert _invoke("llm", "resume", *config_args) == (0, "LLM calls resumed\n")
    code, out = _invoke("llm", "ping", *config_args)
    assert code == 0
    assert out.startswith("no capacity now (try after")
    assert "paid: rate_limited (429)" in out
    code, out = _invoke("llm", "ping", "--provider", "free", *config_args)
    assert code == 0
    assert out.startswith("refused: no provider is configured")  # free has no key here
    code, out = _invoke("llm", "ping", "--provider", "nobody", *config_args)
    assert code == 1
    assert "no provider 'nobody'" in out
    code, out = _invoke("llm", "status", *config_args)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "kill switch: off (calls allowed)"
    assert lines[1] == "this month: $0.000000 of $1.00"
    assert lines[2] == "today: $0.000000 (no daily cap)"
    assert "- paid (cloud, every task): key present; small=p-small, large=p-large" in lines
    assert "- free (cloud, every task): NO KEY; small=f-small" in lines
    assert any(line.strip().startswith("paid/p-small: cooling down until") for line in lines)
    assert "    free/f-small: day 0 req, 0 tok/1000000" in lines
    assert "  paid              1      0          0 $0.000000" in lines
    wire, key = llm.sent[0]
    assert key == "sk-test-paid-0000"
    assert b"Connection test from ARGUS" in wire.body
    assert "sk-test-paid-0000" not in out


def test_a_successful_ping_names_the_provider_and_cost(cli_env: Path, llm: Fake) -> None:  # noqa: F811
    config_args = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config_args)[0] == 0
    llm.replies["paid"] = [
        LlmReply(200, b'{"choices": [{"message": {"content": " {\\"ok\\": true} "}}],'
                 b' "usage": {"prompt_tokens": 10, "completion_tokens": 5}}', 42.0)
    ]  # fmt: skip
    code, out = _invoke("llm", "ping", "--tier", "large", *config_args)
    assert code == 0
    assert out == "paid p-large: '{\"ok\": true}' (10+5 tokens, $0.000200, 42 ms)\n"
    code, out = _invoke("llm", "status", *config_args)
    assert "this month: $0.000200 of $1.00" in out
    assert "today: $0.000200 (no daily cap)" in out
    assert "  paid              1      1         15 $0.000200" in out.splitlines()


def test_status_and_reconcile_show_each_paid_providers_caps(
    cli_env: Path,  # noqa: F811
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    privacy: Privacy,
) -> None:
    """P4-E2: the paid provider's own month and day against its caps, in status and after a
    reconcile; a free provider shows none."""
    keys = tmp_path / "keys.env"
    keys.write_text("PAID_KEY=sk-test-paid-0000\n", encoding="utf-8")
    base = config()
    capped = base.providers[0].model_copy(update={"monthly_cap_usd": 0.5, "daily_cap_usd": 0.25})
    cfg = config(keys_file=str(keys), daily_cap_usd=0.5,
                 providers=[capped.model_dump(), base.providers[1].model_dump()])  # fmt: skip
    answer = LlmReply(200, json.dumps({"choices": [{"message": {"content": '{"ok": true}'}}],
                                       "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
                                      ).encode(), 42.0)  # fmt: skip

    class Transport(Fake):
        async def aclose(self) -> None:
            pass

    monkeypatch.setattr("argus.llm.cli.load_config", lambda: cfg)
    monkeypatch.setattr("argus.llm.cli.HttpxLlmTransport",
                        lambda config: Transport({"paid": [answer]}))  # fmt: skip
    monkeypatch.setattr("argus.llm.cli._privacy", lambda settings: privacy)
    config_args = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config_args)[0] == 0
    code, out = _invoke("llm", "status", *config_args)
    assert code == 0
    lines = out.splitlines()
    spend = lines.index("- paid (cloud, every task): key present; small=p-small, large=p-large") + 1
    assert lines[spend] == "    spend: this month $0.000000 of $0.50, today $0.000000 of $0.25"
    assert not any("spend:" in line for line in lines[spend + 1 :])  # free: none
    code, out = _invoke("llm", "ping", *config_args)
    assert (code, out) == (0, "paid p-small: '{\"ok\": true}' (10+5 tokens, $0.000020, 42 ms)\n")
    code, out = _invoke("llm", "status", *config_args)
    assert "    spend: this month $0.000020 of $0.50, today $0.000020 of $0.25" in out.splitlines()
    code, out = _invoke("llm", "reconcile", *config_args)
    assert (code, out.splitlines()) == (0, [
        "this month's spend: $0.000020 -> $0.000020 (the ledger's settled costs)",
        "  paid: $0.000020 -> $0.000020",
    ])  # fmt: skip
