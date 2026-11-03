"""The LLM gateway's configuration, keys, HTTP transport and recordings (P5)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import stat
import types
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from argus.llm import budget
from argus.llm.providers import DEFAULT_PATH, ROOT, LlmConfig, Tier, load_config, load_keys
from argus.llm.wire import (
    MAX_ANSWER_BYTES,
    CassetteMiss,
    HttpxLlmTransport,
    LlmCassette,
    LlmReply,
    LlmWire,
    TransportError,
    cassette_key,
)
from argus.observability.redaction import redact_text

WIRE = LlmWire("p", "https://p.example/v1/chat/completions", b'{"model": "m", "x": 1}', 5.0)
KEY = SecretStr("sk-test-0123456789abcdef")


def test_the_shipped_config_loads() -> None:
    cfg = load_config(DEFAULT_PATH)
    names = ["groq", "openrouter", "gemini", "openai", "local"]
    assert [p.name for p in cfg.providers] == names
    assert cfg.monthly_cap_usd == 40.0  # D-152
    assert cfg.margin == 0.8
    assert cfg.budget_config().shares[budget.Priority.LOW] == 0.5
    openai = cfg.providers[3]  # paid, last of the enabled ones (D-101)
    assert [p.name for p in cfg.providers if p.enabled][-1] == "openai"
    assert openai.models[Tier.SMALL].name == "gpt-5.4-nano"
    assert openai.max_tokens_field == "max_completion_tokens"
    assert all(p.base_url.startswith("https://") for p in cfg.providers)
    for p in cfg.providers:  # every provider but the paid one costs nothing
        if p is not openai:
            assert all(m.input_per_m == 0 == m.output_per_m for m in p.models.values())
    assert all(p.timeout_s == 120 for p in cfg.providers[:4])  # the agent's 120 s before Q-G1


def provider(**over: Any) -> dict[str, Any]:
    return {"name": "p", "base_url": "https://p.example/v1", "keys": ["K"],
            "models": {"small": {"name": "m"}}, **over}  # fmt: skip


@pytest.mark.parametrize(
    "bad",
    [
        {"providers": []},
        {"providers": [provider(), provider()]},
        {"providers": [provider(base_url="http://p.example/v1")]},
        {"providers": [provider(base_url="https://p.example/v1?x=1")]},
        {"providers": [provider(base_url="https://")]},
        {"providers": [provider(keys=[])]},
        {"providers": [provider(keys=["lower"])]},
        {"providers": [provider(name="Bad Name")]},
        {"providers": [provider(models={})]},
        {"providers": [provider(models={"huge": {"name": "m"}})]},
        {"providers": [provider(models={"small": {"name": "m", "input_per_m": -1}})]},
        {"providers": [provider(limits={"rpm": 0})]},
        {"providers": [provider(unknown=1)]},
        {"providers": [provider()], "margin": 1.5},
        {"providers": [provider()], "margin": 0},
        {"providers": [provider()], "shares": {"high": 1.0}},
        {"providers": [provider()], "shares": {"high": 1.0, "normal": 0, "low": 0.5}},
        {"providers": [provider()], "monthly_cap_usd": -1},
    ],
)
def test_a_bad_config_is_refused(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        LlmConfig.model_validate(bad)


def test_buckets_and_costs() -> None:
    cfg = LlmConfig.model_validate({"providers": [provider(
        limits={"rpm": 5},
        models={"small": {"name": "m", "input_per_m": 2.0, "output_per_m": 8.0,
                          "limits": {"tpd": 10}},
                "medium": {"name": "n"}},
    )]})  # fmt: skip
    p = cfg.providers[0]
    assert p.base_url == "https://p.example/v1"
    assert p.buckets(Tier.SMALL) == (
        budget.Bucket("p", budget.Limits(rpm=5)),
        budget.Bucket("p/m", budget.Limits(tpd=10)),
    )
    assert p.buckets(Tier.MEDIUM) == (budget.Bucket("p", budget.Limits(rpm=5)),)
    assert p.models[Tier.SMALL].cost(1_000_000, 500_000) == pytest.approx(6.0)
    bare = LlmConfig.model_validate({"providers": [provider()]}).providers[0]
    assert bare.buckets(Tier.SMALL) == ()
    assert bare.base_url == "https://p.example/v1"
    trailing = LlmConfig.model_validate({"providers": [provider(base_url="https://p.example/")]})
    assert trailing.providers[0].base_url == "https://p.example"


def test_keys_are_read_by_name_and_registered_for_redaction(tmp_path: Path) -> None:
    path = tmp_path / "keys.env"
    path.write_text(
        "# comment\nA_KEY=sk-aaaa-1111-secret\n B_KEY = 'quoted-bbbb-2222' \nC_KEY=\n"
        'OTHER=not-wanted-3333\nD_KEY="dq-dddd-4444"\nnot a line\n',
        encoding="utf-8",
    )
    keys = load_keys(path, {"A_KEY", "B_KEY", "C_KEY", "D_KEY"})
    assert sorted(keys) == ["A_KEY", "B_KEY", "D_KEY"]
    assert keys["B_KEY"].get_secret_value() == "quoted-bbbb-2222"
    assert keys["D_KEY"].get_secret_value() == "dq-dddd-4444"
    assert "sk-aaaa-1111-secret" not in repr(keys)
    assert "sk-aaaa-1111-secret" not in redact_text("key sk-aaaa-1111-secret here")
    assert "not-wanted-3333" in redact_text("x not-wanted-3333")
    assert load_keys(tmp_path / "missing.env", {"A_KEY"}) == {}


def client(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


P_CONFIG = LlmConfig.model_validate({"providers": [provider()]})


def one(c: httpx.AsyncClient) -> HttpxLlmTransport:
    """The transport with this client for provider "p" (WIRE's)."""
    return HttpxLlmTransport(P_CONFIG, {"p": c})


async def test_the_transport_posts_with_the_key_in_a_header_only() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(429, content=b'{"ok": 1}', headers={"Retry-After": "9"})

    transport = one(client(handler))
    reply = await transport.send(WIRE, KEY)
    await transport.aclose()
    assert (reply.status, reply.body, reply.retry_after) == (429, b'{"ok": 1}', "9")
    assert reply.elapsed_ms >= 0
    (request,) = seen
    assert request.method == "POST"
    assert str(request.url) == WIRE.url
    assert request.headers["authorization"] == f"Bearer {KEY.get_secret_value()}"
    assert request.headers["content-type"] == "application/json"
    assert request.content == WIRE.body
    assert KEY.get_secret_value() not in str(request.url)


async def test_the_transport_never_follows_a_redirect() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://elsewhere.example/"})

    reply = await one(client(handler)).send(WIRE, KEY)
    assert reply.status == 302
    assert reply.retry_after is None


async def test_the_default_client_neither_redirects_nor_uses_a_proxy() -> None:
    transport = HttpxLlmTransport(P_CONFIG)
    assert transport._clients["p"].follow_redirects is False
    assert transport._clients["p"]._trust_env is False
    await transport.aclose()


async def test_an_answer_too_large_is_cut_off() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (MAX_ANSWER_BYTES + 1))

    with pytest.raises(TransportError, match="too large"):
        await one(client(handler)).send(WIRE, KEY)

    def exact(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * MAX_ANSWER_BYTES)

    assert len((await one(client(exact)).send(WIRE, KEY)).body) == MAX_ANSWER_BYTES


async def test_no_answer_is_a_transport_error_naming_only_its_kind() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"failed {KEY.get_secret_value()}")

    with pytest.raises(TransportError) as caught:
        await one(client(handler)).send(WIRE, KEY)
    assert str(caught.value) == "ConnectError"
    assert caught.value.__cause__ is None


class Inner:
    def __init__(self) -> None:
        self.calls = 0

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.calls += 1
        return LlmReply(200, b'{"answer": "yes"}', 12.345, "3")


async def test_a_cassette_records_and_replays_without_the_key(tmp_path: Path) -> None:
    path = tmp_path / "c" / "llm.json"
    inner = Inner()
    rec = LlmCassette(path, "record", inner)
    first = await rec.send(WIRE, KEY)
    rec.save()
    rec.save()  # unchanged: nothing written
    assert inner.calls == 1
    assert first.status == 200
    raw = path.read_text(encoding="utf-8")
    assert KEY.get_secret_value() not in raw
    assert "Bearer" not in raw
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    entry = json.loads(raw)["entries"][cassette_key(WIRE)]
    assert entry == {"provider": "p", "status": 200, "body": '{"answer": "yes"}',
                     "elapsed_ms": 12.3, "retry_after": "3"}  # fmt: skip
    play = LlmCassette(path)
    again = await play.send(WIRE, SecretStr("another"))
    assert (again.status, again.body, again.elapsed_ms, again.retry_after) == (
        200, b'{"answer": "yes"}', 12.3, "3")  # fmt: skip
    play.save()
    assert path.read_text(encoding="utf-8") == raw
    other = LlmWire("p", WIRE.url, b'{"model": "m", "x": 2}', 5.0)
    with pytest.raises(CassetteMiss, match="p: no recorded answer"):
        await play.send(other, KEY)


def test_cassette_keys_follow_provider_url_and_body_not_spacing_or_deadline() -> None:
    same = LlmWire("p", WIRE.url, b'{"x":1,"model":"m"}', 99.0)
    assert cassette_key(same) == cassette_key(WIRE)
    for changed in (LlmWire("q", WIRE.url, WIRE.body, 5.0),
                    LlmWire("p", WIRE.url + "x", WIRE.body, 5.0),
                    LlmWire("p", WIRE.url, b'{"model": "n", "x": 1}', 5.0)):  # fmt: skip
        assert cassette_key(changed) != cassette_key(WIRE)


def test_cassette_setup_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        LlmCassette(tmp_path / "none.json")
    with pytest.raises(ValueError, match="needs a transport"):
        LlmCassette(tmp_path / "none.json", "record")
    bad = tmp_path / "bad.json"
    bad.write_text('{"format": 9, "entries": {}}', encoding="utf-8")
    with pytest.raises(ValueError, match="format 9"):
        LlmCassette(bad)
    assert LlmCassette(tmp_path / "new.json", "record", Inner()).entries == {}


async def test_a_failed_save_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    rec = LlmCassette(tmp_path / "c.json", "record", Inner())
    await rec.send(WIRE, KEY)

    def boom(*a: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("argus.llm.wire.os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        rec.save()
    assert list(tmp_path.iterdir()) == []  # noqa: ASYNC240
    assert rec.changed


# -- the exact values and edges (mutation testing, P5) --------------------------------------


def value_error(data: dict[str, Any]) -> str:
    with pytest.raises(ValidationError) as caught:
        LlmConfig.model_validate(data)
    return str(caught.value.errors()[0]["msg"])


def test_the_config_errors_say_what_is_wrong() -> None:
    assert value_error({"providers": [provider(base_url="http://p.example")]}) == (
        "Value error, a provider is reached over https, with no query or fragment"
    )
    assert value_error({"providers": [provider(), provider()]}) == (
        "Value error, provider names must be unique"
    )
    assert value_error({"providers": [provider()], "shares": {"high": 1.0}}) == (
        "Value error, shares needs exactly high, normal, low"
    )


def test_the_config_defaults_and_smallest_values() -> None:
    cfg = LlmConfig.model_validate({"providers": [provider()]})
    assert cfg.keys_file == Path("reference/llm_api_keys.env")
    assert (cfg.monthly_cap_usd, cfg.margin) == (10.0, 0.8)
    assert cfg.shares == {budget.Priority.HIGH: 1.0, budget.Priority.NORMAL: 0.8,
                          budget.Priority.LOW: 0.5}  # fmt: skip
    p = cfg.providers[0]
    assert p.max_tokens_field == "max_tokens"
    assert p.json_mode is True
    assert p.enabled is True
    limits = {"rpm": 1, "rpd": 1, "tpm": 1, "tpd": 1}
    model = {"name": "m" * 200, "input_per_m": 0.5, "output_per_m": 0.5, "limits": limits}
    small = LlmConfig.model_validate({
        "monthly_cap_usd": 0, "shares": {"high": 1.0, "normal": 1.0, "low": 1.0},
        "providers": [provider(limits=limits, models={"small": model})],
    })  # fmt: skip
    assert small.providers[0].buckets(Tier.SMALL)[0].limits == budget.Limits(1, 1, 1, 1)
    assert small.monthly_cap_usd == 0
    too_long = {"small": {**model, "name": "m" * 201}}
    with pytest.raises(ValidationError):
        LlmConfig.model_validate({"providers": [provider(models=too_long)]})
    with pytest.raises(ValidationError):
        LlmConfig.model_validate({"providers": [provider()],
                                  "shares": {"high": 1.5, "normal": 0.8, "low": 0.5}})  # fmt: skip


def test_the_config_is_immutable() -> None:
    cfg = LlmConfig.model_validate({"providers": [provider()]})
    with pytest.raises(ValidationError):
        cfg.providers[0].name = "q"  # type: ignore[misc]


def test_the_cost_is_per_million_tokens_exactly() -> None:
    cfg = LlmConfig.model_validate(
        {"providers": [provider(models={"small": {"name": "m", "input_per_m": 1.0}})]}
    )
    assert cfg.providers[0].models[Tier.SMALL].cost(1_000_000, 0) == 1.0


def test_only_trailing_slashes_leave_the_base_url() -> None:
    cfg = LlmConfig.model_validate({"providers": [provider(base_url="https://p.example/X/")]})
    assert cfg.providers[0].base_url == "https://p.example/X"


def test_a_relative_keys_file_is_read_from_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "keys.env"
    path.write_text("A_KEY=abcX\n", encoding="utf-8")
    elsewhere = tmp_path.joinpath(*["d"] * len(ROOT.parts))  # ".." never reaches "/" from here
    elsewhere.mkdir(parents=True)
    monkeypatch.chdir(elsewhere)
    keys = load_keys(Path(os.path.relpath(path, ROOT)), {"A_KEY"})
    assert keys["A_KEY"].get_secret_value() == "abcX"


async def test_the_exact_answer_limit_and_the_whole_answer() -> None:
    def big(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (1024 * 1024 + 1))

    with pytest.raises(TransportError) as caught:
        await one(client(big)).send(WIRE, KEY)
    assert str(caught.value) == "answer too large"

    def exact(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (1024 * 1024))

    assert len((await one(client(exact)).send(WIRE, KEY)).body) == 1024 * 1024

    async def parts() -> Any:
        for part in (b'{"a"', b": 1", b"}"):
            yield part

    def chunked(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=parts())

    assert (await one(client(chunked)).send(WIRE, KEY)).body == b'{"a": 1}'


async def test_the_time_an_answer_took(monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([10.0, 10.25])
    monkeypatch.setattr("argus.llm.wire.time", types.SimpleNamespace(monotonic=lambda: next(ticks)))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{}")

    assert (await one(client(handler)).send(WIRE, KEY)).elapsed_ms == 250.0


async def test_the_default_client_times_out_after_a_minute_and_closes() -> None:
    transport = HttpxLlmTransport(P_CONFIG)
    assert transport._clients["p"].timeout == httpx.Timeout(60.0)
    await transport.aclose()
    assert transport._clients["p"].is_closed


def test_the_wire_records_are_immutable() -> None:
    with pytest.raises(dataclasses.FrozenInstanceError):
        WIRE.url = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        LlmReply(200, b"", 1.0).status = 500  # type: ignore[misc]


def test_the_cassette_key_is_the_hash_of_a_compact_canonical_form() -> None:
    canonical = '[1,"p","https://p.example/v1/chat/completions",{"model":"m","x":1}]'
    assert cassette_key(WIRE) == hashlib.sha256(canonical.encode()).hexdigest()


async def test_a_cassette_of_format_1_replays(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    entry = {"status": 200, "body": "{}", "elapsed_ms": 1.0}
    path.write_text(json.dumps({"format": 1, "entries": {cassette_key(WIRE): entry}}),
                    encoding="utf-8")  # fmt: skip
    assert (await LlmCassette(path).send(WIRE, KEY)).body == b"{}"


def test_recording_without_a_transport_says_so(tmp_path: Path) -> None:
    with pytest.raises(ValueError) as caught:  # noqa: PT011 - the exact message follows
        LlmCassette(tmp_path / "c.json", "record")
    assert str(caught.value) == "recording needs a transport to record from"


async def test_saving_writes_only_a_changed_recording(tmp_path: Path) -> None:
    path = tmp_path / "c.json"
    rec = LlmCassette(path, "record", Inner())
    assert rec.changed is False
    rec.save()
    assert not path.exists()
    await rec.send(WIRE, KEY)
    rec.save()
    assert rec.changed is False
    path.unlink()
    rec.save()
    assert not path.exists()
    path.write_text('{"format": 1, "entries": {}}', encoding="utf-8")
    play = LlmCassette(path)
    play.changed = True
    play.save()
    assert path.read_text(encoding="utf-8") == '{"format": 1, "entries": {}}'


async def test_an_answer_that_is_not_utf8_is_recorded_with_replacements(tmp_path: Path) -> None:
    class Bad(Inner):
        async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
            return LlmReply(200, b"\xffok", 1.0)

    rec = LlmCassette(tmp_path / "c.json", "record", Bad())
    await rec.send(WIRE, KEY)
    assert rec.entries[cassette_key(WIRE)]["body"] == "�ok"


async def test_the_recording_file_and_its_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "a" / "b" / "c.json"
    seen: list[str] = []
    real = os.replace

    def replace(src: str, dst: Path) -> None:
        seen.append(Path(src).name)
        real(src, dst)

    monkeypatch.setattr("argus.llm.wire.os.replace", replace)
    rec = LlmCassette(path, "record", Inner())
    await rec.send(WIRE, KEY)
    rec.save()
    assert path.read_text(encoding="utf-8").startswith('{\n "entries": {\n  "')
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    (temp,) = seen
    assert temp.startswith(".cassette-")


async def test_a_failed_save_whose_temporary_file_is_gone_raises_the_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def gone(src: str, dst: Path) -> None:
        Path(src).unlink()
        raise OSError("disk full")

    rec = LlmCassette(tmp_path / "c.json", "record", Inner())
    await rec.send(WIRE, KEY)
    monkeypatch.setattr("argus.llm.wire.os.replace", gone)
    with pytest.raises(OSError, match="disk full"):
        rec.save()


@pytest.mark.parametrize(
    ("error", "reached"),
    [(httpx.ConnectError("x"), False), (httpx.ConnectTimeout("x"), False),
     (httpx.PoolTimeout("x"), False), (httpx.ReadTimeout("x"), True),
     (httpx.ReadError("x"), True), (httpx.RemoteProtocolError("x"), True)],
)  # fmt: skip
async def test_whether_a_failure_reached_the_provider(error: Exception, reached: bool) -> None:
    def fail(request: httpx.Request) -> httpx.Response:
        raise error

    with pytest.raises(TransportError) as caught:
        await one(client(fail)).send(WIRE, KEY)
    assert caught.value.reached is reached
    assert str(caught.value) == type(error).__name__
    assert TransportError("x").reached is True


def test_a_transport_error_keeps_its_message() -> None:
    from argus.llm.wire import TransportError

    assert str(TransportError("refused")) == "refused"
    assert TransportError("x").reached is True
    assert TransportError("x", reached=False).reached is False
