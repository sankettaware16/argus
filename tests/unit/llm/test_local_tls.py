"""The local provider over real TLS (Q-G1, plan §12 item 19): a server with the setup script's
own certificate (a self-signed CA:FALSE leaf for 127.0.0.1) verifies under Python 3.12 with
that certificate pinned and nothing else; any other certificate is ``tls_failed`` with an
alarm. Through the whole gateway: the probe's states, the key, the thinking model's answer,
the context overflow, a cut-off answer, a machine that is off behind the tunnel. Never the
real machine: the stand-in listens on a free port, and the guard refuses 18443."""

from __future__ import annotations

import socket
import ssl
import subprocess
import sys
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from argus.gateway.transport import pinned_context
from argus.llm import budget
from argus.llm.gateway import AUTH_WAIT, Call, LlmGateway, MemoryLlmStore, NoCapacity, Refused
from argus.llm.privacy import Privacy, Request
from argus.llm.probe import ProbeState, probe
from argus.llm.providers import LlmConfig, Tier
from argus.llm.wire import HttpxLlmTransport, LlmWire, TransportError
from tests.unit.llm import local_server as ls

pytestmark = pytest.mark.unit
KEYS = {"LOCAL_LLM_API_KEY": SecretStr(ls.KEY)}


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """The setup script's certificate (pinned), a second run's (another key), and one for
    another address."""
    base = tmp_path_factory.mktemp("certs")
    other_host = base / "host"
    other_host.mkdir()
    command = [a.replace("IP:127.0.0.1", "IP:127.0.0.2") for a in ls.openssl_command(other_host)]
    subprocess.run(command, check=True, capture_output=True)  # noqa: S603
    return {
        "pinned": ls.make_certificate(base / "run1"),
        "next_run": ls.make_certificate(base / "run2"),
        "other_host": other_host / "llm.crt",
    }


def config(port: int, ca: Path, **over: Any) -> LlmConfig:
    provider: dict[str, Any] = {
        "name": "local", "trust": "campus", "base_url": f"https://127.0.0.1:{port}/v1",
        "keys": ["LOCAL_LLM_API_KEY"], "ca_file": str(ca), "timeout_s": 30, "concurrency": 1,
        "tasks": ["evaluate", "ping"], "probe": True, "max_tokens_field": "max_tokens",
        "models": {"small": {"name": ls.MODEL, "context_tokens": 16384, "thinking_tokens": 2048,
                             "max_output": 6144}},
        "limits": {"rpm": 100, "rpd": 300},
    }  # fmt: skip
    provider.update(over)
    return LlmConfig.model_validate({"providers": [provider]})


@pytest.fixture
def machine() -> ls.Machine:
    return ls.Machine()


@pytest.fixture
def port(certs: dict[str, Path], machine: ls.Machine) -> Iterator[int]:
    with ls.serving(certs["pinned"], machine) as p:
        yield p


def ping(privacy: Privacy, **over: Any) -> Call:
    request = Request("Connection test from ARGUS. Reply in JSON.", (), (), (), (),
                      privacy.campus)  # fmt: skip
    return Call(request, 'Answer with the JSON object {"ok": true} only.', "ping", **over)


async def gateway(cfg: LlmConfig) -> tuple[LlmGateway, MemoryLlmStore]:
    store = MemoryLlmStore()
    return LlmGateway(cfg, KEYS, HttpxLlmTransport(cfg), store), store


def test_the_certificate_is_the_setup_scripts_leaf(certs: dict[str, Path]) -> None:
    command = ["openssl", "x509", "-in", str(certs["pinned"]), "-noout", "-text"]
    text = subprocess.run(command, check=True, capture_output=True, text=True).stdout  # noqa: S603
    assert "CA:FALSE" in text
    assert "IP Address:127.0.0.1" in text
    assert "TLS Web Server Authentication" in text
    names = [line.split(":", 1)[1].replace(" ", "") for line in text.splitlines()
             if line.strip().startswith(("Issuer:", "Subject:"))]  # fmt: skip
    assert names == ["CN=ARGUSlocalLLM", "CN=ARGUSlocalLLM"]  # self-signed: no CA above it


def test_python_312_trusts_the_leaf_alone(certs: dict[str, Path], port: int) -> None:
    """Plan §12 item 19: no CA above it, the leaf itself is the trust anchor."""
    assert sys.version_info[:2] == (3, 12)
    context = pinned_context(certs["pinned"])
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname
    with (
        socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
        context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
    ):
        assert tls.getpeercert()["subject"] == ((("commonName", "ARGUS local LLM"),),)
    for other in ("next_run", "other_host"):
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5) as raw,
            pytest.raises(ssl.SSLCertVerificationError),
        ):
            pinned_context(certs[other]).wrap_socket(raw, server_hostname="127.0.0.1")


async def test_a_call_takes_the_answer_never_the_reasoning(
    certs: dict[str, Path], port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    gw, store = await gateway(config(port, certs["pinned"]))
    try:
        done = await gw.complete(ping(privacy, max_output=200))
    finally:
        await gw.aclose()
    assert done.text == '{"ok": true}'
    assert machine.reasoning not in done.text
    assert (done.provider, done.model, done.input_tokens, done.output_tokens) == (
        "local", ls.MODEL, 120, 64)  # fmt: skip
    first, second = machine.seen
    assert (first["method"], first["path"]) == ("GET", "/v1/models")
    assert (second["method"], second["path"]) == ("POST", "/v1/chat/completions")
    assert second["headers"]["Authorization"] == f"Bearer {ls.KEY}"
    assert second["body"]["max_tokens"] == 200 + 2048  # room for the thinking (D-108)
    assert second["body"]["response_format"] == {"type": "json_object"}
    assert [e.outcome for e in store.ledger] == ["probe: up", "ok"]
    state = await store.state()
    assert "local" in state.probed
    assert state.leases == {}  # released


@pytest.mark.parametrize("other", ["next_run", "other_host"])
async def test_any_other_certificate_is_tls_failed_with_an_alarm(
    certs: dict[str, Path], machine: ls.Machine, privacy: Privacy, other: str
) -> None:
    with ls.serving(certs[other], machine) as p:
        gw, store = await gateway(config(p, certs["pinned"]))
        before = datetime.now(UTC)
        try:
            with pytest.raises(NoCapacity) as caught:
                await gw.complete(ping(privacy))
            again = HttpxLlmTransport(config(p, certs["pinned"]))
            wire = LlmWire("local", f"https://127.0.0.1:{p}/v1/chat/completions", b"{}", 5.0)
            with pytest.raises(TransportError) as direct:
                await again.send(wire, KEYS["LOCAL_LLM_API_KEY"])
            await again.aclose()
        finally:
            await gw.aclose()
    assert (direct.value.kind, direct.value.reached) == ("tls_failed", False)
    assert machine.seen == []  # nothing, not even the key, went to the other server
    assert "tls_failed" in str(caught.value)
    assert caught.value.until <= datetime.now(UTC) + AUTH_WAIT
    assert caught.value.until >= before + AUTH_WAIT - timedelta(seconds=5)
    state = await store.state()
    assert state.alarms["local"].kind == "tls_failed"
    assert [e.outcome for e in store.ledger] == ["probe: tls_failed"]
    assert state.cooldowns["local"] == caught.value.until


async def test_a_missing_certificate_file_is_tls_failed(
    tmp_path: Path, port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    cfg = config(port, tmp_path / "not-imported.crt", probe=False)
    gw, store = await gateway(cfg)
    try:
        with pytest.raises(NoCapacity, match="tls_failed"):
            await gw.complete(ping(privacy))
    finally:
        await gw.aclose()
    assert machine.seen == []
    alarm = (await store.state()).alarms["local"]
    assert (alarm.kind, alarm.detail) == ("tls_failed", "its certificate file cannot be used"
                                                        " (FileNotFoundError)")  # fmt: skip
    assert [e.outcome for e in store.ledger] == ["tls_failed"]


@pytest.mark.parametrize(
    ("change", "state", "alarm"),
    [({"key": "another-run-key"}, ProbeState.UNAUTHORIZED, True),
     ({"model": "dolphin3-cyber-8b"}, ProbeState.MODEL_MISMATCH, True),
     ({"mode": "loading"}, ProbeState.LOADING, False)],
)  # fmt: skip
async def test_the_probe_tells_the_states_apart(
    certs: dict[str, Path],
    port: int,
    machine: ls.Machine,
    privacy: Privacy,
    change: dict[str, str],
    state: ProbeState,
    alarm: bool,
) -> None:
    for name, value in change.items():
        setattr(machine, name, value)
    cfg = config(port, certs["pinned"])
    transport = HttpxLlmTransport(cfg)
    try:
        result = await probe(cfg.providers[0], KEYS["LOCAL_LLM_API_KEY"], transport)
    finally:
        await transport.aclose()
    assert result.state is state
    gw, store = await gateway(cfg)
    try:
        with pytest.raises(NoCapacity) as caught:
            await gw.complete(ping(privacy))
    finally:
        await gw.aclose()
    assert [s["method"] for s in machine.seen] == ["GET", "GET"]  # the call itself never went
    assert ("local" in (await store.state()).alarms) is alarm
    assert caught.value.until <= datetime.now(UTC) + timedelta(hours=1)


async def test_an_off_machine_behind_the_tunnel_is_down_not_a_certificate(
    certs: dict[str, Path], privacy: Privacy
) -> None:
    """The tunnel's SSH listener accepts and closes when the machine is off: no answer, the
    provider's breaker (5 minutes first), no alarm; a closed port the same."""
    with ls.closing_listener() as p:
        gw, store = await gateway(config(p, certs["pinned"]))
        try:
            with pytest.raises(NoCapacity) as caught:
                await gw.complete(ping(privacy))
        finally:
            await gw.aclose()
    state = await store.state()
    assert state.alarms == {}
    assert state.breakers["local"].is_open(datetime.now(UTC))
    assert caught.value.until <= datetime.now(UTC) + timedelta(minutes=5)
    assert [e.outcome for e in store.ledger] == ["probe: down"]
    gw, store = await gateway(config(ls.free_port(), certs["pinned"]))
    try:
        with pytest.raises(NoCapacity, match="down"):
            await gw.complete(ping(privacy))
    finally:
        await gw.aclose()


@pytest.mark.parametrize(("mode", "outcome"), [("overflow", "too_large"),
                                               ("cut_off", "truncated"),
                                               ("think_only", "truncated")])  # fmt: skip
async def test_an_overflow_or_a_cut_off_answer_is_never_taken(
    certs: dict[str, Path],
    port: int,
    machine: ls.Machine,
    privacy: Privacy,
    mode: str,
    outcome: str,
) -> None:
    machine.mode = mode
    gw, store = await gateway(config(port, certs["pinned"]))
    try:
        with pytest.raises(Refused, match=outcome):
            await gw.complete(ping(privacy))
    finally:
        await gw.aclose()
    assert store.ledger[-1].outcome == outcome
    assert (await store.state()).breakers.get("local/" + ls.MODEL, budget.breaker_core.
                                              BreakerState()).open_until is None  # fmt: skip


async def test_a_slow_answer_ends_at_the_deadline(
    certs: dict[str, Path], port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    machine.delay_s = 1.5
    gw, store = await gateway(config(port, certs["pinned"], timeout_s=0.5))
    try:
        with pytest.raises(NoCapacity, match="no answer"):
            await gw.complete(ping(privacy))
    finally:
        await gw.aclose()
    assert store.ledger[-1].outcome.startswith("no_answer")
    state = await store.state()
    assert state.breakers["local/" + ls.MODEL].is_open(datetime.now(UTC))  # the model's
    assert state.leases == {}


async def test_only_its_tasks_and_tiers(
    certs: dict[str, Path], port: int, machine: ls.Machine, privacy: Privacy
) -> None:
    gw, _ = await gateway(config(port, certs["pinned"]))
    try:
        with pytest.raises(Refused, match="local: not for assess"):
            await gw.complete(ping(privacy).__class__(**{**vars(ping(privacy)),
                                                       "purpose": "assess"}))  # fmt: skip
        with pytest.raises(Refused, match="no provider"):
            await gw.complete(ping(privacy, tier=Tier.LARGE))
    finally:
        await gw.aclose()
    assert machine.seen == []
