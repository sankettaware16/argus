"""The probe's states with a fake transport, and ``argus doctor``'s offline LLM checks (Q-G1)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from pydantic import SecretStr

from argus.llm import budget
from argus.llm import doctor as llm_doctor
from argus.llm.probe import ProbeState, probe
from argus.llm.providers import LlmConfig
from argus.llm.wire import LlmReply, LlmWire, TransportError
from tests.unit.llm import local_server as ls

pytestmark = pytest.mark.unit
KEY = SecretStr("local-abcdef12")
NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)


def provider(**over: Any) -> Any:
    data: dict[str, Any] = {
        "name": "local", "trust": "self_hosted", "base_url": "https://127.0.0.1:28443/v1",
        "keys": ["LOCAL_LLM_API_KEY"], "ca_file": "data/tls/local-llm.crt",
        "tasks": ["ping"], "limits": {"rpd": 9}, "timeout_s": 600,
        "models": {"small": {"name": "cp"}, "medium": {"name": "cp2"}}, **over,
    }  # fmt: skip
    return LlmConfig.model_validate({"providers": [data]}).providers[0]


class One:
    def __init__(self, answer: LlmReply | Exception) -> None:
        self.answer = answer
        self.asked: list[LlmWire] = []

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        raise AssertionError("a probe never posts")

    async def get(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        self.asked.append(wire)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def listed(*ids: Any) -> bytes:
    return json.dumps({"object": "list", "data": [{"id": i} for i in ids]}).encode()


@pytest.mark.parametrize(
    ("answer", "state", "detail"),
    [
        (LlmReply(200, listed("cp", "cp2", "x"), 7.6), ProbeState.UP, "cp, cp2 listed"),
        (LlmReply(200, listed("cp"), 1.0), ProbeState.MODEL_MISMATCH,
         "cp2 not listed (it lists cp)"),
        (LlmReply(200, listed(), 1.0), ProbeState.MODEL_MISMATCH,
         "cp, cp2 not listed (it lists none)"),
        (LlmReply(200, listed(5, None), 1.0), ProbeState.MODEL_MISMATCH,
         "cp, cp2 not listed (it lists none)"),
        (LlmReply(200, b'{"data": {}}', 1.0), ProbeState.DOWN, "an unreadable model list"),
        (LlmReply(200, b'{"models": []}', 1.0), ProbeState.DOWN, "an unreadable model list"),
        (LlmReply(200, b"<html>", 1.0), ProbeState.DOWN, "an unreadable model list"),
        (LlmReply(200, b"[]", 1.0), ProbeState.DOWN, "an unreadable model list"),
        (LlmReply(401, b"refused", 1.0), ProbeState.UNAUTHORIZED, "the key was refused (401)"),
        (LlmReply(403, b"", 1.0), ProbeState.UNAUTHORIZED, "the key was refused (403)"),
        (LlmReply(503, b"", 1.0), ProbeState.LOADING, "loading the model (503)"),
        (LlmReply(502, b"", 1.0), ProbeState.DOWN, "answered 502"),
        (TransportError("ConnectError", reached=False), ProbeState.DOWN,
         "no answer (ConnectError)"),
        (TransportError("tls_failed", reached=False, kind="tls_failed"), ProbeState.TLS_FAILED,
         "its certificate is not the pinned one"),
        (TransportError("its certificate file cannot be used (FileNotFoundError)", reached=False,
                        kind="tls_failed"), ProbeState.TLS_FAILED,
         "its certificate file cannot be used (FileNotFoundError)"),
    ],
)  # fmt: skip
async def test_the_probe_states(answer: Any, state: ProbeState, detail: str) -> None:
    transport = One(answer)
    result = await probe(provider(), KEY, transport)
    assert (result.state, result.detail) == (state, detail)
    (wire,) = transport.asked
    assert (wire.url, wire.body, wire.timeout_s) == ("https://127.0.0.1:28443/v1/models", b"",
                                                     15.0)  # fmt: skip
    if isinstance(answer, LlmReply):
        assert result.latency_ms == round(answer.elapsed_ms)


async def test_the_probe_never_waits_longer_than_the_provider() -> None:
    transport = One(LlmReply(200, listed("cp", "cp2"), 1.0))
    await probe(provider(timeout_s=5), KEY, transport, timeout_s=15)
    assert transport.asked[0].timeout_s == 5


# -- doctor ----------------------------------------------------------------------------------


def config(tmp_path: Path, **over: Any) -> LlmConfig:
    keys = tmp_path / "keys.env"
    return LlmConfig.model_validate({"keys_file": str(keys),
                                     "providers": [provider(**over).model_dump()]})  # fmt: skip


def test_the_keys_file_must_be_private(tmp_path: Path) -> None:
    llm = config(tmp_path)
    assert llm_doctor.keys_file_check(llm).ok
    keys = tmp_path / "keys.env"
    keys.write_text("LOCAL_LLM_API_KEY=x\n", encoding="utf-8")
    os.chmod(keys, 0o644)
    found = llm_doctor.keys_file_check(llm)
    assert (found.ok, found.detail) == (False, f"{keys} is readable by others (chmod 600)")
    os.chmod(keys, 0o600)
    assert llm_doctor.keys_file_check(llm).ok


def test_the_providers_line_names_keys_and_switches(tmp_path: Path) -> None:
    llm = config(tmp_path, enabled=False)
    found = llm_doctor.providers_check(llm, {"LOCAL_LLM_API_KEY"})
    assert found.detail == "local (disabled, key)"
    assert llm_doctor.providers_check(llm, set()).detail == "local (disabled, no key)"


def test_a_certificate_not_imported_yet(tmp_path: Path) -> None:
    missing = tmp_path / "local-llm.crt"
    off = provider(enabled=False, ca_file=str(missing))
    assert llm_doctor.certificate_check(off, NOW) == llm_doctor.Finding(
        "llm local certificate", True, "not imported yet (setup-argus-side.sh --import)"
    )
    on = provider(ca_file=str(missing))
    found = llm_doctor.certificate_check(on, NOW)
    assert found is not None
    assert not found.ok
    assert "does not exist" in found.detail
    assert llm_doctor.certificate_check(LlmConfig.model_validate({"providers": [{
        "name": "c", "base_url": "https://c.example/v1", "keys": ["K"],
        "models": {"small": {"name": "m"}}}]}).providers[0], NOW) is None  # fmt: skip


def test_an_imported_certificate_is_checked(tmp_path: Path) -> None:
    cert = ls.make_certificate(tmp_path / "run")
    os.chmod(cert, 0o644)
    os.chmod(cert.parent, 0o700)  # as the import makes data/tls
    good = llm_doctor.certificate_check(provider(ca_file=str(cert)), NOW)
    assert good is not None
    assert good.ok, good
    assert good.detail.startswith("self-hosted, for 127.0.0.1, valid until ")
    elsewhere = llm_doctor.certificate_check(
        provider(ca_file=str(cert), base_url="https://127.0.0.2:28443/v1"), NOW
    )
    assert elsewhere is not None
    assert elsewhere.detail == "the certificate does not name 127.0.0.2"
    expires = x509.load_pem_x509_certificate(cert.read_bytes()).not_valid_after_utc
    late = llm_doctor.certificate_check(provider(ca_file=str(cert)), expires + timedelta(days=1))
    assert late is not None
    assert not late.ok
    assert "run the setup again" in late.detail
    os.chmod(cert, 0o664)
    loose = llm_doctor.certificate_check(provider(ca_file=str(cert)), NOW)
    assert loose is not None
    assert not loose.ok
    assert "writable by others" in loose.detail
    junk = tmp_path / "junk.crt"
    junk.write_text("not a certificate", encoding="utf-8")
    os.chmod(junk, 0o644)
    bad = llm_doctor.certificate_check(provider(ca_file=str(junk)), NOW)
    assert bad is not None
    assert not bad.ok
    assert "not a usable PEM certificate" in bad.detail


def test_alarms_fail_the_doctor() -> None:
    assert llm_doctor.alarms_check(budget.State(), {"local"}) == llm_doctor.Finding(
        "llm alarms", True, "none")  # fmt: skip
    state = budget.raise_alarm(budget.State(), "local", "tls_failed", "not pinned", NOW)
    found = llm_doctor.alarms_check(state, {"local"})
    assert not found.ok
    assert found.detail == (
        "local: tls_failed since 2026-10-23 12:00 UTC (not pinned)"
        " (argus llm probe clears an alarm once the provider is up)"
    )


def test_the_offline_checks_together(tmp_path: Path) -> None:
    found = llm_doctor.offline_checks(config(tmp_path, ca_file=str(tmp_path / "x.crt"),
                                             enabled=False), set(), NOW)  # fmt: skip
    assert [f.name for f in found] == ["llm keys", "llm providers", "llm local certificate"]
    assert all(f.ok for f in found)
