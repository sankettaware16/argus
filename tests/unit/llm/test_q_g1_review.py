"""Q-G1's independent review (docs/gates/q-g1.md, "Review"): one regression test per finding,
each seen failing on 2a2dea2 before its fix. Fakes and loopback TLS servers on ports of their
own only: never 18443, never the SIEM.

F1 D-112: the local model gets json_schema (strict) for every task, a deadline from the
   prompt's size, a refusal above 12,000 prompt tokens, and is slow only when slower than its
   measured speed.
F2 at most 150 evaluation calls a night per provider, and the local one gets them.
F3 the evaluation window and gold runs with tools stay out of the SIEM's 00:00-01:30 UTC pause.
F4 an alarm clears once a probe finds the machine right again; one for a provider no longer
   configured does not fail doctor.
F6 a campus certificate file holds exactly one certificate (doctor and client); IPv6 URLs;
   who may write the file.
F7 a window with a UTC offset is refused at load.
F8 one model's failure on the provider's breaker trial does not hold its sibling.
(F5, the test guard, is in tests/_guard/test_netguard_edges.py.)
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr, ValidationError

from argus.agent import schemas as agent_schemas
from argus.agent.registry import BINDINGS
from argus.assess.runner import Defer
from argus.evaluation import agent_eval, comparison
from argus.llm import budget
from argus.llm import doctor as llm_doctor
from argus.llm import prompts as llm_prompts
from argus.llm.gateway import Call, LlmGateway, MemoryLlmStore, NoCapacity, Refused, body_for
from argus.llm.privacy import Privacy, Request
from argus.llm.probe import ProbeState, probe
from argus.llm.providers import LlmConfig, ProviderConfig, Tier, load_config, pinned
from argus.llm.wire import HttpxLlmTransport, LlmReply, LlmWire, TransportError
from tests.unit.llm import local_server as ls
from tests.unit.llm.test_gateway import Clock
from tests.unit.llm.test_gateway_v2 import Fake, cloud, config, local, make, small

pytestmark = pytest.mark.unit
LOCAL_KEYS = {"LOCAL_LLM_API_KEY": SecretStr("local-abcdef12")}
EVENING = datetime(2026, 10, 23, 17, 30, tzinfo=UTC)


def ping_call(req: Request, tier: Tier) -> Call:
    from argus.llm import cli  # `argus llm ping`'s call

    return cli.ping_call(req, tier)  # type: ignore[attr-defined, no-any-return, unused-ignore]


def shipped(**update: Any) -> LlmConfig:
    """config/llm.yaml's local entry as `--provider local --allow-disabled` pins it; no probe
    (the fake answers no model list) unless a test asks for one."""
    cfg = pinned(load_config(), "local", allow_disabled=True)
    provider = cfg.providers[0].model_copy(update={"probe": False, **update})
    return cfg.model_copy(update={"providers": (provider,)})


def shipped_local() -> ProviderConfig:
    return pinned(load_config(), "local", allow_disabled=True).providers[0]


@dataclass
class Watching(Fake):
    """A fake that also notes the local lease while each call is out."""

    store: MemoryLlmStore | None = None
    leases: list[dict[str, datetime]] = field(default_factory=list)

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        if self.store is not None:
            self.leases.append(dict((await self.store.state()).leases.get(wire.provider, {})))
        return await super().send(wire, key)


def gateway(cfg: LlmConfig, fake: Fake | None = None) -> tuple[LlmGateway, Fake, MemoryLlmStore,
                                                                   Clock]:  # fmt: skip
    fake = fake or Watching()
    store = MemoryLlmStore()
    clock = Clock()
    fake.clock = clock
    if isinstance(fake, Watching):
        fake.store = store
    return LlmGateway(cfg, LOCAL_KEYS, fake, store, clock), fake, store, clock


def answer(text: str = '{"ok": true}', prompt: int = 120, written: int = 20,
           ms: float = 1600.0) -> LlmReply:  # fmt: skip
    body = {"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": written}}  # fmt: skip
    return LlmReply(200, json.dumps(body).encode(), ms)


def request(privacy: Privacy, text: str = "Assess I1.") -> Request:
    return Request(text, ("I1",), (), (), (), privacy.ours)


def strict(schema: dict[str, Any]) -> None:
    """OpenAI's strict rules, which llama-server's grammar keeps too: every object names all of
    its keys as required and allows no other; arrays say what they hold."""
    if schema.get("type") == "object":
        assert schema["additionalProperties"] is False, schema
        assert sorted(schema["required"]) == sorted(schema["properties"]), schema
        for sub in schema["properties"].values():
            strict(sub)
    elif schema.get("type") == "array":
        strict(schema["items"])
    else:
        assert schema.get("type") in ("string", "number", "boolean") or "enum" in schema, schema


def sent_format(provider: ProviderConfig, call: Call) -> dict[str, Any]:
    return dict(json.loads(body_for(provider, call)).get("response_format") or {})


# -- F1 (major) D-112: json_schema strict, size-based deadlines, 12,000 tokens, measured speed --


def test_the_shipped_local_provider_takes_a_strict_schema_only() -> None:
    p = shipped_local()
    assert (p.schema_output, p.schema_required) == (True, True)
    model = p.models[Tier.SMALL]
    assert (model.read_tps, model.write_tps, model.max_prompt_tokens) == (45.0, 11.0, 12000)


def test_a_schema_only_provider_needs_schema_output() -> None:
    with pytest.raises(ValidationError, match="schema_required needs schema_output"):
        config(local(schema_required=True))


async def test_every_local_task_sends_a_strict_schema(privacy: Privacy, tmp_path: Path) -> None:
    """ping, gold compare and gold agent (coordinator and specialist) are the local tasks."""
    from tests.unit.agent.test_agent import Model as AgentModel
    from tests.unit.agent.test_agent import agent, run, say
    from tests.unit.evaluation.test_comparison import CASES
    from tests.unit.evaluation.test_comparison import Model as CompareModel

    p = shipped_local()
    calls = [ping_call(Request("ping", (), (), (), (), privacy.ours), Tier.SMALL)]
    compare_model = CompareModel()
    await comparison.run(CASES, privacy, compare_model, tmp_path / "a.json", ("A-fake",))
    calls += compare_model.calls
    notes = json.dumps({"notes": "proxy says x", "cites": [], "ask": []})
    agent_model = AgentModel(say(consult=["proxy"]), notes, say())
    await run(agent(privacy, agent_model, purpose="evaluate"))
    calls += agent_model.calls
    assert {c.purpose for c in calls} == {"ping", "evaluate"} == set(p.tasks or ())
    expected = [llm_prompts.PING_SCHEMA, llm_prompts.ASSESS_V1_SCHEMA,
                llm_prompts.ASSESS_V1_SCHEMA, agent_schemas.COORDINATOR_SCHEMA,
                agent_schemas.SPECIALIST_SCHEMA, agent_schemas.COORDINATOR_SCHEMA]  # fmt: skip
    assert [c.schema for c in calls] == expected
    for call in calls:
        fmt = sent_format(p, call)
        assert fmt["type"] == "json_schema", (call.purpose, fmt)
        assert fmt["json_schema"]["strict"] is True
        strict(fmt["json_schema"]["schema"])
        # a cloud provider without schema_output keeps JSON mode: its bodies (and cassettes)
        # do not change
        assert sent_format(load_config().providers[0], call) == {"type": "json_object"}


def test_the_schemas_hold_the_keys_the_parsers_read() -> None:
    ping = llm_prompts.PING_SCHEMA["properties"]
    assert set(ping) == {"ok"}
    assess = llm_prompts.ASSESS_V1_SCHEMA["properties"]
    assert set(assess) == {"outcome", "confidence", "reason", "missing"}
    assert tuple(assess["outcome"]["enum"]) == llm_prompts.OUTCOMES
    coordinator = agent_schemas.COORDINATOR_SCHEMA["properties"]
    assert set(coordinator) == {"outcome", "confidence", "reason", "hypotheses", "cites",
                                "consult", "ask"}  # fmt: skip
    assert set(coordinator["consult"]["items"]["enum"]) == BINDINGS["investigator"].specialists
    assert set(agent_schemas.SPECIALIST_SCHEMA["properties"]) == {"notes", "cites", "ask"}
    for schema in (llm_prompts.PING_SCHEMA, llm_prompts.ASSESS_V1_SCHEMA,
                   agent_schemas.COORDINATOR_SCHEMA, agent_schemas.SPECIALIST_SCHEMA):  # fmt: skip
        strict(dict(schema))


async def test_a_call_without_a_schema_never_goes_to_a_schema_only_provider(
    privacy: Privacy,
) -> None:
    gw, fake, _, _ = make(config(local(schema_output=True, schema_required=True)))
    with pytest.raises(Refused, match="local: needs a JSON schema"):
        await gw.complete(Call(small(privacy), "x", "ping"))
    with pytest.raises(Refused, match="local: needs a JSON schema"):
        await gw.complete(Call(small(privacy), "x", "ping", json=False,
                               schema=llm_prompts.PING_SCHEMA))  # fmt: skip
    assert fake.sent == []
    await gw.complete(Call(small(privacy), "x", "ping", schema=llm_prompts.PING_SCHEMA))
    assert json.loads(fake.sent[0].body)["response_format"]["type"] == "json_schema"


async def test_the_local_deadline_and_lease_follow_the_prompts_size(privacy: Privacy) -> None:
    deadlines = []
    for size in (40, 20_000):
        gw, fake, _, clock = gateway(shipped())
        assert isinstance(fake, Watching)
        call = ping_call(request(privacy, "Assess I1. " + "x" * size), Tier.SMALL)
        await gw.complete(call)
        wire = fake.sent[0]
        p = gw.config.providers[0]
        model = p.models[Tier.SMALL]
        cap = model.output_cap(call.max_output)
        assert wire.timeout_s == pytest.approx(model.deadline_s(len(wire.body), cap))
        expected = (math.ceil(len(wire.body) / 2) / 45 + cap / 11) * 1.5 + 15
        assert wire.timeout_s == pytest.approx(expected)
        assert wire.timeout_s <= p.timeout_s
        (end,) = fake.leases[0].values()  # the lease: the call's own deadline and a minute
        assert end == clock.now + timedelta(seconds=wire.timeout_s + 60)
        deadlines.append(wire.timeout_s)
    assert deadlines[0] < deadlines[1]
    # a cloud provider without measured speeds keeps its fixed timeout
    gw, fake, _, _ = make(config(cloud(timeout_s=120)))
    await gw.complete(Call(small(privacy), "x", "assess"))
    assert fake.sent[0].timeout_s == 120


async def test_a_call_that_would_outrun_its_time_limit_is_refused_before_sending(
    privacy: Privacy,
) -> None:
    gw, fake, _, clock = gateway(shipped(licence="D-999"))  # Q-G2: after the licence
    clock.now = EVENING
    call = Call(request(privacy, "Assess I1. " + "x" * 22_000), "x", "evaluate", Tier.MEDIUM,
                max_output=2000, schema=llm_prompts.ASSESS_V1_SCHEMA)  # fmt: skip
    p = gw.config.providers[0]
    model = p.models[Tier.MEDIUM]
    assert model.fits(len(body_for(p, call)), model.output_cap(2000))  # it fits the context
    with pytest.raises(Refused, match="local: too slow for its time limit"):
        await gw.complete(call)
    assert fake.sent == []


async def test_a_prompt_above_12000_tokens_is_refused_before_sending(privacy: Privacy) -> None:
    gw, fake, _, _ = gateway(shipped())
    call = ping_call(request(privacy, "Assess I1. " + "x" * 25_000), Tier.SMALL)
    p = gw.config.providers[0]
    size = len(body_for(p, call))
    assert math.ceil(size / 2) + 64 + p.models[Tier.SMALL].output_cap(200) <= 16384
    with pytest.raises(Refused, match="local: too large for its context"):
        await gw.complete(call)
    assert fake.sent == []


async def test_d112s_measured_speed_is_not_slow_but_a_slower_machine_is(privacy: Privacy) -> None:
    """D-112: a 6,624-token prompt took 152 s on the delivered machine, its normal speed."""
    big = request(privacy, "Assess I1. " + "x" * 13_000)  # about 6,600 tokens or more
    normal = answer(prompt=6624, written=20, ms=152_000.0)
    gw, _, _, clock = gateway(shipped(), Watching({"local": [normal]}))
    for _ in range(5):
        done = await gw.complete(ping_call(big, Tier.SMALL))
        assert done.latency_ms == 152_000
        clock.now += timedelta(minutes=3)
    slower = answer(prompt=6624, written=20, ms=152_000.0 * 3)  # 3x: 456 s, 307 s too slow
    gw, _, _, clock = gateway(shipped(), Watching({"local": [slower]}))
    for _ in range(3):
        await gw.complete(ping_call(big, Tier.SMALL))
        clock.now += timedelta(minutes=3)
    with pytest.raises(NoCapacity, match="cooling down") as wait:
        await gw.complete(ping_call(big, Tier.SMALL))
    assert wait.value.until - clock.now <= timedelta(hours=1)


# -- F2 (minor) at most 150 evaluation calls a night, and the local provider gets them -------


async def test_at_most_150_evaluation_calls_a_night(privacy: Privacy) -> None:
    cfg = config(cloud(), evaluation=load_config().evaluation.model_dump(mode="json"))
    gw, _, _, clock = make(cfg)
    clock.now = datetime(2026, 10, 23, 17, 0, tzinfo=UTC)
    sent = 0
    while clock.now < datetime(2026, 10, 24, 2, 0, tzinfo=UTC):
        try:
            await gw.complete(Call(small(privacy), "x", "evaluate"))
            sent += 1
        except NoCapacity:
            pass
        clock.now += timedelta(seconds=55)
    assert sent == 150


async def test_the_shipped_local_provider_gets_150_a_night(privacy: Privacy) -> None:
    gw, _, _, clock = gateway(shipped(licence="D-999"),  # Q-G2: after the licence
                              Watching({"local": [answer(ms=20_000.0)]}))  # fmt: skip
    clock.now = EVENING
    sent = 0
    while clock.now < datetime(2026, 10, 24, 2, 0, tzinfo=UTC):
        try:
            await gw.complete(Call(request(privacy), "x", "evaluate",
                                   schema=llm_prompts.ASSESS_V1_SCHEMA))  # fmt: skip
            sent += 1
        except NoCapacity:
            pass
        clock.now += timedelta(seconds=61)
    assert sent == 150
    # and its own day cap at low priority is not below the evaluation cap
    cfg = load_config()
    p = shipped_local()
    assert p.limits is not None
    assert p.limits.rpd is not None
    low = math.floor(p.limits.rpd * cfg.margin * cfg.shares[budget.Priority.LOW])
    assert low == cfg.evaluation.calls_per_day == 150


# -- F3 (minor) the SIEM's nightly pause, 00:00-01:30 UTC --------------------------------------


def test_the_shipped_evaluation_window_avoids_siems_nightly_pause() -> None:
    window = load_config().evaluation
    for minute in range(90):
        at = datetime(2026, 10, 24, 0, 0, tzinfo=UTC) + timedelta(minutes=minute)
        assert window.opens(at) is not None, f"evaluation calls admitted at {at:%H:%M} UTC"
    assert window.opens(datetime(2026, 10, 23, 23, 59, tzinfo=UTC)) is None
    assert window.opens(EVENING) is None


@pytest.mark.parametrize(
    "window",
    [["17:30", "00:30"], ["00:15", "05:00"], ["23:00", "01:00"], ["12:00", "12:00"],
     ["01:00", "04:00"]],
)  # fmt: skip
def test_a_window_into_the_pause_or_across_midnight_is_refused(window: list[str]) -> None:
    with pytest.raises(ValidationError, match="01:30"):
        config(cloud(), evaluation={"window_utc": window})


def test_a_window_inside_the_day_loads() -> None:
    for window in (["17:30", "00:00"], ["01:30", "05:00"], ["18:00", "23:00"]):
        config(cloud(), evaluation={"window_utc": window})


async def test_gold_runs_with_tools_wait_out_siems_nightly_pause() -> None:
    asked: list[object] = []

    async def fetch(inv: uuid.UUID, version: int, spec: Any) -> dict[str, Any]:
        asked.append(spec)
        return {"status": "ok"}

    now = [datetime(2026, 10, 24, 0, 10, tzinfo=UTC)]
    guarded = agent_eval.outside_siem_pause(fetch, lambda: now[0])
    with pytest.raises(Defer, match="the SIEM's nightly pause") as wait:
        await guarded(uuid.uuid4(), 1, "spec")
    assert wait.value.until == datetime(2026, 10, 24, 1, 30, tzinfo=UTC)
    assert asked == []
    now[0] = datetime(2026, 10, 24, 1, 30, tzinfo=UTC)
    assert await guarded(uuid.uuid4(), 1, "spec") == {"status": "ok"}
    now[0] = datetime(2026, 10, 23, 23, 59, tzinfo=UTC)
    assert await guarded(uuid.uuid4(), 1, "spec") == {"status": "ok"}
    assert asked == ["spec", "spec"]


# -- F4 (minor) stale alarms -----------------------------------------------------------------


async def test_a_probe_that_finds_the_machine_up_clears_its_alarm(privacy: Privacy) -> None:
    bad = TransportError("tls_failed", reached=False, kind="tls_failed")
    fake = Fake({"local": [bad, answer()]})
    gw, fake, store, clock = make(config(local()), fake)
    with pytest.raises(NoCapacity):
        await gw.complete(Call(small(privacy), "x", "ping"))  # an old certificate: an alarm
    assert not llm_doctor.alarms_check(await store.state(), {"local"}).ok
    # the newest hand-over imported; the guide's step 2, `argus llm probe`, finds it up
    result = await probe(gw.config.providers[0], SecretStr("local-abcdef12"), fake)
    assert result.state is ProbeState.UP
    cleared = await store.change(lambda s: budget.probe_up(s, "local", clock.now))
    assert cleared is not None
    assert cleared.kind == "tls_failed"
    clock.now += timedelta(minutes=2)
    assert llm_doctor.alarms_check(await store.state(), {"local"}).ok  # step 1 passes
    done = await gw.complete(Call(small(privacy), "x", "ping"))  # step 3 goes now
    assert done.provider == "local"
    assert await store.change(lambda s: budget.probe_up(s, "local", clock.now)) is None


def test_probe_up_leaves_other_providers_and_model_cool_downs() -> None:
    at = datetime(2026, 10, 16, 12, tzinfo=UTC)
    state = budget.raise_alarm(budget.State(), "local", "unauthorized", "401", at)
    state = budget.raise_alarm(state, "other", "unauthorized", "401", at)
    state = budget.cool_down(state, "local", at + timedelta(hours=1), at)
    state = budget.cool_down(state, "local/cp", at + timedelta(minutes=30), at)
    state = budget.cool_down(state, "other", at + timedelta(hours=1), at)
    cleared, after = budget.probe_up(state, "local", at)
    assert cleared is not None
    assert set(after.alarms) == {"other"}
    assert set(after.cooldowns) == {"local/cp", "other"}  # a slow model stays slow
    assert after.probed["local"] == at


def test_an_alarm_for_a_provider_no_longer_configured_does_not_fail_doctor() -> None:
    at = datetime(2026, 10, 1, tzinfo=UTC)
    state = budget.raise_alarm(budget.State(), "removed", "unauthorized", "refused (401)", at)
    found = llm_doctor.alarms_check(state, {"local"})
    assert found.ok
    assert "removed" in found.detail
    assert "no longer configured" in found.detail
    state = budget.raise_alarm(state, "local", "tls_failed", "not the pinned one", at)
    found = llm_doctor.alarms_check(state, {"local"})
    assert not found.ok
    assert "local: tls_failed" in found.detail


# -- F6 (minor) the pinned certificate file ---------------------------------------------------


def _openssl(*args: str) -> None:
    subprocess.run(["openssl", *args], check=True, capture_output=True)  # noqa: S603, S607


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    base = tmp_path_factory.mktemp("f6")
    base.chmod(0o700)
    leaf = ls.make_certificate(base / "run1")  # the hand-over's certificate
    leaf.parent.chmod(0o700)  # as the import makes data/tls
    other = base / "other"
    other.mkdir(mode=0o700)
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "800", "-subj",
             "/CN=Someone CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign", "-keyout", str(other / "ca.key"),
             "-out", str(other / "ca.crt"))  # fmt: skip
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=not the model machine",
             "-keyout", str(other / "evil.key"), "-out", str(other / "evil.csr"))  # fmt: skip
    ext = other / "ext.cnf"
    ext.write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    _openssl("x509", "-req", "-in", str(other / "evil.csr"), "-CA", str(other / "ca.crt"),
             "-CAkey", str(other / "ca.key"), "-CAcreateserial", "-days", "800",
             "-extfile", str(ext), "-out", str(other / "evil.crt"))  # fmt: skip
    pinned_dir = base / "tls"
    pinned_dir.mkdir(mode=0o700)
    both = pinned_dir / "bundle.crt"
    both.write_bytes(leaf.read_bytes() + (other / "ca.crt").read_bytes())
    both.chmod(0o644)
    v6 = base / "v6"
    v6.mkdir(mode=0o700)
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "800", "-subj",
             "/CN=ARGUS local LLM", "-addext", "subjectAltName=IP:::1",
             "-keyout", str(v6 / "llm.key"), "-out", str(v6 / "llm.crt"))  # fmt: skip
    (v6 / "llm.crt").chmod(0o644)
    leaf.chmod(0o644)
    return {"leaf": leaf, "bundle": both, "evil": other / "evil.crt", "v6": v6 / "llm.crt"}


def ours(port: int, ca: Path, host: str = "127.0.0.1") -> LlmConfig:
    return LlmConfig.model_validate({"providers": [{
        "name": "local", "trust": "self_hosted", "base_url": f"https://{host}:{port}/v1",
        "keys": ["LOCAL_LLM_API_KEY"], "ca_file": str(ca), "timeout_s": 30, "concurrency": 1,
        "tasks": ["evaluate", "ping"], "probe": True,
        "models": {"small": {"name": ls.MODEL}}, "limits": {"rpd": 300}}]})  # fmt: skip


async def test_a_certificate_file_with_more_than_one_certificate_is_never_trusted(
    certs: dict[str, Path],
) -> None:
    machine = ls.Machine()
    with ls.serving(certs["evil"], machine) as port:  # someone else's server, another CA
        cfg = ours(port, certs["bundle"])
        found = llm_doctor.certificate_check(cfg.providers[0], datetime.now(UTC))
        transport = HttpxLlmTransport(cfg)
        try:
            result = await probe(cfg.providers[0], SecretStr(ls.KEY), transport)
        finally:
            await transport.aclose()
    assert found is not None
    assert not found.ok
    assert "holds 2 certificates" in found.detail
    assert result.state is ProbeState.TLS_FAILED
    assert machine.seen == []  # nothing sent, the key least of all


async def test_the_pinned_certificate_alone_still_verifies(certs: dict[str, Path]) -> None:
    machine = ls.Machine()
    with ls.serving(certs["leaf"], machine) as port:
        cfg = ours(port, certs["leaf"])
        found = llm_doctor.certificate_check(cfg.providers[0], datetime.now(UTC))
        transport = HttpxLlmTransport(cfg)
        try:
            result = await probe(cfg.providers[0], SecretStr(ls.KEY), transport)
        finally:
            await transport.aclose()
    assert found is not None
    assert found.ok, found
    assert result.state is ProbeState.UP


def test_doctor_reads_an_ipv6_campus_url(certs: dict[str, Path]) -> None:
    found = llm_doctor.certificate_check(ours(18999, certs["v6"], "[::1]").providers[0],
                                         datetime.now(UTC))  # fmt: skip
    assert found is not None
    assert found.ok, found
    assert "for ::1" in found.detail
    other = llm_doctor.certificate_check(ours(18999, certs["leaf"], "[::1]").providers[0],
                                         datetime.now(UTC))  # fmt: skip
    assert other is not None
    assert not other.ok
    assert "does not name ::1" in other.detail


def test_doctor_fails_a_certificate_others_could_replace(
    certs: dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    cert = shared / "llm.crt"
    cert.write_bytes(certs["leaf"].read_bytes())
    cert.chmod(0o644)
    found = llm_doctor.certificate_check(ours(1, cert).providers[0], datetime.now(UTC))
    assert found is not None
    assert not found.ok
    assert "folder is writable by others" in found.detail
    shared.chmod(0o700)
    found = llm_doctor.certificate_check(ours(1, cert).providers[0], datetime.now(UTC))
    assert found is not None
    assert found.ok, found
    uid = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: uid + 1)
    found = llm_doctor.certificate_check(ours(1, cert).providers[0], datetime.now(UTC))
    assert found is not None
    assert not found.ok
    assert "owned by another account" in found.detail


# -- F7 (minor) a window with a UTC offset ---------------------------------------------------


@pytest.mark.parametrize("window", [["17:30+00:00", "23:30+00:00"], ["17:30+05:30", "23:00"]])
def test_a_window_with_an_offset_is_refused_at_load(window: list[str]) -> None:
    with pytest.raises(ValidationError, match="UTC times without an offset"):
        config(cloud(), evaluation={"window_utc": window})


# -- F8 (minor) per-model breakers: the provider's trial --------------------------------------


@pytest.mark.parametrize("trial", [LlmReply(500, b"", 1.0), LlmReply(429, b"", 1.0),
                                   LlmReply(400, b"{}", 1.0)])  # fmt: skip
async def test_a_models_failure_on_the_providers_trial_does_not_hold_its_sibling(
    privacy: Privacy, trial: LlmReply
) -> None:
    fake = Fake({"cloud": [TransportError("ConnectError", reached=False), trial, answer()]})
    gw, fake, _, clock = make(config(cloud()), fake)
    with pytest.raises(NoCapacity):
        await gw.complete(Call(small(privacy), "x", "assess", Tier.SMALL))  # no connection
    clock.now += timedelta(minutes=5, seconds=1)
    with pytest.raises((NoCapacity, Refused)):
        await gw.complete(Call(small(privacy), "x", "assess", Tier.SMALL))  # small's failure
    clock.now += timedelta(seconds=5)
    done = await gw.complete(Call(small(privacy), "x", "assess", Tier.MEDIUM))  # the sibling
    assert done.model == "c-medium"
