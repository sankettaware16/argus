"""The robustness drill and the hardening check, from ARGUS's side.

``hardening`` asks the machine, through the tunnel, what its setup must refuse (a wrong key,
llama-server's own pages). ``drill`` sends one synthetic call per case, each with ARGUS's side
changed to make a fault: port closed, over-long prompt, short deadline, wrong model, changed
certificate, wrong key, crashed lease holder. Each must defer within an hour, never answer, never
be benign; a control call first must answer. Every case runs on its own in-memory gateway.
"""

from __future__ import annotations

import hashlib
import socket
import tempfile
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import SecretStr

from argus import site
from argus.evaluation import ladder
from argus.evaluation.harness import BENIGN
from argus.llm import budget
from argus.llm import prompts as llm_prompts
from argus.llm.detect import OwnSpace
from argus.llm.gateway import Call, LlmGateway, MemoryLlmStore, NoCapacity, Refused
from argus.llm.privacy import Request
from argus.llm.probe import ProbeState, probe
from argus.llm.providers import LlmConfig, ProviderConfig, Tier
from argus.llm.wire import LlmTransport, LlmWire, TransportError

DRILL_TEXT = (
    "Robustness drill from ARGUS: a synthetic item with no {noun} data. A documentation host"
    " asked example.org for three pages and every answer was 404. Nothing else happened."
)
# An over-long prompt in any tokenizer: single digits apart, about one token each (the
# context is 16,384 tokens; this is about 40,000).
OVERFLOW_TEXT = " ".join(str(i % 10) for i in range(40_000))
SLOW_DEADLINE_S = 1.0  # short enough that any model times out on the drill's prompt
WRONG_KEY = SecretStr("argus-drill-not-the-key")
ABSENT_MODEL = "argus-drill-absent-model"
CASES = tuple(ladder.CASES)
ON_THE_MACHINE = tuple(c for c in CASES if c not in ladder.STAND_IN_ONLY)

TransportFor = Callable[[LlmConfig], LlmTransport]
Hook = Callable[[str], AbstractAsyncContextManager[None]]


@asynccontextmanager
async def _nothing(case: str) -> AsyncIterator[None]:
    yield


def drill_call(ours: OwnSpace, text: str | None = None, **over: Any) -> Call:
    """The drill's call: a synthetic item, ``assess@1``'s prompt and strict schema, as a
    connection test (``ping``: no evaluation window, no real data)."""
    request = Request(site.say(DRILL_TEXT) if text is None else text, (), (), (), (), ours)
    instructions = llm_prompts.PROMPTS[llm_prompts.ASSESS_V1]
    return Call(request, instructions, "ping", Tier.SMALL, budget.Priority.HIGH,
                max_output=200, schema=llm_prompts.ASSESS_V1_SCHEMA, **over)  # fmt: skip


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def other_certificate(folder: Path) -> Path:
    """A file holding one certificate that is not the machine's: the first root of the
    default store (no key, nothing secret), as a new setup run's certificate would be."""
    import certifi

    bundle = Path(certifi.where()).read_text(encoding="ascii")
    end = "-----END CERTIFICATE-----"
    first = bundle[bundle.index("-----BEGIN CERTIFICATE-----") : bundle.index(end) + len(end)]
    path = folder / "other.crt"
    path.write_text(first + "\n", encoding="ascii")
    return path


def setup_of(provider: ProviderConfig) -> dict[str, str | None]:
    """Which setup of the machine a drill checked: its address and the SHA-256 of the
    certificate ARGUS pins (every setup run makes a new certificate), so a drill of an
    earlier setup is not taken for this one. Nothing secret: the key is never in it."""
    path = provider.ca_path()
    digest = None
    if path is not None:
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            digest = None
    return {"base_url": provider.base_url, "certificate_sha256": digest}


@dataclass
class Drill:
    provider: str
    model: str
    hardening: dict[str, bool] = field(default_factory=dict)
    cases: dict[str, ladder.Case] = field(default_factory=dict)
    ledger: list[dict[str, Any]] = field(default_factory=list)  # case, outcome, status
    setup: dict[str, str | None] = field(default_factory=dict)  # setup_of the provider

    def as_json(self, at: datetime) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "setup": self.setup,
            "at": at.isoformat(),
            "hardening": self.hardening,
            "cases": {k: v.model_dump() for k, v in self.cases.items()},
            "ledger": self.ledger,
        }


async def _status(transport: LlmTransport, method: str, wire: LlmWire, key: SecretStr) -> int:
    """The HTTP status, or 0 for no answer."""
    try:
        reply = await (transport.send if method == "POST" else transport.get)(wire, key)
    except TransportError:
        return 0
    return reply.status


async def hardening(
    provider: ProviderConfig, key: SecretStr, transport: LlmTransport, timeout_s: float = 15.0
) -> dict[str, bool]:
    """The machine's protections, as ARGUS sees them. No prompt is sent; no answer means "cannot
    tell", which fails the check."""
    base = provider.base_url
    root = base.removesuffix("/v1")
    name = provider.name
    out: dict[str, bool] = {}
    unkeyed = (
        ("models_without_key", "GET", f"{base}/models"),
        ("chat_without_key", "POST", f"{base}/chat/completions"),
    )
    for check, method, url in unkeyed:
        status = await _status(transport, method, LlmWire(name, url, b"{}", timeout_s), WRONG_KEY)
        out[check] = status in (401, 403)
    for page in ("slots", "props", "health", "metrics"):
        wire = LlmWire(name, f"{root}/{page}", b"", timeout_s)
        status = await _status(transport, "GET", wire, key)
        out[f"{page}_refused"] = status >= 300 or 0 < status < 200
    out["models_with_key"] = (await probe(provider, key, transport)).state is ProbeState.UP
    return out


def _case_config(base: LlmConfig, provider: ProviderConfig, folder: Path, case: str) -> LlmConfig:
    """``provider`` changed on ARGUS's side to make ``case``'s fault."""
    update: dict[str, Any] = {}
    if case == "off":
        update["base_url"] = f"https://127.0.0.1:{_free_port()}/v1"
    elif case == "overflow":  # lift ARGUS's own refusal, so the machine's 400 is seen
        update["models"] = {t: m.model_copy(update={
            "context_tokens": None, "max_prompt_tokens": None, "read_tps": None,
            "write_tps": None}) for t, m in provider.models.items()}  # fmt: skip
    elif case == "wrong_model":
        update["models"] = {t: m.model_copy(update={"name": ABSENT_MODEL})
                            for t, m in provider.models.items()}  # fmt: skip
    elif case == "changed_certificate":
        update["ca_file"] = other_certificate(folder)
    changed = provider.model_copy(update={"enabled": True, **update})
    return base.model_copy(update={"providers": (changed,)})


def _classify(case: str, result: Any, now: datetime) -> ladder.Case:
    if isinstance(result, NoCapacity):
        wait = max(0.0, (result.until - now).total_seconds())
        return ladder.Case(outcome="deferred", wait_s=round(wait, 1), detail=str(result)[:300])
    if isinstance(result, Refused):
        return ladder.Case(outcome="no_proposal", detail=str(result)[:300])
    if isinstance(result, BaseException):
        return ladder.Case(outcome="error", detail=f"{type(result).__name__}: {result}"[:300])
    outcome = llm_prompts.parse(result.text).outcome
    benign = outcome in BENIGN and case != "control"
    return ladder.Case(outcome="benign" if benign else "answered", detail=f"answered {outcome}")


async def drill(
    config: LlmConfig,
    keys: Mapping[str, SecretStr],
    ours: OwnSpace,
    transport_for: TransportFor,
    cases: Sequence[str] = ON_THE_MACHINE,
    hook: Hook = _nothing,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    check_hardening: bool = True,
) -> Drill:
    """The drill against ``config``'s only provider (``pinned``)."""
    (provider,) = config.providers
    key = next((keys[k] for k in provider.keys if k in keys), None)
    if key is None:
        raise ValueError(f"{provider.name}: no key")
    model = provider.models[Tier.SMALL].name
    out = Drill(provider.name, model, setup=setup_of(provider))
    if check_hardening:
        transport = transport_for(config)
        try:
            out.hardening = await hardening(provider, key, transport)
        finally:
            await _close(transport)
    with tempfile.TemporaryDirectory(prefix="argus-drill-") as tmp:
        for case in ("control", *cases):
            async with hook(case):
                out.cases[case] = await _one(config, provider, keys, key, ours, transport_for,
                                             Path(tmp), case, clock, out.ledger)  # fmt: skip
    for case in CASES:
        out.cases.setdefault(case, ladder.Case(
            outcome="skipped", detail="the machine's own state: covered by the stand-in's tests"
        ))  # fmt: skip
    return out


async def _close(transport: LlmTransport) -> None:
    close: Callable[[], Awaitable[None]] | None = getattr(transport, "aclose", None)
    if close is not None:
        await close()


async def _one(
    config: LlmConfig,
    provider: ProviderConfig,
    keys: Mapping[str, SecretStr],
    key: SecretStr,
    ours: OwnSpace,
    transport_for: TransportFor,
    folder: Path,
    case: str,
    clock: Callable[[], datetime],
    ledger: list[dict[str, Any]],
) -> ladder.Case:
    cfg = config if case == "control" else _case_config(config, provider, folder, case)
    chosen = cfg.providers[0]
    case_keys = dict(keys)
    if case == "wrong_key":
        case_keys = dict.fromkeys(provider.keys, WRONG_KEY)
    store = MemoryLlmStore()
    if case == "crashed_lease" and chosen.concurrency is not None:
        now = clock()
        until = now + chosen.lease_for(chosen.timeout_s)

        def crashed(s: budget.State) -> tuple[None, budget.State]:
            for n in range(chosen.concurrency or 1):
                _, s = budget.lease(s, chosen.name, f"crashed-{n}", chosen.concurrency or 1,
                                    now, until)  # fmt: skip
            return None, s

        await store.change(crashed)
    call = drill_call(ours, OVERFLOW_TEXT if case == "overflow" else None,
                      timeout_s=SLOW_DEADLINE_S if case == "slow" else None)  # fmt: skip
    transport = transport_for(cfg)
    gateway = LlmGateway(cfg, case_keys, transport, store, clock)
    result: Any
    try:
        result = await gateway.complete(call)
    except (NoCapacity, Refused) as exc:
        result = exc
    except Exception as exc:  # a drill reports, it does not crash
        result = exc
    finally:
        await _close(transport)
    ledger += [{"case": case, "outcome": e.outcome, "http_status": e.http_status,
                "latency_ms": e.latency_ms} for e in store.ledger]  # fmt: skip
    return _classify(case, result, clock())
