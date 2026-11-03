"""Sending an LLM call: the only code that opens a connection to a model provider (P5, Q-G1).

``HttpxLlmTransport`` holds one client per configured provider. A provider with a ``ca_file``
trusts that certificate and no other (the local model's self-signed certificate, D-108); the
others trust the default store. It posts an OpenAI-compatible chat body (or asks
``GET /v1/models``, the probe) to the provider's base URL over TLS, with the key in a header
only, never through a proxy and never following a redirect, within one deadline for the whole
exchange and a cap on the answer's size. It does not retry. A certificate that does not verify
is ``TransportError(kind="tls_failed")``.

``LlmCassette`` records and replays answers keyed by provider, path and body. A cassette holds
what was sent (already pseudonymized and validated) and what came back, never a key; replay is
strict, a miss raises and nothing is sent.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import ssl
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from pydantic import SecretStr

from argus.gateway.transport import pinned_context
from argus.llm.providers import LlmConfig, ProviderConfig

MAX_ANSWER_BYTES = 1024 * 1024
FORMAT = 1


@dataclass(frozen=True)
class LlmWire:
    provider: str
    url: str  # base_url + "/chat/completions" (or "/models" for a probe, with no body)
    body: bytes
    timeout_s: float


@dataclass(frozen=True)
class LlmReply:
    status: int
    body: bytes
    elapsed_ms: float
    retry_after: str | None = None


class LlmTransport(Protocol):
    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply: ...

    async def get(self, wire: LlmWire, key: SecretStr) -> LlmReply: ...


class TransportError(Exception):
    """No answer: a timeout, a refused connection, a certificate that does not verify, or an
    answer too large. ``reached``: whether the request got to the provider at all (a refused
    or timed-out connection, or a failed TLS handshake, did not, so it cannot have been
    charged, D-096). ``kind``: "tls_failed" for a certificate, else "no_answer"."""

    def __init__(self, message: str, *, reached: bool = True, kind: str = "no_answer") -> None:
        super().__init__(message)
        self.reached = reached
        self.kind = kind


def _tls_failure(exc: BaseException) -> bool:
    """Whether an httpx error is a certificate that does not verify (not the pinned one, or
    not for this host). A handshake cut short is not: through the tunnel that is a machine
    that is off (the SSH listener accepts and closes), which is "no answer"."""
    seen: set[int] = set()
    cause: BaseException | None = exc
    while cause is not None and id(cause) not in seen:
        if isinstance(cause, ssl.SSLCertVerificationError):
            return True
        seen.add(id(cause))
        cause = cause.__cause__ or cause.__context__
    return False


def pem_blocks(data: bytes) -> tuple[int, int]:
    """(PEM blocks, certificates among them) in a certificate file."""
    return data.count(b"-----BEGIN "), data.count(b"-----BEGIN CERTIFICATE-----")


def ssl_context(provider: ProviderConfig) -> ssl.SSLContext | bool:
    """The provider's trust: its own certificate only, or the default store (True). A pinned
    file must hold exactly that one certificate: every certificate in it would be trusted."""
    ca = provider.ca_path()
    if ca is None:
        return True
    blocks, certificates = pem_blocks(ca.read_bytes())
    if blocks != 1 or certificates != 1:
        raise ssl.SSLError(f"the pinned file holds {blocks} PEM blocks, not one certificate")
    return pinned_context(ca)


def _client_for(provider: ProviderConfig) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        verify=ssl_context(provider),
        follow_redirects=False,
        trust_env=False,  # no proxy or certificate settings from the environment
        timeout=httpx.Timeout(provider.timeout_s),
    )


class HttpxLlmTransport:
    """One client per provider of ``config``: each with its own trust, never a proxy."""

    def __init__(
        self, config: LlmConfig, clients: Mapping[str, httpx.AsyncClient] | None = None
    ) -> None:
        self._unusable: dict[str, str] = {}  # provider: why its trust could not be set up
        if clients is not None:
            self._clients = dict(clients)
            return
        self._clients = {}
        for p in config.providers:
            try:
                self._clients[p.name] = _client_for(p)
            except (OSError, ssl.SSLError) as exc:  # a missing or unreadable certificate file
                self._unusable[p.name] = (
                    f"its certificate file cannot be used ({type(exc).__name__})"
                )

    async def aclose(self) -> None:
        for client in self._clients.values():
            await client.aclose()

    def _client(self, wire: LlmWire) -> httpx.AsyncClient:
        client = self._clients.get(wire.provider)
        if client is None:  # never the default trust instead of a provider's own
            why = self._unusable.get(wire.provider)
            if why is not None:
                raise TransportError(why, reached=False, kind="tls_failed")
            raise TransportError(f"no client for provider {wire.provider!r}", reached=False)
        return client

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        return await self._exchange("POST", wire, key)

    async def get(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        return await self._exchange("GET", wire, key)

    async def _exchange(self, method: str, wire: LlmWire, key: SecretStr) -> LlmReply:
        client = self._client(wire)
        start = time.monotonic()
        headers = {"Authorization": f"Bearer {key.get_secret_value()}"}
        if method == "POST":
            headers["Content-Type"] = "application/json"
        try:
            async with (
                asyncio.timeout(wire.timeout_s),  # one deadline for the whole exchange
                client.stream(
                    method, wire.url, content=wire.body if method == "POST" else None,
                    headers=headers, timeout=httpx.Timeout(wire.timeout_s),
                ) as response,
            ):  # fmt: skip
                chunks = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > MAX_ANSWER_BYTES:
                        raise TransportError("answer too large")
                    chunks.append(chunk)
                return LlmReply(
                    response.status_code,
                    b"".join(chunks),
                    (time.monotonic() - start) * 1000,
                    response.headers.get("retry-after"),
                )
        except TimeoutError:
            raise TransportError("deadline") from None
        except (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout) as exc:
            if _tls_failure(exc):
                raise TransportError("tls_failed", reached=False, kind="tls_failed") from None
            raise TransportError(type(exc).__name__, reached=False) from None
        except httpx.HTTPError as exc:
            raise TransportError(type(exc).__name__) from None


class CassetteMiss(Exception):  # noqa: N818 - a test outcome
    pass


def cassette_key(wire: LlmWire, method: str = "POST") -> str:
    parts: list[Any] = [FORMAT, wire.provider, wire.url]
    parts += [json.loads(wire.body)] if method == "POST" else [None, method]
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass
class LlmCassette:
    path: Path
    mode: Literal["replay", "record"] = "replay"
    inner: LlmTransport | None = None
    entries: dict[str, dict[str, Any]] = field(default_factory=dict)
    changed: bool = False

    def __post_init__(self) -> None:
        if self.mode == "record" and self.inner is None:
            raise ValueError("recording needs a transport to record from")
        if self.path.is_file():
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data.get("format") != FORMAT:
                raise ValueError(f"{self.path}: cassette format {data.get('format')}")
            self.entries = data["entries"]
        elif self.mode == "replay":
            raise FileNotFoundError(f"no cassette {self.path}")

    async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        return await self._play("POST", wire, key)

    async def get(self, wire: LlmWire, key: SecretStr) -> LlmReply:
        return await self._play("GET", wire, key)

    async def _play(self, method: str, wire: LlmWire, key: SecretStr) -> LlmReply:
        k = cassette_key(wire, method)
        if self.mode == "replay":
            entry = self.entries.get(k)
            if entry is None:
                raise CassetteMiss(f"{wire.provider}: no recorded answer for this call")
            return LlmReply(
                entry["status"], entry["body"].encode(), entry["elapsed_ms"],
                entry.get("retry_after"),
            )  # fmt: skip
        assert self.inner is not None
        inner = self.inner.send if method == "POST" else self.inner.get
        reply = await inner(wire, key)
        self.entries[k] = {
            "provider": wire.provider,
            "status": reply.status,
            "body": reply.body.decode("utf-8", "replace"),
            "elapsed_ms": round(reply.elapsed_ms, 1),
            "retry_after": reply.retry_after,
        }
        self.changed = True
        return reply

    def save(self) -> None:
        """Write the recording atomically (mode 0600); replay never writes."""
        if self.mode != "record" or not self.changed:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        payload = json.dumps({"format": FORMAT, "entries": self.entries}, indent=1, sort_keys=True)
        descriptor, name = tempfile.mkstemp(prefix=".cassette-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(name, self.path)
        except BaseException:
            Path(name).unlink(missing_ok=True)
            raise
        self.changed = False
