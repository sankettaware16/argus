"""Sending a validated request: the only code that opens a connection to Elasticsearch.

``HttpxTransport`` talks to the SIEM (or the es-local replica) over TLS with the pinned CA
and an API key, never through a proxy, never following redirects, with one deadline
for the whole exchange and a cap on the answer's size. It does not retry: the gateway decides.
"""

from __future__ import annotations

import asyncio
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, assert_never
from urllib.parse import quote

import httpx
from pydantic import SecretStr

from argus.gateway.errors import ResponseError, TimedOutError, TransportFailedError
from argus.gateway.templates import Endpoint
from argus.gateway.validator import FinalRequest

MAX_RESPONSE_BYTES = 32 * 1024 * 1024
NODE_STATS_PATH = "/_nodes/_local/stats/fs,jvm,os,thread_pool,breaker"
# index.uuid makes every existing index answer: Elasticsearch leaves out an index with no
# matching setting, so blocks alone cannot tell "not blocked" from "not there".
BLOCKS_SETTINGS = "index.blocks.*,index.uuid"
# The security index's health: the check before a 401 counts as a refusal.
SECURITY_HEALTH_PATH = "/_cluster/health/.security"


@dataclass(frozen=True)
class WireRequest:
    method: str
    path: str
    params: tuple[tuple[str, str], ...]
    body: bytes | None
    opaque_id: str
    timeout_s: float


@dataclass(frozen=True)
class WireResponse:
    status: int
    body: bytes
    elapsed_ms: float


class Transport(Protocol):
    async def send(self, request: WireRequest) -> WireResponse: ...


def _names(names: tuple[str, ...]) -> str:
    return quote(",".join(names), safe=",.-_+*")  # only a TI source is a pattern


def wire_path(request: FinalRequest) -> tuple[str, str]:
    """(method, path) for a validated request; the gateway alone builds paths. Exhaustive: every
    endpoint has its own case, and one that has none is an error, never a fallback."""
    endpoint = request.spec.endpoint
    match endpoint:
        case Endpoint.INFO:
            return "GET", "/"
        case Endpoint.SEARCH:
            return "POST", f"/{_names(request.indices)}/_search"
        case Endpoint.MGET:
            return "POST", f"/{_names(request.indices)}/_mget"
        case Endpoint.NODE_STATS:
            return "GET", NODE_STATS_PATH
        case Endpoint.INDEX_BLOCKS:
            return "GET", f"/{_names(request.indices)}/_settings/{BLOCKS_SETTINGS}"
        case Endpoint.RESOLVE_INDEX:
            assert request.pattern is not None  # the validator checked it
            return "GET", f"/_resolve/index/{quote(request.pattern, safe='.-_+*')}"
        case Endpoint.AUTHENTICATE:
            return "GET", "/_security/_authenticate"
        case Endpoint.HAS_PRIVILEGES:
            return "POST", "/_security/user/_has_privileges"
        case Endpoint.LICENSE:
            return "GET", "/_license"
        case Endpoint.SECURITY_HEALTH:
            return "GET", SECURITY_HEALTH_PATH
        case Endpoint.DISCOVER_INDICES:
            assert request.pattern is not None  # the validator checked it
            return "GET", f"/_resolve/index/{quote(request.pattern, safe='.-_+*')}"
        case Endpoint.FIELD_MAPPING:
            assert request.pattern is not None  # the validator checked it: the fields
            fields = quote(request.pattern, safe=",.-_+@")
            return "GET", f"/{_names(request.indices)}/_mapping/field/{fields}"
        case Endpoint.ILM_POLICIES:
            return "GET", "/_ilm/policy"
        case _:  # pragma: no cover - mypy proves every member is handled
            assert_never(endpoint)


def pinned_context(ca_file: Path) -> ssl.SSLContext:
    """Verify the server against this CA only: CERT_REQUIRED, hostname checked, TLS ≥ 1.2."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(ca_file))
    return context


@dataclass(frozen=True)
class CaSummary:
    subject: str
    not_after: datetime


def ca_summary(ca_file: Path) -> CaSummary:
    """The pinned CA's subject and expiry (the first certificate of the file). Raises
    ValueError if it is missing or not a certificate."""
    if not ca_file.is_file():
        raise ValueError(f"{ca_file} does not exist")
    try:
        decoded = ssl._ssl._test_decode_cert(str(ca_file))  # type: ignore[attr-defined]
    except (ssl.SSLError, OSError):
        raise ValueError(f"{ca_file} is not a PEM certificate") from None
    names = [
        value for rdn in decoded.get("subject", ()) for key, value in rdn if key == "commonName"
    ]
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC)
    return CaSummary(names[0] if names else "(no common name)", not_after)


class HttpxTransport:
    def __init__(
        self,
        base_url: str,
        context: ssl.SSLContext,
        api_key: SecretStr,
        *,
        max_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("the SIEM is reached over https only")
        self.max_bytes = max_bytes
        self._auth = f"ApiKey {api_key.get_secret_value()}"
        self.client = httpx.AsyncClient(
            base_url=base_url,
            verify=context,
            trust_env=False,  # no proxy or certificate settings from the environment
            follow_redirects=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def send(self, request: WireRequest) -> WireResponse:
        headers = {
            "Authorization": self._auth,
            "Accept": "application/json",
            "X-Opaque-Id": request.opaque_id,
        }
        if request.body is not None:
            headers["Content-Type"] = "application/json"
        started = time.monotonic()
        try:
            async with (
                asyncio.timeout(request.timeout_s),
                self.client.stream(
                    request.method,
                    request.path,
                    params=list(request.params),
                    content=request.body,
                    headers=headers,
                    timeout=httpx.Timeout(request.timeout_s),
                ) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():  # decoded: the cap holds after gzip
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise ResponseError(f"the answer is larger than {self.max_bytes} bytes")
                    chunks.append(chunk)
                status = response.status_code
        except (httpx.ConnectTimeout, httpx.PoolTimeout):  # never reached the SIEM
            raise TimedOutError("no connection before the deadline", reached=False) from None
        except (httpx.TimeoutException, TimeoutError):
            raise TimedOutError() from None
        except httpx.ConnectError:  # refused, no route: never reached the SIEM
            raise TransportFailedError("connection failed", retriable=True, reached=False) from None
        except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError):
            raise TransportFailedError("connection failed or reset", retriable=True) from None
        except httpx.HTTPError as exc:
            raise TransportFailedError(type(exc).__name__, retriable=False) from None
        return WireResponse(status, b"".join(chunks), (time.monotonic() - started) * 1000)
