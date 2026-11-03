"""The identity lane's own transport: the only code that sends a person's credential.

It holds no credential of its own: each call is given the person's ``Authorization`` header, which
goes into that one request and nowhere else (never a client default, a log line or the ledger).
Two routes only (``_authenticate``, ``_has_privileges``); HTTPS with the pinned CA, no proxy, no
redirects, 3 s to connect and 5 s in all, answers capped at 256 KB. Failures are the gateway's typed
errors, with ``reached`` saying whether the SIEM may have done any work.
"""

from __future__ import annotations

import asyncio
import base64
import ssl
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

import httpx
from pydantic import SecretStr

from argus.gateway.errors import ResponseError, TimedOutError, TransportFailedError
from argus.gateway.transport import WireResponse
from argus.identity.names import Credential

MAX_ANSWER_BYTES = 256 * 1024
CONNECT_TIMEOUT_S = 3.0
TOTAL_TIMEOUT_S = 5.0
OPAQUE_ID = "argus-identity"  # never the person's name


class Route(StrEnum):
    WHOAMI = "whoami"
    VERIFY = "verify"


ROUTES: dict[Route, tuple[str, str]] = {
    Route.WHOAMI: ("GET", "/_security/_authenticate"),
    Route.VERIFY: ("POST", "/_security/user/_has_privileges"),
}


@dataclass(frozen=True)
class IdentityRequest:
    route: Route
    body: bytes | None
    timeout_s: float

    def __post_init__(self) -> None:
        if (self.route is Route.VERIFY) != (self.body is not None):
            raise ValueError("only the privileges check has a body")
        if not 0 < self.timeout_s <= TOTAL_TIMEOUT_S:
            raise ValueError(f"an identity call takes at most {TOTAL_TIMEOUT_S:.0f} s")


def authorization(credential: Credential) -> SecretStr:
    """The Basic ``Authorization`` value for one request (RFC 7617, UTF-8)."""
    raw = f"{credential.username}:{credential.password.get_secret_value()}".encode()
    return SecretStr("Basic " + base64.b64encode(raw).decode("ascii"))


class IdentityTransport(Protocol):
    async def send(self, request: IdentityRequest, auth: SecretStr) -> WireResponse: ...


class HttpxIdentityTransport:
    """The identity lane's HTTPS client to Elasticsearch."""

    def __init__(
        self,
        base_url: str,
        context: ssl.SSLContext,
        *,
        connect_timeout_s: float = CONNECT_TIMEOUT_S,
        total_timeout_s: float = TOTAL_TIMEOUT_S,
        max_bytes: int = MAX_ANSWER_BYTES,
    ) -> None:
        if not base_url.startswith("https://"):
            raise ValueError("a credential is sent over https only")
        if not 0 < connect_timeout_s <= total_timeout_s <= TOTAL_TIMEOUT_S:
            raise ValueError("connect within the total, the total within 5 s")
        self.connect_timeout_s = connect_timeout_s
        self.total_timeout_s = total_timeout_s
        self.max_bytes = max_bytes
        self.client = httpx.AsyncClient(
            base_url=base_url,
            verify=context,
            trust_env=False,  # no proxy, netrc or certificate settings from the environment
            follow_redirects=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def send(self, request: IdentityRequest, auth: SecretStr) -> WireResponse:
        method, path = ROUTES[request.route]
        headers = {
            "Authorization": auth.get_secret_value(),
            "Accept": "application/json",
            "X-Opaque-Id": OPAQUE_ID,
        }
        if request.body is not None:
            headers["Content-Type"] = "application/json"
        total = min(request.timeout_s, self.total_timeout_s)
        timeout = httpx.Timeout(total, connect=min(self.connect_timeout_s, total))
        started = time.monotonic()
        try:
            async with (
                asyncio.timeout(total),
                self.client.stream(
                    method, path, content=request.body, headers=headers, timeout=timeout
                ) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise ResponseError(f"the answer is larger than {self.max_bytes} bytes")
                    chunks.append(chunk)
                status = response.status_code
        except (httpx.ConnectTimeout, httpx.PoolTimeout):
            raise TimedOutError("no connection before the deadline", reached=False) from None
        except (httpx.TimeoutException, TimeoutError):
            raise TimedOutError() from None
        except httpx.ConnectError:
            raise TransportFailedError(
                "connection failed", retriable=False, reached=False
            ) from None
        except (httpx.ReadError, httpx.WriteError, httpx.RemoteProtocolError):
            raise TransportFailedError("connection failed or reset", retriable=False) from None
        except httpx.HTTPError as exc:
            raise TransportFailedError(type(exc).__name__, retriable=False) from None
        return WireResponse(status, b"".join(chunks), (time.monotonic() - started) * 1000)
