"""Sending a validated Kibana lane request: the only code that opens a connection to Kibana
(and, for Kibana keys' self-test, to Elasticsearch with a Kibana key).

``HttpxKibanaTransport``: HTTPS only, the pinned CA (DQ2 (a)), never through a proxy, never
following a redirect, Kibana's ``server.basePath`` (if the admin set one) put before every
checked path, one deadline for the exchange (15 s by default), a cap on the answer's
size, ``kbn-xsrf`` on every Kibana request (a write needs it; a read ignores it). Before
sending it holds the request to an allowlist (``wire_refusal``): a Kibana route must be one
``paths.wire_path`` builds (and pass ``paths.refusal``), an Elasticsearch route one of the key
self-checks, so even a request that bypassed the validator never deletes, pushes, reaches
``/internal/`` or any other route of the space; and a request whose key is not installed is
refused (``refusal``, which the gateway asks before a write takes its place in the caps). It
never retries: the gateway decides, and a write is never sent twice (plan §3 rule 4).
"""

from __future__ import annotations

import asyncio
import re
import ssl
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, Protocol

import httpx
from pydantic import SecretStr

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana.errors import KibanaResponseError, UnknownOutcomeError
from argus.gateway.kibana.paths import (
    TEAM_ENDPOINTS,
    TEAM_ONLY_ENDPOINTS,
    built,
    endpoint_of,
    refusal,
)
from argus.gateway.kibana.templates import KeyRole

MAX_RESPONSE_BYTES = 8 * 1024 * 1024
BASE_PATH = re.compile(r"(/[a-z0-9_-]{1,32}){0,3}")
XSRF = "argus"
# The only Elasticsearch routes a Kibana key is sent to: its own identity and privileges.
ES_ROUTES = frozenset(
    {("GET", "/_security/_authenticate"), ("POST", "/_security/user/_has_privileges")}
)


@dataclass(frozen=True)
class KWire:
    target: Literal["kibana", "es"]
    key: KeyRole
    method: str
    path: str
    params: tuple[tuple[str, str], ...]
    body: bytes | None
    opaque_id: str
    timeout_s: float
    as_user: str | None = None  # the case team: whose key sends it (KeyRole.TEAM)
    content_type: str = "application/json"


@dataclass(frozen=True)
class KResponse:
    status: int
    body: bytes
    elapsed_ms: float
    date: str | None = None  # Kibana's Date header (Q-D3 measures the clock offset)


class KibanaTransport(Protocol):
    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        """The error this transport would refuse ``request`` with, sending nothing; or None."""

    async def send(self, request: KWire) -> KResponse: ...


def wire_refusal(request: KWire, space: str) -> str | None:
    """Why a request never leaves, or None: the allowlist of the transport."""
    if request.target == "es":
        return None if (request.method, request.path) in ES_ROUTES else "not a key self-check"
    why = refusal(request.method, request.path, space)
    if why is None and not built(request.method, request.path, space):
        why = "a route ARGUS never builds"
    if why is None:
        endpoint = endpoint_of(request.method, request.path, space)
        if request.key is KeyRole.TEAM and endpoint not in TEAM_ENDPOINTS:
            why = "the case team's keys send only the incident case's own writes"
        elif request.key is not KeyRole.TEAM and endpoint in TEAM_ONLY_ENDPOINTS:
            why = "files and alert tags are the case team's alone"
    return why


class HttpxKibanaTransport:
    def __init__(
        self,
        kibana_url: str,
        es_url: str,
        context: ssl.SSLContext,
        keys: Mapping[KeyRole, SecretStr],
        *,
        space: str,
        base_path: str = "",
        max_bytes: int = MAX_RESPONSE_BYTES,
        team_keys: Mapping[str, SecretStr] | None = None,
    ) -> None:
        for url in (kibana_url, es_url):
            if not url.startswith("https://"):
                raise ValueError("Kibana and Elasticsearch are reached over https only")
        if not BASE_PATH.fullmatch(base_path):
            raise ValueError("Kibana's base path is empty or /name, at most three parts")
        self.space = space
        self.base_path = base_path  # Kibana's server.basePath (the admin's Q1 answer)
        self.max_bytes = max_bytes
        self._auth = {role: f"ApiKey {key.get_secret_value()}" for role, key in keys.items()}
        # the case team's six users: one key each, picked by the request's author (AR8)
        self._team = {
            user: f"ApiKey {key.get_secret_value()}" for user, key in (team_keys or {}).items()
        }
        self.clients = {
            target: httpx.AsyncClient(
                base_url=url,
                verify=context,
                trust_env=False,  # no proxy or certificate settings from the environment
                follow_redirects=False,
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
            )
            for target, url in (("kibana", kibana_url), ("es", es_url))
        }

    async def aclose(self) -> None:
        for client in self.clients.values():
            await client.aclose()

    def refusal(self, request: KWire) -> TemplateRejectedError | None:
        why = wire_refusal(request, self.space)
        if why is not None:
            return TemplateRejectedError("route_refused", why)
        if request.key is KeyRole.TEAM:
            if request.as_user not in self._team:
                return TemplateRejectedError(
                    "no_key", f"no case team key is configured for {str(request.as_user)[:40]}"
                )
            return None
        if request.key not in self._auth:
            return TemplateRejectedError("no_key", f"no {request.key} key is configured")
        return None

    async def send(self, request: KWire) -> KResponse:
        refused = self.refusal(request)
        if refused is not None:
            raise refused
        auth = (
            self._team[str(request.as_user)]
            if request.key is KeyRole.TEAM
            else self._auth[request.key]
        )
        headers = {
            "Authorization": auth,
            "Accept": "application/json",
            "X-Opaque-Id": request.opaque_id,
        }
        if request.target == "kibana":
            headers["kbn-xsrf"] = XSRF
        if request.body is not None:
            headers["Content-Type"] = request.content_type
        started = time.monotonic()
        try:
            async with (
                asyncio.timeout(request.timeout_s),
                self.clients[request.target].stream(
                    request.method,
                    (self.base_path if request.target == "kibana" else "") + request.path,
                    params=list(request.params),
                    content=request.body,
                    headers=headers,
                    timeout=httpx.Timeout(request.timeout_s),
                ) as response,
            ):
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > self.max_bytes:
                        raise UnknownOutcomeError(f"the answer is larger than {self.max_bytes} B")
                    chunks.append(chunk)
                status = response.status_code
                date = response.headers.get("date")
        except KibanaResponseError:
            raise
        except (httpx.ConnectTimeout, httpx.PoolTimeout):  # never reached Kibana
            raise UnknownOutcomeError("no connection", reached=False, timed_out=True) from None
        except httpx.ConnectError:  # refused, no route
            raise UnknownOutcomeError("connection failed", reached=False) from None
        except (httpx.TimeoutException, TimeoutError):
            raise UnknownOutcomeError("no answer before the deadline", timed_out=True) from None
        except httpx.HTTPError as exc:  # reset, protocol error, a write that broke off
            raise UnknownOutcomeError(f"the exchange failed ({type(exc).__name__})") from None
        return KResponse(status, b"".join(chunks), (time.monotonic() - started) * 1000, date)
