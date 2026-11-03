"""The HTTPS transport: what it sends, how failures map to typed errors, the answer size cap,
and the TLS context (CA only, CERT_REQUIRED, hostname checked)."""

from __future__ import annotations

import gzip
import ssl
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from argus.gateway.errors import ResponseError, TimedOutError, TransportFailedError
from argus.gateway.templates import CostClass, Endpoint, Family, Spec
from argus.gateway.transport import (
    NODE_STATS_PATH,
    HttpxTransport,
    WireRequest,
    ca_summary,
    pinned_context,
    wire_path,
)
from argus.gateway.validator import FinalRequest

pytestmark = pytest.mark.unit

CA = Path(__file__).parent / "data" / "test-ca.crt"
REQUEST = WireRequest("POST", "/a/_search", (("x", "1"),), b'{"size":1}', "argus-c/t@1", 5.0)


def transport_with(
    handler: Callable[[httpx.Request], httpx.Response], max_bytes: int = 1000
) -> HttpxTransport:
    sender = HttpxTransport(
        "https://127.0.0.1:9", ssl.create_default_context(), SecretStr("k3y"), max_bytes=max_bytes
    )
    sender.client = httpx.AsyncClient(
        base_url="https://127.0.0.1:9", transport=httpx.MockTransport(handler)
    )
    return sender


def test_the_client_ignores_the_environment_and_redirects() -> None:
    sender = HttpxTransport("https://127.0.0.1:9", ssl.create_default_context(), SecretStr("k"))
    assert sender.client.trust_env is False
    assert sender.client.follow_redirects is False
    with pytest.raises(ValueError, match="https only"):
        HttpxTransport("http://127.0.0.1:9", ssl.create_default_context(), SecretStr("k"))


async def test_what_is_sent() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b'{"ok":true}')

    response = await transport_with(handler).send(REQUEST)
    (request,) = seen
    assert (request.method, request.url.path, request.url.query) == ("POST", "/a/_search", b"x=1")
    assert request.headers["authorization"] == "ApiKey k3y"
    assert request.headers["x-opaque-id"] == "argus-c/t@1"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["accept"] == "application/json"
    assert request.content == b'{"size":1}'
    assert (response.status, response.body) == (200, b'{"ok":true}')
    assert response.elapsed_ms >= 0
    await transport_with(handler).send(WireRequest("GET", "/", (), None, "argus-c/t@1", 5.0))
    assert "content-type" not in seen[-1].headers


async def test_status_codes_pass_through() -> None:
    response = await transport_with(lambda r: httpx.Response(429, content=b"{}")).send(REQUEST)
    assert response.status == 429


@pytest.mark.parametrize(
    ("raised", "error", "retriable"),
    [
        (httpx.ConnectTimeout("t"), TimedOutError, False),
        (httpx.ReadTimeout("t"), TimedOutError, False),
        (httpx.ConnectError("refused"), TransportFailedError, True),
        (httpx.ReadError("reset"), TransportFailedError, True),
        (httpx.WriteError("reset"), TransportFailedError, True),
        (httpx.RemoteProtocolError("bad"), TransportFailedError, True),
        (httpx.TooManyRedirects("x"), TransportFailedError, False),
    ],
)
async def test_failures(
    raised: Exception, error: type[TransportFailedError], retriable: bool
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise raised

    with pytest.raises(error) as info:
        await transport_with(handler).send(REQUEST)
    assert info.value.retriable is retriable


async def test_the_answer_size_is_capped_after_decompression() -> None:
    await transport_with(lambda r: httpx.Response(200, content=b"x" * 1000)).send(REQUEST)
    with pytest.raises(ResponseError, match="larger than 1000 bytes"):
        await transport_with(lambda r: httpx.Response(200, content=b"x" * 1001)).send(REQUEST)
    bomb = gzip.compress(b"x" * 100_000)
    assert len(bomb) < 1000

    def gzipped(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=bomb, headers={"content-encoding": "gzip"})

    with pytest.raises(ResponseError, match="larger than"):
        await transport_with(gzipped).send(REQUEST)


def test_the_pinned_context(tmp_path: Path) -> None:
    context = pinned_context(CA)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version is ssl.TLSVersion.TLSv1_2
    assert len(context.get_ca_certs()) == 1  # this CA only, no system store
    with pytest.raises(FileNotFoundError):
        pinned_context(tmp_path / "missing.crt")


def test_ca_summary(tmp_path: Path) -> None:
    summary = ca_summary(CA)
    assert summary.subject == "ARGUS test CA"
    assert summary.not_after.tzinfo is not None
    with pytest.raises(ValueError, match="does not exist"):
        ca_summary(tmp_path / "none.crt")
    junk = tmp_path / "junk.crt"
    junk.write_text("not a certificate")
    with pytest.raises(ValueError, match="not a PEM certificate"):
        ca_summary(junk)


def spec(endpoint: Endpoint) -> Spec:
    return Spec(name="t", version=1, endpoint=endpoint, family=Family.CLUSTER, cost=CostClass.PROBE)


@pytest.mark.parametrize(
    ("endpoint", "indices", "pattern", "expected"),
    [
        (Endpoint.INFO, (), None, ("GET", "/")),
        (Endpoint.SEARCH, ("a", "b.c"), None, ("POST", "/a,b.c/_search")),
        (Endpoint.MGET, (".x+1",), None, ("POST", "/.x+1/_mget")),
        (Endpoint.NODE_STATS, (), None, ("GET", NODE_STATS_PATH)),
        (Endpoint.INDEX_BLOCKS, ("a",), None, ("GET", "/a/_settings/index.blocks.*,index.uuid")),
        (Endpoint.RESOLVE_INDEX, (), "logs-a-*", ("GET", "/_resolve/index/logs-a-*")),
        (Endpoint.AUTHENTICATE, (), None, ("GET", "/_security/_authenticate")),
        (Endpoint.HAS_PRIVILEGES, (), None, ("POST", "/_security/user/_has_privileges")),
    ],
)
def test_wire_paths(
    endpoint: Endpoint, indices: tuple[str, ...], pattern: str | None, expected: tuple[str, str]
) -> None:
    assert wire_path(FinalRequest(spec(endpoint), indices=indices, pattern=pattern)) == expected
    assert NODE_STATS_PATH == "/_nodes/_local/stats/fs,jvm,os,thread_pool,breaker"


def test_wire_paths_quote_what_the_validator_would_refuse() -> None:
    weird = FinalRequest(spec(Endpoint.SEARCH), indices=("a/../_cluster?x#",))
    assert wire_path(weird) == ("POST", "/a%2F..%2F_cluster%3Fx%23/_search")
