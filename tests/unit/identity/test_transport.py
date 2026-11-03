"""The identity lane's own transport (Q-E1): https and the pinned CA only, two routes, the
person's header on that one request only, no redirects, the answer cap, typed failures."""

from __future__ import annotations

import base64
import ssl
from collections.abc import Callable

import httpx
import pytest
from pydantic import SecretStr

from argus.gateway.errors import ResponseError, TimedOutError, TransportFailedError
from argus.identity.names import Credential
from argus.identity.transport import (
    CONNECT_TIMEOUT_S,
    OPAQUE_ID,
    ROUTES,
    TOTAL_TIMEOUT_S,
    HttpxIdentityTransport,
    IdentityRequest,
    Route,
    authorization,
)

URL = "https://siem.invalid:9200"
ME = Credential("devuser", SecretStr("correct-horse-battery-staple"))


def real(handler: Callable[[httpx.Request], httpx.Response], **kw: float) -> HttpxIdentityTransport:
    t = HttpxIdentityTransport(URL, ssl.create_default_context(), **kw)  # type: ignore[arg-type]
    t.client = httpx.AsyncClient(
        base_url=URL, transport=httpx.MockTransport(handler), follow_redirects=False
    )
    return t


def test_the_basic_header_is_rfc_7617_utf8() -> None:
    value = authorization(Credential("devuser", SecretStr("pässwörd-long"))).get_secret_value()
    scheme, encoded = value.split(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == "devuser:pässwörd-long"
    assert "pässwörd" not in repr(authorization(ME))


def test_two_routes_only() -> None:
    assert ROUTES == {
        Route.WHOAMI: ("GET", "/_security/_authenticate"),
        Route.VERIFY: ("POST", "/_security/user/_has_privileges"),
    }


def test_https_and_sane_timeouts_only() -> None:
    context = ssl.create_default_context()
    with pytest.raises(ValueError, match="https only"):
        HttpxIdentityTransport("http://siem.invalid:9200", context)
    for connect, total in ((0, 5), (4, 3), (3, 6), (-1, 5)):
        with pytest.raises(ValueError, match="within"):
            HttpxIdentityTransport(URL, context, connect_timeout_s=connect, total_timeout_s=total)
    t = HttpxIdentityTransport(URL, context)
    assert (t.connect_timeout_s, t.total_timeout_s) == (CONNECT_TIMEOUT_S, TOTAL_TIMEOUT_S)
    assert (CONNECT_TIMEOUT_S, TOTAL_TIMEOUT_S) == (3, 5)
    assert not t.client._trust_env
    assert not t.client.follow_redirects
    assert "authorization" not in {k.lower() for k in t.client.headers}  # no client default


async def test_each_request_carries_its_own_header_and_nothing_else() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"username": "devuser"})

    t = real(handler)
    other = Credential("other", SecretStr("another-long-password"))
    me = await t.send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))
    body = b'{"cluster": []}'
    await t.send(IdentityRequest(Route.VERIFY, body, 5), authorization(other))
    await t.send(IdentityRequest(Route.WHOAMI, None, 5), SecretStr("Basic Zm9vOmJhcg=="))
    assert me.status == 200
    assert me.body == b'{"username":"devuser"}'
    first, second, third = seen
    assert (first.method, first.url.path) == ("GET", "/_security/_authenticate")
    assert (second.method, second.url.path) == ("POST", "/_security/user/_has_privileges")
    assert first.headers["authorization"] == authorization(ME).get_secret_value()
    assert second.headers["authorization"] == authorization(other).get_secret_value()
    assert third.headers["authorization"] == "Basic Zm9vOmJhcg=="
    assert second.content == body
    assert second.headers["content-type"] == "application/json"
    assert "content-type" not in first.headers
    for request in seen:
        assert request.headers["x-opaque-id"] == OPAQUE_ID == "argus-identity"
        assert "devuser" not in request.headers["x-opaque-id"]
        assert request.url.query == b""
    assert "authorization" not in {k.lower() for k in t.client.headers}
    await t.aclose()


async def test_nothing_is_logged_with_the_header(caplog: pytest.LogCaptureFixture) -> None:
    import logging

    caplog.set_level(logging.DEBUG)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"type": "security_exception"}})

    await real(handler).send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))
    header = authorization(ME).get_secret_value()
    assert header.split(" ", 1)[1] not in caplog.text
    assert "correct-horse" not in caplog.text


async def test_redirects_are_returned_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.invalid/"})

    got = await real(handler).send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))
    assert got.status == 302


async def test_the_answer_is_capped() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 300_000)

    with pytest.raises(ResponseError, match="larger than"):
        await real(handler).send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))


@pytest.mark.parametrize(
    ("raised", "kind", "reached"),
    [
        (httpx.ConnectTimeout("t"), TimedOutError, False),
        (httpx.PoolTimeout("t"), TimedOutError, False),
        (httpx.ReadTimeout("t"), TimedOutError, True),
        (httpx.WriteTimeout("t"), TimedOutError, True),
        (httpx.ConnectError("refused"), TransportFailedError, False),
        (httpx.ReadError("reset"), TransportFailedError, True),
        (httpx.RemoteProtocolError("bad"), TransportFailedError, True),
        (httpx.UnsupportedProtocol("x"), TransportFailedError, True),
    ],
)
async def test_failures_are_typed(raised: Exception, kind: type[Exception], reached: bool) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise raised

    with pytest.raises(kind) as caught:
        await real(handler).send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))
    assert isinstance(caught.value, TransportFailedError)
    assert caught.value.reached is reached
    assert not caught.value.retriable
    assert caught.value.__cause__ is None  # raised from None: httpx's request never travels
    assert "correct-horse" not in str(caught.value)


async def test_the_timeout_is_the_smaller_of_the_requests_and_the_transports() -> None:
    timeouts: list[dict[str, float]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        timeouts.append(request.extensions["timeout"])
        return httpx.Response(200, json={})

    t = real(handler, connect_timeout_s=2, total_timeout_s=4)
    await t.send(IdentityRequest(Route.WHOAMI, None, 5), authorization(ME))
    await t.send(IdentityRequest(Route.WHOAMI, None, 1.5), authorization(ME))
    assert timeouts[0] == {"connect": 2, "read": 4, "write": 4, "pool": 4}
    assert timeouts[1] == {"connect": 1.5, "read": 1.5, "write": 1.5, "pool": 1.5}
