"""The Kibana transport (Q-D2): HTTPS only, ``kbn-xsrf`` on every Kibana request, the key
chosen by role, no redirect followed, the route refused again before sending, typed errors
that say whether a request may have landed, a cap on the answer."""

from __future__ import annotations

import ssl
from collections.abc import Callable

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.gateway.errors import TemplateRejectedError
from argus.gateway.kibana.errors import UnknownOutcomeError
from argus.gateway.kibana.paths import KEndpoint, Target, wire_path
from argus.gateway.kibana.templates import KeyRole
from argus.gateway.kibana.transport import XSRF, HttpxKibanaTransport, KWire

pytestmark = pytest.mark.unit
SPACE = "acme-soc"
KEYS = {KeyRole.READER: SecretStr("reader-secret"), KeyRole.CASES: SecretStr("cases-secret")}


TEAM_KEYS = {"argus-lead": SecretStr("lead-secret"), "argus-reporter": SecretStr("reporter-secret")}


def transport(
    handler: Callable[[httpx.Request], httpx.Response], **kw: int
) -> HttpxKibanaTransport:
    t = HttpxKibanaTransport(
        "https://kibana.test:5601", "https://es.test:9200", ssl.create_default_context(), KEYS,
        space=SPACE, team_keys=TEAM_KEYS, **kw,
    )  # fmt: skip
    for target, url in (("kibana", "https://kibana.test:5601"), ("es", "https://es.test:9200")):
        t.clients[target] = httpx.AsyncClient(
            base_url=url, transport=httpx.MockTransport(handler), follow_redirects=False
        )
    return t


def wire(method: str = "GET", path: str = f"/s/{SPACE}/api/status", **kw: object) -> KWire:
    fields: dict[str, object] = {
        "target": "kibana", "key": KeyRole.READER, "method": method, "path": path,
        "params": (), "body": None, "opaque_id": "argus-test/kibana.status@1", "timeout_s": 5.0,
    }  # fmt: skip
    fields.update(kw)
    return KWire(**fields)  # type: ignore[arg-type]


def test_https_only() -> None:
    with pytest.raises(ValueError, match="https"):
        HttpxKibanaTransport("http://k:5601", "https://e:9200", ssl.create_default_context(),
                             KEYS, space=SPACE)  # fmt: skip
    t = HttpxKibanaTransport("https://k:5601", "https://e:9200", ssl.create_default_context(),
                             KEYS, space=SPACE)  # fmt: skip
    assert all(not c._trust_env for c in t.clients.values())
    assert all(not c.follow_redirects for c in t.clients.values())


@pytest.mark.parametrize("endpoint", list(KEndpoint))
async def test_kbn_xsrf_and_the_roles_key_on_every_kibana_request(endpoint: KEndpoint) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={}, headers={"date": "Fri, 23 Oct 2026 10:00:00 GMT"})

    target = Target(alert_id="a1") if endpoint is KEndpoint.ALERT_CASES else (
        Target(case_id="c1") if "{case}" in _route_doc(endpoint) else Target())  # fmt: skip
    method, path = wire_path(endpoint, SPACE, target)
    body = b"{}" if method != "GET" else None
    key = KeyRole.READER if method == "GET" else KeyRole.CASES
    extra: dict[str, object] = {}
    if endpoint in (KEndpoint.CASE_FILES, KEndpoint.ALERTS_TAGS, KEndpoint.CASE_COMMENT_EDIT):
        # the case team's alone
        key = KeyRole.TEAM
        who = "argus-reporter" if endpoint is KEndpoint.CASE_FILES else "argus-lead"
        extra = {"as_user": who}
        if endpoint is KEndpoint.CASE_FILES:
            extra["content_type"] = "multipart/form-data; boundary=argus-" + "0" * 40
    answer = await transport(handler).send(wire(method, path, body=body, key=key, **extra))
    assert answer.status == 200
    assert answer.date == "Fri, 23 Oct 2026 10:00:00 GMT"
    request = seen[0]
    assert request.headers["kbn-xsrf"] == XSRF
    secret = {KeyRole.READER: "reader-secret", KeyRole.CASES: "cases-secret"}.get(
        key, "reporter-secret" if endpoint is KEndpoint.CASE_FILES else "lead-secret"
    )
    assert request.headers["authorization"] == f"ApiKey {secret}"
    assert request.url.path == path
    if endpoint is KEndpoint.CASE_FILES:
        assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    else:
        assert (request.headers.get("content-type") == "application/json") == (body is not None)


def _route_doc(endpoint: KEndpoint) -> str:
    try:
        wire_path(endpoint, SPACE)
    except ValueError:
        return "{case}"
    return ""


@given(
    method=st.sampled_from(["DELETE", "PUT", "HEAD", "OPTIONS", "GET", "POST"]),
    path=st.sampled_from(
        ["/api/cases", "/s/acme-soc/internal/rac/alerts/bulk_update",
         "/s/acme-soc/api/cases/configure", "/s/other/api/cases/_find",
         "/s/acme-soc/api/cases/x/connector/none/_push", "/_security/user/x"]
    ),
)  # fmt: skip
async def test_a_refused_route_never_leaves(method: str, path: str) -> None:
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(200, json={})

    if method == "GET" and path == "/s/acme-soc/api/cases/configure":
        return  # the one allowed form: reading the configuration
    with pytest.raises(TemplateRejectedError):
        await transport(handler).send(wire(method, path, body=b"{}"))
    assert sent == []


async def test_es_targets_only_the_keys_own_identity_and_privileges() -> None:
    sent: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request.url.path)
        assert "kbn-xsrf" not in request.headers
        return httpx.Response(200, json={})

    t = transport(handler)
    await t.send(wire("POST", "/_security/user/_has_privileges", target="es", body=b"{}"))
    for path in ("/_search", "/.alerts-x/_update_by_query", "/_security/api_key"):
        with pytest.raises(TemplateRejectedError):
            await t.send(wire("POST", path, target="es", body=b"{}"))
    assert sent == ["/_security/user/_has_privileges"]


async def test_a_role_without_a_key_sends_nothing() -> None:
    with pytest.raises(TemplateRejectedError, match="no_key"):
        await transport(lambda r: httpx.Response(200)).send(wire(key=KeyRole.ALERTS))


async def test_a_redirect_is_returned_not_followed() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(302, headers={"location": "https://elsewhere.test/login"})

    answer = await transport(handler).send(wire())
    assert answer.status == 302
    assert calls == [f"/s/{SPACE}/api/status"]


@pytest.mark.parametrize(
    ("raised", "reached", "timed_out"),
    [
        (httpx.ConnectError("refused"), False, False),
        (httpx.ConnectTimeout("slow connect"), False, True),
        (httpx.PoolTimeout("pool"), False, True),
        (httpx.ReadTimeout("slow"), True, True),
        (httpx.ReadError("reset"), True, False),
        (httpx.WriteError("broke off"), True, False),
        (httpx.RemoteProtocolError("bad"), True, False),
    ],
)
async def test_failures_say_whether_the_request_may_have_landed(
    raised: Exception, reached: bool, timed_out: bool
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise raised

    with pytest.raises(UnknownOutcomeError) as caught:
        await transport(handler).send(wire("POST", f"/s/{SPACE}/api/cases", body=b"{}",
                                           key=KeyRole.CASES))  # fmt: skip
    assert caught.value.reached is reached
    assert caught.value.maybe_applied is reached
    assert caught.value.timed_out is timed_out


async def test_an_answer_too_large_is_an_unknown_outcome() -> None:
    big = b"x" * 2048
    with pytest.raises(UnknownOutcomeError, match="larger"):
        await transport(lambda r: httpx.Response(200, content=big), max_bytes=1024).send(wire())


async def test_kibanas_base_path_goes_before_every_checked_path() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.path)
        return httpx.Response(200, json={})

    t = transport(handler)
    t.base_path = "/kibana"
    await t.send(wire())
    await t.send(wire("POST", "/_security/user/_has_privileges", target="es", body=b"{}"))
    assert seen == [f"/kibana/s/{SPACE}/api/status", "/_security/user/_has_privileges"]
    with pytest.raises(TemplateRejectedError):  # the check is on the path without it
        await t.send(wire("DELETE", f"/s/{SPACE}/api/cases"))
    for bad in ("kibana", "/Kibana", "/a/b/c/d", "/../x", "/k/"):
        with pytest.raises(ValueError, match="base path"):
            HttpxKibanaTransport(
                "https://k:5601", "https://e:9200", ssl.create_default_context(), KEYS,
                space=SPACE, base_path=bad,
            )  # fmt: skip
