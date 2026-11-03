"""Q-B1: the app at /app as the server serves it (plan §7.5): the page only to a signed-in
person with view, back through /signin otherwise; its files to anyone, immutable and gzipped;
a missing file is a 404, never the page; the CSP with Trusted Types on /app; no-store on the API;
the build's id on every /app and /api answer; another build folder by setting."""

from __future__ import annotations

import gzip
import re
import shutil
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.config.settings import WebSettings
from argus.web import security, spa
from argus.web.app import create_app
from tests.integration.web.conftest import BASE, NOW, SAME_ORIGIN, log_in

pytestmark = pytest.mark.integration
BUILD = spa.Build()


def committed_assets() -> list[str]:
    index = BUILD.index()
    assert index is not None, "no committed build: npm run build in frontend/"
    return re.findall(r'(?:src|href)="/app/(assets/[^"]+)"', index.body.decode())


def app_client(engine: AsyncEngine, settings: WebSettings | None = None) -> httpx.AsyncClient:
    app = create_app(engine, settings, clock=lambda: NOW + timedelta(hours=1))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE,
                             headers=SAME_ORIGIN)  # fmt: skip


@pytest.mark.parametrize(("path", "back"), [("/app", "/app"), ("/app/design", "/app/design"),
                                            ("/app/x/y?q=1", "/app/x/y?q=1")])  # fmt: skip
async def test_signed_out_the_page_sends_to_signin_and_back(
    client: httpx.AsyncClient, path: str, back: str
) -> None:
    response = await client.get(path)
    assert response.status_code == 303
    target = httpx.URL(response.headers["location"])
    assert target.path == "/signin"
    assert target.params["next"] == back
    assert security.safe_next(target.params["next"]) == back  # sign-in really goes back there
    assert "argus-build" not in response.text  # no app code for a signed-out browser


@pytest.mark.parametrize("path", ["/app", "/app/", "/app/design", "/app/investigations/10.0.0.1",
                                  "/app/hosts/evil.example.com"])  # fmt: skip
async def test_signed_in_every_app_path_is_the_page(client: httpx.AsyncClient, path: str) -> None:
    await log_in(client)
    response = await client.get(path)
    assert response.status_code == 200
    index = BUILD.index()
    assert index is not None
    assert response.content == index.body
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["cache-control"] == "no-cache"
    csp = response.headers["content-security-policy"]
    assert csp == spa.CSP_APP
    assert csp.startswith(security.CSP)  # the site's policy, never loosened
    assert "require-trusted-types-for 'script'; trusted-types 'none'" in csp
    assert response.headers[spa.BUILD_HEADER] == index.build
    assert re.fullmatch(r"[0-9a-f]{16}", index.build or "")
    assert response.headers["x-frame-options"] == "DENY"


async def test_files_are_served_to_anyone_immutable_and_gzipped(client: httpx.AsyncClient) -> None:
    assets = committed_assets()
    assert any(a.endswith(".js") for a in assets)
    assert any(a.endswith(".css") for a in assets)
    for asset in assets:
        on_disk = (spa.BUILD_DIR / asset).read_bytes()
        plain = await client.get(f"/app/{asset}", headers={"Accept-Encoding": "identity"})
        assert plain.status_code == 200, asset
        assert plain.content == on_disk
        assert plain.headers["cache-control"] == spa.IMMUTABLE
        assert "content-encoding" not in plain.headers
        assert plain.headers["content-security-policy"] == spa.CSP_APP
        assert plain.headers["x-content-type-options"] == "nosniff"
        kind = "text/javascript" if asset.endswith(".js") else "text/css"
        assert plain.headers["content-type"].startswith(kind)
        packed = await client.get(f"/app/{asset}", headers={"Accept-Encoding": "gzip, br"})
        assert packed.headers["content-encoding"] == "gzip"
        assert packed.headers["vary"] == "Accept-Encoding"
        assert packed.content == on_disk  # httpx decodes it: the same bytes
        refused = await client.get(f"/app/{asset}", headers={"Accept-Encoding": "gzip;q=0"})
        assert "content-encoding" not in refused.headers
    icon = await client.get("/app/favicon.svg")
    assert icon.status_code == 200
    assert icon.headers["content-type"] == "image/svg+xml"
    assert icon.headers["cache-control"] == "no-cache"


@pytest.mark.parametrize("path", [
    "/app/assets/index-AAAAAAAA.js", "/app/assets/missing.css", "/app/assets/../index.html",
    "/app/assets/..%2Findex.html", "/app/assets/sub/x.js", "/app/assets/.hidden.js",
    "/app/assets/x.exe", "/app/assets/", "/app/assets", "/app/index.html", "/app/x.js",
    "/app/design/main.css", "/app/robots.txt", "/app/x.map",
])  # fmt: skip
async def test_a_missing_file_is_a_404_never_the_page(client: httpx.AsyncClient, path: str) -> None:
    await log_in(client)
    response = await client.get(path)
    assert response.status_code == 404, path
    assert response.headers["content-type"].startswith("text/plain")
    assert response.headers["cache-control"] == "no-store"
    assert b"<html" not in response.content


async def test_the_api_says_its_build_and_is_never_stored(client: httpx.AsyncClient) -> None:
    await log_in(client)
    for path in ("/api/v1/session", "/api/v1/counts", "/api/investigations"):
        response = await client.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers[spa.BUILD_HEADER] == BUILD.build_id()
        assert response.headers["content-security-policy"] == security.CSP  # no TT off /app
    page = await client.get("/rules")  # the classic pages keep their policy, no build header
    assert page.headers["content-security-policy"] == security.CSP
    assert spa.BUILD_HEADER.lower() not in page.headers


async def test_a_view_only_refusal_is_a_page(seeded: AsyncEngine, web_engine: AsyncEngine) -> None:
    from sqlalchemy import text

    async with app_client(web_engine) as http:
        await log_in(http, "ravi")
        async with seeded.begin() as conn:  # taken away after sign-in: checked at each request
            await conn.execute(text("UPDATE users SET capabilities = '{}' WHERE username = 'ravi'"))
        response = await http.get("/app/design")
    assert response.status_code == 403
    assert "view" in response.text
    assert "argus-build" not in response.text


async def test_another_build_folder_and_a_missing_build(
    seeded: AsyncEngine, web_engine: AsyncEngine, tmp_path: Path
) -> None:
    other = tmp_path / "spa"
    shutil.copytree(spa.BUILD_DIR, other)
    html = (other / "index.html").read_text()
    fake = re.sub(r'content="[0-9a-f]{16}"', 'content="0123456789abcdef"', html)
    (other / "index.html").write_text(fake)
    async with app_client(web_engine, WebSettings(spa_dir=other)) as http:
        await log_in(http)
        response = await http.get("/app")
        assert response.headers[spa.BUILD_HEADER] == "0123456789abcdef"
        assert b"0123456789abcdef" in response.content
        # a change on disk is seen at the next request (a deploy without a restart)
        (other / "index.html").write_text(html.replace("<title>", "<title>New "))
        again = await http.get("/app")
        assert b"New ARGUS" in again.content
        assert again.headers[spa.BUILD_HEADER] == BUILD.build_id()
    async with app_client(web_engine, WebSettings(spa_dir=tmp_path / "none")) as http:
        await log_in(http)
        missing = await http.get("/app")
        assert missing.status_code == 503
        assert "not built" in missing.text
        api = await http.get("/api/v1/session")
        assert spa.BUILD_HEADER.lower() not in api.headers


def test_gzip_of_the_committed_files_is_what_the_server_sends() -> None:
    for asset in committed_assets():
        found = BUILD.file(asset)
        assert found is not None
        assert found.gzipped is not None
        assert gzip.decompress(found.gzipped) == found.body


# --------------------------------------------------------------------------- review fixes


@pytest.mark.parametrize("path", ["/app/hosts/assets", "/app/users/assets/history",
                                  "/app/x/assets"])  # fmt: skip
async def test_a_route_segment_named_assets_is_the_page(
    client: httpx.AsyncClient, path: str
) -> None:
    """Review F6 (decision 4): only /app/assets/... or a file name is a file."""
    await log_in(client)
    response = await client.get(path)
    assert response.status_code == 200, (path, response.status_code)
    assert response.headers["cache-control"] == "no-cache"


async def test_head_is_answered_like_get(client: httpx.AsyncClient) -> None:
    """Review F7: HEAD wherever GET is served (RFC 9110), with the same status and headers."""
    signed_out = await client.head("/app/design")
    assert signed_out.status_code == 303
    assert httpx.URL(signed_out.headers["location"]).params["next"] == "/app/design"
    await log_in(client)
    asset = committed_assets()[0]
    for path in ("/app", "/app/design", f"/app/{asset}", "/app/favicon.svg", "/app/assets/x.js",
                 "/app/x.js"):  # fmt: skip
        got, head = await client.get(path), await client.head(path)
        assert head.status_code == got.status_code, path
        for name in ("content-type", "cache-control", "content-security-policy",
                     spa.BUILD_HEADER, "content-encoding", "vary", "content-length"):  # fmt: skip
            assert head.headers.get(name) == got.headers.get(name), (path, name)
    for path in ("/app", f"/app/{asset}"):
        raw = await client.send(client.build_request("HEAD", path), stream=True)
        assert raw.status_code == 200, path
        await raw.aclose()


@pytest.mark.parametrize(("path", "back"), [
    ("/app/hosts/b%C3%BCcher.example", "/app/hosts/b%C3%BCcher.example"),  # a domain route
    ("/app/search/a%3Fb", "/app/search/a%3Fb"),  # an encoded ? stays in the path
    ("/app/search/a%3Fb?q=%C3%BC", "/app/search/a%3Fb?q=%C3%BC"),
    ("/app/a%2Fb", "/app/a%2Fb"),
])  # fmt: skip
async def test_a_deep_link_comes_back_after_sign_in_as_written(
    client: httpx.AsyncClient, path: str, back: str
) -> None:
    """Review F8: next= is the path as the browser sent it (still percent-encoded), so sign-in
    leads back to the same route, not to / and not to another page."""
    response = await client.get(path)
    assert response.status_code == 303
    target = httpx.URL(response.headers["location"])
    assert target.params["next"] == back
    assert security.safe_next(back) == back
