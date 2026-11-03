"""Q-B1: the server side of /app (argus.web.spa) and the committed build itself (DQ25): the build
serves no inline script or style and no data: URI, every file it names is there and hashed, its
initial JavaScript is within 300 KB, it is fresh (built from the current frontend/ sources), and
the file lookup never leaves the build folder."""

from __future__ import annotations

import gzip
import json
import re
import subprocess
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.ops import frontend
from argus.web import security, spa

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[3]
INDEX = spa.BUILD_DIR / "index.html"
LIMIT = 300 * 1024


def index_html() -> str:
    assert INDEX.is_file(), "no committed build: run the frontend gate (npm run build)"
    return INDEX.read_text(encoding="utf-8")


def referenced(html: str) -> list[str]:
    return re.findall(r'(?:src|href)="(/app/[^"]+)"', html)


def test_the_build_lives_where_q_a2_said_and_is_committed() -> None:
    assert frontend.BUILD_DIR.resolve() == spa.BUILD_DIR
    for path in (INDEX, spa.BUILD_DIR / frontend.MANIFEST, *spa.BUILD_DIR.glob("assets/*")):
        ignored = subprocess.run(  # noqa: S603 - git, a fixed command
            ["git", "check-ignore", "-q", str(path)],  # noqa: S607 - git from PATH
            cwd=ROOT,
            check=False,
        )
        assert ignored.returncode == 1, f"{path} is ignored by git: the build must be committed"


def test_the_page_has_no_inline_script_style_or_data_uri() -> None:
    html = index_html()
    scripts = re.findall(r"<script\b.*?</script>", html, re.S)
    assert scripts
    for script in scripts:  # each one a file of the build, with no code inside the tag
        assert re.fullmatch(r'<script type="module" crossorigin src="/app/assets/[^"]+"></script>',
                            script), script  # fmt: skip
    assert "<style" not in html
    assert " style=" not in html
    assert re.search(r"\son[a-z]+=", html) is None
    assert "data:" not in html
    for css in spa.BUILD_DIR.glob("assets/*.css"):
        assert "data:" not in css.read_text(encoding="utf-8"), css.name
    assert re.search(r'<meta name="argus-build" content="[0-9a-f]{16}"', html)


def test_every_file_the_page_names_is_there_and_hashed() -> None:
    html = index_html()
    names = referenced(html)
    assert any(n.endswith(".js") for n in names)
    assert any(n.endswith(".css") for n in names)
    for name in names:
        relative = name.removeprefix("/app/")
        assert spa.Build().file(relative) is not None, name
        if relative.startswith("assets/"):
            assert re.fullmatch(r"assets/[A-Za-z0-9_-]+-[A-Za-z0-9_-]{8}\.(js|css)", relative), name
    for path in (spa.BUILD_DIR / "assets").iterdir():  # nothing in the build that is not served
        assert path.suffix in spa.TYPES, path.name
        assert spa.Build().file(f"assets/{path.name}") is not None, path.name


def test_initial_javascript_is_within_300_kb() -> None:
    html = index_html()
    scripts = re.findall(r'<script\b[^>]*\bsrc="/app/([^"]+)"', html)
    scripts += re.findall(r'<link\b[^>]*rel="modulepreload"[^>]*href="/app/([^"]+)"', html)
    packed = sum(len(gzip.compress((spa.BUILD_DIR / s).read_bytes(), 9)) for s in scripts)
    assert scripts
    assert packed <= LIMIT, f"{packed / 1024:.1f} KB gzip"


def test_the_committed_build_is_fresh() -> None:
    """Built from the current frontend/ sources (Q-A2's manifest; doctor checks the same)."""
    made = frontend.read_manifest(spa.BUILD_DIR)
    assert made is not None
    assert made["sources_sha256"] == frontend.sources_sha256(), (
        "frontend/ changed since the committed build: run the frontend gate (npm run build"
        " and scripts/frontend_build.py manifest)"
    )
    assert made["node"].startswith("v24.")


def test_the_frontend_keeps_the_supply_chain_rules() -> None:
    assert frontend.policy_problems() == []
    package = json.loads((ROOT / "frontend" / "package.json").read_text())
    assert package["devDependencies"]["typescript"] == "6.0.3"
    assert "echarts" not in package["dependencies"]  # Trusted Types refuse its painter (Q-B1)


def test_the_app_policy_only_adds_trusted_types() -> None:
    assert spa.CSP_APP.startswith(security.CSP + "; ")
    added = spa.CSP_APP.removeprefix(security.CSP + "; ")
    assert added == "require-trusted-types-for 'script'; trusted-types 'none'"
    for loosening in ("unsafe-inline", "unsafe-eval", "data:", "*", "blob:", "nonce-"):
        assert loosening not in spa.CSP_APP


@pytest.mark.parametrize(("header", "ok"), [
    (None, False), ("", False), ("gzip", True), ("GZIP", True), ("br, gzip", True),
    ("gzip;q=0", False), ("gzip; q=0.0", False), ("gzip;q=0.5", True), ("gzip;q=x", False),
    ("identity", False), ("*", True), ("deflate, br", False), ("x-gzip", False),
])  # fmt: skip
def test_accepts_gzip(header: str | None, ok: bool) -> None:
    assert spa.accepts_gzip(header) is ok


@pytest.mark.parametrize(("path", "is_file"), [
    ("", False), ("design", False), ("hosts/10.0.0.1", False), ("hosts/evil.example.com", False),
    ("assets", True), ("assets/x.js", True), ("main.js", True),
    ("a/b.css", True), ("index.html", True), ("x.map", True), ("favicon.ico", True),
    ("robots.txt", True), ("data.json", True), ("font.woff2", True), ("assetsx", False),
    # review F6: only the build's own assets/ folder is files; a route may hold "assets"
    ("x/assets/y", False), ("hosts/assets", False), ("users/assets/history", False),
    ("assets/sub/x", True), ("x/assets", False), ("xassets/y", False),
])  # fmt: skip
def test_file_like_paths(path: str, is_file: bool) -> None:
    assert bool(spa.FILE_LIKE.search(path)) is is_file


@given(st.text(max_size=60))
def test_a_file_lookup_never_leaves_the_build(name: str) -> None:
    build = spa.Build()
    for relative in (name, f"assets/{name}"):
        found = build.file(relative)
        if found is not None:
            path = (spa.BUILD_DIR / relative).resolve()
            assert path.is_relative_to(spa.BUILD_DIR.resolve())
            assert path.parent.name in ("assets", "spa")


@pytest.mark.parametrize("relative", [
    "../app.py", "assets/../index.html", "assets/../../app.py", "/etc/passwd", "assets//x.js",
    "assets/.x.js", "index.html", "argus-build.json", "assets/x", "assets/x.py", "spa/x.js",
    "assets/a/b.js", "favicon.svg/x", "",
])  # fmt: skip
def test_only_the_builds_own_files_are_served(relative: str) -> None:
    assert spa.Build().file(relative) is None


def test_a_build_folder_with_no_page(tmp_path: Path) -> None:
    build = spa.Build(tmp_path)
    assert build.index() is None
    assert build.build_id() is None
    (tmp_path / "index.html").write_text("<html>no id</html>")
    assert build.index() is not None
    assert build.build_id() is None
    (tmp_path / "assets").mkdir()
    (tmp_path / "assets" / "a-12345678.js").write_text("x")
    (tmp_path / "assets" / "b-12345678.woff2").write_bytes(b"\0")
    found = build.file("assets/a-12345678.js")
    assert found is not None
    assert found.gzipped is not None
    font = build.file("assets/b-12345678.woff2")
    assert font is not None
    assert font.gzipped is None  # already compressed
    assert font.media_type == "font/woff2"
    (tmp_path / "assets" / "dir.js").mkdir()
    assert build.file("assets/dir.js") is None


def test_is_app_path() -> None:
    assert spa.is_app_path("/app")
    assert spa.is_app_path("/app/")
    assert spa.is_app_path("/app/design")
    assert not spa.is_app_path("/application")
    assert not spa.is_app_path("/apps/x")
    assert not spa.is_app_path("/")


def _mutation_targets() -> dict[str, object]:
    import importlib.util
    import sys

    path = ROOT / "scripts" / "mutation.py"
    spec = importlib.util.spec_from_file_location("argus_mutation_targets", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up while being made
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[spec.name]
    targets: dict[str, object] = module.TARGETS
    return targets


def test_q_b1s_modules_have_mutation_targets() -> None:
    """Review F12: the serving module, and the /app routes in app.py with the tests that reach
    them, are mutation targets (plan §4: 85 %); every frontend module is in a Stryker config:
    the five of plan §4's 100 % in stryker.config.json, the rest (85 %) in
    stryker.rest.config.json."""
    targets = _mutation_targets()
    by_path = {getattr(t, "path"): t for t in targets.values()}  # noqa: B009
    served = by_path.get("src/argus/web/spa.py")
    assert served is not None, "no mutation target for src/argus/web/spa.py"
    tests = set(getattr(served, "tests"))  # noqa: B009
    assert {"tests/unit/web/test_spa.py", "tests/integration/web/test_spa.py"} <= tests
    routes = set(getattr(by_path["src/argus/web/app.py"], "tests"))  # noqa: B009
    assert "tests/integration/web/test_spa.py" in routes
    front = ROOT / "frontend"
    strict = json.loads((front / "stryker.config.json").read_text())
    rest = json.loads((front / "stryker.rest.config.json").read_text())
    assert strict["thresholds"]["break"] == 100
    assert rest["thresholds"]["break"] == 85
    assert not set(strict["mutate"]) & set(rest["mutate"])
    sources = {
        p.relative_to(front).as_posix()
        for p in (front / "src").rglob("*")
        if p.suffix in (".ts", ".tsx")
        and "client" not in p.relative_to(front / "src").parts
        and not p.name.endswith(".d.ts")
    }
    assert sources == set(strict["mutate"]) | set(rest["mutate"])
    assert set(strict["mutate"]) >= {"src/lib/untrusted.ts", "src/components/UntrustedText.tsx",
                                     "src/lib/payload.ts", "src/components/PayloadView.tsx",
                                     "src/components/ConfirmDialog.tsx"}  # fmt: skip
