"""Q-A2 (DQ25): the frontend's supply-chain policy, the hash of its sources and the committed
build's manifest, all from files (no network, no npm)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.ops import frontend

pytestmark = pytest.mark.unit

GOOD_PACKAGE = {
    "name": "argus-app",
    "private": True,
    "dependencies": {"react": "19.3.0"},
    "devDependencies": {"typescript": "6.0.3", "vitest": "3.2.4-beta.1"},
    "scripts": {
        "typecheck": "tsc -b",
        "lint": "eslint .",
        "test": "vitest run",
        "build": "vite build",
    },
}
GOOD_RC = "ignore-scripts=true\nsave-exact=true\nmin-release-age=14\n"
GOOD_LOCK: dict[str, Any] = {
    "lockfileVersion": 3,
    "packages": {"": {}, "node_modules/react": {}, "node_modules/@base-ui-components/react": {}},
}


def project(tmp_path: Path, package: Any = None, rc: str = GOOD_RC, lock: Any = None) -> Path:
    folder = tmp_path / "frontend"
    folder.mkdir(parents=True)
    (folder / "package.json").write_text(json.dumps(GOOD_PACKAGE if package is None else package))
    (folder / ".npmrc").write_text(rc)
    (folder / "package-lock.json").write_text(json.dumps(GOOD_LOCK if lock is None else lock))
    return folder


def test_a_project_that_follows_the_rules_passes(tmp_path: Path) -> None:
    assert frontend.policy_problems(project(tmp_path)) == []


@pytest.mark.parametrize(
    ("spec", "ok"),
    [("1.2.3", True), ("1.2.3-rc.1", True), ("^1.2.3", False), ("~1.2.3", False),
     ("1.2", False), ("*", False), ("latest", False), (">=1.0.0", False),
     ("github:org/repo", False), ("1.2.3 || 2.0.0", False), (3, False)],
)  # fmt: skip
def test_only_exact_versions(tmp_path: Path, spec: Any, ok: bool) -> None:
    package = {**GOOD_PACKAGE, "dependencies": {"left-pad": spec}}
    problems = frontend.policy_problems(project(tmp_path, package))
    assert (problems == []) is ok, problems


@pytest.mark.parametrize(
    ("rc", "message"),
    [
        ("save-exact=true\nmin-release-age=14\n", "ignore-scripts=true"),
        ("ignore-scripts=false\nsave-exact=true\nmin-release-age=14\n", "ignore-scripts=true"),
        ("ignore-scripts=true\nmin-release-age=14\n", "save-exact=true"),
        ("ignore-scripts=true\nsave-exact=true\n", "min-release-age=14"),
        ("ignore-scripts=true\nsave-exact=true\nmin-release-age=7\n", "min-release-age=14"),
        ("ignore-scripts=true\nsave-exact=true\nmin-release-age=two weeks\n", "min-release-age"),
        ("# ignore-scripts=true\nsave-exact=true\nmin-release-age=14\n", "ignore-scripts=true"),
    ],
)
def test_the_npmrc_blocks_scripts_pins_and_waits(tmp_path: Path, rc: str, message: str) -> None:
    problems = frontend.policy_problems(project(tmp_path, rc=rc))
    assert any(message in p for p in problems), problems


def test_a_longer_wait_and_comments_are_fine(tmp_path: Path) -> None:
    rc = "; npm settings\nignore-scripts = true\nsave-exact=true # exact\nmin-release-age=30\n"
    assert frontend.policy_problems(project(tmp_path, rc=rc)) == []


@pytest.mark.parametrize(
    ("key", "shown"),
    [
        ("node_modules/sonner", "sonner"),
        ("node_modules/vaul", "vaul"),
        ("node_modules/@radix-ui/react-dialog", "@radix-ui/react-dialog"),
        ("node_modules/x/node_modules/sonner", "sonner"),  # a dependency's dependency
    ],
)
def test_banned_packages_anywhere_in_the_lockfile(tmp_path: Path, key: str, shown: str) -> None:
    lock = {"lockfileVersion": 3, "packages": {"": {}, key: {}}}
    problems = frontend.policy_problems(project(tmp_path, lock=lock))
    assert problems == [f"banned package in the lockfile: {shown} (plan §7.5)"]


def test_a_banned_package_under_an_npm_alias_is_found(tmp_path: Path) -> None:
    """QA2-R6: an alias ("toast": "npm:sonner@1.5.0") installs a package under another folder
    name; package-lock.json records the real one in the entry's "name"."""
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {},
            "node_modules/toasts": {"version": "1.0.0"},
            "node_modules/toast-ui": {"name": "sonner", "version": "1.5.0"},
            "node_modules/x/node_modules/dialog": {"name": "@radix-ui/react-dialog"},
            "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3"},
        },
    }
    problems = frontend.policy_problems(project(tmp_path, lock=lock))
    assert problems == [
        "banned package in the lockfile: sonner (as toast-ui) (plan §7.5)",
        "banned package in the lockfile: @radix-ui/react-dialog (as dialog) (plan §7.5)",
    ]


@pytest.mark.parametrize("spec", ["npm:sonner@1.5.0", "npm:@radix-ui/react-dialog@1.1.2"])
def test_a_direct_alias_of_a_banned_package_is_named(tmp_path: Path, spec: str) -> None:
    scripts = dict.fromkeys(("typecheck", "lint", "test", "build"), "true")
    package = {"dependencies": {"toast": spec}, "scripts": scripts}
    problems = frontend.policy_problems(project(tmp_path, package=package))
    real = spec.removeprefix("npm:").rpartition("@")[0]
    assert f"dependencies: toast is an alias of the banned package {real} (plan §7.5)" in problems


def test_lookalikes_are_not_banned(tmp_path: Path) -> None:
    lock = {"lockfileVersion": 3, "packages": {"node_modules/sonnet": {},
                                                "node_modules/@radix-uix/x": {}}}  # fmt: skip
    assert frontend.policy_problems(project(tmp_path, lock=lock)) == []


def test_missing_files_and_scripts(tmp_path: Path) -> None:
    assert frontend.policy_problems(tmp_path / "none") == ["package.json is missing or not JSON"]
    folder = project(tmp_path, {**GOOD_PACKAGE, "scripts": {"build": "vite build"}})
    (folder / "package-lock.json").unlink()
    problems = frontend.policy_problems(folder)
    assert "package.json has no 'typecheck' script (the gate runs it)" in problems
    assert problems[-1] == "package-lock.json is missing or not JSON (npm ci needs it)"
    old = project(tmp_path / "old", lock={"lockfileVersion": 2, "packages": {}})
    assert frontend.policy_problems(old) == ["package-lock.json is not lockfile version 3"]


def test_the_sources_hash_covers_sources_only(tmp_path: Path) -> None:
    folder = project(tmp_path)
    (folder / "src").mkdir()
    (folder / "src" / "main.tsx").write_text("export {}\n")
    first = frontend.sources_sha256(folder)
    for generated in ("node_modules", "dist", "coverage", "test-results", ".vite"):
        (folder / generated).mkdir()
        (folder / generated / "x.js").write_text("generated")
    assert frontend.sources_sha256(folder) == first
    (folder / "src" / "main.tsx").write_text("export {};\n")
    assert frontend.sources_sha256(folder) != first
    (folder / "src" / "main.tsx").write_text("export {}\n")
    (folder / "src" / "main.tsx").rename(folder / "src" / "app.tsx")  # same bytes, other name
    assert frontend.sources_sha256(folder) != first
    assert frontend.sources_sha256(tmp_path / "absent") == frontend.sources_sha256(tmp_path / "x")


def test_the_manifest_round_trip(tmp_path: Path) -> None:
    folder = project(tmp_path)
    build = tmp_path / "spa"
    made = frontend.write_manifest(build, folder, "v24.21.0", "11.19.0")
    assert frontend.read_manifest(build) == made
    assert made["sources_sha256"] == frontend.sources_sha256(folder)
    (build / frontend.MANIFEST).write_text("[]")
    assert frontend.read_manifest(build) is None
    (build / frontend.MANIFEST).write_text("not json")
    assert frontend.read_manifest(build) is None


def test_the_build_is_committed_where_gitignore_lets_it_be() -> None:
    """DQ25 commits the build: it cannot live in frontend/dist, dist/ or build/ (gitignored)."""
    assert frontend.BUILD_DIR.relative_to(frontend.REPO).parts == ("src", "argus", "web", "spa")
    import subprocess

    ignored = subprocess.run(  # noqa: S603
        ["git", "check-ignore", "-q", str(frontend.BUILD_DIR / frontend.MANIFEST)],  # noqa: S607
        cwd=frontend.REPO, check=False,
    )  # fmt: skip
    assert ignored.returncode == 1  # not ignored
