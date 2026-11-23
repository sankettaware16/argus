"""The frontend's toolchain and its committed build.

Node 24 and npm 11 live in ``~/.local/opt/node24``; the system's Node is never used. The build is
committed: ``scripts/frontend_gate.sh`` builds ``frontend/`` into :data:`BUILD_DIR` and writes
:data:`MANIFEST`, the hash of the sources it was built from, so ``argus doctor`` can tell a stale
build. The policy check reads the project's files only: exact versions, install scripts blocked, a
14-day release age, no banned package."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from argus.ops.units import REPO

FRONTEND_DIR = REPO / "frontend"
BUILD_DIR = REPO / "src" / "argus" / "web" / "spa"  # served at /app; committed
MANIFEST = "argus-build.json"
NODE_MAJOR, NPM_MAJOR = 24, 11
MIN_RELEASE_AGE_DAYS = 14
# Not part of the sources: what npm, the tools and the build write.
_GENERATED = frozenset(
    {"node_modules", "dist", "build", "coverage", ".vite", "test-results", "playwright-report",
     ".turbo", ".cache", ".stryker-tmp", "reports"}
)  # fmt: skip
_EXACT = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
# CSP breaks (style injection) and XSS-prone components; Radix injects <style>
BANNED = ("sonner", "vaul", "@radix-ui/")


def node_dir() -> Path:
    return Path.home() / ".local" / "opt" / "node24"


def source_files(frontend: Path = FRONTEND_DIR) -> Iterator[Path]:
    """The frontend's own files, in a stable order: everything under ``frontend/`` except what
    tools generate (node_modules, build output, reports)."""
    if not frontend.is_dir():
        return
    for root, dirs, files in os.walk(frontend):
        dirs[:] = sorted(d for d in dirs if d not in _GENERATED)
        for name in sorted(files):
            yield Path(root) / name


def sources_sha256(frontend: Path = FRONTEND_DIR) -> str:
    """One hash of every source file's path and content."""
    digest = hashlib.sha256()
    for path in source_files(frontend):
        relative = path.relative_to(frontend).as_posix()
        digest.update(relative.encode() + b"\0" + hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def write_manifest(
    build: Path, frontend: Path, node: str, npm: str, now: datetime | None = None
) -> dict[str, Any]:
    """Record what the build in ``build`` was made from (after ``npm run build``)."""
    data = {
        "sources_sha256": sources_sha256(frontend),
        "built_at": (now or datetime.now(UTC)).isoformat(),
        "node": node,
        "npm": npm,
    }
    build.mkdir(parents=True, exist_ok=True)
    (build / MANIFEST).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    return data


def read_manifest(build: Path = BUILD_DIR) -> dict[str, Any] | None:
    path = build / MANIFEST
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) and isinstance(data.get("sources_sha256"), str) else None


@dataclass(frozen=True)
class Toolchain:
    node: str | None  # "v24.21.0", or None when not installed
    npm: str | None
    problem: str | None  # why it cannot build ARGUS's frontend, if it cannot


def toolchain(directory: Path | None = None, timeout_s: float = 20.0) -> Toolchain:
    """The Node and npm in ``directory`` (default ``~/.local/opt/node24``), never the ones on
    PATH: both must be there and of the chosen majors."""
    directory = node_dir() if directory is None else directory
    node, npm = directory / "bin" / "node", directory / "bin" / "npm"
    if not node.is_file():
        return Toolchain(None, None, f"no Node at {directory} (the system Node is never used)")
    env = {**os.environ, "PATH": f"{directory / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"}
    node_version = _version([str(node), "--version"], env, timeout_s)
    if node_version is None or not node_version.startswith(f"v{NODE_MAJOR}."):
        found = node_version or "not runnable"
        return Toolchain(node_version, None, f"{node} is {found}, not Node {NODE_MAJOR}")
    npm_version = _version([str(npm), "--version"], env, timeout_s) if npm.is_file() else None
    if npm_version is None or not npm_version.startswith(f"{NPM_MAJOR}."):
        found = npm_version or "missing"
        return Toolchain(node_version, npm_version, f"npm is {found}, not npm {NPM_MAJOR}")
    return Toolchain(node_version, npm_version, None)


def _version(command: list[str], env: Mapping[str, str], timeout_s: float) -> str | None:
    try:
        done = subprocess.run(  # noqa: S603 - a fixed program and argument
            command, env=dict(env), capture_output=True, text=True, timeout=timeout_s, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = done.stdout.strip().splitlines()
    return out[0][:40] if done.returncode == 0 and out else None


def policy_problems(frontend: Path = FRONTEND_DIR) -> list[str]:
    """What breaks the frontend's supply-chain rules, from its files alone:
    exact versions in package.json, a lockfile (version 3), and an ``.npmrc`` that blocks
    install scripts, saves exact versions and waits 14 days for a release; no banned package
    anywhere in the lockfile."""
    problems: list[str] = []
    try:
        package = json.loads((frontend / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["package.json is missing or not JSON"]
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in sorted((package.get(section) or {}).items()):
            if not isinstance(spec, str) or not _EXACT.fullmatch(spec):
                problems.append(f"{section}: {name} is {spec!r}, not an exact version")
            if isinstance(spec, str) and spec.startswith("npm:"):  # an alias: npm:<name>@<v>
                real = spec.removeprefix("npm:").rpartition("@")[0] or spec.removeprefix("npm:")
                if _banned(real):
                    problems.append(f"{section}: {name} is an alias of the banned package {real}")
    for script in ("typecheck", "lint", "test", "build"):
        if script not in (package.get("scripts") or {}):
            problems.append(f"package.json has no {script!r} script (the gate runs it)")
    rc = _npmrc(frontend / ".npmrc")
    if rc.get("ignore-scripts") != "true":
        problems.append(".npmrc must say ignore-scripts=true (no install scripts)")
    if rc.get("save-exact") != "true":
        problems.append(".npmrc must say save-exact=true (exact versions)")
    age = rc.get("min-release-age", "")
    if not age.isdigit() or int(age) < MIN_RELEASE_AGE_DAYS:
        problems.append(f".npmrc must say min-release-age={MIN_RELEASE_AGE_DAYS} or more (days)")
    try:
        lock = json.loads((frontend / "package-lock.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return [*problems, "package-lock.json is missing or not JSON (npm ci needs it)"]
    if lock.get("lockfileVersion") != 3:
        problems.append("package-lock.json is not lockfile version 3")
    entries = lock.get("packages") or {}
    for path in sorted(entries):
        if not path:
            continue
        folder = path.rsplit("node_modules/", 1)[-1]
        entry = entries[path]
        # an npm alias installs a package under another folder name; the entry's "name" says
        # which package it really is
        recorded = entry.get("name") if isinstance(entry, dict) else None
        name = recorded if isinstance(recorded, str) and recorded else folder
        if _banned(name):
            alias = f" (as {folder})" if name != folder else ""
            problems.append(f"banned package in the lockfile: {name}{alias}")
        elif name != folder and _banned(folder):
            problems.append(f"banned package in the lockfile: {folder}")
    return problems


def _banned(name: str) -> bool:
    return any(name == b or (b.endswith("/") and name.startswith(b)) for b in BANNED)


def _npmrc(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for raw in lines:
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        key, sep, value = line.partition("=")
        if sep:
            values[key.strip()] = value.strip()
    return values
