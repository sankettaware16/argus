"""``argus init``'s first step: what this machine needs before anything is set up (Python and uv,
docker with compose v2 and a reachable daemon, a free port for PostgreSQL, disk space), each
missing piece with a one-line fix. Node is not needed: the web's page is built and committed."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path

GIB = 1 << 30
DISK_FAIL = 2 * GIB
DISK_WARN = 10 * GIB
CONTAINER = "argus-db"  # docker-compose.yml's container_name unless COMPOSE_DB_CONTAINER is set
PROJECT = "argus"  # its project name unless COMPOSE_PROJECT_NAME is set
_OWNER = '{{.Names}}|{{.Label "com.docker.compose.project.working_dir"}}'


def compose_names(
    env: Mapping[str, str], environ: Mapping[str, str] = os.environ
) -> tuple[str, str]:
    """The database's container and compose project as docker compose reads them: the
    environment, then .env, then the file's defaults."""

    def named(key: str, default: str) -> str:
        return environ.get(key) or env.get(key) or default

    return named("COMPOSE_DB_CONTAINER", CONTAINER), named("COMPOSE_PROJECT_NAME", PROJECT)


@dataclass(frozen=True)
class Finding:
    ok: bool
    text: str
    warn: bool = False


Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


def run_command(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """A short local command, its output captured (never shown unless the caller shows it)."""
    try:
        return subprocess.run(  # noqa: S603 - fixed programs, arguments from code
            argv, capture_output=True, text=True, timeout=120, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(argv, 127, "", f"{type(exc).__name__}")


def port_free(host: str, port: int) -> bool:
    """Whether nothing listens on ``host:port`` (a bind would succeed)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((host, port))
        except OSError:
            return False
    return True


def check(
    root: Path,
    *,
    compose: bool,
    port: int,
    uv: str | None,
    which: Callable[[str], str | None],
    run: Runner,
    free: Callable[[str, int], bool],
    disk_free: Callable[[Path], int],
    container: str = CONTAINER,
    project: str = PROJECT,
) -> list[Finding]:
    found = []
    found.append(Finding(True, f"Python {sys.version.split()[0]}"))  # the package needs 3.12
    found.append(
        Finding(True, f"uv {uv}")
        if uv
        else Finding(False, "uv is not on PATH: https://docs.astral.sh/uv/getting-started/")
    )
    for needed in ("docker-compose.yml", "config/argus.yaml"):
        if not (root / needed).is_file():
            found.append(Finding(False, f"{needed} is not here: run argus init in the checkout"))
    if compose:
        found += _docker(root, port, which, run, free, container, project)
    else:
        found.append(Finding(True, "PostgreSQL: the one .env names (docker compose not used)"))
    left = disk_free(root)
    shown = f"{left / GIB:.1f} GiB free in {root}"
    if left < DISK_FAIL:
        found.append(Finding(False, f"{shown}: ARGUS needs at least 2 GiB (its database grows)"))
    elif left < DISK_WARN:
        found.append(Finding(True, f"{shown}: 10 GiB or more is better", warn=True))
    else:
        found.append(Finding(True, shown))
    return found


def _docker(
    root: Path,
    port: int,
    which: Callable[[str], str | None],
    run: Runner,
    free: Callable[[str, int], bool],
    container: str,
    project: str,
) -> list[Finding]:
    if which("docker") is None:
        return [Finding(False, "docker is not installed: https://docs.docker.com/engine/install/")]
    version = run(["docker", "compose", "version", "--short"])
    text = version.stdout.strip().lstrip("v")
    if version.returncode != 0 or not text[:1].isdigit() or int(text.split(".")[0]) < 2:
        return [
            Finding(
                False,
                "docker compose v2 is missing: install the compose plugin"
                " (https://docs.docker.com/compose/install/linux/)",
            )
        ]
    out = [Finding(True, f"docker compose {text}")]
    info = run(["docker", "info", "--format", "{{.ServerVersion}}"])
    if info.returncode != 0:
        out.append(
            Finding(
                False,
                "the Docker daemon cannot be reached: start it (systemctl start docker), or add"
                " yourself to the docker group and log in again",
            )
        )
        return out
    foreign = _foreign(root, run, container, project)
    if foreign:
        out.append(
            Finding(
                False,
                f"the database container {foreign[0]} belongs to another ARGUS checkout"
                f" ({foreign[1]}); this one would take it over. Set COMPOSE_PROJECT_NAME,"
                " COMPOSE_DB_CONTAINER and ARGUS_DATABASE__PORT in this checkout's .env to new"
                " values and run argus init again",
            )
        )
        return out
    if free("127.0.0.1", port):
        out.append(Finding(True, f"port {port} is free for PostgreSQL"))
        return out
    ports = run(["docker", "ps", "--filter", f"name=^{container}$", "--format", "{{.Ports}}"])
    if ports.returncode == 0 and f":{port}->" in ports.stdout:
        out.append(Finding(True, f"port {port}: ARGUS's database ({container}) is running there"))
    else:
        out.append(
            Finding(
                False,
                f"port {port} is in use by another program: set ARGUS_DATABASE__PORT in .env to"
                " a free port and run argus init again",
            )
        )
    return out


def _foreign(root: Path, run: Runner, container: str, project: str) -> tuple[str, str] | None:
    """A container compose would take over for this checkout (the same name, or the same
    project's db) that another checkout made: (its name, that checkout), or None."""
    here = root.resolve()
    for selector in (
        ["--filter", f"name=^{container}$"],
        ["--filter", f"label=com.docker.compose.project={project}",
         "--filter", "label=com.docker.compose.service=db"],
    ):  # fmt: skip
        listed = run(["docker", "ps", "-a", *selector, "--format", _OWNER])
        if listed.returncode != 0:
            continue
        for line in listed.stdout.splitlines():
            name, _, where = line.strip().partition("|")
            if name and Path(where or "/").resolve() != here:
                return name, where or "not made by docker compose"
    return None
