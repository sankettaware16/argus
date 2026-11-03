"""Q-A2: the heavy-task lock (scripts/heavy.sh), the frontend's gate steps
(scripts/frontend_gate.sh) and their place in scripts/gate.sh. systemd-run, node, npm and uv
are stubs here: no scope, install or build happens."""

from __future__ import annotations

import fcntl
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

HEAVY = REPO_ROOT / "scripts" / "heavy.sh"
SYSTEMD_RUN_STUB = """#!/bin/sh
echo "$@" >> "{log}"
while [ "$1" != "--" ]; do shift; done
shift
exec "$@"
"""


def _bin(tmp_path: Path) -> tuple[Path, Path]:
    folder = tmp_path / "bin"
    folder.mkdir(exist_ok=True)
    log = tmp_path / "systemd-run.log"
    stub = folder / "systemd-run"
    stub.write_text(SYSTEMD_RUN_STUB.format(log=log))
    stub.chmod(0o755)
    return folder, log


def _heavy_env(tmp_path: Path, **extra: str) -> tuple[dict[str, str], Path]:
    folder, log = _bin(tmp_path)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("ARGUS_", "HEAVY_"))}
    env.update(PATH=f"{folder}{os.pathsep}{os.environ['PATH']}",
               ARGUS_HEAVY_DIR=str(tmp_path / "slots"), **extra)  # fmt: skip
    return env, log


def _run(
    command: list[str], env: dict[str, str], timeout: float = 60
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the repository's scripts and stubs
        command, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def test_the_command_never_sees_the_heavy_variables(tmp_path: Path) -> None:
    env, log = _heavy_env(tmp_path, ARGUS_HEAVY_SLOTS="1", ARGUS_HEAVY_MEM="1G")
    done = _run(["bash", str(HEAVY), "--label", "t", "env"], env)
    assert done.returncode == 0, done.stderr
    lines = done.stdout.splitlines()
    assert "HEAVY_SLOT_HELD=1" in lines
    assert not [line for line in lines if line.startswith("ARGUS_HEAVY_")]
    assert "-p MemoryMax=1G -p MemorySwapMax=0" in log.read_text()


def test_argus_works_inside_a_slot_with_the_heavy_variables_set(tmp_path: Path) -> None:
    """DEFECT (Q-A2): the ARGUS_HEAVY_* variables reached the command, and ARGUS refuses an
    ARGUS_ variable that is not a setting, so every `argus` command (and the test suite's
    settings) failed inside heavy.sh whenever one was exported."""
    config = tmp_path / "argus.yaml"
    config.write_text("environment: dev\n")
    env, _ = _heavy_env(tmp_path, ARGUS_HEAVY_SLOTS="2", ARGUS_HEAVY_MEM="2G")
    code = "from argus.cli import main; main()"
    done = _run(
        ["bash", str(HEAVY), sys.executable, "-c", code, "config", "validate", "-c", str(config)],
        env,
    )
    assert done.returncode == 0, done.stderr
    assert "configuration OK" in done.stdout


def test_a_nested_heavy_command_runs_in_the_slot_held(tmp_path: Path) -> None:
    """DEFECT (Q-A2): with one slot, a heavy command that calls heavy.sh (gate.sh's steps, run
    in a slot) waited for ever for a second slot."""
    env, log = _heavy_env(tmp_path, ARGUS_HEAVY_SLOTS="1")
    inner = f"bash {HEAVY} --mem 9G --label inner sh -c 'echo inner $HEAVY_SLOT_HELD'"
    done = _run(["bash", str(HEAVY), "--label", "outer", "sh", "-c", inner], env, timeout=30)
    assert (done.returncode, done.stdout.strip()) == (0, "inner 1")
    assert len(log.read_text().splitlines()) == 1  # one scope: the inner one used it


def test_the_exit_code_and_a_usage_error(tmp_path: Path) -> None:
    env, _ = _heavy_env(tmp_path)
    assert _run(["bash", str(HEAVY), "sh", "-c", "exit 7"], env).returncode == 7
    assert _run(["bash", str(HEAVY), "--label", "x"], env).returncode == 2


def test_a_busy_slot_is_waited_for(tmp_path: Path) -> None:
    env, _ = _heavy_env(tmp_path, ARGUS_HEAVY_SLOTS="1")
    slots = tmp_path / "slots"
    slots.mkdir()
    holder = open(slots / "slot-1.lock", "w")  # noqa: SIM115 - held across the run below
    fcntl.flock(holder, fcntl.LOCK_EX)
    proc = subprocess.Popen(  # noqa: S603
        ["bash", str(HEAVY), "echo", "ran"],  # noqa: S607
        env=env, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True,
    )  # fmt: skip
    time.sleep(1.0)
    assert proc.poll() is None  # waiting for the slot
    holder.close()  # releases it
    out, err = proc.communicate(timeout=30)
    assert (proc.returncode, out.strip()) == (0, "ran")
    assert "heavy: all 1 slots busy; waiting" in err


# --------------------------------------------------------------------------- frontend gate


NPM_STUB = """#!/bin/sh
echo "npm $*" >> "{log}"
case "$1" in
  --version) echo 11.19.0 ;;
  sbom) echo '{{"bomFormat": "CycloneDX"}}' ;;
esac
if [ -n "$NPM_FAIL" ] && [ "$1 $2" = "$NPM_FAIL" ]; then exit 1; fi
exit 0
"""
UV_STUB = """#!/bin/sh
echo "uv $*" >> "{log}"
case "$*" in
  *policy*) echo "policy: OK" ;;
  *manifest*) echo "manifest: sources abc, Node v24.21.0" ;;
esac
"""


def _frontend_repo(
    tmp_path: Path, node_version: str = "v24.21.0"
) -> tuple[Path, dict[str, str], Path]:
    repo = tmp_path / "repo"
    (repo / "scripts").mkdir(parents=True)
    shutil.copy(REPO_ROOT / "scripts" / "frontend_gate.sh", repo / "scripts")
    (repo / "frontend").mkdir()
    (repo / "frontend" / "package.json").write_text("{}")
    log = tmp_path / "tools.log"
    node_dir = tmp_path / "node24" / "bin"
    node_dir.mkdir(parents=True)
    for name, body in (
        ("node", f"#!/bin/sh\necho {node_version}\n"),
        ("npm", NPM_STUB.format(log=log)),
    ):
        (node_dir / name).write_text(body)
        (node_dir / name).chmod(0o755)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "uv").write_text(UV_STUB.format(log=log))
    (tools / "uv").chmod(0o755)
    env = {**os.environ, "NODE24_DIR": str(tmp_path / "node24"),
           "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}  # fmt: skip
    return repo, env, log


def test_the_frontend_gate_runs_every_step_in_order_with_scripts_blocked(tmp_path: Path) -> None:
    repo, env, log = _frontend_repo(tmp_path)
    out = tmp_path / "out"
    done = _run(["bash", str(repo / "scripts" / "frontend_gate.sh"), str(out)], env)
    assert done.returncode == 0, done.stdout + done.stderr
    assert [line.split("  ")[1] for line in done.stdout.splitlines()] == [
        f"toolchain: Node v24.21.0, npm 11.19.0 ({tmp_path / 'node24'})",
        "supply-chain policy (policy: OK)",
        "npm ci (install scripts blocked)",
        "typecheck",
        "lint",
        "Vitest",
        "build",
        "npm audit (0 high or critical)",
        "npm audit signatures",
        "SBOM (CycloneDX)",
        "build manifest (manifest: sources abc, Node v24.21.0)",
    ]
    assert all(line.startswith("PASS") for line in done.stdout.splitlines())
    calls = log.read_text().splitlines()
    assert [c for c in calls if c.startswith("npm") and "--version" not in c] == [
        "npm ci --ignore-scripts --no-audit",
        "npm run --silent typecheck",
        "npm run --silent lint",
        "npm run --silent test",
        "npm run --silent build",
        "npm audit --audit-level=high",
        "npm audit signatures",
        "npm sbom --sbom-format cyclonedx",
    ]
    assert (out / "sbom.cdx.json").read_text().strip() == '{"bomFormat": "CycloneDX"}'


def test_a_failed_step_fails_the_frontend_gate_and_the_rest_still_runs(tmp_path: Path) -> None:
    repo, env, _ = _frontend_repo(tmp_path)
    env["NPM_FAIL"] = "audit --audit-level=high"
    done = _run(["bash", str(repo / "scripts" / "frontend_gate.sh"), str(tmp_path / "o")], env)
    assert done.returncode == 1
    assert "FAIL  npm audit (0 high or critical)" in done.stdout
    assert "PASS  npm audit signatures" in done.stdout  # the others still ran


def test_the_system_node_is_never_used(tmp_path: Path) -> None:
    repo, env, log = _frontend_repo(tmp_path, node_version="v20.20.2")
    done = _run(["bash", str(repo / "scripts" / "frontend_gate.sh"), str(tmp_path / "o")], env)
    assert done.returncode == 1
    assert done.stdout.startswith("FAIL  toolchain: Node v20.20.2")
    assert "npm ci" not in log.read_text()  # stopped before any install


def test_no_frontend_yet_is_skipped(tmp_path: Path) -> None:
    repo, env, log = _frontend_repo(tmp_path)
    (repo / "frontend" / "package.json").unlink()
    done = _run(["bash", str(repo / "scripts" / "frontend_gate.sh"), str(tmp_path / "o")], env)
    assert (done.returncode, done.stdout.strip()) == (
        0,
        "SKIP  frontend (no frontend/package.json yet)",
    )
    assert not log.exists()


def test_gate_sh_takes_the_heavy_lock_for_its_heavy_steps() -> None:
    gate = (REPO_ROOT / "scripts" / "gate.sh").read_text()
    assert 'heavy "${GATE_MEM_MYPY:-2G}" mypy uv run mypy' in gate
    assert 'heavy "${GATE_MEM_SUITE:-4G}" "full suite" env HYPOTHESIS_PROFILE=gate' in gate
    assert 'heavy "${GATE_MEM_MUTATION:-4G}" mutation uv run python scripts/mutation.py' in gate
    assert "if [ -f frontend/package.json ]; then" in gate
    assert 'heavy "${GATE_MEM_FRONTEND:-3G}" frontend scripts/frontend_gate.sh' in gate
    assert "scripts/heavy.sh --mem" in gate
