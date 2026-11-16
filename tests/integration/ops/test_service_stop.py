"""D-322: the real long-running commands exit 0 when systemd stops them: SIGTERM to the whole
process group, ``uv run`` and the Python under it, as ``systemctl --user stop`` sends it."""

from __future__ import annotations

import os
import shutil
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.integration.test_cli_db import _invoke, cli_env  # noqa: F401 - the fixture

pytestmark = pytest.mark.integration

ARGUS = str(Path(sys.executable).parent / "argus")


def _python_catches_sigterm(pid: int) -> bool:
    """Whether ``pid`` or a process under it runs Python with a SIGTERM handler installed
    (``SigCgt`` in /proc: the service's loop is up; ``uv`` catches it from its start)."""
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
        status = Path(f"/proc/{pid}/status").read_text()
        children = " ".join(p.read_text() for p in Path(f"/proc/{pid}/task").glob("*/children"))
    except OSError:
        return False
    caught = int(next(x for x in status.splitlines() if x.startswith("SigCgt:")).split()[1], 16)
    if Path(exe).name.startswith("python") and caught & (1 << (signal.SIGTERM - 1)):
        return True
    return any(_python_catches_sigterm(int(c)) for c in children.split())


def _serving(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) == 0


def _stopped(
    command: list[str], ready: Callable[[int], bool], *, timeout: float = 90
) -> tuple[int, str]:
    """Start ``command`` in its own process group, wait until ``ready(pid)``, stop it as systemd
    does and return its exit code and output."""
    with subprocess.Popen(  # noqa: S603 - this checkout's own commands
        command, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ) as proc:
        assert proc.stdout is not None
        os.set_blocking(proc.stdout.fileno(), False)
        out = ""
        deadline = time.monotonic() + timeout
        try:
            while not ready(proc.pid):
                assert proc.poll() is None, out
                assert time.monotonic() < deadline, out
                out += (proc.stdout.read() or b"").decode(errors="replace")
                time.sleep(0.2)
            time.sleep(0.5)
            os.killpg(proc.pid, signal.SIGTERM)
            code = proc.wait(timeout=60)
            os.set_blocking(proc.stdout.fileno(), True)
            out += proc.stdout.read().decode(errors="replace")
            return code, out
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_the_worker_exits_0_when_stopped(cli_env: Path) -> None:  # noqa: F811
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    code, out = _stopped([ARGUS, "worker", "run", *config], _python_catches_sigterm)
    assert code == 0, out


@pytest.mark.skipif(shutil.which("uv") is None, reason="needs uv")
def test_under_uv_run_as_the_units_start_it(cli_env: Path) -> None:  # noqa: F811
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    env_uv = str(shutil.which("uv"))
    project = str(Path(__file__).resolve().parents[3])
    code, out = _stopped(
        [env_uv, "run", "--project", project, "argus", "worker", "run", *config],
        _python_catches_sigterm,
    )
    assert code == 0, out


def test_the_web_exits_0_when_stopped(cli_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:  # noqa: F811
    config = ("-c", str(cli_env))
    assert _invoke("db", "upgrade", *config)[0] == 0
    port = _free_port()
    monkeypatch.setenv("ARGUS_WEB__PORT", str(port))
    monkeypatch.setenv("ARGUS_WEB__HOST", "127.0.0.1")
    code, out = _stopped([ARGUS, "web", *config], lambda _pid: _serving(port))
    assert code == 0, out
