"""D-322: a long-running service that is stopped exits 0. systemd stops a unit with SIGTERM to
``uv run`` and the Python under it; a Python that died of the signal made ``uv`` exit 143 and
systemd record "Failed with result 'exit-code'" after every deploy."""

from __future__ import annotations

import asyncio
import inspect
import os
import signal
import socket
import subprocess
import sys
import textwrap
import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor

import pytest
from typer.main import get_command

from argus.cli import app
from argus.ops.stopping import until_stopped
from argus.ops.units import MANIFEST, UNITS_DIR
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _sigterm_as_it_was() -> Iterator[None]:
    """A test that stops the work in this process leaves SIGTERM ignored (the process is on its
    way out); the test process gets its own handler back."""
    before = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, before)


def _soon(sig: signal.Signals = signal.SIGTERM, after: float = 0.05) -> None:
    asyncio.get_running_loop().call_later(after, os.kill, os.getpid(), sig)


async def test_a_signal_cancels_the_work_its_cleanup_runs_and_it_returns() -> None:
    cleaned: list[str] = []

    async def forever() -> str:
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0.05)  # a second signal arrives here, and changes nothing
            cleaned.append("disposed")
        return "never"

    _soon(signal.SIGTERM)
    _soon(signal.SIGTERM, after=0.07)
    assert await until_stopped(forever()) is None
    assert cleaned == ["disposed"]
    assert signal.getsignal(signal.SIGTERM) == signal.SIG_IGN  # a late one ends nothing


async def test_with_a_stop_event_the_work_ends_by_itself() -> None:
    finished: list[str] = []

    async def loop(stop: asyncio.Event) -> str:
        await stop.wait()
        await asyncio.sleep(0.05)  # what runs finishes
        finished.append("drained")
        return "done"

    stop = asyncio.Event()
    _soon(signal.SIGINT)
    assert await until_stopped(loop(stop), stop=stop) is None
    assert finished == ["drained"]


async def test_without_a_signal_the_result_and_the_errors_come_through() -> None:
    async def value() -> int:
        return 7

    async def broken() -> None:
        raise RuntimeError("the database refused it")

    assert await until_stopped(value()) == 7
    with pytest.raises(RuntimeError, match="refused"):
        await until_stopped(broken())
    # the handlers are gone again
    loop = asyncio.get_running_loop()
    assert not loop.remove_signal_handler(signal.SIGTERM)


async def test_a_cancel_from_outside_is_not_taken_for_a_stop() -> None:
    task = asyncio.ensure_future(until_stopped(asyncio.Event().wait()))
    await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_outside_the_main_thread_it_only_runs_the_work() -> None:
    async def value() -> int:
        return 3

    with ThreadPoolExecutor(1) as pool:
        assert pool.submit(asyncio.run, until_stopped(value())).result(timeout=10) == 3


def _exit_code(script: str) -> int:
    """Run ``script`` as its own process group, send SIGTERM as systemd does (to the whole
    group, once it says it is ready), and return its exit code."""
    with subprocess.Popen(  # noqa: S603 - this interpreter, a fixed script
        [sys.executable, "-c", textwrap.dedent(script)],
        start_new_session=True,
        cwd=REPO_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    ) as proc:
        assert proc.stdout is not None
        try:
            line = proc.stdout.readline().decode()
            assert "ready" in line, line
            time.sleep(0.15)
            os.killpg(proc.pid, signal.SIGTERM)
            return proc.wait(timeout=30)
        finally:
            if proc.poll() is None:
                proc.kill()


SERVICE = """
    import asyncio, sys
    from argus.ops.stopping import until_stopped

    async def forever():
        print("ready", flush=True)
        await asyncio.Event().wait()

    asyncio.run(until_stopped(forever()))
"""


def test_a_stopped_service_process_exits_0_and_without_it_dies_of_the_signal() -> None:
    assert _exit_code(SERVICE) == 0
    bare = SERVICE.replace("asyncio.run(until_stopped(forever()))", "asyncio.run(forever())")
    assert _exit_code(bare) == -signal.SIGTERM  # what ``uv run`` turned into 143


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


WEB = """
    import uvicorn
    from argus.ops.stopping import quiet_after_uvicorn

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                message = await receive()
                if message["type"] == "lifespan.startup":
                    print("ready", flush=True)
                    await send({"type": "lifespan.startup.complete"})
                elif message["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return

    QUIET
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
"""


def test_the_web_returns_after_uvicorns_graceful_shutdown() -> None:
    quiet = WEB.replace("PORT", str(_free_port())).replace("QUIET", "quiet_after_uvicorn()")
    assert _exit_code(quiet) == 0
    bare = WEB.replace("PORT", str(_free_port())).replace("QUIET", "pass")
    assert _exit_code(bare) == -signal.SIGTERM  # uvicorn raised the signal again


# every long-running service (a unit that restarts, not run by a timer) and the code its command
# runs: each goes through until_stopped or quiet_after_uvicorn
STOPPED_BY = {
    "argus-admin.service": "until_stopped",
    "argus-assess.service": "until_stopped",
    "argus-collector.service": "until_stopped",
    "argus-kibana-sync.service": "until_stopped",
    "argus-web.service": "quiet_after_uvicorn",
    "argus-worker.service": "until_stopped",
    "argus-writer.service": "until_stopped",
}


def _long_running() -> set[str]:
    out = set()
    for name in MANIFEST:
        if not name.endswith(".service") or name.removesuffix(".service") + ".timer" in MANIFEST:
            continue
        if "Restart=" in (UNITS_DIR / name).read_text():
            out.add(name)
    return out


def _callback(unit: str) -> object:
    words = next(
        line.removeprefix("ExecStart=").split()
        for line in (UNITS_DIR / unit).read_text().splitlines()
        if line.startswith("ExecStart=")
    )
    command: object = get_command(app)
    for word in words[words.index("argus") + 1 :]:
        found = getattr(command, "commands", {}).get(word)
        if found is None:
            break
        command = found
    return command.callback  # type: ignore[attr-defined]


@pytest.mark.parametrize("unit", sorted(STOPPED_BY))
def test_each_long_running_service_exits_0_when_stopped(unit: str) -> None:
    assert _long_running() == set(STOPPED_BY), "a new service: say how it stops (D-322)"
    callback = inspect.unwrap(_callback(unit))  # type: ignore[arg-type]
    source = inspect.getsource(callback)
    assert STOPPED_BY[unit] in source, f"{unit}: {callback.__qualname__}"
    assert "SuccessExitStatus" not in (UNITS_DIR / unit).read_text()


LATE = """
    import asyncio, os, signal, time
    from argus.ops.stopping import until_stopped

    async def forever():
        print("ready", flush=True)
        await asyncio.Event().wait()

    asyncio.run(until_stopped(forever()))
    # the SIGTERM ``uv run`` forwards may come after the work has ended: the process is on its
    # way out and exits 0 all the same
    os.kill(os.getpid(), signal.SIGTERM)
    time.sleep(0.2)
"""


def test_a_late_second_sigterm_after_the_stop_changes_nothing() -> None:
    assert _exit_code(LATE) == 0
