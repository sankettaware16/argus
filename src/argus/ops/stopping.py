"""A service that is stopped exits 0 (D-322).

systemd stops a unit with SIGTERM to every process of its group: ``uv run`` and the Python under
it. ``uv run`` exits with its child's code, and a child that dies of the signal makes it 143,
which systemd records as "Failed with result 'exit-code'": after every deploy doctor and the
remote check reported the long-running services as failed. So each of them handles SIGTERM (and
SIGINT, Ctrl-C at a terminal) and returns:

- :func:`until_stopped` runs a service's coroutine and, on the first signal, either sets the
  ``stop`` event it was given (the collector and the worker end their loop and let what runs
  finish) or cancels it (the read-back, assess, the writer: their ``finally`` blocks run,
  transactions roll back, engines are disposed). Either way it returns None: exit 0. A later
  signal changes nothing (systemd's own SIGTERM and the one ``uv`` forwards may arrive apart:
  after a stop SIGTERM stays ignored until the process ends); a stop that hangs ends with
  systemd's SIGKILL after ``TimeoutStopSec``.
- :func:`quiet_after_uvicorn` makes the web's ``uvicorn.run`` return: uvicorn shuts down
  gracefully and then raises the captured signal again with the handler it found, which would
  end the process by the signal.

The code is correct this way rather than ``SuccessExitStatus=143`` in the units: a unit's status
then still tells a crash from a stop, and the services under the custody layout (no ``uv``, the
Python is the main process) behave the same."""

from __future__ import annotations

import asyncio
import logging
import signal
import threading
from collections.abc import Coroutine
from typing import Any

log = logging.getLogger("argus.ops")

STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)


async def until_stopped[T](
    work: Coroutine[Any, Any, T], *, stop: asyncio.Event | None = None
) -> T | None:
    """``work``'s result, or None when SIGTERM or SIGINT stopped it (see the module)."""
    loop = asyncio.get_running_loop()
    task = asyncio.ensure_future(work)
    signalled: list[int] = []

    def on_signal(sig: int) -> None:
        if signalled:
            return
        signalled.append(sig)
        log.info("%s: stopping", signal.Signals(sig).name)
        if stop is not None:
            stop.set()
        else:
            task.cancel()

    # signals reach only the main thread (a test runs a command in another: it is stopped by
    # its own end there)
    handled = STOP_SIGNALS if threading.current_thread() is threading.main_thread() else ()
    for sig in handled:
        loop.add_signal_handler(sig, on_signal, sig)
    try:
        result = await task
    except asyncio.CancelledError:
        if not signalled or stop is not None:
            raise  # cancelled from outside, or a graceful stop that was cancelled after all
        return None
    finally:
        for sig in handled:
            loop.remove_signal_handler(sig)
        if signalled and handled:
            # the process is on its way out: the SIGTERM ``uv`` forwards may arrive only now,
            # after the handler is gone, and would end it by the signal (143)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
    return None if signalled else result


def _exit_0(_sig: int, _frame: object) -> None:
    raise SystemExit(0)


def quiet_after_uvicorn() -> None:
    """Before ``uvicorn.run``: SIGTERM's handler becomes one that exits 0. uvicorn installs its
    own while it serves (a SIGTERM starts its graceful shutdown), puts this one back afterwards
    and raises the signal again: the process then exits 0, not by the signal. A SIGTERM before
    uvicorn serves exits 0 at once."""
    signal.signal(signal.SIGTERM, _exit_0)
