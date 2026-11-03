"""A delaying TLS proxy in front of the tier's Kibana (§12 #13; Q-D4 reuses it for its 10, 140
and 200 s landings).

It terminates TLS with the tier's own Kibana certificate (valid for 127.0.0.1 under the tier's
CA), so a client that pins that CA cannot tell it from Kibana. Each connection carries one
request. The proxy reads the whole request, then:

* waits ``request_delay`` seconds before Kibana gets it (the request "lands late"), and
  delivers it even when the client has given up meanwhile: bytes already sent stay sent;
* or delivers it at once and holds Kibana's answer for ``response_delay`` seconds (the request
  landed, the client times out before it hears so);
* with ``drop_after_send`` (seconds), closes its connection to Kibana that long after sending
  the request, so Kibana's handler runs on with nobody to answer. ``dropped_unanswered`` says
  that not a byte of Kibana's answer had arrived by then (Kibana was still handling it);
  ``answered_before_drop`` that it had (the drop proves nothing about a running handler).

``events`` records what happened and when (monotonic seconds); ``forwarded`` and ``answered``
are set once a request reached Kibana and once Kibana answered.
"""

from __future__ import annotations

import asyncio
import contextlib
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType

HEAD_END = b"\r\n\r\n"
MAX_HEAD = 64 * 1024


def _with_connection_close(head: bytes) -> bytes:
    """The request head with ``Connection: close``, so Kibana closes after its one answer."""
    lines = [line for line in head.split(b"\r\n") if not line.lower().startswith(b"connection:")]
    return b"\r\n".join([*lines, b"Connection: close"])


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            return int(value.strip())
    return 0


@dataclass
class DelayingProxy:
    upstream_host: str
    upstream_port: int
    certificate: Path  # the tier's Kibana certificate and key: valid for 127.0.0.1
    key: Path
    ca_file: Path  # to verify Kibana
    request_delay: float = 0.0
    response_delay: float = 0.0
    drop_after_send: float | None = None
    port: int = 0
    events: list[tuple[float, str]] = field(default_factory=list)
    forwarded: threading.Event = field(default_factory=threading.Event)
    answered: threading.Event = field(default_factory=threading.Event)
    dropped_unanswered: threading.Event = field(default_factory=threading.Event)
    answered_before_drop: threading.Event = field(default_factory=threading.Event)
    _loop: asyncio.AbstractEventLoop | None = None
    _thread: threading.Thread | None = None
    _server: asyncio.base_events.Server | None = None
    _started: threading.Event = field(default_factory=threading.Event)
    _tasks: set[asyncio.Task[None]] = field(default_factory=set)

    def _event(self, what: str) -> None:
        self.events.append((time.monotonic(), what))

    # ----------------------------------------------------------------------- lifecycle

    def __enter__(self) -> DelayingProxy:
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run, name="delaying-proxy", daemon=True)
        self._thread.start()
        if not self._started.wait(10):
            raise RuntimeError("the delaying proxy did not start")
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self, wait: float = 30.0) -> None:
        """Stop accepting; let requests in flight finish (up to ``wait`` seconds)."""
        if self._loop is None or self._thread is None:
            return
        future = asyncio.run_coroutine_threadsafe(self._shutdown(wait), self._loop)
        with contextlib.suppress(Exception):
            future.result(wait + 5)
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)
        self._loop.close()
        self._loop = None

    def _run(self) -> None:
        assert self._loop is not None
        asyncio.set_event_loop(self._loop)
        self._loop.run_until_complete(self._start())
        self._started.set()
        self._loop.run_forever()

    async def _start(self) -> None:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(str(self.certificate), str(self.key))
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0, ssl=server_context)
        self.port = self._server.sockets[0].getsockname()[1]

    async def _shutdown(self, wait: float) -> None:
        if self._server is not None:
            self._server.close()
        if self._tasks:
            await asyncio.wait(self._tasks, timeout=wait)
        for task in self._tasks:
            task.cancel()

    # ----------------------------------------------------------------------- one request

    def _accept(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.ensure_future(self._handle(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._event("accepted")
        try:
            head = await reader.readuntil(HEAD_END)
            if len(head) > MAX_HEAD:
                raise ValueError("request head too large")
            body = await reader.readexactly(_content_length(head))
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, OSError):
            writer.close()
            return
        self._event("request received")
        request = _with_connection_close(head[: -len(HEAD_END)]) + HEAD_END + body
        if self.request_delay:
            await asyncio.sleep(self.request_delay)  # the client may give up meanwhile
        answer = await self._forward(request)
        if self.response_delay:
            await asyncio.sleep(self.response_delay)
        try:
            if answer:
                writer.write(answer)
                await writer.drain()
                self._event("answer passed on")
            else:  # nothing to pass on: keep the client waiting until it gives up
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(reader.read(), timeout=120)
                self._event("client gone")
        except (ConnectionError, OSError):
            self._event("client gone")
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _forward(self, request: bytes) -> bytes:
        client_context = ssl.create_default_context(cafile=str(self.ca_file))
        upstream_reader, upstream_writer = await asyncio.open_connection(
            self.upstream_host,
            self.upstream_port,
            ssl=client_context,
            server_hostname=self.upstream_host,
        )
        upstream_writer.write(request)
        await upstream_writer.drain()
        self._event("forwarded")
        self.forwarded.set()
        if self.drop_after_send is not None:
            try:  # the first byte of an answer, if Kibana sends one before the drop is due
                first = await asyncio.wait_for(upstream_reader.read(1), self.drop_after_send)
            except TimeoutError:
                first = b""
                self.dropped_unanswered.set()
                self._event("dropped before any answer")
            else:
                if first:
                    self.answered_before_drop.set()
                    self._event("answer began before the drop")
            upstream_writer.transport.abort()
            self._event("upstream dropped")
            return b""
        answer = await upstream_reader.read()  # Connection: close, so up to the end
        upstream_writer.close()
        self._event("answered")
        self.answered.set()
        return answer
