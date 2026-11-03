"""The delaying TLS proxy (tests/kibana/proxy.py, Q-D1) against a local TLS server.

It must be indistinguishable from the server for a client pinning the CA, deliver a request
that the client has given up on, hold an answer, and drop its side after sending; Q-D4's
"lands 10, 140 and 200 s after the timeout" builds on exactly these behaviours.
"""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest

from tests.kibana.proxy import DelayingProxy, _content_length, _with_connection_close
from tests.kibana.tier import tier_script

TIMEOUT = 0.6
DELAY = 1.2


@dataclass
class Upstream:
    """A one-thread HTTPS server answering ``ok`` and noting when each request arrived."""

    certificate: Path
    key: Path
    answer_delay: float = 0.0  # how long it "handles" a request before answering
    port: int = 0
    arrivals: list[tuple[float, bytes]] = field(default_factory=list)
    _listener: socket.socket | None = None
    _stop: threading.Event = field(default_factory=threading.Event)

    def start(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.certificate), str(self.key))
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, args=(context,), daemon=True).start()

    def _serve(self, context: ssl.SSLContext) -> None:
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                raw, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:  # closed by stop()
                return
            try:
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.settimeout(5)
                    data = b""
                    while b"\r\n\r\n" not in data:
                        chunk = tls.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    self.arrivals.append((time.monotonic(), data))
                    time.sleep(self.answer_delay)
                    body = b'{"ok":true}'
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        + body
                    )
            except (ssl.SSLError, OSError):
                continue

    def stop(self) -> None:
        self._stop.set()
        if self._listener is not None:
            self._listener.close()


@pytest.fixture(scope="module")
def tls(tmp_path_factory: pytest.TempPathFactory) -> Any:
    paths = tier_script.Paths(tmp_path_factory.mktemp("proxy-tls"))
    tier_script.ensure_certificates(paths, now=datetime.now(UTC))
    return paths


@pytest.fixture
def upstream(tls: Any) -> Iterator[Upstream]:
    server = Upstream(tls.kibana_tls / "kibana.crt", tls.kibana_tls / "kibana.key")
    server.start()
    yield server
    server.stop()


def proxy(tls: Any, upstream: Upstream, **kw: float | None) -> DelayingProxy:
    return DelayingProxy(
        "127.0.0.1",
        upstream.port,
        tls.kibana_tls / "kibana.crt",
        tls.kibana_tls / "kibana.key",
        tls.ca_crt,
        **kw,  # type: ignore[arg-type]
    )


def client(tls: Any, port: int, timeout: float = 10) -> httpx.Client:
    return httpx.Client(
        base_url=f"https://127.0.0.1:{port}",
        verify=tier_script.tls_context(tls.ca_crt),
        trust_env=False,
        timeout=timeout,
    )


def test_without_delays_it_is_transparent(tls: Any, upstream: Upstream) -> None:
    with proxy(tls, upstream) as p, client(tls, p.port) as c:
        answer = c.post("/api/cases", json={"title": "x"}, headers={"kbn-xsrf": "t"})
    assert (answer.status_code, answer.json()) == (200, {"ok": True})
    (_, request) = upstream.arrivals[0]
    assert request.startswith(b"POST /api/cases HTTP/1.1")
    assert b"connection: close" in request.lower()
    assert request.endswith(b'{"title":"x"}')  # the body, whole


def test_a_request_is_delivered_after_the_client_gave_up(tls: Any, upstream: Upstream) -> None:
    with proxy(tls, upstream, request_delay=DELAY) as p:
        started = time.monotonic()
        with client(tls, p.port, timeout=TIMEOUT) as c, pytest.raises(httpx.ReadTimeout):
            c.post("/api/cases", json={"title": "late"})
        assert not upstream.arrivals  # nothing yet: the client has given up
        assert p.answered.wait(10)
    arrived, request = upstream.arrivals[0]
    assert arrived - started >= DELAY
    assert request.endswith(b'{"title":"late"}')
    assert [what for _, what in p.events][:3] == ["accepted", "request received", "forwarded"]


def test_an_answer_is_held(tls: Any, upstream: Upstream) -> None:
    with proxy(tls, upstream, response_delay=DELAY) as p:
        with client(tls, p.port, timeout=TIMEOUT) as c, pytest.raises(httpx.ReadTimeout):
            c.post("/api/cases", json={"title": "held"})
        assert len(upstream.arrivals) == 1  # it got there before the client gave up
        assert p.answered.is_set()


def test_dropping_after_send_leaves_the_client_without_an_answer(
    tls: Any, upstream: Upstream
) -> None:
    with proxy(tls, upstream, drop_after_send=0.0) as p:
        with client(tls, p.port, timeout=TIMEOUT) as c, pytest.raises(httpx.ReadTimeout):
            c.post("/api/cases", json={"title": "dropped"})
        assert p.forwarded.is_set()
        assert not p.answered.is_set()
        assert "upstream dropped" in [what for _, what in p.events]


def test_a_drop_while_the_server_still_handles_the_request_is_told_apart(tls: Any) -> None:
    """Review F6: the #13 test dropped the connection 0.5 s after sending and could not tell a
    create Kibana had already answered from one it was still handling. The proxy now says
    whether any of the answer had arrived when it dropped."""
    slow = Upstream(tls.kibana_tls / "kibana.crt", tls.kibana_tls / "kibana.key", answer_delay=1.0)
    slow.start()
    try:
        with proxy(tls, slow, drop_after_send=0.3) as p:
            with client(tls, p.port, timeout=TIMEOUT) as c, pytest.raises(httpx.ReadTimeout):
                c.post("/api/cases", json={"title": "still handled"})
            assert p.dropped_unanswered.is_set()
            assert not p.answered_before_drop.is_set()
    finally:
        slow.stop()


def test_a_drop_after_the_answer_began_is_told_apart(tls: Any, upstream: Upstream) -> None:
    with proxy(tls, upstream, drop_after_send=0.5) as p:
        with client(tls, p.port, timeout=TIMEOUT) as c, pytest.raises(httpx.ReadTimeout):
            c.post("/api/cases", json={"title": "answered already"})
        assert p.answered_before_drop.is_set()  # the server had answered within 0.5 s
        assert not p.dropped_unanswered.is_set()


def test_a_client_of_another_ca_cannot_tell_it_is_kibana(
    tls: Any, upstream: Upstream, tmp_path: Path
) -> None:
    other = tier_script.Paths(tmp_path / "other")
    tier_script.ensure_certificates(other, now=datetime.now(UTC))
    with (
        proxy(tls, upstream) as p,
        client(other, p.port) as c,
        pytest.raises(httpx.ConnectError),
    ):
        c.get("/api/status")
    assert not upstream.arrivals


def test_request_head_helpers() -> None:
    head = b"POST /x HTTP/1.1\r\nHost: a\r\nConnection: keep-alive\r\nContent-Length: 12"
    assert _content_length(head) == 12
    assert _content_length(b"GET / HTTP/1.1\r\nHost: a") == 0
    rewritten = _with_connection_close(head)
    assert rewritten.endswith(b"\r\nConnection: close")
    assert b"keep-alive" not in rewritten
