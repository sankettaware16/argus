"""A stand-in for the local model machine (Q-G1): Caddy and llama-server b11476 as ARGUS sees
them through the tunnel, on a loopback port of its own (never 18443: the guard refuses it).

The certificate is made by the exact ``openssl req`` command a self-hosted model's setup
runs (``OPENSSL``), so the tests check the certificate a real run makes: a self-signed
CA:FALSE leaf for 127.0.0.1. Where the first installation's setup script exists
(``deploy/local-llm/setup-llm-machine.sh``, not in the public tree) a test holds its command
to this one.

The server checks the key as Caddy does (``Authorization: Bearer <key>``, else 401
"refused"), lists the model on ``GET /v1/models`` and answers ``POST /v1/chat/completions`` the
way llama-server does for a model that thinks first: the reasoning in ``reasoning_content``,
the JSON answer in ``content``, a ``finish_reason``. ``mode`` switches it to the failures the
gateway must tell apart.
"""

from __future__ import annotations

import json
import re
import shlex
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tests.conftest import private_text

SCRIPT = Path(__file__).resolve().parents[3] / "deploy" / "local-llm" / "setup-llm-machine.sh"
# The setup's certificate command: 3072-bit RSA, 825 days, the loopback address as its only
# name, not a CA, for a server.
OPENSSL = (
    'openssl req -x509 -newkey rsa:3072 -nodes -days 825 -sha256 -subj "/CN=ARGUS local LLM"'
    ' -addext "subjectAltName=IP:127.0.0.1" -addext "basicConstraints=critical,CA:FALSE"'
    ' -addext "extendedKeyUsage=serverAuth" -keyout "$CERT_DIR/llm.key"'
    ' -out "$CERT_DIR/llm.crt"'
)
MODEL = "cyber-prime-1.2"
KEY = "0123456789abcdef" * 4  # 64 hex characters, as the setup's `openssl rand -hex 32`


def script_command() -> list[str]:
    """The setup script's own certificate command (the test is skipped in the public tree)."""
    text = private_text(SCRIPT).replace("\\\n", " ")
    found = re.search(r"openssl req -x509 .*?-out \"\$CERT_DIR/llm\.crt\"", text)
    assert found is not None, "the setup script no longer makes its certificate this way"
    return shlex.split(found.group(0))


def openssl_command(cert_dir: Path) -> list[str]:
    """The setup's certificate command, with its folder replaced."""
    return [a.replace("$CERT_DIR", str(cert_dir)) for a in shlex.split(OPENSSL)]


def make_certificate(cert_dir: Path) -> Path:
    """Run the setup script's command: ``llm.crt`` and ``llm.key`` in ``cert_dir``."""
    cert_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(openssl_command(cert_dir), check=True, capture_output=True)  # noqa: S603
    return cert_dir / "llm.crt"


@dataclass
class Machine:
    """What the stand-in does; a test changes it while the server runs."""

    key: str = KEY
    model: str = MODEL
    mode: str = "ok"  # ok, loading, overflow, cut_off, think_only, slow, server_error
    answer: str = '{"ok": true}'
    reasoning: str = "The user wants JSON with ok set to true. I will answer that."
    delay_s: float = 0.0
    seen: list[dict[str, Any]] = field(default_factory=list)  # method, path, headers, body
    # Q-G2: a weaker setup than D-108's, for the hardening check: paths answered 200 with any
    # key (llama-server's own pages), and the key not checked at all
    exposed: frozenset[str] = frozenset()
    keyless: bool = False
    context_chars: int = 60_000  # a prompt longer than this: llama-server's overflow 400


def _handler(machine: Machine) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: Any) -> None:
            pass

        def _reply(self, status: int, payload: Any) -> None:
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            return machine.keyless or self.headers.get("Authorization") == f"Bearer {machine.key}"

        def do_GET(self) -> None:
            machine.seen.append({"method": "GET", "path": self.path,
                                 "headers": dict(self.headers)})  # fmt: skip
            if self.path in machine.exposed:
                return self._reply(200, {"status": "ok"})
            if self.path != "/v1/models" or not self._authorized():
                return self._reply(401, b"refused")
            if machine.mode == "loading":
                return self._reply(503, {"error": {"code": 503, "message": "Loading model",
                                                   "type": "unavailable_error"}})  # fmt: skip
            self._reply(200, {"object": "list", "data": [
                {"id": machine.model, "object": "model", "owned_by": "llamacpp"}]})  # fmt: skip

        def do_POST(self) -> None:
            size = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(size) or b"{}")
            machine.seen.append({"method": "POST", "path": self.path,
                                 "headers": dict(self.headers), "body": body})  # fmt: skip
            if self.path != "/v1/chat/completions" or not self._authorized():
                return self._reply(401, b"refused")
            if machine.delay_s:
                time.sleep(machine.delay_s)
            if machine.mode == "loading":
                return self._reply(503, {"error": {"code": 503, "message": "Loading model",
                                                   "type": "unavailable_error"}})  # fmt: skip
            prompt = sum(len(str(m.get("content") or "")) for m in body.get("messages") or [])
            if machine.mode == "overflow" or prompt > machine.context_chars:
                return self._reply(400, {"error": {
                    "code": 400, "type": "exceed_context_size_error", "n_prompt_tokens": 17000,
                    "n_ctx": 16384,
                    "message": "the request exceeds the available context size"}})  # fmt: skip
            if machine.mode == "server_error":
                return self._reply(500, {"error": {"code": 500, "type": "server_error"}})
            if body.get("model") != machine.model:
                return self._reply(400, {"error": {"code": 400, "type": "invalid_request_error",
                                                   "message": "model not found"}})  # fmt: skip
            content, finish = machine.answer, "stop"
            if machine.mode == "cut_off":  # the cap ran out part way into the answer
                content, finish = machine.answer[: len(machine.answer) // 2], "length"
            if machine.mode == "think_only":  # the cap ran out while it was still thinking
                content, finish = "", "length"
            self._reply(200, {
                "id": "chatcmpl-1", "object": "chat.completion", "model": machine.model,
                "choices": [{"index": 0, "finish_reason": finish, "message": {
                    "role": "assistant", "content": content,
                    "reasoning_content": machine.reasoning}}],
                "usage": {"prompt_tokens": 120, "completion_tokens": 64, "total_tokens": 184},
            })  # fmt: skip

    return Handler


class _Quiet(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass  # a client that refused the certificate: expected in these tests


@contextmanager
def serving(cert: Path, machine: Machine) -> Iterator[int]:
    """The stand-in on 127.0.0.1 at a free port (yielded), with ``cert`` and its key."""
    server = _Quiet(("127.0.0.1", 0), _handler(machine))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, cert.with_suffix(".key"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    port = server.server_address[1]
    assert port != 18443
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(5)


@contextmanager
def closing_listener() -> Iterator[int]:
    """A port that accepts and closes at once: the tunnel's SSH listener when the model
    machine is off behind it."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    stop = threading.Event()

    def accept() -> None:
        listener.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(5)
        listener.close()


def free_port() -> int:
    """A loopback port nothing listens on (as far as one can tell)."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
