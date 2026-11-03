"""A small SMTP server for the notices' tests (Q-H4): asyncio and the standard library only,
listening on the loopback, running in a thread of its own so that a blocking ``smtplib`` client
(``argus.notices.mail.deliver``) and a test's event loop can both talk to it.

It records everything a relay would see: every command line it was sent, each message's envelope
(``MAIL FROM`` and each ``RCPT TO``) and its body exactly as received, and each login. It can
refuse recipients or the data, advertise or not advertise STARTTLS and AUTH, and drop the
connection, to test what the client does then. It speaks no TLS: tests of STARTTLS use a stub
for ``smtplib.SMTP``.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import email
import re
import threading
from collections.abc import Iterable
from dataclasses import dataclass, field
from email.message import Message
from types import TracebackType
from typing import Self


@dataclass
class Received:
    mail_from: str
    rcpt_to: list[str]
    data: bytes

    @property
    def message(self) -> Message:
        return email.message_from_bytes(self.data)

    @property
    def headers(self) -> list[tuple[str, str]]:
        """The headers as a client reads them: a long one is folded on the wire (a line break
        and a space), and unfolded here."""
        return [
            (name, re.sub(r"\r?\n[ \t]+", " ", value).strip())
            for name, value in self.message.items()
        ]


@dataclass
class FakeSmtp:
    """``refuse``: recipients answered 550. ``refuse_data``: DATA answered 554. ``starttls``:
    advertise STARTTLS (the server cannot do it: a client that asks is told 454). ``login``:
    (user, password) to require (AUTH PLAIN is advertised). ``drop``: close the connection as
    soon as it opens; ``drop_after``: after that many messages."""

    refuse: Iterable[str] = ()
    refuse_data: bool = False
    starttls: bool = False
    login: tuple[str, str] | None = None
    drop: bool = False
    drop_after: int | None = None  # close the connection once this many messages were taken
    host: str = "127.0.0.1"
    port: int = 0
    received: list[Received] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    logins: list[tuple[str, str]] = field(default_factory=list)
    connections: int = 0

    def __post_init__(self) -> None:
        self.refuse = {r.lower() for r in self.refuse}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ready = threading.Event()
        self._stop: asyncio.Event | None = None

    # ------------------------------------------------------------------ running

    def __enter__(self) -> Self:
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        if not self._ready.wait(10):
            raise RuntimeError("the fake relay did not start")
        return self

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        trace: TracebackType | None,
    ) -> None:
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread is not None:
            self._thread.join(10)

    def _serve(self) -> None:
        asyncio.run(self._main())

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        server = await asyncio.start_server(self._client, self.host, 0)
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        async with server:
            await self._stop.wait()

    # ------------------------------------------------------------------ the protocol

    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1

        async def say(*lines: str) -> None:
            writer.write("".join(f"{line}\r\n" for line in lines).encode())
            await writer.drain()

        try:
            if self.drop:
                return
            await say("220 fake.relay ESMTP ready")
            mail_from = ""
            rcpt: list[str] = []
            authed = self.login is None
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                self.commands.append(line)
                verb = line.split(" ", 1)[0].upper()
                if verb in ("EHLO", "HELO"):
                    lines = ["250-fake.relay", "250-8BITMIME"]
                    if self.starttls:
                        lines.append("250-STARTTLS")
                    if self.login is not None:
                        lines.append("250-AUTH PLAIN")
                    await say(*lines, "250 SIZE 1000000")
                elif verb == "STARTTLS":
                    await say("454 TLS not available")
                elif verb == "AUTH":
                    parts = line.split()
                    try:
                        _, user, password = base64.b64decode(parts[2]).decode().split("\0")
                    except (IndexError, ValueError):
                        await say("501 bad AUTH")
                        continue
                    self.logins.append((user, password))
                    authed = (user, password) == self.login
                    await say("235 ok" if authed else "535 no")
                elif verb == "MAIL":
                    if not authed:
                        await say("530 authentication required")
                        continue
                    mail_from, rcpt = _address(line), []
                    await say("250 ok")
                elif verb == "RCPT":
                    address = _address(line)
                    if address.lower() in self.refuse:
                        await say("550 no such user")
                    else:
                        rcpt.append(address)
                        await say("250 ok")
                elif verb == "DATA":
                    if not rcpt:
                        await say("503 need RCPT")
                        continue
                    await say("354 end with <CRLF>.<CRLF>")
                    body = await _data(reader)
                    if self.refuse_data:
                        await say("554 refused")
                    else:
                        self.received.append(Received(mail_from, list(rcpt), body))
                        await say("250 queued")
                        if self.drop_after is not None and len(self.received) >= self.drop_after:
                            return
                    mail_from, rcpt = "", []
                elif verb == "RSET":
                    mail_from, rcpt = "", []
                    await say("250 ok")
                elif verb == "NOOP":
                    await say("250 ok")
                elif verb == "QUIT":
                    await say("221 bye")
                    return
                else:
                    await say("500 what?")
        except (ConnectionError, asyncio.IncompleteReadError):
            return
        finally:
            writer.close()
            with contextlib.suppress(ConnectionError, OSError):
                await writer.wait_closed()


def _address(line: str) -> str:
    start, end = line.find("<"), line.rfind(">")
    return line[start + 1 : end] if 0 <= start < end else line.split(":", 1)[-1].strip()


async def _data(reader: asyncio.StreamReader) -> bytes:
    """The message up to the lone dot, dot-unstuffed, as received (CRLF line ends)."""
    lines = []
    while True:
        line = await reader.readline()
        if line in (b".\r\n", b""):
            break
        lines.append(line[1:] if line.startswith(b"..") else line)
    return b"".join(lines)
