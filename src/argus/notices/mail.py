"""The message and the campus relay (Q-H4, DQ26).

A message is built from addresses :func:`argus.notices.address.parse_address` accepted, a subject
and a body made of fixed text and numbers (:mod:`argus.notices.render`), so no header can be
added or folded in by a value: the sender, the recipients and the subject are checked here again
before the standard library writes them, and a line break in a header is an error in the
library itself. Sending is the standard library's ``smtplib`` in a thread: no dependency.

``starttls`` is never silently dropped: when it is on and the relay does not offer it, nothing is
sent. A login happens only after TLS (or to the loopback), by the settings' own rule. The relay's
reply text is not kept: a failure is reported by the kind of error alone.

A relay cannot hold a pass: the whole conversation has a deadline of its own
(:data:`DEADLINE_S`, a timer that cuts the connection, because a read timeout alone is reset by
every line a relay drips) and one reply is limited in lines and bytes (:data:`MAX_REPLY_LINES`,
:data:`MAX_REPLY_BYTES`; ``smtplib`` itself keeps every continuation line). Over either, the
messages not yet taken fail and the pass goes on.
"""

from __future__ import annotations

import asyncio
import logging
import re
import smtplib
import socket
import ssl
import threading
from collections.abc import Callable, Coroutine, Sequence
from contextlib import suppress
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any, cast

from argus.notices.address import domain_of, parse_address

log = logging.getLogger("argus.notices")
# every control character but the line feed and the tab (a carriage return would end a line)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

TIMEOUT_S = 30.0  # one wait for the relay (connect, read, write)
DEADLINE_S = 60.0  # the whole conversation, whatever the relay does in between
MAX_REPLY_LINES = 64  # a multi-line reply (EHLO) is about ten lines
MAX_REPLY_BYTES = 16384
MAX_SUBJECT = 200


class MailError(Exception):
    """A message that must not be built (a hostile or malformed part); its text never echoes the
    part."""


def build_message(
    sender: str, recipients: Sequence[str], subject: str, body: str, *, test: bool = False
) -> EmailMessage:
    """One plain-text message to ``recipients`` (all in ``To``). Raises :class:`MailError` for an
    address that is not one plain address, an empty recipient list, or a subject or body with
    anything but printable ASCII (a body may have line feeds)."""
    try:
        sender = parse_address(sender)
        wanted = [parse_address(r) for r in recipients]
    except ValueError:
        raise MailError("an address is not one plain e-mail address") from None
    if not wanted:
        raise MailError("a message needs a recipient")
    if (
        not subject
        or len(subject) > MAX_SUBJECT
        or not subject.isascii()
        or not subject.isprintable()
    ):
        raise MailError("the subject is one line of printable ASCII")
    if not body.isascii() or _CONTROL.search(body) is not None:
        raise MailError("the body is ASCII text with line feeds only")
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(wanted)
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=False, usegmt=True)
    message["Message-ID"] = make_msgid(domain=domain_of(sender))
    message["Auto-Submitted"] = "auto-generated"
    message["X-Auto-Response-Suppress"] = "All"
    message["X-ARGUS"] = "test" if test else "notice"
    message.set_content(body)
    return message


@dataclass(frozen=True)
class Relay:
    """Where to send: the campus relay's address, whether to require TLS, and an optional login
    (the password is never shown or logged)."""

    host: str
    port: int
    starttls: bool
    user: str | None = None
    password: str | None = None
    timeout: float = TIMEOUT_S
    deadline: float = DEADLINE_S

    def __repr__(self) -> str:
        return (
            f"Relay({self.host}:{self.port}, starttls={self.starttls},"
            f" login={'yes' if self.user else 'no'})"
        )


@dataclass(frozen=True)
class Delivery:
    """How one message went: sent, or why not (the kind of error, never the relay's reply)."""

    ok: bool
    error: str | None = None


OnResult = Callable[[int, Delivery], None]
AsyncOnResult = Callable[[int, Delivery], Coroutine[Any, Any, None]]


class _CappedReply:
    """The reply file of the connection, counting the lines and bytes of the reply being read
    (``smtplib`` reads a multi-line reply until a line without a hyphen, however long it is)."""

    def __init__(self, file: Any, owner: _Smtp) -> None:
        self._file = file
        self._owner = owner
        self.lines = 0
        self.size = 0

    def readline(self, limit: int = -1) -> bytes:
        line: bytes = self._file.readline(limit)
        self.lines += 1
        self.size += len(line)
        if self.lines > MAX_REPLY_LINES or self.size > MAX_REPLY_BYTES:
            self._owner.why = "ReplyTooLong"
            raise OSError("the relay's reply is too long")
        return line

    def close(self) -> None:
        self._file.close()


class _Smtp(smtplib.SMTP):
    """``smtplib.SMTP`` whose replies are limited (see :class:`_CappedReply`)."""

    why: str | None = None  # the kind of failure this class saw, when it is not the library's
    _capped: _CappedReply | None = None

    def getreply(self) -> tuple[int, bytes]:
        if self.file is None:
            if self.sock is None:
                raise smtplib.SMTPServerDisconnected("please run connect() first")
            self._capped = _CappedReply(self.sock.makefile("rb"), self)
            self.file = cast(Any, self._capped)
        if self._capped is not None:
            self._capped.lines = self._capped.size = 0
        return super().getreply()


def _cut(server: _Smtp, expired: threading.Event) -> None:
    """The deadline passed: end the conversation, whatever the thread is waiting for."""
    expired.set()
    sock = server.sock
    if sock is not None:
        with suppress(OSError):
            sock.shutdown(socket.SHUT_RDWR)
        with suppress(OSError):
            sock.close()


def _kind(exc: BaseException, server: _Smtp, expired: threading.Event) -> str:
    if expired.is_set():
        return "TimeoutError"
    return server.why or type(exc).__name__


def deliver(
    relay: Relay,
    sender: str,
    recipients: Sequence[str],
    messages: Sequence[EmailMessage],
    on_result: OnResult | None = None,
) -> list[Delivery]:
    """Send ``messages`` over one connection (blocking: call it in a thread). A relay that
    cannot be reached or will not do TLS or the login fails every message; one that refuses a
    single message fails that one. Partly refused recipients still count as sent when at least
    one was taken. The whole conversation lasts at most ``relay.deadline`` seconds (the messages
    not yet taken fail with ``TimeoutError``); ``on_result(index, delivery)`` is called as soon
    as each message has its answer, so the caller can record it before the next one is sent."""
    if not messages:
        return []
    try:  # the envelope is checked again here: whatever built the messages, only plain addresses
        sender = parse_address(sender)
        wanted = [parse_address(r) for r in recipients]
    except ValueError:
        return [Delivery(False, "MailError")] * len(messages)
    if not wanted:
        return [Delivery(False, "MailError")] * len(messages)
    expired = threading.Event()
    server = _Smtp(timeout=min(relay.timeout, relay.deadline))  # not connected yet
    timer = threading.Timer(relay.deadline, _cut, (server, expired))
    timer.daemon = True
    out: list[Delivery] = []
    try:
        timer.start()
        with server:
            server.connect(relay.host, relay.port)
            if expired.is_set():
                raise TimeoutError("the deadline passed")
            server.ehlo()
            if relay.starttls:
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if relay.user is not None and relay.password is not None:
                server.login(relay.user, relay.password)
            for index, message in enumerate(messages):
                try:
                    server.send_message(message, from_addr=sender, to_addrs=wanted)
                    result, go_on = Delivery(True), True
                except (smtplib.SMTPException, OSError) as exc:
                    result = Delivery(False, _kind(exc, server, expired))
                    refused = smtplib.SMTPRecipientsRefused | smtplib.SMTPResponseException
                    go_on = isinstance(exc, refused) and not expired.is_set()
                out.append(result)
                if on_result is not None:
                    on_result(index, result)
                if not go_on:
                    break  # the connection is no use any more
            out += [Delivery(False, "NotSent")] * (len(messages) - len(out))
            return out
    except (smtplib.SMTPException, OSError, ssl.SSLError, ValueError) as exc:
        kind = _kind(exc, server, expired)
        log.warning("notice relay failed: %s", kind)
        return out + [Delivery(False, kind)] * (len(messages) - len(out))
    finally:
        timer.cancel()


async def send(
    relay: Relay,
    sender: str,
    recipients: Sequence[str],
    messages: Sequence[EmailMessage],
    on_result: AsyncOnResult | None = None,
) -> list[Delivery]:
    """:func:`deliver` in a worker thread. ``on_result`` is a coroutine function, awaited on this
    loop (the worker waits for it) after each message, before the next one is sent."""
    loop = asyncio.get_running_loop()

    def told(index: int, result: Delivery) -> None:
        if on_result is not None:
            asyncio.run_coroutine_threadsafe(on_result(index, result), loop).result()

    return await asyncio.to_thread(deliver, relay, sender, recipients, messages, told)
