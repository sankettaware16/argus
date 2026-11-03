"""The independent reviewer's unit repros for Q-H4 (docs/gates/q-h4-review.md). Each test is named
for its finding (``test_r<N>_...``) and fails on the reviewed tree (850610e) for the reason the
review gives. Loopback only: the "relay" is a throwaway socket server on 127.0.0.1 in this file;
nothing contacts the SIEM or any real host."""

from __future__ import annotations

import socketserver
import threading
import time

import pytest

from argus.config.settings import NoticesSettings, WebSettings
from argus.notices import mail, render
from argus.notices.model import Target

SENDER = "argus@example.org"
TO = "ta@example.org"


class Endless:
    """A relay whose reply to EHLO never ends: either an endless run of continuation lines
    (``250-x``) sent as fast as it can, or one line every ``pause`` seconds (a slow drip that
    stays inside any per-read timeout). ``stop`` ends it."""

    def __init__(self, pause: float) -> None:
        self.stop = threading.Event()
        self.lines = 0
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                self.wfile.write(b"220 endless ESMTP\r\n")
                self.wfile.flush()
                if not self.rfile.readline():
                    return
                try:
                    while not owner.stop.is_set():
                        self.wfile.write(b"250-more\r\n" * (1 if pause else 200))
                        self.wfile.flush()
                        owner.lines += 1
                        time.sleep(pause or 0.001)
                except OSError:
                    return

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.host, self.port = "127.0.0.1", self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> Endless:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.parametrize(
    ("pause", "kind"),
    [(0.0, "ReplyTooLong"), (0.3, "TimeoutError")],
    ids=["a flood of continuation lines", "a slow drip"],
)
def test_r1_a_relay_that_never_finishes_its_reply_cannot_hold_the_pass(
    pause: float, kind: str
) -> None:
    """``smtplib`` reads a multi-line reply until a line without ``-``, with no limit on the
    number of lines and a timeout per read, not per exchange: the flood grows memory without
    bound and the drip is never "too slow". ``deliver`` has no deadline of its own, so the pass
    (and its advisory lock) lasts until systemd kills the unit at ``TimeoutStartSec`` - after the
    relay may have taken messages that nothing marked (finding 2). The fix: ``Relay.deadline``
    (a timer that cuts the connection; 2 seconds here, 60 by default) and a cap on the lines and
    bytes of one reply."""
    message = mail.build_message(SENDER, [TO], "[ARGUS High] x", "a body\n")
    done = threading.Event()
    result: list[object] = []

    def call(port: int) -> None:
        relay = mail.Relay("127.0.0.1", port, False, timeout=0.5, deadline=2.0)
        result.append(mail.deliver(relay, SENDER, [TO], [message]))
        done.set()

    with Endless(pause) as server:
        worker = threading.Thread(target=call, args=(server.port,), daemon=True)
        worker.start()
        finished = done.wait(5)
        server.stop.set()  # let the relay thread end so the test does not leak
        worker.join(5)
    assert finished, "deliver() was still reading the relay's reply after 5 seconds"
    assert result == [[mail.Delivery(False, kind)]]  # the cap or the deadline, said by its kind


@pytest.mark.parametrize(
    "web",
    [
        {"web_url": "https://-a"},
        {"web_url": "https://."},
        {"allowed_hosts": ("Argus.Example.org",)},
        {"allowed_hosts": ("argus.example.org:8443",)},
    ],
    ids=["leading hyphen", "a dot", "upper case allowed host", "allowed host with a port"],
)
def test_r8_the_link_address_the_settings_accept_is_one_the_notices_can_write(
    web: dict[str, object],
) -> None:
    """``render.link`` accepts a base like ``https://argus.example.org`` only. The settings
    accept hosts it refuses (``_public_url`` allows a leading ``-`` or ``.``; ``allowed_hosts``
    is unchecked and feeds ``web.link_base``). A refused base raises ValueError inside every
    pass that has something due - before anything is stored, even while notices are off - and
    ``argus doctor`` says PASS."""
    try:  # a setting refused at load is a fine answer too (pydantic's error is a ValueError)
        notices = NoticesSettings(web_url=web.get("web_url"))  # type: ignore[arg-type]
        shown = WebSettings(allowed_hosts=web.get("allowed_hosts", ()))  # type: ignore[arg-type]
    except ValueError:
        return
    base = notices.link_base(shown)
    assert render.link(base, Target("home")).startswith(base)


def test_r8_production_names_the_machine_with_capitals_and_it_loads_in_lower_case() -> None:
    """The web's unit sets ``10.13.171.247,devuser-System-Product-Name``: a host name has no
    case, so the setting keeps it, lower-cased, and the links are written with that."""
    web = WebSettings(allowed_hosts=("10.13.171.247", "devuser-System-Product-Name"))  # type: ignore[arg-type]
    assert web.allowed_hosts == ("10.13.171.247", "devuser-system-product-name")
