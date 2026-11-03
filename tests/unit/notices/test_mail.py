"""The message and the campus relay (Q-H4): a message built only from checked parts, the exact
bytes a relay receives, hostile inputs refused before anything leaves, and what the client does
when the relay is down, refuses, will not do TLS or the login. A real SMTP conversation on the
loopback (``tests/fakesmtp.py``)."""

from __future__ import annotations

import dataclasses
import email.policy
import logging
import re
import ssl
from collections.abc import Sequence
from typing import Any, ClassVar

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.notices import mail
from argus.notices.mail import Delivery, MailError, Relay
from tests.fakesmtp import FakeSmtp

pytestmark = pytest.mark.unit

SENDER = "argus@example.org"
TO = ["ta@example.org", "ra@example.org"]
SUBJECT = "[ARGUS High] A confirmed case is still active"
BODY = "Line one.\n\nSeverity: High\nhttps://argus.example.org/go/case/x\n"
HEADERS = {"From", "To", "Subject", "Date", "Message-ID", "Auto-Submitted",
           "X-Auto-Response-Suppress", "X-ARGUS", "MIME-Version", "Content-Type",
           "Content-Transfer-Encoding"}  # fmt: skip


def relay_for(server: FakeSmtp, **changes: Any) -> Relay:
    base = {"host": server.host, "port": server.port, "starttls": False}
    return Relay(**{**base, **changes})


# --------------------------------------------------------------------------- building


def test_a_message_has_the_headers_a_notice_needs_and_no_others() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    assert {name for name, _ in message.items()} == HEADERS
    assert message["From"] == SENDER
    assert message["To"] == "ta@example.org, ra@example.org"
    assert message["Subject"] == SUBJECT
    assert message["Auto-Submitted"] == "auto-generated"
    assert message["X-ARGUS"] == "notice"
    assert message.get_content() == BODY
    assert mail.build_message(SENDER, TO, SUBJECT, BODY, test=True)["X-ARGUS"] == "test"


@pytest.mark.parametrize(
    ("sender", "recipients", "subject", "body"),
    [
        ("argus@example.org\r\nBcc: x@example.org", TO, SUBJECT, BODY),
        ("Name <argus@example.org>", TO, SUBJECT, BODY),
        (SENDER, ["ta@example.org\r\nBcc: evil@example.org"], SUBJECT, BODY),
        (SENDER, ["ta@example.org, evil@example.org"], SUBJECT, BODY),
        (SENDER, ["ta@example.org>\r\nRCPT TO:<evil@example.org"], SUBJECT, BODY),
        (SENDER, [], SUBJECT, BODY),
        (SENDER, TO, "", BODY),
        (SENDER, TO, "Hello\r\nBcc: evil@example.org", BODY),
        (SENDER, TO, "Hello\nBcc: evil@example.org", BODY),
        (SENDER, TO, "Hello\x00", BODY),
        (SENDER, TO, "Hello \u2028 world", BODY),
        (SENDER, TO, "Håll", BODY),
        (SENDER, TO, "x" * 201, BODY),
        (SENDER, TO, SUBJECT, "line\r\nBcc: evil@example.org"),
        (SENDER, TO, SUBJECT, "nul\x00byte"),
        (SENDER, TO, SUBJECT, "escape\x1b[31m"),
        (SENDER, TO, SUBJECT, "Håll"),
    ],
)  # fmt: skip
def test_hostile_parts_are_refused_before_anything_is_built(
    sender: str, recipients: Sequence[str], subject: str, body: str
) -> None:
    with pytest.raises(MailError):
        mail.build_message(sender, recipients, subject, body)


def test_a_refusal_never_echoes_the_hostile_part() -> None:
    with pytest.raises(MailError) as refused:
        mail.build_message(SENDER, ["secret-evil@example.org\r\nBcc: x@y.zz"], SUBJECT, BODY)
    assert "secret-evil" not in str(refused.value)


@given(
    st.text(max_size=100),
    st.text(alphabet=st.characters(codec="ascii"), max_size=200),
)
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_property_whatever_the_subject_and_body_the_headers_are_the_ones_we_set(
    subject: str, body: str
) -> None:
    try:
        message = mail.build_message(SENDER, TO, subject, body)
    except MailError:
        return
    assert {name for name, _ in message.items()} == HEADERS
    assert "\n" not in subject
    assert "\r" not in subject
    assert message["Subject"] == subject
    wire = message.as_bytes(policy=email.policy.SMTP)
    head = wire.split(b"\r\n\r\n", 1)[0]
    assert head.count(b"\r\n") + 1 == len(HEADERS)  # one line a header: nothing was folded in
    assert b"Bcc" not in head


# --------------------------------------------------------------------------- the relay


def test_the_relay_receives_the_exact_message() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        (result,) = mail.deliver(relay_for(server), SENDER, TO, [message])
        assert result == Delivery(True)
        (got,) = server.received
    assert got.mail_from == SENDER
    assert got.rcpt_to == TO
    assert dict(got.headers)["Subject"] == SUBJECT
    assert dict(got.headers)["To"] == "ta@example.org, ra@example.org"
    payload = got.message.get_payload(decode=True)
    assert isinstance(payload, bytes)
    assert payload.decode().replace("\r\n", "\n") == BODY  # CRLF on the wire, as SMTP wants
    assert [n for n in got.headers if n[0] == "Bcc"] == []


def test_several_messages_go_over_one_connection() -> None:
    messages = [mail.build_message(SENDER, TO, f"{SUBJECT} {n}", BODY) for n in range(3)]
    with FakeSmtp() as server:
        results = mail.deliver(relay_for(server), SENDER, TO, messages)
        assert [r.ok for r in results] == [True] * 3
        assert server.connections == 1
        assert [dict(r.headers)["Subject"] for r in server.received] == [
            f"{SUBJECT} {n}" for n in range(3)
        ]
    assert (
        mail.deliver(Relay("127.0.0.1", 9, False), SENDER, TO, []) == []
    )  # nothing: no connection


def test_a_recipient_the_relay_refuses_does_not_stop_the_others() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(refuse=["ra@example.org"]) as server:
        (result,) = mail.deliver(relay_for(server), SENDER, TO, [message])
        assert result.ok
        assert server.received[0].rcpt_to == ["ta@example.org"]


def test_every_recipient_refused_is_a_failure() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(refuse=TO) as server:
        (result,) = mail.deliver(relay_for(server), SENDER, TO, [message])
        assert result == Delivery(False, "SMTPRecipientsRefused")
        assert server.received == []


def test_a_message_the_relay_refuses_fails_alone() -> None:
    one = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(refuse_data=True) as server:
        results = mail.deliver(relay_for(server), SENDER, TO, [one, one])
        assert [r.ok for r in results] == [False, False]
        assert {r.error for r in results} == {"SMTPDataError"}


def test_a_relay_that_is_down_fails_every_message_without_an_exception() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        port = server.port
    results = mail.deliver(Relay("127.0.0.1", port, False, timeout=2), SENDER, TO, [message] * 2)
    assert [r.ok for r in results] == [False, False]
    assert results[0].error == "ConnectionRefusedError"


def test_a_relay_that_hangs_up_fails_every_message() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(drop=True) as server:
        results = mail.deliver(relay_for(server), SENDER, TO, [message])
    assert [r.ok for r in results] == [False]
    assert results[0].error == "SMTPServerDisconnected"


def test_the_envelope_is_checked_again_at_the_door() -> None:
    """Whatever built the messages, only plain addresses reach the relay's commands."""
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        for sender, recipients in [
            ("argus@example.org>\r\nRCPT TO:<evil@example.org", TO),
            (SENDER, ["ta@example.org>\r\nRCPT TO:<evil@example.org"]),
            (SENDER, ["ta@example.org\r\nDATA"]),
            (SENDER, []),
        ]:
            assert mail.deliver(relay_for(server), sender, recipients, [message]) == [
                Delivery(False, "MailError")
            ]
        assert server.connections == 0
        assert server.commands == []


# --------------------------------------------------------------------------- TLS and the login


def test_starttls_is_required_not_hoped_for() -> None:
    """The relay does not offer STARTTLS: nothing is sent and no login is tried (no downgrade)."""
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(login=("argus", "pw")) as server:
        relay = relay_for(server, starttls=True, user="argus", password="pw")
        (result,) = mail.deliver(relay, SENDER, TO, [message])
        assert result == Delivery(False, "SMTPNotSupportedError")
        assert server.received == []
        assert server.logins == []
        assert not any(c.upper().startswith(("MAIL", "AUTH")) for c in server.commands)


def test_starttls_the_relay_offers_and_cannot_do_is_a_failure_too() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(starttls=True) as server:
        (result,) = mail.deliver(relay_for(server, starttls=True), SENDER, TO, [message])
        assert result.ok is False
        assert server.received == []


class Recorder:
    """A stand-in for the library's connection (``mail._Smtp``) that records the order of the
    conversation."""

    calls: ClassVar[list[str]] = []
    sock = None
    why = None

    def __init__(self, timeout: float = 0) -> None:
        self.timeout = timeout

    def connect(self, host: str, port: int) -> None:
        self.calls.append(f"connect {host}:{port} timeout={self.timeout}")

    def __enter__(self) -> Recorder:
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append("close")

    def ehlo(self) -> None:
        self.calls.append("ehlo")

    def starttls(self, context: ssl.SSLContext) -> None:
        assert context.verify_mode is ssl.CERT_REQUIRED
        assert context.check_hostname is True
        self.calls.append("starttls")

    def login(self, user: str, password: str) -> None:
        self.calls.append(f"login {user}")

    def send_message(self, message: Any, from_addr: str, to_addrs: list[str]) -> dict[str, Any]:
        self.calls.append(f"send {from_addr} -> {','.join(to_addrs)}")
        return {}


def test_the_login_happens_after_tls_and_the_certificate_is_checked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    Recorder.calls = []
    monkeypatch.setattr(mail, "_Smtp", Recorder)
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    relay = Relay("mail.example.org", 587, True, "argus", "s3cret", timeout=7)
    assert mail.deliver(relay, SENDER, TO, [message]) == [Delivery(True)]
    assert Recorder.calls == [
        "connect mail.example.org:587 timeout=7",
        "ehlo",
        "starttls",
        "ehlo",
        "login argus",
        "send argus@example.org -> ta@example.org,ra@example.org",
        "close",
    ]


def test_without_starttls_there_is_none_and_without_a_user_no_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    Recorder.calls = []
    monkeypatch.setattr(mail, "_Smtp", Recorder)
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    mail.deliver(Relay("localhost", 25, False), SENDER, TO, [message])
    assert "starttls" not in Recorder.calls
    assert not [c for c in Recorder.calls if c.startswith("login")]


def test_the_login_reaches_the_relay_and_a_wrong_one_is_a_failure() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(login=("argus", "right")) as server:
        ok = mail.deliver(relay_for(server, user="argus", password="right"), SENDER, TO, [message])
        assert ok == [Delivery(True)]
        bad = mail.deliver(relay_for(server, user="argus", password="WRONG"), SENDER, TO, [message])
        assert bad == [Delivery(False, "SMTPAuthenticationError")]
        assert server.logins == [("argus", "right"), ("argus", "WRONG")]
        assert len(server.received) == 1


def test_the_password_is_in_no_repr_and_no_failure_text() -> None:
    relay = Relay("mail.example.org", 587, True, "argus", "Synthetic-Relay-11")
    assert "Synthetic-Relay-11" not in repr(relay)
    assert "Synthetic-Relay-11" not in str(relay)
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(login=("argus", "other")) as server:
        bad = mail.deliver(
            relay_for(server, user="argus", password="Synthetic-Relay-11"), SENDER, TO, [message]
        )
    assert "Synthetic-Relay-11" not in repr(bad)


# --------------------------------------------------------------------------- exactly what is said


def test_the_refusals_use_these_words_and_the_limits_are_exact() -> None:
    with pytest.raises(MailError, match=r"^an address is not one plain e-mail address$"):
        mail.build_message("nope", TO, SUBJECT, BODY)
    with pytest.raises(MailError, match=r"^a message needs a recipient$"):
        mail.build_message(SENDER, [], SUBJECT, BODY)
    with pytest.raises(MailError, match=r"^the subject is one line of printable ASCII$"):
        mail.build_message(SENDER, TO, "", BODY)
    with pytest.raises(MailError, match=r"^the body is ASCII text with line feeds only$"):
        mail.build_message(SENDER, TO, SUBJECT, "bad\rbody")
    assert mail.build_message(SENDER, TO, "x" * 200, BODY)["Subject"] == "x" * 200
    with pytest.raises(MailError):
        mail.build_message(SENDER, TO, "x" * 201, BODY)
    assert (mail.MAX_SUBJECT, mail.TIMEOUT_S) == (200, 30.0)


@pytest.mark.parametrize("char", [chr(c) for c in (*range(0, 9), *range(11, 32), 127)])
def test_every_control_character_but_the_line_feed_and_tab_is_refused_in_a_body(char: str) -> None:
    with pytest.raises(MailError, match="line feeds only"):
        mail.build_message(SENDER, TO, SUBJECT, f"one{char}two\n")


def test_a_body_may_have_line_feeds_tabs_and_any_letter() -> None:
    body = "Xx\tXX\nline two\n"
    message = mail.build_message(SENDER, TO, SUBJECT, body)
    assert message.get_content() == body


def test_the_date_is_utc_and_the_message_asks_not_to_be_answered() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    assert re.fullmatch(r"\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} \+0000", message["Date"])
    assert message["X-Auto-Response-Suppress"] == "All"
    assert message["Message-ID"].endswith("@example.org>")


def test_the_relay_shows_itself_without_its_password_and_cannot_be_changed() -> None:
    assert repr(Relay("mail.example.org", 587, True, "argus", "pw")) == (
        "Relay(mail.example.org:587, starttls=True, login=yes)"
    )
    assert repr(Relay("mail.example.org", 25, False)) == (
        "Relay(mail.example.org:25, starttls=False, login=no)"
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        Relay("h", 25, False).host = "other"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        Delivery(True).ok = False  # type: ignore[misc]
    assert Delivery(True) == Delivery(True, None)


def test_nothing_to_send_opens_no_connection() -> None:
    with FakeSmtp() as server:
        assert mail.deliver(relay_for(server), SENDER, TO, []) == []
        assert server.connections == 0


def test_a_login_needs_both_a_user_and_a_password() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        for user, password in (("argus", None), (None, "pw")):
            relay = relay_for(server, user=user, password=password)
            assert mail.deliver(relay, SENDER, TO, [message]) == [Delivery(True)]
        assert server.logins == []


def test_a_relay_that_drops_midway_fails_that_message_and_sends_nothing_after_it() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(drop_after=1) as server:
        results = mail.deliver(relay_for(server), SENDER, TO, [message] * 3)
        assert len(server.received) == 1
    assert results[0] == Delivery(True)
    assert results[1].ok is False
    assert results[2] == Delivery(False, "NotSent")  # no second try on a dead connection


def test_a_failure_is_logged_by_its_kind_alone(caplog: pytest.LogCaptureFixture) -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        port = server.port
    with caplog.at_level(logging.WARNING, logger="argus.notices"):
        mail.deliver(Relay("127.0.0.1", port, False, timeout=2), SENDER, TO, [message])
    assert caplog.messages == ["notice relay failed: ConnectionRefusedError"]
    assert mail.log.name == "argus.notices"


async def test_the_async_door_sends_in_a_thread() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        results = await mail.send(relay_for(server), SENDER, TO, [message])
        assert results == [Delivery(True)]
        assert len(server.received) == 1


# --------------------------------------------------------------------------- review H4 (R1, R2)


def test_each_answer_is_reported_as_it_comes_and_before_the_next_message_is_sent() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        seen: list[tuple[int, bool, int]] = []

        def told(index: int, result: Delivery) -> None:
            seen.append((index, result.ok, len(server.received)))

        results = mail.deliver(relay_for(server), SENDER, TO, [message] * 3, told)
    assert results == [Delivery(True)] * 3
    assert seen == [(0, True, 1), (1, True, 2), (2, True, 3)]  # the relay had taken index + 1


def test_a_failed_answer_is_reported_too_and_so_are_the_unsent_ones_by_the_caller() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp(drop_after=1) as server:
        seen: list[int] = []
        results = mail.deliver(
            relay_for(server), SENDER, TO, [message] * 3, lambda i, _r: seen.append(i)
        )
    assert seen == [0, 1]  # the third never had a try: the caller settles it from the result
    assert results[2] == Delivery(False, "NotSent")


async def test_the_async_door_awaits_the_callback_between_messages() -> None:
    message = mail.build_message(SENDER, TO, SUBJECT, BODY)
    with FakeSmtp() as server:
        order: list[str] = []

        async def told(index: int, result: Delivery) -> None:
            order.append(f"told {index} after {len(server.received)} received")

        await mail.send(relay_for(server), SENDER, TO, [message] * 2, told)
    assert order == ["told 0 after 1 received", "told 1 after 2 received"]


def test_the_deadline_and_the_reply_caps_are_settings_of_the_relay_with_safe_defaults() -> None:
    relay = Relay("mail.example.org", 25, True)
    assert (relay.timeout, relay.deadline) == (30.0, 60.0)
    assert mail.MAX_REPLY_LINES <= 100
    assert mail.MAX_REPLY_BYTES <= 65536
    assert "deadline" not in repr(relay)  # the repr still shows only where and how
