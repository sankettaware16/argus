"""P1: the egress validator blocks any identifier in the bytes that would leave, also hidden in
JSON escapes; it fails closed and its audit holds no value."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.llm import egress
from argus.llm.detect import OwnSpace

pytestmark = pytest.mark.unit


def body(content: str, *, ascii_only: bool = False) -> bytes:
    payload = {"model": "m", "messages": [{"role": "user", "content": content}]}
    return json.dumps(payload, ensure_ascii=ascii_only).encode()


def test_a_clean_request_is_allowed(ours: OwnSpace) -> None:
    verdict = egress.check(body("I1.IP_1 talked to 8.8.8.8 at evil.example"), ours)
    assert verdict.allowed
    assert verdict.findings == ()
    assert verdict.audit() == {"allowed": True, "kinds": {}, "error": None}


@pytest.mark.parametrize(
    "content",
    ["host 10.20.3.4", "tp8 is down", "see moodle.example.edu", "key sk-abcdefghijklmnopqrstuv"],
)
def test_identifiers_are_blocked(ours: OwnSpace, content: str) -> None:
    verdict = egress.check(body(content), ours)
    assert not verdict.allowed
    assert verdict.findings


def test_json_escapes_hide_nothing(ours: OwnSpace) -> None:
    raw = b'{"content": "10\\u002e20\\u002e3\\u002e4"}'
    verdict = egress.check(raw, ours)
    assert not verdict.allowed
    assert {f.part for f in verdict.findings} >= {"json"}


def test_non_ascii_escaped_by_json_is_still_read(ours: OwnSpace) -> None:
    verdict = egress.check(body("\uff11\uff10.20.3.4", ascii_only=True), ours)
    assert not verdict.allowed


def test_keys_are_checked_too(ours: OwnSpace) -> None:
    assert not egress.check(json.dumps({"10.20.3.4": 1}), ours).allowed


def test_the_audit_holds_kinds_and_counts_only(ours: OwnSpace) -> None:
    verdict = egress.check(body("10.20.3.4 and tp8 and 10.20.3.4"), ours)
    audit = verdict.audit()
    assert audit["allowed"] is False
    assert audit["kinds"]["ip"] >= 2
    assert "name" in audit["kinds"]
    shown = json.dumps(audit) + repr(verdict)
    assert "10.20" not in shown
    assert "tp8" not in shown


@pytest.mark.parametrize(
    ("payload", "error"),
    [(b"\xff\xfe not utf-8", "UnicodeDecodeError"), (b"a" * (egress.MAX_BYTES + 1), "too large")],
)
def test_it_fails_closed(ours: OwnSpace, payload: bytes, error: str) -> None:
    verdict = egress.check(payload, ours)
    assert not verdict.allowed
    assert verdict.error == error


def test_an_error_inside_the_check_blocks(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise RuntimeError("x")

    monkeypatch.setattr(egress, "find", boom)
    verdict = egress.check("plain", OwnSpace())
    assert not verdict.allowed
    assert verdict.error == "RuntimeError"


def test_text_that_is_not_json_is_still_checked(ours: OwnSpace) -> None:
    assert not egress.check("not json 10.20.3.4", ours).allowed
    assert egress.check("not json at all", ours).allowed


def test_foreign_pseudonyms() -> None:
    answer = "I1.IP_1 contacted I2.SITE_3; IP_4 is bare; I3.HOST_1 is unknown"
    assert egress.foreign(answer, ["I1", "I2"]) == ["IP_4", "I3.HOST_1"]
    assert egress.foreign(answer, ["I1", "I2"], about="I1") == ["I2.SITE_3", "IP_4", "I3.HOST_1"]
    assert egress.foreign("nothing here", ["I1"]) == []


@given(st.text(max_size=300))
def test_check_never_raises(text: str) -> None:
    verdict = egress.check(text, OwnSpace(hosts=frozenset({"tp8"})))
    assert verdict.allowed == (not verdict.findings and verdict.error is None)


def test_ordinary_words_are_exempt_only_outside_quotes() -> None:
    ours = OwnSpace(hosts=frozenset({"web", "tp8"}))
    words = frozenset({"web"})
    assert egress.check("Web: 2 user agents", ours, ordinary=words).allowed
    assert not egress.check("Web: 2 user agents", ours).allowed
    blocked = egress.check('Rule: "scan on web"', ours, ordinary=words)
    assert not blocked.allowed
    assert {f.part for f in blocked.findings} == {"quoted"}
    assert not egress.check("tp8: down", ours, ordinary=words).allowed


def test_quoted_strings_inside_a_json_body_are_checked_strictly() -> None:
    ours = OwnSpace(hosts=frozenset({"web"}))
    payload = json.dumps({"messages": [{"content": 'Web: x\nRule: "the web box"'}]})
    verdict = egress.check(payload, ours, ordinary=["web"])
    assert not verdict.allowed
    assert "quoted" in {f.part for f in verdict.findings}


def test_a_json_scalar_is_checked_as_text(ours: OwnSpace) -> None:
    assert egress.check('"plain"', ours).allowed
    assert not egress.check('"10.20.3.4"', ours).allowed
    assert egress.check("42", ours).allowed


def test_a_provider_body_keeps_template_words_exempt_outside_quotes() -> None:
    ours = OwnSpace(hosts=frozenset({"web"}))
    clean = json.dumps({"messages": [{"content": "Web: 2 user agents"}]})
    assert egress.check(clean, ours, ordinary=["web"]).allowed
    dirty = json.dumps({"messages": [{"content": 'Web: 2\nRule: "web down"'}]})
    verdict = egress.check(dirty, ours, ordinary=["web"])
    assert {f.part for f in verdict.findings} == {"quoted"}


def test_keys_and_list_items_of_a_body_are_checked() -> None:
    ours = OwnSpace(hosts=frozenset({"web"}))
    for body in ({'"web box"': 1}, {"a": ['"web box"']}, {"a": {"b": '"web box"'}}):
        assert not egress.check(json.dumps(body), ours, ordinary=["web"]).allowed, body


def test_a_quoted_string_json_cannot_read_is_still_checked_strictly() -> None:
    ours = OwnSpace(hosts=frozenset({"tp8"}))
    verdict = egress.check('note: "tp8 \\q"', ours, ordinary=["tp8"])
    assert {f.part for f in verdict.findings} == {"quoted"}


def test_the_size_limit_is_exact() -> None:
    assert egress.check(b"z" * egress.MAX_BYTES, OwnSpace()).allowed
    assert egress.check(b"z" * (egress.MAX_BYTES + 1), OwnSpace()).error == "too large"
    assert egress.MAX_BYTES == 128 * 1024


def test_verdicts_are_frozen_and_audited_by_kind() -> None:
    verdict = egress.check("x " + base64.b64encode(b"10.1.2.3").decode(), OwnSpace())
    assert verdict.audit()["kinds"] == {"ip (encoded)": 1}
    assert {f.part for f in verdict.findings} == {"bytes"}
    with pytest.raises(AttributeError):
        verdict.allowed = True  # type: ignore[misc]
    with pytest.raises(AttributeError):
        verdict.findings[0].kind = "x"  # type: ignore[misc]


def test_an_unreadable_quoted_string_keeps_its_last_character() -> None:
    ours = OwnSpace(hosts=frozenset({"tp8"}))
    verdict = egress.check('note: "\\q tp8"', ours, ordinary=["tp8"])
    assert {f.part for f in verdict.findings} == {"quoted"}


def test_a_body_is_checked_as_bytes_and_as_strings(ours: OwnSpace) -> None:
    verdict = egress.check(json.dumps({"a": "10.20.3.4"}), ours)
    assert {f.part for f in verdict.findings} == {"bytes", "json"}


def test_json_escapes_do_not_lengthen_a_url_token(privacy: Any) -> None:
    from tests.unit.llm.test_privacy import web_dossier

    body = web_dossier()
    body["context"]["pack"]["fields"]["url.path"] = {"top": [['/?api_key=a"x', 3]]}
    request = privacy.request([body])
    wrapped = json.dumps({"messages": [{"content": request.text}]})
    from argus.llm.privacy import template_words

    assert egress.check(wrapped, request.ours, ordinary=template_words()).allowed
    assert not egress.check(json.dumps({"c": "/?api_key=abcd1234"}), OwnSpace()).allowed
