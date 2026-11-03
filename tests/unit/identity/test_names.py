"""Refusals before any request (plan §7.2 step 2, DQ15 (a)): reserved and service names, names
Elasticsearch cannot hold, passwords under 10 characters; the credential never shows its
password."""

from __future__ import annotations

import pickle

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.identity.names import (
    MAX_NAME,
    MAX_PASSWORD,
    MIN_PASSWORD,
    RESERVED,
    Credential,
    NamePolicy,
    Reason,
    is_elk_name,
    password_refusal,
    refusal,
)

GOOD = "a-long-enough-password"


@pytest.mark.parametrize("name", sorted(RESERVED))
def test_every_reserved_name_is_refused(name: str) -> None:
    assert NamePolicy().refusal(name) == Reason.RESERVED
    assert NamePolicy().refusal(name.upper()) == Reason.RESERVED


def test_the_reserved_list_is_elasticsearchs() -> None:
    assert {
        "elastic", "kibana", "kibana_system", "logstash_system", "beats_system", "apm_system",
        "remote_monitoring_user",
    } == RESERVED  # fmt: skip


@pytest.mark.parametrize("name", ["argus", "ARGUS", "Argus"])
def test_argus_is_always_a_service_name(name: str) -> None:
    assert NamePolicy().refusal(name) == Reason.SERVICE


def test_extra_service_names_ignore_case() -> None:
    policy = NamePolicy.of(["argus-canary", "Kibana-Svc"])
    assert policy.refusal("ARGUS-CANARY") == Reason.SERVICE
    assert policy.refusal("kibana-svc") == Reason.SERVICE
    assert policy.refusal("devuser") is None


@pytest.mark.parametrize(
    "name",
    ["", " devuser", "devuser ", "san:ket", "sankét", "sa\nnket", "sa\tnket", "x" * (MAX_NAME + 1),
     "\x00", "\uff45\uff4c\uff41\uff53\uff54\uff49\uff43"],  # fullwidth "elastic"
)  # fmt: skip
def test_names_elasticsearch_cannot_hold_are_refused(name: str) -> None:
    assert NamePolicy().refusal(name) == Reason.NOT_A_NAME
    assert not is_elk_name(name)


@pytest.mark.parametrize("name", ["s", "devuser", "Devuser.T", "a b", "x" * MAX_NAME, "~!@#"])
def test_names_elasticsearch_can_hold_pass(name: str) -> None:
    assert is_elk_name(name)
    assert NamePolicy().refusal(name) is None


def test_password_limits() -> None:
    assert password_refusal(SecretStr("x" * (MIN_PASSWORD - 1))) == Reason.SHORT_PASSWORD
    assert password_refusal(SecretStr("")) == Reason.SHORT_PASSWORD
    assert password_refusal(SecretStr("x" * MIN_PASSWORD)) is None
    assert password_refusal(SecretStr("x" * MAX_PASSWORD)) is None
    assert password_refusal(SecretStr("x" * (MAX_PASSWORD + 1))) == Reason.LONG_PASSWORD
    assert password_refusal(SecretStr("é" * MIN_PASSWORD)) is None  # characters, not bytes


def test_the_name_is_checked_before_the_password() -> None:
    assert refusal(Credential("elastic", SecretStr("short")), NamePolicy()) == Reason.RESERVED
    assert refusal(Credential("devuser", SecretStr("short")), NamePolicy()) == Reason.SHORT_PASSWORD
    assert refusal(Credential("devuser", SecretStr(GOOD)), NamePolicy()) is None


def test_the_credential_never_shows_its_password() -> None:
    secret = "the-actual-secret-value"
    credential = Credential("devuser", SecretStr(secret))
    for shown in (repr(credential), str(credential), f"{credential}", repr([credential])):
        assert secret not in shown
    assert secret not in repr(pickle.loads(pickle.dumps(credential)))  # noqa: S301
    with pytest.raises(TypeError):
        Credential("devuser", secret)  # type: ignore[arg-type]


@given(st.sampled_from(sorted(RESERVED)), st.data())
def test_any_casing_of_a_reserved_name_is_refused(name: str, data: st.DataObject) -> None:
    cased = "".join(c.upper() if data.draw(st.booleans()) else c for c in name)
    assert NamePolicy().refusal(cased) == Reason.RESERVED


@given(st.text(min_size=1, max_size=40))
def test_any_name_outside_printable_ascii_is_refused(name: str) -> None:
    if any(not " " <= c <= "~" for c in name):
        assert NamePolicy().refusal(name) == Reason.NOT_A_NAME


@given(st.text(alphabet=st.characters(min_codepoint=0x21, max_codepoint=0x7E), min_size=1,
               max_size=60))  # fmt: skip
def test_printable_names_pass_unless_reserved_or_with_a_colon(name: str) -> None:
    got = NamePolicy().refusal(name)
    if ":" in name:
        assert got == Reason.NOT_A_NAME
    elif name.casefold() in RESERVED:
        assert got == Reason.RESERVED
    elif name.casefold() == "argus":
        assert got == Reason.SERVICE
    else:
        assert got is None


@given(st.text(max_size=MIN_PASSWORD - 1))
def test_any_short_password_is_refused(password: str) -> None:
    assert (
        refusal(Credential("devuser", SecretStr(password)), NamePolicy()) == Reason.SHORT_PASSWORD
    )
