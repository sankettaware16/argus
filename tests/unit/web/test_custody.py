"""Q-E2: custody of a person's ELK credential (plan §7.2, DQ16 (a)): AES-256-GCM under a key from
the web's secret and the session's token; no dump and no secret alone opens it; and the names of
failed sign-ins are HMACs."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.cases.signing import KeyFileError
from argus.web.custody import NONCE_BYTES, VERSION, Custody

pytestmark = pytest.mark.unit
SECRET = bytes(range(32))
OTHER = bytes(range(1, 33))
TOKEN = "t" * 43
HASH = hashlib.sha256(TOKEN.encode()).hexdigest()
ARGS = {"token": TOKEN, "token_hash": HASH, "user_id": 7, "elk_username": "asha.rao"}


def sealed(password: str = "correct horse battery", custody: Custody | None = None) -> bytes:  # noqa: S107
    return (custody or Custody(SECRET)).seal(SecretStr(password), **ARGS)


def test_the_secret_is_32_bytes() -> None:
    for bad in (b"", b"x" * 31, b"x" * 33):
        with pytest.raises(ValueError, match="32 bytes"):
            Custody(bad)
    assert "ab" * 32 not in repr(Custody(bytes.fromhex("ab" * 32)))


def test_the_secret_comes_from_a_file_only_its_owner_can_read(tmp_path: Path) -> None:
    good = tmp_path / "secret"
    good.write_text("ab" * 32 + "\n")
    good.chmod(0o600)
    assert Custody.from_file(good).secret == bytes.fromhex("ab" * 32)
    loose = tmp_path / "loose"
    loose.write_text("ab" * 32 + "\n")
    loose.chmod(0o644)
    short = tmp_path / "short"
    short.write_text("abcd\n")
    short.chmod(0o600)
    for bad in (loose, short, tmp_path / "missing", tmp_path):
        with pytest.raises(KeyFileError) as raised:
            Custody.from_file(bad)
        assert "ab" * 32 not in str(raised.value)


@given(st.text(min_size=1, max_size=300).filter(lambda p: p.isascii() or p.encode("utf-8")))
def test_what_is_sealed_opens_for_the_same_token_session_person_and_name(password: str) -> None:
    box = sealed(password)
    assert box[:1] == VERSION
    assert Custody(SECRET).unseal(box, **ARGS) == SecretStr(password)


def test_the_seal_hides_the_password_and_differs_every_time() -> None:
    one, two = sealed("a password nobody sees"), sealed("a password nobody sees")
    assert one != two  # a fresh nonce each time
    assert b"nobody" not in one
    assert len(one) == 1 + NONCE_BYTES + len("a password nobody sees") + 16


@pytest.mark.parametrize(
    "change",
    [
        {"token": "u" * 43},  # another token (the cookie)
        {"token_hash": "0" * 64},  # another session
        {"user_id": 8},  # another person
        {"elk_username": "asha.ra0"},  # another ELK name
    ],
)
def test_it_opens_nowhere_else(change: dict[str, object]) -> None:
    box = sealed()
    assert Custody(SECRET).unseal(box, **{**ARGS, **change}) is None  # type: ignore[arg-type]


def test_neither_the_secret_alone_nor_the_dump_alone_opens_it() -> None:
    box = sealed()
    # a dump holds the sealed bytes and the token's hash, never the token
    assert Custody(SECRET).unseal(box, **{**ARGS, "token": HASH}) is None
    assert Custody(SECRET).unseal(box, **{**ARGS, "token": ""}) is None
    # the token (a cookie) without the secret
    assert Custody(OTHER).unseal(box, **ARGS) is None  # type: ignore[arg-type]


@given(st.integers(min_value=0, max_value=60), st.integers(min_value=1, max_value=255))
def test_a_changed_or_cut_seal_is_no_credential(position: int, flip: int) -> None:
    box = bytearray(sealed("correct horse battery"))
    box[position % len(box)] ^= flip
    assert Custody(SECRET).unseal(bytes(box), **ARGS) is None  # type: ignore[arg-type]
    assert Custody(SECRET).unseal(bytes(box[: position % len(box)]), **ARGS) is None  # type: ignore[arg-type]


def test_names_in_the_audit_trail_are_hmacs_of_the_exact_name() -> None:
    custody = Custody(SECRET)
    name = custody.name_hmac("Asha.Rao")
    assert len(name) == 32
    assert name == custody.name_hmac("Asha.Rao")
    assert name != custody.name_hmac("asha.rao")  # the exact name, as ELK has it
    assert name != Custody(OTHER).name_hmac("Asha.Rao")
    assert "asha" not in name.lower()
    assert custody.name_hmac("\ud800") != custody.name_hmac("?")  # one-to-one on any text
