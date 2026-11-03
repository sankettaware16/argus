"""P4-D2, D-296: how init trusts the SIEM's certificate: a CA file given, the presented CA after
its fingerprint is confirmed (an answers file's mismatch stops), or a public CA; a pin that
still verifies is kept; every pin ends with a handshake against it."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.install import trust
from argus.install.answers import InitError, ScriptedAnswers, TerminalAnswers
from tests.unit.install.fakes import FakeTls, make_pki

pytestmark = pytest.mark.unit

URL = "https://siem.example.org:9200"


def _asker(**answers: object) -> ScriptedAnswers:
    return ScriptedAnswers({f"siem.{k}": v for k, v in answers.items()}, Path("answers.yaml"))


def _pin(tmp_path: Path, tls: FakeTls, asker: object, **kw: object) -> trust.Trusted:
    said: list[str] = []
    target = tmp_path / "data" / "certs" / "siem-ca.crt"
    return trust.establish("siem", URL, target, asker, tls, said.append, force=False, **kw)  # type: ignore[arg-type]


def test_the_presented_ca_is_pinned_when_its_fingerprint_matches(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    fingerprint = tls.pki.ca_fingerprint.lower().replace(":", "")  # any spelling
    done = _pin(tmp_path, tls, _asker(trust="chain", fingerprint=fingerprint))
    assert done.ca_file.read_text() == tls.pki.ca_pem  # the CA only, not the server's own
    assert "pinned the presented CA Example SIEM CA" in done.how
    assert not list(done.ca_file.parent.glob(".*"))


def test_a_fingerprint_that_does_not_match_stops_and_trusts_nothing(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    with pytest.raises(InitError, match="does not match the CA"):
        _pin(tmp_path, tls, _asker(trust="chain", fingerprint="AB:" * 31 + "AB"))
    assert not (tmp_path / "data" / "certs" / "siem-ca.crt").exists()


def test_a_person_confirms_the_fingerprint_or_nothing_is_trusted(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    replies = iter(["chain"])
    no = TerminalAnswers(prompt=lambda q, **kw: next(replies), confirm=lambda q, default: False)
    with pytest.raises(InitError, match="not confirmed"):
        _pin(tmp_path, tls, no)
    replies = iter(["chain"])
    yes = TerminalAnswers(prompt=lambda q, **kw: next(replies), confirm=lambda q, default: True)
    assert _pin(tmp_path, tls, yes).ca_file.is_file()


def test_only_the_confirmed_ca_is_pinned_not_another_one_in_the_chain(tmp_path: Path) -> None:
    """A chain carrying a second, unconfirmed CA (someone in the middle at install time) pins the
    confirmed top only: the extra CA could otherwise sign their own server certificate later."""
    tls = FakeTls(make_pki())
    extra = make_pki("Someone Else's CA")
    tls.presented = lambda url: [tls.pki.leaf, extra.ca, tls.pki.ca]  # type: ignore[method-assign]
    done = _pin(tmp_path, tls, _asker(trust="chain", fingerprint=tls.pki.ca_fingerprint))
    assert done.ca_file.read_text() == tls.pki.ca_pem
    assert extra.ca_pem.strip() not in done.ca_file.read_text()


def test_a_server_that_sends_no_ca_cannot_be_pinned_from_its_chain(tmp_path: Path) -> None:
    tls = FakeTls(make_pki(), presents_ca=False)
    leaf = trust.describe(tls.pki.leaf).fingerprint
    with pytest.raises(InitError, match="give the CA file instead"):
        _pin(tmp_path, tls, _asker(trust="chain", fingerprint=leaf))
    assert not (tmp_path / "data" / "certs" / "siem-ca.crt").exists()
    assert not list((tmp_path / "data" / "certs").glob(".*"))


def test_a_ca_file_is_copied_and_must_verify(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    given = tmp_path / "their-ca.pem"
    given.write_text("junk before\n" + tls.pki.ca_pem)
    done = _pin(tmp_path, tls, _asker(trust="file", ca_file=str(given)))
    assert done.ca_file.read_text() == tls.pki.ca_pem
    other = tmp_path / "other.pem"
    other.write_text(make_pki("Another CA").ca_pem)
    with pytest.raises(InitError, match="does not verify"):
        trust.establish("siem", URL, tmp_path / "b.crt", _asker(trust="file", ca_file=str(other)),
                        tls, print, force=False)  # fmt: skip
    empty = tmp_path / "empty.pem"
    empty.write_text("no certificate\n")
    with pytest.raises(InitError, match="holds no PEM certificate"):
        trust.establish("siem", URL, tmp_path / "c.crt", _asker(trust="file", ca_file=str(empty)),
                        tls, print, force=False)  # fmt: skip


def test_a_public_ca_pins_the_root_that_verified_it(tmp_path: Path) -> None:
    pki = make_pki("Public Root CA")
    tls = FakeTls(pki, root=pki.ca)
    done = _pin(tmp_path, tls, _asker(trust="system"))
    assert done.ca_file.read_text() == pki.ca_pem
    assert "the public CA Public Root CA" in done.how
    refused = FakeTls(make_pki())
    with pytest.raises(InitError, match="does not verify against the system's CA bundle"):
        trust.establish("siem", URL, tmp_path / "x.crt", _asker(trust="system"), refused, print,
                        force=False)  # fmt: skip


def test_a_pin_that_still_verifies_is_kept_and_one_that_does_not_stops(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    target = tmp_path / "data" / "certs" / "siem-ca.crt"
    target.parent.mkdir(parents=True)
    target.write_text(tls.pki.ca_pem)
    kept = trust.establish("siem", URL, target, _asker(), tls, print, force=False)
    assert kept.how.startswith("kept")
    assert tls.asked == [f"verify {URL}"]  # nothing asked of the person, no chain read
    target.write_text(make_pki("Old CA").ca_pem)
    with pytest.raises(InitError, match="--force-trust"):
        trust.establish("siem", URL, target, _asker(), tls, print, force=False)
    again = _asker(trust="chain", fingerprint=tls.pki.ca_fingerprint)
    forced = trust.establish("siem", URL, target, again, tls, print, force=True)
    assert forced.ca_file.read_text() == tls.pki.ca_pem


def test_kibana_may_share_the_siems_pin(tmp_path: Path) -> None:
    tls = FakeTls(make_pki())
    shared = tmp_path / "siem-ca.crt"
    shared.write_text(tls.pki.ca_pem)
    asker = ScriptedAnswers({"kibana.trust": "same"}, Path("a.yaml"))
    done = trust.establish("kibana", "https://kb.example.org:5601", tmp_path / "kb.crt", asker,
                           tls, print, force=False, shared=shared)  # fmt: skip
    assert done.ca_file == shared
    assert not (tmp_path / "kb.crt").exists()


def test_fingerprints_compare_in_any_spelling() -> None:
    digest = "ab" * 32
    assert trust.same_fingerprint(
        digest.upper(), ":".join(digest[i : i + 2] for i in range(0, 64, 2))
    )
    assert not trust.same_fingerprint("ab" * 31, "ab" * 31)  # not a whole SHA-256
    assert not trust.same_fingerprint(digest, "cd" * 32)


def test_what_is_pinned_of_a_chain() -> None:
    assert trust.anchor([b"leaf", b"inter", b"root"]) == b"root"
    assert trust.anchor([b"self-signed"]) == b"self-signed"
    info = trust.describe(make_pki("X CA").ca)
    assert (info.subject, info.issuer, info.self_signed) == ("X CA", "X CA", True)
    assert len(info.fingerprint) == 95


def test_an_address_must_be_https() -> None:
    assert trust.host_port("https://es.example.org:9200") == ("es.example.org", 9200)
    assert trust.host_port("https://es.example.org") == ("es.example.org", 443)
    with pytest.raises(InitError, match="not an https://"):
        trust.host_port("http://es.example.org:9200")
