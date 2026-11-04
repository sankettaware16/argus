"""``argus init``'s web step: the address people open, a certificate for it (self-signed or signed
by the organisation's CA), the allowlists and the pin written together so the web starts, a
machine's new address replacing the old one, and the first person, whose password is typed
twice and never printed."""

from __future__ import annotations

import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from argus.install import webcert
from argus.install.answers import TerminalAnswers
from tests.unit.install.test_init_inputs import BASE_REPLIES
from tests.unit.install.test_run import SIEM_KEY, Run

pytestmark = pytest.mark.unit

PASSWORD = "correct horse battery"


def _terminal(extra: dict[str, list[str]], asked: list[str] | None = None) -> TerminalAnswers:
    replies = {
        **{k: list(v) for k, v in BASE_REPLIES.items()},
        "Kibana's address": ["none"],
        "Paste the SIEM key": [SIEM_KEY],
        "SIEM key expire": ["90d"],
        "keys file": ["none"],
        **extra,
    }

    def prompt(question: str, **kw: Any) -> str:
        if asked is not None:
            asked.append(question)
        for part, answers in replies.items():
            if part in question and answers:
                return answers.pop(0)
        if "(none to skip)" in question:
            return "none"
        if "(comma-separated)" in question:
            return str(kw["default"])  # Enter: the default
        raise AssertionError(f"not expected: {question}")

    return TerminalAnswers(prompt=prompt, confirm=lambda q, default: True if "Trust" in q
                           else default)  # fmt: skip


def _cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def test_an_address_gets_a_certificate_allowlists_a_pin_and_a_first_person(
    tmp_path: Path,
) -> None:
    run = Run(tmp_path)
    terminal = _terminal({
        "address people open": ["172.16.5.10"],
        "sign-in name": ["alex"],
        "name as ARGUS shows it": ["Alex Example"],
        "A password for alex": [PASSWORD, "short", PASSWORD],
        "same password again": ["different one!", "short", PASSWORD],
    })  # fmt: skip
    assert run.go(terminal) == 0, run.text
    web = run.local()["units"]["web"]
    assert web["host"] == "0.0.0.0"  # noqa: S104 - with TLS and allowlists
    assert web["allowed_hosts"] == ["172.16.5.10"]
    assert web["allowed_networks"] == ["172.16.0.0/12"]
    assert web["public_url"] == "https://172.16.5.10:8765"
    cert = run.root / web["tls_cert"]
    key = run.root / web["tls_key"]
    assert webcert.covers(cert, "172.16.5.10")
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert run.local()["web"]["tls_pin_sha256"] == webcert.pin(cert)
    assert run.people == [("alex", "Alex Example", PASSWORD)]
    assert run.text.count("not taken:") == 2  # the passwords differed, then were too short
    assert PASSWORD not in run.text
    assert "signed by itself (self-signed)" in run.text


def test_a_rerun_keeps_the_certificate_and_makes_no_second_person(tmp_path: Path) -> None:
    run = Run(tmp_path)
    first = _terminal({"address people open": ["172.16.5.10"], "sign-in name": ["none"]})
    assert run.go(first) == 0, run.text
    pin = run.local()["web"]["tls_pin_sha256"]
    run.people.append(("someone", "Someone", PASSWORD))
    asked: list[str] = []
    again = _terminal({"address people open": ["172.16.5.10"]}, asked)
    assert run.go(again) == 0, run.text
    assert run.local()["web"]["tls_pin_sha256"] == pin
    assert "certificate: kept" in run.text
    assert not [q for q in asked if "sign-in name" in q]


def test_a_new_address_replaces_the_old_one_everywhere(tmp_path: Path) -> None:
    """The checkout moved to another machine: the old host, link and pin would stop the web."""
    run = Run(tmp_path)
    old = run.root / "data" / "tls" / "argus.crt"
    webcert.make("172.31.9.9", old, run.root / "data" / "tls" / "argus.key")
    (run.root / "config" / "local.yaml").write_text(yaml.safe_dump({
        "web": {"allowed_hosts": ["172.31.9.9", "desk"],
                "public_url": "https://172.31.9.9:8765", "tls_pin_sha256": "0" * 64},
        "units": {"web": {"host": "0.0.0.0", "tls_cert": "data/tls/argus.crt",  # noqa: S104
                          "tls_key": "data/tls/argus.key",
                          "allowed_hosts": ["172.31.9.9", "desk"],
                          "allowed_networks": ["172.16.0.0/12"],
                          "public_url": "https://172.31.9.9:8765"}},
    }))  # fmt: skip
    assert (
        run.go(_terminal({"address people open": ["172.16.5.10"], "sign-in name": ["none"]})) == 0
    ), run.text
    local = run.local()
    assert local["units"]["web"]["allowed_hosts"] == ["172.16.5.10"]
    assert local["web"]["allowed_hosts"] == ["172.16.5.10"]
    assert local["web"]["public_url"] == local["units"]["web"]["public_url"]
    assert local["units"]["web"]["public_url"] == "https://172.16.5.10:8765"
    assert local["units"]["web"]["allowed_networks"] == ["172.16.0.0/12"]  # kept, not asked
    assert webcert.covers(old, "172.16.5.10")
    assert local["web"]["tls_pin_sha256"] == webcert.pin(old)


def _ca(folder: Path) -> tuple[Path, Path, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Example CA")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    cert_file, key_file = folder / "ca.crt", folder / "ca.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))  # fmt: skip
    return cert_file, key_file, cert


def test_the_organisations_ca_signs_it_so_browsers_trust_it(tmp_path: Path) -> None:
    run = Run(tmp_path)
    ca_cert, ca_key, ca = _ca(tmp_path)
    terminal = _terminal({"address people open": ["argus.example.org"],
                          "CA certificate": [str(ca_cert)], "private key file": [str(ca_key)],
                          "networks people open it from": ["192.0.2.0/24"],
                          "sign-in name": ["none"]})  # fmt: skip
    assert run.go(terminal) == 0, run.text
    web = run.local()["units"]["web"]
    made = _cert(run.root / web["tls_cert"])
    assert made.issuer == ca.subject
    ca.public_key().verify(
        made.signature,
        made.tbs_certificate_bytes,  # type: ignore[call-arg]
        ec.ECDSA(made.signature_hash_algorithm),
    )  # type: ignore[arg-type]
    assert web["allowed_hosts"] == ["argus.example.org"]
    assert web["allowed_networks"] == ["192.0.2.0/24"]
    assert "CN=Example CA" in run.text


def test_a_ca_key_that_is_not_the_cas_is_refused(tmp_path: Path) -> None:
    run = Run(tmp_path)
    ca_cert, _, _ = _ca(tmp_path)
    other = tmp_path / "other"
    other.mkdir()
    _, wrong_key, _ = _ca(other)
    terminal = _terminal({"address people open": ["10.1.2.3"], "CA certificate": [str(ca_cert)],
                          "private key file": [str(wrong_key)]})  # fmt: skip
    assert run.go(terminal) == 2
    assert "is not the key of" in run.text


def test_none_keeps_the_web_on_this_machine(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(_terminal({"address people open": ["none"], "sign-in name": ["none"]})) == 0
    assert "web" not in run.local().get("units", {})
    assert "ssh -L 8765:127.0.0.1:8765" in run.text


def test_an_answers_file_sets_up_the_web_and_its_person(tmp_path: Path) -> None:
    run = Run(tmp_path)
    secret = tmp_path / "person.pw"
    secret.write_text(PASSWORD)
    secret.chmod(0o600)
    answers = run.answers(**{"web.address": "192.0.2.10", "web.person": "alex",
                             "web.person_name": "Alex Example",
                             "web.person_password_file": str(secret)})  # fmt: skip
    assert run.go(answers) == 0, run.text
    assert run.local()["units"]["web"]["allowed_networks"] == ["192.0.2.10/32"]
    assert run.people == [("alex", "Alex Example", PASSWORD)]
    assert PASSWORD not in run.text


def test_an_answers_file_without_an_address_leaves_the_web_alone(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers()) == 0, run.text
    assert "web" not in run.local().get("units", {})
    assert run.people == []


def test_the_case_teams_links_follow_the_new_address(tmp_path: Path) -> None:
    run = Run(tmp_path)
    switches = run.root / "local" / "argus-writer.env"
    switches.parent.mkdir(parents=True)
    switches.write_text(
        "ARGUS_CASE_TEAM__POST=true\nARGUS_WEB__PUBLIC_URL=https://172.31.9.9:8765\n"
        "ARGUS_WEB__ALLOWED_HOSTS=172.31.9.9,desk\n"
    )
    switches.chmod(0o600)
    terminal = _terminal({"address people open": ["172.16.5.10"], "sign-in name": ["none"]})
    assert run.go(terminal) == 0, run.text
    text = switches.read_text()
    assert "ARGUS_WEB__PUBLIC_URL=https://172.16.5.10:8765\n" in text
    assert "ARGUS_WEB__ALLOWED_HOSTS=172.16.5.10\n" in text
    assert "ARGUS_CASE_TEAM__POST=true\n" in text
    assert "172.31.9.9" not in text
    assert stat.S_IMODE(switches.stat().st_mode) == 0o600


def test_an_installation_on_the_loopback_is_never_opened_by_pressing_enter(tmp_path: Path) -> None:
    """A rerun of an existing installation, Enter at every question: the web stays local."""
    run = Run(tmp_path)
    (run.root / "config" / "local.yaml").write_text(
        yaml.safe_dump({"units": {"root": str(run.root)}})
    )
    asked: list[str] = []
    assert run.go(_terminal({"sign-in name": ["none"]}, asked)) == 0, run.text
    assert "web" not in run.local()["units"]
    offered = [q for q in asked if "address people open" in q]
    assert offered  # asked, with nothing offered: Enter means none
