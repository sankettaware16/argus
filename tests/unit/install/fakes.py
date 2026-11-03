"""Fakes for ``argus init``'s tests: a TLS server's certificates, the SIEM's reads, a discovery
proposal, and the commands of the machine. Nothing here touches the network or docker."""

from __future__ import annotations

import ssl
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from argus.config.settings import Settings


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


@dataclass(frozen=True)
class Pki:
    ca: bytes  # DER
    leaf: bytes

    @property
    def ca_pem(self) -> str:
        return ssl.DER_cert_to_PEM_cert(self.ca)

    @property
    def ca_fingerprint(self) -> str:
        digest = x509.load_der_x509_certificate(self.ca).fingerprint(hashes.SHA256()).hex()
        return ":".join(digest[i : i + 2] for i in range(0, 64, 2)).upper()


def make_pki(common: str = "Example SIEM CA", days: int = 365) -> Pki:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name(common))
        .issuer_name(_name(common))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name("siem.example.org"))
        .issuer_name(_name(common))
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(ca_key, hashes.SHA256())
    )
    der = serialization.Encoding.DER
    return Pki(ca.public_bytes(der), leaf.public_bytes(der))


@dataclass
class FakeTls:
    """A server presenting ``pki``'s leaf and CA; a pinned file verifies it when it holds the CA."""

    pki: Pki = field(default_factory=make_pki)
    root: bytes | str = "unable to get local issuer certificate"
    presents_ca: bool = True
    asked: list[str] = field(default_factory=list)

    def presented(self, url: str) -> Sequence[bytes]:
        self.asked.append(f"presented {url}")
        return [self.pki.leaf, self.pki.ca] if self.presents_ca else [self.pki.leaf]

    def verify(self, url: str, ca_file: Path) -> str | None:
        self.asked.append(f"verify {url}")
        try:
            text = ca_file.read_text(encoding="ascii")
        except OSError:
            return "no file"
        return None if self.pki.ca_pem.strip() in text else "certificate verify failed"

    def system_root(self, url: str) -> bytes | str:
        self.asked.append(f"system {url}")
        return self.root


@dataclass
class FakeSiem:
    key_problems: list[str] = field(default_factory=list)
    selftest_problems: list[str] = field(default_factory=list)
    kibana_problems: list[str] | None = field(default_factory=list)  # None: lane too busy
    proposal: Any = None
    calls: list[str] = field(default_factory=list)
    names: list[list[str]] = field(default_factory=list)

    def check_key(self, settings: Settings, names: list[str]) -> list[str]:
        self.calls.append("check_key")
        self.names.append(list(names))
        return list(self.key_problems)

    def discover(self, settings: Settings) -> Any:
        self.calls.append("discover")
        return self.proposal if self.proposal is not None else make_proposal()

    def selftest(self, settings: Settings) -> list[str]:
        self.calls.append("selftest")
        return list(self.selftest_problems)

    def kibana_check(self, settings: Settings) -> list[str] | None:
        self.calls.append("kibana_check")
        return None if self.kibana_problems is None else list(self.kibana_problems)


def make_proposal(spaces: Sequence[str] = ("soc", "default"), space: str | None = "soc") -> Any:
    from argus.discover.classify import Confidence, Retention
    from argus.discover.propose import FamilyProposal, Proposal
    from argus.site import LogFamily, Role

    family = LogFamily(role=Role.PROXY, pattern="corp-logs-proxy-*", name="proxy")
    return Proposal(
        families=(
            FamilyProposal(
                family=family,
                confidence=Confidence.HIGH,
                score=9,
                evidence=("named like a proxy log",),
                notes=(),
                retention=Retention(days_kept=30),
                kind="daily",
            ),
        ),
        unclassified=(),
        unclassified_count=0,
        space=space,
        space_evidence="the only alerts index",
        alerts_aliases=tuple(f".alerts-security.alerts-{s}" for s in spaces),
        spaces=tuple(spaces),
        features=None,
        elastic_version="8.19.12",
        kibana_version="8.19.12",
        licence=None,
        history_window=None,
        warnings=(),
        requests=6,
        now=datetime(2026, 11, 3, 10, 0, tzinfo=UTC),
    )


@dataclass
class Commands:
    """The machine's commands, answered from a table: argv prefix -> (code, stdout)."""

    table: dict[tuple[str, ...], tuple[int, str]] = field(default_factory=dict)
    ran: list[list[str]] = field(default_factory=list)

    def __call__(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        self.ran.append(list(argv))
        for prefix, (code, out) in self.table.items():
            if tuple(argv[: len(prefix)]) == prefix:
                return subprocess.CompletedProcess(argv, code, out, "")
        return subprocess.CompletedProcess(argv, 0, "", "")


DOCKER_OK = {
    ("docker", "compose", "version"): (0, "2.29.1\n"),
    ("docker", "info"): (0, "27.1.1\n"),
    ("docker", "inspect"): (0, "healthy\n"),
}
