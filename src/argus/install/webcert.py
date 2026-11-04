"""The web's TLS certificate, made by ``argus init``: for the address people open, self-signed or
signed by a CA whose key this account can read (an organisation's own CA, so browsers that trust
it raise no warning). The key is written with mode 0600 and never printed."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.asymmetric.types import CertificateIssuerPrivateKeyTypes
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from argus.install import files
from argus.install.answers import InitError

DAYS = 825  # what browsers accept for a server certificate
RENEW = timedelta(days=30)  # one that ends sooner is made again
NAME = "ARGUS web"


def _subject_names(address: str) -> list[x509.GeneralName]:
    names: list[x509.GeneralName] = []
    for value in dict.fromkeys([address, "localhost", "127.0.0.1"]):
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(value)))
        except ValueError:
            names.append(x509.DNSName(value))
    return names


def covers(cert_file: Path, address: str, now: datetime | None = None) -> bool:
    """Whether the certificate at ``cert_file`` names ``address`` and lasts another RENEW."""
    try:
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, ValueError, x509.ExtensionNotFound):
        return False
    try:
        wanted: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(address))
    except ValueError:
        wanted = x509.DNSName(address)
    ends = cert.not_valid_after_utc
    return wanted in list(names) and ends - (now or datetime.now(UTC)) > RENEW


def pin(cert_file: Path) -> str:
    """The SHA-256 of the certificate's DER form, lowercase hex (``web.tls_pin_sha256``)."""
    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _load_ca(
    ca_cert: Path, ca_key: Path
) -> tuple[x509.Certificate, CertificateIssuerPrivateKeyTypes]:
    try:
        cert = x509.load_pem_x509_certificate(ca_cert.read_bytes())
    except OSError as exc:
        raise InitError(f"cannot read the CA certificate {ca_cert} ({exc.strerror})", 2) from None
    except ValueError:
        raise InitError(f"{ca_cert} is not a PEM certificate", 2) from None
    try:
        raw = ca_key.read_bytes()
    except OSError as exc:
        raise InitError(
            f"cannot read the CA's key {ca_key} ({exc.strerror}): run argus init as an account"
            " that can read it, or answer none for a self-signed certificate",
            2,
        ) from None
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (ValueError, TypeError):
        raise InitError(f"{ca_key} is not an unencrypted PEM private key", 2) from None
    if not isinstance(
        key, ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey
    ):
        raise InitError(f"{ca_key} cannot sign certificates (an EC, RSA or Ed25519 key)", 2)
    der, spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(der, spki) != cert.public_key().public_bytes(der, spki):
        raise InitError(f"{ca_key} is not the key of {ca_cert}", 2)
    return cert, key


def make(
    address: str,
    cert_file: Path,
    key_file: Path,
    ca: tuple[Path, Path] | None = None,
    organisation: str | None = None,
    now: datetime | None = None,
) -> str:
    """Write a certificate for ``address`` (and the loopback) and its key; who signed it."""
    now = now or datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    common = f"{NAME} ({organisation})" if organisation else NAME
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common[:64])])
    if ca is not None:
        ca_cert, ca_key = _load_ca(*ca)
        issuer, signer, by = ca_cert.subject, ca_key, ca_cert.subject.rfc4514_string()
    else:
        issuer, signer, by = subject, key, "itself (self-signed)"
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=DAYS))
        .add_extension(x509.SubjectAlternativeName(_subject_names(address)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(signer, hashes.SHA256())
    )
    files.write_private(
        key_file,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("ascii"),
    )
    files.write_public(cert_file, cert.public_bytes(serialization.Encoding.PEM).decode("ascii"))
    return by
