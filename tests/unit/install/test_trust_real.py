"""D-296: the real TLS reads of init against a TLS server on the loopback (a made-up CA, a
server certificate for 127.0.0.1): the presented chain, the handshake against a pinned file
(hostname checked), and a refusal against the system's bundle."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import threading
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from argus.install import trust
from argus.install.answers import InitError

pytestmark = pytest.mark.unit


def _name(common: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common)])


def _pki(tmp_path: Path, host: str = "127.0.0.1") -> tuple[Path, Path, bytes]:
    """(the CA file, the server's chain file with its key beside it, the CA's DER)."""
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder().subject_name(_name("Loop CA")).issuer_name(_name("Loop CA"))
        .public_key(ca_key.public_key()).serial_number(1)
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder().subject_name(_name("loop server")).issuer_name(_name("Loop CA"))
        .public_key(key.public_key()).serial_number(2)
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )  # fmt: skip
    pem = serialization.Encoding.PEM
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(pem))
    chain = tmp_path / "chain.pem"
    chain.write_bytes(leaf.public_bytes(pem) + ca.public_bytes(pem))
    (tmp_path / "key.pem").write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    return ca_file, chain, ca.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Path, bytes]]:
    ca_file, chain, ca_der = _pki(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain, tmp_path / "key.pem")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(0.1)
    port = listener.getsockname()[1]
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            raw.settimeout(5)
            try:
                with context.wrap_socket(raw, server_side=True) as tls:
                    tls.recv(1)
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{port}", ca_file, ca_der
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=5)


def test_the_presented_chain_is_read_without_trusting_it(server: tuple[str, Path, bytes]) -> None:
    url, _ca_file, ca_der = server
    chain = trust.RealTls(timeout=5).presented(url)
    assert len(chain) == 2
    assert chain[1] == ca_der
    assert trust.describe(chain[0]).issuer == "Loop CA"


def test_a_handshake_verifies_against_the_pinned_ca_only(
    server: tuple[str, Path, bytes], tmp_path: Path
) -> None:
    url, ca_file, _ = server
    tls = trust.RealTls(timeout=5)
    assert tls.verify(url, ca_file) is None
    (tmp_path / "other").mkdir()
    other, _, _ = _pki(tmp_path / "other")
    assert tls.verify(url, other) is not None
    assert isinstance(tls.system_root(url), str)  # no public CA speaks for it


def test_nothing_listening_is_a_clear_error(tmp_path: Path) -> None:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    with pytest.raises(InitError, match="no TLS handshake"):
        trust.RealTls(timeout=2).presented(f"https://127.0.0.1:{port}")
