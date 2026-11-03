"""Q-A2: certificates on disk and on a local port (expiry, SHA-256), and the 30-day warning."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import shutil
import socket
import ssl
import subprocess
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.ops import certs

pytestmark = pytest.mark.unit

needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="needs openssl")


def make_cert(folder: Path, name: str, cn: str = "argus-test", days: int = 400) -> Path:
    """A self-signed EC certificate and its key, in ``folder``."""
    cert, key = folder / f"{name}.crt", folder / f"{name}.key"
    subprocess.run(  # noqa: S603 - fixed arguments
        ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",  # noqa: S607
         "-nodes", "-days", str(days), "-subj", f"/CN={cn}", "-keyout", str(key),
         "-out", str(cert)],
        check=True, capture_output=True, timeout=60,
    )  # fmt: skip
    return cert


@pytest.fixture(scope="module")
def cert_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    if shutil.which("openssl") is None:
        pytest.skip("needs openssl")
    folder = tmp_path_factory.mktemp("certs")
    make_cert(folder, "one", "argus-one")
    make_cert(folder, "two", "argus-two")
    return folder


def test_a_certificate_is_read_with_its_fingerprint(cert_dir: Path) -> None:
    info = certs.read_cert(cert_dir / "one.crt")
    der = ssl.PEM_cert_to_DER_cert((cert_dir / "one.crt").read_text())
    assert info.sha256 == hashlib.sha256(der).hexdigest()
    assert info.subject == "argus-one"
    assert info.not_after - info.not_before == timedelta(days=400)
    assert info.sha256 != certs.read_cert(cert_dir / "two.crt").sha256


def test_the_first_certificate_of_a_chain_counts(cert_dir: Path, tmp_path: Path) -> None:
    chain = tmp_path / "chain.crt"
    chain.write_text((cert_dir / "one.crt").read_text() + (cert_dir / "two.crt").read_text())
    assert certs.read_cert(chain).subject == "argus-one"


@pytest.mark.parametrize(
    ("content", "message"),
    [
        (None, "does not exist"),
        ("not a certificate", "is not a PEM certificate"),
        ("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", "not a PEM"),
    ],
)
def test_what_is_not_a_certificate_is_named_never_shown(
    tmp_path: Path, content: str | None, message: str
) -> None:
    path = tmp_path / "x.crt"
    if content is not None:
        path.write_text(content)
    with pytest.raises(ValueError, match=message) as info:
        certs.read_cert(path)
    assert "AAAA" not in str(info.value)


def test_a_huge_file_is_not_read(tmp_path: Path) -> None:
    path = tmp_path / "big.crt"
    path.write_bytes(b"x" * ((1 << 20) + 1))
    with pytest.raises(ValueError, match="too large"):
        certs.read_cert(path)


T0 = datetime(2027, 1, 10, tzinfo=UTC)


@pytest.mark.parametrize(
    ("left", "state", "days"),
    [
        (timedelta(days=400), "fine", 400),
        (timedelta(days=30), "fine", 30),
        (timedelta(days=30) - timedelta(seconds=1), "soon", 29),
        (timedelta(seconds=1), "soon", 0),
        (timedelta(0), "expired", 0),
        (-timedelta(seconds=1), "expired", -1),
        (-timedelta(days=2), "expired", -2),
    ],
)
def test_the_expiry_boundaries(left: timedelta, state: str, days: int) -> None:
    assert certs.expiry(T0 + left, T0) == certs.Expiry(state, days)


@given(st.timedeltas(min_value=timedelta(days=-3000), max_value=timedelta(days=3000)))
def test_an_expiry_is_fine_soon_or_expired_by_its_time_left(left: timedelta) -> None:
    got = certs.expiry(T0 + left, T0)
    if left <= timedelta(0):
        assert got.state == "expired"
        assert got.days <= 0
    elif left < timedelta(days=certs.WARN_DAYS):
        assert (got.state, 0 <= got.days < certs.WARN_DAYS) == ("soon", True)
    else:
        assert (got.state, got.days >= certs.WARN_DAYS) == ("fine", True)


# --------------------------------------------------------------------------- a served cert


@pytest.fixture
async def tls_port(cert_dir: Path) -> AsyncIterator[int]:
    """A TLS server on the loopback presenting one.crt."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_dir / "one.crt", cert_dir / "one.key")

    async def answer(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        await _close(writer)

    server = await asyncio.start_server(answer, "127.0.0.1", 0, ssl=context)
    port = server.sockets[0].getsockname()[1]
    try:
        yield port
    finally:
        server.close()
        await server.wait_closed()


@needs_openssl
async def test_the_served_certificate_is_read_without_trusting_it(
    tls_port: int, cert_dir: Path
) -> None:
    der = await certs.served_cert("127.0.0.1", tls_port)
    assert der is not None
    assert certs.fingerprint(der) == certs.read_cert(cert_dir / "one.crt").sha256


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(OSError, ssl.SSLError):
        await writer.wait_closed()


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


async def test_nothing_listening_is_none() -> None:
    assert await certs.served_cert("127.0.0.1", _closed_port(), 1.0) is None


async def test_a_server_that_speaks_no_tls_is_none() -> None:
    async def silent(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.0 400 nope\r\n\r\n")
        await writer.drain()
        await _close(writer)

    server = await asyncio.start_server(silent, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        assert await certs.served_cert("127.0.0.1", port, 2.0) is None
    finally:
        server.close()
        await server.wait_closed()


async def test_a_server_that_never_answers_times_out() -> None:
    async def hang(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await asyncio.sleep(5)
        finally:
            writer.close()

    server = await asyncio.start_server(hang, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        started = asyncio.get_running_loop().time()
        assert await certs.served_cert("127.0.0.1", port, 0.5) is None
        assert asyncio.get_running_loop().time() - started < 3
    finally:
        server.close()
        await server.wait_closed()
