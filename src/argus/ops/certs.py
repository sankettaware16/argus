"""Certificates on disk and on a local port: who, until when, and their SHA-256 (of the DER),
read without trusting them (``argus doctor`` compares, it does not authenticate)."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

WARN_DAYS = 30  # every expiry is announced this long ahead (plan Q-A2)
_PEM = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")
_MAX_PEM_BYTES = 1 << 20


@dataclass(frozen=True)
class CertInfo:
    subject: str  # the common name, or "(no common name)"
    not_before: datetime
    not_after: datetime
    sha256: str  # of the DER, lowercase hex


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def read_cert(path: Path) -> CertInfo:
    """The first certificate of a PEM file. ValueError (naming the file, never its content) if
    it is missing, too large or holds no certificate."""
    if not path.is_file():
        raise ValueError(f"{path} does not exist")
    if path.stat().st_size > _MAX_PEM_BYTES:
        raise ValueError(f"{path} is too large to be a certificate")
    text = path.read_text(encoding="ascii", errors="replace")
    block = _PEM.search(text)
    if block is None:
        raise ValueError(f"{path} is not a PEM certificate")
    try:
        der = ssl.PEM_cert_to_DER_cert(block.group(0))
        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
    except (ssl.SSLError, ValueError, OSError):
        raise ValueError(f"{path} is not a PEM certificate") from None
    names = [
        value for rdn in decoded.get("subject", ()) for key, value in rdn if key == "commonName"
    ]
    return CertInfo(
        subject=names[0] if names else "(no common name)",
        not_before=_when(decoded["notBefore"]),
        not_after=_when(decoded["notAfter"]),
        sha256=fingerprint(der),
    )


def _when(stamp: str) -> datetime:
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(stamp), UTC)


@dataclass(frozen=True)
class Expiry:
    """Where an expiry stands: ``expired``, ``soon`` (within WARN_DAYS) or ``fine``."""

    state: str
    days: int  # whole days left (negative once expired)


def expiry(not_after: datetime, now: datetime) -> Expiry:
    """``days`` is the time left in whole days, rounded down (-1 a second after expiry)."""
    left = not_after - now
    days = left // timedelta(days=1)
    if left <= timedelta(0):
        return Expiry("expired", days)
    return Expiry("soon" if left < timedelta(days=WARN_DAYS) else "fine", days)


async def served_cert(host: str, port: int, wait_s: float = 3.0) -> bytes | None:
    """The DER of the certificate a TLS server on ``host:port`` presents, or None if nothing
    listens there or no TLS handshake completes in ``wait_s`` seconds. The certificate is not
    verified: the caller compares its fingerprint with the one it expects."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        async with asyncio.timeout(wait_s):
            _reader, writer = await asyncio.open_connection(
                host, port, ssl=context, server_hostname=None
            )
    except (OSError, TimeoutError, ssl.SSLError):
        return None
    try:
        tls = writer.get_extra_info("ssl_object")
        der = tls.getpeercert(binary_form=True) if tls is not None else None
        return der if isinstance(der, bytes) else None
    finally:
        writer.close()
        with contextlib.suppress(OSError, TimeoutError, ssl.SSLError):
            async with asyncio.timeout(wait_s):
                await writer.wait_closed()
