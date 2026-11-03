"""How ``argus init`` comes to trust the SIEM's and Kibana's certificates (D-033 pins a CA file;
D-296): a CA file the person gives, copied into ``data/certs/``; or the CA the server presents,
shown with its SHA-256 fingerprint for the person to confirm (an answers file gives the expected
fingerprint, and a mismatch stops); or a public CA, when the certificate verifies against the
system's bundle (certifi's, else /etc/ssl/certs), whose root that verified it is pinned. Each
way ends with a real handshake against the pinned file, hostname checked."""

from __future__ import annotations

import contextlib
import re
import socket
import ssl
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from argus.gateway.transport import pinned_context
from argus.install.answers import Asker, InitError
from argus.install.files import write_public

TRUST_WAYS = ("file", "chain", "system")
SYSTEM_BUNDLES = (
    Path("/etc/ssl/certs/ca-certificates.crt"),
    Path("/etc/pki/tls/certs/ca-bundle.crt"),
)
_HEX = re.compile(r"[^0-9a-f]")


class Tls(Protocol):
    """The TLS reads init makes (the tests give fakes)."""

    def presented(self, url: str) -> Sequence[bytes]:
        """The certificates the server presents (DER, its own first), not verified."""

    def verify(self, url: str, ca_file: Path) -> str | None:
        """None when a handshake verifies against ``ca_file`` alone (hostname checked), else
        why not."""

    def system_root(self, url: str) -> bytes | str:
        """The root (DER) that verified the server in the system's bundle, else why not."""


def host_port(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise InitError(f"{url} is not an https:// address", 2)
    return parts.hostname, parts.port or 443


class RealTls:
    """The real handshakes, each bounded by ``timeout`` seconds."""

    def __init__(self, timeout: float = 10.0) -> None:
        self.timeout = timeout

    def _handshake(self, url: str, context: ssl.SSLContext) -> ssl.SSLSocket:
        host, port = host_port(url)
        raw = socket.create_connection((host, port), timeout=self.timeout)
        try:
            return context.wrap_socket(raw, server_hostname=host)
        except BaseException:
            raw.close()
            raise

    def presented(self, url: str) -> Sequence[bytes]:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with self._handshake(url, context) as tls:
                return _chain(tls, verified=False)
        except (OSError, ssl.SSLError) as exc:
            raise InitError(f"no TLS handshake with {url}: {_why(exc)}") from None

    def verify(self, url: str, ca_file: Path) -> str | None:
        try:
            with self._handshake(url, pinned_context(ca_file)):
                return None
        except ssl.SSLCertVerificationError as exc:
            return exc.verify_message or str(exc)
        except (OSError, ssl.SSLError) as exc:
            return _why(exc)

    def system_root(self, url: str) -> bytes | str:
        why = "no system CA bundle found"
        for bundle in _bundles():
            context = ssl.create_default_context(cafile=str(bundle))
            try:
                with self._handshake(url, context) as tls:
                    chain = _chain(tls, verified=True)
                    return chain[-1]
            except ssl.SSLCertVerificationError as exc:
                why = exc.verify_message or str(exc)
            except (OSError, ssl.SSLError) as exc:
                return _why(exc)
        return why


def _bundles() -> list[Path]:
    found = []
    with contextlib.suppress(ImportError):
        import certifi  # httpx's own dependency

        found.append(Path(certifi.where()))
    return [*found, *(path for path in SYSTEM_BUNDLES if path.is_file())]


def _chain(tls: ssl.SSLSocket, *, verified: bool) -> list[bytes]:
    """The chain as DER (Python 3.13 names these methods; 3.12 has them on the SSL object)."""
    owner = tls if hasattr(tls, "get_unverified_chain") else getattr(tls, "_sslobj", None)
    method = "get_verified_chain" if verified else "get_unverified_chain"
    getter = getattr(owner, method, None)
    if getter is not None:
        chain = getter() or []
        ders = [
            c if isinstance(c, bytes) else c.public_bytes(ssl._ssl.ENCODING_DER)  # type: ignore[attr-defined]
            for c in chain
        ]
        if ders:
            return ders
    leaf = tls.getpeercert(binary_form=True)
    return [leaf] if leaf else []


def _why(exc: BaseException) -> str:
    text = getattr(exc, "strerror", None) or getattr(exc, "reason", None) or str(exc)
    return f"{type(exc).__name__}: {text}"[:200]


# --------------------------------------------------------------------------- certificates


@dataclass(frozen=True)
class Described:
    subject: str
    issuer: str
    not_after: datetime
    fingerprint: str  # SHA-256 of the DER, as AB:CD:...

    @property
    def self_signed(self) -> bool:
        return self.subject == self.issuer


def describe(der: bytes) -> Described:
    cert = x509.load_der_x509_certificate(der)
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return Described(
        subject=_name(cert.subject),
        issuer=_name(cert.issuer),
        not_after=cert.not_valid_after_utc.astimezone(UTC),
        fingerprint=":".join(digest[i : i + 2] for i in range(0, len(digest), 2)),
    )


def _name(name: x509.Name) -> str:
    common = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(common[0].value) if common else name.rfc4514_string()[:120] or "(no name)"


def same_fingerprint(given: str, actual: str) -> bool:
    return (
        _HEX.sub("", given.lower()) == _HEX.sub("", actual.lower())
        and len(_HEX.sub("", given.lower())) == 64
    )


def pem(ders: Sequence[bytes]) -> str:
    return "".join(ssl.DER_cert_to_PEM_cert(der) for der in ders)


def anchor(chain: Sequence[bytes]) -> bytes:
    """What to pin of a presented chain: its last certificate (the CA at its top, or the server's
    own when it is alone, self-signed) and nothing else. Only that one is shown with its
    fingerprint and confirmed, so only that one is trusted: an extra certificate slipped into the
    chain is never pinned beside it."""
    return chain[-1]


# --------------------------------------------------------------------------- the step


@dataclass(frozen=True)
class Trusted:
    ca_file: Path
    how: str


def establish(
    what: str,
    url: str,
    target: Path,
    asker: Asker,
    tls: Tls,
    say: Callable[[str], None],
    *,
    force: bool,
    shared: Path | None = None,
) -> Trusted:
    """Pin a CA for ``url`` at ``target`` (``what``: siem or kibana; the answers' prefix). A
    file there that still verifies the server is kept unless ``force``. ``shared``: the SIEM's
    pinned CA, which Kibana may use too ("same")."""
    if target.is_file() and not force:
        why = tls.verify(url, target)
        if why is None:
            return Trusted(target, f"kept {target} (it verifies {url})")
        raise InitError(
            f"{target} no longer verifies {url} ({why}): run `argus init --force-trust` to pin"
            " the CA again"
        )
    ways: tuple[str, ...] = TRUST_WAYS
    default = "chain"
    if shared is not None and shared.is_file() and tls.verify(url, shared) is None:
        ways = ("same", *TRUST_WAYS)
        default = "same"
    way = asker.choose(
        f"{what}.trust",
        f"How should ARGUS trust {url}'s certificate? same: the SIEM's CA; file: a CA file you"
        " have; chain: the CA the server presents, after you check its fingerprint; system: a"
        " public CA",
        ways,
        default,
    )
    if way == "same":
        assert shared is not None
        return Trusted(shared, f"the SIEM's CA ({shared}) verifies {url}")
    if way == "file":
        source = Path(asker.text(f"{what}.ca_file", "The CA certificate file (PEM)")).expanduser()
        try:
            text = source.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as exc:
            raise InitError(
                f"{what}.ca_file: cannot read {source} ({type(exc).__name__})", 2
            ) from None
        ders = _pem_certificates(text)
        if not ders:
            raise InitError(f"{what}.ca_file: {source} holds no PEM certificate", 2)
        return _pin(url, target, ders, tls, f"the CA file {source}")
    if way == "system":
        root = tls.system_root(url)
        if isinstance(root, str):
            raise InitError(f"{url} does not verify against the system's CA bundle: {root}")
        info = describe(root)
        say(f"  {url} verifies against the public CA {info.subject} ({info.fingerprint})")
        return _pin(url, target, [root], tls, f"the public CA {info.subject}")
    chain = list(tls.presented(url))
    if not chain:
        raise InitError(f"{url} presented no certificate")
    pinned = anchor(chain)
    for der in chain:
        info = describe(der)
        say(
            f"   presented: {info.subject} (issued by {info.issuer}, until"
            f" {info.not_after:%Y-%m-%d}) SHA-256 {info.fingerprint}"
        )
    top = describe(pinned)
    if asker.scripted:
        given = asker.text(f"{what}.fingerprint", "The CA's SHA-256 fingerprint")
        if not same_fingerprint(given, top.fingerprint):
            raise InitError(
                f"{what}.fingerprint does not match the CA {url} presents ({top.subject},"
                f" SHA-256 {top.fingerprint}): nothing is trusted",
            )
    elif not asker.confirm(
        f"{what}.fingerprint",
        f"Trust {top.subject} with SHA-256 {top.fingerprint}? Compare it with the fingerprint"
        " your SIEM's administrator gives you",
        False,
    ):
        raise InitError("the presented CA was not confirmed: nothing is trusted")
    return _pin(url, target, [pinned], tls, f"the presented CA {top.subject}")


def _pin(url: str, target: Path, ders: Sequence[bytes], tls: Tls, source: str) -> Trusted:
    candidate = target.with_name(f".{target.name}.new")
    write_public(candidate, pem(ders))
    why = tls.verify(url, candidate)
    if why is not None:
        candidate.unlink(missing_ok=True)
        raise InitError(
            f"{source} does not verify {url} ({why}); if the server does not send its root CA,"
            " give the CA file instead (trust: file)"
        )
    candidate.replace(target)
    return Trusted(target, f"pinned {source} at {target}")


_PEM = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+?-----END CERTIFICATE-----")


def _pem_certificates(text: str) -> list[bytes]:
    out = []
    for block in _PEM.findall(text):
        try:
            der = ssl.PEM_cert_to_DER_cert(block)
            x509.load_der_x509_certificate(der)
        except ValueError:
            continue
        out.append(der)
    return out
