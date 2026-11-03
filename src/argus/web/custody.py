"""Custody of a person's ELK credential, and names in the audit trail (plan §7.2, DQ16 (a)).

ARGUS keeps a person's ELK password only to re-check their access (every 5 minutes and before
every change). It is sealed with AES-256-GCM under a key made from two things that are never
stored together: the web's secret (``web.secret_file``, readable by ``argus-web`` alone) and the
session's token (the browser's cookie; the database holds only its SHA-256). A dump of the
database has the sealed bytes and the token's hash; the secret alone has no token; the token
alone has no secret. The seal is bound to the session, the person and the ELK name, so it opens
nowhere else. It is wiped when the session ends; an admin account's is never made (DQ15 (b)).

The same secret keys the HMAC that names a person in the audit trail of a failed sign-in: the
trail never holds a raw name that was typed (plan §7.2 step 8), and the same name always has
the same HMAC, so the throttle can count it.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import SecretStr

from argus.cases import signing

VERSION = b"\x01"
NONCE_BYTES = 12
_SEAL_INFO = b"argus-credential-v1"
_NAME_DOMAIN = b"argus-signin-name-v1\0"


@dataclass(frozen=True)
class Custody:
    """The web's secret, and what it keys: sealed credentials and name HMACs."""

    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.secret) != 32:
            raise ValueError("the web's secret is 32 bytes (64 hex digits)")

    @classmethod
    def from_file(cls, path: Path) -> Custody:
        """The secret in ``path``: 64 hex digits in a regular file only its owner can read
        (``argus sessions keygen`` makes one). ``KeyFileError`` names the file, never the key."""
        return cls(signing.load_key(path).secret)

    # ------------------------------------------------------------------ names

    def name_hmac(self, name: str) -> str:
        """The audit trail's name for ``name``: HMAC-SHA256 under the web's secret, 32 hex
        digits. The same exact name always gives the same value."""
        mac = hmac.new(self.secret, _NAME_DOMAIN + name.encode("utf-8", "surrogatepass"),
                       hashlib.sha256)  # fmt: skip
        return mac.hexdigest()[:32]

    # ------------------------------------------------------------------ the credential

    def _key(self, token: str) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.secret,
            info=_SEAL_INFO,
        ).derive(token.encode("utf-8", "surrogatepass"))

    @staticmethod
    def _bound(token_hash: str, user_id: int, elk_username: str) -> bytes:
        """What the seal is bound to: this session, this person, this ELK name."""
        return f"{token_hash}\0{user_id}\0{elk_username}".encode("utf-8", "surrogatepass")

    def seal(
        self, password: SecretStr, *, token: str, token_hash: str, user_id: int,
        elk_username: str,
    ) -> bytes:  # fmt: skip
        nonce = os.urandom(NONCE_BYTES)
        sealed = AESGCM(self._key(token)).encrypt(
            nonce,
            password.get_secret_value().encode("utf-8"),
            self._bound(token_hash, user_id, elk_username),
        )
        return VERSION + nonce + sealed

    def unseal(
        self, sealed: bytes, *, token: str, token_hash: str, user_id: int, elk_username: str
    ) -> SecretStr | None:
        """The password, or None when ``sealed`` was not sealed by this secret for this token,
        session, person and name (or was changed)."""
        if len(sealed) < 1 + NONCE_BYTES + 16 or sealed[:1] != VERSION:
            return None
        nonce, body = sealed[1 : 1 + NONCE_BYTES], sealed[1 + NONCE_BYTES :]
        try:
            plain = AESGCM(self._key(token)).decrypt(
                nonce, body, self._bound(token_hash, user_id, elk_username)
            )
            return SecretStr(plain.decode("utf-8"))
        except (InvalidTag, UnicodeDecodeError):
            return None
