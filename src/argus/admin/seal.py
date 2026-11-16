"""Sealed secrets (D-327): the web seals a key a person pasted with ``argus-admin``'s public key
the moment it arrives, and stores only the sealed bytes; only ``argus-admin``, which holds the
private key in ``local/admin-seal.key`` (0600), can open them. X25519, HKDF-SHA256, AES-256-GCM;
the change's id is the associated data, so a sealed value cannot be moved to another change."""

from __future__ import annotations

import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from argus.install import files

KEY_FILE = Path("local/admin-seal.key")
INFO = b"argus admin seal v1"


class SealError(Exception):
    """A sealed value that cannot be opened (another key, a changed byte, another change)."""


def _derive(shared: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    return HKDF(hashes.SHA256(), 32, salt=ephemeral + recipient, info=INFO).derive(shared)


def public_text(key: X25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def load_or_create(root: Path) -> X25519PrivateKey:
    path = root / KEY_FILE
    if path.is_file():
        return X25519PrivateKey.from_private_bytes(base64.b64decode(path.read_bytes().strip()))
    key = X25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    files.write_private(path, base64.b64encode(raw).decode("ascii") + "\n")
    return key


def seal(public: str, plaintext: str, aad: bytes) -> bytes:
    recipient = base64.b64decode(public)
    ephemeral = X25519PrivateKey.generate()
    eph = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient))
    nonce = os.urandom(12)
    body = AESGCM(_derive(shared, eph, recipient)).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return eph + nonce + body


def open_sealed(key: X25519PrivateKey, sealed: bytes, aad: bytes) -> str:
    if len(sealed) < 32 + 12 + 16:
        raise SealError("too short")
    eph, nonce, body = sealed[:32], sealed[32:44], sealed[44:]
    recipient = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    try:
        shared = key.exchange(X25519PublicKey.from_public_bytes(eph))
        plain = AESGCM(_derive(shared, eph, recipient)).decrypt(nonce, body, aad)
    except Exception as exc:  # InvalidTag, a bad point
        raise SealError("cannot be opened with this key") from exc
    return plain.decode("utf-8")
