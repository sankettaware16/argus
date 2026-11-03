"""Signatures on approval decisions (plan §7.1, §7.9): ``argus-web`` signs every decision it
records, and ``argus-writer`` refuses to send a closure whose decisions are unsigned or were
changed (:mod:`argus.cases.sendcheck`).

A signature is HMAC-SHA256 over the decision's *statement*: the canonical JSON of everything
the decision binds (the request with its case, version, payload hash, alert set, Kibana
version and expiry; the approver, their decision, step-up time, live identity check and the
group they approved with). The writer rebuilds the statement from the database's rows, so a
row changed after signing, a decision written by anything but the web, or a signature moved to
another request fails.

Keys are 32 random bytes in a file of their own (``argus approvals keygen``): mode 0600,
owned by the process that reads it. The web holds the signing key; the writer holds the keys
it accepts (several, for a rotation). Until Q-A5's separate system users both are files of the
one Unix user; then root-owned credentials passed only to ``argus-web`` and ``argus-writer``.
HMAC means the writer could sign too: a writer that is compromised already holds the Kibana
writer keys, so it gains nothing; nothing else (the runtime role, the database, a dump) can.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from argus.normalize.canon import canonical_json

ALGORITHM = "hmac-sha256"
KEY_BYTES = 32
STATEMENT_VERSION = 2  # 2: the request binds its requester's live check (review F2)
_DOMAIN = b"argus-approval-statement-v1\n"
_KEY_ID_DOMAIN = b"argus-approval-key-id\0"
SIGNATURE = re.compile(r"hmac-sha256:([0-9a-f]{16}):([0-9a-f]{64})")
_KEY_TEXT = re.compile(r"[0-9a-f]{64}")


class KeyFileError(Exception):
    """A key file that cannot be used; the message names the file, never the key."""


@dataclass(frozen=True)
class Key:
    key_id: str
    secret: bytes = field(repr=False)


def key_id(secret: bytes) -> str:
    """A key's public name: the first 16 hex digits of a domain-separated SHA-256."""
    return hashlib.sha256(_KEY_ID_DOMAIN + secret).hexdigest()[:16]


def new_key() -> Key:
    secret = secrets.token_bytes(KEY_BYTES)
    return Key(key_id(secret), secret)


def write_key(path: Path, key: Key) -> None:
    """A new key file (refused if ``path`` exists), mode 0600 from its creation."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as out:
        out.write(key.secret.hex() + "\n")


def load_key(path: Path) -> Key:
    """The key in ``path``: 64 hex digits, a regular file no group or other user may use, owned
    by this process's user or by root (a credential systemd passes)."""
    try:
        info = path.stat()
    except OSError as exc:
        raise KeyFileError(f"{path}: cannot read the key file ({exc.strerror})") from None
    if not stat.S_ISREG(info.st_mode):
        raise KeyFileError(f"{path}: the key file is not a regular file")
    if info.st_mode & 0o077:
        raise KeyFileError(f"{path}: the key file may be read by others (chmod 600 it)")
    if info.st_uid not in (os.geteuid(), 0):  # root: systemd's LoadCredential= copy
        raise KeyFileError(f"{path}: the key file belongs to another user")
    try:
        content = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        raise KeyFileError(f"{path}: cannot read the key file") from None
    if not _KEY_TEXT.fullmatch(content):
        raise KeyFileError(f"{path}: not an approval key (64 hex digits)")
    secret = bytes.fromhex(content)
    return Key(key_id(secret), secret)


def iso(value: datetime) -> str:
    """A time as statements carry it: UTC, microseconds (what PostgreSQL keeps)."""
    if value.tzinfo is None:
        raise ValueError("a statement's times are timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _message(statement: Mapping[str, Any]) -> bytes:
    return _DOMAIN + canonical_json(dict(statement)).encode("ascii")


def _mac(key: Key, statement: Mapping[str, Any]) -> str:
    return hmac.new(key.secret, _message(statement), hashlib.sha256).hexdigest()


class Signer:
    """The web's: signs statements with its one key."""

    def __init__(self, key: Key) -> None:
        self._key = key

    @property
    def key_id(self) -> str:
        return self._key.key_id

    def sign(self, statement: Mapping[str, Any]) -> str:
        return f"{ALGORITHM}:{self._key.key_id}:{_mac(self._key, statement)}"

    def verifier(self) -> Verifier:
        """A verifier of the signatures this signer makes (the web shows whether an approval of
        the case team's first sequence stands)."""
        return Verifier([self._key])


class Verifier:
    """The writer's: accepts a signature by any of its keys over exactly this statement."""

    def __init__(self, keys: Iterable[Key]) -> None:
        self._keys = {key.key_id: key for key in keys}

    def verify(self, statement: Mapping[str, Any], signature: str | None) -> bool:
        if signature is None:
            return False
        found = SIGNATURE.fullmatch(signature)
        if found is None:
            return False
        key = self._keys.get(found.group(1))
        if key is None:
            return False
        return hmac.compare_digest(_mac(key, statement), found.group(2))
