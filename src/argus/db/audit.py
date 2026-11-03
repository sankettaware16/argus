"""Writing audit events.

Every value is checked or cleaned *before* the session is touched, so a bad or hostile value can
neither break the caller's transaction nor put a secret into the append-only table. ``actor``,
``action`` and ``target_type`` are short ASCII names written by ARGUS code (anything else is an
:class:`AuditError`); ``target_id``, ``correlation_id`` and ``details`` may carry SIEM data, so
they are redacted, cleaned of NUL and lone surrogates, and capped. Mapping keys in ``details`` are
stored as JSON text; keys that become equal are all kept.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from argus.db.models import AUDIT_OUTCOMES, AuditEvent
from argus.observability.redaction import distinct_keys, redact, redact_text

MAX_DETAILS_BYTES = 64 * 1024
MAX_NAME_CHARS = 128
# target_id has 4 bytes per character at worst and target_type is ASCII: 512 * 4 + 128 bytes stay
# under btree's 2704-byte limit for a (target_type, target_id) index row.
MAX_ID_CHARS = 512

_NAME = re.compile(rf"[A-Za-z0-9][A-Za-z0-9_.:@/-]{{0,{MAX_NAME_CHARS - 1}}}")

# NUL: text and JSONB reject it. Lone surrogates (from surrogateescape decoding or JSON "\ud800"
# escapes in SIEM data) cannot be encoded as UTF-8.
_UNSTORABLE = re.compile("[\x00\ud800-\udfff]")


class AuditError(ValueError):
    """The audit event is malformed; nothing was written."""


async def record_audit(
    session: AsyncSession,
    *,
    actor: str,
    action: str,
    outcome: str = "success",
    target_type: str | None = None,
    target_id: str | None = None,
    correlation_id: str | None = None,
    details: Mapping[str, Any] | None = None,
) -> AuditEvent:
    """Add an audit event to the session (the caller's transaction decides when it commits)."""
    actor = _name("actor", actor)
    action = _name("action", action)
    if outcome not in AUDIT_OUTCOMES:
        raise AuditError(f"audit outcome must be one of {AUDIT_OUTCOMES}, got {outcome!r}")
    if target_type is not None:
        target_type = _name("target_type", target_type)

    safe_details = redact(dict(details or {}))
    if not isinstance(safe_details, dict):
        raise AuditError("audit details could not be redacted")
    try:
        encoded = json.dumps(
            _storable(safe_details),
            default=lambda value: _storable_text(str(value)),
            allow_nan=False,
            ensure_ascii=False,
        )
        size = len(encoded.encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise AuditError(f"audit details are not JSON-serialisable: {exc}") from None
    if size > MAX_DETAILS_BYTES:
        raise AuditError(f"audit details exceed {MAX_DETAILS_BYTES} bytes")

    event = AuditEvent(
        actor=actor,
        action=action,
        outcome=outcome,
        target_type=target_type,
        target_id=_free_text(target_id),
        correlation_id=_free_text(correlation_id),
        details=json.loads(encoded),
    )
    session.add(event)
    await session.flush()
    return event


def _name(field: str, value: str) -> str:
    """A name people read in listings (see the module docstring); the value is never echoed."""
    if not _NAME.fullmatch(value):
        raise AuditError(
            f"audit {field} must be 1-{MAX_NAME_CHARS} ASCII letters, digits or _ . : @ / -, "
            "starting with a letter or digit"
        )
    return value


def _free_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = _storable_text(redact_text(value))
    if len(text) > MAX_ID_CHARS:
        marker = f"...[{len(text)} chars, truncated]"
        text = text[: MAX_ID_CHARS - len(marker)] + marker
    return text


def _storable_text(text: str) -> str:
    return _UNSTORABLE.sub("\ufffd", text)


def _storable(value: Any) -> Any:
    """``value`` with NUL and lone surrogates replaced in every string, and every mapping key
    turned into the text JSON stores for it. Keys that become equal (``1`` and ``"1"``, ``None``
    and ``"null"``, a key with a NUL and the same key with U+FFFD) are all kept: one keeps the
    text and ``distinct_keys`` renames the others."""
    if isinstance(value, str):
        return _storable_text(value)
    if isinstance(value, dict):
        entries = list(value.items())
        keys = distinct_keys([(key, _key_text(key)) for key, _ in entries])
        return {key: _storable(item) for key, (_, item) in zip(keys, entries, strict=True)}
    if isinstance(value, list | tuple):
        return [_storable(item) for item in value]
    return value


def _key_text(key: object) -> str:
    """What JSON makes of a mapping key: a str as is (made storable); an int, float, bool or None
    as its JSON value (``"1"``, ``"2.5"``, ``"true"``, ``"null"``). Any other key is a TypeError,
    as in ``json.dumps``."""
    if isinstance(key, str):
        return _storable_text(key)
    if key is None or isinstance(key, bool | int | float):
        return json.dumps(key, allow_nan=False)
    raise TypeError(f"keys must be str, int, float, bool or None, not {type(key).__name__}")
