"""Configuration errors. Their text is shown to users and logged, so it never holds a value."""

from __future__ import annotations

import re

from argus.observability.redaction import redact_text

_PLAIN_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class ConfigError(Exception):
    """Configuration could not be loaded; the message is safe to show to a user."""


def safe(fragment: object) -> str:
    """Text the user controls (a path, a key, a library message), ready for an error message.
    Messages combine fixed wording with such fragments and never include configuration values.
    Each fragment also goes through log redaction on its own (redacting the finished message would
    mistake ``database.passwd: unknown setting`` for a ``key: secret`` pair)."""
    return redact_text(str(fragment))


def show_name(name: str) -> str:
    """A key or variable name for a message: as written when plain, otherwise quoted and escaped,
    so a key literally named ``history.window`` stays apart from the setting and invisible or
    look-alike characters show."""
    return safe(name if _PLAIN_NAME.fullmatch(name) else ascii(name))
