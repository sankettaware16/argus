"""E-mail addresses ARGUS will put on a message (Q-H4). One plain address each: ASCII, no
display name, no quotes, comments, spaces, commas, semicolons, angle brackets or control
characters, so that nothing a person or a file supplies can add a header, a recipient or an SMTP
command. Imports nothing from ARGUS (the settings use it)."""

from __future__ import annotations

import re

MAX_ADDRESS = 254  # RFC 5321's path limit, less the angle brackets
MAX_LOCAL = 64
MAX_HOST = 253
NOT_AN_ADDRESS = "not a plain e-mail address (one address, ASCII, like name@example.org)"
NOT_A_HOST = "not a host name (letters, digits, hyphens and dots only)"
_LOCAL = r"[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_ADDRESS = re.compile(rf"({_LOCAL})@((?:{_LABEL}\.)+[A-Za-z][A-Za-z0-9-]{{0,61}}[A-Za-z0-9])")
_HOST = re.compile(rf"(?:{_LABEL}\.)*{_LABEL}")


def parse_address(value: str) -> str:
    """``value`` itself if it is one plain address, else a ValueError (never echoing the value:
    it may be hostile text). The pattern allows ASCII letters, digits and ``_ % + - .`` before the
    ``@`` and a dotted host name after it, nothing else."""
    found = None
    if isinstance(value, str) and len(value) <= MAX_ADDRESS:
        found = _ADDRESS.fullmatch(value)
    if found is None or len(found.group(1)) > MAX_LOCAL:
        raise ValueError(NOT_AN_ADDRESS)
    return value


def parse_host(value: str) -> str:
    """A host name (letters, digits, hyphens and dots) of at most 253 characters, else a
    ValueError."""
    if not isinstance(value, str) or len(value) > MAX_HOST or _HOST.fullmatch(value) is None:
        raise ValueError(NOT_A_HOST)
    return value


def domain_of(address: str) -> str:
    """The part after the ``@`` of an address :func:`parse_address` accepted."""
    return parse_address(address).rpartition("@")[2]
