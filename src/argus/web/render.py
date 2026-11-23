"""How the Inbox writes values on a page."""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo

from argus import site

CAP = 200


def untrusted(value: Any, cap: int = CAP) -> str:
    """Text that came from an alert: control, format (bidi, zero-width) and line-separator
    characters are shown as U+XXXX in angle quotes, long text is cut; the template engine
    escapes the rest. Never a link."""
    if value is None:
        return "—"
    if isinstance(value, dict | list):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True)
    out: list[str] = []
    for char in str(value):
        if unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp", "Co", "Cs"):
            out.append(f"‹U+{ord(char):04X}›")  # noqa: RUF001 - deliberate
        else:
            out.append(char)
    text = "".join(out)
    return text if len(text) <= cap else text[:cap] + "…"


def clock12(moment: datetime, seconds: bool = False) -> str:
    """12-hour time of day, as the user reads it: "7:20 PM", never "19:20" or "07:20"."""
    hour = moment.hour % 12 or 12
    rest = f"{moment:%M:%S}" if seconds else f"{moment:%M}"
    return f"{hour}:{rest} {'AM' if moment.hour < 12 else 'PM'}"


def hour12(moment: datetime) -> str:
    """The hour of a chart's bucket: "2 PM", "12 AM" for midnight."""
    return f"{moment.hour % 12 or 12} {'AM' if moment.hour < 12 else 'PM'}"


def ist(moment: datetime | None) -> str:
    """A time as reviewers read it: the site's time zone (``site.timezone``) in 12-hour form,
    with the zone written out. (The name is from when the zone was India's.)"""
    if moment is None:
        return "—"
    local = moment.astimezone(site.zone())
    return f"{local.day} {local:%b %Y}, {clock12(local)} {site.zone_label(local)}"


def utc(moment: datetime | None) -> str:
    """The hover's second reading, in the same 12-hour form."""
    if moment is None:
        return ""
    local = moment.astimezone(ZoneInfo("UTC"))
    return f"{local.day} {local:%b %Y}, {clock12(local, seconds=True)} UTC"


def raw_json(value: Any) -> str:
    """Raw data on demand: pretty JSON with every non-ASCII character escaped, so nothing in it
    can reorder or hide text."""
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True)


_PACKS = (
    ("the threat-intel pack", "a threat-intelligence lookup"),
    ("the proxy pack", "proxy-log statistics"),
    ("the log pivots", "a search of the web and proxy logs"),
)
_CODES = re.compile(r"\s*\((?:R\d{1,2}(?:, )?)+\)")


def plain(text: Any) -> str:
    """ARGUS's stored sentences without its component codes: older dossiers name
    the pack that answers a step ("the proxy pack (R12)"); a reviewer needs what it does."""
    out = str(text)
    for old, new in _PACKS:
        out = out.replace(old, new)
    return _CODES.sub("", out)
