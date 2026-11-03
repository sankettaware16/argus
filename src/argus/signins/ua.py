"""A browser string in words a person reads: "Chrome on Windows", "Safari on iPhone".

A small pure parser with no dependency. It reads the product tokens a browser puts in its
``User-Agent`` in the order that tells them apart (Edge, Opera and Chrome all say "Chrome" and
"Safari"; Chrome on iOS says "CriOS"), and it never raises: anything it does not know reads
"unknown browser".
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable

UNKNOWN = "unknown browser"
MAX_LENGTH = 1000  # a longer string is cut: nothing here needs more

# (token regex, name), first match wins: the more specific product first
_BROWSERS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), name)
    for pattern, name in (
        (r"\bEdg(?:e|A|iOS)?/", "Edge"),
        (r"\b(?:OPR|Opera)/|\bOPiOS/", "Opera"),
        (r"\bSamsungBrowser/", "Samsung Internet"),
        (r"\bFirefox/|\bFxiOS/", "Firefox"),
        (r"\b(?:Chrome|Chromium|CriOS)/", "Chrome"),
        (r"\bVersion/[\d.]+.*\bSafari/", "Safari"),
        (r"\bMSIE |\bTrident/", "Internet Explorer"),
        (r"^curl/", "curl"),
        (r"^python-requests/|^Python-urllib/|^python-httpx/", "a Python script"),
        (r"^Go-http-client/", "a Go program"),
    )
)
# order matters: an iPhone's string also says "like Mac OS X"
_SYSTEMS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(pattern), name)
    for pattern, name in (
        (r"\biPhone\b", "iPhone"),
        (r"\biPad\b", "iPad"),
        (r"\bAndroid\b", "Android"),
        (r"\bWindows\b", "Windows"),
        (r"\bCrOS\b", "ChromeOS"),
        (r"\bMac OS X\b|\bMacintosh\b", "macOS"),
        (r"\bLinux\b|\bX11\b|\bUbuntu\b|\bFedora\b", "Linux"),
    )
)


def device_words(agent: object) -> str:
    """``Chrome on Windows``, ``Safari on iPhone``, ``Firefox`` (the system is not named),
    ``unknown browser on Linux`` (a system and no browser), or ``unknown browser``."""
    if not isinstance(agent, str):
        return UNKNOWN
    text = agent[:MAX_LENGTH]
    browser = next((name for pattern, name in _BROWSERS if pattern.search(text)), None)
    system = next((name for pattern, name in _SYSTEMS if pattern.search(text)), None)
    if browser is None and system is None:
        return UNKNOWN
    if system is None:
        return str(browser)
    return f"{browser or UNKNOWN} on {system}"


def words_of(agents: Iterable[tuple[str, int]], limit: int = 3) -> tuple[str, ...]:
    """The distinct device words of ``(agent, events)`` pairs, the commonest first, at most
    ``limit``; ``unknown browser`` only when nothing better was seen."""
    count: Counter[str] = Counter()
    for agent, events in agents:
        count[device_words(agent)] += max(int(events), 0)
    ranked = [w for w, _ in sorted(count.items(), key=lambda kv: (-kv[1], kv[0]))]
    known = [w for w in ranked if w != UNKNOWN]
    return tuple((known or ranked)[:limit])
