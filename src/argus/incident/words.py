"""The report's plain words: times in the site's zone (12-hour), durations, sizes, plurals and
the one place the writer turns a number into a phrase. Pure; the same input always gives the
same text.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from argus import site

UNREADABLE = "an unreadable time"


def ist_moment(at: datetime) -> str:
    """``15 Oct 2026, 12:05 PM IST`` (the hand-made report's form). Never raises: a time that
    cannot be shown reads "an unreadable time"."""
    try:
        local = at.astimezone(site.zone())
        hour = local.hour % 12 or 12
        label = site.zone_label(local)
        return f"{local:%d %b %Y}, {hour}:{local:%M} {'AM' if local.hour < 12 else 'PM'} {label}"
    except (OverflowError, ValueError, OSError):
        return UNREADABLE


def ist_date(at: datetime) -> str:
    """``15 Oct 2026`` in the site's zone."""
    try:
        return f"{at.astimezone(site.zone()):%d %b %Y}"
    except (OverflowError, ValueError, OSError):
        return UNREADABLE


def ist_day(at: datetime) -> str:
    """The site day as a sortable key, ``2026-10-15``."""
    return f"{at.astimezone(site.zone()):%Y-%m-%d}"


def day_label(key: str) -> str:
    """``Thu 15 Oct`` for ``2026-10-15``."""
    from datetime import date

    try:
        d = date.fromisoformat(key)
    except ValueError:
        return key
    return f"{d:%a %d %b}"


def plural(n: int, one: str, many: str | None = None) -> str:
    """``1 device`` / ``47 devices``."""
    return f"{n} {one if n == 1 else (many or one + 's')}"


def count(n: int) -> str:
    """A count with thousands commas."""
    return f"{n:,}"


def times(n: int) -> str:
    """``1 time`` / ``4,120 times``."""
    return f"{n:,} {'time' if n == 1 else 'times'}"


def dwell(span: timedelta) -> str:
    """A span in the two biggest units: ``13 days 4 hours``, ``2 hours 5 minutes``,
    ``under a minute``."""
    seconds = max(int(span.total_seconds()), 0)
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts: list[str] = []
    if days:
        parts.append(plural(days, "day"))
        if hours:
            parts.append(plural(hours, "hour"))
    elif hours:
        parts.append(plural(hours, "hour"))
        if minutes:
            parts.append(plural(minutes, "minute"))
    elif minutes:
        parts.append(plural(minutes, "minute"))
    return " ".join(parts) or "under a minute"


def size(n: float) -> str:
    """Bytes in the largest unit that keeps a figure of at least 1: ``1.31 GB``, ``6 KB``."""
    value = float(max(n, 0))
    for unit in ("bytes", "KB", "MB", "GB", "TB"):
        if value < 1000 or unit == "TB":
            text = (
                f"{value:.0f}"
                if unit == "bytes" or value >= 100
                else f"{value:.2f}".rstrip("0").rstrip(".")
            )
            return f"{text} {unit}"
        value /= 1000
    return f"{value:.0f} TB"


def confidence_words(value: float | None) -> str | None:
    """A confidence in the words the hand-made report used."""
    if value is None:
        return None
    if value < 0.5:
        return "low"
    if value < 0.7:
        return "medium"
    if value < 0.85:
        return "medium-high"
    return "high"


OUTCOME_WORDS = {
    "true_positive": "a true positive",
    "benign_expected": "benign: expected activity",
    "benign_policy": "benign: allowed by policy",
    "rule_false_positive": "a false positive of the rule",
    "inconclusive": "inconclusive",
}
# the Kibana tag for a verdict
VERDICT_TAG = {
    "true_positive": "verdict:true-positive",
    "benign_expected": "verdict:benign-expected",
    "benign_policy": "verdict:benign-expected",
    "rule_false_positive": "verdict:false-positive",
}


# the analyst brief's steps: who takes one and by when (``model.BriefWho``, ``model.BriefWhen``)
WHO_WORDS = {
    "owner": "Device owner",
    "accounts": "Account holders",
    "network": "Network team",
    "soc": "Security team",
}
WHEN_WORDS = {
    "now": "Immediately",
    "today": "Today",
    "week": "This week",
    "after": "After the device is clean",
}
