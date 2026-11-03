"""The bounds every evidence template of batch 1 keeps (Q-F4, plan §7.3's template rules),
checked where the parameters are made, so no caller can build a request outside them:

* times are timezone-aware, the window is not empty and not longer than the template allows;
* an aggregation reads exactly one daily index (D-067): with the gateway's 1 h pad around
  midnight, a window inside 01:00 to 22:59 UTC of one day;
* addresses are real IPv4 or IPv6 addresses, written the one way Elasticsearch stores them
  (an IPv4-mapped IPv6 address as IPv4; no zone);
* a value is never longer than its field indexes (``ignore_above``, counted in UTF-16 units
  as Elasticsearch counts it).

Pure: nothing here reads a clock or a database.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

from argus import site
from argus.gateway.indices import PAD

MARGIN = timedelta(minutes=15)  # ingest: never read the last minutes (as proxy.MARGIN)


def keyword_chars(source: str | None = None) -> int:
    """The longest value a keyword field of the family ``source`` indexes: its ``ignore_above``
    (the captured mappings' 256). With no family named, the smallest of the site's."""
    return site.keyword_chars(source)


def iso(at: datetime) -> str:
    return at.astimezone(UTC).isoformat().replace("+00:00", "Z")


def utf16_len(value: str) -> int:
    """Length as Elasticsearch counts it for ``ignore_above`` (Java chars)."""
    return len(value.encode("utf-16-le", "surrogatepass")) // 2


def address(value: str) -> str:
    """``value`` as one canonical address, or ValueError. Elasticsearch's ``ip`` type stores
    an IPv4-mapped IPv6 address as the IPv4 address, so that is the one form used."""
    if not isinstance(value, str) or "%" in value or value != value.strip():
        raise ValueError("an address is plain text without a zone")
    parsed = ipaddress.ip_address(value)
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return str(parsed.ipv4_mapped)
    return str(parsed)


def days(start: datetime, end: datetime) -> int:
    """How many daily indices the gateway reads for [start, end] (it pads 1 h each side)."""
    return ((end.astimezone(UTC) + PAD).date() - (start.astimezone(UTC) - PAD).date()).days + 1


def check_window(start: datetime, end: datetime, longest: timedelta, *, one_index: bool) -> None:
    """ValueError unless [start, end) is a window a batch-1 template may read."""
    if start.tzinfo is None or end.tzinfo is None:
        raise ValueError("times must be timezone-aware")
    if end <= start:
        raise ValueError("the window must end after it starts")
    if end - start > longest:
        raise ValueError(f"the window is longer than {longest}")
    if one_index and days(start, end) != 1:
        raise ValueError("an aggregation reads one daily index (01:00 to 22:59 UTC)")
    if not one_index and days(start, end) > 2:
        raise ValueError("a search reads at most two daily indices")


def clamp(
    start: datetime, end: datetime, now: datetime, longest: timedelta
) -> tuple[datetime, datetime] | None:
    """The part of [start, end) a one-index template may read now: whole minutes, never past
    the ingest margin, inside the one daily index that holds its end (near midnight the end
    is cut back first), then at most ``longest`` (the newest part kept). None when nothing
    of it is left."""
    start = start.astimezone(UTC).replace(second=0, microsecond=0)
    end = end.astimezone(UTC)
    if end.second or end.microsecond:
        end = end.replace(second=0, microsecond=0) + timedelta(minutes=1)
    end = min(end, (now.astimezone(UTC) - MARGIN).replace(second=0, microsecond=0))
    if end <= start:
        return None
    # The one day that holds the window's end: its index alone covers 01:00 to 22:59 UTC
    # (the gateway reads the next day's index too for a window that reaches 23:00).
    day = end.replace(hour=0, minute=0)
    if end <= day + PAD:  # the end lies in the first hour: the day before holds the rest
        day -= timedelta(days=1)
    low, high = day + PAD, day + timedelta(days=1) - PAD - timedelta(minutes=1)
    end = min(end, high)
    start = max(start, low, end - longest)
    return (start, end) if end > start else None


def quiet(now: datetime) -> bool:
    """The site's quiet hours (default 00:00 to 01:30 UTC): the SIEM creates the day's
    indices and ILM deletes old ones."""
    return site.in_quiet_hours(now)
