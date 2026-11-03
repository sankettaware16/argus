"""Human-friendly durations for config values: ``5d``, ``30d``, ``36h``, ``15m``, ``90s``, ``2w``.

Bare numbers are rejected on purpose: ``window: 5`` could mean seconds, hours or days, and a
silent guess about the history window is exactly the kind of bug config should never hide.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import timedelta
from typing import Annotated

from pydantic import AfterValidator, BeforeValidator, PlainSerializer, WithJsonSchema

UNIT_SECONDS: dict[str, int] = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# Largest supported value: keeps arithmetic far away from timedelta's limits.
MAX_DURATION = timedelta(days=36500)

_PATTERN = re.compile(r"(?P<amount>[0-9]{1,10})(?P<unit>[smhdw])")
_HINT = "use a number followed by a unit: s, m, h, d or w (for example '5d', '36h', '15m')"


def parse_duration(value: object) -> timedelta:
    """Parse ``value`` into a positive whole-second ``timedelta``.

    Accepts ``timedelta`` objects (from code) and strings such as ``"5d"`` (from config).
    Raises ``ValueError`` with a readable message for anything else.
    """
    if isinstance(value, timedelta):
        return _check(value)
    if isinstance(value, int | float):  # includes bool
        raise ValueError(f"a bare number is ambiguous; {_HINT}")
    if not isinstance(value, str):
        raise ValueError(f"expected a duration string, got {type(value).__name__}; {_HINT}")

    text = value.strip()
    match = _PATTERN.fullmatch(text)
    if match is None:
        # Text that is not a duration is never echoed: a secret pasted into the wrong setting
        # would otherwise end up in the error message.
        if text and text[-1:].isalpha() and text[-1:].upper() == text[-1:]:
            raise ValueError(f"invalid duration: units are lowercase; {_HINT}")
        raise ValueError(f"invalid duration; {_HINT}")

    seconds = int(match["amount"]) * UNIT_SECONDS[match["unit"]]
    if seconds > MAX_DURATION.total_seconds():  # before timedelta(), which overflows on huge values
        raise ValueError(f"duration {text!r} is larger than the supported maximum of 36500d")
    return _check(timedelta(seconds=seconds), original=text)


def _check(delta: timedelta, original: object = None) -> timedelta:
    shown = repr(original) if original is not None else format_duration_loose(delta)
    if delta <= timedelta(0):
        raise ValueError(f"duration {shown} must be greater than zero")
    if delta.microseconds:
        raise ValueError(f"duration {shown} must be a whole number of seconds")
    if delta > MAX_DURATION:
        raise ValueError(f"duration {shown} is larger than the supported maximum of 36500d")
    return delta


def format_duration(delta: timedelta) -> str:
    """Render a whole-second duration with the largest exact unit (``d``, ``h``, ``m``, ``s``).

    ``parse_duration(format_duration(x)) == x`` for every valid duration.
    """
    total = _check(delta).days * 86400 + delta.seconds
    for unit in ("d", "h", "m"):
        size = UNIT_SECONDS[unit]
        if total % size == 0:
            return f"{total // size}{unit}"
    return f"{total}s"


def format_duration_loose(delta: timedelta) -> str:
    """Best-effort rendering for error messages (never raises)."""
    return str(delta)


def duration_between(minimum: timedelta, maximum: timedelta) -> Callable[[timedelta], timedelta]:
    """Validator factory: the duration must lie within ``[minimum, maximum]``."""

    def _validate(value: timedelta) -> timedelta:
        if not minimum <= value <= maximum:
            raise ValueError(
                f"must be between {format_duration(minimum)} and {format_duration(maximum)},"
                f" got {format_duration(value)}"
            )
        return value

    return _validate


Duration = Annotated[
    timedelta,
    BeforeValidator(parse_duration),
    PlainSerializer(format_duration, return_type=str),
    WithJsonSchema({"type": "string", "pattern": r"^[0-9]{1,10}[smhdw]$"}),
]
"""A positive, whole-second duration written like ``5d`` in config and rendered back that way."""


def bounded_duration(minimum: timedelta, maximum: timedelta) -> object:
    """``Annotated`` metadata adding a range check.

    Example: ``Annotated[Duration, bounded_duration(timedelta(hours=1), timedelta(days=365))]``
    """
    return AfterValidator(duration_between(minimum, maximum))
