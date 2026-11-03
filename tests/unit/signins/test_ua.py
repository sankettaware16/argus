"""Browser strings in words (AR6, D-216): "Chrome on Windows", "Safari on iPhone"; unknown reads
"unknown browser"; the parser never raises."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.signins.ua import UNKNOWN, device_words, words_of

pytestmark = pytest.mark.unit

CASES = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/130.0.0.0 Safari/537.36",
        "Chrome on Windows",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like"
        " Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Safari on iPhone",
    ),
    (
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
        "Firefox on Linux",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        "Edge on Windows",
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/130.0.0.0 Safari/537.36 OPR/115.0.0.0",
        "Opera on Windows",
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)"
        " Version/17.6 Safari/605.1.15",
        "Safari on macOS",
    ),
    (
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko)"
        " Chrome/130.0.0.0 Mobile Safari/537.36",
        "Chrome on Android",
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like"
        " Gecko) CriOS/130.0.0.0 Mobile/15E148 Safari/604.1",
        "Chrome on iPhone",
    ),
    (
        "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko)"
        " FxiOS/131.0 Mobile/15E148 Safari/605.1.15",
        "Firefox on iPad",
    ),
    (
        "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 Chrome/130.0.0.0",
        "Chrome on ChromeOS",
    ),
    ("curl/8.5.0", "curl"),
    ("python-requests/2.31.0", "a Python script"),
    ("", UNKNOWN),
    ("something else entirely", UNKNOWN),
    ("Mozilla/5.0 (Windows NT 10.0)", "unknown browser on Windows"),
]


@pytest.mark.parametrize(("agent", "words"), CASES)
def test_the_commonest_browsers_read_in_plain_words(agent: str, words: str) -> None:
    assert device_words(agent) == words


@pytest.mark.parametrize("value", [None, 5, b"Chrome/1", ["Chrome/1"]])
def test_a_value_that_is_not_text_is_an_unknown_browser(value: object) -> None:
    assert device_words(value) == UNKNOWN


@given(st.text(max_size=3000))
def test_the_parser_never_raises_and_always_says_something_short(agent: str) -> None:
    words = device_words(agent)
    assert words
    assert len(words) < 60
    assert "\n" not in words


def test_a_very_long_string_is_cut_before_it_is_read() -> None:
    assert device_words("x" * 10_000_000 + " Firefox/1") == UNKNOWN  # the token is past the cut


def test_the_devices_of_an_account_are_ordered_by_events_and_unknown_is_a_last_resort() -> None:
    assert words_of([(CASES[0][0], 3), (CASES[1][0], 9), ("x", 20)]) == (
        "Safari on iPhone",
        "Chrome on Windows",
    )
    assert words_of([("x", 2)]) == (UNKNOWN,)
    assert words_of([]) == ()
    assert words_of([(CASES[0][0], 1), (CASES[1][0], 1)], limit=1) == ("Chrome on Windows",)
