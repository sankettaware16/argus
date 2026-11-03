"""The number extractor and the check (Q-H3's gate): every dress a number can wear, hostile prose
that tries to smuggle one in, and property tests over generated numbers."""

# ruff: noqa: RUF001 - hostile prose is written with look-alike characters on purpose
from __future__ import annotations

from fractions import Fraction

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from argus.reporter import figures
from argus.reporter.figures import Allowed, allowed_from, check, numbers_of, unknown

pytestmark = pytest.mark.unit


def values(text: str) -> list[tuple[Fraction, ...]]:
    return [f.values for f in numbers_of(text)]


def one(text: str) -> figures.Found:
    (found,) = numbers_of(text)
    return found


def F(*v: int | str) -> tuple[Fraction, ...]:  # noqa: N802
    return tuple(Fraction(x) for x in v)


# --------------------------------------------------------------------------- what is found


@pytest.mark.parametrize(
    ("text", "kind", "want"),
    [
        ("17 cases", "digits", F(17)),
        ("1,234 requests", "digits", F(1234)),
        ("1,234,567.5", "digits", F("1234567.5")),
        ("0.25", "digits", F("0.25")),
        ("007", "digits", F(7)),
        ("seventeen", "word", F(17)),
        ("Seventeen", "word", F(17)),
        ("twenty-three", "word", F(23)),
        ("twenty three", "word", F(23)),
        ("one hundred and five", "word", F(105)),
        ("one hundred five", "word", F(105)),
        ("two thousand twenty six", "word", F(2026)),
        ("three million four hundred thousand", "word", F(3_400_000)),
        ("a hundred", "word", F(100)),
        ("zero", "word", F(0)),
        ("third", "ordinal", F(3)),
        ("twentieth", "ordinal", F(20)),
        ("12%", "percent", F(12)),
        ("12 %", "percent", F(12)),
        ("12 percent", "percent", F(12)),
        ("12 per cent", "percent", F(12)),
        ("twelve percent", "percent", F(12)),
        ("66.7%", "percent", F("66.7")),
        ("5k", "digits", F(5000)),
        ("5K", "digits", F(5000)),
        ("2.5M", "digits", F(2_500_000)),
        ("2.5 million", "digits", F(2_500_000)),
        ("3 billion", "digits", F(3_000_000_000)),
        ("1e3", "digits", F(1000)),
        ("1.5E2", "digits", F(150)),
        ("0xFF", "radix", F(255)),
        ("0b101", "radix", F(5)),
        ("0o17", "radix", F(15)),
        ("XVII", "roman", F(17)),
        ("MCMXCIV", "roman", F(1994)),
        ("dozen", "word", F(12)),
        ("twice", "word", F(2)),
        ("thrice", "word", F(3)),
        ("half", "word", (Fraction(1, 2),)),
        ("hundreds of hosts", "word", F(100)),
        ("none of them", "word", F(0)),
        ("a couple of days", "word", F(2)),
        ("三", "digits", F(3)),
        ("٣", "digits", F(3)),  # Arabic-Indic digit three
        ("４２", "digits", F(42)),  # full-width digits
        ("１,２３４", "digits", F(1234)),
        ("²", "digits", F(2)),
    ],
)
def test_a_number_in_any_dress_is_found_with_its_value(
    text: str, kind: str, want: tuple[Fraction, ...]
) -> None:
    found = one(text)
    assert found.kind == kind
    assert found.values == want


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("3-5 days", [F(3, 5)]),
        ("3 \u2013 5", [F(3, 5)]),
        ("3 to 5", [F(3, 5)]),
        ("3~5", [F(3, 5)]),
        ("1,000-2,000", [F(1000, 2000)]),
        ("1.5-2.5%", [F("1.5", "2.5")]),
        ("10.0.0.1", [F(10, 0, 0, 1)]),
        ("3/4", [F(3), F(4)]),
        ("17 000", [F(17000, 17, 0)]),
        ("1'234'567", [F(1234567, 1, 234, 567)]),
    ],
)
def test_ranges_dotted_numbers_and_spaced_thousands_need_every_part(
    text: str, want: list[tuple[Fraction, ...]]
) -> None:
    assert values(text) == want


def test_a_range_is_one_claim_with_both_ends_and_its_unit() -> None:
    found = one("3-5 days")
    assert (found.kind, found.values, found.unit) == ("range", F(3, 5), "day")
    assert [(f.kind, f.values) for f in numbers_of("three to five")] == [("range", F(3, 5))]


@pytest.mark.parametrize(
    ("text", "hours", "minute", "exact"),
    [
        ("13:52", {13}, 52, {"13:52"}),
        ("7:20 PM", {7, 19}, 20, {"19:20"}),
        ("7:20 pm", {7, 19}, 20, {"19:20"}),
        ("12:05 AM", {0, 12}, 5, {"00:05"}),
        ("12:05 PM", {12}, 5, {"12:05"}),
        ("07:20", {7}, 20, {"07:20"}),
        ("00:00:00", {0}, 0, {"00:00:00", "00:00"}),
    ],
)
def test_a_time_needs_its_hour_and_minute_and_is_the_whole_time(
    text: str, hours: set[int], minute: int, exact: set[str]
) -> None:
    found = one(text)
    assert found.kind == "time"
    assert found.needs[0] == frozenset(Fraction(h) for h in hours)
    assert found.needs[1] == frozenset({Fraction(minute)})
    assert found.exact == frozenset(exact)


def test_a_date_needs_year_month_day_and_is_the_whole_date() -> None:
    found = one("2026-10-25")
    assert found.kind == "date"
    assert found.values == F(2026, 10, 25)
    assert found.exact == {"2026-10-25"}
    stamp = numbers_of("2026-10-25T13:52:00Z")
    assert [f.kind for f in stamp] == ["date", "time"]


@pytest.mark.parametrize(
    ("text", "unit"),
    [
        ("120 ms", "ms"), ("120ms", "ms"), ("5 min", "minute"), ("5 minutes", "minute"),
        ("5 hours", "hour"), ("5h", "hour"), ("2 days", "day"), ("3 weeks", "week"),
        ("3 GB", "gb"), ("3gb", "gb"), ("5 seconds", "second"), ("5s", "second"),
        ("five minutes", "minute"), ("twenty seconds", "second"), ("12%", "percent"),
        ("5 hosts", None), ("5 m", None), ("5 b", "byte"),
    ],
)  # fmt: skip
def test_a_unit_after_a_number_is_named(text: str, unit: str | None) -> None:
    assert one(text).unit == unit


@pytest.mark.parametrize(
    "text",
    [
        "", "no numbers here", "several hosts were affected", "many, many cases", "a few",
        "I think so", "IT and ID and MX and PM", "the case is open", "a lot of noise",
        "someone phoned", "zeroes", "alone", "tone", "wonder", "bone", "stone",
        "cases are waiting for somebody", "-", "...", "e", "x", "DC and CD", "may be late",
    ],
)  # fmt: skip
def test_words_that_only_look_like_numbers_are_not_numbers(text: str) -> None:
    assert numbers_of(text) == []


def test_second_is_a_unit_after_a_number_and_an_ordinal_otherwise() -> None:
    assert [f.values for f in numbers_of("the second host")] == [F(2)]
    assert [f.values for f in numbers_of("every second")] == []
    assert [f.values for f in numbers_of("per second")] == []
    assert [(f.values, f.unit) for f in numbers_of("5 second delay")] == [(F(5), "second")]
    assert [f.values for f in numbers_of("three seconds")] == [F(3)]


def test_number_words_are_read_as_a_number_only_when_they_belong_together() -> None:
    assert values("one two") == [F(1), F(2)]
    assert values("one, two, three") == [F(1), F(2), F(3)]
    assert values("twenty twenty") == [F(20), F(20)]
    assert values("nine nine") == [F(9), F(9)]
    assert values("twenty-one cases and thirty-two hosts") == [F(21), F(32)]
    assert values("one hundred and one dalmatians") == [F(101)]
    assert values("a thousand and one") == [F(1001)]
    assert values("seventeen hundred") == [F(1700)]


def test_hidden_characters_do_not_change_a_number() -> None:
    assert values("1​7") == [F(17)]  # zero-width space
    assert values("1‍7") == [F(17)]  # zero-width joiner
    assert values("1­7") == [F(17)]  # soft hyphen
    assert values("1‮7") == [F(17)]  # right-to-left override
    assert values("1́ 7") == [F(1), F(7)]  # a combining mark is no digit
    assert values("s​e​v​e​n") == [F(7)]  # a word split by invisible marks
    assert values("1\x007") == [F(1), F(7)]  # a control character is a space


def test_huge_figures_are_never_in_the_input_and_never_crash() -> None:
    big = "9" * 5000
    found = numbers_of(f"{big} and 1e999 and {big}.{big} and 0x{'f' * 5000}")
    assert found
    assert all(figures.NEVER in need for f in found for need in f.needs if len(need) == 1)
    assert not check(f"{big}", allowed_from([(10**30, None)]))


# --------------------------------------------------------------------------- the check


def facts() -> Allowed:
    """A typical input: counts, a percentage, durations, a period, a time."""
    return allowed_from(
        [(17, None), (66.7, "percent"), (120, "ms"), (5, "minute"), (2, "hour"), (0, None),
         (1, None), (1234, None), (21, None)],
        ["Cases waiting 3 to 7 days", "5:30 AM IST on 20 Oct 2026", "2026-10-20T00:00:00+00:00"],
    )  # fmt: skip


GOOD = [
    "There are 17 cases waiting.", "Seventeen cases are waiting.", "About 66.7% were approved.",
    "66.70% were approved", "66.7 percent were approved", "No gaps today.",
    "The sync took 120 ms.", "The sync took 120 milliseconds.", "It took 5 minutes.",
    "Five minutes later", "A wait of 2 hours.", "two hours and five minutes", "none", "zero",
    "1,234 requests", "0x4D2 requests", "From 3 to 7 days.", "Three to seven days",
    "On 20 Oct 2026 at 5:30 AM IST", "On October 20, 2026", "It began at 05:30.",
    "On 2026-10-20.", "The 1st case", "the first case",
]  # fmt: skip


@pytest.mark.parametrize("prose", GOOD)
def test_prose_whose_numbers_are_all_in_the_input_passes(prose: str) -> None:
    assert [f.raw for f in unknown(prose, facts())] == [], prose


HOSTILE = [
    "There are 18 cases waiting.",  # one off
    "Eighteen cases are waiting.",  # spelled
    "There are eighteen cases waiting.",
    "67% were approved.",  # rounded
    "Sixty seven percent were approved.",
    "12% were approved.",  # a percentage that is no fact
    "66.7 of the cases",  # a percentage said as a count
    "It took 120 minutes.",  # the unit changed: 120 is milliseconds
    "It took 5 ms.",  # 5 is minutes
    "A wait of 2 days.",  # 2 is hours
    "120 s",
    "It took 120.",  # 120 is milliseconds, not a plain count
    "twenty-two cases",
    "a hundred and twenty-one cases",
    "1,235 requests",
    "1.234 requests",  # thousand separators read as decimals
    "17 000 requests",
    "17_000 requests",
    "seventeen thousand",
    "1k requests",
    "1.2k requests",  # 1200
    "1e3 requests",
    "0x4D3 requests",
    "XVIII cases",
    "dozens of cases",
    "hundreds of cases",
    "thousands of requests",
    "a couple of cases",  # 2: the input holds 2 only as hours, never as a plain count
    "twice as many",
    "thrice",
    "half of them",
    "both hosts",
    "a pair of hosts",
    "the 18th case",
    "the eighteenth case",
    "the second case",  # 2 is only hours; a bare 2 is not in the input
    "13:25",  # a transposed time
    "At 5:31 AM IST",
    "At 5:30 PM IST",  # AM is in the input
    "At 05:31",
    "On 2026-10-21.",
    "On 21 Oct 2026",
    "On Oct 21",
    "On 21st October",
    "18/17 cases",
    "3-9 days",
    "between 9 and 3 days",
    "\uff11\uff18 cases",  # full-width 18
    "\u0661\u0668 cases",  # Arabic-Indic 18
    "1\u200b8 cases",  # 18 with a hidden character
    "e\u200bi\u200bg\u200bh\u200bt\u200be\u200be\u200bn cases",
    "\u5341\u516b cases",  # CJK ten eight
    "10.0.0.1",
    "99999999999999999999999999999999999999999999999999999999999999999 cases",
    "17 cases, 18 hosts",  # one good, one bad: the whole prose fails
]


@pytest.mark.parametrize("prose", HOSTILE)
def test_prose_with_a_number_that_is_not_in_the_input_is_refused(prose: str) -> None:
    assert unknown(prose, facts()), f"{prose!r} was let through"


def test_a_time_must_be_a_time_of_the_input_not_two_of_its_numbers() -> None:
    allowed = allowed_from([], ["The sync read 13:52 and 07:25 and 00:30"])
    assert check("at 13:52", allowed)
    assert check("at 1:52 PM", allowed)  # 12-hour of 13:52
    assert not check("at 13:25", allowed)  # 13 and 25 are numbers of the input; 13:25 is not a time
    assert not check("at 7:52", allowed)
    assert check("at 07:25", allowed)
    assert not check("at 25:07", allowed)


def test_the_unit_of_a_number_must_be_one_it_was_given_with() -> None:
    allowed = allowed_from([(120, "ms"), (7, None)])
    assert check("120 ms", allowed)
    assert check("120 milliseconds", allowed)
    assert not check("120", allowed)  # no unit claimed: a plain count, which 120 was not
    assert not check("120 minutes", allowed)
    assert not check("120%", allowed)
    assert check("7 hosts", allowed)
    assert not check("7 hours", allowed)
    assert not check("7%", allowed)


def test_the_input_is_read_in_the_same_dress_as_the_prose() -> None:
    allowed = allowed_from([], ["Median lag: 3 min 20 s", "Share: 66.7%", "Window: 1 to 3 days"])
    for prose in ("3 min 20 s", "3 minutes and 20 seconds", "66.7 percent", "1 to 3 days"):
        assert check(prose, allowed), prose
    for prose in ("sixty-six", "three", "200 seconds", "2 days", "3 hours"):
        assert not check(prose, allowed), prose


# --------------------------------------------------------------------------- properties

ONES = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen",
        "eighteen", "nineteen"]  # fmt: skip
TENS = ["", "", "twenty", "thirty", "forty", "fifty", "sixty", "seventy", "eighty", "ninety"]
SCALES = [(10**12, "trillion"), (10**9, "billion"), (10**6, "million"), (10**3, "thousand")]


def spell(n: int, sep: str = "-", joiner: str = " and ") -> str:
    """``n`` in English words, written independently of the extractor."""
    if n < 20:
        return ONES[n]
    if n < 100:
        return TENS[n // 10] + (sep + ONES[n % 10] if n % 10 else "")
    for size, name in SCALES:
        if n >= size:
            head, rest = divmod(n, size)
            return f"{spell(head, sep, joiner)} {name}" + (
                (joiner if rest < 100 else " ") + spell(rest, sep, joiner) if rest else ""
            )
    head, rest = divmod(n, 100)
    return f"{ONES[head]} hundred" + (joiner + spell(rest, sep, joiner) if rest else "")


DIGITS = {
    "ascii": "0123456789", "fullwidth": "０１２３４５６７８９", "arabic": "٠١٢٣٤٥٦٧٨٩",
    "devanagari": "०१२३४५६७८९", "bold": "𝟎𝟏𝟐𝟑𝟒𝟓𝟔𝟕𝟖𝟗",
}  # fmt: skip
HIDDEN = ["​", "‍", "­", "⁠", "﻿", "‎"]


def dress(n: int, script: str, commas: bool, hidden: str | None) -> str:
    plain = f"{n:,}" if commas else str(n)
    shown = plain.translate(
        {ord(a): b for a, b in zip(DIGITS["ascii"], DIGITS[script], strict=True)}
    )
    if hidden:
        shown = hidden.join(shown)
    return shown


@settings(max_examples=300, deadline=None)
@given(
    n=st.integers(0, 10**12),
    script=st.sampled_from(sorted(DIGITS)),
    commas=st.booleans(),
    hidden=st.one_of(st.none(), st.sampled_from(HIDDEN)),
)
def test_digits_in_any_script_with_commas_and_hidden_marks_are_read_as_the_number(
    n: int, script: str, commas: bool, hidden: str | None
) -> None:
    if hidden and commas:
        return  # a mark between a comma and its digits is a separate matter (see above)
    found = numbers_of(f"x {dress(n, script, commas, hidden)} y")
    assert [f.values for f in found] == [F(n)]


@settings(max_examples=300, deadline=None)
@given(
    n=st.integers(0, 10**12),
    sep=st.sampled_from(["-", " "]),
    joiner=st.sampled_from([" and ", " "]),
)
def test_a_spelled_number_is_read_as_the_number(n: int, sep: str, joiner: str) -> None:
    text = f"there are {spell(n, sep, joiner)} cases"
    assert [f.values for f in numbers_of(text)] == [F(n)], text


@settings(max_examples=300, deadline=None)
@given(n=st.integers(0, 10**6), upper=st.booleans())
def test_spelled_numbers_ignore_case(n: int, upper: bool) -> None:
    word = spell(n)
    assert values(word.upper() if upper else word.title()) == [F(n)]


@settings(max_examples=200, deadline=None)
@given(
    pool=st.lists(st.integers(0, 10**6), min_size=1, max_size=6, unique=True),
    extra=st.integers(10**7, 10**9),
    style=st.sampled_from(["digits", "words", "percent", "commas"]),
)
def test_prose_of_the_inputs_numbers_passes_and_one_more_fails(
    pool: list[int], extra: int, style: str
) -> None:
    allowed = allowed_from([(n, None) for n in pool])

    def say(n: int) -> str:
        return {"digits": str(n), "words": spell(n), "percent": f"{n}%", "commas": f"{n:,}"}[style]

    if style == "percent":
        allowed = allowed_from([(n, "percent") for n in pool])
    prose = "Today " + ", then ".join(f"{say(n)} items" for n in pool) + "."
    assert check(prose, allowed)
    assert not check(prose + f" Also {say(extra)}.", allowed)
    assert not check(f"{say(extra)} " + prose, allowed)


@settings(max_examples=300, deadline=None)
@given(h=st.integers(0, 23), m=st.integers(0, 59))
def test_a_time_is_the_same_in_24_and_12_hour_clocks_and_nothing_else(h: int, m: int) -> None:
    allowed = allowed_from([], [f"{h:02d}:{m:02d}"])
    clock12 = f"{(h % 12) or 12}:{m:02d} {'AM' if h < 12 else 'PM'}"
    assert check(f"{h:02d}:{m:02d}", allowed)
    assert check(f"{h}:{m:02d}", allowed)
    assert check(clock12, allowed)
    other = f"{(h + 1) % 24:02d}:{m:02d}"
    assert not check(other, allowed)


@settings(max_examples=300, deadline=None)
@given(a=st.integers(0, 10**5), b=st.integers(0, 10**5))
def test_a_range_needs_both_ends(a: int, b: int) -> None:
    only_a = allowed_from([(a, None)])
    both = allowed_from([(a, None), (b, None)])
    assert check(f"{a}-{b}", both)
    assert check(f"{a} to {b}", both)
    assert check(f"{a}–{b}", both)
    assert check(f"{a}-{b}", only_a) == (a == b)


SAFE = st.sampled_from(
    ["the", "case", "cases", "are", "waiting", "for", "a", "person", "hosts", "were", "open",
     "closed", "and", "but", "while", "some", "several", "many", "few", "today", "this", "week",
     "ARGUS", "Kibana", "siem", "sync", "ran", "well", "fine", "late", "quiet"]
)  # fmt: skip


@settings(max_examples=200, deadline=None)
@given(words=st.lists(SAFE, max_size=40), punct=st.sampled_from([" ", ", ", ". ", "; ", " - "]))
def test_text_without_numbers_has_none(words: list[str], punct: str) -> None:
    assert numbers_of(punct.join(words)) == []


@settings(max_examples=500, deadline=None)
@given(text=st.text(max_size=300))
def test_any_text_is_read_without_error_and_every_claim_has_a_need(text: str) -> None:
    for found in numbers_of(text):
        assert found.needs
        assert all(need for need in found.needs)
        assert all(v >= 0 for need in found.needs for v in need if v != figures.NEVER)
    check(text, Allowed())
