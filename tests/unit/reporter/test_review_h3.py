"""Independent review of Q-H3 (reporter): repros that fail on the reviewed commit."""

from __future__ import annotations

import json
import unicodedata
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.reporter import build, figures, prose, render, sections
from argus.reporter.model import Metric, Numbers, Section

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[3]


def _allowed(*values: int) -> figures.Allowed:
    return figures.allowed_from(values=[(v, None) for v in values])


@pytest.mark.parametrize("dash", ["\u2010", "\u2011", "\u2013", "\u2014", "\u2212"])
def test_r3_a_compound_number_word_joined_by_a_typographic_hyphen_is_read_as_one_number(
    dash: str,
) -> None:
    # 23 is not in the input; 20 and 3 are. "twenty-three" with an ASCII hyphen is refused.
    allowed = _allowed(20, 3)
    assert not figures.check("twenty-three hosts", allowed)
    assert not figures.check(f"twenty{dash}three hosts", allowed)


@pytest.mark.parametrize(
    ("text", "have"),
    [
        ("about 1,7 requests", (1, 7)),  # decimal comma: 1.7
        ("1,00,000 requests", (1, 0)),  # Indian grouping: 100000
    ],
)
def test_r4_a_number_split_by_a_comma_is_read_whole(text: str, have: tuple[int, ...]) -> None:
    assert not figures.check(text, _allowed(*have))


@pytest.mark.parametrize(
    ("text", "have"),
    [
        ("3 lakh requests", (3,)),
        ("2 crore requests", (2,)),
        ("2 mil requests", (2,)),
        ("2 mln requests", (2,)),
        ("5 k requests", (5,)),
        ("5 thou of them", (5,)),
    ],
)
def test_r5_a_multiplier_the_extractor_does_not_know_does_not_pass_as_the_bare_count(
    text: str, have: tuple[int, ...]
) -> None:
    assert not figures.check(text, _allowed(*have))


@pytest.mark.parametrize(
    "text",
    [
        "xvii hosts",  # lower-case Roman numeral
        "\u217b hosts",  # SMALL ROMAN NUMERAL TWELVE (NFKC: xii)
        "\U0001f51f hosts",  # KEYCAP TEN
        "twentythree hosts",  # the words run together
        "a tenfold rise",
    ],
)
def test_r6_a_number_the_reader_sees_must_not_be_invisible_to_the_extractor(text: str) -> None:
    # nothing in the input is a number the text could mean (the input holds only 1)
    assert not figures.check(text, _allowed(1))


def _numbers() -> Numbers:
    metric = Metric(key="cases.open", label="Open", value=7, unit="count", definition="d")
    return Numbers(
        kind="daily",
        period_start=datetime(2026, 10, 20, tzinfo=UTC),
        period_end=datetime(2026, 10, 21, tzinfo=UTC),
        as_at=datetime(2026, 10, 21, 6, tzinfo=UTC),
        sections=(Section(id="cases", title="Cases", metrics=(metric,)),),
    )


@pytest.mark.parametrize("hostile", ["\u202e", "\u200b", "\u2028", "\U000e0041", "\u2066", "\t"])
def test_r7_a_newline_must_not_waive_the_printable_check(hostile: str) -> None:
    answer = json.dumps({"paragraph": f"7 cases are open.\n{hostile}drowssap"})
    assert prose.accept(_numbers(), answer) is None


def test_r8_the_services_pin_no_date_and_a_late_run_still_covers_monday_to_sunday() -> None:
    """The timers are Persistent and the services have no --date: the report works out its own
    period, so a run after downtime (any weekday) still covers whole Monday-to-Sunday weeks."""
    for layout in ("deploy/systemd", "deploy/custody/units"):
        for kind in ("daily", "weekly"):
            assert "--date" not in (ROOT / layout / f"argus-report-{kind}.service").read_text()
    for weekday in range(7):  # Monday 19 Oct 2026 .. Sunday 25 Oct 2026
        now = datetime(2026, 10, 19 + weekday, 2, 20, tzinfo=UTC)
        weeks = build.default_days("weekly", now)
        assert len(weeks) == build.WEEKLY_BACKFILL
        assert {d.weekday() for d in weeks} == {6}  # every week ends on a Sunday
        assert weeks[-1] == build.last_complete_week_end(now)
        assert sorted(weeks) == weeks
        assert weeks[-1] < now.date()  # the newest week has ended
        days = build.default_days("daily", now)
        assert days == [now.date() - timedelta(days=i) for i in range(7, 0, -1)]


@given(
    moment=st.datetimes(
        min_value=datetime(2001, 1, 2),  # noqa: DTZ001
        max_value=datetime(2099, 1, 1),  # noqa: DTZ001
    )
)
def test_r8_the_default_week_is_the_last_complete_monday_to_sunday_week(moment: datetime) -> None:
    now = moment.replace(tzinfo=UTC)
    end = build.last_complete_week_end(now)
    assert end.weekday() == 6
    assert end + timedelta(days=1) <= now.date()  # it has ended
    assert end + timedelta(days=8) > now.date()  # and no later week has


def test_r11_the_writers_own_check_and_an_info_edit_are_not_bypass_attempts() -> None:
    assert "settings_changed" not in sections.BYPASS_KINDS
    assert "person_edited" not in sections.BYPASS_KINDS
    assert {"closed_in_kibana", "argus_tags_changed", "person_deleted"} <= set(
        sections.BYPASS_KINDS
    )


def test_r13_the_text_says_when_the_waiting_figures_are_as_at() -> None:
    numbers = _numbers()
    heading = render.heading(numbers)[2]
    assert f"are as at {render.ist12(numbers.as_at)}" in heading
    stamped = build._stamped(
        Section(
            id="cases", title="Cases",
            metrics=(
                Metric(key="a.b", label="A", value=1, unit="count",
                       definition="Rows, as at the making."),
                Metric(key="a.c", label="B", value=1, unit="count",
                       definition="Rows, as at the moment the report was made."),
                Metric(key="a.d", label="C", value=1, unit="count", definition="Rows."),
            ),
        ),
        numbers.as_at,
    )  # fmt: skip
    when = render.ist12(numbers.as_at)
    assert [m.definition for m in stamped.metrics] == [
        f"Rows, as at the making ({when}).",
        f"Rows, as at the moment the report was made ({when}).",
        "Rows.",
    ]


# --------------------------------------------------------------------------- failing closed


@pytest.mark.parametrize(
    "text",
    [
        "3 lakhs",
        "2 crores",
        "5K requests",
        "5 K",
        "5M requests",
        "5 m of them",
        "a dozen",
        "three score",
        "twofold",
        "a thousandfold rise",
        "2 grand",
        "2 mn",
        "5 cr",
        "1,2345 requests",
        "1234,567",
        "12,34 requests",
        "1,23,456",
        "2026,10",
        "1\u060c7",
        "1\u066b5",
        "Phase XVII",
        "MCMXCIV",
        "xcix",
        "onehundred",
        "twentyone",
        "seventyfive",
        "thirdsecond",
        "twothirds",
        "\U0001f51f hosts",
        "\u2780 hosts",
        "\u4e09 hosts",
        "\u0663 hosts",
        "\u1369 hosts",
    ],
)
def test_r3_to_r6_the_prose_check_refuses_what_it_cannot_read_exactly(text: str) -> None:
    everything = figures.allowed_from(values=[(n, None) for n in range(0, 2000)])
    assert figures.unreadable(text), text
    assert not figures.check(text, everything), text


@pytest.mark.parametrize(
    "text",
    [
        "17 cases are waiting",
        "1,234 requests",
        "1,234,567.5 requests",
        "10.0.0.1, 10.0.0.2",
        "the C2 server at DC",
        "a mix of MD5 and CC hosts",
        "From 3 to 7 days",
        "6-7 days",
        "twenty-three hosts",
        "on 2026-10-20 at 13:52",
        "5 ms and 120 MB",
        "the 2nd case",
    ],
)
def test_the_fail_closed_guard_leaves_ordinary_prose_alone(text: str) -> None:
    assert figures.unreadable(text) == [], text


def _number_char(char: str) -> bool:
    return unicodedata.category(char).startswith("N") or unicodedata.numeric(char, None) is not None


# characters that are still a number character other than ASCII 0 to 9 after NFKC
NUMBER_CHARS = [
    chr(i)
    for i in range(0x30000)
    if any(_number_char(c) and not "0" <= c <= "9" for c in unicodedata.normalize("NFKC", chr(i)))
]


@given(
    before=st.text(max_size=12),
    char=st.sampled_from(NUMBER_CHARS),
    after=st.text(max_size=12),
)
def test_a_number_character_the_extractor_did_not_claim_refuses_the_prose(
    before: str, char: str, after: str
) -> None:
    """Whatever the input holds (here: the text's own claims, and every count below 2,000), prose
    with a number character other than ASCII 0 to 9 is refused."""
    text = f"{before}{char}{after}"
    allowed = figures.allowed_from(values=[(n, None) for n in range(2000)])
    allowed.add_text(text)
    assert not figures.check(text, allowed)
