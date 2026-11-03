"""The words of a notice (Q-H4): fixed text and numbers only. A notice names its kind, a
severity, a count and one link; the rest of the facts (a host, an address, a user, a rule) have
no way in. Examples for every kind, then properties over any intent."""

from __future__ import annotations

import dataclasses
import re
import uuid
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases.model import SEVERITIES
from argus.config.settings import WebSettings
from argus.notices import render
from argus.notices.model import KINDS, Intent, Kind, Reason, Target
from argus.web import links

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 26, 6, 0, tzinfo=UTC)
ID = uuid.UUID("0b5f3c1e-7a1d-4a55-9d0e-2f6a8c9b1d34")
BASE = "https://argus.example.org"
# what the data could hold: none of it may appear in a message, whatever the subject says
SENTINELS = [
    "10.8.235.157", "77.221.155.150", "ps1bot-lab-07", "alice.smith", "evil-c2.example.net",
    "Rule: Possible C2 beacon from host", "squid", "root", "alice@example.org", "C:\\Users\\alice",
]  # fmt: skip


def target(kind: Kind) -> Target:
    if kind == "outage":
        return Target("health")
    return Target("investigation", ID) if kind == "ioc_hit" else Target("case", ID)


def intent(kind: Kind, reason: Reason = "new", severity: str = "high", count: int = 3,
           subject: str = "x") -> Intent:  # fmt: skip
    return Intent(kind, reason, severity, count, target(kind), (kind, subject), T0)  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", KINDS)
def test_every_kind_has_a_plain_subject_a_severity_a_count_and_one_link(kind: Kind) -> None:
    said = render.render(intent(kind), BASE)
    assert said.subject == f"[ARGUS High] {render.SUBJECT[kind]}"
    assert "Severity: High" in said.body
    assert render.COUNT[kind][1].format(n=3) in said.body
    assert said.body.count("http") == 1
    assert said.link in said.body
    assert said.body.endswith("\n")


def test_the_subject_for_a_reminder_and_the_end_of_an_outage() -> None:
    assert render.render(intent("case_active", "reminder"), BASE).subject.startswith(
        "[ARGUS High] Still waiting: "
    )
    assert "This is a reminder" in render.render(intent("closure_waiting", "reminder"), BASE).body
    ended = render.render(intent("outage", "ended", count=4), BASE)
    assert ended.subject == "[ARGUS] The earlier outage is over"
    assert "It lasted about 4 hours." in ended.body.split("\n")
    assert "Severity" not in ended.body


def test_the_count_line_says_one_or_many() -> None:
    one = render.render(intent("case_active", count=1), BASE).body
    many = render.render(intent("case_active", count=2), BASE).body
    assert "seen on 1 day since" in one
    assert "seen on 2 days since" in many
    assert "Waiting for 1 hour." in render.render(intent("closure_waiting", count=1), BASE).body


def test_the_links_are_the_webs_own_permanent_links() -> None:
    web = WebSettings(
        public_url=BASE,
        allowed_hosts=("argus.example.org",),
        host="0.0.0.0",  # noqa: S104 - a setting under test, nothing binds it
        tls_cert="/x",
        tls_key="/y",
        allowed_networks=("10.0.0.0/8",),
    )
    assert render.link(BASE, Target("case", ID)) == links.case_url(web, ID)
    assert render.link(BASE, Target("investigation", ID)) == links.investigation_url(web, ID)
    assert render.link(BASE, Target("health")) == f"{BASE}/health"
    assert render.link(BASE, Target("home")) == f"{BASE}/"
    assert render.link("http://127.0.0.1:8765", Target("home")) == "http://127.0.0.1:8765/"


@pytest.mark.parametrize(
    "base",
    ["", "argus.example.org", "https://argus.example.org/", "https://argus.example.org/x",
     "https://user:pw@argus.example.org", "https://argus.example.org\r\nBcc: x", "ftp://a.b",
     "https://argus example.org", "https://argus.example.org?x=1", "https://ARGUS.example.org",
     "javascript:alert(1)", "https://a.b#frag"],
)  # fmt: skip
def test_a_link_base_is_a_scheme_and_a_host_name_only(base: str) -> None:
    with pytest.raises(ValueError, match="scheme and a host name"):
        render.link(base, Target("home"))


def test_a_page_with_an_id_needs_it_and_the_others_have_none() -> None:
    with pytest.raises(ValueError, match="an id"):
        Target("case")
    with pytest.raises(ValueError, match="an id"):
        Target("health", ID)


def test_the_n_more_notice() -> None:
    folded = [intent("case_active", severity="low"), intent("ioc_hit", severity="critical"),
              intent("closure_waiting", severity="medium")]  # fmt: skip
    said = render.render_more(folded, BASE)
    assert said.subject == "[ARGUS Critical] 3 more notices"
    assert "3 more things need a look" in said.body
    assert said.link == f"{BASE}/"
    assert "Severity: Critical" in said.body
    with pytest.raises(ValueError, match="nothing was folded"):
        render.render_more([], BASE)


def test_the_test_message_is_one_line() -> None:
    said = render.render_test()
    assert said.subject == "ARGUS test notice"
    assert said.body.count("\n") == 1
    assert said.body.startswith("This is a test message from ARGUS")


def test_the_words_are_plain_ascii_without_a_line_break_in_a_subject() -> None:
    for kind in KINDS:
        for reason in ("new", "raised", "reminder", "ended"):
            said = render.render(intent(kind, reason), BASE)  # type: ignore[arg-type]
            assert said.subject.isascii()
            assert said.body.isascii()
            assert "\n" not in said.subject
            assert "\r" not in said.subject
            assert len(said.subject) < 120


# --------------------------------------------------------------------------- properties

ALLOWED_LINE = re.compile(
    "|".join(
        [
            r"",
            re.escape(render.REMINDER),
            *(re.escape(h) for h in render.HEADLINE.values()),
            re.escape(render.ENDED_HEADLINE),
            r"\d+ more things need a look\. They are not listed one by one, to keep this calm\.",
            r"Severity: (Low|Medium|High|Critical)",
            *(
                re.escape(form).replace(r"\{n\}", r"\d+")
                for pair in (*render.COUNT.values(), render.ENDED_COUNT, render.MORE_COUNT)
                for form in pair
            ),
            re.escape("Open it in ARGUS:"),
            rf"https?://[a-z0-9.-]+(:\d+)?/(go/(case|investigation)/{ID})?(health)?",
            *(re.escape(line) for line in render.FOOTER.split("\n")),
        ]
    )
)


@given(
    st.sampled_from(KINDS),
    st.sampled_from(["new", "raised", "reminder", "ended"]),
    st.sampled_from(SEVERITIES),
    st.integers(0, 10**6),
    st.sampled_from(SENTINELS) | st.text(max_size=80),
    st.sampled_from(SENTINELS) | st.text(max_size=80),
)
def test_property_a_message_is_fixed_text_a_number_and_a_link_whatever_the_subject_is(
    kind: Kind, reason: Reason, severity: str, count: int, subject: str, other: str
) -> None:
    said = render.render(intent(kind, reason, severity, count, subject), BASE)
    for line in said.body.split("\n"):
        assert ALLOWED_LINE.fullmatch(line), line
    # the subject key has no way in: another key gives the very same message
    assert said == render.render(intent(kind, reason, severity, count, other), BASE)
    for secret in SENTINELS:
        assert secret not in said.subject
        assert secret not in said.body


@given(st.lists(st.sampled_from(KINDS), min_size=1, max_size=30), st.sampled_from(SENTINELS))
def test_property_the_n_more_notice_names_only_how_many(kinds: list[Kind], sentinel: str) -> None:
    said = render.render_more([intent(k, subject=sentinel) for k in kinds], BASE)
    assert sentinel not in said.subject + said.body
    assert str(len(kinds)) in said.subject
    for line in said.body.split("\n"):
        assert ALLOWED_LINE.fullmatch(line), line


# --------------------------------------------------------------------------- the words, written out

LINK = f"{BASE}/go/case/{ID}"
FOOTER = (
    "This is an automatic notice from ARGUS. It names nothing on purpose: the link shows the"
    " details to people who may see them.\n"
    "To stop these messages, ask the person who runs ARGUS to switch notices off."
)


def golden(
    headline: str, severity: str | None, count: str, link: str, reminder: bool = False
) -> str:
    lines = (
        ["This is a reminder: it is still waiting for a person to look at it.", ""]
        if reminder
        else []
    )
    lines += [headline, ""]
    if severity is not None:
        lines.append(f"Severity: {severity}")
    lines += [count, "", "Open it in ARGUS:", link, "", FOOTER]
    return "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("kind", "subject", "headline", "count"),
    [
        (
            "case_active",
            "A confirmed case is still active",
            "A case that was confirmed as a real incident is still showing activity.",
            "Activity seen on 3 days since the verdict or containment.",
        ),
        (
            "after_closure",
            "Activity after a case was closed",
            "A case that was closed as fixed has shown new activity.",
            "Noted 3 times.",
        ),
        (
            "closure_waiting",
            "A closure has been waiting for approval",
            "A request to close a case has waited for approval for more than 12 hours.",
            "Waiting for 3 hours.",
        ),
        (
            "ioc_hit",
            "A campus host reached a known-bad address",
            "A campus host was seen reaching an address that a threat list marks as bad with high"
            " confidence.",
            "3 high-confidence listed addresses or names.",
        ),
        (
            "outage",
            "ARGUS cannot watch everything",
            "Part of ARGUS, or the SIEM it reads, has not been working for more than an hour, so"
            " alerts may be going unwatched.",
            "For about 3 hours so far.",
        ),
    ],
)
def test_the_exact_words_of_each_notice(
    kind: Kind, subject: str, headline: str, count: str
) -> None:
    said = render.render(intent(kind, count=3), BASE)
    where = {"outage": f"{BASE}/health", "ioc_hit": f"{BASE}/go/investigation/{ID}"}.get(kind, LINK)
    assert said.subject == f"[ARGUS High] {subject}"
    assert said.body == golden(headline, "High", count, where)
    assert said.link == where
    again = render.render(intent(kind, "reminder", count=3), BASE)
    assert again.subject == f"[ARGUS High] Still waiting: {subject}"
    assert again.body == golden(headline, "High", count, where, reminder=True)


def test_the_exact_words_of_the_singular_counts_the_end_and_the_n_more_notice() -> None:
    one = {
        "case_active": "Activity seen on 1 day since the verdict or containment.",
        "after_closure": "Noted 1 time.",
        "closure_waiting": "Waiting for 1 hour.",
        "ioc_hit": "1 high-confidence listed address or name.",
        "outage": "For about 1 hour so far.",
    }
    for kind, line in one.items():
        said = render.render(intent(kind, count=1), BASE)  # type: ignore[arg-type]
        assert line in said.body.split("\n")  # a whole line, not a part of one
    ended = render.render(intent("outage", "ended", count=1), BASE)
    assert ended.subject == "[ARGUS] The earlier outage is over"
    assert ended.body == golden(
        "The problem reported earlier has cleared.",
        None,
        "It lasted about 1 hour.",
        f"{BASE}/health",
    )
    five = render.render(intent("outage", "ended", count=5), BASE).body
    assert "It lasted about 5 hours." in five.split("\n")
    more = render.render_more([intent("case_active"), intent("ioc_hit", severity="low")], BASE)
    assert more.subject == "[ARGUS High] 2 more notices"
    assert more.body == golden(
        "2 more things need a look. They are not listed one by one, to keep this calm.",
        "High",
        "2 more notices.",
        f"{BASE}/",
    )
    assert "1 more notice." in render.render_more([intent("case_active")], BASE).body.split("\n")
    assert render.render_test() == render.Rendered(
        "ARGUS test notice",
        "This is a test message from ARGUS: if you can read it, notices can reach you.\n",
        "",
    )


def test_a_page_with_an_id_that_is_missing_is_refused_in_these_words() -> None:
    bad = Target.__new__(Target)  # a record that skipped its own check
    object.__setattr__(bad, "page", "case")
    object.__setattr__(bad, "id", None)
    with pytest.raises(ValueError, match=r"^this page needs an id$"):
        render.link(BASE, bad)
    with pytest.raises(
        ValueError, match=r"^the web address for links is a scheme and a host name only$"
    ):
        render.link("nope", Target("home"))


def test_a_negative_count_is_shown_as_zero_never_as_a_minus_sign() -> None:
    assert "seen on 0 days" in render.render(intent("case_active", count=-4), BASE).body


def test_a_rendered_notice_is_fixed_and_an_empty_fold_is_refused_in_these_words() -> None:
    said = render.render_test()
    with pytest.raises(dataclasses.FrozenInstanceError):
        said.subject = "x"  # type: ignore[misc]
    with pytest.raises(ValueError, match=r"^nothing was folded$"):
        render.render_more([], BASE)


def test_the_closure_headline_names_the_threshold_the_trigger_uses() -> None:
    """The plan's "over 24 hours" became 12 (review R4): the words and the rule move together."""
    from argus.notices import triggers

    assert (
        f"more than {triggers.WAITING.total_seconds() / 3600:.0f} hours"
        in (render.HEADLINE["closure_waiting"])
    )


def test_the_end_of_an_outage_does_not_claim_that_everything_works_again() -> None:
    """Another outage may still last (review R11)."""
    assert "everything" not in render.ENDED_HEADLINE
