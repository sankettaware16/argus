"""Q-B4: where a classic page's address leads in the app, and which classic forms are refused
(``argus.web.classic``): fixed paths and a parsed UUID only, a query kept only where the app reads
it the same way."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from urllib.parse import parse_qsl, quote, urlsplit

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy.ext.asyncio import create_async_engine
from starlette.routing import Route

from argus.web import classic
from argus.web.app import create_app

pytestmark = pytest.mark.unit
ID = "54c802b6-fb1a-5614-a6e4-f76c773213d2"


@pytest.mark.parametrize(
    ("path", "query", "target"),
    [
        ("/", "", "/app"),
        ("/", "view=open", "/app/inbox?view=open"),
        ("/", "view=known", "/app/inbox?view=known"),  # AR4b's tile and summary line
        ("/", "view=all&rule=r-1&sort=urgent&offset=100",
         "/app/inbox?view=all&rule=r-1&sort=urgent"),
        ("/", "view=all&kind=ip&value=10.0.0.1", "/app/inbox?view=all&kind=ip&value=10.0.0.1"),
        ("/", "offset=100", "/app/inbox"),
        ("/dashboard", "", "/app/dashboard"),
        ("/dashboard", "range=24h&severity=high&severity=critical&state=unreviewed",
         "/app/dashboard?range=24h&severity=high&severity=critical&state=unreviewed"),
        ("/dashboard", "range=7d&junk=1", "/app/dashboard?range=7d"),
        ("/rules", "", "/app/rules"),
        ("/hosts", "", "/app/hosts"),
        ("/patterns", "", "/app/patterns"),
        ("/proposals", "confirmed=3-1", "/app/proposals"),
        ("/tuning", "", "/app/tuning"),
        ("/metrics", "", "/app/metrics"),
        ("/gold", "", "/app/gold"),
        ("/health", "", "/app/health"),
        ("/glossary", "", "/app/glossary"),
        (f"/investigations/{ID}", "", f"/app/investigations/{ID}"),
        (f"/investigations/{ID}", "saved=reviewed&gold=1&columns=set&cols=a",
         f"/app/investigations/{ID}"),
        (f"/investigations/{ID}/report", "assessment=4", f"/app/investigations/{ID}?tab=report"),
        (f"/investigations/{ID}/alerts/AbC123", "", f"/app/investigations/{ID}?tab=alerts"),
        (f"/investigations/{ID.upper()}", "", f"/app/investigations/{ID}"),
    ],
)  # fmt: skip
def test_each_classic_page_leads_to_its_page_in_the_app(path: str, query: str, target: str) -> None:
    assert classic.redirect_target(path, query) == target


@pytest.mark.parametrize(
    "path",
    ["/access", "/signin", "/stepup", "/login", "/logout", "/classic", "/go/case/x", "/api/rules",
     "/api/v1/rules", "/app", "/app/rules", "/static/style.css", "/rules/", "/Rules",
     "/investigations/not-a-uuid", f"/investigations/{ID}/other", f"/investigations/{ID}/",
     "/investigations", "/patterns/review", "//evil.example/x", "/rules/../x"],
)  # fmt: skip
def test_no_other_path_is_moved(path: str) -> None:
    assert classic.redirect_target(path, "") is None


@pytest.mark.parametrize(
    ("path", "target"),
    [
        ("/patterns/review", "/app/patterns"),
        ("/proposals/confirm", "/app/proposals"),
        (f"/investigations/{ID}/review", f"/app/investigations/{ID}"),
        (f"/investigations/{ID}/accept", f"/app/investigations/{ID}"),
        (f"/investigations/{ID}/assess", f"/app/investigations/{ID}"),
        (f"/investigations/{ID}/gold", f"/app/investigations/{ID}"),
        (f"/investigations/{ID.upper()}/gold", f"/app/investigations/{ID}"),
    ],
)  # fmt: skip
def test_each_classic_form_is_refused_with_its_place_in_the_app(path: str, target: str) -> None:
    assert classic.action_target(path) == target


@pytest.mark.parametrize(
    "path",
    ["/logout", "/login", "/signin", "/stepup", "/api/login", "/api/v1/patterns/review", "/rules",
     f"/investigations/{ID}", f"/investigations/{ID}/other", "/patterns/review/x", "/proposals"],
)  # fmt: skip
def test_nothing_else_is_refused(path: str) -> None:
    assert classic.action_target(path) is None


@given(st.text(max_size=300), st.text(max_size=300))
def test_whatever_the_path_and_query_a_target_is_a_path_of_the_app_or_none(
    path: str, query: str
) -> None:
    for target in (classic.redirect_target(path, query), classic.action_target(path)):
        if target is None:
            continue
        parts = urlsplit(target)
        assert parts.scheme == ""
        assert parts.netloc == ""
        assert target.startswith("/app")
        assert not target.startswith("//")
        assert "\\" not in target
        assert "\n" not in target
        assert " " not in target


@given(st.uuids(), st.text(min_size=1, max_size=200))
def test_an_investigation_target_holds_only_the_parsed_id_and_a_fixed_tab(
    inv: uuid.UUID, tail: str
) -> None:
    for suffix, expect in (
        ("", ""),
        ("/report", "?tab=report"),
        (f"/alerts/{quote(tail)}", "?tab=alerts"),
        (f"/alerts/{tail}", "?tab=alerts"),  # decoded, with a newline in it too
    ):
        got = classic.redirect_target(f"/investigations/{inv}{suffix}", "saved=x&cols=%00")
        assert got == f"/app/investigations/{inv}{expect}"


@given(
    st.lists(
        st.tuples(
            st.sampled_from([*classic.INBOX_KEYS, "offset", "saved", "x"]),
            st.text(max_size=40),
        ),
        max_size=12,
    )
)
def test_the_inbox_query_keeps_only_the_keys_the_app_reads(pairs: list[tuple[str, str]]) -> None:
    from urllib.parse import urlencode

    target = classic.redirect_target("/", urlencode(pairs))
    assert target is not None
    kept = parse_qsl(urlsplit(target).query)
    assert {k for k, _ in kept} <= set(classic.INBOX_KEYS)
    expected = [(k, v) for k, v in pairs if k in classic.INBOX_KEYS and v != ""]
    assert kept == expected


def test_a_huge_query_is_dropped_not_copied() -> None:
    assert classic.redirect_target("/dashboard", "range=24h&" + "x=1&" * 2000) == "/app/dashboard"


SPELLINGS: list[Callable[[uuid.UUID], str]] = [
    lambda u: str(u),
    lambda u: str(u).upper(),
    lambda u: u.hex,
    lambda u: u.hex.upper(),
    lambda u: "{" + str(u) + "}",
    lambda u: "urn:uuid:" + str(u),
]


@given(
    st.uuids(), st.sampled_from(SPELLINGS), st.sampled_from(["review", "accept", "assess", "gold"])
)
def test_a_classic_form_is_refused_whatever_spelling_of_the_id_the_route_takes(
    inv: uuid.UUID, spell: Callable[[uuid.UUID], str], action: str
) -> None:
    """Review B4 finding 1: the route parses the id with pydantic (more spellings than the
    hyphenated form); the refusal reads the id the same way and points at the parsed one."""
    segment = spell(inv)
    assert classic.action_target(f"/investigations/{segment}/{action}") == (
        f"/app/investigations/{inv}"
    )
    assert classic.redirect_target(f"/investigations/{segment}", "") == f"/app/investigations/{inv}"
    assert classic.redirect_target(f"/investigations/{segment}/report", "") == (
        f"/app/investigations/{inv}?tab=report"
    )


@pytest.mark.parametrize("action", ["review", "accept", "assess", "gold"])
@pytest.mark.parametrize("segment", ["not-a-uuid", "x", "%00", "12345", "{" + ID, "?#"])
def test_a_classic_form_with_an_id_that_does_not_parse_is_refused_and_points_at_the_app(
    segment: str, action: str
) -> None:
    """The shape of the route is refused; the route would answer 422, but nothing reaches it."""
    assert classic.action_target(f"/investigations/{segment}/{action}") == "/app"


def test_every_classic_form_route_of_the_app_is_refused() -> None:
    """A drift guard: a new classic route that changes something (a form post outside /api and
    the sign-in family) must be covered by ``action_target``, or this fails."""
    engine = create_async_engine("postgresql+psycopg://openapi@127.0.0.1:1/none")  # never used
    app = create_app(engine)
    own = {"/signin", "/stepup", "/login", "/logout"}
    forms = [
        route.path
        for route in app.routes
        if isinstance(route, Route)
        and "POST" in (route.methods or ())
        and not route.path.startswith("/api")
        and route.path not in own
    ]
    assert len(forms) >= 6, forms  # the six classic forms
    for path in forms:
        shown = path.replace("{investigation_id}", str(uuid.UUID(ID)))
        assert classic.action_target(shown) is not None, path
