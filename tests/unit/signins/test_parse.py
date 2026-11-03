"""Reading the answer strictly (AR6, D-216): a whole answer becomes lookups and sightings; anything
that is not exactly the template's shape is a BadAnswer and is stored as incomplete, never as
"none seen"."""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest

from argus.signins import model as m
from argus.signins import parse
from tests.unit.signins import kit

pytestmark = pytest.mark.unit
LOOKED = datetime(2026, 10, 29, 3, 0, tzinfo=UTC)
P = kit.params(["10.1.2.3", "10.1.2.4", "10.1.2.5"])


def parsed(body: dict[str, Any]) -> parse.Parsed:
    return parse.parse(P, body, LOOKED)


def test_a_whole_answer_gives_a_lookup_for_every_address_and_the_sightings() -> None:
    a = kit.sighting("user01", address="10.1.2.3", hours=(9, 10), events=6, failures=1)
    b = kit.sighting("user02", address="10.1.2.3", hours=(14,), events=2, agent=kit.SAFARI)
    got = parsed(kit.answer({"10.1.2.3": [a, b]}))
    assert [(lk.address, lk.complete, lk.accounts, lk.more_accounts) for lk in got.lookups] == [
        ("10.1.2.3", True, 2, 0),
        ("10.1.2.4", True, 0, 0),  # asked, no sign-in: complete, none seen
        ("10.1.2.5", True, 0, 0),
    ]
    assert all(lk.looked_at == LOOKED and lk.reason is None for lk in got.lookups)
    first = next(s for s in got.sightings if s.user == "user01")
    assert (first.events, first.successes, first.failures) == (6, 5, 1)
    assert first.hours == (9, 10)
    assert first.first_at == a.first_at
    assert first.last_at == a.last_at
    assert [(x.text, x.events) for x in first.agents] == [(kit.CHROME, 6)]
    assert {s.user for s in got.sightings} == {"user01", "user02"}


def test_accounts_that_were_not_listed_are_counted_as_more() -> None:
    listed = [kit.sighting(f"user{n:02d}", hours=(9,), events=1) for n in range(10)]
    body = kit.answer({"10.1.2.3": listed}, accounts={"10.1.2.3": 14})
    (lk, *_) = parsed(body).lookups
    assert (lk.accounts, lk.more_accounts) == (14, 4)


def test_events_by_accounts_that_were_not_listed_mean_at_least_one_more() -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting()]}, other={"10.1.2.3": 5})
    (lk, *_) = parsed(body).lookups
    assert (lk.accounts, lk.more_accounts) == (2, 1)


def test_an_address_with_events_but_no_account_name_is_incomplete_not_none_seen() -> None:
    """D-223: events that carry no (usable) account name vanish from the accounts aggregation
    without raising ``sum_other_doc_count``; storing them as "complete, no account" would read as
    "no one signed in"."""
    body = kit.answer({"10.1.2.3": []})
    body["aggregations"]["ips"]["buckets"][0]["doc_count"] = 7
    (lk, *_) = parsed(body).lookups
    assert (lk.address, lk.complete, lk.reason, lk.unnamed) == ("10.1.2.3", False, m.UNNAMED, 7)
    assert (lk.accounts, lk.more_accounts) == (0, 0)


def test_the_named_accounts_of_a_day_with_unnamed_events_are_kept_beside_the_gap() -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting("user01", hours=(9,), events=4)]})
    body["aggregations"]["ips"]["buckets"][0]["doc_count"] = 6  # two events without a name
    got = parsed(body)
    (lk, *_) = got.lookups
    assert (lk.complete, lk.reason, lk.unnamed) == (False, m.UNNAMED, 2)
    assert [s.user for s in got.sightings] == ["user01"]
    assert lk.has_answer


def test_an_account_with_an_empty_name_counts_as_unnamed_events() -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting("x", hours=(9,), events=4)]})
    user(body).update(key="  ")
    got = parsed(body)
    (lk, *_) = got.lookups
    assert (lk.reason, lk.unnamed, got.sightings) == (m.UNNAMED, 4, ())


def test_a_multi_valued_name_that_overcounts_is_not_unnamed() -> None:
    """A document with two names is in two buckets: the buckets may add up to more than the
    address's documents. That is no unnamed event."""
    body = kit.answer({"10.1.2.3": [kit.sighting("user01", hours=(9,), events=4)]})
    body["aggregations"]["ips"]["buckets"][0]["doc_count"] = 3
    (lk, *_) = parsed(body).lookups
    assert lk.complete


def test_text_that_the_database_would_refuse_is_made_storable() -> None:
    """D-222: a NUL, a lone surrogate or a control character in an account name or a browser string
    must never reach the database, where it would refuse the whole batch; failed sign-ins carry
    names anyone can type."""
    body = kit.answer({"10.1.2.3": [kit.sighting("x", hours=(9,), events=4)]})
    user(body).update(key="al\x00ice\ud800\x07")
    user(body)["agents"]["buckets"] = [{"key": "Moz\x00illa\udc00/5.0\x1b[0m", "doc_count": 4}]
    (sight,) = parsed(body).sightings
    assert sight.user == "al\ufffdice\ufffd\ufffd"
    assert sight.agents[0].text == "Moz\ufffdilla\ufffd/5.0\ufffd[0m"
    sight.user.encode("utf-8")  # storable
    sight.agents[0].text.encode("utf-8")


def test_a_name_longer_than_the_database_keeps_is_cut_not_refused() -> None:
    body = kit.answer({"10.1.2.3": [kit.sighting("x", hours=(9,), events=4)]})
    user(body).update(key="n" * 400)
    (sight,) = parsed(body).sightings
    assert len(sight.user) == m.MAX_USER_CHARS


def test_names_that_are_one_once_made_storable_are_merged_not_counted_as_two() -> None:
    a = kit.sighting("a\x00", hours=(9,), events=2)
    b = kit.sighting("a\x01", hours=(10,), events=3, agent=kit.SAFARI)
    body = kit.answer({"10.1.2.3": [a, b]}, accounts={"10.1.2.3": 2})
    got = parsed(body)
    (sight,) = got.sightings
    assert (sight.user, sight.events, sight.hours) == ("a\ufffd", 5, (9, 10))
    assert sorted(x.text for x in sight.agents) == sorted([kit.CHROME, kit.SAFARI])
    (lk, *_) = got.lookups
    assert (lk.complete, lk.accounts, lk.more_accounts) == (True, 1, 0)


def test_a_count_the_database_could_not_hold_is_a_bad_answer() -> None:
    with pytest.raises(parse.BadAnswer):
        parsed(bad(lambda b: user(b).update(doc_count=2**31)))


def bad(mutate: Any) -> dict[str, Any]:
    body = kit.answer({"10.1.2.3": [kit.sighting("user01", hours=(9, 10), events=4)]})
    mutate(body)
    return body


def user(body: dict[str, Any]) -> dict[str, Any]:
    return body["aggregations"]["ips"]["buckets"][0]["users"]["buckets"][0]  # type: ignore[no-any-return]


def ip(body: dict[str, Any]) -> dict[str, Any]:
    return body["aggregations"]["ips"]["buckets"][0]  # type: ignore[no-any-return]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.pop("aggregations"),
        lambda b: b["aggregations"].pop("ips"),
        lambda b: b["aggregations"]["ips"].update(buckets="x"),
        lambda b: b["aggregations"]["ips"].update(sum_other_doc_count=3),
        lambda b: ip(b).update(key="10.9.9.9"),  # an address that was not asked about
        lambda b: ip(b).update(key="not an address"),
        lambda b: ip(b).update(key=12),
        lambda b: b["aggregations"]["ips"]["buckets"].append(copy.deepcopy(ip(b))),  # twice
        lambda b: ip(b).update(doc_count=0),
        lambda b: ip(b).update(accounts={"value": -1}),
        lambda b: ip(b).update(accounts={}),
        lambda b: ip(b).pop("users"),
        lambda b: user(b).update(key=["a"]),
        lambda b: user(b).update(doc_count=0),
        lambda b: user(b).update(doc_count=True),
        lambda b: user(b).update(first={"value": None}),
        lambda b: user(b).update(first={"value": float("nan")}),
        lambda b: user(b).update(first={"value": 0}),  # 1970: not the day that was read
        lambda b: user(b).update(last={"value": kit.at(23, 59).timestamp() * 1000 + 3.6e6}),
        lambda b: user(b).update(first=user(b)["last"], last=user(b)["first"]),  # backwards
        lambda b: user(b)["outcomes"]["buckets"].append({"key": "success", "doc_count": 99}),
        lambda b: user(b)["outcomes"]["buckets"].append({"key": 5, "doc_count": 1}),
        lambda b: user(b)["agents"]["buckets"].extend(
            {"key": f"a{n}", "doc_count": 1} for n in range(4)
        ),
        lambda b: user(b)["agents"]["buckets"].append({"key": 7, "doc_count": 1}),
        lambda b: user(b)["hours"]["buckets"][0].update(
            key=user(b)["hours"]["buckets"][0]["key"] + 1800_000
        ),
        lambda b: user(b)["hours"]["buckets"][0].update(key=0),
        lambda b: user(b)["hours"]["buckets"][0].update(doc_count=99),  # hours do not add up
        lambda b: user(b)["hours"].update(buckets=[]),
    ],
)
def test_an_answer_that_is_not_the_contracts_shape_is_a_bad_answer(mutate: Any) -> None:
    with pytest.raises(parse.BadAnswer):
        parsed(bad(mutate))


def test_a_first_event_in_an_hour_with_no_events_is_a_bad_answer() -> None:
    body = bad(lambda b: None)
    user(body)["first"] = {"value": kit.at(3, 5).timestamp() * 1000}
    with pytest.raises(parse.BadAnswer, match="hour with no events"):
        parsed(body)


def test_an_error_message_never_carries_an_account_name() -> None:
    body = bad(lambda b: user(b).update(doc_count=0, key="user-secret-name"))
    with pytest.raises(parse.BadAnswer) as raised:
        parsed(body)
    assert "secret" not in str(raised.value)


def test_a_long_browser_string_is_cut_to_what_is_stored() -> None:
    body = bad(lambda b: None)
    user(body)["agents"]["buckets"] = [{"key": "A" * 900, "doc_count": 4}]
    (sight,) = parsed(body).sightings
    assert len(sight.agents[0].text) == m.MAX_AGENT_CHARS


def test_incomplete_lookups_cover_every_address_and_name_a_reason_from_the_list() -> None:
    got = parse.incomplete(P, LOOKED, m.PARTIAL)
    assert [lk.address for lk in got] == list(P.addresses)
    assert all(not lk.complete and lk.reason == "partial" and lk.accounts == 0 for lk in got)
    with pytest.raises(ValueError, match="not a reason"):
        parse.incomplete(P, LOOKED, "because")
