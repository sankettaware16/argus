"""The pure parts of the AR6 review fixes (D-222 to D-227): when a lookup is dated and final, which
addresses are devices, and what a missing index or a bad answer means to the pass."""

from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import UTC, date, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.assets.classify import IpClassifier
from argus.gateway.errors import (
    OverloadedError,
    PartialResultError,
    SourceMissingError,
)
from argus.signins import model as m
from argus.signins import parse, run, store
from argus.signins.template import DayParams
from tests.unit.signins import kit

pytestmark = pytest.mark.unit
D28 = date(2026, 10, 28)
CLASSIFIER = IpClassifier(None, ())


# ---------------------------------------------------------------- when a lookup is dated and final


def test_a_lookup_for_a_day_not_over_is_dated_no_later_than_what_it_read_plus_the_margin() -> None:
    end = datetime(2026, 10, 29, 15, 25, tzinfo=UTC)
    day = date(2026, 10, 29)
    assert m.stamp(day, end, end + timedelta(minutes=15)) == end + timedelta(minutes=15)
    assert m.stamp(day, end, end + timedelta(minutes=45)) == end + timedelta(minutes=15)
    lookup = m.Lookup("10.1.2.3", day, m.stamp(day, end, end + timedelta(hours=3)), True)
    assert lookup.covered_until() == end  # never claims more than was read


def test_a_lookup_for_a_finished_day_is_dated_when_it_was_answered() -> None:
    at = datetime(2026, 10, 29, 4, 0, tzinfo=UTC)
    assert m.stamp(D28, m.day_end(D28), at) == at
    lookup = m.Lookup("10.1.2.3", D28, at, True)
    assert lookup.covered_until() == m.day_end(D28)
    assert lookup.final(timedelta(hours=3))
    assert not lookup.final(timedelta(hours=5))


@given(
    answered=st.integers(0, 40 * 3600),
    read=st.integers(0, 86400),
    day_offset=st.integers(0, 3),
)
def test_a_lookup_never_claims_more_than_its_request_read(
    answered: int, read: int, day_offset: int
) -> None:
    day = D28 + timedelta(days=day_offset)
    end = m.day_start(day) + timedelta(seconds=max(read, 60))
    at = end + m.MARGIN + timedelta(seconds=answered)  # answered after the margin, as it must be
    covered = m.Lookup("10.1.2.3", day, m.stamp(day, end, at), True).covered_until()
    assert covered is not None
    assert covered == min(end, m.day_end(day))


def test_only_a_lookup_with_an_answer_is_final_or_covers_anything() -> None:
    late = m.day_end(D28) + timedelta(days=1)
    partial = m.Lookup("10.1.2.3", D28, late, False, 0, 0, m.PARTIAL)
    assert not partial.final(timedelta(hours=3))
    assert partial.covered_until() is None
    unnamed = m.Lookup("10.1.2.3", D28, late, False, 0, 0, m.UNNAMED, unnamed=3)
    assert unnamed.has_answer
    assert unnamed.final(timedelta(hours=3))


# ---------------------------------------------------------------- which addresses are devices


def key(*pairs: tuple[str, object]) -> str:
    return json.dumps([list(p) for p in pairs], separators=(",", ":"))


def test_the_source_of_the_traffic_is_the_device_and_the_destination_is_not() -> None:
    both = key(("source.ip", "10.1.2.3"), ("destination.ip", "10.1.2.7"))
    assert store.source_devices(both, CLASSIFIER) == ["10.1.2.3"]
    probed = key(("destination.ip", "10.1.2.7"), ("source.ip", "203.0.113.9"))
    assert store.source_devices(probed, CLASSIFIER) == []  # an outside scanner is no device
    only_destination = key(("destination.ip", "10.1.2.7"))
    assert store.source_devices(only_destination, CLASSIFIER) == []


def test_a_key_that_lists_its_sources_gives_every_campus_one() -> None:
    listed = key(("source.ip", ["10.1.2.9", "10.1.2.3", "8.8.8.8", "fe80::1", "x", 7]))
    assert store.source_devices(listed, CLASSIFIER) == ["10.1.2.3", "10.1.2.9"]
    client = key(("client.ip", "10.1.2.4"), ("dns.question.name", "example.org"))
    assert store.source_devices(client, CLASSIFIER) == ["10.1.2.4"]


@pytest.mark.parametrize("bad", ["", "not json", "{}", "[1, 2]", '[["source.ip"]]', "[[1, 2]]"])
def test_a_key_that_is_not_a_list_of_pairs_names_no_device(bad: str) -> None:
    assert store.source_devices(bad, CLASSIFIER) == []


def test_the_campus_resolvers_are_no_device() -> None:
    inv = uuid.uuid4()
    keys = {inv: key(("source.ip", ["10.53.0.2", "10.1.2.3"]))}
    nets = (ipaddress.ip_network("10.53.0.0/24"),)
    assert store.devices_of(keys, CLASSIFIER, nets) == {inv: ["10.1.2.3"]}
    assert store.devices_of(keys, CLASSIFIER) == {inv: ["10.1.2.3", "10.53.0.2"]}


# ---------------------------------------------------------------- what the pass makes of an error


def test_a_missing_index_inside_the_retention_is_retried_and_outside_it_is_gone() -> None:
    expired = SourceMissingError("source_expired", ("2026.10.28",))
    assert run.verdict_of(expired, kept=True) == (True, m.MISSING)
    assert run.verdict_of(expired, kept=False) == (True, m.GONE)
    not_yet = SourceMissingError("source_not_ready", ("2026.10.29",))
    assert run.verdict_of(not_yet, kept=True) == (True, None)  # nothing to say about it
    gone_stream = SourceMissingError("source_missing", ())  # a data stream that is not there
    assert run.verdict_of(gone_stream, kept=True) == (True, None)
    assert run.verdict_of(gone_stream, kept=False) == (True, None)  # never "the logs are gone"


def test_a_partial_answer_and_a_failure_stop_the_pass() -> None:
    assert run.verdict_of(PartialResultError("timed out")) == (False, m.PARTIAL)
    assert run.verdict_of(OverloadedError("429")) == (False, m.FAILED)


def test_an_incomplete_lookup_for_some_of_a_requests_addresses_carries_the_tries() -> None:
    params = DayParams(
        day=D28, addresses=("10.1.2.3", "10.1.2.4"), actions=kit.params().actions,
        end=m.day_end(D28),
    )  # fmt: skip
    only = ("10.1.2.4",)
    got = parse.incomplete(params, m.day_end(D28), m.STORE_FAILED, only=only)
    assert [(lk.address, lk.reason, lk.store_failures) for lk in got] == [
        ("10.1.2.4", m.STORE_FAILED, 1)
    ]
    assert parse.incomplete(params, m.day_end(D28), m.PARTIAL)[0].store_failures == 0
    with pytest.raises(ValueError, match="without an answer"):
        parse.incomplete(params, m.day_end(D28), m.UNNAMED)


def test_the_operators_view_of_a_lookup_says_the_reason_and_the_tries_without_a_name() -> None:
    from argus.signins import cli

    at = m.day_end(D28)
    assert cli._lookup_words(m.Lookup("10.1.2.3", D28, at, True, 2)) == "complete, 2 accounts"
    unnamed = m.Lookup("10.1.2.3", D28, at, False, 0, 0, m.UNNAMED, unnamed=5)
    assert cli._lookup_words(unnamed) == (
        "incomplete (unnamed_events, 5 sign-in events without an account name)"
    )
    stored = m.Lookup("10.1.2.3", D28, at, False, 0, 0, m.STORE_FAILED, store_failures=2)
    assert cli._lookup_words(stored) == "incomplete (store_failed, 2 of 3 tries)"
    assert cli._lookup_words(m.Lookup("10.1.2.3", D28, at, False, 0, 0, m.MISSING)) == (
        "incomplete (index_missing)"
    )
