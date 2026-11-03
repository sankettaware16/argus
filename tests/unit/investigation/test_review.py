"""Q-F3 review: the pure regression tests, one group per finding (R1, R6, R7, R8). The reviewer's
repros are adapted; the tests that need Postgres are in ``tests/integration/investigation/
test_review.py``."""

from __future__ import annotations

import inspect
from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.gateway.errors import DeadlinePassedError, LaneBusyError
from argus.gateway.gateway import Gateway, Targets
from argus.gateway.health import HealthMemory
from argus.gateway.state import MemoryStore
from argus.gateway.templates import Purpose
from argus.investigation import catalogue, checks, gaps, measure
from argus.investigation.gaps import Profile
from tests.unit.gateway.fakes import FakeClock, FakeTransport, listing, ok
from tests.unit.investigation.kit import NOW, body, step

pytestmark = pytest.mark.unit


# ----------------------------------------------------------------------------- R1: lane debt


def heavy_answer(took: int) -> dict[str, object]:
    return {
        "took": took, "timed_out": False,
        "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
        "hits": {"total": {"value": 3, "relation": "eq"}, "hits": []},
        "aggregations": {"destination_count": {"value": 3}, "bytes": {"value": 10},
                         "timeline": {"buckets": [{"doc_count": 1}]}},
    }  # fmt: skip


async def test_r1_the_lanes_debt_is_a_typed_refusal_with_the_time_it_frees_up() -> None:
    """The gateway refused "frees up too late" with the same error as a deadline that passed,
    and the wave stored both as a SIEM timeout. The refusal is still a
    ``DeadlinePassedError`` (every other caller is unchanged) and now says when to come back."""
    from argus.context import proxy

    clock = FakeClock(now=NOW)
    transport = FakeTransport(clock=clock, latency=timedelta(milliseconds=2000))
    transport.on("_resolve", ok(listing("acme-logs-squid-2026.10.24")))
    transport.on("_search", ok(heavy_answer(2000)))
    memory = MemoryStore(memory=HealthMemory(probed_at=NOW))
    gateway = Gateway(transport, memory, targets=Targets(log_sources=frozenset({"squid"})),
                      clock=clock, sleep=clock.sleep)  # fmt: skip
    params = proxy.WindowParams(ip="10.20.3.4", start=NOW - timedelta(hours=4),
                                end=NOW - timedelta(hours=3))  # fmt: skip

    async def ask() -> object:
        memory.memory = HealthMemory(probed_at=clock.now)
        return await gateway.run(proxy.ProxyHost(), params, purpose=Purpose.INVESTIGATE,
                                 component="investigation", deadline=clock.now + timedelta(
                                     seconds=150))  # fmt: skip

    await ask()
    asked_at = clock.now
    with pytest.raises(LaneBusyError) as info:
        await ask()
    assert isinstance(info.value, DeadlinePassedError)
    assert info.value.reason == "deadline_passed"  # the ledger and every old handler see no change
    assert info.value.retry_at is not None
    assert info.value.retry_at - asked_at > timedelta(minutes=2)
    assert clock.now == asked_at  # refused at once, nothing slept, nothing sent
    assert sum("_search" in c.path for c in transport.calls) == 1


# ----------------------------------------------------------------------------- R6: the leak


def test_r6_the_gold_measurement_scores_the_test_split_by_default() -> None:
    assert inspect.signature(measure.measure).parameters["split"].default == "test"


def test_r6_the_report_is_per_split_and_marks_the_dev_split() -> None:
    answers = {"a": "true_positive", "b": "benign_expected", "c": "true_positive"}
    m = measure.Measured(
        answers, {"a": None, "b": None, "c": "true_positive"},
        [{"a": "true_positive", "b": None, "c": "true_positive"}], [], [],
        {"a": "test", "b": "test", "c": "dev"},
    )  # fmt: skip
    text = "\n".join(measure.report(m))
    assert text.index("== test split ==") < text.index("== dev split ==")
    assert (
        "checks the code and measures nothing" in text.split("== dev split ==")[1].splitlines()[0]
    )
    test_block, dev_block = text.split("== dev split ==")[0], text.split("== dev split ==")[1]
    assert "Gold measurement, repeat 1: 2 answered items" in test_block
    assert "Gold measurement, repeat 1: 1 answered items" in dev_block


def test_r6_the_report_says_no_item_is_lost_by_construction_and_mcnemar_is_a_sign_test() -> None:
    m = measure.Measured({"a": "true_positive"}, {"a": None}, [{"a": "true_positive"}], [], [],
                         {"a": "test"})  # fmt: skip
    text = "\n".join(measure.report(m))
    assert "0 by construction" in text
    assert "sign test" in text
    dry = measure.Measured({"a": "true_positive"}, {"a": None}, [], [], [], {"a": "test"})
    assert "sign test" not in "\n".join(measure.report(dry))  # nothing paired in a dry run


# ----------------------------------------------------------------------------- R7: wildcards

ALL = {"squid", "dns", "nginx", "postfix"}


@pytest.mark.parametrize(
    ("indices", "sources"),
    [
        (("acme-logs-*",), ALL),
        (("*",), ALL),
        (("acme-*",), ALL),
        (("acme-logs-*-*",), ALL),
        (("acme-logs-s*",), {"squid"}),
        (("acme-logs-squid*",), {"squid"}),
        (("acme-logs-squid-*",), {"squid"}),
        (("acme-logs-squid-2026.10.09",), {"squid"}),
        (("acme-logs-squid-2026.10.*",), {"squid"}),
        (("acme-logs-squid-2025.*",), {"squid"}),
        (("acme-logs-squid-*,acme-logs-nginx-*",), {"squid", "nginx"}),
        (("acme-logs-*", "-acme-logs-dns-*"), ALL - {"dns"}),
        (("acme-logs-*,-acme-logs-dns-*,-acme-logs-post*",), {"squid", "nginx"}),
        (("*squid*",), {"squid"}),
        (("ACME-LOGS-SQUID-*",), {"squid"}),
        # not a source of the SIEM's logs
        (("acme-logs-ddns-*",), set()),
        (("acme-logs-ddnsx-*", "squidward-*"), set()),
        (("squidward-*",), set()),
        (("acme-alerts-*",), set()),
        (("-acme-logs-squid-*",), set()),
        (("",), set()),
        # a name that is not ARGUS's own pattern still counts when it names a source as a word
        (("logs-squid.access-default",), {"squid"}),
    ],
)  # fmt: skip
def test_r7_a_wildcard_index_reads_the_sources_it_matches(
    indices: tuple[str, ...], sources: set[str]
) -> None:
    assert set(catalogue.sources_of(indices)) == sources


@pytest.mark.parametrize("pattern", ["acme-logs-*", "*", "acme-*"])
def test_r7_a_wildcard_rule_has_closable_gaps(pattern: str) -> None:
    """The threat-match rule of the production fixtures reads ``acme-logs-*``: its
    unanswered timeline step used to be "the rule reads no log that could answer it"."""
    indices = (pattern,)
    dossier = body(steps=[step(2, "deferred", ["timeline"])], indices=indices)
    (gap,) = gaps.find(dossier, Profile("threat_match", indices))
    assert gap.closable
    assert "proxy.host" in gap.closers


@given(
    source=st.sampled_from(sorted(ALL)),
    day=st.dates().map(lambda d: d.strftime("%Y.%m.%d")),
)
def test_r7_the_daily_index_of_a_source_is_always_read_by_its_own_name(
    source: str, day: str
) -> None:
    assert catalogue.sources_of((f"acme-logs-{source}-{day}",)) == {source}
    assert catalogue.sources_of((f"acme-logs-{source}-*",)) == {source}


# ----------------------------------------------------------------------------- R8: the entity

BAD = [
    "fe80::1%eth0",  # an IPv6 scope id (Python 3.9+ parses it)
    "fe80::1%" + "a" * 300,
    "fe80::1%a\x07b",
    "fe80::1%a\x00b",
    "fe80::1%a‮b",  # a bidirectional override
    "fe80::1%<script>",
    "10.0.0.1\n10.0.0.2",
    "10.0.0.1\x00",
    "10.\u0660.0.1",
    "bücher.example",  # not ASCII
    "a" * 300 + ".example",
    ("a" * 63 + ".") * 5 + "example",
    "exam ple.org",
    "evil.example‮",
    "‮evil.example",
    "evil.example/path",
    "http://evil.example",
    "evil.example:80",
    "",
    " ",
]


@pytest.mark.parametrize("entity", BAD, ids=[f"bad{n}" for n in range(len(BAD))])
@pytest.mark.parametrize("template", ["ti.lookup", "proxy.host", "web.followups"])
def test_r8_a_value_the_database_would_refuse_is_refused_in_plain_words(
    template: str, entity: str
) -> None:
    assert checks.clean(entity) is None
    assert checks.validate(template, entity) is not None


@pytest.mark.parametrize(
    ("entity", "kept"),
    [
        ("10.20.3.4", "10.20.3.4"),
        ("  10.20.3.4 ", "10.20.3.4"),
        ("2001:DB8::1", "2001:db8::1"),
        ("Example.ORG.", "example.org"),
        ("sub-domain.example.co", "sub-domain.example.co"),
    ],
)
def test_r8_what_is_asked_about_is_kept(entity: str, kept: str) -> None:
    assert checks.clean(entity) == kept


@given(st.text(max_size=400))
def test_r8_whatever_passes_the_validator_is_a_value_the_table_stores(entity: str) -> None:
    """The table refuses an entity of over 253 characters or with a control character; the
    validator refuses more than that, so a request is never refused by the table."""
    value = checks.clean(entity)
    if value is None:
        return
    assert len(value) <= 253
    assert value.isascii()
    assert all(33 <= ord(c) <= 126 for c in value)
    assert "%" not in value
    assert checks.validate("ti.lookup", entity) is None


# ----------------------------------------------------------------------------- R9, R10: limits


def test_r9_the_limits_in_the_table_are_the_ones_checks_names() -> None:
    """The caps are enforced by migration 0040's trigger and read first by ``checks.request``;
    the numbers are written in both places and must be the same."""
    import importlib.util
    from pathlib import Path

    from argus.db import migrate

    path = Path(migrate.MIGRATIONS_DIR) / "versions" / "0040_check_limits.py"
    spec = importlib.util.spec_from_file_location("argus_migration_0040", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sql = " ".join(module.LIMITS.split())
    assert f"IF mine >= {checks.OPEN_PER_PERSON} THEN" in sql
    assert f"IF everyones >= {checks.OPEN_IN_ALL} THEN" in sql
    assert f"IF today >= {checks.PER_PERSON_PER_DAY} THEN" in sql
    assert "AR001" in sql
    assert module.WEB_TAKEN_BACK == (
        "REVOKE INSERT (kind, source) ON investigation_checks FROM argus_web",
    )
