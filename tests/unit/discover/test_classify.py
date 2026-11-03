"""The classifier of `argus discover` (P4-D1): what a family of indices is, from its name and the
fields its mapping has. Pure, so it is tested with names and field sets, and by properties:
evidence only adds, and a confidence never falls as the evidence grows."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.discover import classify
from argus.discover.classify import (
    FIELD_HINTS,
    HIGH_SCORE,
    MEDIUM_SCORE,
    MIN_SCORE,
    NAME_HINTS,
    NAME_ONLY_SCORE,
    RANK,
    Candidate,
    Confidence,
    Typed,
    candidates,
    confidence_of,
    score,
    words,
)
from argus.discover.classify import (
    classify as classify_family,
)
from argus.site import FIELD_ROLES, LOG_ROLES, Role

pytestmark = pytest.mark.unit

SCORED = [r for r in LOG_ROLES if r is not Role.OTHER]
ALL_WORDS = sorted({w for hints in NAME_HINTS.values() for w in hints} | {"zzz", "logs", "2026"})
ALL_FIELDS = sorted({f for hints in FIELD_HINTS.values() for f in hints} | {"nothing.here"})


def test_the_hints_name_only_roles_and_known_fields() -> None:
    assert set(NAME_HINTS) == set(FIELD_HINTS) == set(SCORED)
    known = {name for names in FIELD_ROLES.values() for name in names.values()} | {
        "email.from.address",
        "email.to.address",
        "email.message_id",
    }
    for hints in FIELD_HINTS.values():
        assert set(hints) <= known
    assert all(
        p > 0 for hints in (*NAME_HINTS.values(), *FIELD_HINTS.values()) for p in hints.values()
    )


@pytest.mark.parametrize(
    ("name", "present", "role", "confidence"),
    [
        (
            "acme-logs-squid-*",
            ["source.ip", "destination.ip", "url.original", "destination.bytes"],
            Role.PROXY,
            Confidence.HIGH,
        ),
        (
            "logs-nginx.access-default",
            ["source.ip", "url.path", "url.domain", "user_agent.original"],
            Role.WEB,
            Confidence.HIGH,
        ),
        (
            "logs-dns.query-default",
            ["dns.question.name", "dns.question.type", "source.ip"],
            Role.DNS,
            Confidence.HIGH,
        ),
        (
            "acme-logs-sso-*",
            ["user.name", "event.outcome", "event.action", "user_agent.original", "source.ip"],
            Role.AUTH,
            Confidence.HIGH,
        ),
        (
            "acme-logs-sso-*",
            ["user.name", "event.outcome", "source.ip"],
            Role.AUTH,
            Confidence.MEDIUM,
        ),
        (
            "logs-postfix.log-default",
            ["email.from.address", "email.to.address"],
            Role.MAIL,
            Confidence.HIGH,
        ),
        (
            "custom-weblogs-*",
            ["url.path", "url.domain", "http.response.body.bytes"],
            Role.WEB,
            Confidence.MEDIUM,
        ),
        ("logs-nginx.access-default", ["url.path"], Role.WEB, Confidence.MEDIUM),
        ("acme-logs-postfix-*", [], Role.MAIL, Confidence.LOW),
    ],
)
def test_what_a_family_is(
    name: str, present: list[str], role: Role, confidence: Confidence
) -> None:
    verdict = classify_family(name, present)
    assert verdict.role is role
    assert verdict.confidence is confidence
    assert verdict.evidence  # always says why


@pytest.mark.parametrize(
    ("name", "present"),
    [
        ("metrics-system.cpu-default", ["@timestamp"]),
        ("logs-elastic_agent.filebeat-default", ["source.ip"]),
        ("zzz-*", []),
        ("", []),
    ],
)
def test_what_is_no_log_role(name: str, present: list[str]) -> None:
    assert classify_family(name, present).role is None


def test_a_product_name_alone_is_a_low_confidence_proposal_read_or_not() -> None:
    squid = classify_family("acme-logs-squid-*", ["@timestamp"])  # read: no squid fields
    assert (squid.role, squid.confidence) == (Role.PROXY, Confidence.LOW)
    # a weaker word (3 points) is proposed too: reading a mapping that has none of its fields
    # must not remove what the name alone kept (F15)
    for present in ([], ["@timestamp"]):
        weak = classify_family("acme-logs-sso-*", present)
        assert (weak.role, weak.confidence) == (Role.AUTH, Confidence.LOW)
    assert classify_family("metrics-system.cpu-default", []).role is None
    assert classify_family("acme-logs-dns-*", ["@timestamp"]).role is Role.DNS


@given(st.sampled_from(sorted({w for hints in NAME_HINTS.values() for w in hints})),
       st.lists(st.sampled_from(ALL_FIELDS), max_size=8))  # fmt: skip
def test_reading_a_mapping_never_removes_a_proposal(word: str, present: list[str]) -> None:
    by_name = classify_family(f"x-{word}-*", [])
    with_mapping = classify_family(f"x-{word}-*", present)
    if by_name.role is not None:
        assert with_mapping.role is not None


def test_a_family_that_looks_like_two_roles_names_the_rival_without_losing_confidence() -> None:
    # a web access log with proxy-like fields and an ambiguous name
    verdict = classify_family(
        "logs-access-proxy-*",
        ["url.original", "destination.ip", "url.path", "url.domain", "source.ip"],
    )
    assert verdict.role is not None
    assert verdict.rivals
    assert any("also looks like" in line for line in verdict.evidence)


def test_the_roles_do_not_overlap_on_their_telltale_fields() -> None:
    assert classify_family("x-*", ["dns.question.name"]).role is Role.DNS
    assert (
        classify_family("x-*", ["url.path", "url.domain", "user_agent.original"]).role is Role.WEB
    )
    assert classify_family("x-*", ["email.from.address", "email.to.address"]).role is Role.MAIL
    assert classify_family("x-*", ["source.ip"]).role is None  # one shared field is nothing


def test_words_are_the_alphanumeric_runs_of_a_name() -> None:
    assert words("logs-nginx.access-default") == {"logs", "nginx", "access", "default"}
    assert words("ACME-Logs-Squid-*") == {"acme", "logs", "squid"}
    assert words("") == frozenset()


# --------------------------------------------------------------------------- monotonicity


@given(
    role=st.sampled_from(SCORED),
    name=st.sets(st.sampled_from(ALL_WORDS)),
    present=st.sets(st.sampled_from(ALL_FIELDS)),
    more_name=st.sets(st.sampled_from(ALL_WORDS)),
    more_fields=st.sets(st.sampled_from(ALL_FIELDS)),
)
def test_more_evidence_never_lowers_a_roles_score_or_confidence(
    role: Role, name: set[str], present: set[str], more_name: set[str], more_fields: set[str]
) -> None:
    before = score(role, name, present)
    after = score(role, name | more_name, present | more_fields)
    assert after.name_points >= before.name_points
    assert after.field_points >= before.field_points
    assert after.total >= before.total
    assert set(before.name_hits) <= set(after.name_hits)
    assert set(before.field_hits) <= set(after.field_hits)
    low = confidence_of(before.total, before.name_points, before.field_points)
    high = confidence_of(after.total, after.name_points, after.field_points)
    assert RANK[high] >= RANK[low]


@given(
    st.integers(0, 40),
    st.integers(0, 20),
    st.integers(0, 20),
    st.integers(0, 10),
    st.integers(0, 10),
    st.integers(0, 10),
)
def test_a_confidence_never_falls_as_its_points_rise(
    total: int, names: int, fields: int, d_total: int, d_names: int, d_fields: int
) -> None:
    assert (
        RANK[confidence_of(total + d_total, names + d_names, fields + d_fields)]
        >= RANK[confidence_of(total, names, fields)]
    )


@given(
    st.sets(st.sampled_from(ALL_WORDS)),
    st.sets(st.sampled_from(ALL_FIELDS)),
    st.sets(st.sampled_from(ALL_FIELDS)),
)
def test_the_best_roles_score_never_falls_as_fields_are_added(
    name: set[str], present: set[str], more: set[str]
) -> None:
    def best(fields: set[str]) -> int:
        return max(score(r, name, fields).total for r in SCORED)

    assert best(present | more) >= best(present)


def test_the_thresholds_are_ordered() -> None:
    assert 0 < MIN_SCORE < MEDIUM_SCORE < HIGH_SCORE
    assert confidence_of(MIN_SCORE, 0, MIN_SCORE) is Confidence.LOW
    assert confidence_of(MEDIUM_SCORE, 0, MEDIUM_SCORE) is Confidence.MEDIUM
    assert confidence_of(HIGH_SCORE, 1, HIGH_SCORE - 1) is Confidence.MEDIUM  # the name must count
    assert confidence_of(HIGH_SCORE, 2, HIGH_SCORE - 2) is Confidence.HIGH


@given(st.sets(st.sampled_from(ALL_WORDS)), st.sets(st.sampled_from(ALL_FIELDS)))
def test_a_proposed_role_always_qualifies_and_is_the_best(
    name: set[str], present: set[str]
) -> None:
    verdict = classify_family("-".join(sorted(name)), present)
    scores = {r: score(r, words("-".join(sorted(name))), present) for r in SCORED}
    totals = {r: s.total for r, s in scores.items()}
    qualifying = {r: s for r, s in scores.items() if classify.qualifies(s)}
    if verdict.role is None:
        assert not qualifying
    else:
        assert totals[verdict.role] >= NAME_ONLY_SCORE
        assert verdict.role in qualifying
        # the best of the roles that qualify
        assert totals[verdict.role] == max(totals[r] for r in qualifying)


# --------------------------------------------------------------------------- the listing


LISTING = {
    "indices": [
        {"name": "acme-logs-squid-2026.10.29"},
        {"name": "acme-logs-squid-2026.10.30"},
        {"name": "acme-logs-dns-2026.10.30"},
        {"name": "app-metrics-2026.10.30"},
        {"name": ".kibana_8.19.12_001"},
        {"name": "single-index"},
        {
            "name": ".ds-logs-nginx.access-default-2026.10.30-000001",
            "data_stream": "logs-nginx.access-default",
        },
        {"name": "backing-without-flag-2026.10.30-000001"},
        7,
    ],
    "aliases": [{"name": "logs-all"}, {"name": ".hidden-alias"}, {"x": 1}],
    "data_streams": [
        {
            "name": "logs-nginx.access-default",
            "timestamp_field": "@timestamp",
            "backing_indices": [
                ".ds-logs-nginx.access-default-2026.10.28-000001",
                ".ds-logs-nginx.access-default-2026.10.30-000002",
            ],
        },
        {"name": ".internal-stream", "backing_indices": []},
    ],
}  # fmt: skip


def test_a_listing_is_grouped_into_candidate_families() -> None:
    found = {c.pattern: c for c in candidates(LISTING)}
    assert set(found) == {
        "logs-nginx.access-default",
        "acme-logs-squid-*",
        "acme-logs-dns-*",
        "app-metrics-*",
        "logs-all",
    }
    squid = found["acme-logs-squid-*"]
    assert (squid.kind, squid.days) == ("daily", ("2026.10.29", "2026.10.30"))
    assert squid.sample == "acme-logs-squid-2026.10.30"  # the newest
    stream = found["logs-nginx.access-default"]
    assert stream.kind == "stream"
    assert stream.time_field == "@timestamp"
    assert stream.sample == ".ds-logs-nginx.access-default-2026.10.30-000002"
    assert stream.days == ("2026.10.28", "2026.10.30")
    assert found["logs-all"].kind == "alias"
    assert found["logs-all"].sample == "logs-all"
    # a single index with no day, a dot-index and a backing index are no family
    assert "single-index" not in found
    assert ".kibana_8.19.12_001" not in found


def test_a_listing_with_nothing_or_junk_has_no_candidates() -> None:
    assert candidates({}) == []
    assert candidates({"indices": "x", "aliases": None, "data_streams": [3, {"name": 5}]}) == []


def test_the_candidates_to_examine_are_ordered_by_their_names() -> None:
    by_pattern = {c.pattern: classify.name_score(c) for c in candidates(LISTING)}
    assert by_pattern["acme-logs-squid-*"] == 4
    assert by_pattern["logs-nginx.access-default"] == 4 + 1  # nginx, access
    assert by_pattern["app-metrics-*"] == 0


# --------------------------------------------------------------------------- time and fields


def test_the_event_time_field() -> None:
    stream = Candidate("s", "stream", time_field="event.created")
    assert classify.time_field(stream, {}) == ("event.created", "the data stream's timestamp field")
    daily = Candidate("d-*", "daily")
    mapped = {"event.created": Typed("date"), "@timestamp": Typed("keyword")}
    assert classify.time_field(daily, mapped)[0] == "event.created"
    assert classify.time_field(daily, {"@timestamp": Typed("date")})[0] == "@timestamp"
    field_, why = classify.time_field(daily, {})
    assert field_ == "@timestamp"
    assert "guess" in why


def test_the_fields_that_differ_from_ecs_and_the_notes() -> None:
    mapped = {
        "url.domain": Typed("text", True),
        "url.path": Typed("keyword"),
        "source.ip": Typed("ip"),
        "user_agent.original": Typed("text", False),
        "http.request.method": Typed("text", True),
    }
    entries, notes = classify.field_names(Role.WEB, mapped)
    assert entries == {"domain": "url.domain.keyword"}  # the method is returned, never queried
    assert not any("user_agent.original" in n for n in notes)  # nor is the agent, in a web family
    entries, notes = classify.field_names(Role.AUTH, {"user_agent.original": Typed("text")})
    assert entries == {}
    assert any("cannot be queried" in n for n in notes)
    entries, notes = classify.field_names(Role.WEB, mapped)
    assert any("http.response.status_code" in n and "not mapped" in n for n in notes)
    assert not any("url.path" in n for n in notes)


def test_retention_from_the_dated_indices() -> None:
    squid = next(c for c in candidates(LISTING) if c.pattern == "acme-logs-squid-*")
    r = classify.retention_of(squid, "5d")
    assert (r.days_kept, r.oldest, r.newest, r.delete_after) == (
        2,
        "2026.10.29",
        "2026.10.30",
        "5d",
    )
    alias = classify.retention_of(Candidate("logs-all", "alias"))
    assert alias.days_kept is None
    assert alias.note
