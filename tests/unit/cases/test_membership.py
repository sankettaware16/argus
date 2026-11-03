"""Which investigations belong to a case (Q-C2): the strong and weak matches, shared
infrastructure (content-delivery networks and clouds), ambiguity, and the properties the gate
names: no silent join on an ambiguous match, and a CDN or cloud address never joins by itself."""

from __future__ import annotations

import ipaddress
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import membership, opener
from argus.cases.membership import NO_SHARED, load_shared, resolve
from argus.cases.model import Indicator
from argus.config.errors import ConfigError

REPO = Path(__file__).resolve().parents[3]
CF = "104.21.5.5"  # inside Cloudflare's 104.16.0.0/13


@dataclass
class Seen:
    actors: tuple[Indicator, ...] = ()
    entities: frozenset[tuple[str, str]] = field(default_factory=frozenset)


def case(
    number: int, indicators: dict[tuple[str, str], str], state: str = "open"
) -> opener.Indexed:
    return opener.Indexed(uuid.UUID(int=number), number, state, None, set(), dict(indicators))  # type: ignore[arg-type]


def host(value: str) -> Indicator:
    return Indicator("ip", value, "actor")


SHARED = load_shared(REPO / "config" / "shared_infrastructure.yaml")


# --------------------------------------------------------------------------- shared infrastructure


@pytest.mark.parametrize(
    ("kind", "value", "shared"),
    [
        ("ip", "104.21.5.5", True),  # Cloudflare IPv4
        ("ip", "172.67.200.1", True),
        ("ip", "2606:4700:3030::6815:1", True),  # Cloudflare IPv6
        ("ip", "151.101.1.69", True),  # Fastly
        ("ip", "::ffff:104.21.5.5", True),  # an IPv4-mapped address is the IPv4 one
        ("ip", "77.221.155.150", False),  # a real C2 hoster
        ("ip", "10.0.0.1", False),
        ("ip", "104.15.255.255", False),  # just below the range
        ("ip", "not an address", False),
        ("domain", "d111.cloudfront.net", True),
        ("domain", "CLOUDFRONT.NET.", True),
        ("domain", "bucket.s3.amazonaws.com", True),
        ("domain", "evil.herokuapp.com", True),
        ("domain", "notcloudfront.net", False),  # a suffix means a whole label
        ("domain", "cloudfront.net.evil.example", False),
        ("domain", "evil.example", False),
        ("host", "104.21.5.5", False),  # only addresses and names are looked up
    ],
)
def test_what_is_shared_infrastructure(kind: str, value: str, shared: bool) -> None:
    assert (SHARED.reason(kind, value) is not None) is shared


def test_a_value_seen_in_very_many_investigations_is_shared() -> None:
    common = SHARED.with_common({("ip", "203.0.113.7")})
    assert common.reason("ip", "203.0.113.7") == membership.SHARED_COMMON
    assert common.reason("ip", "203.0.113.8") is None
    assert common.networks == SHARED.networks  # only the common set changed


def test_the_prevalence_limit_is_the_gates_own() -> None:
    from argus.context import batch1

    assert membership.COMMON_INVESTIGATIONS == batch1.INVESTIGATIONS_LIMIT


def test_the_shipped_list_loads_and_every_entry_is_well_formed() -> None:
    assert len(SHARED.networks) >= 20
    assert all(
        isinstance(n, ipaddress.IPv4Network | ipaddress.IPv6Network) for n in SHARED.networks
    )
    assert "cloudfront.net" in SHARED.domains


def test_a_bad_list_is_an_error_never_an_empty_list(tmp_path: Path) -> None:
    def written(text: str) -> Path:
        path = tmp_path / "s.yaml"
        path.write_text(text)
        return path

    with pytest.raises(ConfigError, match="is missing"):
        load_shared(tmp_path / "nope.yaml")
    with pytest.raises(ConfigError, match="invalid"):
        load_shared(written("version: 1\nnetworks: [300.1.1.0/24]\n"))
    with pytest.raises(ConfigError, match="invalid"):
        load_shared(written("version: 1\nnetworks: [10.0.0.1/24]\n"))  # host bits set
    with pytest.raises(ConfigError, match="invalid"):
        load_shared(written("version: 1\ndomains: [localhost]\n"))
    with pytest.raises(ConfigError, match="invalid"):
        load_shared(written("version: 1\nsurprise: yes\n"))
    ok = load_shared(written("version: 1\nnetworks: [198.51.100.0/24]\ndomains: [Example.NET.]\n"))
    assert ok.reason("ip", "198.51.100.9")
    assert ok.reason("domain", "a.example.net")


# --------------------------------------------------------------------------- matches


def test_an_actor_or_a_c2_in_common_is_a_strong_match() -> None:
    held = {("ip", "10.0.0.1"): "actor", ("ip", "77.221.155.150"): "c2"}
    by_actor = membership.keys(Seen((host("10.0.0.1"),)), held, SHARED)
    assert [(m.link, m.strong) for m in by_actor] == [("actor", True)]
    seen = Seen(entities=frozenset({("ip", "77.221.155.150")}))
    assert [(m.link, m.strong) for m in membership.keys(seen, held, SHARED)] == [("c2", True)]
    nothing = Seen((host("10.0.0.9"),), frozenset({("ip", "8.8.8.8")}))
    assert membership.keys(nothing, held, SHARED) == []


def test_an_actor_is_not_an_entity_and_a_c2_is_not_an_actor() -> None:
    """A host that merely appears in an investigation (as its target) is no actor; a C2 address
    that is the investigation's own actor does not become the case's c2 match."""
    held = {("ip", "10.0.0.1"): "actor", ("ip", "77.221.155.150"): "c2"}
    assert membership.keys(Seen(entities=frozenset({("ip", "10.0.0.1")})), held, SHARED) == []
    assert membership.keys(Seen((host("77.221.155.150"),)), held, SHARED) == []


def test_a_cloud_address_alone_is_a_weak_match_only() -> None:
    held = {("ip", CF): "c2"}
    (match,) = membership.keys(Seen(entities=frozenset({("ip", CF)})), held, SHARED)
    assert not match.strong
    assert match.shared == membership.SHARED_ADDRESS
    assert "content-delivery" in match.words()


def test_a_weak_match_is_suggested_and_never_joined() -> None:
    cases = [case(1, {("ip", CF): "c2"})]
    out = resolve(Seen(entities=frozenset({("ip", CF)})), cases, SHARED)
    assert out.join is None
    assert [(s.case.number, s.kind) for s in out.suggest] == [(1, "shared")]
    assert not out.ambiguous


def test_the_same_campus_host_beside_a_cloud_address_does_join() -> None:
    """Shared infrastructure is not enough alone; a second, real key is."""
    cases = [case(1, {("ip", CF): "c2", ("ip", "10.0.0.1"): "actor"})]
    seen = Seen((host("10.0.0.1"),), frozenset({("ip", CF)}))
    out = resolve(seen, cases, SHARED)
    assert out.join is not None
    assert (out.join.case.number, out.join.match.link) == (1, "actor")


def test_one_case_holding_the_best_match_wins_and_the_rest_are_suggested() -> None:
    cases = [
        case(7, {("ip", "10.0.0.1"): "actor"}),
        case(1, {("ip", "8.8.8.8"): "c2"}),
        case(9, {("ip", CF): "c2"}),
    ]
    seen = Seen((host("10.0.0.1"),), frozenset({("ip", "8.8.8.8"), ("ip", CF)}))
    out = resolve(seen, cases, SHARED)
    assert out.join is not None
    assert out.join.case.number == 7
    assert [(s.case.number, s.kind) for s in out.suggest] == [(1, "also"), (9, "shared")]


def test_equally_strong_cases_are_ambiguous_and_nothing_is_joined() -> None:
    cases = [case(7, {("ip", "10.0.0.1"): "actor"}), case(3, {("ip", "10.0.0.1"): "actor"})]
    out = resolve(Seen((host("10.0.0.1"),)), cases, SHARED)
    assert out.join is None
    assert out.ambiguous
    assert [(s.case.number, s.kind) for s in out.suggest] == [(3, "tie"), (7, "tie")]
    assert "matches other cases just as well" in out.suggest[0].words()


def test_a_closed_case_is_never_joined() -> None:
    out = resolve(
        Seen((host("10.0.0.1"),)), [case(1, {("ip", "10.0.0.1"): "actor"}, "closed")], NO_SHARED
    )
    assert out.join is None
    assert out.suggest == ()


def test_a_suspected_case_can_take_a_join() -> None:
    out = resolve(
        Seen((host("10.0.0.1"),)), [case(1, {("ip", "10.0.0.1"): "actor"}, "suspected")], NO_SHARED
    )
    assert out.join is not None


def test_a_domain_on_a_cloud_service_is_weak_too() -> None:
    held = {("domain", "evil.herokuapp.com"): "c2"}
    out = resolve(
        Seen(entities=frozenset({("domain", "evil.herokuapp.com")})), [case(1, held)], SHARED
    )
    assert out.join is None
    assert out.suggest[0].match.shared == membership.SHARED_NAME


# --------------------------------------------------------------------------- the opener uses it


def test_the_opener_never_joins_a_cdn_address_and_names_the_suggestion() -> None:
    from datetime import UTC, datetime

    from argus.cases.opener import Candidate

    now = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)
    candidate = Candidate(
        "review", 1, uuid.UUID(int=900), True, now, "Rule", "medium", (host("10.0.0.2"),), True,
        frozenset({("ip", CF)}), (), {"proxy.regularity": ("known", 0.1)},
    )  # fmt: skip
    cases = [case(4, {("ip", CF): "c2"})]
    (opening,) = opener.plan([candidate], cases, now=now, created_last_hour=0, shared=SHARED)
    assert opening.decision == "opened"  # on its own merits, a new case
    assert opening.case_ref == "new:1"
    assert [(s.case.number, s.kind) for s in opening.suggested] == [(4, "shared")]
    # without the shared list the same address would join (the old behaviour, shown by contrast)
    (without,) = opener.plan([candidate], [case(4, {("ip", CF): "c2"})], now=now,
                             created_last_hour=0)  # fmt: skip
    assert without.decision == "linked"


# --------------------------------------------------------------------------- properties

POOL_IPS = [f"203.0.113.{n}" for n in range(1, 7)] + [f"10.0.0.{n}" for n in range(1, 4)]
CDN_IPS = [f"104.21.0.{n}" for n in range(1, 4)]
ROLES = st.sampled_from(["actor", "c2", "indicator"])
INDICATORS = st.dictionaries(
    st.sampled_from([("ip", v) for v in (*POOL_IPS, *CDN_IPS)]), ROLES, max_size=5
)
CASES = st.lists(INDICATORS, min_size=0, max_size=5)
SEEN = st.builds(
    Seen,
    st.lists(st.sampled_from([host(v) for v in (*POOL_IPS, *CDN_IPS)]), max_size=3).map(tuple),
    st.sets(st.sampled_from([("ip", v) for v in (*POOL_IPS, *CDN_IPS)]), max_size=4).map(frozenset),
)
STATES = st.sampled_from(["suspected", "open", "assigned", "contained", "closed"])


def build(
    indicator_sets: list[dict[tuple[str, str], str]], states: list[str]
) -> list[opener.Indexed]:
    return [case(n + 1, ind, states[n % len(states)]) for n, ind in enumerate(indicator_sets)]


def rank(seen: Seen, c: opener.Indexed) -> tuple[bool, int] | None:
    matches = membership.keys(seen, c.indicators, SHARED)
    if not matches:
        return None
    best = matches[0]
    return (not best.strong, membership.LINK_ORDER[best.link])


@given(CASES, SEEN, st.lists(STATES, min_size=1, max_size=5))
def test_property_no_silent_join_on_an_ambiguous_match(
    sets: list[dict[tuple[str, str], str]], seen: Seen, states: list[str]
) -> None:
    cases = build(sets, states)
    out = resolve(seen, cases, SHARED)
    ranks = {c.number: rank(seen, c) for c in cases if c.state != "closed"}
    strong = {n: r for n, r in ranks.items() if r is not None and not r[0]}
    if out.join is not None:
        # exactly one case holds the strongest match, and it is the joined one
        best = min(r[1] for r in strong.values())
        assert [n for n, r in strong.items() if r[1] == best] == [out.join.case.number]
        assert out.join.match.strong
    elif strong:
        best = min(r[1] for r in strong.values())
        assert len([n for n, r in strong.items() if r[1] == best]) >= 2  # a tie, suggested
        assert out.ambiguous
        assert {s.case.number for s in out.suggest} >= set(strong)
    else:
        assert not out.ambiguous


@given(CASES, SEEN, st.lists(STATES, min_size=1, max_size=5))
def test_property_a_cdn_or_cloud_address_never_joins_by_itself(
    sets: list[dict[tuple[str, str], str]], seen: Seen, states: list[str]
) -> None:
    cases = build(sets, states)
    out = resolve(seen, cases, SHARED)
    if out.join is not None:
        assert out.join.match.value not in CDN_IPS  # a joined match is never a CDN address
        assert SHARED.reason(out.join.match.kind, out.join.match.value) is None
    for suggestion in out.suggest:
        if suggestion.kind == "shared":
            assert SHARED.reason(suggestion.match.kind, suggestion.match.value) is not None


@given(CASES, SEEN, st.lists(STATES, min_size=1, max_size=5), st.randoms(use_true_random=False))
def test_property_the_resolution_does_not_depend_on_the_order_of_the_cases(
    sets: list[dict[tuple[str, str], str]], seen: Seen, states: list[str], rng: object
) -> None:
    import random

    assert isinstance(rng, random.Random)
    cases = build(sets, states)
    shuffled = list(cases)
    rng.shuffle(shuffled)
    first, second = resolve(seen, cases, SHARED), resolve(seen, shuffled, SHARED)
    assert (first.join.case.number if first.join else None) == (
        second.join.case.number if second.join else None
    )
    assert [(s.case.number, s.kind) for s in first.suggest] == [
        (s.case.number, s.kind) for s in second.suggest
    ]


@given(CASES, SEEN, st.lists(STATES, min_size=1, max_size=5))
def test_property_a_closed_case_is_never_joined_or_suggested(
    sets: list[dict[tuple[str, str], str]], seen: Seen, states: list[str]
) -> None:
    cases = build(sets, states)
    closed = {c.number for c in cases if c.state == "closed"}
    out = resolve(seen, cases, SHARED)
    assert out.join is None or out.join.case.number not in closed
    assert not {s.case.number for s in out.suggest} & closed
