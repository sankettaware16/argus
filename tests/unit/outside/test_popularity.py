"""D-174: what makes a domain "popular". VirusTotal's ``popularity_ranks`` mixes lists of how many
people visit a site with lists of how many devices ask for a name; infected devices ask for a
command-and-control domain, so it ranks on the second kind. Only the first kind (Majestic, Tranco,
Cloudflare Radar's top buckets), and only a rank from the last year, makes a domain popular.

The real answers of 28 Oct (the lead looked them up): ``fast-dns-host.com`` and
``service-windows.com`` are the DNS campaign; ``agora.io`` is a real-time media service.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.outside import facts, providers
from argus.outside.providers import PROVIDERS, Reply

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
VT = PROVIDERS["virustotal"]


def when(days_ago: float) -> int:
    return int((NOW - timedelta(days=days_ago)).timestamp())


def lists(**ranks: tuple[int, float]) -> dict[str, Any]:
    """``popularity_ranks`` as VirusTotal writes it: list name -> rank and timestamp."""
    return {name.replace("_", " "): {"rank": rank, "timestamp": when(days)}
            for name, (rank, days) in ranks.items()}  # fmt: skip


FAST_DNS_HOST = lists(Cisco_Umbrella=(706_434, 2), Cloudflare_Radar=(50_000, 3))
SERVICE_WINDOWS = {
    "Alexa": {"rank": 268_720, "timestamp": 1_587_000_000},  # 2020: the list stopped long ago
    **lists(Cisco_Umbrella=(967_313, 2), Cloudflare_Radar=(100_000, 3)),
}
AGORA = {
    **lists(Majestic=(28_474, 5), Cisco_Umbrella=(9_014, 2), Cloudflare_Radar=(1_000, 3)),
    "Statvoo": {"rank": 11_569, "timestamp": when(900)},
    "Alexa": {"rank": 11_569, "timestamp": when(900)},
}


def body(ranks: object) -> Reply:
    attributes = {"last_analysis_stats": {"malicious": 5, "harmless": 80},
                  "popularity_ranks": ranks}  # fmt: skip
    return Reply(200, json.dumps({"data": {"attributes": attributes}}).encode())


# -- the real answers ---------------------------------------------------------------------------


def test_the_campaign_domains_are_unranked_and_agora_is_popular() -> None:
    fast = facts.popularity(FAST_DNS_HOST, NOW)
    assert fast["ranked"] is False  # DNS-volume lists only: Cloudflare Radar at 50,000 is not top
    assert fast["best_rank"] is None
    assert fast["ranks"] == {"Cloudflare Radar": 50_000, "Cisco Umbrella": 706_434}
    service = facts.popularity(SERVICE_WINDOWS, NOW)
    assert service["ranked"] is False
    assert "Alexa" not in service["ranks"]  # a rank from 2020 says nothing about today
    assert set(service["ranks"]) == {"Cisco Umbrella", "Cloudflare Radar"}
    agora = facts.popularity(AGORA, NOW)
    assert agora["ranked"] is True
    assert agora["best_rank"] == 1_000  # Cloudflare Radar's top-10,000 bucket
    assert set(agora["ranks"]) == {"Majestic", "Cisco Umbrella", "Cloudflare Radar"}  # 2023: stale


def test_the_provider_keeps_the_ranks_and_the_verdict_in_the_answer() -> None:
    got = VT.parse("domain", body(FAST_DNS_HOST), NOW)
    assert got.outcome == providers.FOUND
    assert got.answer["ranked"] is False
    assert got.answer["ranks"] == {"Cloudflare Radar": 50_000, "Cisco Umbrella": 706_434}
    assert got.answer["shape"] == facts.DOMAIN_SHAPE == 3
    agora = VT.parse("domain", body(AGORA), NOW).answer
    assert (agora["ranked"], agora["best_rank"]) == (True, 1_000)


def test_an_answer_of_the_old_shape_is_asked_again() -> None:
    old = {"shape": 2, "ranked": True, "malicious": 0}
    assert not facts.current_domain("found", old)  # asked again, never read
    assert facts.current_domain("found", {"shape": facts.DOMAIN_SHAPE})
    assert facts.current_domain("not_found", {})


# -- the rule -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "rank", "popular"),
    [
        ("Majestic", 1, True), ("Majestic", 4_000_000, True),  # any rank
        ("Tranco", 900_000, True), ("tranco", 5, True), ("  MAJESTIC ", 7, True),
        ("Cloudflare Radar", 10_000, True), ("Cloudflare Radar", 10_001, False),
        ("Cloudflare Radar", 100, True),
        ("Cisco Umbrella", 1, False), ("Alexa", 1, False), ("Statvoo", 1, False),
        ("Quantcast", 1, False), ("Majestic Million", 1, False), ("", 1, False),
    ],
)  # fmt: skip
def test_only_a_web_popularity_list_makes_a_domain_popular(
    name: str, rank: int, popular: bool
) -> None:
    got = facts.popularity({name: {"rank": rank, "timestamp": when(1)}}, NOW)
    assert got["ranked"] is popular
    assert facts.web_popular({name: rank}) is popular


@pytest.mark.parametrize(
    ("days_ago", "counts"),
    [(0, True), (364, True), (365, True), (365.5, False), (366, False), (3000, False), (-5, True)],
)
def test_only_a_rank_from_the_last_year_counts(days_ago: float, counts: bool) -> None:
    got = facts.popularity({"Majestic": {"rank": 10, "timestamp": when(days_ago)}}, NOW)
    assert got["ranked"] is counts
    assert ("Majestic" in got["ranks"]) is counts  # a stale rank is not kept for display either


@pytest.mark.parametrize(
    "entry",
    [
        {"rank": 10},
        {"rank": 10, "timestamp": "x"},
        {"rank": 10, "timestamp": None},
        {"rank": 0, "timestamp": 1},
        {"rank": "10", "timestamp": 1},
        {"timestamp": 1},
        5,
        None,
    ],
)
def test_a_rank_that_cannot_be_dated_does_not_count(entry: object) -> None:
    assert facts.popularity({"Majestic": entry}, NOW)["ranked"] is False


@pytest.mark.parametrize("junk", ["x", 5, [], None, [{"rank": 3}], {}, {5: {"rank": 3}}])
def test_a_reply_with_nothing_usable_is_unranked_not_unknown(junk: object) -> None:
    got = facts.popularity(junk, NOW)
    assert got == {"ranked": False, "best_rank": None, "ranks": {}}


def test_the_web_lists_and_the_best_web_rank() -> None:
    ranks = {"Cisco Umbrella": 5, "Majestic": 900, "Tranco": 300, "Cloudflare Radar": 20_000}
    assert facts.best_web_rank(ranks) == 300  # Umbrella's 5 and Radar's 20,000 do not count
    assert facts.best_web_rank({"Cisco Umbrella": 5}) is None
    assert facts.best_web_rank({}) is None


def test_the_ranks_kept_are_bounded_and_the_web_lists_come_first() -> None:
    many = {f"List {n}": {"rank": n, "timestamp": when(1)} for n in range(1, 40)}
    many["Majestic"] = {"rank": 9_000_000, "timestamp": when(1)}
    got = facts.popularity(many, NOW)
    assert got["ranked"] is True
    assert len(got["ranks"]) == facts.MAX_RANK_LISTS
    assert next(iter(got["ranks"])) == "Majestic"  # the one that counts is never cut


@given(
    st.dictionaries(
        st.one_of(st.sampled_from(["Majestic", "Tranco", "Cloudflare Radar", "Cisco Umbrella",
                                   "Alexa", "Statvoo", "Quantcast"]), st.text(max_size=40)),
        st.one_of(
            st.fixed_dictionaries({"rank": st.integers(-5, 3_000_000),
                                   "timestamp": st.integers(-10, 2_000_000_000)}),
            st.fixed_dictionaries({"rank": st.one_of(st.none(), st.text(), st.floats())}),
            st.integers(), st.none(),
        ),
        max_size=30,
    )
)  # fmt: skip
def test_popular_is_exactly_a_current_rank_in_a_web_list(raw: dict[str, Any]) -> None:
    def web(name: str, rank: int) -> bool:  # the rule, written out again
        key = " ".join((facts.clean(name, facts.MAX_LIST_NAME) or "").lower().split())
        return key in ("majestic", "tranco") or (key == "cloudflare radar" and rank <= 10_000)

    def current(entry: dict[str, Any]) -> bool:
        rank, seen = entry.get("rank"), entry.get("timestamp")
        return (
            isinstance(rank, int) and rank >= 1 and isinstance(seen, int)
            and 0 <= seen <= 4_102_444_800
            and NOW - datetime.fromtimestamp(seen, UTC) <= timedelta(days=365)
        )  # fmt: skip

    got = facts.popularity(raw, NOW)
    expected = [
        entry["rank"] for name, entry in raw.items()
        if isinstance(entry, dict) and current(entry) and web(name, entry["rank"])
    ]  # fmt: skip
    assert got["ranked"] is bool(expected)
    assert got["best_rank"] == (min(expected) if expected else None)
    assert len(got["ranks"]) <= facts.MAX_RANK_LISTS
    assert all(isinstance(v, int) and v >= 1 for v in got["ranks"].values())
    assert len(json.dumps(got)) < facts.MAX_ANSWER_JSON // 2


# -- how long an answer is kept -----------------------------------------------------------------

DAY, WEEK = timedelta(days=1), timedelta(days=7)


def test_a_popular_clean_domain_is_kept_for_the_week_not_the_clean_day() -> None:
    popular = {"malicious": 0, "engines": 90, "shape": facts.DOMAIN_SHAPE, "ranked": True}
    rare = {**popular, "ranked": False}
    assert facts.kept_for("virustotal", "found", popular, 3, WEEK, DAY) == WEEK
    assert facts.kept_for("virustotal", "found", rare, 3, WEEK, DAY) == DAY
    assert facts.kept_for("virustotal", "not_found", {}, 3, WEEK, DAY) == DAY
    ip = {"malicious": 0, "engines": 90}  # an address answer has no rank
    assert facts.kept_for("virustotal", "found", ip, 3, WEEK, DAY) == DAY
    assert facts.kept_for("virustotal", "found", {**rare, "malicious": 5}, 3, WEEK, DAY) == WEEK
    assert facts.kept_for("virustotal", "found", popular, 3, WEEK, None) == WEEK


# -- the words ----------------------------------------------------------------------------------


def test_the_sentence_names_the_dns_lists_that_do_not_make_a_domain_popular() -> None:
    answer = {**VT.parse("domain", body(FAST_DNS_HOST), NOW).answer}
    entry = facts.fact("virustotal", "domain", "fast-dns-host.example", "found", answer, 3)
    text = facts.describe(entry)
    assert "not among the popular sites (other lists: Cloudflare Radar 50000, Cisco Umbrella" in (
        text
    )
    popular = facts.fact(
        "virustotal",
        "domain",
        "agora.example",
        "found",
        VT.parse("domain", body(AGORA), NOW).answer,
        3,
    )
    assert "among the popular sites (rank 1000)" in facts.describe(popular)
    assert "other lists" not in facts.describe(popular)
