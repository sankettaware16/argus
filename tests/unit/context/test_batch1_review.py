"""Q-F4's independent review (findings F4-R1, R2, R4-R12), pinned: each test asserts the
right behaviour and failed on 18e2e6c, where the finding held. The send-time rules (F4-R3)
are in test_batch1_review_send.py; the planted shared addresses (F4-R2) on Postgres in
tests/integration/context/test_batch1_review_gate.py."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from argus.context import batch1, beacon, dns, paths, source_events
from argus.context.evidence import canonical, extract
from argus.context.packs import SNAPSHOT_BYTES, SNAPSHOT_ROWS, TaskSpec
from argus.gateway.gateway import Result

T = datetime(2026, 10, 20, 3, 0, tzinfo=UTC)
REF = {"task_key": "k", "status": "ok"}


def at(minutes: int) -> int:
    return int((T + timedelta(minutes=minutes)).timestamp() * 1000)


# --------------------------------------------------------------- F4-R1: random traffic


def random_minutes(p: float, seed: int, minutes: int = 360) -> list[int]:
    rng = random.Random(seed)
    return [m for m in range(minutes) if rng.random() < p]


@pytest.mark.parametrize("seed", range(5))
def test_random_traffic_is_not_a_beacon(seed: int) -> None:
    """A host that uses a site at random (busy in ~45 % of minutes, no rhythm) must not be
    called regular. On 18e2e6c it read 'about every 1.x minutes (± 1 min), still active'."""
    keys = random_minutes(0.45, seed)
    aggs = {
        "beats": {"buckets": [{"key": at(m), "doc_count": 3} for m in keys]},
        "first": {"value": at(keys[0])},
        "last": {"value": at(keys[-1])},
        "requests": {"value": 3 * len(keys)},
    }
    got = beacon.cadence(aggs, T, T + timedelta(hours=6))
    assert got.period is None, (got.period, got.jitter, got.regular_share, got.still_active)


# --------------------------------------------------------------- F4-R5: stale last contact


def test_contact_last_is_not_taken_from_the_top_25_only() -> None:
    """30 hosts reached the destination; the 25 busiest stopped at 04:00, a quiet host's
    request at 11:00 is the newest. contact.last is the answer's own newest request."""
    old = at(60)
    buckets = [{"key": f"10.0.0.{i}", "doc_count": 100 - i, "first": {"value": at(0)},
                "last": {"value": old}} for i in range(1, 26)]  # fmt: skip
    aggs = {"requests": {"value": 3000}, "host_count": {"value": 30},
            "first": {"value": at(0)}, "last": {"value": at(480)},
            "hosts": {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 5,
                      "buckets": buckets}}  # fmt: skip
    params = beacon.ContactParams(destination="203.0.113.9", start=T, end=T + timedelta(hours=9))
    signals = {s.name: s for s in beacon.read_contact(1, params, REF, {"aggregations": aggs})}
    last = signals["contact.last"]
    assert (last.status, last.value) == ("known", "2026-10-20T11:00:00Z")
    assert not beacon.every_host_listed(aggs)
    # the request asks for the newest request over every host
    body = beacon.ProxyContact().build(params).body
    assert body["aggs"]["last"] == {"max": {"field": "@timestamp"}}


# --------------------------------------------------------------- F4-R7: 16 KiB worst case


def test_dns_worst_answer_with_non_ascii_names_fits_the_snapshot() -> None:
    """dns.question.name.keyword indexes up to 256 UTF-16 units; a name of 256 BMP
    characters is 768 bytes of UTF-8 in the snapshot (canonical: ensure_ascii=False). The
    worst answer the request can get now fits; on 18e2e6c (15, 15, 5, 5 buckets) it was
    dropped as too large."""
    name = "一" * 256  # 256 UTF-16 units, under ignore_above
    count = 99_999_999

    def terms(size: int) -> dict[str, Any]:
        return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": count,
                "buckets": [{"key": name, "doc_count": count} for _ in range(size)]}  # fmt: skip

    params = dns.DomainsParams(ip="10.9.8.7", start=T, end=T + timedelta(hours=2))
    asked = dns.DnsHostDomains().build(params).body["aggs"]
    aggs: dict[str, Any] = {"queries": {"value": count}, "named": {"value": count},
                            "names": {"value": count}}  # fmt: skip
    for key in ("top", "rare", "types", "codes"):
        aggs[key] = terms(asked[key]["terms"]["size"])
    body = {"took": 5, "timed_out": False, "_shards": {"total": 1, "successful": 1, "failed": 0},
            "hits": {"hits": []}, "aggregations": aggs}  # fmt: skip
    got = extract(body, max_rows=SNAPSHOT_ROWS, max_bytes=SNAPSHOT_BYTES)
    assert "dropped" not in got.snapshot, len(canonical(body["aggregations"]).encode())
    assert len(canonical(got.snapshot).encode()) <= SNAPSHOT_BYTES


# --------------------------------------------------------------- F4-R8: PTR / DNSBL lookups


@pytest.mark.parametrize("suffix", ["in-addr.arpa", "zen.spamhaus.org"])
def test_reverse_and_blocklist_lookups_are_not_a_tunnel(suffix: str) -> None:
    """A campus mail or web server resolving its clients' addresses (PTR) or checking them on
    a DNS blocklist asks thousands of distinct names under one parent. On 18e2e6c that read
    as dns.tunnel_suspected = True."""
    rare = [{"key": f"{i % 250}.{i // 250}.113.203.{suffix}", "doc_count": 1}
            for i in range(15)]  # fmt: skip
    aggs = {"queries": {"value": 4000}, "named": {"value": 4000}, "names": {"value": 3500},
            "top": {"buckets": []}, "rare": {"buckets": rare}}  # fmt: skip
    got = dns.lookups(aggs)
    assert got.tunnel_parent is None, got.tunnel_parent


# --------------------------------------------------------------- F4-R9: one file, two spellings


def _web(sizes: dict[str, tuple[int, int | None]]) -> dict[str, Any]:
    """{path: (status, 2xx size or None)} as the answer gives it (paths sorted)."""
    tried = sorted(sizes)
    aggs: dict[str, Any] = {
        "requests": {"value": len(tried)}, "answered": {"value": len(tried)},
        "paths": {"buckets": [{"key": p, "doc_count": 1, "statuses": {"buckets": [
            {"key": sizes[p][0], "doc_count": 1}]}} for p in tried]},
    }  # fmt: skip
    for i, p in enumerate(tried):
        size = sizes[p][1]
        aggs[f"ok_{i}"] = {"doc_count": int(size is not None), "sizes": {
            "sum_other_doc_count": 0,
            "buckets": [] if size is None else [{"key": size, "doc_count": 1}]}}  # fmt: skip
    return aggs


def test_one_real_file_under_two_spellings_is_not_read_as_a_catch_all() -> None:
    """An attacker asks for /.env and //.env (nginx merges slashes: the same real file, 2xx,
    the same size). On 18e2e6c both read as the site's catch-all page."""
    tried = ("//.env", "/.env")
    found = paths.outcomes(_web({"//.env": (200, 1187), "/.env": (200, 1187)}), tried)
    assert [o.outcome for o in found] == ["possible", "possible"]  # nothing else to compare
    # with another file answered differently, the one file's 2xx is a success
    spec = {"//.env": (200, 1187), "/%2eenv": (200, 1187), "/.env": (200, 1187),
            "/.git/config": (404, None)}  # fmt: skip
    found = paths.outcomes(_web(spec), sorted(spec))
    assert {o.path: o.outcome for o in found} == {
        "//.env": "success", "/%2eenv": "success", "/.env": "success",
        "/.git/config": "refused"}  # fmt: skip
    # two files of one size are still most likely the catch-all
    found = paths.outcomes(_web({"/.env": (200, 1187), "/a/../.git/config": (200, 1187)}),
                           ("/.env", "/a/../.git/config"))  # fmt: skip
    assert [o.outcome for o in found] == ["catch_all", "catch_all"]
    # a 2xx with no other file answered at all cannot be compared
    found = paths.outcomes(_web({"/.env": (200, 1187)}), ("/.env", "/.git/config"))
    assert [o.outcome for o in found] == ["possible", "unknown"]


@pytest.mark.parametrize(("path", "served"), [
    ("//.env", "/.env"), ("/%2eenv", "/.env"), ("/a/../.env", "/.env"), ("/./.env", "/.env"),
    ("/../../.env", "/.env"), ("/a//b/", "/a/b/"), ("/", "/"), ("/%zz", "/%zz"),
    ("/A/.Env", "/A/.Env"),
])  # fmt: skip
def test_the_file_a_path_is_served_as(path: str, served: str) -> None:
    assert paths.same_file(path) == served


def test_the_catch_all_reading_never_says_no_success() -> None:
    """The builder's fix: a catch-all is 'not shown to succeed', never 'no success'. The
    signal's display text (config/signals.yaml) still said it on 18e2e6c."""
    from argus.context.display import registry

    how = registry()["web.paths_catch_all"].how_to_read
    assert "no success" not in how, how
    assert "not shown to succeed" in how


# --------------------------------------------------------------- F4-R2: watched NAT host


def test_a_watched_host_is_gated_like_any_campus_host() -> None:
    """proxy.contact with watched hosts had no prevalence key at all: a NAT (a shared
    address) named as the watched host was never checked; nor was web's client."""
    params = beacon.ContactParams(destination="203.0.113.50", hosts=("10.0.0.66",), start=T,
                                  end=T + timedelta(hours=9))  # fmt: skip
    keys = batch1.keys("proxy.contact", params)
    assert batch1.Key("host", "10.0.0.66") in keys, keys
    web = paths.PathParams(ip="10.0.0.66", site="s.example.org", paths=("/login",), start=T,
                           end=T + timedelta(hours=6))  # fmt: skip
    assert batch1.Key("host", "10.0.0.66") in batch1.keys("web.path_outcomes", web)


# --------------------------------------------------------------- F4-R6: first runs


class Conn:
    def __init__(self, raws: list[dict[str, Any]]) -> None:
        self.raws = raws

    async def execute(self, *_: Any, **__: Any) -> Any:
        class R:
            def __init__(self, raw: dict[str, Any]) -> None:
                self.raw, self.normalized = raw, None

        return [R(raw) for raw in self.raws]


IDX = {"kibana.alert.rule.indices": ["acme-logs-squid-*"]}
EMPTY = {"aggregations": {"requests": {"value": 0}, "beats": {"buckets": []},
                          "first": {"value": None}, "last": {"value": None},
                          "bytes": {"value": 0.0}}}  # fmt: skip


async def test_a_first_run_that_read_nothing_does_not_pass() -> None:
    """A first run measures the template's cost on production. An answer that matched no
    document passed on 18e2e6c, and its pair was taken from two different alerts."""
    # newest alert: a campus host to a campus address; older: an outside host to a public
    # destination. The pair (10.8.0.5, 45.9.9.9) never appears in one alert.
    split = Conn(
        [
            {**IDX, "source": {"ip": "10.8.0.5"}, "destination": {"ip": "10.9.9.9"}},
            {**IDX, "source": {"ip": "8.8.4.4"}, "destination": {"ip": "45.9.9.9"}},
        ]
    )
    who = await batch1.subjects(split)  # type: ignore[arg-type]
    assert (who["host"], who["destination"], who["pair"]) == ("10.8.0.5", "45.9.9.9", None)
    sent: list[Any] = []

    async def run(template: Any, params: Any) -> Result:
        sent.append(params)
        return Result(EMPTY, 2, ("acme-logs-squid-2026.10.20",))

    now = datetime(2026, 10, 20, 16, 20, tzinfo=UTC)
    lines = await batch1.first_run(split, run, "proxy.pair", now)  # type: ignore[arg-type]
    assert lines[-1] == "FIRST RUN FAILED"  # no single alert names both: no subject
    assert sent == []
    one = Conn([{**IDX, "source": {"ip": "10.8.0.5"}, "destination": {"ip": "45.9.9.9"}}])
    lines = await batch1.first_run(one, run, "proxy.pair", now)  # type: ignore[arg-type]
    assert lines[-2:] == [
        "nothing matched, so this measured nothing; it stays off. Run it again when the subject"
        " is active.", "FIRST RUN INCONCLUSIVE"]  # fmt: skip
    assert (sent[0].host, sent[0].destination) == ("10.8.0.5", "45.9.9.9")


def test_what_counts_as_matched() -> None:
    assert not batch1.matched(EMPTY)
    assert batch1.matched({"aggregations": {"requests": {"value": 2}}})
    assert batch1.matched({"aggregations": {"queries": {"value": 1}}})
    assert not batch1.matched({"aggregations": {"requests": {"value": True}}})
    assert not batch1.matched({"aggregations": {}})
    assert batch1.matched({"hits": {"hits": [{"_id": "a"}]}})
    assert not batch1.matched({"hits": {"hits": []}})
    assert not batch1.matched(None)


# --------------------------------------------------------------- F4-R4: first-run window size


@pytest.mark.parametrize("now", [datetime(2026, 10, 20, 23, 30, tzinfo=UTC),
                                 datetime(2026, 10, 20, 2, 0, tzinfo=UTC),
                                 datetime(2026, 10, 20, 13, 7, tzinfo=UTC)])  # fmt: skip
@pytest.mark.parametrize("name", ["proxy.pair", "proxy.contact", "dns.host_domains",
                                  "web.path_outcomes"])  # fmt: skip
def test_the_first_run_reads_as_much_as_a_production_request(name: str, now: datetime) -> None:
    """The first run is the only cost measurement before switch-on, so it reads the largest
    window the template's builders make in production. On 18e2e6c it read 29 to 60 minutes
    while production reads up to 12 h (pair), 22 h (contact) or 6 h (web)."""
    web = ("45.1.2.3", "s.example.org", ["/.env", "/.git/config"])
    who = {"host": "10.8.0.5", "destination": "45.9.9.9", "pair": ("10.8.0.5", "45.9.9.9"),
           "web": web, "alert": None}  # fmt: skip
    first = batch1.first_task(name, who, now)
    assert isinstance(first, TaskSpec)
    day = datetime(2026, 10, 19, tzinfo=UTC)  # a whole earlier day: the largest production asks
    if name == "proxy.pair":
        prod = batch1.pair_task(
            {"first_event_at": (day + timedelta(hours=1)).isoformat(),
             "last_event_at": (day + timedelta(hours=22)).isoformat()},
            {"source.ip": {"top": [["10.8.0.5", 3]]}, "destination.ip": {"top": [["45.9.9.9", 3]]}},
            {"10.8.0.5": {"class": "internal"}, "45.9.9.9": {"class": "public"}}, now)  # fmt: skip
    elif name == "proxy.contact":
        prod = batch1.contact_task("45.9.9.9", now, day=day)
    elif name == "dns.host_domains":
        prod = batch1.dns_task("10.8.0.5", day + timedelta(hours=12), now)
    else:
        prod = batch1.paths_task("45.1.2.3", "s.example.org", ["/.env", "/.git/config"],
                                 day + timedelta(hours=10), now).task  # fmt: skip
    assert isinstance(prod, TaskSpec)
    length = lambda t: t.params.end - t.params.start  # noqa: E731
    assert length(first) >= length(prod), (name, length(first), length(prod))


# --------------------------------------------------------------- F4-R11: 21 rows stored as complete


def test_the_twenty_first_row_is_not_stored_as_a_complete_answer() -> None:
    """logs.source_events asks 21 rows to know there were more than 20. On 18e2e6c the
    evidence record built from the answer (graph.py: extract) said 21 rows, exact, not
    truncated. The template's answer now keeps 20 and makes the total a lower bound."""
    params = source_events.SourceParams(source="squid", ip="10.0.0.1", start=T,
                                        end=T + timedelta(hours=1))  # fmt: skip
    hits = [{"_index": "i", "_id": str(n), "_source": {}} for n in range(21)]
    body = {"took": 3, "timed_out": False, "hits": {"hits": hits},
            "_shards": {"total": 1, "successful": 1, "failed": 0}}  # fmt: skip
    answer = source_events.LogsSourceEvents().answer(params, body)
    got = extract(answer, max_rows=SNAPSHOT_ROWS, max_bytes=SNAPSHOT_BYTES)
    assert not (got.exact_total and not got.truncated and got.snapshot["rows_complete"]), got
    assert (got.row_count, got.exact_total, len(got.snapshot["rows"])) == (21, False, 20)
    ref = {**REF, "coverage": {"total": "lower_bound"}}  # what the graph stores for it
    signal = source_events.read(1, params, ref, got.snapshot)[0]
    assert (signal.value, signal.completeness) == (21, "lower_bound")
    # 20 or fewer: the answer as it came
    twenty = {**body, "hits": {"hits": hits[:20]}}
    assert source_events.LogsSourceEvents().answer(params, twenty) is twenty
    assert source_events.LogsSourceEvents().answer(params, {"took": 1}) == {"took": 1}


# --------------------------------------------------------------- F4-R12: lower bounds as exact


def test_a_lower_bound_of_names_is_not_stated_as_exact() -> None:
    """5,000 of 9,000 lookups have names too long to index: dns.names is a lower bound, but
    on 18e2e6c the note's sentence stated it as an exact number."""
    p = dns.DomainsParams(ip="10.9.8.7", start=T, end=T + timedelta(hours=2))
    rare = [{"key": f"x{i}.tunnel-example.net", "doc_count": 1} for i in range(15)]
    aggs = {"queries": {"value": 9000}, "named": {"value": 4000}, "names": {"value": 4000},
            "top": {"buckets": []}, "rare": {"buckets": rare}}  # fmt: skip
    sig = [s.as_dict() for s in dns.read(1, p, REF, {"aggregations": aggs})]
    assert {s["name"]: s["completeness"] for s in sig}["dns.names"] == "lower_bound"
    assert {s["name"]: s["completeness"] for s in sig}["dns.lookups"] == "exact"
    sentence = batch1.answers(sig)["log_pivot"]
    assert "of 4000 distinct names" not in sentence or "at least" in sentence, sentence
    assert sentence == "DNS logs: the client made 9000 lookups of at least 4000 distinct names."
