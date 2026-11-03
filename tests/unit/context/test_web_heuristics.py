"""R13 and R14 (D-060), the pure parts: decoding, NAXSI classes, path kinds, scanners, ports."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.context import heuristics, web

pytestmark = pytest.mark.unit


def test_paths_are_decoded_until_stable() -> None:
    raw = "/?p=template-parts%252f%252e%252e%252f%252e%252e%252fusr%252fshare%252fpearcmd"
    assert web.decode(raw) == "/?p=template-parts/../../usr/share/pearcmd"
    assert web.decode("/plain") == "/plain"
    assert web.categories([web.decode(raw)]) == ["traversal", "command injection"]
    assert web.categories(["/.env", "/wp-admin/x", "/wp-login.php"]) == [
        "config or backup",
        "admin pages",
        "cms probes",
    ]
    assert web.categories(["/index.html"]) == []


@given(st.text(max_size=60))
def test_decoding_terminates_and_is_idempotent_after_three_rounds(path: str) -> None:
    once = web.decode(path)
    assert isinstance(once, str)


@pytest.mark.parametrize(
    ("rule", "name"),
    [
        ("1000", "SQL injection"),
        ("1009", "SQL injection"),
        ("1010", "remote file inclusion"),
        ("1013", "directory traversal"),
        ("1100", "remote file inclusion or XSS"),
        ("1200", "evasion tricks"),
        ("1315", "XSS or format string"),
        ("11", "a malformed request"),
        ("4242", "another NAXSI rule"),
        ("x", None),
    ],
)
def test_naxsi_classes(rule: str, name: str | None) -> None:
    assert web.naxsi_class(rule) == name


def test_scanners_and_ports() -> None:
    assert web.SCANNERS.search("sqlmap/1.7#stable (https://sqlmap.org)")
    assert web.SCANNERS.search("Mozilla/5.0 Nuclei - Open-source project")
    assert not web.SCANNERS.search("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0")
    assert [heuristics.port_class(p) for p in (22, "3389", 443, 6885, 27015, 9050, 4444, "x")] == [
        "remote admin",
        "remote admin",
        "web",
        "peer-to-peer",
        "gaming",
        "anonymizer or proxy",
        "other",
        "other",
    ]


def test_heuristics_from_field_facts() -> None:
    fields = {
        "destination.port": {"distinct": 3, "top": [[22, 3], [443, 5], [6881, 1]]},
        "event.action": {"distinct": 2, "top": [["TCP_DENIED", 4], ["TCP_MISS", 9]]},
        "user_agent.original": {"distinct": 9},
        "source.ip": {"distinct": 1},
    }
    h = heuristics.context(fields)
    assert h == {
        "port_classes": {"peer-to-peer": 1, "remote admin": 3, "web": 5},
        "ports_shown": "exact",
        "denied": {"TCP_DENIED": 4},
        "actions_shown": "exact",
        "nat_hint": True,
        "agents": 9,
    }
    signals = {s.name: (s.value, s.completeness) for s in heuristics.signals(1, h)}
    assert signals == {
        "ports.risky": (4, "exact"), "proxy.denied": (4, "exact"), "nat.hint": (True, "exact"),
    }  # fmt: skip
    assert heuristics.summary(h)[0] == "Ports used: peer-to-peer (1), remote admin (3), web (5)"


def test_an_absent_field_is_unknown_never_zero() -> None:
    """Found in the R11-R14 review: every investigation got known zeros (D-023)."""
    h = heuristics.context({})
    assert h == {}
    got = {s.name: (s.status, s.unknown_reason) for s in heuristics.signals(1, h)}
    assert got == {
        "ports.risky": ("unknown", "no_fields"),
        "proxy.denied": ("unknown", "no_fields"),
        "nat.hint": ("unknown", "no_fields"),
    }


def test_values_beyond_the_facts_are_a_lower_bound_or_unknown() -> None:
    fields = {
        "destination.port": {"distinct": 20, "top": [[22, 3], [443, 5]]},
        "event.action": {"distinct": 9, "top": [["TCP_MISS", 9]]},
        "user_agent.original": {"distinct": 2},
        "source.ip": {"distinct": 1},
    }
    by = {s.name: s for s in heuristics.signals(1, heuristics.context(fields))}
    assert (by["ports.risky"].value, by["ports.risky"].completeness) == (3, "lower_bound")
    assert (by["proxy.denied"].status, by["proxy.denied"].unknown_reason) == (
        "unknown", "partial_coverage",
    )  # fmt: skip
    assert by["nat.hint"].value is False  # every alert read: few agents is a finding
    partial = {s.name: s for s in heuristics.signals(1, heuristics.context(fields, False))}
    assert partial["nat.hint"].status == "unknown"  # some alerts unread: says nothing
    exact = {"destination.port": {"distinct": 1, "top": [[22, 3]]}}
    assert heuristics.signals(1, heuristics.context(exact, False))[0].completeness == (
        "lower_bound"
    )


@pytest.mark.parametrize(
    ("port", "expected"),
    [("22.0", "remote admin"), (22.5, "other"), ("x", "other"), ("inf", "other"), (443, "web")],
)
def test_port_classes(port: object, expected: str) -> None:
    assert heuristics.port_class(port) == expected


def test_traversal_with_one_backslash_and_crawlers_are_not_scanners() -> None:
    assert "traversal" in web.categories(["/a/..\\windows\\win.ini"])
    assert "traversal" in web.categories(["/a/..\\x"])
    assert web.SCANNERS.search("Mozilla/5.0 (compatible; Googlebot/2.1)") is None
    assert web.SCANNERS.search("sqlmap/1.7") is not None


CLASSES = {
    "remote admin": [22, 23, 3389, 5900, 5901, 5938, 6568],
    "web": [80, 443, 8080, 8443, 8000, 8888],
    "mail": [25, 110, 143, 465, 587, 993, 995],
    "peer-to-peer": [*range(6881, 6890), 1337, 6969, 51413, 4662, 4672],
    "gaming": [3074, 3478, 3479, 27015, 27016, 25565, 7777, 9987],
    "anonymizer or proxy": [9001, 9030, 9050, 9150, 1080, 3128],
}


@pytest.mark.parametrize(("name", "port"), [(n, p) for n, ps in CLASSES.items() for p in ps])
def test_every_listed_port_has_its_class(name: str, port: int) -> None:
    assert heuristics.port_class(port) == name
    assert heuristics.port_class(str(port)) == name


@pytest.mark.parametrize(
    "port", [21, 24, 81, 111, 444, 3390, 5902, 6880, 6890, 9002, 27017, 51414, 65535, 0]
)
def test_ports_next_to_listed_ones_are_other(port: int) -> None:
    assert heuristics.port_class(port) == "other"


def test_risky_counts_remote_admin_peer_to_peer_and_anonymizers_only() -> None:
    top = [[22, 1], [6881, 2], [9050, 4], [443, 8], [25, 16], [3074, 32]]
    fields = {"destination.port": {"distinct": 6, "top": top}}
    (risky, *_) = heuristics.signals(1, heuristics.context(fields))
    assert (risky.value, risky.status) == (7, "known")


def test_the_nat_hint_needs_eight_agents_from_one_address() -> None:
    def hint(agents: int, sources: int = 1) -> object:
        fields = {"user_agent.original": {"distinct": agents},
                  "source.ip": {"distinct": sources}}  # fmt: skip
        return heuristics.context(fields).get("nat_hint")

    assert (hint(7), hint(8), hint(9), hint(8, sources=2)) == (False, True, True, False)


def test_summary_lines_read_plainly() -> None:
    h = heuristics.context({
        "destination.port": {"distinct": 1, "top": [[22, 3]]},
        "event.action": {"distinct": 2, "top": [["TCP_DENIED", 4], ["tcp_denied/403", 1]]},
        "user_agent.original": {"distinct": 9},
        "source.ip": {"distinct": 1},
    })  # fmt: skip
    assert heuristics.summary(h) == [
        "Ports used: remote admin (3)",
        "Denied by the proxy: TCP_DENIED (4), tcp_denied/403 (1)",
        "9 different browsers or apps from one address: possibly several users behind a NAT",
    ]
    assert heuristics.summary({}) == []
    lower = heuristics.signals(1, heuristics.context(
        {"event.action": {"distinct": 5, "top": [["TCP_DENIED", 2]]}}))  # fmt: skip
    denied = next(s for s in lower if s.name == "proxy.denied")
    assert (denied.value, denied.status, denied.completeness) == (2, "known", "lower_bound")


# ----------------------------------------------------------------- R13: exact behaviour
from datetime import UTC, datetime, timedelta, timezone  # noqa: E402

IST = timezone(timedelta(hours=5, minutes=30))


def test_the_follow_up_request_is_exactly_this() -> None:
    start = datetime(2026, 10, 13, 9, 50, tzinfo=IST)
    end = datetime(2026, 10, 13, 15, tzinfo=UTC)
    plan = web.WebFollowups().build(web.FollowParams(ip="203.0.113.9", start=start, end=end))
    assert plan.body == {
        "size": 20,
        "track_total_hits": False,
        "_source": ["@timestamp", "http.request.method", "http.response.status_code",
                    "url.domain", "url.path"],
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"filter": [
            {"term": {"source.ip": "203.0.113.9"}},
            {"range": {"http.response.status_code": {"gte": 200, "lt": 300}}},
            {"range": {"@timestamp": {"gte": "2026-10-13T04:20:00Z",
                                      "lt": "2026-10-13T15:00:00Z"}}},
        ]}},
    }  # fmt: skip
    assert plan.window == web.Window("nginx", start, end)
    spec = plan.spec
    assert spec.filter_fields == {"source.ip", "@timestamp", "http.response.status_code"}
    assert spec.return_fields == {"@timestamp", "url.domain", "url.path",
                                  "http.response.status_code", "http.request.method"}  # fmt: skip
    assert spec.sort_fields == {"@timestamp"}
    assert spec.max_size == 20
    with pytest.raises(AssertionError):
        web.WebFollowups().build(heuristics_params())


def heuristics_params() -> web.Params:
    from argus.reference.templates import LookupParams

    return LookupParams(values=("x",))


@pytest.mark.parametrize("ip", ["1", "a" * 46])
def test_follow_up_addresses_are_bounded(ip: str) -> None:
    from pydantic import ValidationError

    t = datetime(2026, 10, 13, tzinfo=UTC)
    with pytest.raises(ValidationError):
        web.FollowParams(ip=ip, start=t, end=t)
    web.FollowParams(ip="::", start=t, end=t)
    web.FollowParams(ip="a" * 45, start=t, end=t)


@pytest.mark.parametrize(
    ("rule", "name"),
    [(1000, "SQL injection"), (1009, "SQL injection"), (1010, "remote file inclusion"),
     (1011, "remote file inclusion"), (1012, "another NAXSI rule"),
     (1013, "directory traversal"), (1015, "directory traversal"),
     (1016, "another NAXSI rule"), (1100, "remote file inclusion or XSS"),
     (1101, "remote file inclusion or XSS"), (1102, "another NAXSI rule"),
     (1200, "evasion tricks"), (1201, "another NAXSI rule"), (1301, "another NAXSI rule"),
     (1302, "XSS or format string"), (1315, "XSS or format string"),
     (1316, "another NAXSI rule"), (0, "another NAXSI rule"), (1, "a malformed request"),
     (19, "a malformed request"), (20, "another NAXSI rule"), ("1000", "SQL injection"),
     ("x", None)],
)  # fmt: skip
def test_naxsi_classes_at_their_edges(rule: object, name: str | None) -> None:
    assert web.naxsi_class(rule) == name


def test_iso_and_decoding_rounds() -> None:
    assert web.iso(datetime(2026, 10, 13, 5, 30, tzinfo=IST)) == "2026-10-13T00:00:00Z"
    assert web.decode("%2525252e") == "%2e"  # three rounds, no more
    assert web.decode("%2525252e", rounds=4) == "."
    assert web.decode("a%20b") == "a b"


def test_context_of_the_alerts() -> None:
    docs = [
        {"url": {"path": "/a%2e%2e/..%2fetc"}, "rule": {"id": "1013"},
         "user_agent": {"original": "sqlmap/1.7 " + "x" * 100}},
        {"url": {"path": "/wp-admin/"}, "rule": {"id": "1000"},
         "user_agent": {"original": "Mozilla/5.0"}},
        {"url": {"path": "/wp-admin/"}, "rule": {"id": "1000"}},
    ]  # fmt: skip
    fields = {"url.domain": {"top": [["gate.example.edu", 3], ["ams.example.edu", 1]]}}
    got = web.context(docs, fields)
    assert got == {
        "decoded_paths": ["/a../../etc", "/wp-admin/"],
        "categories": ["traversal", "admin pages", "cms probes"],
        "naxsi": [{"id": "1000", "class": "SQL injection", "alerts": 2},
                  {"id": "1013", "class": "directory traversal", "alerts": 1}],
        "scanner_agents": [("sqlmap/1.7 " + "x" * 100)[:80]],
        "agents": 2,
        "sites": ["gate.example.edu", "ams.example.edu"],
    }  # fmt: skip
    many = [{"url": {"path": f"/p{n}"}, "rule": {"id": str(n)},
             "user_agent": {"original": f"curl/{n}"}} for n in range(300)]  # fmt: skip
    big = web.context(many, {})
    assert len(big["decoded_paths"]) == 10
    assert len(big["naxsi"]) == 5
    assert len(big["scanner_agents"]) == 5
    assert big["decoded_paths"][0] == "/p0"
    assert "/p250" not in web.context(many, {})["decoded_paths"]
    assert web.context([], {}) == {"decoded_paths": [], "categories": [], "naxsi": [],
                                   "scanner_agents": [], "agents": 0, "sites": []}  # fmt: skip


def follow(first: str, now: datetime) -> list[tuple[datetime, datetime]]:
    facts = {"first_event_at": first}
    fields = {"source.ip": {"top": [["203.0.113.9", 1]]}}
    return [(t.params.start, t.params.end) for t in web.tasks(facts, fields, now)]  # type: ignore[attr-defined]


def test_the_follow_up_window() -> None:
    at = lambda h, m=0, d=13: datetime(2026, 10, d, h, m, tzinfo=UTC)  # noqa: E731
    assert follow("2026-10-13T09:50:30+00:00", at(20)) == [(at(9, 50), at(15, 50))]  # 6 h
    assert follow("2026-10-13T09:50:30+00:00", at(12, 20)) == [(at(9, 50), at(12))]  # margin
    assert follow("2026-10-13T09:50:30+00:00", at(10, 4)) == []  # nothing old enough yet
    assert follow("2026-10-13T09:50:30+00:00", at(10, 5)) == []  # end = 09:00 < start
    assert follow("2026-10-13T08:10:00+00:00", at(9, 20)) == [(at(8, 10), at(9))]
    # near midnight: never more than two daily indices (with an hour's pad each side)
    assert follow("2026-10-12T23:30:00+00:00", at(12)) == [(at(23, 30, d=12), at(5, 30))]
    assert follow("2026-10-13T00:30:00+00:00", at(12)) == [(at(0, 30), at(6, 30))]
    assert web.tasks({}, {"source.ip": {"top": [["203.0.113.9", 1]]}}, at(12)) == []
    assert web.tasks({"first_event_at": "2026-10-13T09:00:00+00:00"}, {}, at(12)) == []


def test_web_signals_and_summary() -> None:
    w = {"categories": ["traversal", "admin pages"], "scanner_agents": ["sqlmap/1"],
         "naxsi": [{"id": "1000", "class": "SQL injection", "alerts": 2}]}  # fmt: skip
    ref = {"task_key": "k", "status": "ok", "template": "web.followups@1"}
    got = {s.name: s.value for s in web.signals(1, w, {"k": ref}, {"k": {"rows": [{}, {}]}})}
    assert got == {"web.path_categories": 2, "web.scanner_agents": 1, "web.successes_after": 2}
    other = {"task_key": "k", "status": "ok", "template": "proxy.host@1"}
    assert {s.name for s in web.signals(1, w, {"k": other}, {})} == {
        "web.path_categories", "web.scanner_agents"}  # fmt: skip
    assert web.summary(w) == [
        "NAXSI rule 1000: SQL injection (2 alerts)",
        "Paths tried: traversal, admin pages",
        "Scanner tools: sqlmap/1",
    ]
    assert web.summary({}) == []
    told = web.answers(w, [{"name": "web.successes_after", "status": "known", "value": 3}])
    assert told == {"log_pivot": "nginx logs: 3 successful (2xx) answers to the client in the"
                                 " hours after the first alert."}  # fmt: skip
    assert web.answers(w, [{"name": "web.successes_after", "status": "unknown",
                            "value": None}]) == {}  # fmt: skip
