"""AR3 (D-165): what an outside answer is and how ARGUS says it. The sentences are the ones the
run's checks, the model's item and the investigation page show, so each is written out; a
detection is VirusTotal's engines only (Shodan and Censys describe a server, they never flag
one); text a source supplies is cleaned and quoted, never trusted.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from argus.outside import facts

VT_BAD = {"malicious": 7, "suspicious": 1, "harmless": 60, "undetected": 26}  # 94 engines
VT_CLEAN = {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 24, "engines": 94}
SHODAN = {
    "ports": [22, 80, 443], "products": ["nginx 1.18.0"], "hostnames": ["srv1.hosting.net"],
    "org": "Acme Hosting", "country": "DE", "vulns": ["CVE-2021-23017", "CVE-2022-41741"],
}  # fmt: skip


def entry(source: str, kind: str, answer: dict[str, Any], status: str = "found") -> dict[str, Any]:
    return facts.fact(source, kind, "203.0.113.9", status, answer, 3)


# -- the sentences ------------------------------------------------------------------------------


def test_the_virustotal_sentence_is_the_one_the_checks_show() -> None:
    bad = entry("virustotal", "ip", {**VT_BAD, "engines": 94, "suspicious": 0})
    assert facts.describe(bad) == "VirusTotal: 7 of 94 engines flag this IP"
    with_odd = entry("virustotal", "domain", {**VT_BAD, "engines": 94})
    assert facts.describe(with_odd) == (
        "VirusTotal: 7 of 94 engines flag this domain, 1 more call it suspicious"
    )
    assert facts.describe(entry("virustotal", "ip", VT_CLEAN)) == (
        "VirusTotal: no engine of 94 flags this IP"
    )
    only_odd = {**VT_CLEAN, "suspicious": 2}
    assert facts.describe(entry("virustotal", "ip", only_odd)) == (
        "VirusTotal: no engine of 94 calls this IP malicious, 2 call it suspicious"
    )
    assert facts.describe(entry("virustotal", "hash", {"engines": 0})) == (
        "VirusTotal: has a record of this file but no engine has scored it"
    )
    assert facts.describe(entry("virustotal", "url", {}, "not_found")) == (
        "VirusTotal: has no record of this URL"
    )


def test_a_server_is_described_by_its_ports_software_names_and_owner() -> None:
    said = facts.describe(entry("shodan", "ip", SHODAN), quote=lambda t: f"<{t}>")
    assert said == (
        "Shodan: open ports 22, 80, 443; software <nginx 1.18.0>; names <srv1.hosting.net>;"
        " run by <Acme Hosting>; in DE; 2 known CVEs"
    )
    assert facts.describe(entry("censys", "ip", {"ports": [8080]})) == "Censys: open ports 8080"
    assert facts.describe(entry("shodan", "ip", {})) == (
        "Shodan: has a record of this IP but no detail"
    )
    assert facts.describe(entry("censys", "ip", {}, "not_found")) == (
        "Censys: has no record of this IP"
    )
    many = facts.describe(entry("shodan", "ip", {"ports": list(range(1, 20))}))
    assert many.endswith("12 and 7 more")


@given(
    st.dictionaries(
        st.text(max_size=8), st.one_of(st.none(), st.integers(), st.text(), st.lists(st.integers()))
    )
)
def test_describing_any_answer_never_raises(answer: dict[str, Any]) -> None:
    for source in facts.SOURCES:
        for status in (facts.FOUND, facts.NOT_FOUND):
            assert isinstance(facts.describe(entry(source, "ip", answer, status)), str)
    assert isinstance(facts.describe({"source": 1, "answer": 5}), str)


# -- a detection --------------------------------------------------------------------------------


def test_only_virustotal_flags_and_only_from_the_threshold() -> None:
    assert not facts.flagged("virustotal", "found", {"malicious": 2}, 3)
    assert facts.flagged("virustotal", "found", {"malicious": 3}, 3)
    assert facts.flagged("virustotal", "found", {"malicious": 1}, 1)
    assert not facts.flagged("virustotal", "not_found", {"malicious": 90}, 3)
    assert not facts.flagged("shodan", "found", {"malicious": 90, "tags": ["malware"]}, 3)
    assert not facts.flagged("censys", "found", {"malicious": 90}, 3)
    assert facts.flagged("virustotal", "found", {"malicious": 1}, 0)  # never below one engine


@given(st.integers(0, 100), st.integers(1, 50))
def test_the_threshold_is_a_line(engines: int, threshold: int) -> None:
    got = facts.flagged("virustotal", "found", {"malicious": engines}, threshold)
    assert got is (engines >= threshold)


WEEK, DAY = timedelta(days=7), timedelta(days=1)


def test_a_detection_and_a_servers_description_are_kept_the_window_the_rest_a_day() -> None:
    def kept(
        source: str, status: str, answer: dict[str, Any], clean: timedelta | None = DAY
    ) -> Any:
        return facts.kept_for(source, status, answer, 3, WEEK, clean)

    assert kept("virustotal", "found", {"malicious": 3}) == WEEK  # a detection
    assert kept("virustotal", "found", {"malicious": 2}) == DAY  # too few engines: still fresh
    assert kept("virustotal", "found", VT_CLEAN) == DAY
    assert kept("virustotal", "found", {"engines": 0}) == DAY  # no engine has scored it
    assert kept("virustotal", "not_found", {}) == DAY
    assert kept("virustotal", "not_found", {"malicious": 90}) == DAY  # (never stored that way)
    assert kept("shodan", "found", SHODAN) == WEEK  # what a server is changes slowly
    assert kept("censys", "found", {"ports": [22]}) == WEEK
    assert kept("shodan", "not_found", {}) == DAY
    assert kept("censys", "not_found", {}) == DAY
    assert kept("virustotal", "not_found", {}, None) == WEEK  # no clean window: the one window
    assert kept("virustotal", "not_found", {}, timedelta(days=30)) == WEEK  # never longer


@given(st.integers(0, 60), st.integers(1, 50), st.sampled_from(facts.SOURCES),
       st.sampled_from([facts.FOUND, facts.NOT_FOUND]))  # fmt: skip
def test_a_clean_answer_is_never_kept_longer_than_a_detection(
    engines: int, threshold: int, source: str, status: str
) -> None:
    got = facts.kept_for(source, status, {"malicious": engines}, threshold, WEEK, DAY)
    assert got in (WEEK, DAY)
    if facts.flagged(source, status, {"malicious": engines}, threshold):
        assert got == WEEK


def test_a_detection_adds_one_flag_last_and_once() -> None:
    bad = [entry("virustotal", "ip", {**VT_BAD, "engines": 94})]
    assert facts.with_flag(("regular traffic, like a beacon",), bad) == (
        "regular traffic, like a beacon", facts.FLAG,
    )  # fmt: skip
    assert facts.with_flag((facts.FLAG,), bad) == (facts.FLAG,)
    clean = [entry("virustotal", "ip", VT_CLEAN), entry("shodan", "ip", SHODAN)]
    assert facts.with_flag(("x",), clean) == ("x",)
    assert facts.with_flag((), None) == ()
    assert facts.FLAG == "flagged by outside threat intel"


@given(
    st.one_of(
        st.none(),
        st.integers(),
        st.text(),
        st.lists(
            st.one_of(
                st.none(),
                st.text(),
                st.dictionaries(st.text(max_size=4), st.one_of(st.booleans(), st.integers())),
            )
        ),
    )
)
def test_anything_that_is_not_a_flagged_fact_is_no_detection(value: Any) -> None:
    if not isinstance(value, list) or not any(
        isinstance(f, dict) and f.get("flagged") is True for f in value
    ):
        assert not facts.any_flagged(value)


def test_the_items_facts_keep_only_well_formed_entries() -> None:
    good = entry("virustotal", "ip", VT_CLEAN)
    junk = [good, 5, "x", {"source": "bing", "kind": "ip", "value": "a", "status": "found"},
            {**good, "kind": "mac"}, {**good, "value": 3}, {**good, "status": "maybe"}]  # fmt: skip
    assert facts.facts_of(junk) == [good]
    assert facts.facts_of("x") == [] == facts.facts_of(None)


def test_a_newer_fact_replaces_an_older_one_for_the_same_indicator() -> None:
    old = entry("virustotal", "ip", VT_CLEAN)
    new = facts.fact("virustotal", "ip", "203.0.113.9", "found", {"malicious": 9}, 3)
    other = facts.fact("shodan", "ip", "203.0.113.9", "found", SHODAN, 3)
    merged = facts.merge([old, other], [new])
    assert [f["source"] for f in merged] == ["virustotal", "shodan"]
    assert merged[0]["flagged"] is True


# -- the indicators -----------------------------------------------------------------------------


def test_canonical_spellings() -> None:
    assert facts.canonical("ip", " 203.0.113.9 ") == "203.0.113.9"
    assert facts.canonical("ip", "::ffff:203.0.113.9") == "203.0.113.9"
    assert facts.canonical("ip", "2001:DB8:0:0:0:0:0:1") == "2001:db8::1"
    assert facts.canonical("ip", "203.0.113.999") is None
    assert facts.canonical("ip", "2606:4700:4700::1111%eth0") == "2606:4700:4700::1111"
    assert facts.canonical("ip", "fe80::1%2") == "fe80::1"  # a zone is where, not who
    assert facts.canonical("ip", "::ffff:203.0.113.9%eth0") == "203.0.113.9"
    for bad in ("1.2.3.4%eth0", "fe80::1%", "fe80::1%a/b", "fe80::1%a%b", "%eth0"):
        assert facts.canonical("ip", bad) is None, bad
    assert facts.canonical("domain", "Evil.Example.COM.") == "evil.example.com"
    assert facts.canonical("domain", "bücher.example.com") == "xn--bcher-kva.example.com"
    for bad in ("localhost", "a..b.com", "-a.com", "a b.com", "1.2.3.4", "x" * 64 + ".com", ""):
        assert facts.canonical("domain", bad) is None, bad
    assert facts.canonical("hash", "D41D8CD98F00B204E9800998ECF8427E") == (
        "d41d8cd98f00b204e9800998ecf8427e"
    )
    assert facts.canonical("hash", "abc") is None
    assert facts.canonical("url", "HTTP://x.com/a?b=1") == "http://x.com/a?b=1"
    for bad in ("ftp://x.com/", "http://u:p@x.com/", "http://x.com/ a", "x.com", "http://"):
        assert facts.canonical("url", bad) is None, bad
    assert facts.canonical("url", "http://x.com/" + "a" * 3000) is None
    assert facts.canonical("mac", "aa:bb:cc:dd:ee:ff") is None
    assert facts.canonical("ip", None) is None


@given(st.text(max_size=60))
def test_canonical_is_idempotent_and_never_raises(text: str) -> None:
    for kind in facts.KINDS:
        once = facts.canonical(kind, text)
        if once is not None:
            assert facts.canonical(kind, once) == once


def test_the_host_of_a_url() -> None:
    assert facts.host_of("http://Evil.com:8080/a/b?c") == "evil.com"
    assert facts.host_of("https://203.0.113.9/x") == "203.0.113.9"
    assert facts.host_of("http://[2001:db8::1]:81/x") == "2001:db8::1"


# -- what a source supplies ---------------------------------------------------------------------


def test_text_from_a_source_is_cleaned_and_cut() -> None:
    assert facts.clean("Acme\nHosting\x00 <script>", 80) == "Acme Hosting script"
    assert facts.clean("x" * 200, 10) == "x" * 10
    assert facts.clean("\x00\x01", 10) is None
    assert facts.clean(5) is None
    assert facts.names(["A.example.com", "a.example.com", "bad host", 5, "b.example.com"], 5) == [
        "a.example.com", "b.example.com",
    ]  # fmt: skip
    assert facts.cves(["CVE-2021-23017", "cve-2021-1", "CVE-2021-23017", "x"]) == ["CVE-2021-23017"]
    assert facts.tags(["Malware", "x" * 40, "c2", "c2", 5]) == ["malware", "c2"]
    assert facts.ports([443, 80, 443, -1, 70000, True, "22", 22.0]) == [22, 80, 443]
    assert facts.number(True) is None
    assert facts.number(2.5) is None
    assert facts.number(7.0) == 7
    assert facts.number(10**12) is None


@given(st.text(max_size=300))
def test_cleaned_text_has_no_control_or_markup_characters(text: str) -> None:
    got = facts.clean(text, 80)
    assert got is None or (
        len(got) <= 80 and all(c.isprintable() and c not in '<>&"`\\{}[]' for c in got)
    )
