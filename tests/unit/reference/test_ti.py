"""Threat intelligence in one shape (R9 gate: both schemas, staleness at 7 d ± 1 s, the
no-match answer)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.reference.ti import (
    STALE_AFTER,
    Freshness,
    Indicator,
    answer,
    canonical,
    from_ecs,
    from_ioc,
    kind_of,
)

pytestmark = pytest.mark.unit

NOW = datetime(2026, 10, 13, 12, tzinfo=UTC)
ABUSE = "abuse-ioc"  # ACME's mirrored ECS source (the source id is its index)
ACME = "acme-threat-intel"  # ACME's looked-up ioc source


def from_abuse(doc: dict[str, Any]) -> list[Indicator]:
    return from_ecs(ABUSE, doc)


def from_acme(doc: dict[str, Any]) -> list[Indicator]:
    return from_ioc(ACME, doc)


def abuse(indicator: dict[str, Any], **doc: Any) -> dict[str, Any]:
    return {"@timestamp": "2026-10-01T00:00:00Z", "threat": {"indicator": indicator}, **doc}


# ----------------------------------------------------------------------------- abuse-ioc


def test_abuse_ip_domain_url_hash_and_email() -> None:
    (ip,) = from_abuse(abuse({"type": "ipv4-addr", "ip": "::ffff:77.221.155.150",
                                "first_seen": "2026-10-07T23:39:00Z", "confidence": "High",
                                "description": "PS1Bot C2"}))  # fmt: skip
    assert ip == Indicator(ABUSE, "ip", "77.221.155.150", "ipv4-addr",
                           datetime(2026, 10, 7, 23, 39, tzinfo=UTC),
                           datetime(2026, 10, 1, tzinfo=UTC), "High", "PS1Bot C2")  # fmt: skip
    (domain,) = from_abuse(abuse({"type": "domain-name", "domain": "Evil.EXAMPLE."}))
    assert (domain.kind, domain.value) == ("domain", "evil.example")
    (url,) = from_abuse(abuse({"type": "url", "url": {"full": "http://x.example/a?b=1"}}))
    assert (url.kind, url.value) == ("url", "http://x.example/a?b=1")
    (sha,) = from_abuse(abuse({"type": "file", "file": {"hash": {"sha256": "AB" * 32}}}))
    assert (sha.kind, sha.value) == ("hash", "ab" * 32)
    (mail,) = from_abuse(abuse({"type": "email-addr", "email": {"address": "A@B.example"}}))
    assert (mail.kind, mail.value) == ("email", "a@b.example")


def test_abuse_flat_fields_lists_feed_names_and_rejects() -> None:
    indicator = {"type": "ipv4-addr", "ip": ["1.2.3.4", "bad-ip", "5.6.7.8"],
                 "last_seen": "2026-10-05T00:00:00Z"}  # fmt: skip
    flat = {"@timestamp": "2026-10-01T00:00:00Z", "threat.indicator": indicator,
            "threat.feed.name": "CERT-X"}  # fmt: skip
    got = from_abuse(flat)
    assert [i.value for i in got] == ["1.2.3.4", "5.6.7.8"]  # the invalid one dropped
    assert got[0].last_seen == datetime(2026, 10, 5, tzinfo=UTC)
    assert got[0].description == "CERT-X"
    assert from_abuse({"threat": {"indicator": "nope"}}) == []
    assert from_abuse({"no": "indicator"}) == []
    (other,) = from_abuse(abuse({"type": "x-mutex", "name": "Global\\evil"}))
    assert (other.kind, other.value, other.type_raw) == ("other", "global\\evil", "x-mutex")
    assert from_abuse(abuse({"type": "ipv4-addr", "ip": "300.1.1.1"})) == []
    no_zone = {"type": "ipv4-addr", "ip": "1.1.1.1", "first_seen": "2026-10-05T00:00:00"}
    naive = from_abuse(abuse(no_zone, **{"@timestamp": "x"}))
    assert (naive[0].first_seen, naive[0].last_seen) == (None, None)  # no zone, no time


# ----------------------------------------------------------------------------- acme


@pytest.mark.parametrize(
    ("ioc_type", "value", "kind", "canonical_value"),
    [
        ("ip", "10.8.0.1", "ip", "10.8.0.1"),
        ("IPv4", " 10.8.0.1 ", "ip", "10.8.0.1"),
        ("ip-dst", "::ffff:10.8.0.1", "ip", "10.8.0.1"),
        ("domain", "BAD.example.", "domain", "bad.example"),
        ("hostname", "c2.Bad.example", "domain", "c2.bad.example"),
        ("url", "http://x/", "url", "http://x/"),
        ("md5", "D41D8CD98F00B204E9800998ECF8427E", "hash", "d41d8cd98f00b204e9800998ecf8427e"),
        ("weird", "thing", "other", "thing"),
    ],
)
def test_acme_rows(ioc_type: str, value: str, kind: str, canonical_value: str) -> None:
    (ind,) = from_acme({"ioc_type": ioc_type, "ioc_value": value, "intel_source": "feodo",
                         "@timestamp": "2026-09-02T10:00:00Z"})  # fmt: skip
    assert (ind.source, ind.kind, ind.value, ind.description) == (ACME, kind, canonical_value,
                                                                   "feodo")  # fmt: skip
    assert ind.last_seen == datetime(2026, 9, 2, 10, tzinfo=UTC)


def test_acme_rejects_and_prefers_last_seen() -> None:
    assert from_acme({"ioc_type": "ip", "ioc_value": "not-an-ip"}) == []
    assert from_acme({"ioc_type": "ip"}) == []
    assert from_acme({"ioc_type": "url", "ioc_value": "x" * 3000}) == []
    (ind,) = from_acme({"ioc_type": "ip", "ioc_value": "1.1.1.1", "last_seen":
                         "2026-10-01T00:00:00Z", "@timestamp": "2026-09-01T00:00:00Z"})  # fmt: skip
    assert ind.last_seen == datetime(2026, 10, 1, tzinfo=UTC)
    assert ind.type_raw == "ip"
    assert ind.confidence is None


@given(st.text(max_size=40))
def test_canonical_is_idempotent(value: str) -> None:
    for kind in ("ip", "domain", "url", "hash", "email", "other"):
        once = canonical(kind, value)
        assert once is None or canonical(kind, once) == once


@pytest.mark.parametrize("value", ["@ 0", "http://a b/", "//\x85x", "@\x00a"])
def test_a_url_whose_host_has_blanks_or_controls_is_no_url(value: str) -> None:
    """Found by Hypothesis (2026-10-14): canonical('url', '@ 0') was ' 0', not idempotent."""
    assert canonical("url", value) is None


def test_kinds() -> None:
    assert kind_of(None) == kind_of("") == kind_of("x") == "other"
    assert kind_of(" IPv6-ADDR ") == "ip"
    assert canonical("ip", True) is None
    assert canonical("url", "  ") is None


# ----------------------------------------------------------------------------- freshness


def test_a_source_is_stale_one_second_after_seven_days() -> None:
    assert timedelta(days=7) == STALE_AFTER
    assert not Freshness(ACME, NOW - timedelta(days=7), NOW).stale(NOW)
    assert Freshness(ACME, NOW - timedelta(days=7, seconds=1), NOW).stale(NOW)
    assert Freshness(ACME, None, None).stale(NOW)  # never seen: stale
    assert not Freshness(ACME, NOW, NOW).stale(NOW)


def test_answers_match_or_no_match_with_freshness() -> None:
    sources = [Freshness(ABUSE, NOW - timedelta(days=1), NOW),
               Freshness(ACME, datetime(2026, 9, 2, tzinfo=UTC), NOW)]  # fmt: skip
    hit = Indicator(ABUSE, "ip", "77.221.155.150", "ipv4-addr", None, None, "High", "C2")
    got = answer("77.221.155.150", [hit], sources, NOW)
    assert got == {
        "value": "77.221.155.150",
        "sources": {
            ABUSE: {"match": [{"kind": "ip", "type": "ipv4-addr", "first_seen": None,
                                "last_seen": None, "confidence": "High", "description": "C2"}],
                     "freshness": {"source": ABUSE,
                                   "newest": (NOW - timedelta(days=1)).isoformat(),
                                   "checked_at": NOW.isoformat(), "stale": False}},
            ACME: {"no_match": {"source": ACME, "newest": "2026-09-02T00:00:00+00:00",
                                 "checked_at": NOW.isoformat(), "stale": True}},
        },
    }  # fmt: skip
    miss = answer("10.0.0.1", [hit], sources, NOW)
    assert set(miss["sources"][ABUSE]) == {"no_match"}
    assert miss["sources"][ABUSE]["no_match"]["stale"] is False


# ----------------------------------------------------------------- exact (mutation testing)
from argus.reference import ti as ti_module  # noqa: E402

TYPES = {
    "ip": ["ipv4-addr", "ipv6-addr", "ip", "ipv4", "ipv6", "ip-dst", "ip-src", "ip_address",
           "ipv4-address", "ipv6-address", "ip-address", "IPv4 Address", " IP_SRC "],
    "domain": ["domain-name", "domain", "hostname", "fqdn", "Domain Name"],
    "url": ["url", "uri", "url-address", "URL"],
    "hash": ["file", "md5", "sha1", "sha256", "hash", "file-hash", "sha-256", "sha-1", "SHA 256"],
    "email": ["email-addr", "email", "e-mail", "E_Mail"],
    "other": ["mutex", "ip-port", "", None, "domain|ip"],
}  # fmt: skip


@pytest.mark.parametrize(("kind", "spelling"), [(k, s) for k, ss in TYPES.items() for s in ss])
def test_every_type_spelling_has_its_kind(kind: str, spelling: Any) -> None:
    assert kind_of(spelling) == kind


def test_the_names_and_limits() -> None:
    assert (ABUSE, ACME) == ("abuse-ioc", "acme-threat-intel")
    assert ti_module.KINDS == ("ip", "domain", "url", "hash", "email", "other")
    assert ti_module.TEXT_CHARS == 512
    assert timedelta(days=7) == STALE_AFTER
    (long,) = from_acme({"ioc_type": "ip", "ioc_value": "1.2.3.4", "intel_source": "x" * 600,
                          "confidence": " high ", "ioc_type_extra": 1})  # fmt: skip
    assert long.description == "x" * 512
    assert long.confidence == "high"
    (blank,) = from_acme({"ioc_type": "ip", "ioc_value": "1.2.3.4", "intel_source": "  "})
    assert blank.description is None
    (typed,) = from_acme({"ioc_type": "ip" + " " * 70, "ioc_value": "1.2.3.4"})
    assert len(typed.type_raw) == 64


def test_abuse_reads_each_kinds_fields() -> None:
    (d,) = from_abuse(abuse({"type": "domain", "url": {"domain": "a.example"}}))
    assert (d.kind, d.value) == ("domain", "a.example")
    (u,) = from_abuse(abuse({"type": "url", "url": {"original": "http://b.example/X"}}))
    assert u.value == "http://b.example/X"
    hashes = from_abuse(abuse({"type": "file", "file": {"hash": {
        "sha1": "A" * 40, "md5": "B" * 32}}}))  # fmt: skip
    assert sorted(h.value for h in hashes) == ["a" * 40, "b" * 32]
    assert all(h.kind == "hash" for h in hashes)
    (m,) = from_abuse(abuse({"type": "email", "email": {"address": "x@y.example"}}))
    assert m.value == "x@y.example"
    assert from_abuse(abuse({"type": "ip", "name": "9.9.9.9"})) == []  # name: other kinds only
    misfiled = from_abuse(abuse({"type": "domain-name", "domain": "10.0.0.7"}))
    assert [(i.kind, i.value) for i in misfiled] == [("ip", "10.0.0.7")]
    url_ind = {"type": "url", "url": {"full": "http://c.example/"}}
    fed = from_abuse({"threat": {"indicator": url_ind, "feed": {"name": "Feed"}}})
    assert fed[0].description == "Feed"


def test_guessing_a_kind_by_its_shape() -> None:
    from argus.reference.ti import guess_kind

    assert guess_kind(" " + "a" * 64 + " ") == "hash"
    assert guess_kind("1.2.3.4") == "ip"
    assert guess_kind("a@b.example") == "email"
    assert guess_kind("http://x.example/a") == "url"
    assert guess_kind("x.example/a") == "url"
    assert guess_kind("x.example") == "domain"
    assert guess_kind("@") is None
    assert guess_kind("http://") is None
    assert guess_kind("no spaces allowed.example") is None
    assert guess_kind("a" * 63) is None


def test_canonical_values_exactly() -> None:
    assert canonical("domain", "a.123") is None  # a numeric last label is no domain
    assert canonical("domain", "A.Example.") == "a.example"
    assert canonical("domain", "single") is None
    assert canonical("url", "x" * 2049) is None
    assert canonical("url", "x.example/" + "a" * 2030) is not None
    assert canonical("url", "HTTP://X.Example:80/P?Q=1#frag") == "http://x.example/P?Q=1"
    assert canonical("url", "https://x.example:443/") == "https://x.example/"
    assert canonical("url", "https://x.example:8443/") == "https://x.example:8443/"
    assert canonical("url", "http://x.example:443/") == "http://x.example:443/"
    assert canonical("url", "x.example./a") == "x.example/a"
    assert canonical("url", "http://x.example:99999/") is None  # a bad port
    assert canonical("email", "A.B@X.Example") == "a.b@x.example"
    assert canonical("email", "@x.example") is None
    assert canonical("email", "a@") is None
    assert canonical("hash", "Z" * 32) is None
    assert canonical("other", " MiXed ") == "mixed"
    assert canonical("ip", "1.2.3.4") == "1.2.3.4"
    assert canonical("ip", 12) is None


def test_spelling_variants() -> None:
    from argus.reference.ti import variants

    assert variants("hash", "ab") == ["ab", "AB"]
    assert variants("domain", "a.example") == ["a.example", "A.EXAMPLE"]
    assert variants("email", "a@b.example") == ["a@b.example", "A@B.EXAMPLE"]
    assert variants("other", "x") == ["x", "X"]
    assert variants("ip", "1.2.3.4") == ["1.2.3.4", "::ffff:1.2.3.4"]
    assert variants("ip", "2001:db8::1") == ["2001:db8::1"]
    assert variants("url", "http://a/") == ["http://a/"]
    assert variants("other", "1") == ["1"]  # the same spelling once


def test_fields_and_times() -> None:
    assert ti_module._get({"a.b": 1}, "a.b") == 1
    assert ti_module._get({"a": {"b": {"c": 2}}}, "a.b.c") == 2
    assert ti_module._get({"a": 3}, "a.b") is None
    assert ti_module._get({}, "a") is None
    assert ti_module._time("2026-10-01T00:00:00Z") == datetime(2026, 10, 1, tzinfo=UTC)
    assert ti_module._time("2026-10-01T05:30:00+05:30") == datetime(2026, 10, 1, tzinfo=UTC)
    assert ti_module._time("") is None
    assert ti_module._time(5) is None
    assert ti_module._time("nope") is None
    assert ti_module._text(None) is None
    assert ti_module._text("  ") is None
    assert ti_module._text(7) == "7"


def test_freshness_and_answers_exactly() -> None:
    newest = NOW - STALE_AFTER
    fresh = Freshness(ABUSE, newest, NOW)
    assert fresh.stale(NOW) is False  # exactly 7 days: still fresh
    assert fresh.stale(NOW + timedelta(seconds=1)) is True
    assert Freshness(ACME, None, None).stale(NOW) is True
    assert fresh.as_dict(NOW) == {"source": ABUSE, "newest": newest.isoformat(),
                                  "checked_at": NOW.isoformat(), "stale": False}  # fmt: skip
    assert Freshness(ACME, None, None).as_dict(NOW) == {
        "source": ACME, "newest": None, "checked_at": None, "stale": True}  # fmt: skip
    hit = Indicator(ACME, "ip", "1.2.3.4", "ip", None, None, "high", "feodo")
    other = Indicator(ABUSE, "ip", "9.9.9.9", "ip", None, None, None, None)
    got = answer("1.2.3.4", [other, hit], [Freshness(ACME, newest, NOW), fresh], NOW)
    assert list(got["sources"]) == [ABUSE, ACME]  # by source name
    assert got["value"] == "1.2.3.4"
    assert got["sources"][ABUSE] == {"no_match": fresh.as_dict(NOW)}
    assert got["sources"][ACME]["match"] == [{"kind": "ip", "type": "ip", "first_seen": None,
                                               "last_seen": None, "confidence": "high",
                                               "description": "feodo"}]  # fmt: skip
    assert got["sources"][ACME]["freshness"]["stale"] is False
