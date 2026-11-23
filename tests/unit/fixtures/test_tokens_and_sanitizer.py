"""R2 tokens, domains, sanitizer and leak scanner (synthetic data only)."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.fixtures import FixturePolicy, LeakScanner, Sanitizer, Tokenizer
from argus.fixtures.tokens import DomainMapper

KEY = b"k" * 32
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    own_domains=("campus.example.edu",),
    keep_domains=("vendor-cdn.com",),
    literals={"Campus University": "Example University", "CU": "EU"},
    fields={
        "host": ("host.name", "observer.hostname"),
        "user": ("user.name",),
        "email": ("user.email",),
        "place": ("source.site.department",),
        "domain": ("url.domain",),
        "id": ("_id", "kibana.alert.uuid", "kibana.alert.ancestors.id"),
    },
)
TOKENS = Tokenizer(KEY)


# ------------------------------------------------------------------ tokens


def test_tokens_are_deterministic_prefixed_base32() -> None:
    t = TOKENS.token("host", "node7", "h-")
    assert t == Tokenizer(KEY).token("host", "node7", "h-")
    assert re.fullmatch(r"h-[a-z2-7]{8}", t)
    assert TOKENS.token("host", "node7", "h-") != TOKENS.token("user", "node7", "h-")


@pytest.mark.parametrize(
    ("value", "pattern"),
    [
        ("a" * 64, r"[0-9a-f]{64}"),
        ("0123456789abcdef0123456789abcdef01234567", r"[0-9a-f]{40}"),
        ("ABCDEF0123", r"[0-9A-F]{10}"),
        (
            "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a",
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ),
        ("SyntheticAlertId0001", r"[A-Za-z0-9_-]{20}"),
        ("weird id/with spaces", r"id-[a-z2-7]{20}"),
    ],
)
def test_opaque_ids_keep_their_shape(value: str, pattern: str) -> None:
    out = TOKENS.opaque_id(value)
    assert re.fullmatch(pattern, out)
    assert out != value
    assert out == TOKENS.opaque_id(value)


@given(st.text(alphabet="0123456789abcdef", min_size=1, max_size=96))
def test_hex_ids_keep_length(value: str) -> None:
    assert len(TOKENS.opaque_id(value)) == len(value)


DOMAINS = DomainMapper(TOKENS, ["campus.example.edu"], ["vendor-cdn.com"])


@pytest.mark.parametrize(
    ("domain", "pattern"),
    [
        ("www.lab.campus.example.edu", r"[a-z2-7]{8}\.[a-z2-7]{8}\.univ\.example"),
        ("campus.example.edu", r"univ\.example"),
        ("WWW.Campus.Example.Edu.", r"[a-z2-7]{8}\.univ\.example"),
        ("vendor-cdn.com", r"vendor-cdn\.com"),
        ("a.b.vendor-cdn.com", r"a\.b\.vendor-cdn\.com"),
        ("evil.example-c2.ru", r"[a-z2-7]{8}\.[a-z2-7]{8}\.ru"),
        ("x.shop.co.uk", r"[a-z2-7]{8}\.[a-z2-7]{8}\.co\.uk"),
        ("localhostname", r"[a-z2-7]{8}"),
    ],
)
def test_domain_mapping(domain: str, pattern: str) -> None:
    assert re.fullmatch(pattern, DOMAINS.map(domain)), DOMAINS.map(domain)


def test_idn_domains_are_punycoded_then_mapped() -> None:
    out = DOMAINS.map("bücher.example-shop.de")
    assert out.isascii()
    assert out.endswith(".de")


# ------------------------------------------------------------------ sanitizer


def _alert() -> dict[str, object]:
    return {
        "_index": ".internal.alerts-security.alerts-cu-000001",
        "_id": "SyntheticAlertId0001",
        "_score": 1.0,
        "fields": {"source.ip": ["10.1.2.3"]},
        "_source": {
            "kibana.alert.uuid": "SyntheticAlertId0001",
            "kibana.alert.ancestors": [
                {"id": "Zz9AncestorIdAbCdEfG", "index": "logs-proxy-2026.10.08"}
            ],
            "kibana.alert.reason": "source 10.1.2.3:52159 to 8.8.4.4 on node7 (Campus University)",
            "kibana.alert.rule.query": "not destination.ip:(10.0.0.0/8 or 172.16.0.0/12)",
            "kibana.alert.risk_score": 47,
            "@timestamp": "2026-10-08T12:00:00.000Z",
            "host": {"name": "node7"},
            "observer": {"hostname": "node7", "ip": "192.0.2.79"},
            "source": {"ip": "10.1.2.3", "site": {"department": "PHYS", "zone": "hostel"}},
            "destination": {"ip": "8.8.4.4", "port": 22},
            "url": {
                "original": "http://alice:hunter2@www.campus.example.edu"  # fake-secret
                "/x?ip=10.9.9.9&next=https://8.8.4.4/y",
                "domain": "www.campus.example.edu",
            },
            "user": {"name": "alice", "email": "Alice.Smith@campus.example.edu"},
            "user_agent": {"original": "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36"},
            "event": {
                "original": "node7 squid: 10.1.2.3:52159 192.0.2.79:3128 GET http://8.8.4.4/a"
            },
            "message": (
                "contact alice at Alice.Smith@campus.example.edu from lab.campus.example.edu"
            ),
            "flags": [True, None, 3.5],
        },
    }


@pytest.fixture
def sanitized() -> tuple[Sanitizer, dict[str, object], dict[str, object]]:
    raw = _alert()
    s = Sanitizer(POLICY, KEY)
    s.harvest([raw])
    return s, raw, s.sanitize(raw)


def _src(doc: dict[str, object]) -> dict[str, object]:
    out = doc["_source"]
    assert isinstance(out, dict)
    return out


def test_wire_format_drops_discover_extras(sanitized) -> None:  # type: ignore[no-untyped-def]
    _, _, out = sanitized
    assert set(out) == {"_index", "_id", "_source"}


def test_ids_are_consistent(sanitized) -> None:  # type: ignore[no-untyped-def]
    _, raw, out = sanitized
    src = _src(out)
    assert out["_id"] == src["kibana.alert.uuid"] != raw["_id"]
    assert src["kibana.alert.ancestors"][0]["id"] != "Zz9AncestorIdAbCdEfG"  # type: ignore[index]
    assert src["kibana.alert.ancestors"][0]["index"] == "logs-proxy-2026.10.08"  # type: ignore[index]


def test_ips_hosts_and_text_are_mapped_consistently(sanitized) -> None:  # type: ignore[no-untyped-def]
    s, _, out = sanitized
    src = _src(out)
    internal = s.ips.map_text("10.1.2.3")
    public = s.ips.map_text("8.8.4.4")
    site = s.ips.map_text("192.0.2.79")
    host = src["host"]["name"]  # type: ignore[index]
    assert src["observer"]["hostname"] == host  # type: ignore[index]
    assert ipaddress.ip_address(internal) in ipaddress.ip_network("10.0.0.0/8")
    assert ipaddress.ip_address(site) in ipaddress.ip_network("198.18.0.0/15")
    reason = src["kibana.alert.reason"]
    assert reason == f"source {internal}:52159 to {public} on {host} (Example University)"
    original = src["event"]["original"]  # type: ignore[index]
    assert original == f"{host} squid: {internal}:52159 {site}:3128 GET http://{public}/a"


def test_class_level_cidrs_and_versions_are_kept(sanitized) -> None:  # type: ignore[no-untyped-def]
    _, _, out = sanitized
    src = _src(out)
    assert src["kibana.alert.rule.query"] == "not destination.ip:(10.0.0.0/8 or 172.16.0.0/12)"
    assert src["user_agent"]["original"] == "Mozilla/5.0 Chrome/154.0.0.0 Safari/537.36"  # type: ignore[index]


def test_urls_emails_and_campus_domains(sanitized) -> None:  # type: ignore[no-untyped-def]
    s, _, out = sanitized
    src = _src(out)
    url = src["url"]["original"]  # type: ignore[index]
    assert "hunter2" not in url
    assert "alice" not in url
    assert ":REDACTED@" in url
    assert ".univ.example/x?ip=" in url
    assert s.ips.map_text("10.9.9.9") in url
    assert f"https://{s.ips.map_text('8.8.4.4')}/y" in url
    assert src["url"]["domain"].endswith(".univ.example")  # type: ignore[index]
    assert re.fullmatch(r"u-[a-z2-7]{8}@univ\.example", src["user"]["email"])  # type: ignore[index]
    assert "campus.example.edu" not in json.dumps(out)
    assert "Alice" not in json.dumps(out)


def test_non_identifiers_are_untouched(sanitized) -> None:  # type: ignore[no-untyped-def]
    _, raw, out = sanitized
    src, rsrc = _src(out), _src(raw)
    assert src["@timestamp"] == rsrc["@timestamp"]
    assert src["kibana.alert.risk_score"] == 47
    assert src["destination"]["port"] == 22  # type: ignore[index]
    assert src["flags"] == [True, None, 3.5]
    assert src["source"]["site"]["zone"] == "hostel"  # type: ignore[index]
    assert src["source"]["site"]["department"].startswith("pl-")  # type: ignore[index]


def test_output_is_deterministic() -> None:
    raw = _alert()
    a, b = Sanitizer(POLICY, KEY), Sanitizer(POLICY, KEY)
    a.harvest([raw])
    b.harvest([raw])
    assert json.dumps(a.sanitize(raw), sort_keys=True) == json.dumps(
        b.sanitize(raw), sort_keys=True
    )


def test_no_harvested_identifier_survives(sanitized, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    s, _, out = sanitized
    denylist = (s.harvested - s.unchanged - s.pseudonyms) | set(POLICY.literals)
    scanner = LeakScanner(denylist)
    path = tmp_path / "fixture.json"
    path.write_text(json.dumps(out))
    assert scanner.scan_file(path) == []


# ------------------------------------------------------------------ leak scanner


@pytest.mark.parametrize(
    "text",
    [
        '{"a": "host 10.1.2.3 seen"}',
        '{"a": "host 10\\u002e1.2.3 seen"}',
        '{"a": "q=10%2E1.2.3"}',
        '{"a": "q=10%252E1.2.3"}',
        '{"a": "secret-hostname-x9 here"}',
        '{"a": "SECRET-HOSTNAME-X9 here"}',
    ],
)
def test_leak_scanner_finds_hidden_forms(text: str, tmp_path: Path) -> None:
    scanner = LeakScanner({"10.1.2.3", "secret-hostname-x9"})
    path = tmp_path / "f.json"
    path.write_text(text)
    leaks = scanner.scan_file(path)
    assert leaks
    assert "10.1.2.3" not in str(leaks[0])  # reports never print the identifier


@pytest.mark.parametrize(
    "text",
    ['{"a": "10.1.2.30"}', '{"a": "110.1.2.3"}', '{"a": "EEXIST and ee"}', '{"meta": 1}'],
)
def test_leak_scanner_boundaries(text: str, tmp_path: Path) -> None:
    scanner = LeakScanner({"10.1.2.3", "EE", "META"})
    path = tmp_path / "f.json"
    path.write_text(text)
    assert scanner.scan_file(path) == []
