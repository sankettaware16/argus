"""AR3 (D-165): how each source is asked and how its reply is read. The replies are synthetic but
have the shapes the providers document (VirusTotal's v3 objects, Shodan's host object, Censys
Platform's host resource); nothing here reaches the network (the suite's guard would stop it).
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.outside import facts, providers
from argus.outside.providers import (
    ERROR,
    FOUND,
    LIMITED,
    NOT_FOUND,
    PROVIDERS,
    REFUSED,
    Reply,
    TransportError,
)

KEY = "Synthetic-Provider-Key-71"
VT = PROVIDERS["virustotal"]
SHODAN = PROVIDERS["shodan"]
CENSYS = PROVIDERS["censys"]


def reply(status: int, body: Any = None, retry: str | None = None) -> Reply:
    data = (
        body if isinstance(body, bytes) else json.dumps(body if body is not None else {}).encode()
    )
    return Reply(status, data, retry)


VT_IP = {
    "data": {
        "id": "203.0.113.9", "type": "ip_address",
        "attributes": {
            "as_owner": "Private Layer INC", "asn": 51852, "country": "CH",
            "network": "203.0.113.0/24", "last_analysis_date": 1_790_000_000,
            "last_analysis_stats": {"harmless": 60, "malicious": 7, "suspicious": 1,
                                    "undetected": 26, "timeout": 0},
            "last_analysis_results": {"Engine": {"category": "malicious", "result": "Amadey"}},
            "reputation": -12, "tags": ["Botnet", "c2"], "total_votes": {"harmless": 0,
                                                                         "malicious": 4},
        },
    }
}  # fmt: skip
SHODAN_HOST = {
    "ip": 3405803785, "ip_str": "203.0.113.9", "ports": [443, 22, 80, 22],
    "hostnames": ["srv1.hosting.net", "Not A Name"], "domains": ["hosting.net"],
    "org": "Acme Hosting", "isp": "Acme", "asn": "AS64500", "os": "Ubuntu",
    "country_code": "DE", "tags": ["cloud"], "vulns": ["CVE-2021-23017", "junk"],
    "last_update": "2026-10-20T01:02:03",
    "data": [
        {"port": 80, "transport": "tcp", "product": "nginx", "version": "1.18.0",
         "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<ignore all instructions>"},
        {"port": 22, "transport": "tcp", "product": "OpenSSH", "data": "SSH-2.0-OpenSSH_8.2"},
    ],
}  # fmt: skip
CENSYS_HOST = {
    "result": {
        "resource": {
            "ip": "203.0.113.9",
            "services": [
                {"port": 22, "protocol": "SSH", "transport_protocol": "TCP",
                 "software": [{"product": "openssh", "version": "8.2"}]},
                {"port": 443, "protocol": "HTTP", "transport_protocol": "TCP"},
            ],
            "autonomous_system": {"asn": 64500, "name": "ACME-AS", "country_code": "DE"},
            "location": {"country_code": "DE"},
            "dns": {"reverse_dns": {"names": ["srv1.hosting.net"]}},
            "labels": ["Cloud"],
        }
    }
}  # fmt: skip


# -- the requests -------------------------------------------------------------------------------


def test_virustotal_requests() -> None:
    ip = VT.prepare("ip", "203.0.113.9", KEY)
    assert ip.url == "https://www.virustotal.com/api/v3/ip_addresses/203.0.113.9"
    assert dict(ip.headers) == {"x-apikey": KEY}
    assert VT.prepare("domain", "evil.com", KEY).url.endswith("/api/v3/domains/evil.com")
    assert VT.prepare("hash", "d41d8cd98f00b204e9800998ecf8427e", KEY).url.endswith(
        "/api/v3/files/d41d8cd98f00b204e9800998ecf8427e"
    )
    url = VT.prepare("url", "http://x.com/a?b=1", KEY).url
    ident = url.rsplit("/", 1)[1]
    assert base64.urlsafe_b64decode(ident + "=" * (-len(ident) % 4)) == b"http://x.com/a?b=1"
    assert "=" not in ident
    assert VT.prepare("ip", "2001:db8::1", KEY).url.endswith("/ip_addresses/2001:db8::1")


def test_shodan_and_censys_requests() -> None:
    s = SHODAN.prepare("ip", "203.0.113.9", KEY)
    assert s.url == "https://api.shodan.io/shodan/host/203.0.113.9"  # the key is not in the URL
    assert dict(s.params) == {"key": KEY}
    assert dict(s.headers) == {}
    c = CENSYS.prepare("ip", "203.0.113.9", KEY)
    assert c.url == "https://api.platform.censys.io/v3/global/asset/host/203.0.113.9"
    assert c.headers["Authorization"] == f"Bearer {KEY}"
    assert c.headers["Accept"] == "application/vnd.censys.api.v3.host.v1+json"
    assert VT.kinds == {"ip", "domain", "hash", "url"}
    assert SHODAN.kinds == CENSYS.kinds == {"ip"}


def test_a_prepared_request_shows_no_key_in_its_repr() -> None:
    for source in (VT, SHODAN, CENSYS):
        prepared = source.prepare("ip", "203.0.113.9", KEY)
        assert KEY not in repr(prepared)
        assert KEY not in prepared.url
        assert KEY not in str(prepared)


# -- the replies --------------------------------------------------------------------------------


def test_virustotal_reads_the_engines_that_flag_an_address() -> None:
    got = VT.parse("ip", reply(200, VT_IP))
    assert got.outcome == FOUND
    a = got.answer
    assert (a["malicious"], a["suspicious"], a["harmless"], a["undetected"], a["engines"]) == (
        7, 1, 60, 26, 94,
    )  # fmt: skip
    assert (a["reputation"], a["owner"], a["asn"], a["country"]) == (
        -12, "Private Layer INC", 51852, "CH",
    )  # fmt: skip
    assert a["tags"] == ["botnet", "c2"]
    assert a["analysed"] == "2026-09-21"
    assert "last_analysis_results" not in a  # per-engine results are not kept
    assert facts.describe(facts.fact("virustotal", "ip", "203.0.113.9", "found", a, 3)) == (
        "VirusTotal: 7 of 94 engines flag this IP, 1 more call it suspicious"
    )


def test_virustotal_without_scores_is_still_a_record() -> None:
    bare = {"data": {"attributes": {"last_analysis_stats": {}}}}
    got = VT.parse("domain", reply(200, bare))
    assert got.outcome == FOUND
    assert got.answer["engines"] == 0
    assert got.answer["malicious"] == 0


@pytest.mark.parametrize("source", [VT, SHODAN, CENSYS])
def test_every_source_settles_a_status_alone(source: Any) -> None:
    assert source.parse("ip", reply(404, {"error": {"code": "NotFoundError"}})).outcome == NOT_FOUND
    limited = source.parse("ip", reply(429, {}, "37"))
    assert (limited.outcome, limited.retry_after) == (LIMITED, 37)
    assert source.parse("ip", reply(429, {}, "99999999")).retry_after == 86_400
    assert source.parse("ip", reply(429, {}, "Wed, 21 Oct 2026 07:28:00 GMT")).retry_after is None
    assert source.parse("ip", reply(401)).outcome == REFUSED
    assert source.parse("ip", reply(403)).outcome == REFUSED
    for status in (400, 500, 502, 503, 204, 301):
        assert source.parse("ip", reply(status, VT_IP)).outcome == ERROR, status


@pytest.mark.parametrize(
    ("value", "seconds"),
    [("0", 0), ("00", 0), (" 37 ", 37), ("86400", 86_400), ("86401", 86_400),
     ("999999999999", 86_400), ("9" * 5_000, 86_400), ("0" * 5_000, 0), ("0" * 5_000 + "5", 5),
     ("\u00b2", None), ("\u0663", None), ("\u0661\u0662", None),  # ² and Arabic-Indic digits
     ("\uff11", None), ("1.5", None), ("-5", None), ("+5", None), ("", None), ("  ", None),
     ("5 s", None), ("1e3", None), ("Wed, 21 Oct 2026 07:28:00 GMT", None), (None, None)],
    ids=lambda v: v[:12] + "..." if isinstance(v, str) and len(v) > 12 else None,
)  # fmt: skip
def test_a_retry_after_is_ascii_digits_within_a_day_and_zero_is_now(
    value: str | None, seconds: int | None
) -> None:
    assert providers._retry(value) == seconds
    for source in (VT, SHODAN, CENSYS):  # whatever it holds, the 429 is read as a stop
        got = source.parse("ip", reply(429, {}, value))
        assert (got.outcome, got.retry_after) == (LIMITED, seconds)


@given(st.text(max_size=40))
def test_no_retry_after_makes_the_reader_raise(value: str) -> None:
    got = providers._retry(value)
    assert got is None or 0 <= got <= providers.MAX_RETRY


NESTED = [b"[" * 200_000 + b"]" * 200_000, b'{"a":' * 200_000, b'{"data":' * 100_000]


@pytest.mark.parametrize("source", [VT, SHODAN, CENSYS])
@pytest.mark.parametrize("body", NESTED)
def test_a_reply_nested_past_the_json_readers_depth_is_an_error_not_a_crash(
    source: Any, body: bytes
) -> None:
    assert source.parse("ip", reply(200, body)).outcome == ERROR


@pytest.mark.parametrize(
    "big", ["AS" + "9" * 5_000, "9" * 5_000, "9" * 11, 10**30],
    ids=lambda v: v[:12] + "..." if isinstance(v, str) and len(v) > 12 else None,
)  # fmt: skip
def test_an_autonomous_system_number_of_any_size_is_read_or_dropped(big: Any) -> None:
    host = {**SHODAN_HOST, "asn": big}
    got = SHODAN.parse("ip", reply(200, host))
    assert got.outcome == FOUND
    assert "asn" not in got.answer
    censys = {"result": {"resource": {"autonomous_system": {"asn": big, "name": "X"}}}}
    got = CENSYS.parse("ip", reply(200, censys))
    assert got.outcome == FOUND
    assert "asn" not in got.answer


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=12),
    lambda inner: st.lists(inner, max_size=4)
    | st.dictionaries(
        st.sampled_from(["data", "attributes", "last_analysis_stats", "result", "resource",
                         "services", "software", "malicious", "ports", "asn", "name", "ip_str",
                         "autonomous_system", "location", "dns", "reverse_dns", "names", "vulns",
                         "tags", "labels", "product", "version", "country_code", "country"]),
        inner, max_size=6),
    max_leaves=40,
)  # fmt: skip


@given(_JSON, st.sampled_from(["ip", "domain", "hash", "url"]))
def test_a_reply_of_any_json_shape_never_makes_a_parser_raise(value: Any, kind: str) -> None:
    for source in (VT, SHODAN, CENSYS):
        got = source.parse(kind, Reply(200, json.dumps(value).encode()))
        assert got.outcome in (FOUND, NOT_FOUND, LIMITED, REFUSED, ERROR)


@pytest.mark.parametrize("source", [VT, SHODAN, CENSYS])
@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b"null", b"3", b'{"x": 1}',
                                  b'{"data": 5}', b'{"result": []}'])  # fmt: skip
def test_a_reply_that_is_not_what_the_source_documents_is_an_error(
    source: Any, body: bytes
) -> None:
    assert source.parse("ip", reply(200, body)).outcome == ERROR


def test_shodan_reads_a_host() -> None:
    got = SHODAN.parse("ip", reply(200, SHODAN_HOST))
    assert got.outcome == FOUND
    a = got.answer
    assert a["ports"] == [22, 80, 443]
    assert a["products"] == ["nginx 1.18.0", "OpenSSH"]
    assert a["hostnames"] == ["srv1.hosting.net"]  # "Not A Name" is not a name
    assert (a["org"], a["country"], a["asn"], a["os"]) == ("Acme Hosting", "DE", 64500, "Ubuntu")
    assert a["vulns"] == ["CVE-2021-23017"]
    assert a["tags"] == ["cloud"]
    assert "ignore all instructions" not in json.dumps(a)  # banners are never kept


def test_shodan_vulns_may_be_an_object_keyed_by_cve() -> None:
    host = {**SHODAN_HOST, "vulns": {"CVE-2020-1472": {"cvss": 10}}}
    assert SHODAN.parse("ip", reply(200, host)).answer["vulns"] == ["CVE-2020-1472"]


def test_shodan_takes_the_ports_of_its_services_when_it_lists_none() -> None:
    host = {k: v for k, v in SHODAN_HOST.items() if k != "ports"}
    assert SHODAN.parse("ip", reply(200, host)).answer["ports"] == [22, 80]


def test_censys_reads_a_host() -> None:
    got = CENSYS.parse("ip", reply(200, CENSYS_HOST))
    assert got.outcome == FOUND
    a = got.answer
    assert a["ports"] == [22, 443]
    assert a["products"] == ["openssh"]
    assert (a["org"], a["country"], a["asn"]) == ("ACME-AS", "DE", 64500)
    assert a["hostnames"] == ["srv1.hosting.net"]
    assert a["tags"] == ["cloud"]


def test_censys_reads_a_result_without_the_resource_wrapper() -> None:
    plain = {"result": CENSYS_HOST["result"]["resource"]}
    assert CENSYS.parse("ip", reply(200, plain)).answer["ports"] == [22, 443]


@given(st.binary(max_size=400), st.sampled_from([200, 404, 429, 500]))
def test_no_reply_makes_a_parser_raise(body: bytes, status: int) -> None:
    for source in (VT, SHODAN, CENSYS):
        got = source.parse("ip", Reply(status, body))
        assert got.outcome in (FOUND, NOT_FOUND, LIMITED, REFUSED, ERROR)
        assert len(json.dumps(dict(got.answer))) <= facts.MAX_ANSWER_JSON


@given(
    st.dictionaries(
        st.sampled_from(
            [
                "ports",
                "hostnames",
                "org",
                "os",
                "tags",
                "vulns",
                "data",
                "country_code",
                "asn",
                "ip_str",
            ]
        ),
        st.one_of(
            st.none(),
            st.integers(),
            st.text(max_size=50),
            st.lists(st.one_of(st.integers(), st.text(max_size=20)), max_size=100),
        ),
    )
)
def test_a_shodan_host_of_any_shape_is_kept_small_and_clean(host: dict[str, Any]) -> None:
    got = SHODAN.parse("ip", reply(200, {"ip_str": "x", **host}))
    if got.outcome == FOUND:
        assert len(json.dumps(dict(got.answer))) <= facts.MAX_ANSWER_JSON
        assert len(got.answer.get("ports", [])) <= 40


# -- the transport ------------------------------------------------------------------------------


def client_for(handler: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


async def test_the_transport_sends_https_to_the_sources_hosts_and_reads_the_reply() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": 1}, headers={"retry-after": "5"})

    transport = providers.HttpxTransport(client_for(handler))
    got = await transport.get(SHODAN.prepare("ip", "203.0.113.9", KEY), 5.0)
    assert (got.status, json.loads(got.body), got.retry_after) == (200, {"ok": 1}, "5")
    assert seen[0].url.params["key"] == KEY
    assert seen[0].method == "GET"
    got = await transport.get(VT.prepare("ip", "203.0.113.9", KEY), 5.0)
    assert seen[1].headers["x-apikey"] == KEY
    assert got.status == 200
    await transport.aclose()


async def test_the_transport_refuses_any_other_host_or_a_plain_http_url() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("nothing may be sent")

    transport = providers.HttpxTransport(client_for(handler))
    for url in ("https://evil.example.net/x", "http://www.virustotal.com/api/v3/x",
                "https://www.virustotal.com.evil.net/x", "https://127.0.0.1/x"):  # fmt: skip
        with pytest.raises(TransportError, match="not one of the sources' hosts"):
            await transport.get(providers.Prepared(url, {"x-apikey": KEY}), 5.0)


async def test_a_failure_says_its_type_never_the_url_that_holds_shodans_key() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot reach {request.url}")

    transport = providers.HttpxTransport(client_for(handler))
    with pytest.raises(TransportError) as caught:
        await transport.get(SHODAN.prepare("ip", "203.0.113.9", KEY), 5.0)
    assert str(caught.value) == "ConnectError"
    assert KEY not in repr(caught.value)
    assert caught.value.__cause__ is None  # `from None`: the original message stays out


async def test_a_reply_over_the_cap_is_refused() -> None:
    big = b"x" * (providers.MAX_REPLY_BYTES + 1)
    transport = providers.HttpxTransport(client_for(lambda r: httpx.Response(200, content=big)))
    with pytest.raises(TransportError, match="reply too large"):
        await transport.get(VT.prepare("ip", "203.0.113.9", KEY), 5.0)


async def test_a_redirect_is_not_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.shodan.io":
            return httpx.Response(302, headers={"location": "https://evil.example.net/x"})
        raise AssertionError("the redirect was followed")

    transport = providers.HttpxTransport(client_for(handler))
    got = await transport.get(SHODAN.prepare("ip", "203.0.113.9", KEY), 5.0)
    assert got.status == 302
    assert SHODAN.parse("ip", got).outcome == ERROR


# -- AR2c (D-168): a domain's answer carries its popularity, registrar and where it points -----

VT_DOMAIN = {
    "data": {
        "id": "fast-dns-host.example", "type": "domain",
        "attributes": {
            "last_analysis_stats": {"harmless": 60, "malicious": 5, "suspicious": 0,
                                    "undetected": 26, "timeout": 0},
            "last_analysis_results": {"Engine": {"category": "malicious", "result": "phishing"}},
            "creation_date": 1_790_000_000, "registrar": "Namecheap, Inc.  <b>x</b>",
            "popularity_ranks": {},
            "last_dns_records": [
                {"type": "A", "ttl": 300, "value": "203.0.113.9"},
                {"type": "A", "ttl": 300, "value": "203.0.113.10"},
                {"type": "A", "ttl": 300, "value": "203.0.113.9"},
                {"type": "NS", "ttl": 3600, "value": "NS1.Dnshost.Example."},
                {"type": "NS", "ttl": 3600, "value": "ns2.dnshost.example"},
                {"type": "MX", "ttl": 3600, "value": "mail.fast-dns-host.example"},
                {"type": "AAAA", "ttl": 300, "value": "2001:db8::1"},
                {"type": "A", "ttl": 300, "value": "not an address"},
            ],
        },
    }
}  # fmt: skip


def test_virustotal_reads_a_domains_family_fields() -> None:
    a = VT.parse("domain", reply(200, VT_DOMAIN)).answer
    assert (a["malicious"], a["engines"]) == (5, 91)
    assert a["shape"] == facts.DOMAIN_SHAPE
    assert a["ranked"] is False  # an empty object: VirusTotal knows no rank for it
    assert "best_rank" not in a
    assert a["created"] == "2026-09-21"
    assert a["registrar"] == "Namecheap, Inc. b x /b"  # cleaned: no markup
    assert a["name_servers"] == ["ns1.dnshost.example", "ns2.dnshost.example"]
    assert a["addresses"] == ["203.0.113.9", "203.0.113.10"]  # A records only, distinct, in order
    assert "last_dns_records" not in a
    assert "last_analysis_results" not in a


def test_a_ranked_domain_says_so_and_keeps_the_best_web_rank() -> None:
    now = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)
    stamp = int(now.timestamp()) - 86_400
    ranked = {"data": {"attributes": {
        "last_analysis_stats": {"harmless": 80},
        "popularity_ranks": {"Majestic": {"rank": 1873, "timestamp": stamp},
                             "Cisco Umbrella": {"rank": 412, "timestamp": stamp},
                             "Broken": {"rank": "x"}, "Other": 5},
    }}}  # fmt: skip
    a = VT.parse("domain", reply(200, ranked), now).answer
    # Cisco Umbrella ranks what devices ask for, not what people visit: it is kept for display
    assert (a["ranked"], a["best_rank"]) == (True, 1873)
    assert a["ranks"] == {"Majestic": 1873, "Cisco Umbrella": 412}


def test_a_reply_without_a_usable_rank_is_unranked() -> None:
    """A reply of the current shape with no qualifying rank is unranked (D-174): the old rule left
    ``ranked`` out, and a family could then neither be rare nor popular."""
    bare = {"data": {"attributes": {"last_analysis_stats": {"harmless": 80}}}}
    a = VT.parse("domain", reply(200, bare)).answer
    assert a["ranked"] is False
    assert "best_rank" not in a
    assert a["shape"] == facts.DOMAIN_SHAPE
    for junk in ("x", 5, [], None, [{"rank": 3}]):
        odd = {"data": {"attributes": {"last_analysis_stats": {}, "popularity_ranks": junk}}}
        assert VT.parse("domain", reply(200, odd)).answer["ranked"] is False, junk


def test_an_address_answer_has_no_family_fields() -> None:
    a = VT.parse("ip", reply(200, VT_IP)).answer
    assert not {"shape", "ranked", "name_servers", "addresses", "registrar"} & set(a)


@given(
    st.lists(
        st.fixed_dictionaries(
            {"type": st.sampled_from(["A", "NS", "MX", "TXT", 5, None]),
             "value": st.one_of(st.text(max_size=300), st.integers(), st.none())}
        ),
        max_size=200,
    ),
    st.one_of(st.dictionaries(st.text(max_size=20), st.integers(), max_size=60), st.none()),
)  # fmt: skip
def test_a_domain_of_any_records_is_kept_small_and_clean(
    records: list[dict[str, Any]], ranks: Any
) -> None:
    attributes = {"last_analysis_stats": {"malicious": 1}, "last_dns_records": records,
                  "popularity_ranks": ranks}  # fmt: skip
    body = {"data": {"attributes": attributes}}
    got = VT.parse("domain", reply(200, body))
    assert got.outcome == FOUND
    a = got.answer
    assert len(json.dumps(dict(a))) <= facts.MAX_ANSWER_JSON
    assert len(a.get("addresses", [])) <= 5
    assert len(a.get("name_servers", [])) <= 5
    assert all(facts.canonical("ip", x) == x for x in a.get("addresses", []))
    assert all(facts.canonical("domain", x) == x for x in a.get("name_servers", []))


# -- AR2c (D-168): Shodan's free InternetDB -----------------------------------------------------

INTERNETDB = providers.INTERNETDB
INTERNETDB_HOST = {
    "cpes": ["cpe:/a:apache:http_server:2.4.41", "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*",
             "cpe:/o:linux:linux_kernel", "cpe:/a:apache:http_server:2.4.41", "junk", 5],
    "hostnames": ["srv1.hosting.net", "Not A Name"], "ip": "203.0.113.9",
    "ports": [443, 22, 80, 22], "tags": ["Cloud", "self-signed"],
    "vulns": ["CVE-2021-23017", "junk", "CVE-2021-23017"],
}  # fmt: skip


def test_internetdb_request_has_no_key_and_the_shodan_source() -> None:
    got = INTERNETDB.prepare("ip", "203.0.113.9", "")
    assert got.url == "https://internetdb.shodan.io/203.0.113.9"
    assert dict(got.headers) == {}
    assert dict(got.params) == {}
    assert INTERNETDB.source == facts.SHODAN
    assert INTERNETDB.kinds == {"ip"}
    assert INTERNETDB.prepare("ip", "2001:db8::1", "").url.endswith("/2001:db8::1")


def test_internetdb_reads_a_record() -> None:
    got = INTERNETDB.parse("ip", reply(200, INTERNETDB_HOST))
    assert got.outcome == FOUND
    a = got.answer
    assert a["ports"] == [22, 80, 443]
    assert a["products"] == ["http server 2.4.41", "openssh 8.2", "linux kernel"]
    assert a["hostnames"] == ["srv1.hosting.net"]
    assert a["tags"] == ["cloud", "self-signed"]
    assert a["vulns"] == ["CVE-2021-23017"]
    assert "org" not in a
    assert "asn" not in a
    sentence = facts.describe(facts.fact("shodan", "ip", "203.0.113.9", "found", a, 3))
    assert sentence.startswith("Shodan: open ports 22, 80, 443; software http server 2.4.41,")
    assert "1 known CVE" in sentence


def test_internetdb_no_record_is_a_404_and_settles_like_the_others() -> None:
    assert INTERNETDB.parse("ip", reply(404, {"detail": "No information available"})).outcome == (
        NOT_FOUND
    )
    assert INTERNETDB.parse("ip", reply(429, {}, "11")).retry_after == 11
    assert INTERNETDB.parse("ip", reply(500)).outcome == ERROR


@pytest.mark.parametrize("body", [b"", b"[]", b"null", b'{"cpes": []}', b'{"ip": 5}',
                                  b'{"detail": "nothing"}'])  # fmt: skip
def test_an_internetdb_reply_that_names_no_address_is_an_error(body: bytes) -> None:
    assert INTERNETDB.parse("ip", reply(200, body)).outcome == ERROR


def test_an_empty_internetdb_record_is_still_a_record() -> None:
    got = INTERNETDB.parse("ip", reply(200, {"ip": "203.0.113.9", "ports": [], "cpes": []}))
    assert (got.outcome, dict(got.answer)) == (FOUND, {})


@given(
    st.dictionaries(
        st.sampled_from(["cpes", "hostnames", "ports", "tags", "vulns", "ip"]),
        st.one_of(st.none(), st.integers(), st.text(max_size=50),
                  st.lists(st.one_of(st.integers(), st.text(max_size=40)), max_size=100),
                  st.dictionaries(st.text(max_size=12), st.integers(), max_size=20)),
    )
)  # fmt: skip
def test_an_internetdb_record_of_any_shape_never_raises_and_is_kept_small(
    record: dict[str, Any],
) -> None:
    got = INTERNETDB.parse("ip", reply(200, {"ip": "203.0.113.9", **record}))
    assert got.outcome in (FOUND, ERROR)
    assert len(json.dumps(dict(got.answer))) <= facts.MAX_ANSWER_JSON
    assert len(got.answer.get("ports", [])) <= 40
    assert len(got.answer.get("products", [])) <= 6


@pytest.mark.parametrize(
    ("cpe", "text"),
    [("cpe:/a:apache:http_server:2.4.41", "http server 2.4.41"),
     ("cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", "nginx 1.18.0"),
     ("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "nginx"),
     ("cpe:/a:vendor:product", "product"), ("cpe:/a:vendor", None), ("nginx", None), ("cpe:", None),
     (5, None), (None, None)],
)  # fmt: skip
def test_a_cpe_is_reduced_to_its_product_and_version(cpe: Any, text: str | None) -> None:
    assert providers._cpe(cpe) == text


async def test_the_transport_reaches_internetdb_and_still_no_other_host() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ip": "203.0.113.9"})

    transport = providers.HttpxTransport(client_for(handler))
    got = await transport.get(INTERNETDB.prepare("ip", "203.0.113.9", ""), 5.0)
    assert got.status == 200
    assert str(seen[0].url) == "https://internetdb.shodan.io/203.0.113.9"
    with pytest.raises(TransportError):
        await transport.get(providers.Prepared("https://internetdb.shodan.io.evil.test/x"), 5.0)
    with pytest.raises(TransportError):
        await transport.get(providers.Prepared("http://internetdb.shodan.io/203.0.113.9"), 5.0)
