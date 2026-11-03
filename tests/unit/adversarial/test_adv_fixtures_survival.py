"""Adversarial attack on R2's fixture sanitizer: does an original identifier survive?

Lens: an internal or campus IP, a site-prefix IP, a host name, a user name, an e-mail, a campus
domain, a policy literal (the institution's name) or an internal id that comes out of
``Sanitizer.sanitize`` / ``map_text`` in any form a reader could recover. Attacked: IP notations
(padding, glue, ``addr.port``, reverse DNS, IPv6 forms, CIDRs, URLs), domain forms (case, dots,
underscore labels, LDAP DNs, URL encoding, kept vendor domains), identifiers from identifier fields
reappearing in free text in another form (case, FQDN vs short name, UPN, paths), policy literals,
structure (keys, lists, unlisted ECS fields, rule queries, threshold terms) and the fixture file
name ``scripts/sanitize_fixtures.py`` derives from the rule name.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests pass
today and pin behaviour that held up under attack. Every identifier here is synthetic
(documentation and private address ranges, example domains, made-up names); the only repository
files read are the tracked policy ``config/fixtures.yaml`` (for its list of identifier fields) and
the ``slug`` function of the driver script, compiled on its own so nothing else in it runs.
"""

from __future__ import annotations

import ast
import re
import types
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from argus.fixtures import FixturePolicy, Sanitizer, load_policy

REPO = Path(__file__).resolve().parents[3]
KEY = b"k" * 32
CAMPUS = "campus.ac.in"
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    campus_domains=(CAMPUS,),
    keep_domains=("vendor-cdn.example",),
    literals={"Campus University": "Example University", "campusu": "exampleu"},
    fields={
        "host": ("host.name", "observer.hostname"),
        "user": ("user.name", "related.user"),
        "email": ("user.email",),
        "domain": ("url.domain", "dns.question.name"),
        "id": ("_id",),
    },
)


def _run(source: dict[str, Any], policy: FixturePolicy = POLICY) -> dict[str, Any]:
    """Harvest and sanitize one wire-format document; return the sanitized ``_source``."""
    doc = {"_index": "logs-synthetic-000001", "_id": "AbCdEfGhIjKlMnOpQrSt", "_source": source}
    sanitizer = Sanitizer(policy, KEY)
    sanitizer.harvest([doc])
    out = sanitizer.sanitize(doc)["_source"]
    assert isinstance(out, dict)
    return out


def _strings(node: Any) -> Iterator[str]:
    """Every string in the output, mapping keys included (keys are committed too)."""
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _strings(item)


def _found(pattern: str, out: Any, flags: int = re.IGNORECASE) -> list[str]:
    rx = re.compile(pattern, flags)
    return [m.group(0) for s in _strings(out) for m in rx.finditer(s)]


def _word(identifier: str) -> str:
    """The identifier as a whole word (pseudonym tokens are alphanumeric runs, never a match)."""
    return rf"(?<![A-Za-z0-9]){re.escape(identifier)}(?![A-Za-z0-9])"


def _ip(identifier: str) -> str:
    return rf"(?<![0-9]){re.escape(identifier)}(?![0-9])"


def _nested(path: str, value: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    node = out
    *parents, leaf = path.split(".")
    for part in parents:
        node = node.setdefault(part, {})
    node[leaf] = value
    return out


def _script_slug() -> Callable[[str], str]:
    """``slug`` from scripts/sanitize_fixtures.py, compiled alone (the module body never runs)."""
    path = REPO / "scripts" / "sanitize_fixtures.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "slug")
    module = compile(ast.Module(body=[fn], type_ignores=[]), str(path), "exec")
    code = next(
        c for c in module.co_consts if isinstance(c, types.CodeType) and c.co_name == "slug"
    )
    return types.FunctionType(code, {"re": re})  # type: ignore[return-value]


# ====================================================================== DEFECTS


@pytest.mark.parametrize(
    ("source", "identifier"),
    [
        pytest.param(
            {"host": {"name": "lab-pc-07"}, "message": "An account logged on: LAB-PC-07$"},
            "lab-pc-07",
            id="host-upper-netbios",
        ),
        pytest.param(
            {"user": {"name": "bob"}, "message": "Account Name: Bob  Logon Type: 3"},
            "bob",
            id="user-titlecase",
        ),
        pytest.param(
            {"user": {"name": "bob"}, "message": "CAMPUSNB\\BOB failed to log on"},
            "bob",
            id="user-upper-domain-backslash",
        ),
    ],
)
def test_fxa01_identifier_in_another_case_survives(source: dict[str, Any], identifier: str) -> None:
    """DEFECT FXA-01: the harvested-identifier dictionary is case-sensitive.

    ``host.name: lab-pc-07`` is pseudonymized, but the Windows message carrying the NetBIOS form
    ``LAB-PC-07$`` keeps it; ``user.name: bob`` is pseudonymized but ``Bob`` / ``BOB`` in text are
    not. (For names shorter than 5 characters the leak scanner matches exactly, so it is blind too.)
    """
    out = _run(source)
    assert _found(_word(identifier), out) == []


@pytest.mark.parametrize(
    ("source", "identifier"),
    [
        pytest.param(
            {
                "host": {"name": f"lab-pc-07.{CAMPUS}"},
                "message": "Kerberos TGT requested by LAB-PC-07$ from lab-pc-07",
            },
            "lab-pc-07",
            id="fqdn-host-short-name-in-text",
        ),
        pytest.param(
            {"user": {"name": f"carol@{CAMPUS}"}, "message": "session opened for user carol"},
            "carol",
            id="upn-user-bare-name-in-text",
        ),
        pytest.param(
            {"user": {"name": "CAMPUSNB\\carol"}, "message": "carol changed her password"},
            "carol",
            id="domain-user-bare-name-in-text",
        ),
    ],
)
def test_fxa02_bare_part_of_a_qualified_identifier_survives(
    source: dict[str, Any], identifier: str
) -> None:
    """DEFECT FXA-02: an identifier field holding a qualified name protects only the whole value.

    ``host.name: lab-pc-07.campus.ac.in`` becomes ``<tok>.univ.example`` and the dictionary holds
    only the FQDN, so the short host name in the same document (``LAB-PC-07$``, ``lab-pc-07``)
    survives; likewise ``carol`` from ``carol@campus.ac.in`` or ``CAMPUSNB\\carol``. The short form
    is never harvested, so the leak scanner's denylist does not contain it either.
    """
    out = _run(source)
    assert _found(_word(identifier), out) == []


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        pytest.param(
            "GET /login?redirect=http%3A%2F%2F10.1.2.3%2Fportal HTTP/1.1",
            _ip("10.1.2.3"),
            id="internal-ip-after-encoded-slashes",
        ),
        pytest.param(
            "GET /sso?next=https%3A%2F%2Fcampus.ac.in%2Fhome HTTP/1.1",
            re.escape(CAMPUS),
            id="campus-domain-after-encoded-slashes",
        ),
        pytest.param(
            "GET /authorize?login_hint=alice%40campus.ac.in&prompt=login HTTP/1.1",
            r"alice|campus\.ac\.in",
            id="email-with-encoded-at",
        ),
    ],
)
def test_fxa03_url_encoded_identifiers_survive(text: str, pattern: str) -> None:
    """DEFECT FXA-03: percent-encoded query values hide identifiers from every detector.

    The IPv4, e-mail and campus regexes refuse to start after a word character, and the hex digit of
    ``%2F`` / ``%40`` / ``%3D`` is one. ``redirect=http%3A%2F%2F10.1.2.3%2F`` keeps the internal IP,
    ``next=https%3A%2F%2Fcampus.ac.in`` keeps the campus domain and
    ``login_hint=alice%40campus.ac.in`` keeps the user and the domain. None of them is harvested,
    so the scanner's denylist misses them unless the same value appears elsewhere in the corpus.
    """
    out = _run({"event": {"original": text}})
    assert _found(pattern, out) == []


_SHIPPED_FIELDS = dict(load_policy(REPO / "config" / "fixtures.yaml")[0].fields)
_SHIPPED = FixturePolicy(
    site_prefixes=("192.0.2.0/24",), campus_domains=(CAMPUS,), fields=_SHIPPED_FIELDS
)


@pytest.mark.parametrize(
    ("path", "value", "identifier"),
    [
        ("user.target.name", "syn-dave", "syn-dave"),
        ("winlog.event_data.TargetUserName", "syn-erin", "syn-erin"),
        ("winlog.event_data.SubjectUserName", "syn-frank", "syn-frank"),
        ("winlog.event_data.WorkstationName", "WS-ROOM-12", "WS-ROOM-12"),
        ("winlog.computer_name", "dc-room-01", "dc-room-01"),
        ("observer.name", "fw-core-09", "fw-core-09"),
        ("related.hosts", ["srv-room-09"], "srv-room-09"),
        ("process.user.name", "syn-gina", "syn-gina"),
        ("user.full_name", "Ivy Synthetic", "Ivy Synthetic"),
        ("file.path", "C:\\Users\\syn-judy\\AppData\\Local\\Temp\\a.exe", "syn-judy"),
        ("process.working_directory", "/home/syn-kate/build", "syn-kate"),
    ],
)
def test_fxa04_identifiers_in_unlisted_fields_survive(
    path: str, value: Any, identifier: str
) -> None:
    """DEFECT FXA-04: the shipped field list misses common ECS / Windows identifier fields.

    With the ``fields`` of config/fixtures.yaml, a user or host that appears only in
    ``user.target.name``, ``winlog.event_data.TargetUserName``, ``winlog.computer_name``,
    ``observer.name``, ``related.hosts``, ``process.user.name``, ``user.full_name`` or a
    home-directory path is never harvested and goes through untouched (and is absent from the
    leak denylist).
    """
    out = _run(_nested(path, value), _SHIPPED)
    assert _found(_word(identifier), out) == []


@pytest.mark.parametrize(
    "text",
    [
        "query[SRV] _ldap._tcp.dc._msdcs.campus.ac.in from 10.9.8.7",
        "query[TXT] _dmarc.campus.ac.in from 10.9.8.7",
        "query[SRV] _kerberos._udp.campus.ac.in from 10.9.8.7",
    ],
)
def test_fxa05_underscore_dns_labels_hide_the_campus_domain(text: str) -> None:
    """DEFECT FXA-05: a campus name under an underscore label survives in free text.

    The campus regex's label class ``[a-z0-9-]`` has no ``_`` and its look-behind rejects a ``_`` or
    ``.`` before ``campus``, so ``_ldap._tcp.dc._msdcs.campus.ac.in`` (AD SRV lookups),
    ``_dmarc.campus.ac.in`` and ``_kerberos._udp.campus.ac.in`` are not matched at all.
    """
    out = _run({"event": {"original": text}})
    assert _found(re.escape(CAMPUS), out) == []


@pytest.mark.parametrize(
    ("text", "recoverable"),
    [
        pytest.param(
            "client 10.9.8.7#5353: query: 254.2.1.10.in-addr.arpa IN PTR",
            "254.2.1.10",
            id="ptr-last-octet-254",
        ),
        pytest.param(
            "client 10.9.8.7#5353: query: 0.2.1.10.in-addr.arpa IN PTR",
            "0.2.1.10",
            id="ptr-last-octet-0",
        ),
        pytest.param(
            "zone 2.1.10.in-addr.arpa/IN: transferred serial 7",
            "2.1.10.in-addr",
            id="three-octet-reverse-zone",
        ),
    ],
)
def test_fxa06_reverse_dns_names_survive(text: str, recoverable: str) -> None:
    """DEFECT FXA-06: reverse-DNS names are read as forward dotted quads.

    ``254.2.1.10.in-addr.arpa`` is the PTR name of 10.1.2.254. The text pass maps "254.2.1.10" as
    if it were an address; 240.0.0.0/4 (and 0/8, 127/8, 224/4) is a keep region, so it stays
    verbatim and the reader reverses it back. A /24 reverse zone (three octets) is not matched at
    all. Every internal address ending in .0, .127 or .224-.255 leaks this way.
    """
    out = _run({"event": {"original": text}})
    assert _found(re.escape(recoverable), out) == []


@pytest.mark.parametrize(
    ("source", "identifiers"),
    [
        pytest.param(
            {
                "kibana.alert.rule.parameters": {
                    "query": 'event.code:4625 and not host.name : "backup-srv-9" '
                    "and not user.name : syn-kim"
                }
            },
            ["backup-srv-9", "syn-kim"],
            id="kql-rule-query",
        ),
        pytest.param(
            {
                "kibana.alert.threshold_result": {
                    "terms": [
                        {"field": "user.name", "value": "syn-leo"},
                        {"field": "host.name", "value": "pc-leo-09"},
                    ],
                    "count": 31,
                }
            },
            ["syn-leo", "pc-leo-09"],
            id="threshold-terms",
        ),
    ],
)
def test_fxa07_identifier_values_carried_as_field_value_pairs_survive(
    source: dict[str, Any], identifiers: list[str]
) -> None:
    """DEFECT FXA-07: identifiers named by field in rule queries and threshold terms survive.

    ``not host.name : "backup-srv-9"`` in ``kibana.alert.rule.parameters.query`` and
    ``{"field": "user.name", "value": "syn-leo"}`` in ``kibana.alert.threshold_result.terms`` are
    host and user names by construction, but only the dictionary (filled from listed fields) can
    replace them. When the value appears only there, it survives and is not denylisted.
    """
    out = _run(source)
    for identifier in identifiers:
        assert _found(_word(identifier), out) == [], identifier


def test_fxa08_ldap_distinguished_name_keeps_the_campus_domain() -> None:
    """DEFECT FXA-08: an LDAP DN spells the campus domain as ``DC=`` components.

    ``CN=syn-amy,OU=Students,DC=campus,DC=ac,DC=in`` (Windows 4662/5136 events, certificate
    subjects) leaves ``DC=campus,DC=ac,DC=in`` verbatim: no detector knows the DN form.
    """
    out = _run(
        {"message": "Directory object modified: CN=syn-amy,OU=Students,DC=campus,DC=ac,DC=in"}
    )
    assert _found(r"DC=campus\s*,\s*DC=ac\s*,\s*DC=in", out) == []


@pytest.mark.parametrize(
    "text",
    [
        "Issuer: O=CAMPUS UNIVERSITY, C=IN",
        "SSID Campus-University-Guest associated",
        "Welcome to Campus  University",
        "Campus\nUniversity webmail",
    ],
)
def test_fxa09_policy_literal_variants_survive(text: str) -> None:
    """DEFECT FXA-09: literals are replaced only in their exact case and exact spacing.

    ``Campus University`` is replaced, but ``CAMPUS UNIVERSITY`` (certificate subjects),
    ``Campus-University`` (SSIDs, hostnames), a double space or a line break are not. The scanner
    matches long literals case-insensitively but with the literal's own single space, so the
    hyphen, double-space and newline forms pass it too.
    """
    out = _run({"message": text})
    assert _found(r"campus[\s_-]*university", out) == []


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        pytest.param(
            {"message": "GET https://campusu-backups.s3.vendor-cdn.example/db.tar.gz"},
            r"campusu",
            id="literal-in-kept-bucket-host",
        ),
        pytest.param(
            {"message": f"GET http://www.{CAMPUS}.vendor-cdn.example/index.html"},
            re.escape(CAMPUS),
            id="campus-cname-in-kept-url-host",
        ),
        pytest.param(
            {"dns": {"question": {"name": f"www.{CAMPUS}.vendor-cdn.example"}}},
            re.escape(CAMPUS),
            id="campus-cname-in-domain-field",
        ),
    ],
)
def test_fxa10_kept_vendor_domains_carry_campus_labels(
    source: dict[str, Any], pattern: str
) -> None:
    """DEFECT FXA-10: a kept vendor domain is copied verbatim with every label in front of it.

    ``DomainMapper.map`` returns any ``*.vendor-cdn.example`` name unchanged before it checks for
    a campus suffix, and URL hosts are spans that skip the literal pass. So a bucket host
    ``campusu-backups.s3.vendor-cdn.example`` keeps the literal and a CDN CNAME
    ``www.campus.ac.in.vendor-cdn.example`` keeps the campus domain (S3/GCS bucket and ELB names
    under amazonaws.com / googleapis.com are the real-world shape).
    """
    out = _run(source)
    assert _found(pattern, out) == []


@pytest.mark.parametrize(
    ("text", "pattern"),
    [
        pytest.param(
            "IP 10.1.2.3.52159 > 192.0.2.53.53: UDP, length 40",
            rf"{_ip('10.1.2.3')}|192\.0\.2\.53",
            id="bsd-addr-dot-port",
        ),
        pytest.param("src_10.1.2.3 dst_192.0.2.9", r"10\.1\.2\.3|192\.0\.2\.9", id="underscore"),
        pytest.param("saved capture_10.1.2.3.pcap", r"10\.1\.2\.3", id="filename"),
        pytest.param("peer a10.1.2.3 down", r"10\.1\.2\.3", id="hex-letter-glued"),
        pytest.param("host 010.001.002.003 up", r"0*10\.0*1\.0*2\.0*3", id="zero-padded"),
        pytest.param("ip-10-1-2-3.ec2.internal", r"10-1-2-3", id="dashed-hostname"),
    ],
)
def test_fxa11_other_ipv4_notations_survive(text: str, pattern: str) -> None:
    """DEFECT FXA-11: dotted quads that touch a word character or a ``.port`` are not addresses.

    ``_IPV4`` needs a non-word character before and no ``\\w`` / ``.digit`` after, and
    ``ipaddress`` rejects leading zeros: tcpdump/pf ``10.1.2.3.52159``, ``src_10.1.2.3``,
    ``capture_10.1.2.3.pcap``, ``010.001.002.003`` and the dashed host form survive. The scanner's
    address pattern has the same blind spots (``.5`` after, a hex letter before, padding).
    """
    out = _run({"event": {"original": text}})
    assert _found(pattern, out) == []


@pytest.mark.parametrize(
    ("source", "pattern"),
    [
        pytest.param(
            {"host": {"name": "lab-pc-07"}, "labels": {"lab-pc-07": "quarantined"}},
            _word("lab-pc-07"),
            id="host-as-key",
        ),
        pytest.param(
            {"stats": {"top_sources": {"10.1.2.3": 412, "192.0.2.9": 17}}},
            r"10\.1\.2\.3|192\.0\.2\.9",
            id="ips-as-keys",
        ),
    ],
)
def test_fxa12_identifiers_in_mapping_keys_survive(source: dict[str, Any], pattern: str) -> None:
    """DEFECT FXA-12: mapping keys are copied as they are and never harvested.

    ``_sanitize_node`` rebuilds every mapping with the original keys, and ``walk_strings`` only
    yields values, so an IP used as a key is not even in the leak denylist.
    """
    out = _run(source)
    assert _found(pattern, out) == []


def test_fxa13_fixture_file_name_carries_a_surviving_identifier() -> None:
    """DEFECT FXA-13: the committed file name inherits rule-name survivors, and slug hides them.

    ``cmd_samples`` names the file from the sanitized ``kibana.alert.rule.name``. A host named in
    another case survives sanitization (FXA-01) and ``slug`` turns ``LAB-PC-07`` into
    ``lab_pc_07``; ``cmd_verify`` scans ``p.name`` for ``lab-pc-07`` and cannot see it.
    """
    slug = _script_slug()
    out = _run(
        {
            "host": {"name": "lab-pc-07"},
            "kibana.alert.rule.name": "Beaconing from LAB-PC-07 to rare domain",
            "kibana.alert.rule.type": "query",
        }
    )
    name = f"{out['kibana.alert.rule.type']}__{slug(out['kibana.alert.rule.name'])}.json"
    skeleton = re.sub(r"[^a-z0-9]", "", name.lower())
    assert "labpc07" not in skeleton, name


def test_fxa14_email_field_with_display_name_keeps_the_name() -> None:
    """DEFECT FXA-14: an ``email`` field that is not a bare address keeps its display name.

    ``user.email: "Ivy Synthetic <ivy.s@campus.ac.in>"`` fails the full match and falls back to the
    text pass, which maps only the address; the person's name survives in a field the policy says
    is an identifier as a whole.
    """
    out = _run({"user": {"email": f"Ivy Synthetic <ivy.s@{CAMPUS}>"}})
    assert _found(r"Ivy Synthetic", out) == []


# ====================================================================== LOCK-INS

_SANITIZER = Sanitizer(POLICY, KEY)
_CONTEXTS = (
    "{ip}:443",
    "src={ip},dst=8.8.4.4",
    "({ip})",
    "[{ip}]",
    '"{ip}"',
    "'{ip}'",
    "reached {ip}.",
    "{ip}\tTCP_MISS/200",
    "http://{ip}:8080/x",
    "http://u-1:pw@{ip}/",
    "http://h.example/p/{ip}/x",
    "http://h.example/?ip={ip}&y=1",
    "https://h.example/#{ip}",
    "\\\\{ip}\\share",
    "::ffff:{ip}",
    "{ip}/32",
    "client {ip}#5353",
    "from {ip} port 22",
    "{ip}|{ip}",
    "<{ip}>",
)


@given(
    ip=st.one_of(
        st.ip_addresses(v=4, network="10.0.0.0/8"),
        st.ip_addresses(v=4, network="172.16.0.0/12"),
        st.ip_addresses(v=4, network="192.0.2.0/24"),
    ),
    context=st.sampled_from(_CONTEXTS),
)
def test_lockin_ipv4_in_delimited_contexts_never_survives(ip: Any, context: str) -> None:
    """LOCK-IN: internal and site IPv4 addresses delimited by punctuation, URLs or ports are mapped.

    Covers ports, trailing dots, brackets and quotes, URL host/userinfo/path/query/fragment, UNC
    paths, IPv4-mapped IPv6, /32 and DNS-log ``#port``. ``10.0.0.0`` after ``<letter>/`` is kept on
    purpose (the ``Chrome/154.0.0.0`` version exemption); it is the class network itself and
    identifies nothing, and no site or other class address has the ``N.0.0.0`` shape.
    """
    assume(not str(ip).endswith(".0.0.0"))
    text = context.format(ip=ip)
    out = _SANITIZER.map_text(text)
    assert re.search(_ip(str(ip)), out) is None, (text, out)


@pytest.mark.parametrize(
    ("text", "forbidden"),
    [
        ("::ffff:10.1.2.3", [r"10\.1\.2\.3"]),
        ("::FFFF:0A01:0203", [r"0a01:0203", r"10\.1\.2\.3"]),
        ("FD00:0000:0000:0000:0000:0000:0000:0001", [r"fd00:0+:0+:0+:0+:0+:0+:0*1"]),
        ("[fd00::1]:443", [r"fd00::1\b"]),
        ("fd00::1%eth0", [r"fd00::1%"]),
        ("::10.1.2.3", [r"10\.1\.2\.3"]),
        ("64:ff9b::10.1.2.3", [r"10\.1\.2\.3"]),
        ("::ffff:192.0.2.9", [r"192\.0\.2\.9"]),
    ],
)
def test_lockin_ipv6_forms_do_not_survive(text: str, forbidden: list[str]) -> None:
    """LOCK-IN: expanded, upper-case, bracketed, zoned and IPv4-embedding IPv6 forms are mapped."""
    out = _SANITIZER.map_text(f"addr {text} seen")
    for pattern in forbidden:
        assert re.search(pattern, out, re.IGNORECASE) is None, (text, out)


@pytest.mark.parametrize("cidr", ["192.0.2.0/23", "192.0.2.128/25", "192.0.2.77/24", "10.1.2.0/7"])
def test_lockin_region_spanning_cidrs_do_not_keep_their_address(cidr: str) -> None:
    """LOCK-IN: CIDRs that span regions or sit inside a site prefix never keep the site address."""
    out = _SANITIZER.map_text(f"allow {cidr} only")
    assert "192.0.2." not in out
    assert "10.1.2.0" not in out


@pytest.mark.parametrize(
    "text",
    [
        "LAB.CAMPUS.AC.IN.",
        "https://Lab.Campus.Ac.In:8443/x",
        "http://h.example/r?next=lab.campus.ac.in&x=1",
        "mail for bob@LAB.campus.ac.in",
        "\\\\fs1.campus.ac.in\\share",
        "10-1-2-3.campus.ac.in",
        "HOST/lab-pc-07.campus.ac.in@CAMPUS.AC.IN",
        "next=https%3A%2F%2Fwww.campus.ac.in%2F",
        "CAMPUS.AC.IN\\bob",
        "http:\\/\\/lab.campus.ac.in\\/x",
    ],
)
def test_lockin_campus_domain_forms_are_mapped(text: str) -> None:
    """LOCK-IN: campus names in any case, with trailing dots, in URLs, e-mails, UNC paths, SPNs,
    under an encoded subdomain and in JSON-escaped URLs are replaced."""
    out = _run({"message": text})
    assert _found(r"campus\.ac\.in|campus\.ac", out) == []


@pytest.mark.parametrize(
    "text",
    [
        "C:\\Users\\bob\\Desktop\\run.ps1 on lab-pc-07",
        "CAMPUSNB\\bob logged on to lab-pc-07$",
        "/home/bob/.ssh/authorized_keys",
        'user "bob" from "lab-pc-07"',
        "bob, lab-pc-07; bob.",
        "lab-pc-07.corp.example resolved",
        '{"user":"bob","host":"lab-pc-07"}',
        "http://h.example/~bob/?u=bob&h=lab-pc-07",
    ],
)
def test_lockin_same_case_identifiers_are_replaced_in_text(text: str) -> None:
    """LOCK-IN: a harvested host/user in its own case is replaced inside paths, quotes, JSON
    strings, URL paths and queries, with punctuation, a ``$`` suffix or a domain suffix."""
    out = _run({"host": {"name": "lab-pc-07"}, "user": {"name": "bob"}, "message": text})
    assert _found(_word("bob"), out, 0) == []
    assert _found(_word("lab-pc-07"), out, 0) == []


@pytest.mark.parametrize(
    "text",
    [
        "Alice+news@campus.ac.in",
        "ALICE@CAMPUS.AC.IN",
        "mailto:alice@campus.ac.in",
        "<alice@mail.campus.ac.in>",
        "from=<alice@other-uni.example>",
    ],
)
def test_lockin_email_variants_are_mapped(text: str) -> None:
    """LOCK-IN: plus tags, upper case, mailto: and angle brackets do not save an e-mail."""
    out = _run({"message": f"msg {text} queued"})
    assert _found(_word("alice"), out) == []
    assert _found(r"campus\.ac\.in|other-uni", out) == []


@pytest.mark.parametrize(
    "text",
    ["Campus University's portal", "(Campus University)", "campusu.", "campusu-net down"],
)
def test_lockin_literal_with_punctuation_is_replaced(text: str) -> None:
    """LOCK-IN: an exact-case literal is replaced next to punctuation and possessives."""
    out = _run({"message": text})
    assert _found(r"Campus University|campusu", out, 0) == []


def test_lockin_nested_lists_in_identifier_fields_are_mapped() -> None:
    """LOCK-IN: list items (at any depth) keep their parent's path and are mapped by kind."""
    out = _run(
        {
            "host": {"name": [["lab-pc-07"], "lab-pc-07"]},
            "related": {"user": ["bob", ["bob", ["bob"]]]},
        }
    )
    assert _found(_word("lab-pc-07"), out) == []
    assert _found(_word("bob"), out) == []
