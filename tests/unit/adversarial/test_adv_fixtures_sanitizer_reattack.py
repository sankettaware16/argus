"""Adversarial re-attack on R2's sanitizer v2 (SANITIZER_VERSION 2.0.0, D-041) after fix round 1.

Lens FXE: the rules D-041 added (case folding, kind priority, keep names, short numbers, the
host-like first label, qualified values, mapping keys, ``{field, value}`` objects, ``field: value``
pairs, reverse DNS, LDAP DNs, dashed / padded IPv4, URL-encoded boundaries, e-mail forms, home
directories) and their edges, attacked for leaks (an original survives), integrity (one original,
one pseudonym, whatever the context or order), robustness (anything but the documented
``IPMapError`` for site-space addresses) and fidelity (structure, timestamps, versions, payloads,
rule queries).

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests pass
today and pin behaviour that held up under attack. Every identifier here is synthetic
(documentation and private address ranges, ``campus.ac.in``-style names, key ``b"k" * 32``); the
only repository file read is the tracked policy ``config/fixtures.yaml`` (its field list).
"""

from __future__ import annotations

import ipaddress
import random
import re
import string
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.fixtures import FixturePolicy, IPMapError, LeakScanner, Sanitizer, load_policy

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
        "place": ("source.site.department",),
        "org": ("observer.dept",),
        "domain": ("url.domain", "dns.question.name"),
        "id": ("_id", "event.id"),
    },
)
# The tracked policy's identifier fields (the real list, so "covered by a pattern" is real too).
SHIPPED = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    campus_domains=(CAMPUS,),
    fields=dict(load_policy(REPO / "config" / "fixtures.yaml")[0].fields),
)


def _sanitizer(*docs: Any, policy: FixturePolicy = POLICY) -> Sanitizer:
    s = Sanitizer(policy, KEY)
    s.harvest(list(docs))
    return s


def _run(*docs: Any, policy: FixturePolicy = POLICY) -> list[Any]:
    """Harvest every document, then sanitize every document."""
    s = _sanitizer(*docs, policy=policy)
    return [s.sanitize(d) for d in docs]


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


# ====================================================================== DEFECTS: integrity


def test_fxe01_two_letter_code_follows_harvest_order() -> None:
    """DEFECT FXE-01 (HIGH): the FXD-01 fix stops at three characters.

    Kind priority is applied to ``_candidates`` only. A 2-character name goes to ``_short`` with
    ``setdefault``, so the first kind harvested wins. Department codes are exactly that shape:
    ``observer.dept: CC`` (org) and ``source.site.department: CC`` (place) make the text
    ``... in CC`` read ``org-...`` or ``pl-...`` depending on document order. That is the
    FXD-01 example itself, now for 2-letter codes. Fix: keep ``{kind: pseudonym}`` for short names
    too and pick by ``_NAME_KINDS`` in ``_rebuild``.
    """
    as_org = {"observer": {"dept": "CC"}}
    as_place = {"source": {"site": {"department": "CC"}}}
    text = {"message": "Beaconing from a host in CC (block 4)"}
    first = _sanitizer(as_org, as_place, text).sanitize(text)
    second = _sanitizer(as_place, as_org, text).sanitize(text)
    assert first == second


@pytest.mark.parametrize(
    ("source", "field", "text_index"),
    [
        pytest.param(
            {
                "dns": {"question": {"name": "7.2.1.10.in-addr.arpa"}},
                "message": "query[PTR] 7.2.1.10.in-addr.arpa from 10.9.8.7",
            },
            ("dns", "question", "name"),
            1,
            id="reverse-name-in-dns-question-name",
        ),
        pytest.param(
            {"host": {"name": "ip-10-1-2-3"}, "message": "ip-10-1-2-3 joined the domain"},
            ("host", "name"),
            0,
            id="dashed-ip-host-name",
        ),
        pytest.param(
            {"host": {"name": "010.001.002.003"}, "message": "010.001.002.003 joined the domain"},
            ("host", "name"),
            0,
            id="zero-padded-ip-host-name",
        ),
    ],
)
def test_fxe08_ip_shaped_field_values_skip_the_ip_detectors(
    source: dict[str, Any], field: tuple[str, ...], text_index: int
) -> None:
    """DEFECT FXE-08 (MEDIUM): an IP-shaped host or domain field value is mapped label by label.

    ``_map_field`` checks ``_as_ip``, then ``domains.map``. The reverse, dashed and padded forms
    are handled only by the text detectors. So ``dns.question.name: 7.2.1.10.in-addr.arpa`` (a
    PTR query in the DNS logs) becomes ``<tok>.<tok>.<tok>.<tok>.<tok>.arpa``, while the same name
    in the message becomes ``<mapped reverse>.in-addr.arpa``. One original gets two pseudonyms,
    and the field no longer looks like a PTR name. ``ip-10-1-2-3`` and ``010.001.002.003`` in
    ``host.name`` likewise disagree with their text forms; the padded one keeps its last octet
    verbatim. Fix: in ``_map_field``, for host and domain kinds, try the reverse, dashed and padded
    IPv4 forms (full match) before ``domains.map``.
    """
    (out,) = _run(source)
    value: Any = out
    for part in field:
        value = value[part]
    assert value == out["message"].split()[text_index]


# ====================================================================== DEFECTS: leaks


@pytest.mark.parametrize(
    ("docs", "identifier"),
    [
        pytest.param(
            [{"user": {"name": "syn-alice"}}, {"url": {"original": "/search?q=ask%20syn-alice"}}],
            "syn-alice",
            id="user-after-encoded-space",
        ),
        pytest.param(
            [
                {"user": {"name": "syn-alice"}},
                {"url": {"original": "/api?filter=%7B%22user%22%3A%22syn-alice%22%7D"}},
            ],
            "syn-alice",
            id="user-in-url-encoded-json",
        ),
        pytest.param(
            [{"host": {"name": "lab-pc-07"}}, {"url": {"original": "/smb?path=%2Flab-pc-07%2Fc"}}],
            "lab-pc-07",
            id="host-after-encoded-slash",
        ),
        pytest.param(
            [{"url": {"original": "/search?q=about%20campusu%20hostel"}}],
            "campusu",
            id="policy-literal-after-encoded-space",
        ),
    ],
)
def test_fxe02_names_after_a_percent_escape_survive(docs: list[Any], identifier: str) -> None:
    """DEFECT FXE-02 (MEDIUM): the dictionary and literal passes have no ``%XX`` boundary.

    D-041 gave the URL, e-mail, IPv6 and domain detectors a ``(?<=%XX)`` start. The dictionary
    regex starts at ``(?<![\\w.-])`` and the literal regex at ``(?<![A-Za-z0-9])``, and the hex
    digit of ``%20``/``%22``/``%2F`` is a word character. So a harvested name or a policy literal
    right after an escape survives: ``q=ask%20syn-alice``, ``%22syn-alice%22``,
    ``%2Flab-pc-07``, ``q=about%20campusu``. Squid URLs are full of these. The scanner's
    URL-decoded view catches them, so ``samples`` refuses the fixture rather than leaking it.
    Fix: add the ``_PCT`` alternative to the left boundary of ``_dict_re`` and
    ``_Literals.pattern``.
    """
    outs = _run(*docs)
    assert _found(re.escape(identifier), outs) == []


@pytest.mark.parametrize(
    ("text", "address"),
    [
        pytest.param("/ping?target=%2210.1.2.99%22", "10.1.2.99", id="json-quoted"),
        pytest.param("/tools?cmd=ping%2010.1.2.98", "10.1.2.98", id="encoded-space"),
        pytest.param("/q?expr=host%2810.1.2.97%29", "10.1.2.97", id="encoded-paren"),
    ],
)
def test_fxe03_ipv4_after_a_digit_ending_escape_survives(text: str, address: str) -> None:
    """DEFECT FXE-03 (MEDIUM): ``_IPV4`` has no ``%XX`` start, unlike ``_IPV6``.

    Its left boundary is ``(?<![0-9.])``. After ``%20``, ``%22``, ``%27``, ``%28`` or ``%29`` (the
    escapes of space, quotes and parentheses end in a digit), ``2210.1.2.99`` has no start that
    parses, so the address is neither mapped nor harvested. Because it is not harvested, the leak
    scanner's denylist misses it. A class address (10/8, 172.16/12, 192.168/16) is reported only
    if denylisted, so this leak is silent. Fix: ``(?:(?<![0-9.])|(?<=%[0-9A-Fa-f]{2}))`` as
    ``_IPV4``'s left boundary (harvest uses the same regex).
    """
    (out,) = _run({"url": {"original": text}})
    assert _found(re.escape(address) + r"(?![0-9])", out) == []


@pytest.mark.parametrize(
    ("source", "identifier"),
    [
        pytest.param(
            {
                "kibana.alert.rule.parameters": {
                    "filters": [
                        {
                            "meta": {
                                "key": "host.name",
                                "negate": True,
                                "type": "phrase",
                                "params": {"query": "vuln-scan-01"},
                            },
                            "query": {"match_phrase": {"host.name": "vuln-scan-01"}},
                        }
                    ]
                }
            },
            "vuln-scan-01",
            id="kibana-filter-pill-in-rule-parameters",
        ),
        pytest.param(
            {"request": {"query": {"bool": {"filter": [{"term": {"host.name": "lab-pc-07"}}]}}}},
            "lab-pc-07",
            id="term-query-in-recorded-request",
        ),
        pytest.param(
            {"request": {"query": {"term": {"user.name.keyword": "syn-bob"}}}},
            "syn-bob",
            id="keyword-subfield",
        ),
    ],
)
def test_fxe04_values_keyed_by_a_field_name_in_query_dsl_survive(
    source: dict[str, Any], identifier: str
) -> None:
    """DEFECT FXE-04 (MEDIUM): Query DSL and Kibana filters name the field as a mapping key.

    The alert documents carry ``kibana.alert.rule.parameters.filters``, the filter pills of the
    rule, for example an exclusion ``NOT host.name: vuln-scan-01``. Each pill holds the host as
    ``query.match_phrase["host.name"]`` and as ``meta.params.query`` (with ``meta.key``). R4
    cassettes will record ``term``/``terms`` bodies the same way. These paths end in
    ``...match_phrase.host.name``, which no shipped field or pattern covers. (``*.user.name``
    covers the user by luck, but not ``user.name.keyword``.) The value is neither mapped nor
    harvested, so the scanner is silent; an excluded host is typically seen nowhere else. Fix:
    treat a mapping key that is an identifier field path, or that path plus ``.keyword``, like
    ``{field, value}``: its string, list items or ``{query: v}`` take that kind. Also map
    ``meta.params.query``, ``meta.params[]`` and ``meta.value`` by the kind of ``meta.key``.
    """
    (out,) = _run(source, policy=SHIPPED)
    assert _found(_word(identifier), out) == []


@pytest.mark.parametrize(
    "query",
    [
        'event.code:4625 and not host.name : ("lab-pc-07" or "lab-pc-08")',
        "host.name:(lab-pc-07 OR lab-pc-08)",
        'FROM logs-* | WHERE host.name IN ("lab-pc-07", "lab-pc-08") | LIMIT 10',
        'process where host.name in ("lab-pc-07", "lab-pc-08")',
    ],
    ids=["kql-list", "lucene-list", "esql-in", "eql-in"],
)
def test_fxe05_value_lists_in_rule_queries_survive(query: str) -> None:
    """DEFECT FXE-05 (MEDIUM): ``_pair_re`` takes one value; lists are not parsed.

    The pair's value alternative excludes ``(``, and ``IN``/``in`` is not an operator. So KQL
    ``host.name : ("a" or "b")``, Lucene ``host.name:(a OR b)``, and ES|QL and EQL
    ``host.name IN ("a", "b")`` keep every host, and none is harvested (the scanner is silent).
    The corpus has query, ES|QL and EQL rules, and exception-style lists are the usual way to
    exclude several hosts. Fix: after the operator (with ``(?i:\\s+in\\s+)`` added), accept a
    parenthesised list and map each quoted or bare item that is not ``or``/``and``/``not``, by
    the field's kind.
    """
    (out,) = _run({"kibana.alert.rule.parameters": {"query": query}})
    assert _found(_word("lab-pc-07"), out) == []
    assert _found(_word("lab-pc-08"), out) == []


@pytest.mark.parametrize(
    "response",
    [
        pytest.param(
            {
                "hits": {
                    "hits": [
                        {
                            "_index": "logs-synthetic-000001",
                            "_id": "AbCdEfGhIjKlMnOpQrSt",
                            "_source": {"@timestamp": "2026-10-12T00:00:00Z"},
                            "fields": {"host.name": ["lab-pc-07"]},
                        }
                    ]
                }
            },
            id="nested-hit-fields",
        ),
        pytest.param(
            {
                "request": {"size": 0, "aggs": {"by_host": {"terms": {"field": "host.name"}}}},
                "response": {
                    "aggregations": {"by_host": {"buckets": [{"key": "lab-pc-07", "doc_count": 4}]}}
                },
            },
            id="terms-aggregation-bucket",
        ),
    ],
)
def test_fxe06_identifiers_outside_source_in_search_responses_survive(
    response: dict[str, Any],
) -> None:
    """DEFECT FXE-06 (MEDIUM): only ``_source`` paths are recognised in a search response.

    A nested hit's ``fields`` (dotted field names as keys) is neither dropped
    (``drop_top_level`` applies to the top-level wrapper only) nor read as field paths. Its path
    is ``hits.hits.fields.host.name``. Bucket ``key`` values of a ``terms`` aggregation have no
    kind at all. A ``size: 0`` aggregation cassette (R4 "heavy" templates) holds hosts only
    there. They are never harvested, so they survive and the scanner is silent. Fix: read the
    ``fields`` (and ``highlight``) of any mapping that has ``_id``/``_index`` like ``_source``
    (key = field path). Map ``aggregations.<name>.buckets[].key`` by the kind of the recorded
    request's ``aggs.<name>.terms.field``, and refuse an aggregation response whose field is
    unknown.
    """
    (out,) = _run(response, policy=SHIPPED)
    assert _found(_word("lab-pc-07"), out) == []


def test_fxe10_plus_tagged_email_hides_the_account() -> None:
    """DEFECT FXE-10 (LOW): ``alice+tag@...`` registers ``alice+tag`` as the account.

    ``_harvest_email`` registers the whole local part as the user. The account a postfix log
    names elsewhere (``sasl_username=syn-alice``) is never harvested, so it survives, and the
    scanner is silent (it knows only ``syn-alice+lists``). Fix: also register the local part
    before the first ``+`` as a user. Map ``local+tag`` as ``<user(local)>+<token(tag)>``.
    """
    outs = _run(
        {"message": "postfix/smtp: to=<syn-alice+lists@campus.ac.in>, status=sent"},
        {"message": "postfix/smtpd: client=unknown, sasl_username=syn-alice"},
    )
    assert _found(_word("syn-alice"), outs) == []


def test_fxe11_upper_case_short_name_in_a_compound_is_missed_by_both_layers() -> None:
    """DEFECT FXE-11 (MEDIUM): the safety net D-041 relies on has a hole for 3- and 4-letter names.

    The sanitizer leaves names inside compound tokens alone (``RAVI-PC``, ``RAVI_LAPTOP``: the
    FXD-04 rule). D-041 counts on the looser scanner for these glued forms. But the scanner
    matches names under 5 characters without a digit, ``.`` or ``-`` in exact case only. The
    sanitizer folds case from 3 characters. So user ``ravi`` in a DHCP/DNS host label
    ``RAVI-PC`` passes both layers silently. Fix: in ``LeakScanner``, keep exact case only for
    names of at most 2 characters (the sanitizer's ``_SHORT_EXACT``) and fold the rest.
    """
    s = _sanitizer({"user": {"name": "ravi"}})
    out = s.sanitize({"message": "dhcp: DHCPACK 10.9.8.7 to RAVI-PC"})["message"]
    scanner = LeakScanner(s.harvested)
    assert "ravi" not in out.lower() or scanner.scan_text(out) != [], out


def test_fxe12_wildcard_value_hides_an_identifier() -> None:
    """DEFECT FXE-12 (LOW): a wildcard value's literal part is neither mapped nor harvested.

    D-041 leaves KQL wildcard values alone (so ``destination.domain:*`` is not tokenised). But
    ``not user.name : svc-backup-07*`` names an account, and an account that appears only in a
    rule exclusion survives silently. Fix: for a wildcard value, map the literal fragments that
    look like names (4+ characters with a digit, ``-`` or ``_``) by the field's kind and keep the
    wildcards. At least harvest them, so the scanner fails loudly.
    """
    (out,) = _run({"kibana.alert.rule.parameters": {"query": "not user.name : svc-backup-07*"}})
    assert _found(_word("svc-backup-07"), out) == []


def test_fxe15_shorter_exact_entry_preempts_a_longer_name() -> None:
    """DEFECT FXE-15 (LOW): the dictionary regex tries every exact entry before any folded one.

    ``_rebuild`` builds ``(?:(?-i:<ids and 2-char names>)|(?i:<names>))``. A short exact entry
    therefore wins over a longer folded name at the same position whenever its right boundary
    holds, and ``.`` is a valid right boundary. With users ``li`` and ``li.wei``, the text
    ``li.wei`` becomes ``u-<li>.wei``: the second half of the name survives, and nothing
    denylists ``wei``. Fix: one alternation ordered by length over both groups (each entry in
    its own ``(?-i:)``/``(?i:)``), or a longest-first set lookup.
    """
    outs = _run({"user": {"name": "li"}}, {"user": {"name": "li.wei"}}, {"message": "by li.wei"})
    assert _found(_word("wei"), outs[2]) == []


def test_fxe16_dotted_capital_i_name_survives_case_folding() -> None:
    """DEFECT FXE-16 (LOW): the folded dictionary is built from ``raw.lower()``.

    ``"İrem".lower()`` is ``"i̇rem"`` (5 code points). ``re``'s ``(?i)`` compares single
    characters, so the pattern never matches the original spelling, and the very string from
    ``user.name`` survives in the message. The scanner's odd-name regex catches it, so this fails
    loudly. Fix: build the ``(?i:...)`` alternatives from the original spellings (one per folded
    key) and look the match up by ``casefold()``.
    """
    (out,) = _run({"user": {"name": "İrem"}, "message": "session opened for İrem"})
    assert "İrem" not in out["message"]


def test_fxe17_field_shaped_key_keeps_a_host_name() -> None:
    """DEFECT FXE-17 (LOW): a lower-case host name used as a key is never renamed.

    ``_map_key`` renames a whole harvested name only when the key does not look like a field
    name (``[a-z0-9_@.]+``), which protects ``meta`` from a department called META (FXL-03). Host
    ``kiosk7`` therefore survives as ``labels.kiosk7``; the scanner reads keys, so this fails
    loudly. Fix: rename a field-shaped key when it is a harvested host, user or e-mail name
    (never place/org, which caused FXL-03) and not a segment of any policy field path.
    """
    (_, out) = _run({"host": {"name": "kiosk7"}}, {"labels": {"kiosk7": "quarantined"}})
    assert "kiosk7" not in out["labels"]


# ====================================================================== DEFECTS: fidelity


def test_fxe07_threat_mapping_value_is_tokenised_as_a_domain() -> None:
    """DEFECT FXE-07 (MEDIUM): a threat-match mapping entry is read as a ``{field, value}`` pair.

    Indicator-match rules (in the corpus) store
    ``threat_mapping[].entries[] = {field: destination.domain, type: mapping,
    value: threat.indicator.url.domain}``: ``value`` is the indicator FIELD. The pair rule maps
    it as a domain, giving ``<tok>.<tok>.<tok>.domain``, and harvests it. The dictionary then
    rewrites the field name in the rule's note and query text too. Fix: skip the pair override
    when the mapping has ``type: mapping``, or when ``value`` is a dotted field path.
    """
    note = "Matches destination.domain against threat.indicator.url.domain."
    entry = {
        "field": "destination.domain",
        "type": "mapping",
        "value": "threat.indicator.url.domain",
    }
    doc = {"kibana.alert.rule.parameters": {"threat_mapping": [{"entries": [entry]}], "note": note}}
    (out,) = _run(doc, policy=SHIPPED)
    params = out["kibana.alert.rule.parameters"]
    assert params["threat_mapping"][0]["entries"][0]["value"] == "threat.indicator.url.domain"
    assert params["note"] == note


@pytest.mark.parametrize(
    ("source", "path", "expected"),
    [
        pytest.param(
            {"event": {"id": "1"}, "http": {"version": "1.1"}},
            ("http", "version"),
            "1.1",
            id="short-event-id-rewrites-http-version",
        ),
        pytest.param(
            {"url": {"original": "/api/item?_id=7"}, "message": "took 7 ms at 10:07:7"},
            ("message",),
            "took 7 ms at 10:07:7",
            id="id-pair-in-a-url-rewrites-numbers",
        ),
    ],
)
def test_fxe09_short_ids_rewrite_numbers_everywhere(
    source: dict[str, Any], path: tuple[str, ...], expected: str
) -> None:
    """DEFECT FXE-09 (MEDIUM): ids enter the exact dictionary without the short-number filter.

    The FXD-05 fix (``_dictionary_worthy``) covers names only. An id of any length goes to
    ``self.ids``, and from there into every free-text gap. ``event.id: "1"`` turns
    ``http.version: 1.1`` into ``7.1`` and byte counts ``1`` into ``7``. The text pair
    ``_id=7`` in any URL (``_id`` is a policy path, so ``_pair_re`` harvests it) is enough: one
    attacker-controlled query string in the nginx/squid logs rewrites every standalone ``7``,
    ports and timestamp fields included, in every fixture. Fix: apply ``_dictionary_worthy``
    (and a minimum length) to ids before they enter ``self.ids``. Id fields and pair spans stay
    mapped.
    """
    (out,) = _run(source)
    value: Any = out
    for part in path:
        value = value[part]
    assert value == expected


@pytest.mark.parametrize(
    ("docs", "check"),
    [
        pytest.param(
            [
                {"dns": {"question": {"name": "www.campus.ac.in"}}},
                {"url": {"original": "/go?to=%20www.campus.ac.in"}},
            ],
            "space-escape-and-label",
            id="domain-after-encoded-space",
        ),
        pytest.param(
            [{"url": {"original": "/authorize?login_hint=syn-alice%40campus.ac.in&p=1"}}],
            "at-escape",
            id="email-with-encoded-at",
        ),
    ],
)
def test_fxe13_url_encoding_is_destroyed_around_mapped_spans(docs: list[Any], check: str) -> None:
    """DEFECT FXE-13 (LOW): spans next to ``%XX`` escapes damage the encoding.

    ``_domain_re``'s ``(?<![\\w.-])`` start also succeeds right after ``%``, so in
    ``%20www.campus.ac.in`` the label is ``20www``. The output is ``%<token(20www)>.univ.example``:
    the escape is gone (``%`` followed by a base32 token can even form a new escape), and ``www``
    gets a pseudonym different from the same host in ``dns.question.name``. ``_map_email``
    always writes ``@``, so ``syn-alice%40campus.ac.in`` comes out with a raw ``@`` in the query
    string. Fix: forbid a start right after ``%`` or ``%X``, and keep the matched ``@``/``%40``.
    """
    outs = _run(*docs)
    if check == "space-escape-and-label":
        field = outs[0]["dns"]["question"]["name"]
        assert outs[1]["url"]["original"] == f"/go?to=%20{field}"
    else:
        assert "%40" in outs[0]["url"]["original"]


@pytest.mark.parametrize(
    "text",
    [
        "NT AUTHORITY\\SYSTEM",
        "NT AUTHORITY\\NETWORK SERVICE",
    ],
)
def test_fxe18_well_known_windows_realm_is_tokenised(text: str) -> None:
    """DEFECT FXE-18 (LOW): a ``DOMAIN\\user`` realm bypasses ``keep_names``.

    ``_map_field`` and ``_harvest_field`` give the realm ``domains.label(realm)`` without the
    keep check that the account gets. ``NT AUTHORITY\\SYSTEM``, the commonest principal in
    Windows security logs, becomes ``<token>\\SYSTEM``, and ``NT AUTHORITY`` enters the
    dictionary, so it is tokenised in every message. Detection fixtures for later Windows sources
    then lose the principal their rules key on. Fix: check realms against ``keep_names``, and add
    the well-known authorities (``NT AUTHORITY``, ``BUILTIN``, ``NT SERVICE``, ``WORKGROUP``,
    ``Window Manager``, ``Font Driver Host``) to ``DEFAULT_KEEP_NAMES``.
    """
    (out,) = _run({"user": {"name": text}, "message": f"Subject: {text}"})
    assert out["user"]["name"].startswith("NT AUTHORITY\\")
    assert "NT AUTHORITY" in out["message"]


# ====================================================================== DEFECTS: robustness


@pytest.mark.parametrize(
    "text",
    [
        "client 10.9.8.7#5353: query: 07.2.1.10.in-addr.arpa IN PTR",
        "GET /lookup?q=३.२.१.१०.in-addr.arpa HTTP/1.1",
    ],
    ids=["zero-padded-octet", "devanagari-digits"],
)
def test_fxe14_reverse_name_with_odd_octets_crashes_harvest(text: str) -> None:
    """DEFECT FXE-14 (LOW): ``_map_reverse_v4`` passes raw octets to ``IPv4Address``.

    For a 4-octet name it joins the matched octets unchanged. ``07`` (leading zero) and the
    Devanagari digits that ``\\d`` matches make ``IPv4Address`` raise ``AddressValueError``,
    not the documented ``IPMapError``. Any URL or DNS query carrying such a name (attacker
    controlled) stops ``harvest``, and with it the whole fixture build. Fix: normalise with
    ``str(int(o))`` after an ``isascii()`` check, as ``_parse_v4`` does, and use ``[0-9]``
    instead of ``\\d`` in the IPv4-shaped detectors.
    """
    s = Sanitizer(POLICY, KEY)
    doc = {"message": text}
    try:
        s.harvest([doc])
        out = s.sanitize(doc)
    except IPMapError:  # pragma: no cover - the documented refusal would be acceptable
        raise
    except ValueError as exc:
        pytest.fail(f"{type(exc).__name__}: {exc}")
    assert "2.1.10.in-addr" not in out["message"]


def test_fxe19_dictionary_pass_is_linear_in_dictionary_size() -> None:
    """DEFECT FXE-19 (LOW): the dictionary is one regex alternation, O(text * entries).

    FXB-02 replaced the scanner's alternation with set lookups, and the sanitizer kept its own.
    With about 30,000 entries (15k ids and 15k host names; the real denylist has 39,468
    identifiers), 100 kB of ordinary text takes about 7 s through ``map_text``, about 70 s per MB.
    That is fine for today's eight small fixtures, but not for R4 cassettes or golden dossiers.
    Fix: tokenize at the dictionary boundaries and look candidate spans up longest-first in
    ``ids``/``_short``/``dictionary``, as the scanner's word index does.
    """
    rnd = random.Random(7)
    ids = ["".join(rnd.choices(string.ascii_letters + string.digits, k=20)) for _ in range(15_000)]
    hosts = [f"{''.join(rnd.choices(string.ascii_lowercase, k=4))}-{i:05d}" for i in range(15_000)]
    s = _sanitizer({"event": {"id": ids}, "host": {"name": hosts}})
    text = ("GET /a/b?c=d " * 8_000)[:100_000]
    start = time.perf_counter()
    s.map_text(text)
    assert time.perf_counter() - start < 3.0


# ====================================================================== LOCK-INS


hosts = st.sampled_from(["kali", "lab-pc-07", "web01"])
codes = st.sampled_from(["CSE", "Hostel-12", "kali"])


@st.composite
def _multi_kind_doc(draw: st.DrawFn) -> dict[str, Any]:
    """Values of 3+ characters under several kinds (user and host; org and place)."""
    name, code = draw(hosts), draw(codes)
    return draw(
        st.sampled_from(
            [
                {"user": {"name": name}, "message": f"{name} on {code}"},
                {"host": {"name": name}, "labels": {name.upper(): code}},
                {"observer": {"dept": code}, "message": f"{code.upper()} {name}"},
                {"source": {"site": {"department": code}}, "related": {"user": [name]}},
            ]
        )
    )


@given(st.lists(_multi_kind_doc(), min_size=1, max_size=6), st.randoms(use_true_random=False))
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_lockin_order_and_duplicates_do_not_matter_from_three_characters(
    docs: list[dict[str, Any]], rnd: Any
) -> None:
    """LOCK-IN: for names of 3+ characters under several kinds (``kali`` user/host, ``CSE``
    org/place), shuffling, duplicating or splitting the harvest never changes any output (the
    FXD-01 fix and the harvest dedup cache hold)."""
    shuffled = list(docs)
    rnd.shuffle(shuffled)
    one = _sanitizer(*docs)
    other = _sanitizer(*shuffled, *docs)
    split = Sanitizer(POLICY, KEY)
    for doc in reversed(docs):
        split.harvest([doc])
    expected = [one.sanitize(d) for d in docs]
    assert [other.sanitize(d) for d in docs] == expected
    assert [split.sanitize(d) for d in docs] == expected
    assert one.harvested == other.harvested == split.harvested


def test_lockin_one_ipv4_gets_one_pseudonym_in_every_text_form() -> None:
    """LOCK-IN: field, plain, dashed, zero-padded, ``addr.port``, bracketed, IPv4-mapped, reverse
    name, partial reverse zone, ``user@IP``, URL host and mapping key all agree."""
    s = _sanitizer({"source": {"ip": "10.1.2.3"}})
    m = s.ips.map_text("10.1.2.3")
    octets = m.split(".")
    cases = {
        "10.1.2.3": m,
        "ip-10-1-2-3.lab": f"ip-{m.replace('.', '-')}.lab",
        "010.001.002.003": ".".join(o.zfill(3) for o in octets),
        "10.1.2.3.52159 >": f"{m}.52159 >",
        "[10.1.2.3]:443": f"[{m}]:443",
        "::ffff:10.1.2.3": f"::ffff:{m}",
        "3.2.1.10.IN-ADDR.ARPA.": ".".join(reversed(octets)) + ".IN-ADDR.ARPA.",
        "2.1.10.in-addr.arpa": ".".join(reversed(octets[:3])) + ".in-addr.arpa",
        "root@10.1.2.3": f"root@{m}",
        "http://10.1.2.3:8080/x": f"http://{m}:8080/x",
    }
    for text, expected in cases.items():
        assert s.map_text(text) == expected, text
    assert s.sanitize({"source": {"ip": "10.1.2.3"}}) == {"source": {"ip": m}}
    assert s.sanitize({"top": {"10.1.2.3": 4}}) == {"top": {m: 4}}


def test_lockin_one_host_gets_one_pseudonym_in_every_context() -> None:
    """LOCK-IN: a host in its field, in another case, as NetBIOS ``$``, as a URL host with port,
    as the first label of a campus FQDN, in an ES|QL ``==`` pair, in a ``{field, value}`` object
    and as a non-field-shaped key gets one label token."""
    s = _sanitizer({"host": {"name": "lab-pc-07"}})
    token = s.sanitize({"host": {"name": "lab-pc-07"}})["host"]["name"]
    assert s.sanitize({"observer": {"hostname": "LAB-PC-07"}}) == {"observer": {"hostname": token}}
    assert s.map_text("LAB-PC-07$ logon") == f"{token}$ logon"
    assert s.map_text("http://Lab-Pc-07:8080/") == f"http://{token}:8080/"
    assert s.map_text("lab-pc-07.campus.ac.in") == f"{token}.univ.example"
    esql = 'FROM logs | WHERE host.name == "LAB-PC-07"'
    assert s.map_text(esql) == f'FROM logs | WHERE host.name == "{token}"'
    pair = {"terms": [{"field": "host.name", "value": "Lab-PC-07"}]}
    assert s.sanitize(pair) == {"terms": [{"field": "host.name", "value": token}]}
    assert s.sanitize({"labels": {"LAB-PC-07": 1}}) == {"labels": {token: 1}}


def test_lockin_reverse_zones_agree_with_their_addresses() -> None:
    """LOCK-IN: IPv6 reverse names of any nibble count (9, 10, 31, 32) and IPv4 zones of 1-3
    octets map to prefixes of the mapped address; the class prefix is kept and nothing leaks."""
    s = Sanitizer(POLICY, KEY)
    v6 = ipaddress.IPv6Address("fd12:3456:789a:bcde:f012:3456:789a:bcd1")
    mapped6 = f"{int(s.ips.map_address(v6)):032x}"
    nibbles = f"{int(v6):032x}"
    for count in (9, 10, 31, 32):
        name = ".".join(reversed(nibbles[:count])) + ".ip6.arpa"
        assert s.map_text(name) == ".".join(reversed(mapped6[:count])) + ".ip6.arpa", count
    assert mapped6[:2] in ("fc", "fd")
    assert mapped6[2:10] != nibbles[2:10]
    m = s.ips.map_text("10.1.2.3").split(".")
    assert s.map_text("1.10.in-addr.arpa") == f"{m[1]}.10.in-addr.arpa"
    assert s.map_text("10.in-addr.arpa") == "10.in-addr.arpa"


def test_lockin_keep_names_never_shelter_a_lookalike() -> None:
    """LOCK-IN: ``Root``/``ROOT`` stay verbatim and are never denylisted, while lookalikes that are
    not keep names (``admin2``, ``rootkit``) are mapped in fields and in text."""
    s = _sanitizer({"user": {"name": ["Root", "ROOT", "admin2", "rootkit"]}})
    assert {"Root", "ROOT"}.isdisjoint(s.harvested)
    assert {"admin2", "rootkit"} <= s.harvested
    out = s.sanitize({"user": {"name": ["Root", "admin2"]}, "message": "root ROOT admin2 rootkit"})
    assert out["user"]["name"][0] == "Root"
    assert out["message"].startswith("root ROOT u-")
    assert _found(_word("admin2"), out) == []
    assert _found(_word("rootkit"), out) == []


@pytest.mark.parametrize(
    ("text", "forbidden"),
    [
        ("base dc=campus,dc=ac,dc=in", r"dc=campus"),
        ("DC=campus , DC=ac,DC=in", r"DC=campus"),
        ("login_hint=syn-alice%40campus.ac.in&x=1", r"syn-alice|campus\.ac\.in"),
        ("https%3a%2f%2fsyn-bob%40wiki.campus.ac.in%2f", r"syn-bob|campus\.ac\.in"),
        ("mailto:Syn-Alice@Campus.AC.IN", r"syn-alice|campus\.ac\.in"),
        ("_ldap._tcp.dc._msdcs.CAMPUS.AC.IN", r"campus\.ac\.in"),
    ],
)
def test_lockin_ldap_encoded_and_email_forms_do_not_leak(text: str, forbidden: str) -> None:
    """LOCK-IN: lower-case and spaced ``dc=`` DNs, ``%40`` e-mails, lower-case ``%3a%2f%2f`` URL
    users, mixed-case ``mailto:`` and upper-case SRV names are all mapped."""
    s = Sanitizer(POLICY, KEY)
    s.harvest([{"message": text}])
    assert _found(forbidden, s.sanitize({"message": text})) == []


def test_lockin_structure_and_non_identifiers_survive() -> None:
    """LOCK-IN: an alert-shaped document keeps every key, every list length and every
    non-identifier: timestamps, ports, MITRE ids, versions, attack payloads, rule wildcards."""
    doc = {
        "@timestamp": "2026-10-12T10:07:01.123Z",
        "kibana.alert.rule.threat": [
            {"technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}]}
        ],
        "kibana.alert.rule.parameters": {"query": "destination.domain:* and destination.port:443"},
        "user_agent": {
            "original": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        },
        "url": {"original": "/index.php?id=1' OR '1'='1 -- <script>alert(1)</script>"},
        "http": {"version": "1.1", "response": {"status_code": 200}},
        "event": {"duration": 1_500_000, "category": ["network", "web"]},
        "squid": {"elapsed": "153", "hierarchy": "HIER_DIRECT"},
        "tls": {"version": "1.3", "cipher": "TLS_AES_128_GCM_SHA256"},
        "host": {"name": "lab-pc-07"},
        "meta": {"tags": ["a", "b", "c"]},
    }
    (out,) = _run(doc)

    def shape(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: shape(v) for k, v in node.items()}
        if isinstance(node, list):
            return [shape(v) for v in node]
        return type(node).__name__

    assert shape(out) == shape(doc)
    for key in ("@timestamp", "kibana.alert.rule.threat", "kibana.alert.rule.parameters"):
        assert out[key] == doc[key]
    for key in ("user_agent", "url", "http", "event", "squid", "tls", "meta"):
        assert out[key] == doc[key], key


_FRAGMENTS = st.sampled_from(
    [
        "10.1.2.3",
        "192.0.2.7",
        "lab-pc-07",
        "syn-alice",
        "@",
        "%40",
        "%2F",
        "%20",
        ".",
        ":",
        "::",
        "-",
        "_",
        "/",
        "\\",
        "ip6.arpa",
        "DC=",
        ",",
        "host.name",
        "user.name",
        ": ",
        "==",
        '"',
        "(",
        "*",
        "http://",
        "https%3A%2F%2F",
        "campus.ac.in",
        "0",
        "1",
        "255",
        "ffff",
        "fe80",
        "/home/",
        "C:\\Users\\",
        "İ",
        "ß",
        "१",
        "[",
        "]",
        "#",
        "=",
        " ",
        "field",
        "value",
    ]
)
_TEXT = st.lists(_FRAGMENTS, max_size=12).map("".join) | st.text(max_size=30)
_KEYS = st.one_of(
    _TEXT,
    st.integers(),
    st.sampled_from(["host.name", "user.name", "user.email", "_id", "_source", "field", "value"]),
)
_DOCS = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.floats(allow_nan=True), _TEXT),
    lambda inner: st.lists(inner, max_size=4) | st.dictionaries(_KEYS, inner, max_size=4),
    max_leaves=20,
)


@given(st.lists(_DOCS, max_size=3))
@settings(deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_lockin_harvest_and_sanitize_raise_nothing_but_the_site_space_refusal(
    docs: list[Any],
) -> None:
    """LOCK-IN: documents built from detector fragments (addresses, escapes, ``host.name:``,
    ``{field, value}``, IPv6 and reverse suffixes, non-ASCII digits and letters) plus non-string
    keys, NaN, ``None`` and nesting never raise anything but ``IPMapError``, and keep their list
    lengths. (``in-addr.arpa`` is left out: FXE-14 covers its crash.)"""
    s = Sanitizer(POLICY, KEY)
    try:
        s.harvest(docs)
        outs = [s.sanitize(d) for d in docs]
    except IPMapError:
        return

    def lengths(node: Any) -> Any:
        if isinstance(node, dict):
            return [(type(k).__name__, lengths(v)) for k, v in node.items()]
        if isinstance(node, list):
            return [lengths(v) for v in node]
        return None

    assert [lengths(o) for o in outs] == [lengths(d) for d in docs]


@pytest.mark.parametrize(
    "text",
    [
        "a." * 50_000,
        "http://" + "a" * 100_000,
        "http://a:" + "b" * 100_000,
        "1-" * 50_000,
        "%41" * 33_000,
        "a:" * 50_000,
        "DC=a," * 20_000,
        'user.name:"' + "a" * 100_000,
        "user.name" + " " * 100_000,
        "1.1.1.1." * 12_500,
        "1." * 50_000 + "in-addr.arpa",
        "a." * 50_000 + "ip6.arpa",
        "x." * 50_000 + "campus.ac.in",
        "a@" + "b." * 50_000 + "-",
        "ab://" * 20_000,
        "/home/" * 16_000,
    ],
    ids=lambda t: re.sub(r"\W", "_", t[:12]),
)
def test_lockin_detectors_are_linear_on_100kb_adversarial_strings(text: str) -> None:
    """LOCK-IN: no detector backtracks catastrophically: harvest plus map_text of a 100 kB
    adversarial string (one per detector) stays under 3 s with a small dictionary."""
    start = time.perf_counter()
    s = Sanitizer(POLICY, KEY)
    s.harvest([{"message": text, "file": {"path": text}}])
    s.map_text(text)
    assert time.perf_counter() - start < 3.0
