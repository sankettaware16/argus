"""Adversarial review of R2's sanitizer: determinism, referential integrity, structure, policy.

Lens FXD of the R2 adversarial review. Later components group alerts by host, user, IP and rule,
follow ``kibana.alert.ancestors`` ids to source events and compare fixtures with each other, so the
same original must get the same pseudonym in every field, in free text, in URLs, in e-mails, in
ids and across documents, and the same key, policy and input must give byte-identical output
whatever the document order or the process's hash seed.

Conventions, as in the sibling adversarial files: a docstring starting with **DEFECT** marks a test
that fails on the current code on purpose and passes once the hole is closed; **LOCK-IN** tests
pass today and pin behaviour that held up under attack. Every identifier here is synthetic
(documentation address space, ``campus.ac.in``-style names, key ``b"k" * 32``); the only real file
read is the tracked policy ``config/fixtures.yaml``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from argus.fixtures import FixturePolicy, Sanitizer, Tokenizer, load_policy, walk_strings
from argus.fixtures.ipmap import IPMapError
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
TOKENS = Tokenizer(KEY)
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    own_domains=("campus.ac.in", "campus-alt.org"),
    keep_domains=("ubuntu.com", "vendor-cdn.com"),
    literals={"Campus University": "Example University", "CU": "EU", "ACME-CU": "ACME-EU"},
    fields={
        "host": ("host.name", "host.hostname", "agent.name", "observer.hostname"),
        "user": ("user.name", "user.id", "related.user"),
        "email": ("user.email",),
        "place": ("source.site.department",),
        "org": ("observer.dept",),
        "domain": ("url.domain", "dns.question.name"),
        "id": (
            "_id",
            "kibana.alert.uuid",
            "kibana.alert.ancestors.id",
            "kibana.alert.original_event.id",
            "event.id",
        ),
    },
)


def _sanitizer(docs: list[Any], policy: FixturePolicy = POLICY) -> Sanitizer:
    s = Sanitizer(policy, KEY)
    s.harvest(docs)
    return s


def _dump(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def _ip(text: str) -> str:
    return Sanitizer(POLICY, KEY).ips.map_text(text)


# ====================================================================== order dependence


def test_fxd01_harvest_order_changes_free_text() -> None:
    """DEFECT FXD-01: the free-text pseudonym of a value depends on the order documents are
    harvested. ``kali`` is both a user name and a host name (default user and hostname of the
    image); ``dictionary.setdefault`` keeps whichever kind was seen first, so the message reads
    ``u-...`` or ``h-...`` depending on document order."""
    as_user = {"user": {"name": "kali"}}
    as_host = {"host": {"name": "kali"}}
    text = {"message": "session opened on kali for kali"}
    first = _sanitizer([as_user, as_host, text]).sanitize(text)
    second = _sanitizer([as_host, as_user, text]).sanitize(text)
    assert first == second


hosts = st.sampled_from(["web01", "lab-pc-07", "kiosk7", "mail.campus.ac.in"])
users = st.sampled_from(["alice", "bob.smith", "carol"])
ips = st.sampled_from(["10.1.2.3", "192.0.2.79", "203.0.113.9", "::ffff:10.1.2.3", "2001:db8::5"])


@st.composite
def _same_kind_doc(draw: st.DrawFn) -> dict[str, Any]:
    host, user, ip = draw(hosts), draw(users), draw(ips)
    return {
        "_id": draw(st.sampled_from(["SyntheticAlertId0001", "Zz9AncestorIdAbCdEfG"])),
        "_source": {
            "host": {"name": host},
            "user": {"name": user, "email": f"{user}@campus.ac.in"},
            "source": {"ip": ip},
            "message": f"{user} on {host} from {ip} via http://{host}/x and {user}@campus.ac.in",
        },
    }


@given(st.lists(_same_kind_doc(), min_size=1, max_size=6), st.randoms(use_true_random=False))
def test_lockin_order_does_not_matter_when_no_value_has_two_kinds(
    docs: list[dict[str, Any]], rnd: Any
) -> None:
    """LOCK-IN: when every value has a single kind, harvest order does not change any output."""
    shuffled = list(docs)
    rnd.shuffle(shuffled)
    a, b = _sanitizer(docs), _sanitizer(shuffled)
    assert _dump([a.sanitize(d) for d in docs]) == _dump([b.sanitize(d) for d in docs])


def test_lockin_incremental_harvest_equals_one_harvest() -> None:
    """LOCK-IN: harvesting in two calls gives the same output as harvesting once."""
    d1 = {"host": {"name": "web01"}, "message": "web01 up"}
    d2 = {"user": {"name": "alice"}, "message": "alice on web01"}
    one = _sanitizer([d1, d2])
    two = Sanitizer(POLICY, KEY)
    two.harvest([d1])
    two.harvest([d2])
    assert _dump([one.sanitize(d1), one.sanitize(d2)]) == _dump(
        [two.sanitize(d1), two.sanitize(d2)]
    )


_SEED_SCRIPT = """
import hashlib, json, sys
from argus.fixtures import FixturePolicy, Sanitizer
policy = FixturePolicy.model_validate(json.loads(sys.argv[1]))
docs = json.loads(open(sys.argv[2], encoding="utf-8").read())
s = Sanitizer(policy, b"k" * 32)
s.harvest(docs)
out = json.dumps([s.sanitize(d) for d in docs], ensure_ascii=False)
extra = json.dumps([list(s.dictionary.items()), sorted(s.harvested), sorted(s.pseudonyms)])
sys.stdout.write(hashlib.sha256((out + extra).encode()).hexdigest())
"""


def test_lockin_output_is_identical_across_hash_seeds(tmp_path: Path) -> None:
    """LOCK-IN: byte-identical output in processes with different PYTHONHASHSEED values, with
    equal-length campus and keep domains (their order comes from a set) and every detector."""
    policy = POLICY.model_copy(
        update={
            "own_domains": ("aaaa.ac.in", "bbbb.ac.in", "cccc.org.in"),
            "keep_domains": ("cdn-a.com", "cdn-b.com", "cdn-c.com"),
        }
    )
    docs = [
        {
            "_id": f"BeidIKEBBF47AFeQSJ{i:02d}",
            "_source": {
                "host": {"name": f"lab-{i}.aaaa.ac.in", "hostname": f"lab-{i}"},
                "user": {"name": f"user{i}", "email": f"User{i}@bbbb.ac.in"},
                "url": {"domain": f"x{i}.cdn-b.com"},
                "message": (
                    f"user{i} lab-{i} www.cccc.org.in http://u:p@x{i}.evil.ru/a "
                    f"10.0.{i}.7 192.0.2.{i} 2001:db8::{i} 10.0.{i}.0/24 CU ACME-CU"
                ),
            },
        }
        for i in range(25)
    ]
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps(docs), encoding="utf-8")
    digests = set()
    for seed in ("0", "1", "77", "4242", "999999"):
        completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed local script
            [sys.executable, "-c", _SEED_SCRIPT, policy.model_dump_json(), str(corpus)],
            capture_output=True,
            text=True,
            check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
            timeout=120,
        )
        digests.add(completed.stdout)
    assert len(digests) == 1


# ====================================================================== cross-form integrity


def test_fxd02_host_case_variants_get_unrelated_pseudonyms() -> None:
    """DEFECT FXD-02: host names are case-insensitive, but ``LAB-PC-07`` (host.name, NetBIOS
    style) and ``lab-pc-07`` (agent.name, Elastic Agent lower-cases it) get unrelated tokens,
    while a dotted host name is lower-cased by the domain mapper."""
    doc = {"host": {"name": "LAB-PC-07"}, "agent": {"name": "lab-pc-07"}}
    out = _sanitizer([doc]).sanitize(doc)
    assert out["host"]["name"] == out["agent"]["name"]


def test_fxd02_case_variant_in_text_is_not_mapped() -> None:
    """DEFECT FXD-02: the free-text dictionary is case-sensitive. With host.name ``LAB-PC-07``
    harvested, ``lab-pc-07`` in a message stays raw instead of becoming the host's pseudonym."""
    doc = {"host": {"name": "LAB-PC-07"}, "message": "lab-pc-07 rebooted"}
    out = _sanitizer([doc]).sanitize(doc)
    assert "lab-pc-07" not in out["message"].lower()
    assert out["host"]["name"] in out["message"]


def test_fxd02_user_case_differs_between_field_email_and_url() -> None:
    """DEFECT FXD-02: the e-mail mapper lower-cases the local part, user fields and URL userinfo
    do not: ``Alice`` (user.name), ``alice@campus.ac.in`` and ``http://Alice:pw@x.ru/`` give
    two different user pseudonyms for one person."""
    doc = {
        "user": {"name": "Alice", "email": "alice@campus.ac.in"},
        "url": {"original": "http://Alice:pw@x.ru/login"},  # fake-secret
    }
    out = _sanitizer([doc]).sanitize(doc)
    from_field = out["user"]["name"]
    from_email = out["user"]["email"].split("@")[0]
    from_url = re.search(r"//(u-[a-z2-7]{8})", out["url"]["original"])
    assert from_url is not None
    assert from_field == from_email == from_url.group(1)


def test_fxd03_user_at_ip_maps_the_ip_as_a_domain() -> None:
    """DEFECT FXD-03: ``root@10.1.2.3`` (ssh/scp command lines, sudo and network-device logs) is
    taken as an e-mail, so the IP goes through the domain mapper: it no longer matches
    ``source.ip``'s pseudonym, stops being an IP and keeps its last octet."""
    doc = {
        "source": {"ip": "10.1.2.3"},
        "process": {"command_line": "ssh root@10.1.2.3 -p 22"},
        "message": "scp a.tgz admin@192.0.2.5:/tmp",
    }
    out = _sanitizer([doc]).sanitize(doc)
    assert out["source"]["ip"] == _ip("10.1.2.3")
    assert f"@{_ip('10.1.2.3')} " in out["process"]["command_line"]
    assert f"@{_ip('192.0.2.5')}:" in out["message"]


def test_fxd06_same_short_host_name_differs_by_field_kind() -> None:
    """DEFECT FXD-06: one string, three pseudonyms. ``moodle`` as host.name is ``h-<token>``,
    as a single-label DNS question or URL host it is a bare label token; nothing ties them."""
    doc = {
        "host": {"hostname": "moodle"},
        "dns": {"question": {"name": "moodle"}},
        "url": {"original": "http://moodle/login/index.php"},
    }
    out = _sanitizer([doc]).sanitize(doc)
    host = out["host"]["hostname"]
    assert out["dns"]["question"]["name"] == host
    assert out["url"]["original"] == f"http://{host}/login/index.php"


def test_fxd06_short_host_name_is_unrelated_to_its_fqdn() -> None:
    """DEFECT FXD-06: Elastic Agent reports host.hostname ``lab-pc-07`` and host.name
    ``lab-pc-07.campus.ac.in``; the short name's pseudonym is not the FQDN's first label, so one
    machine gets two unrelated identities."""
    doc = {"host": {"hostname": "lab-pc-07", "name": "lab-pc-07.campus.ac.in"}}
    out = _sanitizer([doc]).sanitize(doc)
    assert out["host"]["name"].split(".")[0] == out["host"]["hostname"]


def test_fxd07_upn_in_user_field_differs_from_the_same_upn_in_text() -> None:
    """DEFECT FXD-07: a UPN in user.name (Windows, Azure AD, O365) is tokenised whole as
    ``u-<token>``; the same string in the message becomes ``u-<other>@univ.example``."""
    doc = {"user": {"name": "alice@campus.ac.in"}, "message": "logon by alice@campus.ac.in"}
    out = _sanitizer([doc]).sanitize(doc)
    assert out["message"] == f"logon by {out['user']['name']}"


def test_fxd08_url_host_swallows_trailing_punctuation() -> None:
    """DEFECT FXD-08: the URL host pattern takes ``)``, ``,``, ``;`` and ``]`` as host characters.
    ``(see http://www.campus.ac.in)`` then maps ``www.campus.ac.in)`` as a generic domain
    (``tok.tok.tok.in)``) instead of ``tok.univ.example``, and a kept vendor domain followed by a
    comma is pseudonymised."""
    s = _sanitizer([])
    ours = s.domains.map("www.campus.ac.in")
    assert s.map_text("(see http://www.campus.ac.in)") == f"(see http://{ours})"
    assert s.map_text("[http://www.campus.ac.in];") == f"[http://{ours}];"
    assert (
        s.map_text("fetched http://vendor-cdn.com, done") == "fetched http://vendor-cdn.com, done"
    )


def test_lockin_ip_forms_agree() -> None:
    """LOCK-IN: an IP in a field, in text, in a URL, IPv4-mapped, bracketed IPv6, an IPv6 in
    another spelling and a /24 CIDR all agree with the field's pseudonym."""
    doc = {
        "source": {"ip": "10.1.2.3"},
        "destination": {"ip": "2001:DB8:0:0::5"},
        "message": (
            "from 10.1.2.3:52159 ::ffff:10.1.2.3 http://10.1.2.3:8080/a http://[2001:db8::5]/b "
            "net 10.1.2.0/24."
        ),
    }
    s = _sanitizer([doc])
    out = s.sanitize(doc)
    v4, v6 = _ip("10.1.2.3"), _ip("2001:db8::5")
    assert out["source"]["ip"] == v4
    assert out["destination"]["ip"] == v6
    net = s.ips.map_network(ipaddress.ip_network("10.1.2.0/24"))
    assert ipaddress.ip_address(v4) in net
    assert out["message"] == (
        f"from {v4}:52159 ::ffff:{v4} http://{v4}:8080/a http://[{v6}]/b net {net}."
    )


def test_lockin_domain_forms_agree() -> None:
    """LOCK-IN: a domain in a field, in a URL (any case), as an e-mail domain and as a campus
    subdomain in plain text map to the same pseudonym; kept vendor domains survive."""
    doc = {
        "url": {"domain": "www.campus.ac.in", "original": "HTTPS://WWW.Campus.AC.IN/x"},
        "user": {"email": "bob@www.campus.ac.in"},
        "message": "see www.campus.ac.in and http://a.vendor-cdn.com/x",
    }
    s = _sanitizer([doc])
    out = s.sanitize(doc)
    mapped = s.domains.map("www.campus.ac.in")
    assert mapped.endswith(".univ.example")
    assert out["url"]["domain"] == mapped
    assert out["url"]["original"] == f"HTTPS://{mapped}/x"
    assert out["user"]["email"].endswith(f"@{mapped}")
    assert out["message"] == f"see {mapped} and http://a.vendor-cdn.com/x"


def test_lockin_ids_agree_across_alert_ancestor_and_text() -> None:
    """LOCK-IN: ``_id``, kibana.alert.uuid, an ancestor's ``_id`` and kibana.alert.ancestors.id,
    original_event.id and the source event.id, and an id inside kibana.alert.url all agree."""
    alert = {
        "_index": ".internal.alerts-security.alerts-default-000001",
        "_id": "SyntheticAlertId0001",
        "_source": {
            "kibana.alert.uuid": "SyntheticAlertId0001",
            "kibana.alert.ancestors": [{"id": "Zz9AncestorIdAbCdEfG", "index": "logs-a"}],
            "kibana.alert.original_event.id": "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a",
            "kibana.alert.url": "https://kibana.example:5601/app/security/alerts/redirect/"
            "SyntheticAlertId0001?index=x",
        },
    }
    ancestor = {
        "_index": "logs-a",
        "_id": "Zz9AncestorIdAbCdEfG",
        "_source": {"event": {"id": "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"}},
    }
    s = _sanitizer([alert, ancestor])
    a, b = s.sanitize(alert), s.sanitize(ancestor)
    src = a["_source"]
    assert a["_id"] == src["kibana.alert.uuid"] != alert["_id"]
    assert src["kibana.alert.ancestors"][0]["id"] == b["_id"] != ancestor["_id"]
    assert src["kibana.alert.original_event.id"] == b["_source"]["event"]["id"]
    assert f"/redirect/{a['_id']}?index=x" in src["kibana.alert.url"]


# ====================================================================== dictionary over-matching


def test_fxd04_dictionary_matches_inside_compound_tokens() -> None:
    """DEFECT FXD-04: dictionary boundaries are ``[^A-Za-z0-9]``, so ``-``, ``.`` and ``_`` count as
    word breaks. Host ``lab-pc`` turns ``lab-pc-07`` into ``h-<lab-pc>-07`` (another host's
    pseudonym spliced in), host ``ubuntu`` corrupts the kept domain ``archive.ubuntu.com``, and
    user ``admin`` rewrites the attack path ``/wp-admin/``."""
    doc = {
        "host": {"name": "lab-pc"},
        "observer": {"hostname": "ubuntu"},
        "user": {"name": "admin"},
    }
    s = _sanitizer([doc])
    lab_pc = s.sanitize(doc)["host"]["name"]
    assert lab_pc not in s.map_text("lab-pc-07 rebooted")
    assert s.map_text("Hit archive.ubuntu.com focal InRelease") == (
        "Hit archive.ubuntu.com focal InRelease"
    )
    assert s.map_text("GET /wp-admin/setup.php 404") == "GET /wp-admin/setup.php 404"


def test_fxd05_numeric_user_ids_rewrite_timestamps_and_numbers() -> None:
    """DEFECT FXD-05: user.id ``33`` (www-data) enters the free-text dictionary, so every
    standalone ``33`` in every document becomes ``u-<token>``: ``12:33:45`` in a raw syslog line
    turns into ``12:u-xxxxxxxx:45``; ``1000`` does the same to byte counts."""
    doc = {
        "user": {"id": "33"},
        "related": {"user": ["1000"]},
        "event": {"original": "Oct  8 12:33:45 web01 CRON[2210]: sent 1000 bytes"},
    }
    out = _sanitizer([doc]).sanitize(doc)
    assert out["event"]["original"] == "Oct  8 12:33:45 web01 CRON[2210]: sent 1000 bytes"


def test_lockin_literals_longest_first_and_single_pass() -> None:
    """LOCK-IN: ``ACME-CU`` wins over ``CU`` inside it, a replacement is never re-replaced
    (``Campus University`` -> ``Example University`` keeps ``EU`` out), and literals respect
    word boundaries."""
    s = _sanitizer([])
    assert s.map_text("ACME-CU alert at Campus University, CU") == (
        "ACME-EU alert at Example University, EU"
    )
    assert s.map_text("CUSTOM ACU") == "CUSTOM ACU"


# ====================================================================== collisions and ids


def test_fxd15_two_campus_domains_collide() -> None:
    """DEFECT FXD-15: every campus domain maps onto the single ``own_replacement``, so
    ``www.campus.ac.in`` and ``www.campus-alt.org`` (two different hosts; the real policy has two
    campus domains) get the same pseudonym."""
    s = _sanitizer([])
    assert s.domains.map("www.campus.ac.in") != s.domains.map("www.campus-alt.org")
    assert s.domains.map("campus.ac.in") != s.domains.map("campus-alt.org")


def test_fxd16_forty_bit_tokens_collide_undetected() -> None:
    """DEFECT FXD-16: tokens are 8 base32 characters (40 bits) and nothing checks for collisions.
    Under the test key, users ``student884542`` and ``student1129612`` both become
    ``u-4nriaeeq`` (found with ~1.1M HMACs), and domain labels ``host1044505`` and
    ``host1635031`` share a label token. A detected collision (an error) is an acceptable fix."""
    docs = [{"user": {"name": "student884542"}}, {"user": {"name": "student1129612"}}]
    s = Sanitizer(POLICY, KEY)
    try:
        s.harvest(docs)
    except ValueError:
        return
    a, b = (s.sanitize(d)["user"]["name"] for d in docs)
    assert a != b
    assert s.domains.map("host1044505.campus.ac.in") != s.domains.map("host1635031.campus.ac.in")


def test_fxd17_short_decimal_ids_collide() -> None:
    """DEFECT FXD-17: ``opaque_id`` truncates a hash to the input's length, so short ids are not
    injective: the 10,000 ids ``0000``..``9999`` map onto far fewer pseudonyms (716 collisions)."""
    mapped = {TOKENS.opaque_id(f"{i:04d}") for i in range(10_000)}
    assert len(mapped) == 10_000


def test_fxd17_decimal_ids_change_alphabet() -> None:
    """DEFECT FXD-17: a decimal id matches the hex pattern and comes back with letters
    (``1234`` -> ``bb45``), so the shape (alphabet) is not kept."""
    for value in ("1234", "20261008", "9007199254740993"):
        assert TOKENS.opaque_id(value).isdigit(), value


def test_fxd18_uuid_case_variants_are_unrelated() -> None:
    """DEFECT FXD-18: UUIDs are case-insensitive, but the upper-case form of a UUID is hashed as a
    different string, so ``BE2D3F8C-...`` and ``be2d3f8c-...`` get unrelated pseudonyms."""
    value = "0f8e7d6c-5b4a-4392-8170-6f5e4d3c2b1a"
    assert TOKENS.opaque_id(value.upper()) == TOKENS.opaque_id(value).upper()


@given(
    st.text(
        alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        min_size=20,
        max_size=20,
    )
)
def test_lockin_es_ids_keep_their_shape(value: str) -> None:
    """LOCK-IN: Elasticsearch ``_id`` shapes (20-character base64url) keep length and alphabet."""
    out = TOKENS.opaque_id(value)
    assert re.fullmatch(r"[A-Za-z0-9_-]{20}", out)
    assert out == TOKENS.opaque_id(value)


@given(st.text(alphabet="0123456789abcdef", min_size=32, max_size=64))
def test_lockin_hex_and_uuid_shapes(value: str) -> None:
    """LOCK-IN: lower/upper hex keep length and case; UUIDs keep their layout and case."""
    assert re.fullmatch(rf"[0-9a-f]{{{len(value)}}}", TOKENS.opaque_id(value))
    upper = value.upper()
    if not upper.isdigit():
        assert re.fullmatch(rf"[0-9A-F]{{{len(value)}}}", TOKENS.opaque_id(upper))
    h = value[:32].ljust(32, "a")
    uuid = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"
    layout = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    assert re.fullmatch(layout, TOKENS.opaque_id(uuid))


# ====================================================================== CIDR and structure


def test_fxd12_cidr_with_host_bits_loses_the_address() -> None:
    """DEFECT FXD-12: ``inet 10.1.2.3/24`` (interface notation) becomes ``inet X.Y.Z.0/24``: the
    host address is dropped, so the text no longer names the host whose field reads
    ``map(10.1.2.3)``. ``map(ip)/24`` keeps both the address and the network."""
    s = _sanitizer([])
    assert s.map_text("inet 10.1.2.3/24 brd 10.1.2.255") == (
        f"inet {_ip('10.1.2.3')}/24 brd {_ip('10.1.2.255')}"
    )


def test_fxd09_documents_inside_a_search_response_are_not_recognised() -> None:
    """DEFECT FXD-09: only a top-level ``_source.`` prefix is stripped, so a hit inside a search
    response (``hits.hits[]._source``, the shape gateway cassettes record) has no field kinds:
    the host name passes raw and is never harvested (the leak denylist never learns it), and
    ``_id`` is not mapped."""
    hit = {
        "_index": "logs-a",
        "_id": "SyntheticAlertId0001",
        "_source": {"host": {"name": "kiosk7"}},
    }
    response = {"took": 3, "hits": {"total": {"value": 1}, "hits": [hit]}}
    s = _sanitizer([response])
    assert "kiosk7" in s.harvested
    assert s.sanitize(response)["hits"]["hits"][0] == _sanitizer([hit]).sanitize(hit)


def test_fxd10_real_policy_leaves_ti_match_ids_unmapped() -> None:
    """DEFECT FXD-10: config/fixtures.yaml does not list ``threat.enrichments.matched.id`` (the
    TI document an indicator-match alert matched) as an id, so it is only mapped when the TI
    document itself was harvested; otherwise it stays raw and no longer points at the TI
    document's pseudonymous ``_id``."""
    policy, _ = load_policy(REPO_ROOT / "config" / "fixtures.yaml")
    alert = {
        "_index": ".internal.alerts-security.alerts-default-000001",
        "_id": "Q2xhbmtBbGVydElkMDAx",
        "_source": {
            "kibana.alert.rule.type": "threat_match",
            "threat": {
                "enrichments": [
                    {
                        "matched": {
                            "atomic": "203.0.113.50",
                            "field": "destination.ip",
                            "id": "VGlEb2NJZEFiQ2RFZkdo",
                            "index": "logs-ti_abusech.malware-default",
                        }
                    }
                ]
            },
        },
    }
    out = _sanitizer([alert], policy).sanitize(alert)
    matched = out["_source"]["threat"]["enrichments"][0]["matched"]
    assert matched["id"] == TOKENS.opaque_id("VGlEb2NJZEFiQ2RFZkdo")


def test_fxd19_deep_documents_crash_with_recursion_error() -> None:
    """DEFECT FXD-19: ``walk_strings`` and ``_sanitize_node`` recurse per level; a 1,200-deep
    document that ``json.loads`` accepts makes harvest and sanitize raise RecursionError."""
    text = '"10.1.2.3"'
    for _ in range(1_200):
        text = '{"a":' + text + "}"
    doc = json.loads(text)
    s = _sanitizer([doc])
    assert "10.1.2.3" not in json.dumps(s.sanitize(doc))


def test_fxd20_drop_top_level_also_drops_data_of_bare_documents() -> None:
    """DEFECT FXD-20: ``drop_top_level`` is meant for search-hit extras, but it is applied to any
    mapping, so a bare event loses real data such as Filebeat's custom ``fields`` object."""
    doc = {"fields": {"env": "prod", "site": "lab"}, "message": "x"}
    assert _sanitizer([doc]).sanitize(doc) == doc


def test_lockin_wrapped_and_bare_documents_agree() -> None:
    """LOCK-IN: a wrapped ``{_index, _id, _source}`` document and its bare ``_source`` sanitize
    to the same source; Discover extras are dropped from the wrapper only."""
    source = {"host": {"name": "web01"}, "user": {"name": "alice"}, "message": "alice on web01"}
    wrapped = {"_index": "logs-a", "_id": "SyntheticAlertId0001", "_source": source, "_score": 1}
    s = _sanitizer([wrapped])
    out = s.sanitize(wrapped)
    assert set(out) == {"_index", "_id", "_source"}
    assert out["_source"] == s.sanitize(source)


def test_lockin_structure_edge_cases() -> None:
    """LOCK-IN: tuples, lists of dicts, non-string keys, non-dict top levels, empty and
    whitespace strings and non-string scalars are handled without loss or crash."""
    s = _sanitizer([{"host": {"name": "web01"}}])
    doc = {
        1: "web01",
        "t": ("10.1.2.3", ""),
        "l": [{"host": {"name": "web01"}}, None, True, 1.5, "   "],
    }
    out = s.sanitize(doc)
    host = s.sanitize({"host": {"name": "web01"}})["host"]["name"]
    assert out == {
        1: host,
        "t": [_ip("10.1.2.3"), ""],
        "l": [{"host": {"name": host}}, None, True, 1.5, "   "],
    }
    assert s.sanitize("10.1.2.3") == _ip("10.1.2.3")
    assert s.sanitize(["web01"]) == [host]
    assert s.sanitize(None) is None


_FRAGMENTS = [
    "10.1.2.3",
    "::ffff:10.1.2.3",
    "192.0.2.7",
    "2001:db8::1",
    "fe80::1%eth0",
    "/24",
    "http://",
    "u:p@",
    "www.campus.ac.in",
    "x.ru",
    "alice@",
    "web01",
    "alice",
    "Campus University",
    "SyntheticAlertId0001",
    " ",
    ".",
    ":",
    "-",
    "[",
    "]",
    "/",
]
_texts = st.lists(st.sampled_from(_FRAGMENTS) | st.text(max_size=3), max_size=8).map("".join)
_json = st.recursive(
    st.none() | st.booleans() | st.integers() | _texts,
    lambda inner: (
        st.lists(inner, max_size=3)
        | st.dictionaries(
            st.sampled_from(["host", "name", "user", "message", "_id", "a"]), inner, max_size=3
        )
    ),
    max_leaves=12,
)


@given(_json)
def test_lockin_sanitize_is_deterministic_and_resanitizable(doc: Any) -> None:
    """LOCK-IN: two sanitizers built alike give identical output, and sanitizing a sanitized
    document again does not crash (pseudonyms are not required to be fixed points)."""
    a = _sanitizer([doc, {"host": {"name": "web01"}, "user": {"name": "alice"}}])
    b = _sanitizer([doc, {"host": {"name": "web01"}, "user": {"name": "alice"}}])
    once = a.sanitize(doc)
    assert _dump(once) == _dump(b.sanitize(doc))
    # Looked for in the strings themselves: JSON would write "\x19198.18..." as "\u0019198.18...".
    if any(
        re.search(r"(?<![0-9.])198\.1[89]\.[0-9]{1,3}\.[0-9]{1,3}", text)
        for _path, text in walk_strings(once)
    ):
        # Revised with FXC-01: a site pseudonym lies in the site space, and a real address there
        # is refused (a one-to-one map has no image left for it), so it cannot be re-sanitized.
        with pytest.raises(IPMapError, match="site space"):
            _sanitizer([once]).sanitize(once)
        return
    again = _sanitizer([once]).sanitize(once)
    assert isinstance(_dump(again), str)


# ====================================================================== policy handling


def test_fxd11_duplicate_yaml_keys_silently_drop_policy_entries(tmp_path: Path) -> None:
    """DEFECT FXD-11: ``yaml.safe_load`` keeps the last of two equal keys. A second ``host:`` list
    under ``fields`` silently removes host.name and agent.name from the policy; harvest uses the
    same policy, so those raw host names are not even on the leak denylist."""
    path = tmp_path / "fixtures.yaml"
    path.write_text(
        "fields:\n"
        "  host: [host.name, agent.name]\n"
        "  user: [user.name]\n"
        "  host: [observer.hostname]\n"
    )
    with pytest.raises((ValueError, yaml.YAMLError)):
        load_policy(path)


def test_fxd13_field_in_two_kinds_passes_load_policy(tmp_path: Path) -> None:
    """DEFECT FXD-13: a field listed under two kinds is only refused when a Sanitizer is built
    (``field_kinds()``); ``load_policy`` and ``FixturePolicy`` accept it."""
    path = tmp_path / "fixtures.yaml"
    path.write_text("fields:\n  host: [host.name]\n  user: [host.name]\n")
    with pytest.raises(ValueError, match="two kinds"):
        load_policy(path)


def test_fxd14_keep_domain_covering_a_campus_domain_is_accepted() -> None:
    """DEFECT FXD-14: a keep domain that covers a campus domain (``ac.in`` over ``campus.ac.in``)
    is accepted; campus names then pass verbatim and are recorded as ``unchanged``, which the
    driver removes from the leak denylist, so the leak goes unreported."""
    with pytest.raises(ValueError):  # noqa: PT011 - any refusal at load time is the fix
        Sanitizer(
            FixturePolicy(own_domains=("campus.ac.in",), keep_domains=("ac.in",)), KEY
        ).harvest([{"m": "http://www.campus.ac.in/"}])


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (b"- a\n- b\n", ValueError),
        (b"colour: red\n", ValueError),
        (b"fields:\n  person: [user.name]\n", ValueError),
        (b'literals:\n  "Caf\xe9": "x"\n', yaml.YAMLError),
    ],
)
def test_lockin_bad_policies_are_refused(
    tmp_path: Path, content: bytes, error: type[Exception]
) -> None:
    """LOCK-IN: a non-mapping, an unknown key, an unknown field kind and invalid UTF-8 are
    refused at load time; a missing file raises."""
    path = tmp_path / "fixtures.yaml"
    path.write_bytes(content)
    with pytest.raises(error):
        load_policy(path)
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "missing.yaml")


def test_lockin_empty_policy_still_maps_addresses(tmp_path: Path) -> None:
    """LOCK-IN: an empty policy file is a valid default policy; addresses are still mapped and
    its hash is recorded."""
    path = tmp_path / "fixtures.yaml"
    path.write_bytes(b"")
    policy, digest = load_policy(path)
    assert digest == hashlib.sha256(b"").hexdigest()
    s = _sanitizer([], policy)
    assert s.map_text("from 10.1.2.3") != "from 10.1.2.3"
