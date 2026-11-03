"""The sanitizer's field mappers and text pass, one behaviour at a time (synthetic data only).

Found missing by mutation testing: the golden document and the round tests put each identifier in
several places, so one broken path is hidden by another that writes the same pseudonym. Each test
here isolates one mapper, detector or boundary, with exact output under the fixed synthetic key.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest

from argus.fixtures import FixturePolicy
from argus.fixtures.sanitizer import Sanitizer

KEY = b"k" * 32
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    campus_domains=("campus.ac.in",),
    keep_domains=("vendor-cdn.example",),
    literals={"Campus University": "Example University", "SynOrg": "ExampleOrg"},
    fields={
        "host": ("host.name", "*.hostname"),
        "user": ("user.name",),
        "email": ("user.email",),
        "place": ("source.site.department",),
        "org": ("organization.name",),
        "domain": ("destination.domain",),
        "id": ("kibana.alert.uuid",),
    },
)
ALICE = "u-x4qh5bqa"
CAROL = "u-u7lk66pv"
LAB_PC_07 = "7k75la5f"  # the label token of lab-pc-07
ADDRESS = "10.55.161.254"  # 10.1.2.3


FIELDS = {
    "user": "user.name",
    "email": "user.email",
    "host": "host.name",
    "domain": "destination.domain",
    "place": "source.site.department",
    "org": "organization.name",
    "id": "kibana.alert.uuid",
}


def fresh(*docs: Any) -> Sanitizer:
    sanitizer = Sanitizer(POLICY, KEY)
    sanitizer.harvest(list(docs))
    return sanitizer


def sanitized_field(kind: str, value: str) -> Any:
    """``value`` in the policy field of ``kind``, sanitized as part of a document."""
    path = FIELDS[kind].split(".")
    doc: Any = value
    for part in reversed(path):
        doc = {part: doc}
    out = fresh().sanitize(doc)
    for part in path:
        out = out[part]
    return out


# ------------------------------------------------------------------ strings by context


def test_a_query_string_over_user_fields_is_mapped_term_by_term() -> None:
    doc = {"query": {"query_string": {"query": '1000 OR "alice"', "fields": ["user.name"]}}}
    out = fresh(doc).sanitize(doc)
    assert out["query"]["query_string"]["query"] == f'u-tpa5bjmp OR "{ALICE}"'


def test_a_dsl_wildcard_keeps_its_wildcard() -> None:
    doc = {"query": {"wildcard": {"host.name": "svc-backup-07*"}}}
    assert fresh(doc).sanitize(doc) == {"query": {"wildcard": {"host.name": "enyjsz7q*"}}}


def test_a_value_typed_by_its_key_is_mapped_by_its_kind_not_as_text() -> None:
    """A uid is no dictionary word: only its field's kind maps it."""
    doc = {"query": {"term": {"user.name": "1000"}}}
    assert fresh(doc).sanitize(doc) == {"query": {"term": {"user.name": "u-tpa5bjmp"}}}


# ------------------------------------------------------------------ whole addresses


def test_a_whole_address_value_and_key_are_mapped() -> None:
    """Seven groups and ``::`` (8 colons): before 2.3.0 only the whole-value path found it."""
    s = fresh()
    assert s.map_text("1:2:3:4:5:6:7::") == "c45e:4581:e8eb:5f23:d58c:ceb9:cec7:8e7f"
    assert s.sanitize({"1:2:3:4:5:6:7::": 1}) == {"c45e:4581:e8eb:5f23:d58c:ceb9:cec7:8e7f": 1}


def test_a_scoped_address_keeps_its_zone() -> None:
    assert fresh().map_text("fd12::7%eth0") == "fc06:c546:a667:bc7f:f090:995d:ee30:acbd%eth0"


def test_the_longest_address_spelling_is_an_address() -> None:
    text = "2001:0db8:0000:0000:0000:ffff:192.168.100.200"  # 45 characters
    assert len(text) == 45
    assert fresh().map_text(text) == "2001:db8:f0fe:2091:e528:4ca9:50ad:ac82"


# ------------------------------------------------------------------ mapping keys


def test_a_harvested_id_used_as_a_key_is_mapped_as_the_id() -> None:
    s = fresh({"kibana": {"alert": {"uuid": "SyntheticAlertId0001"}}})
    assert s.sanitize({"SyntheticAlertId0001": "x"}) == {"4CtSuXXut2l-0MU8X04M": "x"}
    assert s.map_text("alert SyntheticAlertId0001 closed") == "alert 4CtSuXXut2l-0MU8X04M closed"


def test_a_host_used_as_a_key_is_renamed_unless_it_holds_structure() -> None:
    plain = fresh({"host": {"name": "kiosk7"}})
    assert plain.sanitize({"labels": {"kiosk7": "on"}}) == {"labels": {"4xxn2sgm": "on"}}
    for nested in (
        {"status": {"kiosk7": {"since": "2026"}}},
        {"status": [{"kiosk7": {"since": "2026"}}]},
        {"a": {"b": [{"kiosk7": ["x"]}]}},
    ):
        s = fresh({"host": {"name": "kiosk7"}}, nested)
        assert s.sanitize({"labels": {"kiosk7": "on"}}) == {"labels": {"kiosk7": "on"}}


def test_only_hosts_users_and_emails_rename_a_field_shaped_key() -> None:
    """A place or a policy path word used as a key is structure, not a name."""
    s = fresh({"source": {"site": {"department": "physlab"}}, "host": {"name": "source"}})
    assert s.sanitize({"labels": {"physlab": 1, "source": 2}}) == {
        "labels": {"physlab": 1, "source": 2}
    }


def test_an_email_used_as_a_key_gets_the_email_pseudonym() -> None:
    s = fresh({"user": {"email": "alice@campus.ac.in"}})
    assert s.sanitize({"alice@campus.ac.in": 1}) == {f"{ALICE}@univ.example": 1}
    assert s.sanitize({"Alice@Campus.ac.in": 1}) == {f"{ALICE}@univ.example": 1}
    from_text = fresh({"message": "mail alice@campus.ac.in"})
    assert from_text.sanitize({"alice@campus.ac.in": 1}) == {f"{ALICE}@univ.example": 1}


def test_a_harvested_name_that_is_no_field_name_is_renamed_as_a_key() -> None:
    """``Dept-Q7`` cannot be a field name: as a key it is the department, whatever it holds."""
    s = fresh({"source": {"site": {"department": "Dept-Q7"}}})
    assert s.sanitize({"labels": {"Dept-Q7": 1}, "Dept-Q7": {"a": 1}}) == {
        "labels": {"pl-zkpgksh6": 1},
        "pl-zkpgksh6": {"a": 1},
    }


def test_a_key_with_an_address_quad_keeps_its_own_spelling() -> None:
    s = fresh({"host": {"name": "ip-10-1-2-3"}})
    assert s.sanitize({"IP-10-1-2-3": 1, "ip-10-1-2-3": 2}) == {
        "IP-10-55-161-254": 1,
        "ip-10-55-161-254": 2,
    }


def test_a_two_character_key_is_never_looked_up_in_the_dictionary() -> None:
    """A dotted capital I lower-cases to two characters: the key is two characters long, its
    lower-case form three, the spelling of a harvested name."""
    s = fresh({"user": {"name": "i\u0307a"}})
    assert "i\u0307a" in s.dictionary
    assert s.sanitize({"\u0130a": 1}) == {"\u0130a": 1}


# ------------------------------------------------------------------ field kinds by path


def test_a_path_has_its_own_kind_whatever_was_looked_up_before() -> None:
    """Kinds are cached by the whole dotted path: no other spelling of the keys shares one."""
    s = fresh({"user": {"name": "1000"}})
    assert s.sanitize({"user": {"name": "1000"}, "userXX": {"XXname": "1000"}}) == {
        "user": {"name": "u-tpa5bjmp"},
        "userXX": {"XXname": "1000"},
    }


def test_the_innermost_source_decides_the_path() -> None:
    s = fresh()
    doc = {"hits": [{"_source": {"x": {"_source": {"user": {"name": "1000"}}}}}]}
    assert s.sanitize(doc) == {
        "hits": [{"_source": {"x": {"_source": {"user": {"name": "u-tpa5bjmp"}}}}}]
    }


def test_a_field_pattern_gives_its_kind() -> None:
    s = fresh({"observer": {"hostname": "1000"}})
    assert s.sanitize({"observer": {"hostname": "1000"}}) == {"observer": {"hostname": "uthgnv2o"}}


def test_every_id_field_is_an_id() -> None:
    s = fresh()
    assert s.sanitize({"_id": "SyntheticAlertId0001", "a": {"_id": "Zz9AncestorIdAbCdEfG"}}) == {
        "_id": "4CtSuXXut2l-0MU8X04M",
        "a": {"_id": "mv6mA4sC_DUCLyzZLdxc"},
    }


# ------------------------------------------------------------------ field mappers


@pytest.mark.parametrize(
    ("kind", "value", "expected"),
    [
        ("user", "  ", "  "),
        ("id", " ", " "),
        ("user", "10.1.2.3", ADDRESS),
        ("user", "8.8.4.4", "55.105.252.97"),
        ("user", "alice@campus.ac.in", f"{ALICE}@univ.example"),
        ("user", "alice%40campus.ac.in", f"{ALICE}%40univ.example"),
        ("user", "CORP\\alice", f"wev5xaqw\\{ALICE}"),
        ("user", "\\alice", "u-ijtwehrf"),
        ("user", "CORP\\", "u-lxh4nd7n"),
        ("user", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\SYSTEM"),
        ("user", "alice", ALICE),
        ("user", "root", "root"),
        ("host", "LOCALHOST", "LOCALHOST"),
        ("host", "3.2.1.10.in-addr.arpa", "254.161.55.10.in-addr.arpa"),
        ("host", "010.001.002.003", "010.055.161.254"),
        ("host", "0010.1.2.3", "o6gjd4ib.2ae74tgd.33bdddgi.3"),
        ("org", "SynOrg", "ExampleOrg"),
        ("org", "synorg", "exampleorg"),
        ("org", "Acme Labs", "org-mgbjxdxv"),
        ("place", "Physics", "pl-kel7du5p"),
        ("domain", "www.campus.ac.in", "nj4xtrco.univ.example"),
        ("domain", "localhost", "localhost"),
        ("email", "alice", ALICE),
        ("email", "not an address", "not an address"),
        ("email", "@alice", "@alice"),
        ("email", "alice%40campus.ac.in", f"{ALICE}%40univ.example"),
        ("email", "<ivy.s@campus.ac.in>", "<u-z3zi6kys@univ.example>"),
        ("email", "Ivy Synthetic <ivy.s@campus.ac.in>", "u-uxz3my42 <u-z3zi6kys@univ.example>"),
        ("email", "alice+lists@campus.ac.in", f"{ALICE}+yeh3pq@univ.example"),
        ("email", "+lists@campus.ac.in", "u-oggsos7i@univ.example"),
        ("email", "alice+@campus.ac.in", "u-us655mzy@univ.example"),
    ],
)
def test_field_values_by_kind(kind: str, value: str, expected: str) -> None:
    assert sanitized_field(kind, value) == expected


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("ip-10-1-2-3.campus.ac.in", "ip-10-55-161-254.62o6vdys.hvg43mlm.265rqf7m"),
        ("ip-10-1-2-3.example.com", "ip-10-55-161-254.sauzwvfx.com"),
        ("web.ip-10-1-2-3.example.com", "jvqtrrg2.ip-10-55-161-254.sauzwvfx.com"),
        ("ip-8-8-8-8.example.com", "paq5iqjb.sauzwvfx.com"),
    ],
)
def test_a_host_label_with_a_private_address_quad_keeps_the_mapped_quad(
    value: str, expected: str
) -> None:
    assert sanitized_field("host", value) == expected


# ------------------------------------------------------------------ query values


QUERY = 'host.name: (lab-pc-07 or "lab-pc-08" OR \'lab-pc-09\' and not svc-backup-07* AND NOT "")'


def test_a_query_list_harvests_its_items_but_never_its_operators() -> None:
    s = fresh({"message": QUERY})
    assert s.harvested == {QUERY, "lab-pc-07", "lab-pc-08", "lab-pc-09", "svc-backup-07"}
    query = "user.name: (alice or carol)"
    assert fresh({"message": query}).harvested == {query, "alice", "carol"}


def test_a_query_list_maps_each_item_and_keeps_operators_and_quotes() -> None:
    assert fresh().map_text(QUERY) == (
        f'host.name: ({LAB_PC_07} or "r3nghfwi" OR \'buafnbgh\' and not enyjsz7q* AND NOT "")'
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("host.name: X-07*", "host.name: 3g6tvbyi*"),
        ("host.name: *-svc-backup-07-*", "host.name: *-enyjsz7q-*"),
        ("host.name: pc-7*", "host.name: n3hkwj67*"),
        ("host.name: abcd*", "host.name: abcd*"),
        ('host.name: ""', 'host.name: ""'),
        ("user.name: anna", "user.name: u-zybvvjsu"),
        ("host.name: XLAB-07X", "host.name: odu6rgm6"),
        ('user.name: "alice', 'user.name: "alice'),
        ("user.name: 'alice'", f"user.name: '{ALICE}'"),
        ("host.name.keyword: lab-pc-07", f"host.name.keyword: {LAB_PC_07}"),
        (
            'host.name == "lab-pc-07" and user.name != alice',
            f'host.name == "{LAB_PC_07}" and user.name != {ALICE}',
        ),
        ('user.name NOT IN ("alice", "carol")', f'user.name NOT IN ("{ALICE}", "{CAROL}")'),
    ],
)
def test_query_values(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


# ------------------------------------------------------------------ credentials


def test_digest_credentials() -> None:
    text = (
        'Digest username="carol", realm="campus.ac.in", nonce="abc123", uri="/x?ip=10.1.2.3",'
        ' response="d41d8cd9", opaque="zz9", cnonce="0a4f", qop=auth'
    )
    assert fresh().map_text(text) == (
        f'Digest username="{CAROL}", realm="univ.example", nonce="REDACTED",'
        f' uri="/x?ip={ADDRESS}", response="REDACTED", opaque="REDACTED", cnonce="REDACTED",'
        " qop=auth"
    )
    assert fresh().map_text("Digest username=carol, realm=campus") == (
        f"Digest username={CAROL}, realm=campus"
    )
    assert fresh().map_text('Digest username="", nonce="n0"') == (
        'Digest username="", nonce="REDACTED"'
    )


def test_a_detection_right_after_another_is_still_made() -> None:
    assert fresh().map_text('Digest username="carol"10.1.2.3') == (
        f'Digest username="{CAROL}"{ADDRESS}'
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Basic ZGFuYTpwYXNz", "Authorization: Basic REDACTED"),  # dana:pass
        ("Authorization: Bearer abcdefgh.ijk", "Authorization: Bearer REDACTED"),
        ("basic authentication", "basic authentication"),
        ("token authentication", "token authentication"),
    ],
)
def test_http_credentials(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


@pytest.mark.parametrize(
    ("header", "accounts"),
    [
        ("Basic ZGFuYTpwYXNz", {"dana"}),
        ("Basic YWxpY2U6cHc", {"alice"}),  # alice:pw without its padding
        ("Bearer ZGFuYTpwYXNz", set()),  # only Basic carries an account
        ("Basic YWxp.Y2U6cHc=", set()),  # not base64
        ("Basic " + _b64(b"synthetic-token"), set()),  # no user:password
        ("Basic " + _b64(b"a\x01b:pw"), set()),  # not printable
        ("Basic " + _b64(b"\xff\xfe:pw"), set()),  # not UTF-8
    ],
)
def test_the_account_of_a_basic_credential_is_harvested(header: str, accounts: set[str]) -> None:
    s = fresh({"message": f"Authorization: {header}"})
    assert {h for h in s.harvested if not h.startswith(("Basic", "Bearer"))} == accounts


# ------------------------------------------------------------------ text detectors


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "http://alice:hunter2@www.campus.ac.in/x",  # fake-secret
            f"http://{ALICE}:REDACTED@nj4xtrco.univ.example/x",  # fake-secret
        ),
        ("http://alice@www.campus.ac.in/x", f"http://{ALICE}@nj4xtrco.univ.example/x"),
        (
            "ftp://carol:@files.example.com",  # fake-secret
            f"ftp://{CAROL}:REDACTED@2v2xkne3.sauzwvfx.com",  # fake-secret
        ),
        ("http://[2001:db8::5]:8080/x", "http://[2001:db8:f0fe:2091:e528:85a2:4e1:795c]:8080/x"),
        ("http://10.1.2.3/x", f"http://{ADDRESS}/x"),
        ("http://X10.1.2.3/", "http://hvgqa5o2.2ae74tgd.33bdddgi.3/"),
        ("https://www.example.com/a", "https://nj4xtrco.sauzwvfx.com/a"),
    ],
)
def test_urls(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("mail alice@10.1.2.3 now", f"mail {ALICE}@10.55.161.254 now"),
        ("hint=bob.k%2Bnews%40campus.ac.in", "hint=u-gfpj3ta6+7k5nwk%40univ.example"),
    ],
)
def test_emails(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10-1-2-3.campus.ac.in", "keikh336.univ.example"),
        ("10.1.2.3.campus.ac.in", "g5msmpyz.2ae74tgd.33bdddgi.zcu4lxtg.univ.example"),
    ],
)
def test_the_longest_detection_at_one_place_wins(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10.1.2.3/24", "10.55.161.254/24"),  # an interface keeps its host
        ("10.1.2.0/24", "10.55.161.0/24"),
        ("010.001.002.000/24", "010.055.161.252/24"),
        ("10.0.0.0/8", "10.0.0.0/8"),
        ("8.8.8.0/24", "55.105.245.167/24"),
        ("192.0.2.0/23", "198.18.0.192/23"),  # two regions: the address is mapped
        ("10.1.2.3/33", "10.55.161.254/33"),
        ("224.0.0.0/03", "224.0.0.0/3"),
        ("127.0.0.0/08", "127.0.0.0/8"),
        ("0.0.0.0/0", "0.0.0.0/0"),
        ("fd12:3456:0:0:0:0:0:0/32", "fc06:eb31::/32"),
        ("2001:db8::5/64", "2001:db8:f0fe:2091:e528:85a2:4e1:795c/64"),
        ("010.001.002.255", "010.055.161.107"),
        ("host 192.0.2.242 up", "host 198.18.0.7 up"),  # no padding to the original's widths
        ("link fe80:0000:0000:0000:0000:0000:0000:0001 up", "link fe80::1 up"),
        ("010.001.002.256", "010.001.002.256"),
        ("10.1.2.3:52159", "10.55.161.254:52159"),
        ("[fd12::7]:443", "[fc06:c546:a667:bc7f:f090:995d:ee30:acbd]:443"),
    ],
)
def test_addresses_and_networks(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


def test_address_quads_in_names() -> None:
    assert (
        fresh().map_text("ip-10-1-2-3 ip-192-0-2-7 ip-8-8-8-8 ip-127-0-0-1 dump_10_1_2_3.pcap")
        == "ip-10-55-161-254 ip-198-18-0-199 ip-8-8-8-8 ip-127-0-0-1 dump_10_55_161_254.pcap"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("3.2.1.10.in-addr.arpa", "254.161.55.10.in-addr.arpa"),
        ("2.1.10.in-addr.arpa", "161.55.10.in-addr.arpa"),
        ("1.10.in-addr.arpa", "55.10.in-addr.arpa"),
        ("10.in-addr.arpa", "10.in-addr.arpa"),
        ("07.2.1.10.in-addr.arpa", "251.161.55.10.in-addr.arpa"),
        ("255.2.1.10.in-addr.arpa", "107.161.55.10.in-addr.arpa"),
        ("256.2.1.10.in-addr.arpa", "256.2.1.10.in-addr.arpa"),
        ("8.8.8.in-addr.arpa", "245.105.55.in-addr.arpa"),
        ("0.127.in-addr.arpa", "0.127.in-addr.arpa"),
        (
            "7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.5.4.3.2.1.d.f.ip6.arpa",
            "a.f.c.6.6.c.2.d.b.8.a.4.2.3.a.a.a.2.6.e.0.0.a.6.1.3.b.e.6.0.c.f.ip6.arpa",
        ),
        ("6.5.4.3.2.1.d.f.ip6.arpa", "1.3.b.e.6.0.c.f.ip6.arpa"),
        ("d.f.ip6.arpa", "c.f.ip6.arpa"),
    ],
)
def test_reverse_dns_names(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("CN=carol,OU=Labs,DC=campus,DC=ac,DC=in", "CN=carol,OU=Labs,DC=univ,DC=example"),
        ("DC=corp, DC=example,DC=com", "DC=wev5xaqw,DC=sauzwvfx,DC=com"),
    ],
)
def test_ldap_domains(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Chrome/154.0.0.0", "Chrome/154.0.0.0"),
        ("x/154.0.0.0", "x/154.0.0.0"),
        ("1x/154.0.0.0", "1x/154.0.0.0"),
        ("v 154.0.0.0", "v 181.175.68.55"),
        ("/154.0.0.0", "/181.175.68.55"),
        ("154.0.0.0", "181.175.68.55"),
        ("Chrome/154.1.0.0", "Chrome/181.174.46.140"),
    ],
)
def test_a_product_version_is_no_address(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


# ------------------------------------------------------------------ the dictionary


def test_a_name_inside_a_longer_harvested_name_is_not_replaced_again() -> None:
    s = fresh(
        {"user": {"email": "Ivy Synthetic <ivy.s@campus.ac.in>", "name": ["ivy", "synthetic"]}}
    )
    assert s.map_text("Ivy Synthetic") == "u-uxz3my42"
    assert s.map_text("Ivy Synthetics") == "u-zry5qvdl Synthetics"
    assert s.map_text("ivy and synthetic") == "u-zry5qvdl and u-664zmajq"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("seen on lab-pc-07", f"seen on {LAB_PC_07}"),
        ("lab-pc-07 seen", f"{LAB_PC_07} seen"),
        ("lab-pc-077 and lab-pc-07x and xlab-pc-07", "lab-pc-077 and lab-pc-07x and xlab-pc-07"),
        ("lab-pc-07.campus", f"{LAB_PC_07}.campus"),
        ("q=%20lab-pc-07%20", f"q=%20{LAB_PC_07}%20"),
        (" \\tlab-pc-07", f" \\t{LAB_PC_07}"),
    ],
)
def test_dictionary_boundaries(text: str, expected: str) -> None:
    assert fresh({"host": {"name": "lab-pc-07"}}).map_text(text) == expected


def test_a_two_letter_name_is_replaced_in_its_own_case_only() -> None:
    s = fresh({"source": {"site": {"department": "QA"}}})
    assert s.map_text("QA team and qa team") == "pl-q4dvi3xx team and qa team"


def test_short_numbers_and_single_characters_are_not_dictionary_words() -> None:
    s = fresh({"user": {"name": ["q", "123456", "4321"]}})
    assert s.map_text("q and 123456 and 4321") == "q and u-ped4fn2m and 4321"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Campus_University", "Example University"),
        ("SYNORG", "EXAMPLEORG"),
        ("campus university", "example university"),
        ("CampusUniversity", "Example University"),
    ],
)
def test_literals(text: str, expected: str) -> None:
    assert fresh().map_text(text) == expected


def test_the_dictionary_replaces_harvested_names_only_and_literals_keep_their_spacing() -> None:
    s = fresh({"source": {"site": {"department": "SynOrg Lab"}}})
    assert s.map_text("SynOrg     and SynOrg Lab") == "ExampleOrg     and pl-kvt7a33w"


def test_a_kept_domain_in_another_case_is_kept_not_denylisted() -> None:
    policy = POLICY.model_copy(update={"keep_domains": ("cdn.example.mx",)})
    s = Sanitizer(policy, KEY)
    s.harvest([{"message": "see https://CDN.EXAMPLE.MX/x"}])
    assert s.harvested == set()
    assert "CDN.EXAMPLE.MX" in s.unchanged


# ------------------------------------------------------------------ aggregations


def test_bucket_keys_take_the_kind_of_the_aggregated_field_only() -> None:
    doc = {
        "request": {
            "aggs": {
                "by_host": {"terms": {"field": "host.name"}},
                "by_script": {"terms": {"script": "doc['x']"}},
                "listed": {"terms": ["host.name"]},
                "pairs": {
                    "composite": {
                        "sources": [
                            {"day": {"date_histogram": {"field": "@timestamp"}}},
                            {"h": {"terms": {"field": "host.name"}}},
                            {"s": {"terms": {"script": "x"}}},
                            "odd",
                        ]
                    }
                },
                "mt": {"multi_terms": {"terms": [{"field": "user.name"}, {"script": "x"}, "odd"]}},
                "meta": 1,
            }
        },
        "response": {
            "aggregations": {
                "by_host": {"buckets": [{"key": "1000"}]},
                "by_script": {"buckets": [{"key": "1000"}]},
                "pairs": {
                    "buckets": [{"key": {"day": 1700000000000, "h": "lab-pc-07", "s": "1000"}}]
                },
                "mt": {"buckets": [{"key": ["1000", "x"], "key_as_string": "1000|x"}]},
            }
        },
    }
    out = fresh(doc).sanitize(doc)["response"]["aggregations"]
    assert out == {
        "by_host": {"buckets": [{"key": "uthgnv2o"}]},
        "by_script": {"buckets": [{"key": "1000"}]},
        "pairs": {"buckets": [{"key": {"day": 1700000000000, "h": LAB_PC_07, "s": "1000"}}]},
        "mt": {"buckets": [{"key": ["u-tpa5bjmp", "x"], "key_as_string": "u-tpa5bjmp|x"}]},
    }


# ------------------------------------------------- leaks fixed at the R2 gate (sanitizer 2.3.0)


def _run(policy: FixturePolicy, doc: dict[str, Any]) -> tuple[Any, list[str]]:
    sanitizer = Sanitizer(policy, KEY)
    sanitizer.harvest([doc])
    return sanitizer.sanitize(doc), sorted(sanitizer.harvested)


def test_an_email_right_after_an_escape_is_learned_without_the_escape_letter() -> None:
    """JSON inside a log line: the n of \\n is no part of the address after it."""
    policy = FixturePolicy(campus_domains=("campus.ac.in",))
    doc = {"message": '{"note":"mail \\nalice@campus.ac.in"} later alice logged in'}
    out, harvested = _run(policy, doc)
    assert harvested == ["alice", "alice@campus.ac.in", "campus.ac.in"]
    expected = '{"note":"mail \\nu-x4qh5bqa@univ.example"} later u-x4qh5bqa logged in'
    assert out == {"message": expected}


def test_a_campus_host_right_after_an_escape_keeps_the_escape_and_its_pseudonym() -> None:
    policy = FixturePolicy(campus_domains=("campus.ac.in",))
    out, _ = _run(policy, {"message": "from \\nwww.campus.ac.in and www.campus.ac.in"})
    assert out == {"message": "from \\nnj4xtrco.univ.example and nj4xtrco.univ.example"}


def test_an_email_in_a_windows_path_is_still_found() -> None:
    """``\\b`` after a word character is a path separator, not an escape."""
    _, harvested = _run(FixturePolicy(), {"message": "path C:\\Users\\bob@corp.example\\x"})
    assert harvested == ["bob", "bob@corp.example", "corp.example"]


def test_a_realm_qualified_machine_account_names_its_host() -> None:
    policy = FixturePolicy(fields={"user": ("user.name",)})
    doc = {"user": {"name": "CAMPUSNB\\LAB-PC-07$"}, "message": "LAB-PC-07 logged on"}
    out, _ = _run(policy, doc)
    assert out == {"user": {"name": "xuiv3kv3\\u-dlm7lhna"}, "message": f"{LAB_PC_07} logged on"}


def test_ipv6_with_seven_groups_and_a_double_colon_is_mapped_in_text() -> None:
    text = "addr 2001:db8:1:2:3:4:5:: and ::2:3:4:5:6:7:8 seen"
    out, _ = _run(FixturePolicy(), {"message": text})
    assert out == {
        "message": "addr 2001:db8:f0ff:e99f:83db:c632:66c6:8d46"
        " and c45f:b602:d408:2765:fdd:1f3a:7f05:8768 seen"
    }


def test_a_script_term_keeps_the_positions_of_multi_terms_keys() -> None:
    policy = FixturePolicy(fields={"user": ("user.name",)})
    doc = {
        "request": {
            "aggs": {
                "mt": {
                    "multi_terms": {"terms": [{"script": {"source": "x"}}, {"field": "user.name"}]}
                }
            }
        },
        "response": {
            "aggregations": {
                "mt": {"buckets": [{"key": ["4625", "syn-dave"], "key_as_string": "4625|syn-dave"}]}
            }
        },
    }
    out, harvested = _run(policy, doc)
    bucket = out["response"]["aggregations"]["mt"]["buckets"][0]
    assert bucket == {"key": ["4625", "u-ml463jzj"], "key_as_string": "4625|u-ml463jzj"}
    assert harvested == ["syn-dave"]
