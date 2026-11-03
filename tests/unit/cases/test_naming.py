"""D-230: a case's title names the incident. The titler is pure: the shapes with a synthetic example
each, the length bound, the strict set of values a title may hold (Hypothesis feeds it hostile
text), the families, and the asset map's place words. Every address is a documentation, private or
synthetic one; nothing here is a real alert."""

from __future__ import annotations

import dataclasses
import ipaddress
import string

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.assess import raised
from argus.cases import naming
from argus.cases.naming import BEACON, LISTED, OUTSIDE, SUCCESS, Device, Facts, title
from argus.outside import facts as outside_facts
from argus.outside import prefetch

SERVERS = ("176.65.139.158", "176.65.139.159", "176.65.139.160")
ALLOWED = frozenset(string.ascii_letters + string.digits + " .,:()/&+-—→")


def devices(n: int, *, place: str | None = None, kind: str | None = None) -> tuple[Device, ...]:
    return tuple(Device(f"10.198.36.{i + 1}", "ip", kind, place) for i in range(n))


def test_the_flags_are_the_words_the_pipeline_stores() -> None:
    assert BEACON == prefetch.BEACON
    assert LISTED == raised.THREAT_LIST
    assert OUTSIDE == raised.OUTSIDE
    assert naming.OPERATOR == raised.OPERATOR


# -- the shapes ----------------------------------------------------------------------------------


def test_one_device_beaconing_to_flagged_servers() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=SERVERS)
    assert title(f) == (
        "Beaconing to 176.65.139.158 and 2 more flagged servers from 10.198.1.1".replace(
            "10.198.1.1", "10.198.36.1"
        )
    )


def test_one_flagged_server_is_named_alone() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=SERVERS[:1])
    assert title(f) == "Beaconing to 176.65.139.158 from 10.198.36.1"
    f = Facts(flags=frozenset({LISTED}), devices=devices(1), servers=SERVERS[:2])
    assert title(f) == "Contact with 176.65.139.158 and 1 more flagged server from 10.198.36.1"
    f = Facts(flags=frozenset({LISTED}), devices=devices(1), servers=SERVERS[:1])
    assert title(f) == "Contact with flagged server 176.65.139.158 from 10.198.36.1"


def test_devices_in_one_place_say_where() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(4, place="Hostel 12"), servers=SERVERS)
    assert title(f) == (
        "Beaconing to 176.65.139.158 and 2 more flagged servers from 4 campus devices in Hostel 12"
    )


def test_devices_of_one_kind_of_site_say_which() -> None:
    mixed = tuple(Device(f"10.198.36.{i}", "ip", "hostel", f"Hostel {i}") for i in range(1, 48))
    f = Facts(flags=frozenset({BEACON}), devices=mixed, servers=SERVERS[:1])
    assert title(f) == "Beaconing to 176.65.139.158 from 47 hostel devices"
    some = (*mixed[:3], Device("10.198.40.1", "ip", "lab", "Physics"))
    f = Facts(flags=frozenset({BEACON}), devices=some, servers=SERVERS[:1])
    assert title(f) == "Beaconing to 176.65.139.158 from 4 campus devices"


def test_a_known_family_leads_the_title() -> None:
    f = Facts(
        rules=(("Squid: beacon", 3),),
        flags=frozenset({BEACON}),
        devices=devices(1),
        servers=SERVERS[:1],
        labels=("amadey",),
    )
    assert title(f) == "Amadey beaconing from 10.198.36.1 to 176.65.139.158"
    contact = Facts(flags=frozenset({LISTED}), devices=devices(1), servers=SERVERS[:1],
                    labels=("c2", "Cobalt-Strike"))  # fmt: skip
    assert title(contact) == "Cobalt Strike contact from 10.198.36.1 to 176.65.139.158"


def test_beaconing_with_no_server_to_name() -> None:
    assert title(Facts(flags=frozenset({BEACON}), devices=devices(1))) == (
        "Beaconing from 10.198.36.1"
    )
    assert title(Facts(flags=frozenset({OUTSIDE}), devices=devices(2))) == (
        "Contact with flagged servers from 2 campus devices"
    )


def test_a_dns_campaign_names_the_parent_and_the_count() -> None:
    names = tuple(f"x{i}q.fast-dns-host.com" for i in range(12))
    f = Facts(devices=devices(35), domains=names, flags=frozenset({naming.OPERATOR}))
    assert title(f) == (
        "DNS lookups of 12 look-alike domains under fast-dns-host.com from 35 campus devices"
    )
    both = (*names[:3], "a.service-windows.com", "b.service-windows.com")
    f = Facts(devices=devices(2, place="Hostel 5"), domains=both)
    assert title(f) == (  # the place is the first detail to go when the title is too long
        "DNS lookups of 5 look-alike domains under fast-dns-host.com and service-windows.com"
        " from 2 campus devices"
    )
    short = Facts(devices=devices(2, place="Hostel 5"), domains=names[:2])
    assert title(short) == (
        "DNS lookups of 2 look-alike domains under fast-dns-host.com from 2 campus devices"
        " in Hostel 5"
    )
    three = (*both, "c.one-more-host.net", "d.one-more-host.net")
    assert title(Facts(devices=devices(1), domains=three)) == (
        "DNS lookups of 7 look-alike domains under fast-dns-host.com and 2 more domains"
        " from 10.198.36.1"
    )


def test_names_under_different_parents_are_not_look_alikes() -> None:
    f = Facts(devices=devices(1), domains=("a.one.com", "b.two.net"), servers=SERVERS[:1],
              flags=frozenset({BEACON}))  # fmt: skip
    assert title(f) == "Beaconing to 176.65.139.158 from 10.198.36.1"


def test_campus_sites_are_not_look_alikes_of_a_dns_campaign() -> None:
    f = Facts(devices=devices(1), domains=("a.example.edu", "b.example.edu"),
              sites=("a.example.edu", "b.example.edu"), rules=(("Rule", 1),))  # fmt: skip
    assert not title(f).startswith("DNS")


def test_outside_addresses_scanning_campus_sites() -> None:
    f = Facts(
        outsiders=tuple(f"203.0.113.{i}" for i in range(16)),
        sites=("www.example.example.edu", "a.example.edu", "b.example.edu"),
    )
    assert (
        title(f)
        == "Web scanning of www.example.example.edu and 2 more campus sites by 16 outside addresses"
    )
    one = Facts(outsiders=("203.0.113.9",), sites=("www.example.example.edu",))
    assert title(one) == "Web scanning of www.example.example.edu by 203.0.113.9"


def test_a_served_config_file_ends_the_title() -> None:
    f = Facts(outsiders=("203.0.113.9",), sites=("www.example.example.edu",), served=True)
    assert (
        title(f) == "Web scanning of www.example.example.edu by 203.0.113.9 — config files served"
    )
    by_rule = Facts(
        rules=(("Web: Sensitive, Backup or Config File Served Successfully", 4),),
        outsiders=("203.0.113.9", "203.0.113.10"),
        sites=("www.example.example.edu", "a.example.edu"),
    )
    assert title(by_rule) == (
        "Web scanning of www.example.example.edu and 1 more campus site by 2 outside addresses"
        " — config files served"
    )
    ok = Facts(outsiders=("203.0.113.9",), sites=("a.example.edu",), flags=frozenset({SUCCESS}))
    assert (
        title(ok) == "Web scanning of a.example.edu by 203.0.113.9 — attacks got successful answers"
    )


def test_a_web_attack_that_got_answers_with_no_site_known() -> None:
    f = Facts(outsiders=("185.220.101.4",), flags=frozenset({SUCCESS}))
    assert title(f) == "Web attack by 185.220.101.4 got successful answers"


def test_a_threat_listed_address_probing_campus_servers() -> None:
    one = Facts(outsiders=("45.138.12.51",), listed=("45.138.12.51",), campus_servers=3)
    assert title(one) == "Threat-listed 45.138.12.51 probing 3 campus servers"
    many = Facts(
        outsiders=tuple(f"203.0.113.{i}" for i in range(10)),
        listed=tuple(f"203.0.113.{i}" for i in range(10)),
        sites=("a.example.edu", "b.example.edu"),
    )
    assert title(many) == "10 threat-listed outside addresses probing 2 campus web sites"
    alone = Facts(outsiders=("45.138.12.51",), listed=("45.138.12.51",), sites=("a.example.edu",))
    assert title(alone) == "Threat-listed 45.138.12.51 probing a.example.edu"
    assert title(
        Facts(outsiders=("45.138.12.51",), listed=("45.138.12.51",), campus_servers=1)
    ) == ("Threat-listed 45.138.12.51 probing a campus server")


def test_the_fallback_is_the_rule_the_actor_and_the_target() -> None:
    f = Facts(
        rules=(("Mail: odd login", 2),), outsiders=("203.0.113.9",), servers=("evil.example.com",)
    )
    assert title(f) == "Mail: odd login — 203.0.113.9 → evil.example.com"
    plain = Facts(rules=(("Odd login", 2),), devices=devices(3), domains=("a.example.org",))
    assert title(plain) == "Odd login: 3 campus devices → example.org"
    assert title(Facts(rules=(("Odd login", 1),), accounts=3)) == "Odd login: 3 user accounts"
    assert title(Facts(rules=(("Odd login", 1),))) == "Odd login"
    assert title(Facts()) == naming.EMPTY


# -- the bound and the values a title may hold ---------------------------------------------------


def test_a_long_value_falls_back_to_a_count_not_a_cut() -> None:
    long_name = "a" * 40 + ".fast-dns-host.com"
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(long_name, SERVERS[0]))
    assert title(f) == "Beaconing to 176.65.139.158 and 1 more flagged server from 10.198.36.1"
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(long_name,))
    assert title(f) == "Beaconing to a flagged server from 10.198.36.1"


def test_a_long_title_drops_its_detail_before_its_values() -> None:
    f = Facts(
        flags=frozenset({BEACON}),
        devices=devices(5, place="Department of Chemical Engineering Block"),
        servers=("2001:db8:85a3:8d3:1319:8a2e:370:7348", *SERVERS),
        labels=("agent tesla",),
    )
    out = title(f)
    assert len(out) <= naming.MAX_TITLE
    assert out.startswith("Agent Tesla beaconing from 5 campus devices")
    assert "2001:db8:85a3:8d3:1319:8a2e:370:7348" in out


def test_a_value_that_is_not_an_address_or_a_name_is_never_in_a_title() -> None:
    bad = "10.0.0.1<script>alert(1)</script>"
    f = Facts(flags=frozenset({BEACON}), devices=(Device(bad), Device("10.198.36.2")),
              servers=(bad, "not an address", "x_y.example.com"))  # fmt: skip
    out = title(f)
    assert "script" not in out
    assert out == "Beaconing to 3 flagged servers from 2 campus devices"


def test_ipv6_is_written_in_one_spelling_and_a_zone_is_dropped() -> None:
    f = Facts(
        flags=frozenset({BEACON}), devices=(Device("fe80::1%eth0"),), servers=("::ffff:1.2.3.4",)
    )
    assert title(f) == "Beaconing to 1.2.3.4 from fe80::1"


def test_the_places_of_the_asset_map_are_plain_words_or_nothing() -> None:
    odd = tuple(Device(f"10.198.36.{i}", "ip", None, "H<b>12</b>") for i in range(1, 4))
    f = Facts(flags=frozenset({BEACON}), devices=odd, servers=SERVERS[:1])
    assert title(f) == "Beaconing to 176.65.139.158 from 3 campus devices"
    spaced = tuple(Device(f"10.198.36.{i}", "ip", "Hostel_Wing", "  Hostel   12 ") for i in (1, 2))
    f = Facts(flags=frozenset({BEACON}), devices=spaced, servers=SERVERS[:1])
    assert title(f) == "Beaconing to 176.65.139.158 from 2 campus devices in Hostel 12"


def test_a_rule_name_is_plain_words_or_it_is_not_used() -> None:
    assert naming.rule_name("  Web:   Sensitive,  Backup\tFile ") == "Web: Sensitive, Backup File"
    assert naming.rule_name("`rm -rf` <b>x</b>") is None
    assert naming.rule_name("x" * 30 + " " + "y" * 40) == "x" * 30
    assert title(Facts(rules=(("<b>x</b>", 1),), accounts=1)) == "Alert: a user account"


def test_a_family_is_the_tables_spelling_matched_as_whole_words() -> None:
    assert naming.family_of(["suspicious-udp", "AMADEY"]) == "Amadey"
    assert naming.family_of(["agenttesla"]) is None  # one word is not two
    assert naming.family_of(["Agent_Tesla"]) == "Agent Tesla"
    assert naming.family_of(["amadeyish", "xmrigx"]) is None
    assert naming.family_of(["cobalt strike beacon"]) == "Cobalt Strike"
    assert naming.family_of(["tor", "cdn"]) is None
    assert all(naming.family_of([name]) == name for name in naming.FAMILIES)


def test_a_case_that_follows_a_closed_one_says_so_within_the_bound() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=SERVERS[:1], follows=12)
    assert title(f) == "Beaconing to 176.65.139.158 from 10.198.36.1 — follows case 12"
    long = Facts(
        flags=frozenset({BEACON}),
        devices=devices(5, place="Department of Chemical Engineering Block"),
        servers=("2001:db8:85a3:8d3:1319:8a2e:370:7348", *SERVERS),
        labels=("agent tesla",),
        follows=1234,
    )
    out = title(long)
    assert out.endswith(" — follows case 1234")
    assert len(out) <= naming.MAX_TITLE
    assert title(Facts(follows=3)) == "Alert — follows case 3"


def test_the_same_facts_give_the_same_title() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(3), servers=SERVERS)
    assert title(f) == title(Facts(flags=frozenset({BEACON}), devices=devices(3), servers=SERVERS))


# -- Hypothesis ------------------------------------------------------------------------------------

hostile = st.one_of(
    st.text(max_size=90),
    st.text(alphabet="<>`'\"|*#\\\n\t\x1b[]{}$%^;@!?~=_ ab.0:-", max_size=60),
    st.ip_addresses().map(str),
    st.from_regex(r"[a-z0-9]{1,12}(\.[a-z0-9-]{1,12}){1,3}", fullmatch=True),
    st.sampled_from(
        [
            "",
            " ",
            "::",
            "0.0.0.0",  # noqa: S104
            "a" * 300,
            "x_y.example.com",
            "-.-",
        ]
    ),
)
devices_st = st.builds(
    Device,
    hostile,
    st.sampled_from(["ip", "host", "other"]),
    st.none() | hostile,
    st.none() | hostile,
)
flags_st = st.frozensets(st.sampled_from([BEACON, LISTED, OUTSIDE, naming.OPERATOR, SUCCESS, "x"]))
facts_st = st.builds(
    Facts,
    rules=st.lists(st.tuples(hostile, st.integers(1, 9)), max_size=3).map(tuple),
    flags=flags_st,
    devices=st.lists(devices_st, max_size=8).map(tuple),
    outsiders=st.lists(hostile, max_size=8).map(tuple),
    accounts=st.integers(0, 5),
    servers=st.lists(hostile, max_size=8).map(tuple),
    domains=st.lists(hostile, max_size=14).map(tuple),
    sites=st.lists(hostile, max_size=6).map(tuple),
    campus_servers=st.integers(0, 40),
    listed=st.lists(hostile, max_size=6).map(tuple),
    served=st.booleans(),
    labels=st.lists(hostile, max_size=4).map(tuple),
    follows=st.integers(0, 99999),
)


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=400)
@given(facts_st)
def test_any_facts_give_a_short_plain_title(f: Facts) -> None:
    out = title(f)
    assert 1 <= len(out) <= naming.MAX_TITLE
    assert not (set(out) - ALLOWED), out
    assert out == out.strip()
    assert "  " not in out
    assert title(f) == out


def _canonical(values: list[str]) -> tuple[set[str], set[str]]:
    """The addresses and the names (and their registered parents) the facts can spell."""
    ips: set[str] = set()
    names: set[str] = set()
    for value in values:
        found = outside_facts.canonical("ip", value)
        if found:
            ips.add(found)
        name = outside_facts.canonical("domain", value)
        if name:
            names.add(name)
            parent = naming.registered_parent(name)
            if parent:
                names.add(parent)
    return ips, names


@settings(suppress_health_check=[HealthCheck.too_slow], max_examples=400)
@given(facts_st)
def test_every_address_and_name_in_a_title_comes_from_the_facts(f: Facts) -> None:
    ips, names = _canonical([
        *(d.value for d in f.devices), *f.outsiders, *f.servers, *f.domains, *f.sites,
    ])  # fmt: skip
    words = " ".join([*(r for r, _ in f.rules), *(d.place or "" for d in f.devices)])
    values = {*(d.value for d in f.devices), *f.outsiders, *f.servers, *f.domains, *f.sites}
    for raw in title(f).replace("→", " ").replace("—", " ").split():
        if raw in words or raw.strip(",()").rstrip(":") in values:  # a host named "0.0" is a fact
            continue
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            token = raw.strip(",()").rstrip(":")
            if token not in words and "." in token and not token.endswith("."):
                assert token in names, token
        else:
            assert raw in ips, raw


@given(st.lists(st.ip_addresses(v=4), min_size=1, max_size=30, unique=True), st.integers(1, 40))
def test_counts_in_a_title_are_the_facts_counts(servers: list[object], n: int) -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(n), servers=tuple(str(s) for s in servers))
    out = title(f)
    if n > 1:
        assert f"{n} campus devices" in out
    if len(servers) > 1:
        assert f"{len(servers) - 1} more flagged server" in out or f"{len(servers)} flagged" in out


def test_attacked_paths_name_what_was_probed_in_fixed_words() -> None:
    envs = ("/.env.local", "/admin/.env", "/api/.env", "/.env.bak.zip~")
    assert naming.probed(envs) == ".env secrets files"
    assert naming.probed(("/@fs/proc", "/../etc/passwd")) == "path traversal"
    assert naming.probed(("/a", "/b", "/.git/config")) is None  # no kind holds 60 %
    assert naming.probed(()) is None
    f = naming.Facts(
        outsiders=("45.148.10.238", "103.215.74.112"),
        flags=frozenset({naming.SUCCESS}),
        probed=naming.probed(envs),
    )
    assert naming.title(f) == (
        "Probing for .env secrets files by 2 outside addresses — some got successful answers"
    )
    assert "Probing for" not in naming.title(dataclasses.replace(f, probed="<script>"))
