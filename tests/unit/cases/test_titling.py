"""D-230: the facts of a title read from what the database holds (the pure part of
``argus.cases.titling``): campus devices and the asset map's places, flagged servers from the
indicators, the outside answers and the threat lists, families from outside tags, campus sites.
Every address is a documentation or private one; nothing here is a real alert."""

from __future__ import annotations

from typing import Any

from argus.assets import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.cases import naming, titling
from argus.cases.naming import BEACON, OUTSIDE
from argus.cases.titling import Context, Found, facts_of, title_of

HOST = "10.198.36.230"
SERVERS = ("176.65.139.158", "176.65.139.159", "176.65.139.160")
ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - name: H12 Wing-C
    range: 10.198.36.0/24
    fields: {site.type: hostel, site.building: Hostel 12, site.wing: C}
  - name: H5
    range: 10.198.40.0/24
    fields: {site.type: hostel, site.building: Hostel 5}
  - name: Physics
    range: 10.198.50.0/24
    fields: {site.type: lab, site.department: Physics}
  - name: Twice
    range: 10.198.60.0/24
    fields: {site.type: lab, site.building: One}
  - name: Twice again
    range: 10.198.60.0/24
    fields: {site.type: lab, site.building: Two}
"""
)
CTX = Context(IpClassifier(ASSETS), ("example.edu",))
PLAIN = Context(None, ("example.edu",))


def vt(value: str, bad: int = 7, **more: Any) -> tuple[str, str, str, str, dict[str, Any]]:
    answer = {"malicious": bad, "suspicious": 0, "engines": 94, **more}
    return ("virustotal", "ip" if value[0].isdigit() else "domain", value, "found", answer)


def amadey(**more: Any) -> Found:
    base: dict[str, Any] = {
        "members": [
            ("Rule download", (BEACON, OUTSIDE), ()),
            ("Rule beacon", (BEACON, OUTSIDE), ()),
        ],
        "indicators": [
            ("ip", HOST, "actor"),
            *(("ip", s, "indicator") for s in SERVERS),
        ],
        "outside": [vt(s) for s in SERVERS],
    }
    base.update(more)
    return Found(**base)


def test_the_amadey_host_with_its_flagged_servers() -> None:
    assert title_of(amadey(), PLAIN) == (
        "Beaconing to 176.65.139.158 and 2 more flagged servers from 10.198.36.230"
    )


def test_a_family_in_an_outside_tag_names_the_infection() -> None:
    found = amadey(outside=[vt(SERVERS[0], tags=["amadey", "c2"]), vt(SERVERS[1]), vt(SERVERS[2])])
    assert title_of(found, PLAIN) == (
        "Amadey beaconing from 10.198.36.230 to 176.65.139.158 and 2 more flagged servers"
    )
    labelled = amadey(outside=[vt(SERVERS[0], threat_label="trojan.Emotet/x")])
    assert "Emotet beaconing" in str(title_of(labelled, PLAIN))


def test_a_clean_answer_is_no_flagged_server() -> None:
    found = amadey(outside=[vt(s, bad=0) for s in SERVERS], members=[("Rule", (BEACON,), ())])
    assert title_of(found, PLAIN) == "Beaconing from 10.198.36.230"


def test_a_threat_listed_value_the_case_holds_is_a_server() -> None:
    found = Found(
        members=[("Rule", (BEACON,), (SERVERS[0],))],
        indicators=[("ip", HOST, "actor"), ("ip", SERVERS[0], "c2")],
    )
    assert title_of(found, PLAIN) == "Beaconing to 176.65.139.158 from 10.198.36.230"


def test_the_asset_map_names_the_place_devices_share() -> None:
    hosts = [("ip", f"10.198.36.{i}", "actor") for i in range(1, 5)]
    found = amadey(indicators=[*hosts, *(("ip", s, "indicator") for s in SERVERS[:1])],
                   outside=[vt(SERVERS[0])])  # fmt: skip
    assert title_of(found, CTX) == (
        "Beaconing to 176.65.139.158 from 4 campus devices in Hostel 12"
    )
    elsewhere = [*hosts[:2], ("ip", "10.198.40.7", "actor")]
    found = amadey(
        indicators=[*elsewhere, ("ip", SERVERS[0], "indicator")], outside=[vt(SERVERS[0])]
    )
    assert title_of(found, CTX) == "Beaconing to 176.65.139.158 from 3 hostel devices"


def test_a_network_listed_twice_with_two_places_names_none() -> None:
    hosts = [("ip", f"10.198.60.{i}", "actor") for i in (1, 2)]
    found = amadey(indicators=[*hosts, ("ip", SERVERS[0], "indicator")], outside=[vt(SERVERS[0])])
    assert title_of(found, CTX) == "Beaconing to 176.65.139.158 from 2 lab devices"


def test_a_department_names_the_place_when_there_is_no_building() -> None:
    hosts = [("ip", f"10.198.50.{i}", "actor") for i in (1, 2)]
    found = amadey(indicators=[*hosts, ("ip", SERVERS[0], "indicator")], outside=[vt(SERVERS[0])])
    assert title_of(found, CTX) == "Beaconing to 176.65.139.158 from 2 campus devices in Physics"


def test_without_the_asset_map_private_addresses_are_campus_devices() -> None:
    found = amadey(indicators=[("ip", "192.168.1.9", "actor"), ("ip", SERVERS[0], "indicator")],
                   outside=[vt(SERVERS[0])])  # fmt: skip
    assert title_of(found, PLAIN) == "Beaconing to 176.65.139.158 from 192.168.1.9"
    public = amadey(indicators=[("ip", "203.0.113.9", "actor"), ("ip", SERVERS[0], "indicator")])
    assert not str(title_of(public, PLAIN)).startswith("Beaconing")


def test_outside_actors_at_campus_sites_and_a_served_config_file() -> None:
    found = Found(
        members=[("Web scan", (), ())],
        indicators=[
            *(("ip", f"203.0.113.{i}", "actor") for i in range(1, 17)),
            ("domain", "www.example.example.edu", "indicator"),
            ("url", "/~hostel5/.git", "indicator"),
        ],
        sites=["home.example.edu"],
        served=True,
    )
    assert title_of(found, PLAIN) == (
        "Web scanning of home.example.edu and 1 more campus site by 16 outside addresses"
        " — config files served"
    )


def test_a_threat_listed_outsider_probing_campus_servers() -> None:
    found = Found(
        members=[("Web scan", (naming.LISTED,), ("45.138.12.51",))],
        indicators=[
            ("ip", "45.138.12.51", "actor"),
            ("ip", "10.198.36.5", "indicator"),
            ("ip", "10.198.36.6", "indicator"),
        ],
    )
    assert title_of(found, PLAIN) == "Threat-listed 45.138.12.51 probing 2 campus servers"


def test_names_under_one_parent_are_a_dns_campaign() -> None:
    found = Found(
        members=[("DNS rule", (), ())],
        indicators=[
            *(("ip", f"10.198.36.{i}", "actor") for i in range(1, 36)),
            *(("domain", f"r{i}x.fast-dns-host.com", "indicator") for i in range(12)),
            ("ip", SERVERS[0], "indicator"),
        ],
        outside=[vt(SERVERS[0])],
    )
    assert title_of(found, PLAIN) == (
        "DNS lookups of 12 look-alike domains under fast-dns-host.com from 35 campus devices"
    )


def test_nothing_to_name_is_no_title() -> None:
    assert title_of(Found(), PLAIN) is None
    assert title_of(Found(members=[("Rule", (), ())]), PLAIN) == "Rule"


def test_the_newest_outside_answer_is_the_one_read() -> None:
    """The rows come newest first: a clean answer after a flagged one clears the server."""
    cleared = amadey(outside=[vt(SERVERS[0], bad=0), vt(SERVERS[0], bad=9)])
    assert facts_of(cleared, PLAIN).servers == ()
    flagged = amadey(outside=[vt(SERVERS[0], bad=9), vt(SERVERS[0], bad=0)])
    assert facts_of(flagged, PLAIN).servers == (SERVERS[0],)


def test_the_campus_domain_pattern_matches_the_domain_and_what_is_below_it() -> None:
    import re

    pattern = re.compile(titling._campus_pattern(("example.edu", "example-univ.org")), re.I)
    assert pattern.search("www.example.edu")
    assert pattern.search("EXAMPLE.EDU")
    assert not pattern.search("example.edu.evil.com")
    assert not pattern.search("notexample.edu")
    assert not re.compile(titling._campus_pattern(())).search("anything")
