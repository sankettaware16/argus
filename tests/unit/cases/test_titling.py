"""Naming v2's facts read from what the database holds (the pure part of ``argus.cases.titling``):
campus devices with the asset map's place and zone (never its network equipment), which device did
what (the members' entities and flags), flagged servers and who flagged them, families from stored
threat names, the stored web checks (sites, 2xx answers, path checks), the verdicts, and the retitle
policy (what is a material change). Every value is made up; nothing here is a real alert."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from hypothesis import given
from hypothesis import strategies as st

from argus.assets import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.cases import naming, titling
from argus.cases.naming import BEACON, CAMPAIGN, OUTSIDE, PORTS
from argus.cases.titling import Context, Found, Member, facts_of, title_of

HOST = "10.20.36.30"
SERVERS = ("198.51.100.58", "198.51.100.59", "198.51.100.60")
ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - name: H12 Wing-C
    range: 10.20.36.0/24
    fields: {site.type: switch, site.zone: hostel, site.building: Hostel 12, site.wing: C}
  - name: H5
    range: 10.20.40.0/24
    fields: {site.type: gateway, site.zone: hostel, site.building: Hostel 5}
  - name: Physics
    range: 10.20.50.0/24
    fields: {site.type: lab, site.zone: department, site.department: Physics}
  - name: Twice
    range: 10.20.60.0/24
    fields: {site.type: lab, site.zone: department, site.building: One}
  - name: Twice again
    range: 10.20.60.0/24
    fields: {site.type: lab, site.zone: hostel, site.building: Two}
"""
)
CTX = Context(IpClassifier(ASSETS), ("example.edu",))
PLAIN = Context(None, ("example.edu",))
NOW = datetime(2026, 11, 6, 12, 0, tzinfo=UTC)


def vt(value: str, bad: int = 7, **more: Any) -> tuple[str, str, str, str, dict[str, Any]]:
    answer = {"malicious": bad, "suspicious": 0, "engines": 94, **more}
    return ("virustotal", "ip" if value[0].isdigit() else "domain", value, "found", answer)


def infected(**more: Any) -> Found:
    base: dict[str, Any] = {
        "members": [
            ("Rule download", (BEACON, OUTSIDE), ()),
            ("Rule beacon", (BEACON, OUTSIDE), ()),
        ],
        "indicators": [("ip", HOST, "actor"), *(("ip", s, "indicator") for s in SERVERS)],
        "outside": [vt(s) for s in SERVERS],
    }
    base.update(more)
    return Found(**base)


def test_a_host_beaconing_to_flagged_servers() -> None:
    assert title_of(infected(), PLAIN) == (
        f"Suspected beaconing from {HOST} to {SERVERS[0]} (VirusTotal: 7 engines)"
        " +2 flagged servers"
    )


def test_a_family_in_an_outside_tag_or_a_stored_threat_name_names_the_infection() -> None:
    tagged = infected(
        outside=[vt(SERVERS[0], tags=["amadey", "c2"]), vt(SERVERS[1]), vt(SERVERS[2])]
    )
    assert "Amadey beaconing" in str(title_of(tagged, PLAIN))
    labelled = infected(outside=[vt(SERVERS[0], threat_label="trojan.Emotet/x")])
    assert "Emotet beaconing" in str(title_of(labelled, PLAIN))
    threat = infected(members=[Member("Rule", (BEACON, OUTSIDE), (), threats=("PS1Bot C2",))])
    assert "PS1Bot beaconing" in str(title_of(threat, PLAIN))
    rule_only = infected(members=[("PS1Bot IOC match", (BEACON, OUTSIDE), ())])
    assert "PS1Bot" not in str(title_of(rule_only, PLAIN))  # a rule's name names no family


def test_a_clean_answer_is_no_flagged_server() -> None:
    found = infected(outside=[vt(s, bad=0) for s in SERVERS], members=[("Rule", (BEACON,), ())])
    assert title_of(found, PLAIN) == f"Suspected beaconing from {HOST}"


def test_virus_total_engines_are_read_from_the_newest_answer() -> None:
    found = infected(outside=[vt(SERVERS[0], bad=9), vt(SERVERS[0], bad=3)])
    assert facts_of(found, PLAIN).vt == {SERVERS[0]: 9}


def test_a_threat_listed_value_the_case_holds_is_a_server() -> None:
    found = Found(
        members=[("Rule", (BEACON,), (SERVERS[0],))],
        indicators=[("ip", HOST, "actor"), ("ip", SERVERS[0], "c2")],
    )
    assert title_of(found, PLAIN) == (
        f"Suspected beaconing from {HOST} to {SERVERS[0]} (on a threat list)"
    )


def test_the_asset_map_gives_the_place_and_the_zone_never_the_equipment() -> None:
    hosts = [("ip", f"10.20.36.{i}", "actor") for i in range(1, 5)]
    found = infected(indicators=[*hosts, ("ip", SERVERS[0], "indicator")], outside=[vt(SERVERS[0])])
    assert title_of(found, CTX) == (
        f"Suspected beaconing to {SERVERS[0]} (VirusTotal: 7 engines) from 4 campus devices"
        " in Hostel 12"
    )
    elsewhere = [*hosts[:2], ("ip", "10.20.40.7", "actor")]
    found = infected(indicators=[*elsewhere, ("ip", SERVERS[0], "indicator")],
                     outside=[vt(SERVERS[0])])  # fmt: skip
    assert title_of(found, CTX) == (
        f"Suspected beaconing to {SERVERS[0]} (VirusTotal: 7 engines) from 3 campus devices"
        " in hostels"
    )
    assert "switch" not in str(title_of(found, CTX))
    assert "gateway" not in str(title_of(found, CTX))
    device = facts_of(found, CTX).devices[0]
    assert (device.place, device.zone, device.type) == ("Hostel 12", "hostel", "switch")


def test_a_network_listed_twice_with_two_places_or_zones_names_none() -> None:
    hosts = [("ip", f"10.20.60.{i}", "actor") for i in (1, 2)]
    found = infected(indicators=[*hosts, ("ip", SERVERS[0], "indicator")], outside=[vt(SERVERS[0])])
    assert title_of(found, CTX) == (
        f"Suspected beaconing to {SERVERS[0]} (VirusTotal: 7 engines) from 2 campus devices"
    )


def test_without_the_asset_map_private_addresses_are_campus_devices() -> None:
    found = infected(indicators=[("ip", "192.168.1.9", "actor"), ("ip", SERVERS[0], "indicator")],
                     outside=[vt(SERVERS[0])])  # fmt: skip
    assert str(title_of(found, PLAIN)).startswith("Suspected beaconing from 192.168.1.9 to")
    public = infected(indicators=[("ip", "203.0.113.9", "actor"), ("ip", SERVERS[0], "indicator")])
    assert "beaconing" not in str(title_of(public, PLAIN))


def test_which_device_did_what_comes_from_the_members_entities() -> None:
    devices = [f"10.20.36.{i}" for i in range(1, 6)]
    members = [
        Member("Beacon rule", (BEACON,), (), (("ip", devices[0]), ("ip", SERVERS[0]))),
        Member("Beacon rule", (BEACON,), (), (("ip", devices[1]), ("ip", SERVERS[0]))),
        Member("Sweep rule", (PORTS,), (), (("ip", devices[2]),)),
        Member("Other rule", (), (), (("ip", devices[3]), ("ip", SERVERS[0]))),
        Member("Other rule", (), (), (("ip", devices[4]), ("domain", "cdn.example.net"))),
    ]
    found = Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in devices), ("ip", SERVERS[0], "indicator")],
        outside=[vt(SERVERS[0])],
    )
    facts = facts_of(found, CTX)
    assert facts.doing[BEACON] == frozenset(devices[:2])
    assert facts.doing[PORTS] == frozenset(devices[2:3])
    assert facts.reaches[SERVERS[0]] == frozenset({devices[0], devices[1], devices[3]})
    assert facts.destinations == ("cdn.example.net",)
    assert title_of(found, CTX) == (
        f"Suspected beaconing to {SERVERS[0]} (VirusTotal: 7 engines) from 2 of 5 campus devices"
        " in Hostel 12"
    )


def test_outside_actors_at_campus_sites_named_by_the_stored_checks() -> None:
    found = Found(
        members=[("Web scan", (), ())],
        indicators=[*(("ip", f"203.0.113.{i}", "actor") for i in range(1, 17)),
                    ("url", "/.git/config", "indicator"), ("url", "/.git/HEAD", "indicator")],
        answered=[("www.example.edu", "/.git/config"), ("evil.example.org", "/x")],
        outcomes=[("home.example.edu", "/.git/config", "success")],
    )  # fmt: skip
    facts = facts_of(found, PLAIN)
    assert facts.sites == ("www.example.edu", "home.example.edu")  # campus sites only
    assert title_of(found, PLAIN) == (  # the site that served the file is the one named
        "Suspected Git-folder scan of home.example.edu +1 site by 16 outside IPs"
        " — a Git file served"
    )


def test_a_threat_listed_outsider_probing_campus_servers() -> None:
    found = Found(
        members=[("Port probe", (naming.LISTED,), ("203.0.113.51",))],
        indicators=[("ip", "203.0.113.51", "actor"), ("ip", "10.20.36.5", "indicator"),
                    ("ip", "10.20.36.6", "indicator")],
    )  # fmt: skip
    assert title_of(found, PLAIN) == (
        "Suspected probing of 2 campus servers by 203.0.113.51 (on a threat list)"
    )


def test_nothing_to_name_is_no_title() -> None:
    assert title_of(Found(), PLAIN) is None
    assert title_of(Found(members=[("Rule", (), ())]), PLAIN) == "Suspected: alerts of rule 'Rule'"


def test_the_newest_outside_answer_is_the_one_read() -> None:
    """The rows come newest first: a clean answer after a flagged one clears the server."""
    cleared = infected(outside=[vt(SERVERS[0], bad=0), vt(SERVERS[0], bad=9)])
    assert facts_of(cleared, PLAIN).servers == ()
    flagged = infected(outside=[vt(SERVERS[0], bad=9), vt(SERVERS[0], bad=0)])
    assert facts_of(flagged, PLAIN).servers == (SERVERS[0],)


def test_the_campus_domain_pattern_matches_the_domain_and_what_is_below_it() -> None:
    import re

    pattern = re.compile(titling._own_pattern(("example.edu", "example-univ.org")), re.I)
    assert pattern.search("www.example.edu")
    assert pattern.search("EXAMPLE.EDU")
    assert not pattern.search("example.edu.evil.com")
    assert not pattern.search("notexample.edu")
    assert not re.compile(titling._own_pattern(())).search("anything")


# -- the verdicts ----------------------------------------------------------------------------------


def test_the_verdicts_people_and_argus_gave() -> None:
    members = [
        Member("R", said=("proposal", "true_positive")),
        Member("R", said=("reading", "benign_expected")),
        Member("R", reviewed="true_positive"),
    ]
    v = titling.verdict_of(members, None, False)
    assert v == naming.Verdict("true_positive", False, ("true_positive",), ("benign_expected",))
    assert titling.verdict_of(members, "benign_expected", True).person == "benign_expected"
    assert titling.people([]) is None
    assert titling.people(["true_positive", "true_positive", "benign_expected"]) == "true_positive"
    assert titling.people(["true_positive", "benign_expected"]) == "inconclusive"


def test_a_decision_on_the_report_makes_it_confirmed() -> None:
    found = infected(decision="true_positive")
    assert str(title_of(found, PLAIN)).startswith("Confirmed beaconing")
    opened = infected(opened=True)
    assert str(title_of(opened, PLAIN)).startswith("Confirmed beaconing")


def _row(member: str, assessor: str, status: str, outcome: str | None, reasons: Any = None,
         shared: bool = False) -> SimpleNamespace:  # fmt: skip
    return SimpleNamespace(member=member, assessor=assessor, status=status, outcome=outcome,
                           reasons=reasons or [], shared=shared)  # fmt: skip


def test_argus_own_word_ranks_a_proposal_before_a_reading() -> None:
    reading = {"reading": {"kind": "floor"}, "answer": {"outcome": "benign_expected"}}
    rows = [
        _row("a", "agent:investigator", "no_decision", None, [reading]),
        _row("a", "engine", "proposed", "true_positive"),
        _row("b", "agent:investigator", "no_decision", None, [reading]),
        _row("c", "engine", "no_decision", None, ["nothing"]),
    ]
    said = titling.best_said(rows)
    assert said["a"] == ("proposal", "true_positive")
    assert said["b"] == ("reading", "benign_expected")
    assert "c" not in said


# -- what the dossiers and the stored checks hold --------------------------------------------------


def test_threat_names_are_the_descriptions_of_the_values_listed() -> None:
    answers = [
        {"value": SERVERS[0], "sources": {"list": {"match": [{"description": "PS1Bot C2"}]}}},
        {"value": SERVERS[1], "sources": {"list": {"match": [{"description": "Other"}]}}},
        {"value": SERVERS[0], "sources": {"list": {"no_match": {}}}},
        "garbage",
        {"value": SERVERS[0], "sources": "x"},
    ]
    assert titling.threat_names(answers, [SERVERS[0]]) == ("PS1Bot C2",)
    assert titling.threat_names(None, [SERVERS[0]]) == ()


def test_a_followup_answer_gives_its_site_and_path() -> None:
    snapshot = {"rows": [
        {"_source": {"url": {"domain": "www.example.edu", "path": "/.env"},
                     "http": {"response": {"status_code": 200}}}},
        {"_source": {"url": {"domain": "www.example.edu", "path": "/x"},
                     "http": {"response": {"status_code": 404}}}},
        {"_source": {"url": {"path": "/no-site"}, "http": {"response": {"status_code": 200}}}},
        "garbage",
    ]}  # fmt: skip
    assert titling.followup_answers(snapshot) == [("www.example.edu", "/.env")]
    assert titling.followup_answers(None) == []
    assert titling.followup_answers({"rows": "x"}) == []


@given(st.recursive(st.none() | st.booleans() | st.integers() | st.text(max_size=8),
                    lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=8), c,
                                                                         max_size=3),
                    max_leaves=12))  # fmt: skip
def test_odd_stored_json_never_breaks_the_reading(value: Any) -> None:
    titling.followup_answers(value)
    titling.followup_answers({"rows": [value]})
    titling.threat_names(value, ["x"])
    titling.threat_names([value], ["x"])


# -- the retitle policy ----------------------------------------------------------------------------

OLD = f"Likely beaconing to {SERVERS[0]} from 12 of 22 campus devices"


def test_a_material_change_is_retitled_at_once() -> None:
    assert titling.material(OLD, OLD.replace("Likely", "Confirmed"), NOW, NOW)
    assert titling.material(OLD, OLD.replace("beaconing to", "contact with"), NOW, NOW)
    assert titling.material(OLD, OLD.replace("12 of 22", "11 of 22"), NOW, NOW)  # shrank
    assert titling.material(OLD, OLD.replace("12 of 22", "18 of 22"), NOW, NOW)  # grew by half
    assert not titling.material(OLD, OLD, NOW, NOW)


def test_a_small_count_change_waits_six_hours() -> None:
    bump = OLD.replace("12 of 22", "13 of 23")
    assert not titling.material(OLD, bump, NOW - timedelta(hours=5), NOW)
    assert titling.material(OLD, bump, NOW - timedelta(hours=6), NOW)
    assert titling.material(OLD, bump, None, NOW)


def test_a_new_address_case_or_place_is_material_at_once_and_said_as_new_facts() -> None:
    old = "Likely beaconing from 10.0.4.12 to 203.0.113.5 (VirusTotal: 4 engines)"
    new = old.replace("10.0.4.12", "10.0.4.13").replace("203.0.113.5", "203.0.113.6")
    assert titling.material(old, new, NOW - timedelta(hours=1), NOW)
    assert titling.why(naming.change_of(old, new), old, new) == "the facts changed"
    place = f"Suspected beaconing to {SERVERS[0]} from 4 campus devices in Hostel 12"
    assert titling.material(place, place.replace("Hostel 12", "Hostel 13"), NOW, NOW)
    case = f"Likely beaconing from {HOST} to {SERVERS[0]}, the server of case 3"
    assert titling.material(case, case.replace("case 3", "case 4"), NOW, NOW)


def test_the_reason_says_what_changed() -> None:
    assert titling.why("certainty", OLD, OLD.replace("Likely", "Confirmed")) == (
        "the certainty changed: Likely → Confirmed"
    )
    assert titling.why("counts", OLD, OLD) == "the counts changed"
    assert titling.why("words", OLD, OLD) == "the facts changed"
    assert titling.why("certainty", "Beaconing", "Likely beaconing") == (
        "the certainty changed: none → Likely"
    )


def test_a_beacon_names_only_a_destination_its_own_timed_investigation_names() -> None:
    """A sweep of the same device named other servers: "beaconing to" says the beacon's own."""
    members = [
        Member("Beacon rule", (BEACON,), (), (("ip", HOST), ("ip", "192.0.2.30"))),
        Member("Sweep rule", (PORTS,), (), (("ip", HOST), *(("ip", f"192.0.2.{i}") for i in
                                                               range(40, 49)))),
    ]  # fmt: skip
    found = Found(members=members, indicators=[("ip", HOST, "actor")])
    facts = facts_of(found, CTX)
    assert facts.beacon_reaches == {"192.0.2.30": frozenset({HOST})}
    assert title_of(found, CTX) == f"Suspected beaconing from {HOST} (Hostel 12) to 192.0.2.30"


def test_dns_beaconing_pairs_the_flag_with_the_names_on_one_investigation() -> None:
    """The campaign flag on one investigation of a device, the look-alike names on another of its
    investigations: DNS look-ups, not DNS beaconing; the C2 beacon of one device is beaconing."""
    devices = [f"10.20.36.{i}" for i in range(1, 6)]
    names = ["a1.example-bad.example", "a2.example-bad.example"]
    members = [
        Member("Beacon rule", (BEACON,), (), (("ip", devices[0]), ("ip", "192.0.2.30"))),
        Member("Campaign rule", (CAMPAIGN,), (), (("ip", devices[1]),)),
        *(Member("DNS rule", (), (), (("ip", d), *(("domain", n) for n in names)))
          for d in devices),
    ]  # fmt: skip
    found = Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in devices), *(("domain", n, "indicator")
                                                              for n in names)],
    )  # fmt: skip
    facts = facts_of(found, CTX)
    assert facts.campaign_reaches is not None
    assert names[0] not in facts.campaign_reaches  # the flagged investigation names no name
    assert title_of(found, CTX) == (  # its place is the first detail to go (101 characters)
        "Suspected DNS look-ups of 2 look-alike names under example-bad.example"
        " from 5 campus devices"
    )
    paired = Found(
        members=[*members, Member("Campaign rule", (CAMPAIGN,), (),
                                  (("ip", devices[2]), ("domain", names[0])))],
        indicators=found.indicators,
    )  # fmt: skip
    assert title_of(paired, CTX) == (
        f"Suspected DNS beaconing to example-bad.example from {devices[2]} (Hostel 12)"
    )


def scan(order: list[str], counts: dict[str, int], current: str | None = None) -> Found:
    members = [Member("Web scan", (), (), (("domain", site),)) for site in order
               for _ in range(counts[site])]  # fmt: skip
    return Found(
        members=members,
        indicators=[*(("ip", f"203.0.113.{i}", "actor") for i in range(1, 7)),
                    ("url", "/.env", "indicator")],
        sites=order, checks=frozenset({"ok"}), current=current,
    )  # fmt: skip


def test_the_site_a_title_names_stays_while_it_is_about_as_common() -> None:
    a, b = "a.example.edu", "b.example.edu"
    first = title_of(scan([a, b], {a: 5, b: 4}), PLAIN)
    assert first is not None
    assert f"of {a} +1 site" in first
    # b is now the commoner, but not by half: the title keeps naming a
    assert title_of(scan([b, a], {a: 5, b: 6}, first), PLAIN) == first
    # b by half: it leads
    moved = title_of(scan([b, a], {a: 5, b: 8}, first), PLAIN)
    assert moved is not None
    assert f"of {b} +1 site" in moved
    assert title_of(scan([b, a], {a: 5, b: 8}), PLAIN) == moved  # no title yet: the commonest


def test_sticky_keeps_the_named_value_first_until_the_leader_outweighs_it_by_half() -> None:
    a, b, c = "a.example.edu", "b.example.edu", "aa.example.edu"
    named = f"Likely .env scan of {a} +1 site by 6 outside IPs"
    assert titling.sticky([b, a], {a: 5, b: 7}, named) == [a, b]
    assert titling.sticky([b, a], {a: 4, b: 6}, named) == [b, a]
    assert titling.sticky([b, a], {}, named) == [a, b]  # no weights: it stays
    assert titling.sticky([b, a], {a: 5, b: 7}, None) == [b, a]
    assert titling.sticky([b, c], {b: 7, c: 1}, named) == [b, c]  # "aa." is not "a."
    assert titling.sticky([], {}, named) == []


def test_the_destination_a_beacon_title_names_stays_too() -> None:
    devices = [f"10.20.36.{i}" for i in range(1, 12)]
    x, y = "192.0.2.40", "192.0.2.41"

    def beacons(to_x: int, to_y: int, current: str | None = None) -> Found:
        members = [
            Member("Beacon rule", (BEACON,), (), (("ip", d), ("ip", x))) for d in devices[:to_x]
        ]
        members += [Member("Beacon rule", (BEACON,), (), (("ip", d), ("ip", y)))
                    for d in devices[to_x:to_x + to_y]]  # fmt: skip
        return Found(members=members, indicators=[("ip", d, "actor") for d in devices],
                     current=current)  # fmt: skip

    first = title_of(beacons(5, 4), CTX)
    assert first is not None
    assert f"beaconing to {x} +1 outside server" in first
    later = title_of(beacons(5, 6, first), CTX)  # y has 6, not 1.5 times x's 5: x stays
    assert later is not None
    assert f"beaconing to {x} +1 outside server" in later
    assert f"to {y} +1" in str(title_of(beacons(3, 8, first), CTX))
