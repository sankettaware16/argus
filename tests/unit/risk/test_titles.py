"""Incident titles from the engine's facts, rule by rule: who did it is the incident's own device
objects, the destination and "the server of case N" come from the linker, "served" only from the
checking lane, the family from threat names and campaigns, the place from the asset map's zone,
the certainty word is the caller's, and a retitle follows only the lifecycle's material change
(the certainty word aside), never taking a person's confirmation back."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.cases import naming
from argus.risk import titles
from argus.risk.exposure import CheckRow, PairFacts
from argus.risk.titles import LinkFacts, retitle, title_for_incident
from tests.unit.risk.titles_kit import chain, dev, grp, host, incident, site

pytestmark = pytest.mark.unit
SERVER = "203.0.113.10"
WEBSITE = "www.dept-a.example.edu"


def beacons(n: int, timed: int, **more: Any) -> titles.IncidentFacts:
    devices = [dev(f"10.40.1.{i + 1}") for i in range(n)]
    groups = [grp({d: {"beacon"} if i < timed else ()}, threats=[SERVER])
              for i, d in enumerate(devices)]  # fmt: skip
    return incident(
        groups,
        links=chain(devices, "flagged", f"ip:{SERVER}"),
        flags={f"ip:{SERVER}": "outside"},
        **more,
    )


def test_the_device_count_is_the_incidents_devices_never_its_alert_rows() -> None:
    d = dev("10.40.1.1")
    many = [grp({d: {"beacon"}}, threats=[SERVER]) for _ in range(40)]  # 40 alert groups
    made = title_for_incident(incident(many, flags={f"ip:{SERVER}": "outside"}))
    assert made.text == f"Suspected beaconing from 10.40.1.1 to {SERVER}"


def test_a_devices_days_are_one_device() -> None:
    days = [dev("10.40.1.1", f"2026-11-0{i}") for i in (1, 2, 3)]
    groups = [grp({d: {"beacon"}}, threats=[SERVER]) for d in days]
    made = title_for_incident(incident(groups, flags={f"ip:{SERVER}": "outside"}))
    assert made.text == f"Suspected beaconing from 10.40.1.1 to {SERVER}"


def test_an_address_and_its_host_name_without_a_host_link_are_two_devices() -> None:
    a, h = dev("10.40.3.8"), host("lab-pc-08")
    groups = [grp({a: {"beacon"}}, threats=[SERVER]), grp({h: {"beacon"}}, threats=[SERVER])]
    assert "2 campus devices" in title_for_incident(incident(groups)).text
    joined = incident(groups, links=[LinkFacts(a, h, "host", "host:lab-pc-08")])
    assert title_for_incident(joined).text == f"Suspected beaconing from 10.40.3.8 to {SERVER}"


def test_n_of_m_counts_the_devices_whose_own_groups_carry_the_beacon() -> None:
    made = title_for_incident(beacons(7, 3, vt={SERVER: 5}), naming.LIKELY)
    assert made.text == (
        f"Likely beaconing to {SERVER} (VirusTotal: 5 engines) from 3 of 7 campus devices"
    )
    assert any(c.fact == "actors:beacon:3:7" for c in made.claims)


def test_a_device_that_only_reached_the_server_is_contact() -> None:
    made = title_for_incident(beacons(4, 0))
    assert made.text == f"Suspected contact with {SERVER} from 4 campus devices"


def test_a_destination_is_one_the_links_carry_or_a_beacon_timed_group_names() -> None:
    d = dev("10.40.1.1")
    plain = grp({d: ()}, threats=["198.51.100.1"])  # named, but not by the timed group
    timed = grp({d: {"beacon"}}, threats=["198.51.100.2"])
    made = title_for_incident(incident([plain, timed]))
    assert made.text == "Suspected beaconing from 10.40.1.1 to 198.51.100.2"
    alone = title_for_incident(incident([plain, grp({d: {"beacon"}})]))
    assert alone.text == "Suspected beaconing from 10.40.1.1"


def test_the_server_of_another_incidents_case_and_never_the_one_it_follows() -> None:
    f = incident([grp({dev("10.40.1.1"): {"beacon"}}, threats=["198.51.100.9"])],
                 others={"198.51.100.9": 14})  # fmt: skip
    assert title_for_incident(f).text.endswith("to 198.51.100.9, the server of case 14")
    followed = replace(f, follows=14)
    assert title_for_incident(followed).text == (
        "Suspected beaconing from 10.40.1.1 to 198.51.100.9 — follows case 14"
    )


def test_a_family_from_the_threat_names_or_a_campaigns_threat_never_a_rule() -> None:
    f = beacons(3, 3, labels={SERVER: ("win.amadey",)})
    assert title_for_incident(f).text.startswith("Suspected Amadey beaconing to")
    by_rule = beacons(3, 3)
    by_rule = replace(by_rule, groups=tuple(replace(g, rule="Amadey C2 rule")
                                            for g in by_rule.groups))  # fmt: skip
    assert "Amadey" not in title_for_incident(by_rule).text
    devices = [dev("10.40.2.1"), dev("10.40.2.2")]
    bound = incident([grp({d: {"beacon"}}, threats=[SERVER]) for d in devices],
                     links=chain(devices, "campaign", "campaign:domain:c2.example,ip:198.51.100.5"),
                     labels={"198.51.100.5": ("PS1Bot",)})  # fmt: skip
    assert title_for_incident(bound).text.startswith("Suspected PS1Bot beaconing")


def test_the_place_is_the_zone_or_building_of_the_counted_devices_never_the_equipment() -> None:
    hostel = [dev("10.20.4.7"), dev("10.20.9.7")]
    f = incident([grp({d: {"beacon"}}, threats=[SERVER]) for d in hostel],
                 flags={f"ip:{SERVER}": "outside"})  # fmt: skip
    assert title_for_incident(f).text.endswith("from 2 campus devices in hostels")
    switch = incident([grp({dev("10.40.9.9"): {"beacon"}}, threats=[SERVER])])
    assert "switch" not in title_for_incident(switch).text


def test_served_only_when_the_checking_lane_verified_it() -> None:
    def scan(**more: Any) -> titles.IncidentFacts:
        groups = [grp({site(WEBSITE): {"success"}}, actors=[f"198.51.100.{i}"], paths=["/.env"],
                      answered=[(WEBSITE, "/.env")]) for i in (20, 21)]  # fmt: skip
        return incident(groups, **more)

    assert title_for_incident(scan()).text.endswith("— got HTTP 200, not verified")
    served = PairFacts("198.51.100.20", WEBSITE, served=("/.env",), through=("/.env",))
    assert title_for_incident(scan(exposure=[served])).text.endswith("— a .env file served")
    elsewhere = replace(served, site="other.example.edu")  # a site the incident does not hold
    assert "served" not in title_for_incident(scan(exposure=[elsewhere])).text
    stranger = replace(served, source="198.51.100.99")  # an address that did not attack it
    assert "served" not in title_for_incident(scan(exposure=[stranger])).text
    through = replace(served, served=())  # verified as no catch-all page, not shown served
    assert title_for_incident(scan(exposure=[through])).text.endswith("not verified")
    bulk = PairFacts("198.51.100.20", WEBSITE, bulk=40, bulk_prefix="/.git/")
    assert title_for_incident(scan(exposure=[bulk])).text.endswith("— a Git file served")
    catch = title_for_incident(scan(catch_all=[(WEBSITE, "/.env")])).text
    assert catch.endswith("— the site answers every path alike")


def test_a_rule_that_says_served_changes_nothing() -> None:
    groups = [grp({site(WEBSITE): ()}, actors=["198.51.100.20"], paths=["/.env"],
                  rule="Sensitive File Served Successfully")]  # fmt: skip
    assert "served" not in title_for_incident(incident(groups)).text


def test_the_web_title_says_outside_ips_and_names_the_site() -> None:
    groups = [grp({site(WEBSITE): ()}, actors=[f"198.51.100.{i}"], paths=["/wp-login.php"])
              for i in range(5)]  # fmt: skip
    made = title_for_incident(incident(groups), naming.LIKELY)
    assert made.text == f"Likely WordPress scan of {WEBSITE} by 5 outside IPs — no web check yet"
    assert made.kibana == f"WordPress scan of {WEBSITE} by 5 outside IPs — no web check yet"


def test_the_certainty_word_is_the_callers() -> None:
    f = beacons(2, 2)
    for word in naming.CERTAINTIES:
        made = title_for_incident(f, word)
        assert made.text.startswith(word + (": " if word in naming.COLON else " "))
        assert made.claims[0] == naming.Claim(
            "certainty", word + (":" if word in naming.COLON else ""), f"certainty:{word}"
        )
    assert title_for_incident(f).certainty == naming.SUSPECTED
    with pytest.raises(ValueError, match="not a certainty word"):
        title_for_incident(f, "Definitely")


def test_every_claim_is_backed_by_the_facts() -> None:
    f = beacons(5, 2, vt={SERVER: 3}, labels={SERVER: ("Lumma",)})
    made = title_for_incident(f, naming.LIKELY)
    facts = replace(titles.naming_facts(f), verdict=naming.Verdict(given=naming.LIKELY))
    assert naming.check(naming.Titled(made.parts), facts) == []
    assert made.text.startswith("Likely Lumma beaconing")


def test_facts_that_say_nothing_give_the_empty_title() -> None:
    assert title_for_incident(titles.IncidentFacts()).empty


# --------------------------------------------------------------------------- retitles


OLD = f"Likely beaconing to {SERVER} from 3 of 7 campus devices"


def test_no_title_yet_takes_the_facts_title() -> None:
    made = retitle(None, beacons(7, 3), naming.LIKELY, material=False)
    assert made is not None
    assert made.reason == "new"
    assert retitle(None, titles.IncidentFacts(), material=True) is None  # nothing to say


def test_without_a_material_change_the_words_stay() -> None:
    grown = beacons(9, 5)  # more devices, but the lifecycle saw nothing material
    assert retitle(OLD, grown, naming.LIKELY, material=False) is None
    made = retitle(OLD, grown, naming.LIKELY, material=True)
    assert made is not None
    assert made.reason == "material"
    assert made.text == f"Likely beaconing to {SERVER} from 5 of 9 campus devices"


def test_only_the_certainty_word_follows_between_material_changes() -> None:
    made = retitle(OLD, beacons(9, 5), naming.UNCLEAR, material=False)
    assert made is not None
    assert made.reason == "certainty"
    assert made.text == f"Unclear: beaconing to {SERVER} from 3 of 7 campus devices"
    assert [c.slot for c in made.claims] == ["certainty"]
    assert "".join(p if isinstance(p, str) else p.words for p in made.parts) == made.text
    same = retitle(OLD, beacons(7, 3), naming.SUSPECTED, material=False)
    assert same is not None
    assert same.text == OLD.replace("Likely", "Suspected", 1)


def test_a_persons_confirmation_is_never_taken_back() -> None:
    confirmed = OLD.replace("Likely", "Confirmed", 1)
    for word in naming.CERTAINTIES:
        for material in (False, True):
            made = retitle(confirmed, beacons(9, 5), word, material=material, confirmed=True)
            assert made is None or made.text.startswith("Confirmed ")
    made = retitle(OLD, beacons(7, 3), naming.LIKELY, material=False, confirmed=True)
    assert made is not None
    assert made.text.startswith("Confirmed beaconing")


def test_a_persons_title_is_theirs() -> None:
    mine = "Amadey on the lab PC (SOC-IR-2026-1101-01)"
    assert retitle(mine, beacons(9, 5), naming.LIKELY, material=True, by_person=True) is None
    assert retitle(mine, beacons(9, 5), naming.LIKELY, material=False) is None  # no word to swap


def test_material_since_reads_the_lifecycles_version() -> None:
    assert titles.material_since(None, 1)
    assert titles.material_since(1, 2)
    assert not titles.material_since(2, 2)


# --------------------------------------------------------------------------- the pieces


def test_campaign_threats_read_both_binding_keys() -> None:
    assert titles.campaign_threats("campaign:domain:a.example,ip:198.51.100.5") == [
        "domain:a.example", "ip:198.51.100.5"
    ]  # fmt: skip
    assert titles.campaign_threats("threat:ip:198.51.100.5") == ["ip:198.51.100.5"]
    assert titles.campaign_threats("campaign") == []


def test_a_thing_is_keyed_as_the_engine_keys_it() -> None:
    assert titles.thing("domain", "X1.Cdn.Example.COM.") == "domain:example.com"
    assert titles.thing("ip", "198.51.100.5") == "ip:198.51.100.5"


def _row(kind: str, verdict: str, facts: dict[str, object], *, day: int = 2) -> CheckRow:
    source = None if kind == "catchall" else "198.51.100.20"
    return CheckRow(kind, source, WEBSITE, date(2026, 11, day), verdict, facts,
                    datetime(2026, 11, day, 10, tzinfo=UTC))  # fmt: skip


def test_catch_all_paths_are_the_2xx_the_soft_404_check_did_not_let_through() -> None:
    paths = _row("paths", "ok", {"paths": [
        {"path": "/.env", "outcome": "success", "sizes": {"5120": 1}},
        {"path": "/.git/config", "outcome": "possible", "sizes": {"5120": 1}},
        {"path": "/backup.zip", "outcome": "success", "sizes": {}},  # no size: unverified
        {"path": "/x", "outcome": "not_found", "sizes": {"731": 1}},
    ]})  # fmt: skip
    page = _row("catchall", "soft_404", {})
    pair = PairFacts("198.51.100.20", WEBSITE, through=("/.git/config",))
    found = titles.catch_all_of([paths, page], {("198.51.100.20", WEBSITE): pair})
    assert found == {(WEBSITE, "/.env")}
    assert titles.catch_all_of([paths], {}) == frozenset()  # no soft-404 check: none judged
    far = _row("catchall", "soft_404", {}, day=9)
    assert titles.catch_all_of([paths, far], {}) == frozenset()
    unknown = _row("catchall", "unknown", {})
    assert titles.catch_all_of([paths, unknown], {}) == frozenset()


def test_naming_takes_the_given_word_and_ignores_an_unknown_one() -> None:
    evidence = naming.Facts(flags=frozenset({naming.BEACON}))
    given = replace(evidence, verdict=naming.Verdict(given=naming.LIKELY))
    assert naming.certainty(given) == naming.LIKELY
    unknown = replace(evidence, verdict=naming.Verdict(given="Surely"))
    assert naming.certainty(unknown) == naming.SUSPECTED
    person = replace(evidence, verdict=naming.Verdict(person="true_positive", given=naming.UNCLEAR))
    assert naming.certainty(person) == naming.UNCLEAR  # the caller decided for all of them


def test_the_fallbacks_certainty_word_splits_off_with_its_colon() -> None:
    text = "Suspected: alerts of rule 'Proxy rule' for 10.40.1.5"
    rest = "alerts of rule 'Proxy rule' for 10.40.1.5"
    assert titles.split_certainty(text) == ("Suspected", rest)
    made = titles.Title(text, naming.SUSPECTED)
    assert made.kibana == "Alerts of rule 'Proxy rule' for 10.40.1.5"
    assert titles.split_certainty("Likely harmless: beaconing") == ("Likely harmless", "beaconing")
    assert titles.split_certainty("Likely beaconing") == ("Likely", "beaconing")
    assert titles.split_certainty("Unclear beaconing") == (None, "Unclear beaconing")
    assert naming.split_certainty(text) == (None, text)  # phase 1's own split is unchanged


def test_a_flagged_thing_several_devices_reached_is_no_dns_campaign() -> None:
    devices = [dev(f"10.40.6.{i}") for i in (1, 2, 3)]
    names = ["a1.lookalike.example.com", "b2.lookalike.example.com"]
    groups = [grp({d: ()}, threats=names) for d in devices]
    family = incident(groups, links=chain(devices, "campaign", "campaign:domain:example.com"))
    assert "DNS beaconing to example.com" in title_for_incident(family).text
    flagged = incident(groups, links=chain(devices, "campaign", "threat:domain:example.com"))
    assert "DNS beaconing" not in title_for_incident(flagged).text


@given(
    st.dictionaries(
        st.from_regex(r"[a-c]{1,2}(\.[a-c]{1,2}){0,3}\.example\.com\.?", fullmatch=True),
        st.frozensets(st.sampled_from(["10.0.0.1", "10.0.0.2", "10.0.0.3"]), max_size=2),
        max_size=90,
    ),
    st.lists(st.from_regex(r"([a-c]{1,2}\.){0,2}example\.com", fullmatch=True), max_size=4),
)
def test_names_under_a_domain_are_found_alike_scanned_or_indexed(
    table: dict[str, frozenset[str]], values: list[str]
) -> None:
    def brute(vs: list[str]) -> frozenset[str]:
        out: set[str] = set()
        for v in vs:
            out |= table.get(v, frozenset())
            if (name := naming.domain(v)) is not None:
                for named, who in table.items():
                    if named.lower().rstrip(".").endswith("." + name):
                        out |= who
        return frozenset(out)

    assert naming._under(table, values) == brute(values)


# ---------------------------------------------------------------- devices, families and bounds


def _dhcp(*, untied: bool = False) -> titles.IncidentFacts:
    """Two laptops that held 10.40.1.5 on different days (host links on each day's key), both
    beaconing to a flagged server; ``untied``: a third day no host link ties."""
    d1, d2, d3 = (dev("10.40.1.5", f"2026-11-0{i}") for i in (1, 2, 3))
    alice, bob = host("pc-alice"), host("pc-bob")
    days = [d1, d2, d3] if untied else [d1, d2]
    groups = [grp({r: {"beacon"}}, threats=[SERVER]) for r in (alice, bob, *days)]
    links = [
        LinkFacts(d1, alice, "host", "host:pc-alice"),
        LinkFacts(d2, bob, "host", "host:pc-bob"),
    ]
    return incident(groups, links=links, flags={f"ip:{SERVER}": "outside"})


def test_two_hosts_on_one_reused_address_are_two_devices() -> None:
    made = title_for_incident(_dhcp())
    assert made.text == f"Suspected beaconing to {SERVER} from 2 campus devices"
    names = titles._device_names(_dhcp())
    assert {names[host("pc-alice")], names[host("pc-bob")]} == {("pc-alice", "host"),
                                                                ("pc-bob", "host")}  # fmt: skip
    assert names[dev("10.40.1.5", "2026-11-01")] == ("pc-alice", "host")
    assert names[dev("10.40.1.5", "2026-11-02")] == ("pc-bob", "host")
    # a day no host link ties is one more device (it may be a third person), by its address
    assert title_for_incident(_dhcp(untied=True)).text == (
        f"Suspected beaconing to {SERVER} from 3 campus devices"
    )
    assert titles._device_names(_dhcp(untied=True))[dev("10.40.1.5", "2026-11-03")] == (
        "10.40.1.5", "ip",
    )  # fmt: skip


def test_one_host_on_a_reused_addresss_days_is_still_one_device_with_its_place() -> None:
    d1, d2 = dev("10.20.4.5", "2026-11-01"), dev("10.20.4.5", "2026-11-02")
    alice = host("pc-alice")
    groups = [grp({r: {"beacon"}}, threats=[SERVER]) for r in (alice, d1, d2)]
    f = incident(groups, links=[LinkFacts(d1, alice, "host", "host:pc-alice")],
                 flags={f"ip:{SERVER}": "outside"})  # fmt: skip
    assert (
        title_for_incident(f).text == f"Suspected beaconing from 10.20.4.5 (Hostel 4) to {SERVER}"
    )
    # two hosts on it: each laptop is named by its host, and keeps the address's place
    b2 = host("pc-bob")
    two = incident([*groups, grp({b2: {"beacon"}}, threats=[SERVER])],
                   links=[LinkFacts(d1, alice, "host", "host:pc-alice"),
                          LinkFacts(d2, b2, "host", "host:pc-bob")],
                   flags={f"ip:{SERVER}": "outside"})  # fmt: skip
    assert (
        title_for_incident(two).text
        == f"Suspected beaconing to {SERVER} from 2 campus devices in Hostel 4"
    )


def test_an_unflagged_destinations_tags_never_name_a_family() -> None:
    d = dev("10.40.1.1")
    tagged = incident(
        [grp({d: {"beacon"}}, threats=["198.51.100.7"])],
        labels={"198.51.100.7": ("cobalt-strike",)},
    )  # Shodan-like, not flagged
    assert title_for_incident(tagged).text == "Suspected beaconing from 10.40.1.1 to 198.51.100.7"
    flagged = replace(tagged, flags={"ip:198.51.100.7": "outside"})
    assert title_for_incident(flagged).text.startswith("Suspected Cobalt Strike beaconing")
    listed = replace(tagged, listed=frozenset({"198.51.100.7"}))  # on a threat list of a dossier
    assert title_for_incident(listed).text.startswith("Suspected Cobalt Strike beaconing")


def test_a_family_of_another_thing_is_never_pinned_on_the_named_server() -> None:
    d, d2 = dev("10.40.1.1"), dev("10.40.1.2")
    groups = [grp({d: {"beacon"}}, threats=["198.51.100.7"]),
              grp({d2: ()}, threats=["rare-example.org"])]  # fmt: skip
    rare = incident(groups, links=[LinkFacts(d, d2, "rare", "domain:rare-example.org")],
                    labels={"rare-example.org": ("Lumma stealer",)})  # fmt: skip
    assert title_for_incident(rare).text == "Suspected beaconing from 10.40.1.1 to 198.51.100.7"
    # flagged, the other thing is the title's own server (contact), and its family shows
    other = replace(rare, flags={"domain:rare-example.org": "outside"})
    assert title_for_incident(other).text.startswith(
        "Suspected Lumma contact with rare-example.org"
    )


def test_a_campaigns_family_goes_only_with_the_devices_it_binds() -> None:
    d1, d2, d3 = dev("10.40.2.1"), dev("10.40.2.2"), dev("10.40.2.3")
    key = "campaign:domain:c2.example,ip:198.51.100.5"
    groups = [grp({d1: {"beacon"}}, threats=[SERVER]), grp({d2: ()}), grp({d3: ()})]
    f = incident(groups, links=[LinkFacts(d2, d3, "campaign", key)],
                 labels={"198.51.100.5": ("PS1Bot",)})  # fmt: skip
    assert "PS1Bot" not in title_for_incident(f).text  # the beaconing device is not bound
    bound = replace(f, links=(LinkFacts(d1, d2, "campaign", key),))
    assert title_for_incident(bound).text.startswith("Suspected PS1Bot beaconing from 10.40.2.1")


def test_m_counts_the_devices_past_a_capped_read() -> None:
    f = replace(beacons(4, 3), more_devices=6, more_accounts=2)
    made = title_for_incident(f, naming.LIKELY)
    assert made.text == f"Likely beaconing to {SERVER} from 3 of 10 campus devices"
    assert any(c.fact == "actors:beacon:3:10" for c in made.claims)
    assert titles.naming_facts(f).accounts == 2
    checked = replace(titles.naming_facts(f), verdict=naming.Verdict(given=naming.LIKELY))
    assert naming.check(naming.Titled(made.parts), checked) == []


LONG = "Likely beaconing on a remote-admin port to 2 outside servers from 3 of 7 campus devices"
NEAR = ("Likely contact with c2-panel-0001.example-ab.com (VirusTotal: 5 engines) from 3 of 7"
        " campus devices")  # fmt: skip


def test_a_certainty_swap_that_would_break_the_bounds_takes_the_facts_title() -> None:
    devices = [dev(f"10.40.3.{i}") for i in range(1, 4)]
    f = incident([grp({x: {"beacon", "ports"}}, threats=[SERVER]) for x in devices[:2]]
                 + [grp({devices[2]: ()}, threats=[SERVER])],
                 links=chain(devices, "flagged", f"ip:{SERVER}"),
                 flags={f"ip:{SERVER}": "outside"})  # fmt: skip
    current = title_for_incident(f, naming.LIKELY).text
    assert (
        current == f"Likely beaconing on a remote-admin port to {SERVER} from 2 of 3 campus devices"
    )
    grown = replace(f, groups=(*f.groups, grp({devices[2]: {"beacon"}}, threats=[SERVER])))
    for stored in (current, LONG):
        for word in naming.CERTAINTIES:
            made = retitle(stored, grown, word, material=False)
            if made is None:
                continue
            rest = titles.split_certainty(made.text)[1]
            assert len(made.text) <= naming.MAX_TITLE
            assert titles.fits(made.text, rest)
            if made.reason == "fit":
                assert made == replace(title_for_incident(grown, word), reason="fit")
                checked = replace(titles.naming_facts(grown), verdict=naming.Verdict(given=word))
                assert naming.check(naming.Titled(made.parts), checked) == []
            else:
                assert made.reason == "certainty"
                assert not made.checkable
                assert rest == titles.split_certainty(stored)[1]

    def reason(stored: str, word: str) -> str | None:
        made = retitle(stored, grown, word, material=False)
        return None if made is None else made.reason

    assert reason(current, naming.HARMLESS) == "fit"  # "Likely harmless: beaconing on a ..." 49
    assert reason(current, naming.SUSPECTED) == "certainty"
    swap = retitle(current, grown, naming.SUSPECTED, material=False)
    assert swap is not None
    assert swap.text == current.replace("Likely", "Suspected", 1)
    assert reason(LONG, naming.SUSPECTED) == "certainty"
    assert reason(LONG, naming.HARMLESS) == "fit"  # the activity would end at 49
    assert len(NEAR) == 99
    assert reason(NEAR, naming.SUSPECTED) == "fit"  # 102 characters
    assert reason(NEAR, naming.UNCLEAR) == "fit"  # 101
    assert reason(NEAR, naming.LIKELY) is None  # its own word: nothing to swap


def test_the_activity_is_found_after_the_certainty_word() -> None:
    assert titles.activity_end("beaconing from 10.40.1.1") == len("beaconing")
    assert titles.activity_end("beaconing on a remote-admin port to x") == len(
        "beaconing on a remote-admin port"
    )
    assert titles.activity_end("Cobalt Strike DNS beaconing to x") == len(
        "Cobalt Strike DNS beaconing"
    )
    assert titles.activity_end(".env and Git-folder scan of x") == len(".env and Git-folder scan")
    assert titles.activity_end("web scan of x by 2 outside IPs") == len("web scan")
    assert titles.activity_end("alerts of rule 'x'") == len("alerts")
    assert titles.activity_end("Amadey on the lab PC") is None
    assert titles.activity_end("beaconingly") is None
