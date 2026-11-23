"""Naming v2 (D-230, D-232, P4-F track 5): a title is a list of claims, each resting on a fact; the
checker refuses a claim with no fact. The shapes and the catalogue with a made-up example each
(and the fact removed: the words go), the outcome ladder, the certainty words, the checker's
refusals, the Kibana form, what changed between two titles, the Inbox row, and Hypothesis: every
claim backed, counts true, bounds kept, rule names never choose words, the same facts give the same
title. Every address is a documentation, private or made-up one; nothing here is a real alert."""

from __future__ import annotations

import dataclasses
import ipaddress
import re
import string
from types import MappingProxyType

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from argus.assess import raised
from argus.cases import naming
from argus.cases.naming import (
    BEACON,
    CAMPAIGN,
    LISTED,
    OUTSIDE,
    PORTS,
    SUCCESS,
    Claim,
    Device,
    Facts,
    Titled,
    Verdict,
    check,
    title,
    titled,
)
from argus.context import paths as path_outcomes
from argus.outside import facts as outside_facts
from argus.outside import prefetch

SERVER = "198.51.100.20"
SERVERS = (SERVER, "198.51.100.21", "198.51.100.22")
HOST = "10.0.4.7"
TP = Verdict(proposals=("true_positive",))
ALLOWED = frozenset(string.ascii_letters + string.digits + " .,:()/&+-—'")


def devices(n: int, *, place: str | None = None, zone: str | None = None) -> tuple[Device, ...]:
    return tuple(Device(f"10.0.4.{i + 1}", "ip", None, place, zone) for i in range(n))


def values(n: int) -> frozenset[str]:
    return frozenset(f"10.0.4.{i + 1}" for i in range(n))


def test_the_flags_are_the_words_the_pipeline_stores() -> None:
    assert BEACON == prefetch.BEACON
    assert LISTED == raised.THREAT_LIST
    assert OUTSIDE == raised.OUTSIDE
    assert naming.OPERATOR == raised.OPERATOR
    assert CAMPAIGN == raised.CAMPAIGN
    assert naming.PATH_SERVED == path_outcomes.SUCCESS
    assert naming.PATH_CATCH_ALL == path_outcomes.CATCH_ALL


def test_the_ports_and_success_flags_are_the_gold_flags_words() -> None:
    from argus.evaluation import gold

    def known(name: str) -> dict[str, object]:
        return {"name": name, "version": 1, "value": 2, "status": "known", "unknown_reason": None}

    body = {"local_signals": [known("ports.risky"), known("web.successes_after")]}
    flags = gold.flags(body)
    assert PORTS in flags
    assert SUCCESS in flags


# -- the device shapes -----------------------------------------------------------------------------


def test_one_device_beaconing_names_the_destination_and_who_flagged_it() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(SERVER,),
              vt=MappingProxyType({SERVER: 5}), verdict=TP)  # fmt: skip
    assert title(f) == f"Likely beaconing from 10.0.4.1 to {SERVER} (VirusTotal: 5 engines)"


def test_the_server_of_another_case_is_said() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), destinations=(SERVER,),
              doing=MappingProxyType({BEACON: values(1)}),
              reaches=MappingProxyType({SERVER: values(1)}),
              server_cases=MappingProxyType({SERVER: 14}), verdict=TP)  # fmt: skip
    assert title(f) == f"Likely beaconing from 10.0.4.1 to {SERVER}, the server of case 14"
    alone = dataclasses.replace(f, server_cases=MappingProxyType({}))
    assert title(alone) == f"Likely beaconing from 10.0.4.1 to {SERVER}"


def test_a_count_is_the_devices_that_did_the_activity() -> None:
    f = Facts(
        flags=frozenset({BEACON}), devices=devices(22), servers=(SERVER,),
        vt=MappingProxyType({SERVER: 4}), doing=MappingProxyType({BEACON: values(12)}),
        reaches=MappingProxyType({SERVER: values(18)}), verdict=TP,
    )  # fmt: skip
    assert title(f) == (
        f"Likely beaconing to {SERVER} (VirusTotal: 4 engines) from 12 of 22 campus devices"
    )
    assert any(c.fact == "actors:beacon:12:22" for c in titled(f).claims)


def test_reaching_without_beacon_timing_is_contact() -> None:
    f = Facts(flags=frozenset({BEACON, OUTSIDE}), devices=devices(3), servers=(SERVER,),
              doing=MappingProxyType({BEACON: frozenset({"10.0.4.3"}), OUTSIDE: values(2)}),
              reaches=MappingProxyType({SERVER: values(2)}), verdict=TP)  # fmt: skip
    assert title(f) == f"Likely contact with {SERVER} from 2 of 3 campus devices"


def test_a_remote_admin_port_beacon_with_its_place() -> None:
    one = (Device(HOST, "ip", "switch", "Block C", "department"),)
    f = Facts(flags=frozenset({BEACON, PORTS}), devices=one, destinations=("203.0.113.78",),
              doing=MappingProxyType({BEACON: frozenset({HOST}), PORTS: frozenset({HOST})}),
              reaches=MappingProxyType({"203.0.113.78": frozenset({HOST})}),
              verdict=TP)  # fmt: skip
    assert title(f) == (
        f"Likely beaconing on a remote-admin port from {HOST} (Block C) to 203.0.113.78"
    )


def test_the_place_is_the_zone_never_the_network_equipment() -> None:
    kit = tuple(Device(f"10.0.4.{i}", "ip", "switch", None, "hostel") for i in range(1, 6))
    f = Facts(flags=frozenset({BEACON}), devices=kit, servers=(SERVER,), verdict=TP)
    assert title(f) == f"Likely beaconing to {SERVER} from 5 campus devices in hostels"
    assert "switch" not in title(f)
    mixed = (*kit[:4], Device("10.0.4.9", "ip", "gateway", None, "department"))
    assert title(dataclasses.replace(f, devices=mixed)) == (
        f"Likely beaconing to {SERVER} from 5 campus devices (4 in hostels)"
    )
    few = (*kit[:2], *(Device(f"10.0.5.{i}", "ip", None, None, "department") for i in (1, 2, 3)))
    assert "hostel" not in title(dataclasses.replace(f, devices=few))  # 2 of 5: below 60 %


def test_devices_in_one_building_say_where() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(4, place="Hostel 12", zone="hostel"),
              servers=(SERVER,))  # fmt: skip
    assert title(f) == f"Suspected beaconing to {SERVER} from 4 campus devices in Hostel 12"


def test_a_family_from_a_threat_name_leads_and_a_rule_name_gives_none() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(SERVER,),
              labels=("PS1Bot C2",), verdict=TP)  # fmt: skip
    assert title(f) == f"Likely PS1Bot beaconing from 10.0.4.1 to {SERVER}"
    by_rule = dataclasses.replace(f, labels=(), rules=(("Amadey PS1Bot IOC match", 3),))
    assert "Amadey" not in title(by_rule)
    assert "PS1Bot" not in title(by_rule)


def test_a_dns_campaign_names_its_parents() -> None:
    names = (*(f"r{i}.rare-names.example" for i in range(5)),
             *(f"q{i}.svc-update.example" for i in range(3)))  # fmt: skip
    f = Facts(devices=devices(47, zone="hostel"), domains=names, flags=frozenset({CAMPAIGN}),
              verdict=Verdict(person="true_positive"))  # fmt: skip
    assert title(f) == (
        "Confirmed DNS beaconing to rare-names.example and svc-update.example"
        " from 47 campus devices"
    )
    looked = dataclasses.replace(f, flags=frozenset(), devices=devices(3, zone="hostel"))
    assert title(looked) == (
        "Confirmed DNS look-ups of 8 look-alike names from 3 campus devices in hostels"
    )
    short = dataclasses.replace(looked, domains=tuple(f"r{i}.fast.example" for i in range(4)))
    assert title(short) == (
        "Confirmed DNS look-ups of 4 look-alike names under fast.example"
        " from 3 campus devices in hostels"
    )


def test_dns_beaconing_needs_the_flag_on_the_investigation_that_names_the_names() -> None:
    """One device beacons to an address; five merely looked up names under one parent: that is
    DNS look-ups by five, not DNS beaconing by five."""
    names = ("a1.example-bad.example", "a2.example-bad.example")
    f = Facts(devices=devices(5), domains=names, flags=frozenset({BEACON}), destinations=(SERVER,),
              doing=MappingProxyType({BEACON: values(1)}),
              reaches=MappingProxyType({**dict.fromkeys(names, values(5)), SERVER: values(1)}),
              beacon_reaches=MappingProxyType({SERVER: values(1)}), verdict=TP)  # fmt: skip
    assert title(f) == (
        "Likely DNS look-ups of 2 look-alike names under example-bad.example from 5 campus devices"
    )
    timed = dataclasses.replace(f, beacon_reaches=MappingProxyType({names[0]: values(1)}))
    assert title(timed) == "Likely DNS beaconing to example-bad.example from 10.0.4.1"
    campaign = dataclasses.replace(
        f, flags=frozenset({CAMPAIGN}), doing=MappingProxyType({CAMPAIGN: values(3)}),
        beacon_reaches=None, campaign_reaches=MappingProxyType({names[1]: values(2)}),
    )  # fmt: skip
    assert title(campaign) == (
        "Likely DNS beaconing to example-bad.example from 2 of 5 campus devices"
    )
    elsewhere = dataclasses.replace(campaign, campaign_reaches=MappingProxyType({}))
    assert title(elsewhere).startswith("Likely DNS look-ups of 2 look-alike names")


def test_dns_beaconing_names_only_the_parents_its_flagged_investigations_name() -> None:
    names = (*(f"r{i}.rare-names.example" for i in range(3)), "q1.svc-update.example",
             "q2.svc-update.example")  # fmt: skip
    f = Facts(devices=devices(4), domains=names, flags=frozenset({CAMPAIGN}),
              doing=MappingProxyType({CAMPAIGN: values(4)}),
              reaches=MappingProxyType(dict.fromkeys(names, values(4))),
              campaign_reaches=MappingProxyType({names[0]: values(4)}), verdict=TP)  # fmt: skip
    assert title(f) == "Likely DNS beaconing to rare-names.example from 4 campus devices"
    assert not any(c.fact == "parent:svc-update.example" for c in titled(f).claims)


def test_a_beacon_to_a_flagged_server_beats_names_under_a_shared_parent() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(SERVER,),
              domains=("www.shared-cdn.example", "mail.shared-cdn.example"),
              vt=MappingProxyType({SERVER: 9}), verdict=TP)  # fmt: skip
    assert title(f) == f"Likely beaconing from 10.0.4.1 to {SERVER} (VirusTotal: 9 engines)"
    contact = dataclasses.replace(f, flags=frozenset({OUTSIDE}))  # reached, not timed
    assert title(contact).startswith("Likely DNS look-ups of 2 look-alike names")


def test_beaconing_with_no_destination_names_the_device_alone() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1))
    assert title(f) == "Suspected beaconing from 10.0.4.1"
    assert title(Facts(flags=frozenset({OUTSIDE}), devices=devices(2))) == (
        "Suspected contact with a flagged server from 2 campus devices"
    )


# -- the web shape and the outcome ladder ----------------------------------------------------------

ATTACKERS = tuple(f"203.0.113.{i}" for i in range(1, 7))
SITE = "www.clinic.example.edu"


def web(**more: object) -> Facts:
    base: dict[str, object] = {
        "outsiders": ATTACKERS, "sites": (SITE, "a.example.edu"),
        "paths": ("/.env", "/api/.env", "/.env.bak", "/x/.env"), "verdict": TP,
    }  # fmt: skip
    base.update(more)
    return Facts(**base)  # type: ignore[arg-type]


def test_a_scan_names_the_site_and_says_http_200_is_not_verified() -> None:
    f = web(answered=((SITE, "/.env"),))
    assert title(f) == (
        f"Likely .env scan of {SITE} +1 site by 6 outside IPs — got HTTP 200, not verified"
    )


def test_served_only_after_argus_own_path_check() -> None:
    served = web(outcomes=((SITE, "/.env", "success"), (SITE, "/x", "refused")))
    assert title(served).endswith("— a .env file served")
    by_rule = web(rules=(("Web: a config file served successfully", 4),))
    assert "served" not in title(by_rule)
    assert title(by_rule).endswith("— no web check yet")


def test_the_outcome_ladder_rung_by_rung() -> None:
    assert title(web(outcomes=((SITE, "/.env", "catch_all"),))).endswith(
        "— the site answers every path alike"
    )
    lab = "w.example.edu"
    traversal = web(paths=("/../etc/passwd", "/a/../b", "/%2e%2e/x"), sites=(lab,),
                    answered=((lab, "/.env"), (lab, "/secrets.env")))  # fmt: skip
    assert title(traversal) == (
        "Likely path-traversal scan of w.example.edu by 6 outside IPs"
        " — .env files got HTTP 200, not verified"
    )
    longer = dataclasses.replace(traversal, sites=(SITE, "a.example.edu"),
                                 answered=((SITE, "/.env"), (SITE, "/secrets.env")))  # fmt: skip
    assert title(longer) == (  # the site stays named: the details go first
        f"Likely path-traversal scan of {SITE} by 6 outside IPs — got HTTP 200, not verified"
    )
    wordpress = web(paths=("/wp-login.php", "/wp-admin/", "/xmlrpc.php"), sites=("w.example.edu",),
                    answered=(("w.example.edu", "/wp-config.php"),))  # fmt: skip
    assert title(wordpress).endswith("— a config file got HTTP 200, not verified")
    ordinary = web(answered=((SITE, "/"), (SITE, "/academic/")))
    assert title(ordinary).endswith("— only ordinary pages got HTTP 200")
    assert title(web(checks=frozenset({"empty"}))).endswith("— no HTTP 200 after the alerts")
    assert title(web(checks=frozenset({"skipped_budget"}))).endswith("— web check skipped (budget)")
    assert title(web(flags=frozenset({SUCCESS}))).endswith("— got HTTP 200, not verified")


def test_the_named_site_is_the_one_whose_own_check_backs_the_outcome() -> None:
    """The 2xx or the served file is on another site than the commonest: that site is named, so
    the outcome is never said of a site that did not give it."""
    sites = ("reach.gymkhana.example.edu", *(f"s{i}.example.edu" for i in range(1, 12)))
    many = web(outsiders=tuple(f"198.51.100.{i}" for i in range(18)), sites=sites,
               answered=(("s3.example.edu", "/.env"),))  # fmt: skip
    assert naming.lead_site(many) == "s3.example.edu"
    assert title(many) == (
        "Likely .env scan of s3.example.edu +11 sites by 18 outside IPs"
        " — got HTTP 200, not verified"
    )
    portal = "departmental-research-portal.example.edu"
    two = web(
        sites=(portal, "b.example.edu"),
        outcomes=(("b.example.edu", "/.env", "success"), (portal, "/.env", "catch_all")),
    )
    assert title(two) == (
        "Likely .env scan of b.example.edu +1 site by 6 outside IPs — a .env file served"
    )
    assert naming.outcome_sites(two) == frozenset({"b.example.edu"})
    assert naming.outcome_sites(web(checks=frozenset({"empty"}))) is None


def test_a_site_named_alone_keeps_its_count_when_no_check_of_it_backs_the_outcome() -> None:
    f = web(flags=frozenset({SUCCESS}))  # a flag: no site's check backs the 200
    assert title(f) == (
        f"Likely .env scan of {SITE} +1 site by 6 outside IPs — got HTTP 200, not verified"
    )
    alone = Titled((
        Claim("certainty", "Likely", "certainty:Likely"), " ",
        Claim("activity", ".env scan", "activity:scan:.env"), " of ",
        Claim("object", SITE, f"site:{SITE}"), " by ",
        Claim("actors", "6 outside IPs", "outsiders:6"),
        " — ", Claim("outcome", naming.UNVERIFIED, "outcome:unverified:"),
    ))  # fmt: skip
    assert check(alone, f) == [f"the outcome is not {SITE}'s own: another site's checks back it"]
    assert check(alone, dataclasses.replace(f, sites=(SITE,))) == []  # one site: it is its own
    own = Titled(
        (*alone.parts[:-1], Claim("outcome", naming.UNVERIFIED, "outcome:unverified:.env"))
    )
    assert check(own, dataclasses.replace(f, answered=((SITE, "/.env"),))) == []  # SITE's own 200


def test_two_kinds_of_a_quarter_each_or_a_plain_web_scan() -> None:
    both = web(paths=("/db.sql", "/backup.zip", "/.env", "/x/.env", "/a", "/b"))
    assert title(both).startswith("Likely .env and backup scan of")
    plain = web(paths=("/a", "/b", "/c", "/.env"))
    assert title(plain).startswith("Likely web scan of")


def test_a_threat_listed_prober_of_campus_servers() -> None:
    f = Facts(outsiders=("203.0.113.51",), listed=("203.0.113.51",), own_servers=3)
    assert title(f) == "Suspected probing of 3 campus servers by 203.0.113.51 (on a threat list)"


def test_a_web_scan_by_some_threat_listed_addresses() -> None:
    f = web(listed=ATTACKERS[:2], sites=("w.example.edu",))
    assert title(f) == (
        "Likely .env scan of w.example.edu by 6 outside IPs (2 on a threat list) — no web check yet"
    )


# -- the fallback --------------------------------------------------------------------------------


def test_the_fallback_quotes_and_attributes_the_rule() -> None:
    f = Facts(rules=(("Mail: odd login", 2),), outsiders=("203.0.113.9",))
    assert title(f) == "Suspected: alerts of rule 'Mail: odd login' for 203.0.113.9"
    assert title(Facts(rules=(("Odd login", 1),), accounts=3)) == (
        "Suspected: alerts of rule 'Odd login' for 3 user accounts"
    )
    assert title(Facts(rules=(("Odd login", 1),))) == "Suspected: alerts of rule 'Odd login'"
    assert title(Facts()) == naming.EMPTY
    assert title(Facts(follows=3)) == "Alert — follows case 3"
    assert title(Facts(rules=(("<b>x</b>", 1),), accounts=1)) == (
        "Suspected: alerts of 1 rule for a user account"
    )


def test_a_case_that_follows_a_closed_one_says_so_within_the_bound() -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(SERVER,), follows=12)
    assert title(f) == f"Suspected beaconing from 10.0.4.1 to {SERVER} — follows case 12"
    long = dataclasses.replace(
        f, devices=devices(5, place="Department of Chemical Engineering Block"),
        servers=("2001:db8:85a3:8d3:1319:8a2e:370:7348", *SERVERS), labels=("agent tesla",),
        follows=12345,
    )  # fmt: skip
    out = title(long)
    assert out.endswith(" — follows case 12345")
    assert len(out) <= naming.MAX_TITLE


# -- certainty -------------------------------------------------------------------------------------


def test_the_certainty_words_come_from_who_decided() -> None:
    plain = Facts(flags=frozenset({BEACON}), devices=devices(1), servers=(SERVER,))

    def cert(v: Verdict) -> str:
        return naming.certainty(dataclasses.replace(plain, verdict=v))

    assert cert(Verdict()) == "Suspected"
    assert cert(Verdict(person="true_positive")) == "Confirmed"
    assert cert(Verdict(opened=True)) == "Confirmed"
    assert cert(Verdict(proposals=("true_positive",) * 3)) == "Likely"
    assert cert(Verdict(proposals=("true_positive", "benign_expected"))) == "Unclear"
    assert cert(Verdict(proposals=("true_positive",) * 3 + ("benign_expected",))) == "Likely"
    assert cert(Verdict(readings=("true_positive",))) == "Suspected"
    assert cert(Verdict(readings=("benign_expected",))) == "Unclear"  # the evidence says otherwise
    assert cert(Verdict(person="inconclusive", proposals=("true_positive",))) == "Unclear"
    quiet = Facts(devices=devices(1), rules=(("Rule", 1),),
                  verdict=Verdict(proposals=("benign_expected",)))  # fmt: skip
    assert naming.certainty(quiet) == "Likely harmless"
    assert title(quiet) == "Likely harmless: alerts of rule 'Rule' for 10.0.4.1"
    assert title(dataclasses.replace(plain, verdict=Verdict(readings=("benign_expected",)))) == (
        f"Unclear: beaconing from 10.0.4.1 to {SERVER}"
    )


# -- the checker -----------------------------------------------------------------------------------


def _swap(made: Titled, slot: str, new: Claim) -> Titled:
    return Titled(tuple(new if isinstance(p, Claim) and p.slot == slot else p for p in made.parts))


def test_the_checker_refuses_claims_without_their_fact() -> None:
    f = web(answered=((SITE, "/.env"),))
    made = titled(f)
    assert check(made, f) == []
    served = _swap(made, "outcome", Claim("outcome", "a .env file served", "outcome:served:.env"))
    assert any("no such fact" in p for p in check(served, f))
    count = _swap(made, "actors", Claim("actors", "60 outside IPs", "outsiders:60"))
    assert check(count, f)
    words = _swap(made, "actors", Claim("actors", "60 outside IPs", "outsiders:6"))
    assert any("is not what" in p for p in check(words, f))
    sure = Titled((Claim("certainty", "Confirmed", "certainty:Confirmed"), *made.parts[1:]))
    assert check(sure, f)
    rule = Titled((*made.parts, " — ", Claim("outcome", "Served Successfully", "outcome:x")))
    assert check(rule, f)
    stray = Titled((*made.parts, " leaked words"))
    assert any("joining" in p for p in check(stray, f))
    family = Titled((made.parts[0], made.parts[1], Claim("family", "Amadey", "family:Amadey"),
                     " ", *made.parts[2:]))  # fmt: skip
    assert check(family, f)
    no_cert = Titled(made.parts[2:])
    assert any("certainty" in p for p in check(no_cert, f))
    late = Titled((made.parts[0], " ", Claim("object", "x" * 50, "x"), " ", *made.parts[2:]))
    assert any("after 48" in p for p in check(late, f))


def test_a_stale_title_is_refused_when_its_fact_goes() -> None:
    f = web(outcomes=((SITE, "/.env", "success"),))
    made = titled(f)
    gone = dataclasses.replace(f, outcomes=())
    assert check(made, gone)  # "served" no longer rests on a path check
    assert check(titled(gone), gone) == []


# -- the Kibana form and what changed --------------------------------------------------------------


def test_kibana_leaves_out_the_certainty_word_only_for_argus_title() -> None:
    assert naming.without_certainty("Likely beaconing from 10.0.4.1", "Likely") == (
        "Beaconing from 10.0.4.1"
    )
    assert naming.without_certainty("Unclear: beaconing", "Unclear") == "Beaconing"
    assert naming.without_certainty("Likely harmless: x", "Likely harmless") == "X"
    assert naming.without_certainty("Confirmed .env scan of a", "Confirmed") == ".env scan of a"
    assert naming.without_certainty("Likely phishing, a person's", None) == (
        "Likely phishing, a person's"
    )
    assert naming.without_certainty("Likely harmless: x", "Likely") == "Likely harmless: x"


def test_what_changed_between_two_titles() -> None:
    a = f"Likely beaconing to {SERVER} from 12 of 22 campus devices"
    assert naming.change_of(a, a) == "same"
    assert naming.change_of(a, a.replace("Likely", "Confirmed")) == "certainty"
    assert naming.change_of(a, a.replace("12 of 22", "13 of 23")) == "counts"
    assert naming.change_of(a, a.replace("beaconing to", "contact with")) == "words"
    assert not naming.counts_moved(a, a.replace("12 of 22", "13 of 23"))
    assert naming.counts_moved(a, a.replace("12 of 22", "18 of 22"))  # grew by half
    assert naming.counts_moved(a, a.replace("12 of 22", "11 of 22"))  # shrank


def test_an_address_a_case_a_place_or_a_rule_is_words_not_a_count() -> None:
    """A number in an address, "case N", a place or a rule's quoted name is a word: a change of it
    is material at once, never a count change that waits (and is said as "the counts changed")."""
    a = "Likely beaconing from 10.0.4.12 to 203.0.113.5 (VirusTotal: 4 engines)"
    moved = a.replace("10.0.4.12", "10.0.4.13").replace("203.0.113.5", "203.0.113.6")
    assert naming.change_of(a, moved) == "words"
    assert naming.change_of(a, a.replace("4 engines", "5 engines")) == "counts"
    case = f"Likely beaconing from 10.0.4.1 to {SERVER}, the server of case 3"
    assert naming.change_of(case, case.replace("case 3", "case 4")) == "words"
    follows = f"Likely beaconing to {SERVER} from 4 campus devices — follows case 7"
    assert naming.change_of(follows, follows.replace("case 7", "case 8")) == "words"
    place = f"Suspected beaconing to {SERVER} from 4 campus devices in Hostel 12"
    assert naming.change_of(place, place.replace("Hostel 12", "Hostel 13")) == "words"
    assert naming.change_of(place, place.replace("4 campus", "5 campus")) == "counts"
    one = f"Likely beaconing from 10.0.4.1 (Hostel 12) to {SERVER}"
    assert naming.change_of(one, one.replace("Hostel 12", "Hostel 13")) == "words"
    rule = "Suspected: alerts of rule 'Top 10 sites' for 3 user accounts"
    assert naming.change_of(rule, rule.replace("Top 10", "Top 20")) == "words"
    assert naming.change_of(rule, rule.replace("3 user", "4 user")) == "counts"
    kibana = "ACME-IR-2026-1106-01 · Beaconing from 10.0.4.12 to 203.0.113.5"
    assert naming.change_of(kibana, kibana.replace("10.0.4.12", "10.0.4.13")) == "words"
    scan = "Likely .env scan of a.example.edu +1 site by 6 outside IPs (2 on a threat list)"
    assert naming.counts_in(scan + " — got HTTP 200, not verified")[1] == (1, 6, 2)
    zones = f"Likely beaconing to {SERVER} +2 flagged servers from 5 campus devices (4 in hostels)"
    assert naming.counts_in(zones) == (
        f"Likely beaconing to {SERVER} +# flagged servers from # campus devices (# in hostels)",
        (2, 5, 4),
    )
    assert naming.counts_in("Likely Gh0st beaconing from pc-12 to 3 outside servers")[1] == (3,)


@given(st.integers(1, 253), st.integers(1, 253), st.integers(2, 90), st.integers(1, 98),
       st.integers(1, 98))  # fmt: skip
def test_a_new_device_server_case_or_place_is_never_a_count_change(
    device: int, server: int, engines: int, case: int, hostel: int
) -> None:
    def made(d: int, s: int, c: int, h: int) -> str:
        value = f"203.0.113.{s}"
        return title(Facts(
            flags=frozenset({BEACON}), devices=(Device(f"10.0.4.{d}", "ip", None, f"Hostel {h}"),),
            servers=(value,), vt=MappingProxyType({value: engines}),
            server_cases=MappingProxyType({value: c}), verdict=TP,
        ))  # fmt: skip

    base = made(device, server, case, hostel)
    assert naming.change_of(base, made(device + 1, server, case, hostel)) == "words"
    assert naming.change_of(base, made(device, server + 1, case, hostel)) == "words"
    assert naming.change_of(base, made(device, server, case + 1, hostel)) in ("words", "same")
    assert naming.change_of(base, made(device, server, case, hostel + 1)) in ("words", "same")


# -- the Inbox row ---------------------------------------------------------------------------------


def test_an_inbox_row_is_titled_by_activity_not_the_rule() -> None:
    assert naming.row_title([("source.ip", "10.0.4.12")], [BEACON], 12) == (
        "10.0.4.12 · beacon-timed",
        "from 10.0.4.12",
    )
    assert naming.row_title([("source.ip", "10.0.4.12")], [], 1) == (
        "10.0.4.12 · 1 alert",
        "from 10.0.4.12",
    )
    many = [("source.ip", [f"203.0.113.{i}" for i in range(16)]), ("user.name", "a@example.org")]
    assert naming.row_title(many, [], 1) == (
        "16 outside IPs → 1 account · 1 alert",
        "from 16 outside IPs to 1 account",
    )
    inside = [("source.ip", [f"10.0.4.{i}" for i in range(8)]), ("destination.ip", SERVER)]
    line1, line2 = naming.row_title(inside, [BEACON, LISTED], 40)
    assert line1 == f"8 campus devices → {SERVER} · beacon-timed"
    assert line2 == f"from 8 campus devices to {SERVER}"
    assert naming.row_title([], [], 1) == ("1 alert", "one alert, no key")
    assert naming.row_title([("source.ip", "<script>")], [], 2)[0] == "2 alerts"


@given(
    st.lists(st.tuples(st.sampled_from(["source.ip", "destination.ip", "user.name", "url.domain",
                                        "host.name", "x.y"]),
                       st.one_of(st.text(max_size=60), st.lists(st.text(max_size=20), max_size=20),
                                 st.ip_addresses().map(str))), max_size=4),
    st.lists(st.sampled_from([BEACON, LISTED, SUCCESS, PORTS, OUTSIDE, "x"]), max_size=4),
    st.integers(0, 10**6),
)  # fmt: skip
def test_an_inbox_row_is_short_and_never_names_an_account(
    pairs: list[tuple[str, object]], flags: list[str], alerts: int
) -> None:
    line1, line2 = naming.row_title(pairs, flags, alerts)
    assert 1 <= len(line1) <= naming.FRONT
    assert line2
    for name, value in pairs:
        if name.startswith("user.") and isinstance(value, str) and "@" in value and value.strip():
            assert value not in line1
            assert value not in line2


def test_an_inbox_row_keeps_each_value_on_its_side() -> None:
    """A key with no one who acted says where it went, never "from" the destination or the site."""
    assert naming.row_title([("destination.ip", SERVER)], [], 40) == (
        f"→ {SERVER} · 40 alerts", f"to {SERVER}",
    )  # fmt: skip
    assert naming.row_title([("url.domain", "www.example.edu")], [SUCCESS], 4) == (
        "→ www.example.edu · got HTTP 200 after", "to www.example.edu",
    )  # fmt: skip
    asked = [("dns.question.name", "bad.example.com"), ("user.name", "x")]
    assert naming.row_title(asked, [], 4) == (
        "1 account → bad.example.com · 4 alerts", "from 1 account to bad.example.com",
    )  # fmt: skip
    assert naming.row_title([("user.name", "x"), ("user.name", "y")], [], 2) == (
        "2 accounts · 2 alerts", "for 2 accounts",
    )  # fmt: skip


def test_an_account_under_any_side_is_counted_never_named() -> None:
    for name in ("source.user.name", "client.user.id", "destination.user.email", "host.user.name"):
        line1, line2 = naming.row_title([(name, "jdoe"), ("destination.ip", SERVER)], [], 4)
        assert (line1, line2) == (f"1 account → {SERVER} · 4 alerts", f"from 1 account to {SERVER}")
    line1, line2 = naming.row_title([("source.ip", HOST), ("source.user.name", "jdoe")], [], 4)
    assert (line1, line2) == (f"{HOST} → 1 account · 4 alerts", f"from {HOST} to 1 account")


ACCOUNT_FIELDS = ["user.name", "source.user.name", "client.user.id", "destination.user.email",
                  "related.user", "host.user.name"]  # fmt: skip
OBJECT_FIELDS = ["destination.ip", "server.address", "url.domain", "url.path", "dns.question.name"]
key_values = st.ip_addresses().map(str) | st.from_regex(r"[a-z]{1,8}\.example\.(com|edu)",
                                                        fullmatch=True)  # fmt: skip


@given(
    st.lists(st.tuples(st.sampled_from([*OBJECT_FIELDS, "source.ip", "client.ip", "x.y"]),
                       key_values), max_size=3),
    st.lists(st.tuples(st.sampled_from(ACCOUNT_FIELDS),
                       st.from_regex(r"u[a-z]{4}[0-9]{2}", fullmatch=True)), max_size=3),
    st.booleans(),
)  # fmt: skip
def test_an_inbox_row_never_names_an_account_or_says_from_a_destination(
    others: list[tuple[str, str]], accounts: list[tuple[str, str]], reverse: bool
) -> None:
    pairs = [*others, *accounts]
    line1, line2 = naming.row_title(pairs[::-1] if reverse else pairs, [], 3)
    for _, value in accounts:
        assert value not in line1
        assert value not in line2
    acted = any(n.startswith(("source.", "client.")) for n, _ in others) or accounts
    if not acted:
        assert "from" not in line2


# -- Hypothesis ------------------------------------------------------------------------------------

hostile = st.one_of(
    st.text(max_size=60),
    st.text(alphabet="<>`'\"|*#\\\n\t\x1b[]{}$%^;@!?~=_ ab.0:-", max_size=40),
    st.ip_addresses().map(str),
    st.from_regex(r"[a-z0-9]{1,10}(\.[a-z0-9-]{1,10}){1,3}", fullmatch=True),
    st.sampled_from(["", " ", "::", "0.0.0.0", "a" * 300, "x_y.example.com", "-.-"]),  # noqa: S104
)
device_values = st.sampled_from([f"10.0.4.{i}" for i in range(1, 9)]) | hostile
places = st.none() | st.sampled_from(["Hostel 12", "Block C", "Lab 3"]) | hostile
zones = st.none() | st.sampled_from(["hostel", "department"]) | hostile
devices_st = st.builds(Device, device_values, st.sampled_from(["ip", "host", "other"]),
                       st.none() | hostile, places, zones)  # fmt: skip
flags_st = st.frozensets(st.sampled_from([BEACON, LISTED, OUTSIDE, naming.OPERATOR, SUCCESS,
                                          PORTS, CAMPAIGN, "x"]))  # fmt: skip
outcomes_st = st.sampled_from(["true_positive", "benign_expected", "inconclusive",
                               "rule_false_positive"])  # fmt: skip
verdict_st = st.builds(
    Verdict, st.none() | outcomes_st, st.booleans(),
    st.lists(outcomes_st, max_size=4).map(tuple), st.lists(outcomes_st, max_size=4).map(tuple),
)  # fmt: skip
servers_st = st.lists(st.sampled_from(SERVERS) | hostile, max_size=6).map(tuple)
sets_st = st.dictionaries(st.sampled_from([*SERVERS, BEACON, PORTS, CAMPAIGN, OUTSIDE, LISTED,
                                           naming.BEACON_PORTS, "r1.fast.example"]),
                          st.frozensets(device_values, max_size=6), max_size=5)  # fmt: skip
path_st = st.sampled_from(["/.env", "/wp-login.php", "/.git/config", "/", "/backup.zip",
                           "/../etc/passwd", "/admin", "/config.yml"]) | hostile  # fmt: skip
sites_st = st.sampled_from([SITE, "a.example.edu", "b.example.edu"]) | hostile
path_outcome_st = st.sampled_from(["success", "catch_all", "refused", "possible", "unknown"])
facts_st = st.builds(
    Facts,
    rules=st.lists(st.tuples(hostile, st.integers(1, 9)), max_size=3).map(tuple),
    flags=flags_st,
    devices=st.lists(devices_st, max_size=8).map(tuple),
    outsiders=st.lists(st.sampled_from(ATTACKERS) | hostile, max_size=8).map(tuple),
    accounts=st.integers(0, 5),
    servers=servers_st,
    domains=st.lists(
        hostile | st.sampled_from([f"r{i}.fast.example" for i in range(4)]), max_size=10
    ).map(tuple),
    sites=st.lists(sites_st, max_size=5).map(tuple),
    own_servers=st.integers(0, 40),
    listed=st.lists(st.sampled_from([*SERVERS, *ATTACKERS]) | hostile, max_size=5).map(tuple),
    labels=st.lists(
        hostile | st.sampled_from(["amadey", "PS1Bot C2", "cobalt strike"]), max_size=3
    ).map(tuple),
    follows=st.integers(0, 99999),
    verdict=verdict_st,
    doing=sets_st.map(MappingProxyType),
    reaches=sets_st.map(MappingProxyType),
    destinations=servers_st,
    vt=st.dictionaries(st.sampled_from(SERVERS) | hostile, st.integers(0, 90), max_size=3).map(
        MappingProxyType
    ),
    paths=st.lists(path_st, max_size=6).map(tuple),
    answered=st.lists(st.tuples(sites_st, path_st), max_size=4).map(tuple),
    outcomes=st.lists(st.tuples(sites_st, path_st, path_outcome_st), max_size=4).map(tuple),
    checks=st.frozensets(st.sampled_from(["ok", "empty", "skipped_budget"])),
    server_cases=st.dictionaries(
        st.sampled_from(SERVERS) | hostile, st.integers(0, 999), max_size=3
    ).map(MappingProxyType),
    beacon_reaches=st.none() | sets_st.map(MappingProxyType),
    campaign_reaches=st.none() | sets_st.map(MappingProxyType),
)
SLOW = settings(suppress_health_check=[HealthCheck.too_slow], max_examples=300, deadline=None)


@SLOW
@given(facts_st)
def test_every_claim_is_backed_and_the_bounds_hold(f: Facts) -> None:
    made = titled(f)
    out = made.text
    assert check(made, f) == [], (out, check(made, f))
    assert 1 <= len(out) <= naming.MAX_TITLE
    assert not (set(out) - ALLOWED), out
    assert out == out.strip()
    assert "  " not in out
    assert titled(f) == made  # the same facts give the same title
    if made.parts[0] != naming.EMPTY:
        activity = next(c for c in made.claims if c.slot == "activity")
        assert out.index(activity.words) + len(activity.words) <= naming.FRONT
        assert made.claims[0].slot == "certainty"
        assert made.claims[0].words.rstrip(":") == naming.certainty(f)


@SLOW
@given(facts_st)
def test_every_address_and_name_in_a_title_comes_from_the_facts(f: Facts) -> None:
    given_values = {*(d.value for d in f.devices), *f.outsiders, *f.servers, *f.domains, *f.sites,
                    *f.destinations}  # fmt: skip
    ips = {a for v in given_values if (a := outside_facts.canonical("ip", v))}
    names = {n for v in given_values if (n := outside_facts.canonical("domain", v))}
    names |= {p for n in names if (p := naming.registered_parent(n))}
    words = " ".join([*(r for r, _ in f.rules), *(d.place or "" for d in f.devices)])
    for raw in title(f).replace("—", " ").split():
        token = raw.strip(",()'").rstrip(":")
        if token in words or token in given_values:
            continue
        try:
            ipaddress.ip_address(token)
        except ValueError:
            if "." in token and not token.endswith(".") and not token.startswith("."):
                assert token in names, token
        else:
            assert token in ips, token


@SLOW
@given(facts_st, st.text(alphabet=string.ascii_letters + " ", min_size=1, max_size=20))
def test_a_rule_name_never_chooses_the_words(f: Facts, renamed: str) -> None:
    made = titled(f)
    other = titled(dataclasses.replace(
        f, rules=tuple((f"{renamed} {i}", n) for i, (_, n) in enumerate(f.rules))
    ))  # fmt: skip
    fallback = [
        t
        for t in (made, other)
        if t.parts[0] == naming.EMPTY or any(c.fact == "activity:rule" for c in t.claims)
    ]
    if fallback:
        return  # the fallback quotes the rule: only that claim may change
    assert other.text == made.text


@SLOW
@given(facts_st)
def test_counts_are_the_sizes_of_their_sets(f: Facts) -> None:
    devices_m = len(dict.fromkeys(d.value for d in f.devices if d.value))
    for claim in titled(f).claims:
        if claim.fact.startswith("actors:"):
            _, _, n, m = claim.fact.split(":")
            assert int(n) <= int(m) == devices_m
            assert claim.words.startswith((n + " ", "a ", "an "))
        if claim.fact.startswith("outsiders:"):
            assert int(claim.fact.split(":")[1]) == len(dict.fromkeys(v for v in f.outsiders if v))


@SLOW
@given(facts_st)
def test_an_outcome_after_a_site_named_alone_is_that_sites_own(f: Facts) -> None:
    claims = titled(f).claims
    named = [c.fact.removeprefix("site:") for c in claims if c.fact.startswith("site:")]
    more = any(c.fact.startswith("more:sites:") for c in claims)
    backing = naming.outcome_sites(f)
    if named and not more and any(c.slot == "outcome" for c in claims) and backing is not None:
        assert (
            len(dict.fromkeys(v for v in f.sites if v)) <= 1 or naming.domain(named[0]) in backing
        )


COUNT_FACTS = ("actors:", "count:", "more:", "outsiders:", "vt:", "zone:", "listed_actors:",
               "accounts:", "rules:")  # fmt: skip
ALONE = re.compile(r"(?<![\w.-])\d+(?![\w.-])")


@SLOW
@given(facts_st)
def test_the_counts_of_a_title_are_its_count_claims(f: Facts) -> None:
    """Exactly the numbers of the count claims are counts: a title's addresses, cases, places and
    families never are."""
    made = titled(f)
    expected = tuple(
        int(n)
        for c in made.claims
        if c.fact.startswith(COUNT_FACTS)
        for n in ALONE.findall(c.words)
    )
    assert naming.counts_in(made.text)[1] == expected, made.text


@SLOW
@given(facts_st)
def test_kibana_form_has_no_certainty_and_fits(f: Facts) -> None:
    out = title(f)
    word, _ = naming.split_certainty(out)
    kibana = f"ACME-IR-2026-1106-01 · {naming.without_certainty(out, word)}"
    assert len(kibana.encode("utf-16-le")) // 2 <= 160
    if word is not None:
        assert naming.split_certainty(kibana.split(" · ", 1)[1])[0] is None


@SLOW
@given(facts_st)
def test_removing_a_fact_never_leaves_its_claim_standing(f: Facts) -> None:
    made = titled(f)
    for gone in (dataclasses.replace(f, outcomes=()),
                 dataclasses.replace(f, vt=MappingProxyType({})),
                 dataclasses.replace(f, server_cases=MappingProxyType({})),
                 dataclasses.replace(f, labels=()), dataclasses.replace(f, verdict=Verdict()),
                 dataclasses.replace(f, follows=0)):  # fmt: skip
        stale = [c for c in made.claims if c.words not in naming.held(gone).get(c.fact, ())]
        if stale:
            assert check(made, gone)
        assert check(titled(gone), gone) == []


@given(st.integers(1, 30), st.integers(0, 30))
def test_a_device_without_the_activity_changes_m_not_n(n: int, extra: int) -> None:
    f = Facts(flags=frozenset({BEACON}), devices=devices(n + extra), servers=(SERVER,),
              doing=MappingProxyType({BEACON: values(n)}), verdict=TP)  # fmt: skip
    claim = next(c for c in titled(f).claims if c.slot == "actors")
    if n == 1:
        assert claim.fact == "device:10.0.4.1"
    else:
        assert claim.fact == f"actors:beacon:{n}:{n + extra}"


def test_a_path_check_moves_the_outcome_up_the_ladder() -> None:
    base = web(answered=((SITE, "/.env"),))
    assert title(base).endswith("got HTTP 200, not verified")
    catch = dataclasses.replace(base, outcomes=((SITE, "/.env", "catch_all"),))
    assert title(catch).endswith("the site answers every path alike")
    served = dataclasses.replace(base, outcomes=((SITE, "/.env", "success"),))
    assert title(served).endswith("a .env file served")


def test_a_persons_true_positive_turns_likely_into_confirmed_and_nothing_else() -> None:
    f = web(answered=((SITE, "/.env"),))
    confirmed = dataclasses.replace(f, verdict=Verdict(person="true_positive"))
    assert naming.change_of(title(f), title(confirmed)) == "certainty"


FIRST = ("server:", "dest:", "site:", "parent:")


@SLOW
@given(facts_st, facts_st)
def test_different_first_objects_never_share_a_title(a: Facts, b: Facts) -> None:
    ta, tb = titled(a), titled(b)
    oa = next((c for c in ta.claims if c.slot == "object" and c.fact.startswith(FIRST)), None)
    ob = next((c for c in tb.claims if c.slot == "object" and c.fact.startswith(FIRST)), None)
    if oa is not None and ob is not None and oa.words != ob.words:
        assert ta.text != tb.text


def test_attacked_paths_name_what_was_looked_for_in_fixed_words() -> None:
    envs = ("/.env.local", "/admin/.env", "/api/.env", "/.env.bak.zip~")
    assert naming.probed(envs) == ".env"
    assert naming.probed(("/@fs/proc", "/../etc/passwd")) == "path-traversal"
    assert naming.probed(("/a", "/b", "/.git/config")) is None
    assert naming.probed(()) is None
    assert naming.scan_kinds(("/db.sql", "/x.bak", "/.env", "/b/.env")) == (".env", "backup")
    assert naming.file_kind("/wp-config.php") == "config"
    assert naming.file_kind("/.git/config") == "git"
    assert naming.file_kind("/academic/") == naming.ORDINARY


def test_a_family_is_the_tables_spelling_matched_as_whole_words() -> None:
    assert naming.family_of(["suspicious-udp", "AMADEY"]) == "Amadey"
    assert naming.family_of(["agenttesla"]) is None
    assert naming.family_of(["Agent_Tesla"]) == "Agent Tesla"
    assert naming.family_of(["PS1Bot C2 server"]) == "PS1Bot"
    assert naming.family_of(["tor", "cdn"]) is None
    assert all(naming.family_of([name]) == name for name in naming.FAMILIES)


def test_a_rule_name_is_plain_words_or_it_is_not_used() -> None:
    assert naming.rule_name("  Web:   Sensitive,  Backup\tFile ") == "Web: Sensitive, Backup File"
    assert naming.rule_name("`rm -rf` <b>x</b>") is None
    assert naming.rule_name("x" * 30 + " " + "y" * 40) == "x" * 30


def test_a_long_scan_keeps_the_site_named_before_it_keeps_the_kind() -> None:
    lab = "portal.chem.example.edu"
    f = web(paths=("/../a", "/../b", "/c.bak", "/d.bak"), sites=(lab,), answered=((lab, "/.env"),))
    assert title(f) == (  # the two kinds do not fit with the site: the site stays, as "web scan"
        f"Likely web scan of {lab} by 6 outside IPs — a .env file got HTTP 200, not verified"
    )
