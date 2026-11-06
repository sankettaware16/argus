"""Naming v2's golden examples: made-up cases shaped like the naming audit's real ones (each failure
class: "served" from a rule's name, the wrong kind word, an over-count, a verb against ARGUS's own
verdict, no certainty, no site, no destination, a family or a place missing), as the database
would hold them (:class:`titling.Found`), with the title v1 gave and the title v2 gives. Every value
is made up (TEST-NET addresses, private campus ranges, ``example`` domains); nothing is a real
alert, address or site."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from argus.assets import parse_asset_map
from argus.assets.classify import IpClassifier
from argus.cases import naming, titling
from argus.cases.naming import BEACON, CAMPAIGN, OUTSIDE, PORTS
from argus.cases.titling import Context, Found, Member

ASSETS = parse_asset_map(
    b"""
defaults: {site.organization: Example}
networks:
  - {name: H4, range: 10.20.4.0/24,
     fields: {site.type: switch, site.zone: hostel, site.building: Hostel 4}}
  - {name: H9, range: 10.20.9.0/24,
     fields: {site.type: gateway, site.zone: hostel, site.building: Hostel 9}}
  - {name: CSE, range: 10.30.6.0/24,
     fields: {site.type: lab, site.zone: department, site.department: Dept North}}
  - {name: DeptS, range: 10.30.20.0/24,
     fields: {site.type: switch, site.zone: department, site.department: Dept South}}
  - {name: Misc, range: 10.40.0.0/16, fields: {site.type: switch}}
"""
)
CTX = Context(IpClassifier(ASSETS), ("example.edu",))
TP = ("proposal", "true_positive")
Said = tuple[str, str] | None


def vt(value: str, bad: int) -> tuple[str, str, str, str, dict[str, Any]]:
    answer = {"malicious": bad, "suspicious": 0, "engines": 94}
    return ("virustotal", "ip", value, "found", answer)


def member(
    rule: str, flags: Iterable[str] = (), entities: Iterable[tuple[str, str]] = (),
    said: Said = TP, reviewed: str | None = None, threats: Iterable[str] = (),
) -> Member:  # fmt: skip
    return Member(rule, tuple(flags), (), tuple(entities), tuple(threats), reviewed, said)


def outsiders(n: int) -> list[tuple[str, str, str]]:
    return [("ip", f"203.0.113.{i + 1}", "actor") for i in range(n)]


ENV = ("/.env", "/api/.env", "/.env.bak", "/admin/.env", "/.env.local")
WP = ("/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/wp-content/x")
GIT = ("/.git/config", "/.git/HEAD", "/.git.tar.gz", "/.git.zip")
TRAVERSAL = ("/../etc/passwd", "/a/../b", "/%2e%2e/x", "/..%2fwin.ini")
WEB_RULES = ("Web: path probe", "Web: scanner")


def scan(
    paths: Iterable[str], n: int, sites: Iterable[str] = (),
    answered: Iterable[tuple[str, str]] = (), outcomes: Iterable[tuple[str, str, str]] = (),
    checks: frozenset[str] = frozenset({"ok"}), said: Said = TP, reviewed: str | None = None,
) -> Found:  # fmt: skip
    return Found(
        members=[member(r, said=said, reviewed=reviewed) for r in WEB_RULES],
        indicators=[*outsiders(n), *(("url", p, "indicator") for p in paths)],
        sites=list(sites), answered=list(answered), outcomes=list(outcomes), checks=checks,
    )  # fmt: skip


def beacon(
    devices: list[str], server: str, timed: Iterable[str], reaching: Iterable[str],
    engines: int = 0, said: Said = TP, cases: dict[str, int] | None = None,
    threats: Iterable[str] = (), more: Iterable[str] = (),
) -> Found:  # fmt: skip
    timed, reaching = set(timed), set(reaching)
    members = [
        member("Proxy: plain HTTP POST to an address", [*([BEACON] if d in timed else []), *more],
               [("ip", d), *([("ip", server)] if d in reaching else [])], said, threats=threats)
        for d in devices
    ]  # fmt: skip
    return Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in devices), ("ip", server, "indicator")],
        outside=[vt(server, engines)] if engines else [],
        server_cases=cases or {},
    )


def dns_campaign() -> Found:
    devices = [f"10.20.4.{i}" for i in range(1, 20)] + [f"10.40.1.{i}" for i in range(1, 21)]
    names = [f"k{i}.rare-names.example" for i in range(30)]
    names += [f"w{i}.svc-update.example" for i in range(11)]
    members = [  # each of the 23 campaign investigations names a name under both parents
        member("DNS: many unique subdomains of a rare domain", [CAMPAIGN] if i < 23 else [],
               [("ip", d), *([("domain", names[i]), ("domain", names[30 + i % 11])]
                             if i < 23 else [])])
        for i, d in enumerate(devices)
    ]  # fmt: skip
    return Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in devices),
                    *(("domain", n, "indicator") for n in names)],
    )  # fmt: skip


def reference_dns() -> Found:
    hostel = [f"10.20.4.{i}" for i in range(1, 30)] + [f"10.20.9.{i}" for i in range(1, 19)]
    names = [f"a{i}.rare-names.example" for i in range(12)]
    names += [f"b{i}.svc-update.example" for i in range(9)]
    members = [
        member("DNS: many unique subdomains of a rare domain", [CAMPAIGN],
               [("ip", d), ("domain", names[i % len(names)])], reviewed="true_positive")
        for i, d in enumerate(hostel)
    ]  # fmt: skip
    return Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in hostel),
                    *(("domain", n, "indicator") for n in names)],
    )  # fmt: skip


def one_device(device: str, servers: list[str], flags: list[str]) -> Found:
    entities = [("ip", device), *(("ip", s) for s in servers)]
    return Found(
        members=[member("Proxy: allowed tunnel to a remote-admin port", flags, entities)],
        indicators=[("ip", device, "actor")],
    )


def eight_devices() -> Found:
    devices = [f"10.40.5.{i}" for i in range(1, 9)]
    members = [
        member("Proxy: plain HTTP POST to an address", [BEACON] if i < 4 else [],
               [("ip", d), *([("ip", "198.51.100.48")] if i < 7 else [])])
        for i, d in enumerate(devices)
    ]  # fmt: skip
    return Found(
        members=members,
        indicators=[*(("ip", d, "actor") for d in devices), ("ip", "198.51.100.48", "indicator"),
                    ("ip", "198.51.100.49", "indicator")],
        outside=[vt("198.51.100.48", 11), vt("198.51.100.49", 6)],
    )  # fmt: skip


SITES4 = ["portal.example.edu", "www.example.edu", "home.dept.example.edu", "www.lab2.example.edu"]
DEV10 = [f"10.40.10.{i}" for i in range(1, 23)]
DEV14 = [f"10.40.14.{i}" for i in range(1, 8)]
DEV7 = [f"10.40.7.{i}" for i in range(1, 5)]
DEV21 = [f"10.40.21.{i}" for i in range(1, 4)]
MED = "www.clinic.example.edu"

# (what the case is, its facts, the title v1 gave, the title v2 gives)
GOLDEN: list[tuple[str, Found, str, str]] = [
    ("a person's .env scan: sites from the stored checks, 200 not verified",
     scan(ENV, 21, SITES4,
          [("portal.example.edu", "/search/.env"), ("www.example.edu", "/web.config")],
          reviewed="true_positive"),
     "Probing for .env secrets files by 21 outside addresses — config files served",
     "Confirmed .env scan of portal.example.edu +3 sites by 21 outside IPs"
     " — got HTTP 200, not verified"),
    ("the follow-ups came back empty: nothing was served",
     scan(ENV, 3, checks=frozenset({"empty"})),
     "Probing for .env secrets files by 3 outside addresses — config files served",
     "Likely .env scan by 3 outside IPs — no HTTP 200 after the alerts"),
    ("a DNS campaign: 23 of 39 devices named the domains",
     dns_campaign(),
     "Beaconing to rare-names.example and 1 more flagged server from 39 campus devices",
     "Likely DNS beaconing to rare-names.example and svc-update.example"
     " from 23 of 39 campus devices"),
    ("one device on a remote-admin port: its department and destinations",
     one_device("10.30.6.59", ["192.0.2.10", "192.0.2.11", "192.0.2.12"], [BEACON, PORTS, OUTSIDE]),
     "Beaconing from 10.30.6.59",
     "Likely beaconing on a remote-admin port from 10.30.6.59 to 192.0.2.10"
     " +2 outside servers"),  # its department is the first detail to go (101 characters)
    ("8 devices, 4 beacon-timed to a named server",
     eight_devices(),
     "Beaconing to 198.51.100.48 and 1 more flagged server from 8 campus devices",
     "Likely beaconing to 198.51.100.48 +1 flagged server from 4 of 8 campus devices"),
    ("ARGUS's benign reading against a flagged server of another case",
     beacon(["10.40.6.26"], "198.51.100.81", ["10.40.6.26"], ["10.40.6.26"], 12,
            ("reading", "benign_expected"), {"198.51.100.81": 11}),
     "Beaconing to 198.51.100.81 from 10.40.6.26",
     "Unclear: beaconing from 10.40.6.26 to 198.51.100.81 (VirusTotal: 12 engines),"
     " the server of case 11"),
    ("a WordPress scan whose WordPress page answered",
     scan(WP, 12, ["jobs.example.edu", "apps.example.edu"],
          [("jobs.example.edu", "/xmlrpc.php")]),
     "Probing for WordPress pages by 12 outside addresses — some got successful answers",
     "Likely WordPress scan of jobs.example.edu +1 site by 12 outside IPs"
     " — got HTTP 200, not verified"),
    ("one device whose destination is case 14's server",
     beacon(["10.40.8.99"], "198.51.100.121", ["10.40.8.99"], ["10.40.8.99"],
            cases={"198.51.100.121": 14}, more=[PORTS]),
     "Beaconing from 10.40.8.99",
     "Likely beaconing on a remote-admin port from 10.40.8.99 to 198.51.100.121,"
     " the server of case 14"),
    ("22 devices, 12 beacon-timed: who flagged the server",
     beacon(DEV10, "198.51.100.242", DEV10[:12], DEV10[:18], 4),
     "Beaconing to 198.51.100.242 from 22 campus devices",
     "Likely beaconing to 198.51.100.242 (VirusTotal: 4 engines) from 12 of 22 campus devices"),
    ("only the home page answered a WordPress scan",
     scan(WP, 2, ["a.example.edu", "b.example.edu", "c.example.edu", "d.example.edu"],
          [("a.example.edu", "/")]),
     "Probing for WordPress pages by 2 outside addresses — config files served",
     "Likely WordPress scan of a.example.edu +3 sites by 2 outside IPs"
     " — only ordinary pages got HTTP 200"),
    ("an accurate title already: it gains certainty and who flagged the server",
     beacon(DEV14, "198.51.100.121", DEV14, DEV14, 5),
     "Beaconing to 198.51.100.121 from 7 campus devices",
     "Likely beaconing to 198.51.100.121 (VirusTotal: 5 engines) from 7 campus devices"),
    ("a Git-folder scan whose archives answered on many sites",
     scan(GIT, 9, [f"s{i}.example.edu" for i in range(9)],
          [(f"s{i}.example.edu", "/.git.tar.gz") for i in range(8)]),
     "Probing for Git repository folders by 9 outside addresses — config files served",
     "Likely Git-folder scan of s0.example.edu +8 sites by 9 outside IPs"
     " — got HTTP 200, not verified"),
    ("a .env scan that many .env paths answered on one site",
     scan(ENV, 6, [MED, "x.example.edu"], [(MED, p) for p in ENV]),
     "Probing for .env secrets files by 6 outside addresses — config files served",
     f"Likely .env scan of {MED} +1 site by 6 outside IPs — got HTTP 200, not verified"),
    ("a path-traversal scan that .env files answered",
     scan(TRAVERSAL, 6, ["www.centre.example.edu"],
          [("www.centre.example.edu", "/.env"), ("www.centre.example.edu", "/secrets.env")]),
     "Probing for path traversal by 6 outside addresses — config files served",
     "Likely path-traversal scan of www.centre.example.edu by 6 outside IPs"
     " — got HTTP 200, not verified"),
    ("a backup scan that a .env file answered",
     scan(("/db.sql", "/backup.zip", "/.env", "/x/.env", "/a.bak"), 3,
          ["apps.example.edu", *(f"t{i}.example.edu" for i in range(5))],
          [("apps.example.edu", "/db.sql"), ("apps.example.edu", "/.env")]),
     "Web attack by 3 outside addresses got successful answers",
     "Likely backup scan of apps.example.edu by 3 outside IPs"
     " — a .env file got HTTP 200, not verified"),
    ("no web check stored at all",
     scan(WP, 2, checks=frozenset()),
     "Probing for WordPress pages by 2 outside addresses — config files served",
     "Likely WordPress scan by 2 outside IPs — no web check yet"),
    ("no web check and no evidence flag",
     scan(ENV, 2, checks=frozenset()),
     "Probing for .env secrets files by 2 outside addresses — config files served",
     "Likely .env scan by 2 outside IPs — no web check yet"),
    ("one device, a remote-admin port, its department and destination",
     one_device("10.30.20.32", ["192.0.2.178"], [BEACON, PORTS]),
     "Beaconing from 10.30.20.32",
     "Likely beaconing on a remote-admin port from 10.30.20.32 (Dept South) to 192.0.2.178"),
    ("a family from a threat name ARGUS stores",
     beacon(DEV7, "198.51.100.158", DEV7, DEV7, 13, threats=["Amadey C2"]),
     "Beaconing to 198.51.100.158 from 4 campus devices",
     "Likely Amadey beaconing to 198.51.100.158 (VirusTotal: 13 engines) from 4 campus devices"),
    ("ARGUS's benign reading of three devices against a flagged server",
     beacon(DEV21, "198.51.100.90", DEV21, DEV21, 3, ("reading", "benign_expected")),
     "Beaconing to 198.51.100.90 from 3 campus devices",
     "Unclear: beaconing to 198.51.100.90 (VirusTotal: 3 engines) from 3 campus devices"),
    ("a WordPress scan that a config file answered",
     scan(WP, 2, answered=[("w.example.edu", "/wp-config.php")]),
     "Probing for WordPress pages by 2 outside addresses — some got successful answers",
     "Likely WordPress scan of w.example.edu by 2 outside IPs"
     " — a config file got HTTP 200, not verified"),
    ("ordinary pages answered and no WordPress kind holds",
     scan(("/wp-login.php", "/a", "/b", "/c"), 2,
          answered=[("w.example.edu", "/"), ("w.example.edu", "/academic/")]),
     "Probing for WordPress pages by 2 outside addresses — some got successful answers",
     "Likely web scan of w.example.edu by 2 outside IPs — only ordinary pages got HTTP 200"),
    ("no verdict yet: Suspected",
     scan(TRAVERSAL[:3], 5, answered=[("v.example.edu", "/.env"), ("v.example.edu", "/Dockerfile")],
          said=None),
     "Probing for path traversal by 5 outside addresses — config files served",
     "Suspected path-traversal scan of v.example.edu by 5 outside IPs"
     " — got HTTP 200, not verified"),
    ("served after ARGUS's own path check",
     scan(ENV, 4, [MED], [(MED, "/.env")], [(MED, "/.env", "success"), (MED, "/no", "refused")]),
     "Probing for .env secrets files by 4 outside addresses — config files served",
     f"Likely .env scan of {MED} by 4 outside IPs — a .env file served"),
    ("a site that answers every path alike",
     scan(ENV, 4, [MED], [(MED, "/.env")], [(MED, p, "catch_all") for p in ENV]),
     "Probing for .env secrets files by 4 outside addresses — config files served",
     f"Likely .env scan of {MED} by 4 outside IPs — the site answers every path alike"),
    ("the team's reference case, confirmed by a person",
     reference_dns(),
     "DNS lookups of 21 look-alike domains under rare-names.example and"
     " svc-update.example from 47 campus devices",
     "Confirmed DNS beaconing to rare-names.example and svc-update.example"
     " from 47 campus devices"),
]  # fmt: skip


@pytest.mark.parametrize(("what", "found", "before", "after"), GOLDEN, ids=[g[0] for g in GOLDEN])
def test_golden_title(what: str, found: Found, before: str, after: str) -> None:
    made = titling.titled_of(found, CTX)
    assert made is not None
    assert made.text == after, what
    assert made.text != before
    facts = titling.facts_of(found, CTX)
    assert naming.check(made, facts) == []
    assert len(made.text) <= naming.MAX_TITLE


def test_no_two_golden_titles_are_the_same() -> None:
    afters = [g[3] for g in GOLDEN]
    assert len(set(afters)) == len(afters)


def test_served_is_said_only_with_a_path_check_behind_it() -> None:
    for _, found, _, after in GOLDEN:
        if "served" in after:
            assert any(o == "success" for _, _, o in found.outcomes), after


def test_the_golden_kibana_titles_carry_no_certainty_and_fit() -> None:
    for _, _found, _, after in GOLDEN:
        word, rest = naming.split_certainty(after)
        assert word is not None
        kibana = f"ACME-IR-2026-1106-01 · {naming.without_certainty(after, word)}"
        assert len(kibana) <= 160
        assert kibana.split(" · ", 1)[1][:1] == rest[:1].upper()
