"""Naming v2 on the incident engine's facts: golden before/after examples, made up in the shapes of
the naming audit's real cases (the over-counted beacon, the single device with no destination,
"served" with no check, a site never named, a family and a place missing). ``before`` is the title
the case titler gave such a case from its alert rows; ``after`` the one the engine's own facts give.
Every value is made up (``titles_kit``)."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from argus.cases import naming
from argus.risk.exposure import PairFacts
from argus.risk.titles import IncidentFacts, LinkFacts, title_for_incident
from tests.unit.risk.titles_kit import chain, dev, grp, host, incident, site

pytestmark = pytest.mark.unit

S = "203.0.113.10"
HOSTEL = [f"10.20.4.{i}" for i in range(10, 32)] + [f"10.20.9.{i}" for i in range(10, 12)]


def overcount() -> IncidentFacts:
    """22 devices reach a flagged server; 12 of them beacon to it (the rest came in through it)."""
    devices = [dev(a) for a in HOSTEL[:22]]
    groups = [grp({d: {"beacon"} if i < 12 else set()}, threats=[S]) for i, d in enumerate(devices)]
    return incident(groups, links=chain(devices, "flagged", f"ip:{S}"),
                    flags={f"ip:{S}": "outside"}, vt={S: 4})  # fmt: skip


def one_device_server_of_case() -> IncidentFacts:
    """One device beacons to a server the linker kept apart: another incident's (case 14)."""
    return incident([grp({dev("10.40.2.17"): {"beacon"}}, threats=["198.51.100.9"])],
                    others={"198.51.100.9": 14})  # fmt: skip


def remote_admin_port() -> IncidentFacts:
    return incident([grp({dev("10.30.6.59"): {"beacon", "ports"}}, threats=["198.51.100.33"])])


def family_from_threat_names() -> IncidentFacts:
    d = dev("10.40.9.26")
    return incident([grp({d: {"beacon", "outside"}}, threats=["203.0.113.81"])],
                    flags={"ip:203.0.113.81": "outside"}, vt={"203.0.113.81": 12},
                    labels={"203.0.113.81": ("amadey", "loader")})  # fmt: skip


def campaign_family() -> IncidentFacts:
    """Three devices a campaign binds through a listed server whose threat-list entry names
    PS1Bot; two of them beacon to it."""
    devices = [dev(f"10.40.5.{i}") for i in (3, 4, 5)]
    thing = "ip:198.51.100.70"
    groups = [grp({d: {"beacon"} if i < 2 else {"ti"}}, threats=["198.51.100.70"])
              for i, d in enumerate(devices)]  # fmt: skip
    return incident(
        groups,
        links=chain(devices, "campaign", f"threat:{thing}"),
        flags={thing: "ti"},
        labels={"198.51.100.70": ("PS1Bot C2 server list",)},
    )


def dns_campaign() -> IncidentFacts:
    """Hostel devices ask for random names under two rare parents; the campaign binds them."""
    devices = [dev(a) for a in HOSTEL[15:]]  # two hostels
    names = [f"x{i}k2q.rare-names.example" for i in range(4)]
    names += [f"u{i}zz9.svc-update.example" for i in range(3)]
    groups = [grp({d: ()}, threats=names[i % 7 : i % 7 + 2]) for i, d in enumerate(devices)]
    links = chain(
        devices, "campaign", "campaign:domain:rare-names.example,domain:svc-update.example"
    )
    return incident(groups, links=links)


def contact_listed() -> IncidentFacts:
    devices = [dev(f"10.40.7.{i}") for i in (1, 2, 3)]
    groups = [grp({d: {"ti"}}, threats=["198.51.100.48"]) for d in devices]
    return incident(groups, links=chain(devices, "flagged", "ip:198.51.100.48"),
                    flags={"ip:198.51.100.48": "ti"})  # fmt: skip


def same_host() -> IncidentFacts:
    """An address and the host name the linker's host link ties to it: one device."""
    a, h = dev("10.40.3.8"), host("lab-pc-08")
    groups = [
        grp({a: {"beacon"}}, threats=["203.0.113.90"]),
        grp({h: ()}, threats=["203.0.113.90"]),
    ]
    return incident(groups, links=[LinkFacts(a, h, "host", "host:lab-pc-08")])


WEBSITE, OTHER = "www.dept-a.example.edu", "lab.example.edu"
SCANNERS = ["198.51.100.20", "198.51.100.21", "203.0.113.40", "203.0.113.41", "203.0.113.42",
            "203.0.113.43"]  # fmt: skip
ENV = ["/.env", "/api/*.env", "/.env.bak", "/admin/*.env", "/.env.local"]


def web(**more: Any) -> Callable[[], IncidentFacts]:
    answered = more.pop("answered", [(WEBSITE, "/.env")])
    checks = more.pop("checks", ("ok",))

    def make() -> IncidentFacts:
        groups = [grp({site(WEBSITE): {"success"}}, actors=[s], paths=ENV, rule="Path rule",
                      answered=answered, checks=checks) for s in SCANNERS]  # fmt: skip
        groups.append(grp({site(OTHER): ()}, actors=[SCANNERS[0]], paths=ENV[:2], rule="Path rule"))
        return incident(groups, **more)

    return make


def wordpress_unchecked() -> IncidentFacts:
    groups = [
        grp(
            {site("blog.example.edu"): ()},
            actors=[s],
            rule="Path rule",
            paths=["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
        )
        for s in SCANNERS[:2]
    ]
    return incident(groups)


def follows_sealed() -> IncidentFacts:
    return incident([grp({dev("10.40.2.40"): {"beacon"}}, threats=["198.51.100.61"])], follows=7)


def rule_only() -> IncidentFacts:
    return incident([grp([dev("10.40.1.5")], rule="Proxy: Port Sweep or Fan-out from One Host")])


SERVED = PairFacts(SCANNERS[0], WEBSITE, served=("/.env",), through=("/.env",),
                   checked=("catchall", "paths"))  # fmt: skip
GOLDEN: list[tuple[str, Callable[[], IncidentFacts], str, str, str]] = [
    (
        "overcount",
        overcount,
        naming.LIKELY,
        f"Beaconing to {S} from 22 campus devices",
        f"Likely beaconing to {S} (VirusTotal: 4 engines) from 12 of 22 campus devices in Hostel 4",
    ),
    (
        "destination",
        one_device_server_of_case,
        naming.LIKELY,
        "Beaconing from 10.40.2.17",
        "Likely beaconing from 10.40.2.17 to 198.51.100.9, the server of case 14",
    ),
    (
        "port and place",
        remote_admin_port,
        naming.SUSPECTED,
        "Beaconing from 10.30.6.59",
        "Suspected beaconing on a remote-admin port from 10.30.6.59 (Dept North) to 198.51.100.33",
    ),
    (
        "family",
        family_from_threat_names,
        naming.UNCLEAR,
        "Beaconing to 203.0.113.81 from 10.40.9.26",
        "Unclear: Amadey beaconing from 10.40.9.26 to 203.0.113.81 (VirusTotal: 12 engines)",
    ),
    (
        "campaign family",
        campaign_family,
        naming.LIKELY,
        "Contact with a threat-listed address from several campus devices",
        "Likely PS1Bot beaconing to 198.51.100.70 (on a threat list) from 2 of 3 campus devices",
    ),
    (
        "dns",
        dns_campaign,
        naming.LIKELY,
        "Beaconing to rare-names.example and 1 more flagged server from 9 campus devices",
        "Likely DNS beaconing to rare-names.example and svc-update.example from 9 campus devices"
        " in hostels",
    ),
    (
        "contact",
        contact_listed,
        naming.SUSPECTED,
        "Several campus devices reach outside infrastructure flagged by threat intel",
        "Suspected contact with 198.51.100.48 (on a threat list) from 3 campus devices",
    ),
    (
        "one host",
        same_host,
        naming.SUSPECTED,
        "Beaconing to 203.0.113.90 from 2 campus devices",
        "Suspected beaconing from 10.40.3.8 to 203.0.113.90",
    ),
    (
        "unverified",
        web(),
        naming.LIKELY,
        "Probing for .env secrets files by 6 outside addresses — config files served",
        f"Likely .env scan of {WEBSITE} +1 site by 6 outside IPs — got HTTP 200, not verified",
    ),
    (
        "served",
        web(exposure=[SERVED]),
        naming.LIKELY,
        "Probing for .env secrets files by 6 outside addresses — config files served",
        f"Likely .env scan of {WEBSITE} +1 site by 6 outside IPs — a .env file served",
    ),
    (
        "catch-all",
        web(catch_all=[(WEBSITE, "/.env")]),
        naming.LIKELY,
        "Probing for .env secrets files by 6 outside addresses — config files served",
        f"Likely .env scan of {WEBSITE} by 6 outside IPs — the site answers every path alike",
    ),
    (
        "empty",
        web(answered=[], checks=("empty",)),
        naming.SUSPECTED,
        "Probing for .env secrets files by 6 outside addresses — config files served",
        f"Suspected .env scan of {WEBSITE} +1 site by 6 outside IPs — got HTTP 200, not verified",
    ),
    (
        "no check",
        wordpress_unchecked,
        naming.LIKELY,
        "Probing for WordPress pages by 2 outside addresses — config files served",
        "Likely WordPress scan of blog.example.edu by 2 outside IPs — no web check yet",
    ),
    (
        "follows",
        follows_sealed,
        naming.HARMLESS,
        "Activity after case 7 was closed",
        "Likely harmless: beaconing from 10.40.2.40 to 198.51.100.61 — follows case 7",
    ),
    (
        "fallback",
        rule_only,
        naming.SUSPECTED,
        "Proxy: Port Sweep or Fan-out from One Host: 10.40.1.5 → several outside addresses",
        "Suspected: alerts of rule 'Proxy: Port Sweep or Fan-out from One Host' for 10.40.1.5",
    ),
]


@pytest.mark.parametrize(("name", "make", "word", "before", "after"), GOLDEN,
                         ids=[g[0] for g in GOLDEN])  # fmt: skip
def test_golden(name: str, make: Callable[[], IncidentFacts], word: str, before: str,
                after: str) -> None:  # fmt: skip
    made = title_for_incident(make(), word)
    assert made.text == after
    assert made.text != before
    assert len(made.text) <= naming.MAX_TITLE
    assert made.certainty == word
    assert not made.kibana.startswith(word)


def test_no_two_golden_titles_are_the_same() -> None:
    texts = [title_for_incident(make(), word).text for _, make, word, _, _ in GOLDEN]
    assert len(set(texts)) == len(texts)
