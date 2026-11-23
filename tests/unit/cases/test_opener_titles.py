"""D-230: the title the opener plans from one investigation (the stored title is made again from the
database's facts, ``tests/integration/cases/test_opener.py``): its campus devices, outside
addresses and accounts, the threat-listed values, and the signals that made it a candidate."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from argus.cases import opener
from argus.cases.model import Indicator
from argus.cases.opener import Candidate

NOW = datetime(2026, 10, 30, 6, 0, tzinfo=UTC)
BEACON = "a regular beacon"
LISTED = "a campus host in contact with a threat-listed address"
SUCCESS = "successful answers after the attack"


def cand(
    *actors: Indicator,
    ours: bool = True,
    keys: frozenset[tuple[str, str]] = frozenset(),
    listed: tuple[str, ...] = (),
    rule: str | None = "Rule",
) -> Candidate:
    return Candidate(
        "review", 1, uuid.UUID(int=1), True, NOW, rule, "medium", actors, ours, frozenset(),
        listed, own_keys=keys,
    )  # fmt: skip


def ip(value: str) -> Indicator:
    return Indicator("ip", value, "actor")


HOST = "10.0.4.7"
SERVER = "198.51.100.20"


def test_a_campus_host_beaconing_to_a_listed_server() -> None:
    c = cand(ip(HOST), listed=(SERVER,))
    assert opener.title(c, [BEACON, LISTED]) == (
        f"Suspected beaconing from {HOST} to {SERVER} (on a threat list)"
    )


def test_a_beacon_with_no_listed_server_names_the_host_only() -> None:
    assert opener.title(cand(ip(HOST)), [BEACON]) == f"Suspected beaconing from {HOST}"


def test_contact_with_a_listed_server_without_a_beacon() -> None:
    c = cand(ip(HOST), listed=(SERVER,))
    assert opener.title(c, [LISTED]) == (
        f"Suspected contact with {SERVER} (on a threat list) from {HOST}"
    )


def test_the_campus_keys_tell_a_device_from_an_outside_address() -> None:
    c = cand(ip(HOST), ip("203.0.113.9"), keys=frozenset({("ip", HOST)}), listed=(SERVER,))
    assert opener.title(c, [BEACON]) == (
        f"Suspected beaconing from {HOST} to {SERVER} (on a threat list)"
    )


def test_an_outside_address_whose_attack_got_answers() -> None:
    c = cand(ip("203.0.113.44"), ours=False)
    assert opener.title(c, [SUCCESS]) == (
        "Suspected web scan by 203.0.113.44 — got HTTP 200, not verified"
    )


def test_the_rule_names_what_has_no_shape_quoted_and_attributed() -> None:
    c = cand(Indicator("user", "someone@example.org", "actor"), ours=False, rule="Odd login")
    assert opener.title(c, ["severity high"]) == (
        "Suspected: alerts of rule 'Odd login' for a user account"
    )
    assert opener.title(cand(rule=None, ours=False), []) == "Alert"


def test_a_value_that_is_not_an_address_never_reaches_the_title() -> None:
    c = cand(ip("10.0.0.1"), listed=("<script>alert(1)</script>",))
    assert opener.title(c, [BEACON]) == "Suspected beaconing from 10.0.0.1 to a flagged server"


def test_the_attempt_reason_hyphenates_the_sites_word() -> None:
    """ "no impact or campus-host signal" on ACME's site (a modifier, as it always read); a noun
    that reads "of your network" stays as it is (D-289)."""
    from argus import site
    from argus.cases import opener

    assert opener._no_impact() == "no impact or campus-host signal"
    with site.using(site.SiteSettings()):  # "your network"
        assert opener._no_impact() == "no impact or host of your network signal"
    with site.using(site.SiteSettings(own_network_noun="office network")):
        assert opener._no_impact() == "no impact or office-network-host signal"
