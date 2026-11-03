"""P4-D1 part 2, step 3 (D-284): the sentences that say "campus" and name the team follow the
site. On ACME's section they read as they always did (the existing suites check that); here the
tokens, the tables written with them and the neutral and other-noun readings."""

from __future__ import annotations

import pytest

from argus import site
from argus.cases import naming
from argus.cases.naming import BEACON, Device, Facts, title
from argus.incident import evidence
from argus.site import SiteSettings, Words, say
from argus.web import access, casepages

pytestmark = pytest.mark.unit
NEUTRAL = SiteSettings()
OFFICE = SiteSettings(own_network_noun="office network")


def test_the_tokens_on_acmes_section() -> None:
    assert say("{own:host} {a_own:host} {A_own:host} {the} {The} {noun} {Noun}") == (
        "campus host a campus host A campus host the campus The campus campus Campus"
    )
    assert say("{team} / {org} / {logs} / {source:proxy} / {source:web}") == (
        "ACME / Example University / acme-logs-* / squid / nginx"
    )
    assert say("no token, {braces} and {own} stay as they are") == (
        "no token, {braces} and {own} stay as they are"
    )


def test_the_tokens_on_the_neutral_default() -> None:
    with site.using(NEUTRAL):
        assert say("{own:hosts} reached it") == "hosts of your network reached it"
        assert say("{A_own:host}'s proxy traffic") == "A host of your network's proxy traffic"
        assert say("outside {the}") == "outside your network"
        assert say("{Noun} device") == "Your network device"
        assert say("{team} at {org}") == "SOC at your organisation"
        assert say("({logs})") == "(the log indices)"
        assert say("({source:proxy})") == "(proxy)"  # no family: the role's own name


def test_the_tokens_with_a_noun_that_is_an_adjective() -> None:
    with site.using(OFFICE):
        assert say("{a_own:address} {own:servers} {the}") == (
            "an office network address office network servers the office network"
        )


def test_a_table_of_words_reads_through_the_site() -> None:
    table = Words({"a": "Which {own:hosts} reached {the}", "b": "plain"})
    assert table["a"] == "Which campus hosts reached the campus"
    assert table.get("b") == "plain"
    assert table.get("z", "none") == "none"
    assert list(table) == ["a", "b"]
    assert dict(table.items())["a"] == "Which campus hosts reached the campus"
    with site.using(NEUTRAL):
        assert table["a"] == "Which hosts of your network reached your network"


def test_acmes_evidence_and_check_words_are_what_they_were() -> None:
    assert evidence.TITLES["proxy.host"] == "A campus host's proxy traffic"
    assert evidence.TITLES["proxy.destination"] == "Which campus hosts reached a destination"
    assert evidence.SOURCES["proxy.pair"] == "the campus proxy logs (squid)"
    assert evidence.SOURCES["dns.host_domains"] == "the campus DNS logs"
    assert evidence.SOURCES["web.followups"] == "the web server logs (nginx)"
    assert casepages.CHECK_WORDS["proxy.contact"] == (
        "Which campus hosts reached an outside address that day"
    )
    assert casepages.TAKES_WORDS["internal"] == "a campus address"
    assert casepages.TAKES_WORDS["public"] == "an address outside the campus"
    assert casepages.REASON_WORDS["benign_expected"][1] == (
        "It happened, and it is activity {the} expects."
    )
    assert say(casepages.REASON_WORDS["benign_policy"][1]) == (
        "It happened, and the campus policy allows it."
    )


def test_the_neutral_evidence_words_name_no_campus_or_squid() -> None:
    with site.using(NEUTRAL):
        said = [
            *(evidence.TITLES[k] for k in evidence.TITLES),
            *(evidence.SOURCES[k] for k in evidence.SOURCES),
            *(casepages.CHECK_WORDS[k] for k in casepages.CHECK_WORDS),
            *(casepages.TAKES_WORDS[k] for k in casepages.TAKES_WORDS),
        ]
        assert not [t for t in said if "campus" in t.lower() or "squid" in t or "nginx" in t]
        assert evidence.SOURCES["proxy.host"] == "the proxy logs of your network (proxy)"


def test_the_access_page_names_the_sites_team_and_logs() -> None:
    from argus.web.capabilities import Capability

    assert access.NEEDS_IN_ELK[Capability.VIEW] == (
        "your ELK account needs access to the ACME space in Kibana and to read the alerts"
    )
    assert access.NEEDS_IN_ELK[Capability.SEE_LOGS] == (
        "your ELK account needs to read the raw logs (acme-logs-*)"
    )
    with site.using(NEUTRAL):
        assert "SOC space" in access.NEEDS_IN_ELK[Capability.VIEW]


# --------------------------------------------------------------------------- case titles


def devices(n: int, place: str | None = None) -> tuple[Device, ...]:
    return tuple(Device(f"10.198.36.{i + 1}", "ip", None, place) for i in range(n))


HOSTEL_CASE = Facts(
    flags=frozenset({BEACON}), devices=devices(4, "Hostel 12"), servers=("176.65.139.158",)
)


def test_acmes_case_titles_are_what_they_were() -> None:
    f = Facts(
        flags=frozenset({BEACON}), devices=devices(4, "Hostel 12"), servers=("176.65.139.158",)
    )
    assert title(f) == "Beaconing to 176.65.139.158 from 4 campus devices in Hostel 12"
    f = Facts(flags=frozenset({BEACON}), devices=devices(1))
    assert "campus device" not in title(f)  # a named device is named


def test_a_title_follows_the_sites_noun() -> None:
    f = Facts(
        flags=frozenset({BEACON}), devices=devices(4, "Hostel 12"), servers=("176.65.139.158",)
    )
    with site.using(NEUTRAL):
        assert title(f) == "Beaconing to 176.65.139.158 from 4 devices of your network in Hostel 12"
        assert "campus" not in naming._devices(f, where=False)
    with site.using(OFFICE):
        assert title(f) == "Beaconing to 176.65.139.158 from 4 office network devices in Hostel 12"
        assert naming._devices(Facts(devices=devices(2)), where=False) == "2 office network devices"


def test_every_title_a_site_can_make_stays_in_the_allowed_characters() -> None:
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:()/&+-—→")
    f = Facts(
        flags=frozenset({BEACON}), devices=devices(4, "Hostel 12"), servers=("176.65.139.158",)
    )
    for noun in ("campus", "your network", "office network", "the plant", "our site"):
        with site.using(SiteSettings(own_network_noun=noun)):
            assert set(title(f)) <= allowed, noun
