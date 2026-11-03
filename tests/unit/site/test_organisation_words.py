"""P4-D1 part 2 review F6 (D-285): the sentences ARGUS writes, and the text it sends to a model,
say the site's words ("campus", "university", the team's name) and not ACME's unless the site is
ACME's. On ACME's section every text is byte-for-byte what it was (the digests below were made by
the code before the change); on the neutral default none names ACME, a campus, a university or a
hostel; and no new sentence can be written with those words without a person allowing it here."""

from __future__ import annotations

import ast
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path

import pytest

from argus import site
from argus.agent import catalogue
from argus.evaluation import tasks
from argus.incident import prose
from argus.investigation import catalogue as checks_catalogue
from argus.llm import privacy as privacy_module
from argus.llm import prompts
from argus.notices import render as notices
from argus.site import Organisation, SiteSettings, article, say
from argus.tuning import advise
from tests.conftest import REPO_ROOT

pytestmark = pytest.mark.unit

NEUTRAL = SiteSettings()
ORGANISATION_WORDS = re.compile(r"campus|universit|hostel|acme|iit ?b|bombay", re.I)

# sha256 of each text as the code before P4-D1's review fixes made it, on ACME's section
ACME_DIGESTS = {
    "advise.INSTRUCTIONS": "6dd74975655a55668a258bf0197c2d6e3e716eef4aa73a470710c6d1dabc7fe1",
    "catalogue.lines": "ff3dfbf1d69275575b318dae63ba85a84f952526be6712dc8629786962855263",
    "notices.HEADLINE.after_closure":
        "f4e9ccf1999655c286578e824078a43aae4cc9598b31a42dba873dea16a6ab6f",
    "notices.HEADLINE.case_active":
        "a4cf4e8fef7aa4013ad0e11844e67cd97e5251183603cd2264a226df3c5d097c",
    "notices.HEADLINE.closure_waiting":
        "ff79f7ff6b6342c99450f3b6485dbf95affac6f455d0f0865af4a2f9f8c78435",
    "notices.HEADLINE.ioc_hit": "c7b7f54a0667aa8bb6cf664a262d94da8b5f5ef392f19c20dad7ad5261f641ec",
    "notices.HEADLINE.outage": "b7955c1ce56f8c0412baca43573364018be37c69b6f21fd75c8c3f0bd60e1ed5",
    "notices.SUBJECT.after_closure":
        "0d3fb2a7d8c43ecad8cd2e265c0e123c9607bd7556f4edb9e1a524d637b4dd8c",
    "notices.SUBJECT.case_active":
        "7bbe8cbc09d28fa12b386d6c475e035afb0006de59fd2dfc223d2288a4f491db",
    "notices.SUBJECT.closure_waiting":
        "10b7134362ca2435bf588fd854388f9107768c8bd26b778b506a746e2d4eef7b",
    "notices.SUBJECT.ioc_hit": "718dc9e04191f9ad65c5226fe88ee4465c0e854c368b05a9ec5f0b2f40c93882",
    "notices.SUBJECT.outage": "529393290679d2868d77599ab71cdf22f31931e1e47271d0122104e885d58db4",
    "prompts.ASSESS_V1_TEXT": "1bded78bc1252a1c309d4eb7d7e2fed39b51a571b65649b541d52d86502166cb",
    "prose.INSTRUCTIONS": "9921aa09bf8211616e4549f312f531e4691da3ad754b73cdada6ba5104866f94",
    "tasks.EXTRACT_TEXT": "22bc367a17c1a6a53abef3179b2c67d1679f1edadda545b79129265434c9991f",
    "tasks.SUMMARY_TEXT": "230293612f669c73c2defe66e2e17b2ec5cd59f57099bd2a89947d5690b0e480",
    "tasks.TRIAGE_TEXT": "42f9f84d0bf187e84047f5edb098383fe530514bc925eb14d2773e00d87df4c0",
}  # fmt: skip


def texts() -> dict[str, str]:
    """Every text the review named that a model, a notice or a tool list is made of, as the active
    site reads it."""
    out = {
        "prompts.ASSESS_V1_TEXT": prompts.PROMPTS[prompts.ASSESS_V1],
        "tasks.EXTRACT_TEXT": site.say(tasks.EXTRACT_TEXT),
        "tasks.TRIAGE_TEXT": site.say(tasks.TRIAGE_TEXT),
        "tasks.SUMMARY_TEXT": site.say(tasks.SUMMARY_TEXT),
        "prose.INSTRUCTIONS": site.say(prose.INSTRUCTIONS),
        "advise.INSTRUCTIONS": site.say(advise.INSTRUCTIONS),
        "catalogue.lines": catalogue.lines(set(catalogue.TOOLS)),
    }
    for kind in notices.SUBJECT:
        out[f"notices.SUBJECT.{kind}"] = notices.SUBJECT[kind]
    for kind in notices.HEADLINE:
        out[f"notices.HEADLINE.{kind}"] = notices.HEADLINE[kind]
    return out


def test_every_text_is_what_it_was_on_acmes_section() -> None:
    got = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in texts().items()}
    assert got == ACME_DIGESTS


def test_the_prompt_a_model_reads_still_says_what_it_said_to_acme() -> None:
    assert "for a university network" in prompts.PROMPTS[prompts.ASSESS_V1]
    assert "allowed by campus policy" in prompts.PROMPTS[prompts.ASSESS_V1]
    assert "analyst at a university" in site.say(tasks.TRIAGE_TEXT)
    assert "You help a university's research and teaching assistants" in site.say(
        prose.INSTRUCTIONS
    )
    assert "a campus host's proxy traffic" in catalogue.lines({"proxy.host"})


def test_the_neutral_default_names_no_organisation_in_what_a_model_reads() -> None:
    with site.using(NEUTRAL):
        for name, text in texts().items():
            assert not ORGANISATION_WORDS.search(text), (name, ORGANISATION_WORDS.search(text))
        assert "for an organisation network" in prompts.PROMPTS[prompts.ASSESS_V1]
        assert "analyst at an organisation" in site.say(tasks.TRIAGE_TEXT)
        assert "You help an organisation's analysts read" in site.say(prose.INSTRUCTIONS)
        assert "- notice" not in notices.SUBJECT["ioc_hit"]
        assert notices.SUBJECT["ioc_hit"] == "A host of your network reached a known-bad address"


def test_the_site_can_say_its_own_kind_units_and_readers() -> None:
    plant = SiteSettings(
        own_network_noun="the plant",
        organisation=Organisation(
            name="Acme", short_name="Acme SOC", kind="manufacturer", units="line, shop or office",
            reviewers="shift engineers",
        ),
    )  # fmt: skip
    with site.using(plant):
        assert say("{a_kind}|{Kind}|{kind}|{units}|{units2}|{reviewers}") == (
            "a manufacturer|Manufacturer|manufacturer|line, shop or office|line or shop"
            "|shift engineers"
        )
        assert say("{own:hosts} on {where}, {The}") == "plant hosts on the plant, The plant"
        assert "for a manufacturer network" in prompts.PROMPTS[prompts.ASSESS_V1]
        assert "You help a manufacturer's shift engineers read" in site.say(prose.INSTRUCTIONS)
        assert notices.SUBJECT["ioc_hit"] == "A plant host reached a known-bad address"


def test_acmes_organisation_words() -> None:
    acme = site.active().organisation
    assert (acme.kind, acme.units, acme.reviewers) == (
        "university", "department, hostel or lab", "research and teaching assistants",
    )  # fmt: skip
    assert say("{units2}") == "department or hostel"
    assert say("{a_kind} {Kind}") == "a university University"


@pytest.mark.parametrize("bad", ["", "Uni", "uni\nversity", "<b>", "a" * 41, "x{y}", "uni."])
def test_the_kind_is_a_plain_lower_case_word_or_two(bad: str) -> None:
    with pytest.raises(ValueError, match="kind"):
        Organisation(kind=bad)


def test_the_articles_follow_the_sound() -> None:
    for word, expected in (
        ("university", "a"), ("unit", "a"), ("European", "a"), ("organisation", "an"),
        ("hour", "an"), ("office", "an"), ("campus", "a"), ("uncle", "an"), ("uninstalled", "an"),
        ("user", "a"), ("umbrella", "an"), ("one-way", "a"), ("honest", "an"),
    ):  # fmt: skip
        assert article(word) == expected, word
    assert site.a_noun() == "a campus"
    with site.using(NEUTRAL):
        assert site.a_noun() == "your network"
    with site.using(SiteSettings(own_network_noun="university")):
        assert site.a_noun() == "a university"
        assert site.a_own("device") == "a university device"
    with site.using(SiteSettings(own_network_noun="office network")):
        assert site.a_own("device") == "an office network device"


def test_a_own_or_reads_as_english_for_both_kinds_of_noun() -> None:
    assert site.a_own_or("address", "private", "special-use") == (
        "a campus, private or special-use address"
    )
    assert site.a_own_or("one", "private") == "a campus or private one"
    with site.using(NEUTRAL):
        assert site.a_own_or("address", "private", "special-use") == (
            "an address in your network, or a private or special-use one"
        )
        assert site.a_own_or("one", "private") == "one in your network, or a private one"
    with site.using(SiteSettings(own_network_noun="office network")):
        assert site.a_own_or("address", "private") == "an office network or private address"


# --------------------------------------------------------------------------- the scan

SRC = REPO_ROOT / "src" / "argus"
# Where a string literal may still hold one of the words, and why: the key of a stored decision or
# flag, a trust class, an API field or the name of a configuration key.
ALLOWED: Mapping[str, tuple[str, ...]] = {
    "agent/loader.py": ("campus",),  # the words the agents' pins were made with (D-289)
    "agent/reading.py": ("a destination few campus hosts reach",),  # a stored floor part, keyed
    "assess/engine.py": ("a destination few campus hosts reach",),
    "assess/raised.py": ("many campus devices reach one rare domain",),  # a stored flag
    "assets/classify.py": ("campus",),  # IpClass.CAMPUS
    "cases/blocklist.py": ("first_seen_on_campus", "campus_devices"),  # API field names
    "cases/cli.py": ("campus-managed",),  # operator CLI labels
    "cases/titling.py": (":campus", "campus"),  # a query parameter, a class name
    "context/batch1.py": ("campus",),  # classes
    "context/proxy.py": ("campus",),
    "investigation/checks.py": ("campus",),
    "evaluation/ladder.py": ("campus",),  # the trust class of a model's machine
    "doctor.py": ("campus_domains",),  # a configuration key
    "llm/privacy.py": ("campus_domains",),
    "llm/providers.py": ("campus",),  # Trust.CAMPUS and its messages
    "llm/cli.py": ("campus",),
    "llm/doctor.py": ("campus",),
    "llm/gateway.py": ("on campus",),
    "llm/arms.py": ("campus", "hostel"),  # the comparison arms' stand-in names
    "fixtures/policy.py": ("campus",),  # the sanitizer's own policy words
}


def sentences_with_organisation_words() -> list[tuple[str, str]]:
    found = []
    for path in sorted(SRC.rglob("*.py")):
        if "migrations" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = {
            id(node.value)
            for node in ast.walk(tree)
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
        }  # docstrings and attribute docstrings
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and id(node) not in docs
                and ORGANISATION_WORDS.search(node.value)
            ):
                found.append((str(path.relative_to(SRC)), node.value))
    return found


def test_no_sentence_says_the_organisation_words_unless_it_is_allowed_here() -> None:
    unexpected = [
        (name, text[:80])
        for name, text in sentences_with_organisation_words()
        if not any(key in text for key in ALLOWED.get(name, ("\0",)))
    ]
    assert unexpected == []


def test_every_allowance_is_still_needed() -> None:
    used = {name for name, _ in sentences_with_organisation_words()}
    assert set(ALLOWED) <= used, sorted(set(ALLOWED) - used)


def test_the_text_of_the_privacy_legends_is_the_sites() -> None:
    assert privacy_module._LEGENDS["SITE"] == "a campus site"
    assert privacy_module._LEGENDS["HOST"] == "a campus host name"
    with site.using(NEUTRAL):
        assert privacy_module._LEGENDS["SITE"] == "a site of your network"
        assert privacy_module._LEGENDS["HOST"] == "a host name of your network"
        assert not any(ORGANISATION_WORDS.search(v) for v in privacy_module._LEGENDS.values())


def test_the_reason_a_check_is_asked_follows_the_site() -> None:
    spec = checks_catalogue.CHECKS["proxy.destination"]
    assert spec.said == "which campus hosts reached the destination"
    with site.using(NEUTRAL):
        assert spec.said == "which hosts of your network reached the destination"
    assert Path(SRC / "site.py").exists()
