"""AR2c (D-168): what a domain's VirusTotal answer adds to the sentence ARGUS says about it: whether
it is among the popular sites and when it was registered. An answer without those fields (an older
one, an address) has the sentence it always had."""

from __future__ import annotations

from typing import Any

from argus.outside import facts


def entry(kind: str, answer: dict[str, Any]) -> dict[str, Any]:
    return facts.fact("virustotal", kind, "fast-dns-host.example", "found", answer, 3)


def test_a_domain_sentence_says_whether_it_is_popular_and_when_it_was_registered() -> None:
    base = {"malicious": 5, "engines": 91}
    rare = entry("domain", {**base, "ranked": False, "created": "2026-09-21"})
    assert facts.describe(rare) == (
        "VirusTotal: 5 of 91 engines flag this domain; not among the popular sites;"
        " registered 2026-09-21"
    )
    popular = entry(
        "domain",
        {"malicious": 0, "engines": 90, "ranked": True, "best_rank": 412, "created": "1998-09-15"},
    )
    assert facts.describe(popular) == (
        "VirusTotal: no engine of 90 flags this domain; among the popular sites (rank 412);"
        " registered 1998-09-15"
    )
    assert facts.describe(entry("domain", {**base, "ranked": True})) == (
        "VirusTotal: 5 of 91 engines flag this domain; among the popular sites"
    )


def test_an_answer_without_the_family_fields_has_the_old_sentence() -> None:
    old = entry("domain", {"malicious": 5, "engines": 91})
    assert facts.describe(old) == "VirusTotal: 5 of 91 engines flag this domain"
    ip = entry("ip", {"malicious": 5, "engines": 91, "ranked": False})
    assert facts.describe(ip) == "VirusTotal: 5 of 91 engines flag this IP"  # only a domain has one
    junk = entry("domain", {"malicious": 5, "engines": 91, "ranked": "yes", "created": "last year"})
    assert facts.describe(junk) == "VirusTotal: 5 of 91 engines flag this domain"
