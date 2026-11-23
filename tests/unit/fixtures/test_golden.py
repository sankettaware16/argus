"""A golden document: one synthetic alert through the sanitizer, compared byte for byte.

``golden/golden_alert.json`` puts an identifier in every context the sanitizer knows (policy
fields, field-shaped keys, KQL and ES|QL, filters, aggregations, URLs, credentials, e-mail, DNs,
reverse DNS, address spellings, home directories, literals). ``golden_alert.sanitized.json`` is
what 2.3.0 makes of it under a fixed synthetic key. A change to the output must be deliberate:
bump SANITIZER_VERSION, regenerate the committed fixtures and this file
(``uv run python tests/unit/fixtures/test_golden.py``), and review the diff.

The synthetic words were checked against the local denylist (``sanitize_fixtures.py verify``):
none is a real campus identifier.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.fixtures import FixturePolicy, LeakScanner, Sanitizer

DATA = Path(__file__).parent / "golden"
KEY = b"k" * 32
POLICY = FixturePolicy(
    site_prefixes=("192.0.2.0/24",),
    own_domains=("campus.ac.in", "campus-alt.org"),
    keep_domains=("vendor-cdn.example",),
    literals={"Campus University": "Example University"},
    fields={
        "host": ("host.name", "host.hostname", "related.hosts", "*.hostname"),
        "user": ("user.name", "user.id", "related.user", "*.user.name"),
        "email": ("user.email",),
        "place": ("source.site.department",),
        "domain": ("url.domain", "destination.domain", "dns.question.name"),
        "id": ("_id", "kibana.alert.uuid", "kibana.alert.ancestors.id"),
    },
)
# Every original identifier planted in the alert, in the spelling it has there.
PLANTED = (
    "SyntheticAlertId0001",
    "Zz9AncestorIdAbCdEfG",
    "10.1.2.3",
    "8.8.4.4",
    "10.9.9.9",
    "192.0.2.79",
    "fd12:3456::7",
    "2001:db8::5",
    "lab-pc-07",
    "LAB-PC-07",
    "lab-pc-08",
    "lab-pc-09",
    "lab-pc-10",
    "lab-pc-11",
    "lab-pc-12",
    "lab-pc-13",
    "backup-srv-9",
    "kiosk7",
    "vuln-scan-01",
    "WS-ROOM-12",
    "svc-backup-07",
    "ravi-k9",
    "dana-x",
    "carol",
    "CAMPUSNB",
    "alice",
    "hunter2",
    "bob.k",
    "ivy.s",
    "Ivy Synthetic",
    "syn-judy",
    "Dept-Q7",
    "Campus University",
    "campus.ac.in",
    "campus-alt.org",
    "YWxpY2U6c2VjcmV0LXgx",
    "abc123",
)


def sanitized() -> dict[str, Any]:
    document = json.loads((DATA / "golden_alert.json").read_text(encoding="utf-8"))
    sanitizer = Sanitizer(POLICY, KEY)
    sanitizer.harvest([document])
    return sanitizer.sanitize(document)


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def test_the_golden_document_sanitizes_to_its_golden_output() -> None:
    assert render(sanitized()) == (DATA / "golden_alert.sanitized.json").read_text(encoding="utf-8")


def test_no_planted_identifier_survives_in_the_golden_output() -> None:
    scanner = LeakScanner(PLANTED, networks=POLICY.site_prefixes)
    output = (DATA / "golden_alert.sanitized.json").read_text(encoding="utf-8")
    assert scanner.scan_document(output, "golden_alert.sanitized.json") == []


@pytest.mark.parametrize("identifier", PLANTED)
def test_the_scanner_finds_each_planted_identifier_in_the_original(identifier: str) -> None:
    """So that the clean scan of the output above means something."""
    raw = (DATA / "golden_alert.json").read_text(encoding="utf-8")
    assert LeakScanner([identifier]).scan_document(raw, "golden_alert.json")


if __name__ == "__main__":
    (DATA / "golden_alert.sanitized.json").write_text(render(sanitized()), encoding="utf-8")
