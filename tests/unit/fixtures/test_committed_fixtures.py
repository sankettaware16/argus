"""Checks on the committed sanitized fixtures that need no local raw data (fresh clones too)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path

import pytest

from argus.fixtures import walk_strings
from argus.fixtures.ipmap import CLASS_REGIONS
from tests.conftest import REPO_ROOT

FIXTURES = REPO_ROOT / "tests" / "fixtures" / "alerts"
MANIFEST = json.loads((FIXTURES / "MANIFEST.json").read_text())
FILES = sorted(MANIFEST["files"])
_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?!\w|\.\d)")
# The suite's site's own identifiers (its organisation, domain, SIEM and public range) never
# appear in a fixture: fixtures are sanitized to univ.example and 198.18.0.0/15. A real site's
# pack checks its own identifiers the same way.
FORBIDDEN = re.compile(r"(?i)example\.edu|10\.20\.60\.11|the SIEM|131\.21\.12[4-7]\.")


def test_manifest_lists_exactly_the_fixture_files() -> None:
    on_disk = sorted(p.name for p in FIXTURES.glob("*.json") if p.name != "MANIFEST.json")
    assert on_disk == FILES


@pytest.mark.parametrize("name", FILES)
def test_hash_matches_manifest(name: str) -> None:
    data = (FIXTURES / name).read_bytes()
    assert hashlib.sha256(data).hexdigest() == MANIFEST["files"][name]["sha256"]


@pytest.mark.parametrize("name", FILES)
def test_wire_format_and_identity(name: str) -> None:
    doc = json.loads((FIXTURES / name).read_text())
    assert set(doc) == {"_index", "_id", "_source"}
    assert doc["_source"]["kibana.alert.uuid"] == doc["_id"]
    assert doc["_source"]["kibana.alert.rule.type"] == MANIFEST["files"][name]["rule_type"]


@pytest.mark.parametrize("name", FILES)
def test_no_known_campus_identifiers(name: str) -> None:
    text = (FIXTURES / name).read_text()
    assert FORBIDDEN.search(text) is None
    assert FORBIDDEN.search(name) is None


@pytest.mark.parametrize("name", FILES)
def test_every_ipv4_is_in_an_allowed_space(name: str) -> None:
    doc = json.loads((FIXTURES / name).read_text())
    site = ipaddress.ip_network("198.18.0.0/15")
    for _path, value in walk_strings(doc):
        for match in _IPV4.finditer(value):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            # internal stays private, campus public sits in the site space, external stays public;
            # version strings like "154.0.0.0" are allowed through.
            in_class = any(ip.version == n.version and ip in n for n in CLASS_REGIONS)
            ok = (
                in_class
                or ip.is_private
                or ip in site
                or ip.is_global
                or str(ip).endswith(".0.0.0")
            )
            assert ok, f"{name}: unexpected address class"


def test_manifest_records_provenance_without_secrets() -> None:
    assert re.fullmatch(r"[0-9a-f]{16}", MANIFEST["key_fingerprint"])
    assert re.fullmatch(r"[0-9a-f]{64}", MANIFEST["policy_sha256"])
    assert MANIFEST["sanitizer_version"]
    assert Path(REPO_ROOT / "config" / "fixtures.yaml").is_file()
