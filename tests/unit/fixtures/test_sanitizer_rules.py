"""Sanitizer rules found by running R2 on the real corpus after the adversarial review (synthetic
data here). Each test pins one rule the real data showed was needed."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import pytest
import yaml

from argus.fixtures import FixturePolicy, Sanitizer
from tests.conftest import REPO_ROOT

KEY = b"k" * 32
POLICY = FixturePolicy(
    campus_domains=("campus.ac.in",),
    keep_domains=("mitre.org",),
    fields={
        "host": ("host.name",),
        "user": ("user.name",),
        "place": ("source.site.department",),
        "domain": ("destination.domain",),
    },
)


def _sanitizer(*docs: object) -> Sanitizer:
    s = Sanitizer(POLICY, KEY)
    s.harvest(list(docs))
    return s


def test_a_field_name_key_is_never_renamed_by_the_dictionary() -> None:
    """A department called META must not rename the structural key ``meta`` (it did, in a rule's
    ``parameters.meta``); a host name used as a key, which no field name looks like, still is."""
    s = _sanitizer({"source": {"site": {"department": "META"}}}, {"host": {"name": "LAB-PC-07"}})
    rule = {"parameters": {"meta": {"created_from": "x"}}, "labels": {"LAB-PC-07": "quarantined"}}
    out = s.sanitize(rule)
    assert set(out["parameters"]) == {"meta"}
    assert "LAB-PC-07" not in out["labels"]
    assert set(out["labels"]) == {s.sanitize({"host": {"name": "LAB-PC-07"}})["host"]["name"]}


@pytest.mark.parametrize("key", ["10.1.2.3", "user@campus.ac.in", "www.campus.ac.in"])
def test_addresses_and_domains_in_keys_are_still_mapped(key: str) -> None:
    s = _sanitizer({key: 1})
    (out,) = s.sanitize({key: 1})
    assert out != key


def test_home_directories_count_only_in_filesystem_fields() -> None:
    """``/home/login`` in a web path is a scanner probe, not an account: harvesting it turned the
    word "login" into a name (and flagged every ``wp-login``). In a file path it is an account."""
    web = {"url": {"path": "/home/login"}, "attempted_paths": ["/home/.env", "/~admin1/"]}
    s = _sanitizer(web)
    assert {"login", ".env", "admin1"}.isdisjoint(s.harvested)
    s = _sanitizer({"file": {"path": "/home/syn-kate/build/a.o"}}, {"process": {"cwd": "x"}})
    assert "syn-kate" in s.harvested
    assert "syn-kate" not in s.map_text("owner syn-kate")
    s = _sanitizer({"file": {"path": "/home/.config/x"}})
    assert ".config" not in s.harvested  # a dot-name is a file, not an account


@pytest.mark.parametrize(
    "query",
    ["destination.domain:*", 'host.name: "lab-*"', "user.name:?dmin", "destination.domain : *.ru"],
)
def test_query_wildcards_are_kept(query: str) -> None:
    s = _sanitizer({"kibana.alert.rule.parameters": {"query": query}})
    assert s.map_text(query) == query
    assert query not in s.harvested


def test_a_kept_vendor_url_that_only_changes_case_is_not_an_identifier() -> None:
    s = _sanitizer({"message": "see https://ATTACK.mitre.org/techniques/T1105/"})
    assert not any("mitre" in h.lower() for h in s.harvested)
    assert s.map_text("https://attack.mitre.org/x") == "https://attack.mitre.org/x"


def test_repeated_strings_are_harvested_once_with_the_same_result() -> None:
    docs = [{"host": {"name": "lab-pc-07"}, "message": "lab-pc-07 to 10.1.2.3"}] * 50
    one, many = _sanitizer(docs[0]), _sanitizer(*docs)
    assert one.harvested == many.harvested
    assert one.dictionary == many.dictionary


def _script() -> Any:  # a script module: its globals are set by the tests
    spec = importlib.util.spec_from_file_location(
        "argus_sanitize_fixtures_rules", REPO_ROOT / "scripts" / "sanitize_fixtures.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_two_letter_asset_names_are_not_denylisted(tmp_path: Path) -> None:
    """A 2-letter asset name (a public department code) matches ordinary tokens such as
    ``AI_Report_Writer``; it is read but neither denylisted nor replaced."""
    script = _script()
    script.ASSETS_PATH = tmp_path / "assets.yaml"
    script.ASSETS_PATH.write_text(
        yaml.safe_dump({"networks": [{"name": "AI", "range": "10.9.0.0/16"}, {"name": "Lab-7"}]})
    )
    assert script.asset_names() == ["AI", "Lab-7"]
    assert script.identifying_asset_names() == ["Lab-7"]


def test_a_harvested_value_that_is_a_literal_keeps_the_literal_case_style() -> None:
    policy = POLICY.model_copy(
        update={"literals": {"CU": "EU", "cu": "eu"}, "fields": {"org": ("observer.org",)}}
    )
    s = Sanitizer(policy, KEY)
    s.harvest([{"observer": {"org": "cu"}}])
    assert s.map_text("CU logs and cu logs") == "EU logs and eu logs"
