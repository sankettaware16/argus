"""T10: the engine is generic. No rule name or id appears in its code or its settings, and its
settings are checked (unknown keys and incomplete tables are errors)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

from argus.config.errors import ConfigError
from argus.db import models
from argus.risk import config as risk_config
from argus.risk import incident_config, observe, roles, score

pytestmark = pytest.mark.unit
REPO = Path(__file__).resolve().parents[3]
ENGINE = [*sorted((REPO / "src" / "argus" / "risk").glob("*.py")), risk_config.RISK_PATH,
          incident_config.INCIDENTS_PATH]  # fmt: skip
FIXTURES = REPO / "tests" / "fixtures" / "alerts"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def fixture_rules() -> tuple[set[str], set[str]]:
    names, ids = set(), set()
    for path in FIXTURES.glob("*.json"):
        if path.name == "MANIFEST.json":
            continue
        hits = json.loads(path.read_text())
        for hit in hits if isinstance(hits, list) else [hits]:
            source = hit.get("_source", {})
            names.add(source.get("kibana.alert.rule.name", ""))
            ids.update(str(source.get(k, "")) for k in
                       ("kibana.alert.rule.rule_id", "kibana.alert.rule.uuid"))  # fmt: skip
    return {n for n in names if n}, {i for i in ids if i}


def test_no_rule_name_or_id_in_the_engine() -> None:
    names, ids = fixture_rules()
    assert names
    assert ids
    for path in ENGINE:
        body = path.read_text().lower()
        assert not UUID.search(body), path
        for name in names:
            assert name.lower() not in body, (path, name)
        for rule_id in ids:
            assert rule_id.lower() not in body, (path, rule_id)
        # words a rule name would bring, never a generic signal
        for word in ("cert-", "naxsi", "path enumeration", "squid", "nginx", "dns:"):
            assert word not in body, (path, word)


def test_the_repo_settings_load_and_name_only_generic_things() -> None:
    config = risk_config.load()
    assert {e.kind for e in config.evidence} >= {"outside", "ti", "operator", "beacon"}
    assert config.lanes.decisive.base == config.severity_base["critical"]


def raw() -> dict[str, object]:
    data = yaml.safe_load(risk_config.RISK_PATH.read_text())
    assert isinstance(data, dict)
    return data


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(unknown=1),
        lambda d: d["lanes"].update(fast={"score": 1}),
        lambda d: d["severity_base"].pop("high"),
        lambda d: d["windows"].pop("14d"),
        lambda d: d["evidence"].append(dict(d["evidence"][0])),
        lambda d: d["evidence"].append({"kind": "persistence", "signals": {"x": "true"},
                                        "base": 1}),
        lambda d: d["evidence"].append({"kind": "empty", "base": 1}),
        lambda d: d["evidence"].append({"kind": "bad", "signals": {"x": {"below": 1,
                                                                         "at_most": 2}},
                                        "base": 1}),
        lambda d: d["evidence"].append({"kind": "feed", "signals": {"x": "true"},
                                        "feeds": {"y": "mirror"}, "base": 1}),
        lambda d: d.update(gray_band=1.5),
        lambda d: d["risk_scale"].update(min=3),
    ],
)  # fmt: skip
def test_invalid_settings_are_errors(change: object) -> None:
    data = raw()
    change(data)  # type: ignore[operator]
    with pytest.raises(ConfigError):
        risk_config.parse(data)


def test_a_missing_settings_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="missing"):
        risk_config.load(tmp_path / "nope.yaml")


@pytest.mark.parametrize(
    ("test", "value", "holds"),
    [
        ("positive", 1, True), ("positive", 0, False), ("positive", True, False),
        ("positive", "3", False), ("true", True, True), ("true", 2, True), ("true", False, False),
        (risk_config.Bound(below=0.3), 0.29, True), (risk_config.Bound(below=0.3), 0.3, False),
        (risk_config.Bound(at_most=1), 1, True), (risk_config.Bound(at_most=1), None, False),
    ],
)  # fmt: skip
def test_signal_tests(test: risk_config.Test, value: object, holds: bool) -> None:
    assert risk_config.passes(test, value) is holds


def test_the_tables_vocabularies_are_the_engines() -> None:
    assert models.RISK_OBJECT_KINDS == observe.OBJECT_KINDS
    assert models.RISK_ENTITY_KINDS == roles.KINDS
    assert models.RISK_ROLES == roles.ROLES
    assert models.RISK_DIRECTIONS == roles.DIRECTIONS
    assert models.RISK_LANES == score.LANES
    assert models.RISK_CATEGORIES == score.CATEGORIES
    assert models.RISK_WINDOWS == risk_config.WINDOWS
    assert set(models.RISK_HELD) == {"lane", "gray_band", "probation", "rules_only", "below",
                                     "target"}  # fmt: skip
