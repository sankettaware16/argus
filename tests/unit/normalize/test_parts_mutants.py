"""Tests written for the mutants the R3 suite missed in the parts (canon, fields, grouping,
times, model): exact limits as literals, whitespace-only values, every listed name."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.normalize.canon import (
    canon_domain,
    canon_ip,
    canon_port,
    canon_values,
    canonical_json,
    digest,
    field_kind,
)
from argus.normalize.model import FieldIssueKind as K

pytestmark = pytest.mark.unit


def test_canonical_json_sorts_keys_and_escapes_non_ascii() -> None:
    assert canonical_json({"b": 1, "a": "é\ud800"}) == '{"a":"\\u00e9\\ud800","b":1}'
    assert digest({"b": 1, "a": 2}) == digest({"a": 2, "b": 1})


@pytest.mark.parametrize(
    ("field", "kind"),
    [
        ("source.ip", "ip"), ("ip", "ip"), ("source.ip.keyword", "ip"),
        ("destination.port", "port"),
        ("url.domain", "domain"), ("url.registered_domain", "domain"),
        ("url.subdomain", "domain"), ("dns.question.name", "domain"),
        ("dns.question.name.keyword", "domain"),
        ("host.name", "other"), ("ipx", "other"), ("a.ip.b", "other"),
    ],
)  # fmt: skip
def test_field_kinds(field: str, kind: str) -> None:
    assert field_kind(field) == kind


def test_key_string_limit_is_512() -> None:
    assert canon_values("host.name", ["h" * 512]) == ("h" * 512, ())
    value, issues = canon_values("host.name", ["h" * 513])
    assert isinstance(value, str)
    assert value.startswith("sha256:")
    assert issues == (K.VALUE_TOO_LONG,)


def test_key_values_limit_is_64() -> None:
    names = [f"h{i:03}" for i in range(65)]
    assert canon_values("host.name", names[:64]) == (tuple(names[:64]), ())
    assert canon_values("host.name", names) == (tuple(names[:64]), (K.TOO_MANY_VALUES,))


def test_ip_text_limit_is_64() -> None:
    scoped = "fe80::1%" + "x" * 56  # 64 characters, a valid scoped address
    assert canon_ip(scoped) == (scoped, None)
    assert canon_ip(scoped + "x") == (scoped + "x", K.INVALID_IP)


@pytest.mark.parametrize("canon", [canon_ip, canon_port, canon_domain])
def test_whitespace_only_is_null(canon: object) -> None:
    assert canon("  \t") == (None, None)  # type: ignore[operator]


def test_domain_trailing_dot_and_case() -> None:
    assert canon_domain("WWW.EXAMPLE.BOX.") == ("www.example.box", None)
    assert canon_domain(" Ex.Example. ") == ("ex.example", None)


def test_domain_length_limit_is_512() -> None:
    assert canon_domain("A" * 512) == ("a" * 512, None)
    value, issue = canon_domain("A" * 513)
    assert isinstance(value, str)
    assert value.startswith("sha256:")
    assert issue is K.VALUE_TOO_LONG


def test_canonical_json_is_json() -> None:
    assert json.loads(canonical_json([1, "x", None])) == [1, "x", None]


# --------------------------------------------------------------------------- fields


def test_a_value_that_repeats_its_own_key_is_read_once() -> None:
    from argus.normalize.fields import values

    assert values({"a": {"a": 1}}, "a") == [{"a": 1}]
    assert values({"a.b": {"a.b": 5}}, "a.b") == [{"a.b": 5}]


def test_a_bare_keyword_suffix_is_not_a_multi_field() -> None:
    from argus.normalize.fields import field_kind_name, values

    assert field_kind_name(".keyword") == ".keyword"
    assert field_kind_name("x.keyword") == "x"
    assert values({"": 5}, ".keyword") == []
    assert values({"x": 5}, "x.keyword") == [5]


# --------------------------------------------------------------------------- model contract

# The stored wire values (R5 persists them). Changing one is a NORMALIZER_VERSION bump.
WIRE_VALUES = {
    "Adapter": ["event", "threshold", "esql_aggregate", "eql_sequence", "generic"],
    "AncestorKind": ["concrete", "pattern", "empty"],
    "ExecutionType": ["scheduled", "manual", "unknown"],
    "FieldIssueKind": [
        "invalid_ip", "invalid_port", "invalid_domain", "not_scalar", "value_too_long",
        "unstorable_text", "too_many_values", "conflicting_values", "invalid_time",
        "missing_time", "invalid_value", "invalid_rule_parameter", "rule_type_mismatch",
    ],
    "KeySource": ["suppression", "threshold", "config", "generic"],
    "QuarantineReason": [
        "not_a_document", "too_large", "missing_field", "invalid_field", "conflicting_field",
        "id_mismatch",
    ],
    "RuleType": [
        "query", "saved_query", "threat_match", "new_terms", "threshold", "esql", "eql",
        "machine_learning", "unknown",
    ],
    "SingletonReason": ["all_null", "missing_field"],
    "TimeAnomaly": ["event_after_ingest", "event_after_detection", "window_inverted"],
    "TimeBasis": ["original_time", "intended_timestamp", "detection_timestamp"],
    "WindowBasis": ["point", "threshold", "esql_lookback"],
}  # fmt: skip


def test_wire_values_are_fixed() -> None:
    from enum import StrEnum

    import argus.normalize.model as model

    enums = {
        name: [member.value for member in obj]
        for name, obj in vars(model).items()
        if isinstance(obj, type) and issubclass(obj, StrEnum) and obj is not StrEnum
    }
    assert enums == WIRE_VALUES
    assert model.NORMALIZER_VERSION == "1.1.0"


def test_models_are_frozen_and_closed() -> None:
    from pydantic import ValidationError

    from argus.normalize import NormalizedAlert, normalize
    from argus.normalize.model import Entity
    from tests.unit.normalize.alerts import QUERY, fixture

    alert = normalize(fixture(QUERY))
    assert isinstance(alert, NormalizedAlert)
    with pytest.raises(ValidationError):
        alert.rule_id = "other"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        Entity(kind="user", field="user.name", value="a", extra=1)  # type: ignore[call-arg]
    for kind in ("ip", "domain", "host", "user"):
        assert Entity(kind=kind, field="f", value="v").kind == kind
    with pytest.raises(ValidationError):
        Entity(kind="other", field="f", value="v")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- grouping file


def test_default_grouping_path_is_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from argus.normalize.grouping import load_grouping

    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "grouping.yaml").write_text("rules:\n  r-1:\n    key_fields: [a]\n")
    monkeypatch.chdir(tmp_path)
    assert load_grouping().rules["r-1"].key_fields == ("a",)


def test_grouping_version_and_field_count_limits() -> None:
    from pydantic import ValidationError

    from argus.normalize.grouping import GroupingConfig, RuleGrouping

    assert GroupingConfig().version == 1
    assert GroupingConfig.model_validate({"version": 1}).version == 1
    for version in (0, 2):
        with pytest.raises(ValidationError):
            GroupingConfig.model_validate({"version": version})
    names = [f"f{i}" for i in range(17)]
    assert len(RuleGrouping(key_fields=tuple(names[:16])).key_fields) == 16
    with pytest.raises(ValidationError):
        RuleGrouping(key_fields=tuple(names))
    config = GroupingConfig()
    with pytest.raises(ValidationError):
        config.version = 1  # type: ignore[misc]


def test_grouping_error_messages(tmp_path: Path) -> None:
    from argus.config.errors import ConfigError
    from argus.normalize.grouping import load_grouping

    path = tmp_path / "g.yaml"
    path.write_text("version: 2\nrules:\n  r-1:\n    key_fields: []\n")
    with pytest.raises(ConfigError) as info:
        load_grouping(path)
    assert str(info.value) == (
        f"invalid grouping file {path}: version: Input should be less than or equal to 1; "
        "rules.r-1.key_fields: Tuple should have at least 1 item after validation, not 0"
    )


# --------------------------------------------------------------------------- times


def test_time_text_limit_is_64() -> None:
    from argus.normalize.times import parse_time

    padded = "2026-10-09T12:00:00Z".ljust(64)
    assert parse_time(padded) is not None
    assert parse_time(padded + " ") is None


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("1s", 1), ("2m", 120), ("3h", 3 * 3600), ("4d", 4 * 86400), ("1w", 7 * 86400)],
)
def test_every_duration_unit(text: str, seconds: int) -> None:
    from datetime import timedelta

    from argus.normalize.times import parse_interval, parse_lookback

    assert parse_interval(text) == timedelta(seconds=seconds)
    assert parse_lookback(f"now-{text}") == timedelta(seconds=seconds)
