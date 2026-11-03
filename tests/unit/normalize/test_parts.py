"""Field resolution, canonical values, time parsing and the grouping file."""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.config.errors import ConfigError
from argus.normalize.canon import (
    MAX_KEY_STRING,
    MAX_KEY_VALUES,
    canon_domain,
    canon_ip,
    canon_port,
    canon_scalar,
    canon_values,
    canonical_json,
    field_kind,
)
from argus.normalize.fields import leaf_values, values
from argus.normalize.grouping import load_grouping
from argus.normalize.model import FieldIssueKind as K
from argus.normalize.times import parse_interval, parse_lookback, parse_time
from tests.unit.normalize.alerts import REPO_ROOT, flatten, nest

pytestmark = pytest.mark.unit

# --------------------------------------------------------------------------- fields


def test_values_in_every_shape() -> None:
    assert values({"source.ip": "a"}, "source.ip") == ["a"]
    assert values({"source": {"ip": "a"}}, "source.ip") == ["a"]
    assert values({"a": {"b.c": {"d": 1}}}, "a.b.c.d") == [1]
    assert values({"a.b": {"c": 1}, "a": {"b": {"c": 2}}, "a.b.c": 3}, "a.b.c") == [2, 1, 3]
    assert values({"a": [{"b": 1}, {"b": [2, [3, None]]}, "x", None]}, "a.b") == [1, 2, 3]
    assert values({"a": None, "b": [], "c": [[], [None]]}, "a") == []
    assert values({"a": {"b": 1}}, "a") == [{"b": 1}]
    assert values({"a": 1}, "a.b") == []
    assert values({}, "") == []


def test_keyword_suffix() -> None:
    assert values({"url": {"domain": "x"}}, "url.domain.keyword") == ["x"]
    assert values({"url.domain.keyword": "k", "url.domain": "x"}, "url.domain.keyword") == ["k"]
    assert values({"keyword": "x"}, ".keyword") == []


def test_deep_arrays_do_not_recurse() -> None:
    deep: Any = "leaf"
    for _ in range(100_000):
        deep = [deep]
    assert values({"a": deep}, "a") == ["leaf"]
    nested: Any = {"b": "leaf"}
    for _ in range(10_000):
        nested = [nested]
    assert values({"a": nested}, "a.b") == ["leaf"]


simple_docs = st.recursive(
    st.integers() | st.text(max_size=5),
    lambda inner: st.dictionaries(st.sampled_from(["a", "b", "c"]), inner, min_size=1, max_size=3),
    max_leaves=12,
).filter(lambda d: isinstance(d, dict))


@given(simple_docs)
def test_leaf_values_and_values_agree_across_shapes(doc: dict[str, Any]) -> None:
    leaves = leaf_values(doc)
    assert leaf_values(flatten(doc)) == leaves == leaf_values(nest(doc))
    for path, found in leaves.items():
        assert values(doc, path) == found == values(flatten(doc), path)


# --------------------------------------------------------------------------- canon


def test_field_kinds() -> None:
    assert [field_kind(f) for f in ("source.ip", "related.ip", "ip", "source.ip.keyword")] == [
        "ip"
    ] * 4
    assert field_kind("destination.port") == "port"
    assert [
        field_kind(f) for f in ("url.domain", "url.registered_domain", "dns.question.name")
    ] == ["domain"] * 3
    assert field_kind("url.domain.keyword") == "domain"
    assert [field_kind(f) for f in ("source.ipx", "host.name", "")] == ["other"] * 3


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("10.0.0.1", ("10.0.0.1", None)),
        (" 10.0.0.1 ", ("10.0.0.1", None)),
        ("::ffff:10.0.0.1", ("10.0.0.1", None)),
        ("2001:DB8:0:0::1", ("2001:db8::1", None)),
        ("fe80::1%eth0", ("fe80::1%eth0", None)),
        ("", (None, None)),
        ("010.0.0.1", ("010.0.0.1", K.INVALID_IP)),
        ("10.0.0.1:80", ("10.0.0.1:80", K.INVALID_IP)),
        (167772161, (167772161, K.INVALID_IP)),
        ("9" * 100, ("9" * 100, K.INVALID_IP)),
        (None, (None, None)),
        (
            {"a": 1},
            ("json:" + __import__("hashlib").sha256(b'[{"a":1}]').hexdigest(), K.NOT_SCALAR),
        ),
    ],
)
def test_canon_ip(raw: Any, expected: Any) -> None:
    assert canon_ip(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (443, (443, None)), (0, (0, None)), (65535, (65535, None)), (443.0, (443, None)),
        (" 22 ", (22, None)), ("", (None, None)),
        (65536, (65536, K.INVALID_PORT)), (-1, (-1, K.INVALID_PORT)),
        (True, (True, K.INVALID_PORT)),
        ("\uff12\uff12", ("\uff12\uff12", K.INVALID_PORT)), ("22a", ("22a", K.INVALID_PORT)),
        (22.5, (22.5, K.INVALID_PORT)), (float("nan"), ("nan", K.NOT_SCALAR)),
    ],
)  # fmt: skip
def test_canon_port(raw: Any, expected: Any) -> None:
    assert canon_port(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", ("example.com", None)),
        ("  ", (None, None)),
        (".", (None, None)),
        ("Bücher.Example", ("xn--bcher-kva.example", None)),
        ("bücher。example", ("xn--bcher-kva.example", None)),
        ("ü" * 80 + ".example", ("ü" * 80 + ".example", K.INVALID_DOMAIN)),
        (5, (5, K.INVALID_DOMAIN)),
    ],
)
def test_canon_domain(raw: Any, expected: Any) -> None:
    assert canon_domain(raw) == expected


def test_long_and_unstorable_text_becomes_a_digest() -> None:
    long_value, issue = canon_scalar("x" * (MAX_KEY_STRING + 1))
    assert issue is K.VALUE_TOO_LONG
    assert str(long_value).startswith("sha256:")
    assert canon_scalar("x" * MAX_KEY_STRING) == ("x" * MAX_KEY_STRING, None)
    for bad in ("a\x00b", "a\ud800b"):
        value, issue = canon_scalar(bad)
        assert issue is K.UNSTORABLE_TEXT
        assert str(value).startswith("sha256:")
        value, issue = canon_domain(bad + "é")
        assert issue is K.UNSTORABLE_TEXT
    assert canon_scalar("a\x00b") != canon_scalar("a\x00c")


def test_canon_values() -> None:
    assert canon_values("source.ip", []) == (None, ())
    assert canon_values("source.ip", ["10.0.0.2", "::ffff:10.0.0.2", ""]) == ("10.0.0.2", ())
    assert canon_values("x", ["b", "a", "b", 1, True]) == (("a", "b", 1, True), ())
    assert canon_values("source.ip", ["bad", "10.0.0.1"]) == (("10.0.0.1", "bad"), (K.INVALID_IP,))
    many, issues = canon_values("x", [str(i) for i in range(MAX_KEY_VALUES + 5)])
    assert isinstance(many, tuple)
    assert len(many) == MAX_KEY_VALUES
    assert issues == (K.TOO_MANY_VALUES,)


key_inputs = st.lists(
    st.one_of(st.ip_addresses().map(str), st.text(max_size=8), st.integers(), st.none()), max_size=8
)


@given(
    st.sampled_from(["source.ip", "destination.port", "url.domain", "user.name"]),
    key_inputs,
    st.randoms(),
)
def test_canon_values_is_order_free_and_idempotent(field: str, raw: list[Any], rnd: Any) -> None:
    value, issues = canon_values(field, raw)
    shuffled = list(raw)
    rnd.shuffle(shuffled)
    assert canon_values(field, shuffled) == (value, issues)
    again = list(value) if isinstance(value, tuple) else [value]
    assert canon_values(field, again)[0] == value


@given(st.ip_addresses())
def test_ip_canon_matches_ipaddress(address: Any) -> None:
    text, issue = canon_ip(str(address))
    expected = address.ipv4_mapped if getattr(address, "ipv4_mapped", None) else address
    assert (text, issue) == (str(expected), None)
    assert canon_ip(
        str(ipaddress.IPv6Address(f"::ffff:{address}")) if address.version == 4 else str(address)
    )[0] == str(expected)


def test_canonical_json_keeps_types_apart() -> None:
    assert len({canonical_json(v) for v in (1, 1.0, True, "1", float("nan"), "NaN", [1])}) == 7


# --------------------------------------------------------------------------- times


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-10-09T12:22:47.697Z", datetime(2026, 10, 9, 12, 22, 47, 697000, tzinfo=UTC)),
        ("2026-10-09T12:22:47.697123456Z", datetime(2026, 10, 9, 12, 22, 47, 697123, tzinfo=UTC)),
        ("2026-10-09T17:52:47+05:30", datetime(2026, 10, 9, 12, 22, 47, tzinfo=UTC)),
        ("2026-10-09T12:22:47", datetime(2026, 10, 9, 12, 22, 47, tzinfo=UTC)),
        ("1970-01-01T00:00:00Z", datetime(1970, 1, 1, tzinfo=UTC)),
        ("1969-12-31T23:59:59.999999Z", None),
        ("2199-12-31T23:59:59.999999Z", datetime(2199, 12, 31, 23, 59, 59, 999999, tzinfo=UTC)),
        ("2200-01-01T00:00:00Z", None),
        ("0001-01-01T00:00:00+14:00", None),
        ("9999-12-31T23:59:59-14:00", None),
        ("2026-02-30T00:00:00Z", None),
        ("2026-10-09T12:22:47Z" + " " * 60, None),
        (1760000000000, None),
        (None, None),
    ],
)
def test_parse_time(raw: Any, expected: datetime | None) -> None:
    assert parse_time(raw) == expected


def test_parse_durations() -> None:
    assert parse_lookback("now") == timedelta(0)
    assert parse_lookback(" now-6m ") == timedelta(minutes=6)
    assert parse_lookback("now-360s") == timedelta(minutes=6)
    assert parse_lookback("now-2w") == timedelta(days=14)
    assert parse_lookback("now-366d") == timedelta(days=366)
    for bad in ("now-367d", "now-1d/d", "now+5m", "now-1M", "now-5", "6m", 5, None, "now-\u0665m"):
        assert parse_lookback(bad) is None, bad
    assert parse_interval("5m") == timedelta(minutes=5)
    for bad in ("0m", "now-5m", "5", "5M", "999999999d", None):
        assert parse_interval(bad) is None, bad


# --------------------------------------------------------------------------- grouping file


def test_committed_grouping_file_loads() -> None:
    config = load_grouping(REPO_ROOT / "config" / "grouping.yaml")
    assert config.version == 1
    assert config.rules == {}


def test_grouping_file(tmp_path: Path) -> None:
    assert load_grouping(tmp_path / "missing.yaml").rules == {}
    good = tmp_path / "g.yaml"
    good.write_text("rules:\n  r-1:\n    key_fields: [source.ip, url.domain.keyword]\n")
    assert load_grouping(good).rules["r-1"].key_fields == ("source.ip", "url.domain.keyword")
    for text in (
        "rules:\n  r-1:\n    key_fields: []\n",
        "rules:\n  r-1:\n    key_fields: ['bad field']\n",
        "rules:\n  r-1:\n    key_feilds: [source.ip]\n",
        "version: 2\n",
        "rulez: {}\n",
    ):
        good.write_text(text)
        with pytest.raises(ConfigError):
            load_grouping(good)
