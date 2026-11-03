"""P1: the pseudonymizer's limits and branches, value by value (mutation testing, D-040)."""

from __future__ import annotations

import inspect
import json
import pickle
import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from argus import site
from argus.llm import privacy as privacy_module
from argus.llm.detect import Campus, Found
from argus.llm.privacy import (
    Policy,
    Privacy,
    PrivacyConfigError,
    _cut,
    _label,
    _parse_time,
    _relative,
    load_policy,
)
from argus.site import SiteSettings
from tests.unit.llm.conftest import ASSETS
from tests.unit.llm.test_privacy import dossier

pytestmark = pytest.mark.unit
T0 = datetime(2026, 10, 14, 20, 30, tzinfo=UTC)


def render(privacy: Privacy, **facts: Any) -> str:
    body = dossier()
    body["facts"].update(facts)
    return privacy.request([body]).text


def rule_line(privacy: Privacy, name: str) -> str:
    return render(privacy, rule_name=name).splitlines()[1]


@pytest.mark.parametrize(
    ("first", "hour"),
    [("2026-10-14T18:29:00Z", 23), ("2026-10-14T18:30:00Z", 0), ("2026-10-14T20:30:00Z", 2)],
)
def test_the_ist_hour_at_its_edges(privacy: Privacy, first: str, hour: int) -> None:
    assert f"the first at {hour:02d} h IST" in render(privacy, first_event_at=first)


@pytest.mark.parametrize(
    ("value", "label"),
    [("a" * 32, "HASH"), ("a" * 40, "HASH"), ("a" * 64, "HASH"), ("a" * 128, "HASH"),
     ("a" * 33, "ID"), ("123e4567-e89b-12d3-a456-426614174000", "ID")],
)  # fmt: skip
def test_hash_or_id(value: str, label: str) -> None:
    assert _label(Found(0, 1, "hex_id", value), Campus()) == label


@pytest.mark.parametrize(
    ("kind", "label"),
    [("ip", "IP"), ("mac", "MAC"), ("domain", "SITE"), ("email", "EMAIL"), ("user_path", "USER"),
     ("roll_number", "USER"), ("secret", "CRED"), ("url_token", "CRED"), ("credentials", "CRED")],
)  # fmt: skip
def test_labels(kind: Any, label: str) -> None:
    assert _label(Found(0, 1, kind, "x"), Campus()) == label


def test_names_are_hosts_or_users() -> None:
    campus = Campus(hosts=frozenset({"tp8"}), users=frozenset({"alice"}))
    assert _label(Found(0, 1, "name", "Alice"), campus) == "USER"
    assert _label(Found(0, 1, "name", "tp8"), campus) == "HOST"


@pytest.mark.parametrize(
    ("change", "message"),
    [({"text_chars": 39}, "greater than or equal"), ({"text_chars": 2001}, "less than or equal"),
     ({"top_values": 0}, "greater"), ({"top_values": 21}, "less"),
     ({"entities": 0}, "greater"), ({"entities": 51}, "less"),
     ({"ti_answers": 0}, "greater"), ({"ti_answers": 51}, "less"),
     ({"version": 0}, "greater")],
)  # fmt: skip
def test_policy_bounds(change: dict[str, Any], message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        Policy.model_validate({**load_policy().model_dump(), **change})


@pytest.mark.parametrize(
    "change",
    [{"text_chars": 40}, {"text_chars": 2000}, {"top_values": 1}, {"top_values": 20},
     {"entities": 1}, {"entities": 50}, {"ti_answers": 1}, {"ti_answers": 50}],
)  # fmt: skip
def test_policy_bounds_allowed(change: dict[str, Any]) -> None:
    assert Policy.model_validate({**load_policy().model_dump(), **change})


def test_policy_defaults_and_frozen() -> None:
    minimal = Policy.model_validate({"version": 1, "campus_domains": ["x.in"], "fields": {}})
    assert (minimal.text_chars, minimal.top_values, minimal.entities, minimal.ti_answers) == (
        300, 5, 10, 10,
    )  # fmt: skip
    assert minimal.asset_fields == ()
    assert minimal.query_values_for is None  # the site's web families (query_patterns)
    with pytest.raises(ValidationError):
        minimal.version = 2  # type: ignore[misc]


def test_template_words_include_the_registry() -> None:
    words = privacy_module.template_words()
    assert {"repeats", "detection", "domains"} <= words


def test_pickling_names_the_rule() -> None:
    with pytest.raises(TypeError) as caught:
        pickle.dumps(privacy_module.Pseudonyms("I1"))
    assert str(caught.value) == "pseudonym maps are never pickled"


def test_the_asset_map_message() -> None:
    with pytest.raises(ValueError, match="asset map") as caught:
        Privacy.build(load_policy(), None)
    assert str(caught.value) == "the privacy layer needs the asset map"


def test_reprs_hold_no_campus_or_map(privacy: Privacy) -> None:
    shown = repr(privacy.request([dossier()]))
    assert "Campus(" not in shown
    assert "Pseudonyms(" not in shown


def test_campus_domains_are_normalised() -> None:
    policy = Policy.model_validate(
        {**load_policy().model_dump(), "campus_domains": [".EXAMPLE.edu."]}
    )
    with site.using(SiteSettings()):  # the policy's domains alone, cleaned
        assert Privacy.build(policy, ASSETS).campus.domains == ("example.edu",)


def test_the_campus_domains_are_the_sites_and_the_policys() -> None:
    policy = Policy.model_validate({**load_policy().model_dump(), "campus_domains": ["x.in"]})
    assert Privacy.build(policy, ASSETS).campus.domains == (
        "example.edu",
        "example-univ.org",
        "x.in",
    )
    with site.using(SiteSettings(own_domains=("a.example", "b.example"))):
        assert Privacy.build(policy, ASSETS).campus.domains == ("a.example", "b.example", "x.in")
    # none configured: the layer refuses (D-285)
    with site.using(SiteSettings()), pytest.raises(PrivacyConfigError, match="at least one domain"):
        Privacy.build(load_policy(require_domains=False), ASSETS)


def test_the_default_request_size() -> None:
    default = inspect.signature(Privacy.request).parameters["max_chars"].default
    assert default == 60_000


def test_sizes_at_the_edge(privacy: Privacy) -> None:
    one = len(privacy.request([dossier()]).text)
    three = [dossier(), dossier(), dossier()]
    assert privacy.request(three, max_chars=3 * one + 2).items == ("I1", "I2", "I3")
    assert privacy.request(three, max_chars=3 * one + 1).items == ("I1", "I2")


def test_a_request_never_carries_another_items_pseudonym(
    privacy: Privacy, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(privacy_module, "LOOKALIKE", re.compile("(?!)"))
    forged = dossier()
    forged["facts"]["rule_name"] = "see I2.IP_1"
    request = privacy.request([forged, dossier()])
    assert request.failed == ("I1",)
    assert request.items == ("I2",)


def test_the_campus_collects_request_names(privacy: Privacy) -> None:
    body = dossier()
    body["facts"]["entities"] = {"host": ["web7", "8.8.8.8", "10.1.2.3"], "user": ["bob"]}
    body["facts"]["group_key"] = json.dumps([["host.name", "gk1"], ["user.name", "carol"]])
    body["context"]["pack"]["fields"]["host.name"]["top"] = [["fld1", 1], ["8.8.4.4", 1]]
    body["context"]["pack"]["fields"]["user.name"] = {"top": [["dave", 1]]}
    campus = privacy.campus_for([body, "not a body", {"facts": {"entities": "x"}}])
    assert campus.hosts == {"web7", "10.1.2.3", "gk1", "fld1", "tp8"} - {"tp8"} | set()
    assert campus.users == {"bob", "carol", "dave"}


def test_grouping_keys_need_pairs(privacy: Privacy) -> None:
    line = render(privacy, group_key='[["a", "b", "c"]]').splitlines()[3]
    assert line == 'Grouped by: "[[\\"a\\", \\"b\\", \\"c\\"]]"'


@pytest.mark.parametrize(
    ("days", "relative"),
    [(399, True), (400, False), (-399, True), (-400, False)],
)
def test_epochs_within_400_days(days: int, relative: bool) -> None:
    at = T0 + timedelta(days=days)
    assert (_parse_time(str(int(at.timestamp())), T0) is not None) == relative


@pytest.mark.parametrize(
    "month", ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
)
def test_every_month(month: str) -> None:
    at = _parse_time(f"01/{month}/2026:00:00:00", T0)
    assert at is not None
    assert at.strftime("%b") == month
    assert _parse_time(f"{month}  1 00:00:00", T0) is not None


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("at 20261014T204000Z", "at t0+10m"),
        ("at 14/Oct/2026:20:40:00", "at t0+10m"),
        ("at Oct 14, 2026 @ 20:40", "at t0+10m"),
        ("at Oct 14 20:40:00", "at t0+10m"),
        ("at 2026-10-15", "at t0+4h"),
        (f"at {int((T0 + timedelta(hours=3)).timestamp())}", "at t0+3h"),  # epoch seconds
        (f"at {int((T0 + timedelta(hours=3)).timestamp()) * 1000}", "at t0+3h"),  # milliseconds
        ("at 1500000000", "at [a time]"),  # an epoch far from t0
    ],
)
def test_times_in_text(privacy: Privacy, text: str, shown: str) -> None:
    assert rule_line(privacy, text) == f'Rule: "{shown}" · severity high · risk 73'


def test_relative_rounding() -> None:
    assert _relative(T0 + timedelta(minutes=5040), T0) == "t0+4d"
    assert _relative(T0 + timedelta(minutes=4970), T0) == "t0+3d"


@pytest.mark.parametrize(
    ("value", "shown"),
    [(None, "?"), ("x", '"x"'), ("y" * 60, '"' + "y" * 36 + ' […]"')],
)
def test_counts_of_odd_values(privacy: Privacy, value: Any, shown: str) -> None:
    assert f"Alerts: {shown} over" in render(privacy, alert_count=value)


@pytest.mark.parametrize(
    ("value", "shown"),
    [(None, "?"), ("123456", "123456"), ("1234567", '"1234567"'), ("12a", '"12a"'),
     (3.0, "3"), (float("inf"), "?"), (True, '"True"')],
)  # fmt: skip
def test_exact_values(privacy: Privacy, value: Any, shown: str) -> None:
    body = dossier()
    body["report"]["steps"][0]["number"] = value
    text = privacy.request([body]).text
    assert f"\n{shown}. [answered]" in text


@pytest.mark.parametrize(
    ("value", "shown"),
    [(None, "?"), (99.5, "99.5"), (100.0, "~100"), (100, "~100"), (99, "99"),
     (float("nan"), "?"), ("hi", '"hi"')],
)  # fmt: skip
def test_real_values(privacy: Privacy, value: Any, shown: str) -> None:
    assert f"· risk {shown}\n" in render(privacy, risk_score=value)


def test_a_legend_without_asset_fields(privacy: Privacy) -> None:
    policy = Policy.model_validate({**load_policy().model_dump(), "asset_fields": []})
    bare = Privacy.build(policy, ASSETS)
    assert "- I1.IP_1: a campus device in the asset map\n" in bare.request([dossier()]).text


@pytest.mark.parametrize(
    ("url", "shown"),
    [
        (" http://x.org/a ", '"http://x.org/a"'),
        ("http://x.org/a\tb", '"http://x.org/a\\tb"'),
        ("http://bob@evil.example/", '"http://[credentials]@evil.example/"'),
        ("http://x.org/a?b=1?c=2&d", '"http://x.org/a?b=...&d=..."'),
        ("/p?&b=1", '"/p?b=..."'),
    ],
)
def test_url_edges(privacy: Privacy, url: str, shown: str) -> None:
    body = dossier()
    body["context"]["pack"]["fields"]["url.original"]["top"] = [[url, 1]]
    assert f"- url.original (1): {shown} x1" in privacy.request([body]).text


def test_domains_are_normalised(privacy: Privacy) -> None:
    body = dossier()
    body["context"]["pack"]["fields"]["url.domain"] = {"top": [[" MOODLE.EXAMPLE.EDU. ", 1]]}
    assert "- url.domain (?): I1.SITE_1 x1" in privacy.request([body]).text


def test_text_at_its_limit_is_not_cut(privacy: Privacy) -> None:
    body = dossier()
    body["report"]["steps"][0]["text"] = "x" * 300
    request = privacy.request([body])
    assert '"' + "x" * 300 + '"' in request.text
    assert request.truncated == ()


def test_four_deep_encodings_are_withheld(privacy: Privacy) -> None:
    dot = "%2525252e"  # "." percent-encoded four times
    deep = f"10{dot}20{dot}3{dot}4"
    assert rule_line(privacy, f"x {deep}") == (
        'Rule: "[withheld: encoded identifier]" · severity high · risk 73'
    )


def test_replacements_are_set_apart(privacy: Privacy) -> None:
    assert rule_line(privacy, "10.20.3.4.") == 'Rule: "I1.IP_1 ." · severity high · risk 73'
    assert rule_line(privacy, "ip-10-20-3-4") == 'Rule: "ip- I1.IP_1" · severity high · risk 73'


def test_cut_edges() -> None:
    assert _cut("x" * 100, 100) == "x" * 100
    token = "/" * 89 + "I1.IP_1" + "/" * 50  # the pseudonym ends exactly at the cut
    assert _cut(token, 100) == "/" * 89 + "I1.IP_1 […]"
    assert _cut(" " + "x" * 100, 40) == " […]"
    assert _cut("y" * 60, 40) == "y" * 36 + " […]"  # no blank at all: a hard cut
    assert _cut("a" * 56 + " " + "b" * 100, 100) == "a" * 56 + " " + "b" * 39 + " […]"
    assert _cut("a" * 57 + " " + "b" * 100, 100) == "a" * 57 + " […]"


def test_threat_intel_and_web_edges(privacy: Privacy) -> None:
    def lines(pack: dict[str, Any]) -> list[str]:
        body = dossier()
        body["context"]["pack"].update(pack)
        text = privacy.request([body]).text
        return [x for x in text.splitlines() if x.startswith(("Threat intel", "Web", "- WAF"))]

    assert lines({"ti": {}}) == []
    assert lines({"ti": {"listed": ["x"]}}) == [
        "Threat intel: 1 value(s) listed; 0 checked; source answers: none; stale answers 0"
    ]
    source = {"s": {"match": [{}], "freshness": {"stale": True}}}
    stale = {"answers": [{"kind": "ip", "value": "1.1.1.1", "sources": source}]}
    assert lines({"ti": stale})[0].endswith("source answers: match 1; stale answers 1")
    assert lines({"ti": {}, "web": {"categories": ["x"]}}) == ["Web: 0 user agent(s)"]
    assert lines({"ti": {}, "web": {}}) == []
