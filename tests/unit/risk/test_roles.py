"""E0: entity roles from ECS namespaces and address classes, and the new fields."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from argus.risk import roles
from argus.risk.roles import RoleEntity
from tests.unit.risk.conftest import CAMPUS, CLASSIFIER

pytestmark = pytest.mark.unit


def of(fields: dict[str, list[object]]) -> tuple[str, set[tuple[str, str, str]]]:
    way, found = roles.roles(fields, CLASSIFIER, CAMPUS)
    return way, {(e.kind, e.value, e.role) for e in found}


def test_outbound_campus_actor_and_outside_threats() -> None:
    way, found = of({
        "source.ip": ["10.1.1.1"], "destination.ip": ["45.138.12.9"],
        "url.domain": ["Bad.Example.COM."], "url.path": ["/a/b/c/x.PHP?q=1"],
        "file.hash.sha256": ["A" * 64], "user.name": ["Alice"],
    })  # fmt: skip
    assert way == "outbound"
    assert found == {
        ("ip", "10.1.1.1", "actor"), ("ip", "45.138.12.9", "threat"),
        ("domain", "bad.example.com", "threat"), ("url_pattern", "/a/b/*.php", "threat"),
        ("hash", "a" * 64, "threat"), ("user", "alice", "actor"),
    }  # fmt: skip


def test_inbound_outside_actor_and_campus_targets() -> None:
    way, found = of({
        "source.ip": ["45.138.13.7"], "destination.ip": ["131.21.124.10"],
        "url.domain": ["www.example.edu"], "host.name": ["web-1"], "user.name": ["bob"],
    })  # fmt: skip
    assert way == "inbound"
    assert found == {
        ("ip", "45.138.13.7", "actor"), ("ip", "131.21.124.10", "target"),
        ("domain", "www.example.edu", "target"), ("host", "web-1", "target"),
        ("user", "bob", "target"),  # the account tried, not who acted
    }  # fmt: skip


def test_lateral_and_unknown_directions() -> None:
    assert of({"source.ip": ["10.1.1.1"], "destination.ip": ["10.2.2.2"]})[0] == "lateral"
    assert of({"client.ip": ["10.1.1.1"]})[0] == "outbound"
    assert of({"user.name": ["carol"]})[0] == "unknown"
    assert of({"source.ip": ["127.0.0.1"]}) == ("unknown", {("ip", "127.0.0.1", "other")})


def test_mail_addresses_take_their_role_from_the_campus_domain() -> None:
    _, found = of({
        "source.ip": ["10.1.1.1"], "email.from.address": ["dean@Example.edu"],
        "email.to.address": ["x@outside.test", "y@dept.example.edu"],
        "email.sender.address": ["spoof@outside.test"], "user.email": ["me@example.edu"],
    })  # fmt: skip
    assert found >= {
        ("email", "dean@example.edu", "actor"), ("email", "x@outside.test", "threat"),
        ("email", "y@dept.example.edu", "target"), ("email", "spoof@outside.test", "threat"),
        ("email", "me@example.edu", "actor"),
    }  # fmt: skip


def test_generic_accounts_bad_hashes_and_unusable_values_are_dropped() -> None:
    _, found = of({
        "source.ip": ["10.1.1.1", "not an ip", True], "user.name": ["root", "Admin", ""],
        "email.from.address": ["postmaster@example.edu", "no-at-sign"],
        "file.hash.md5": ["xyz"], "url.path": ["", "?only=query"],
    })  # fmt: skip
    assert found == {("ip", "10.1.1.1", "actor")}


@pytest.mark.parametrize("name", [".", "..", " . ", "...."])
def test_a_root_or_dots_only_domain_is_no_entity(name: str) -> None:
    """The database refuses an empty value; one such alert would stop every pass."""
    _, found = of({"source.ip": ["10.1.1.1"], "dns.question.name": [name], "url.domain": [name]})
    assert found == {("ip", "10.1.1.1", "actor")}
    assert of({"dns.question.name": ["Example.COM.."]})[1] == {("domain", "example.com", "threat")}


def test_values_per_field_are_capped() -> None:
    _, found = of({"source.ip": ["10.1.1.1"],
                   "destination.ip": [f"45.138.12.{n}" for n in range(1, 40)]})  # fmt: skip
    assert len([e for e in found if e[2] == "threat"]) == roles.MAX_VALUES


@pytest.mark.parametrize(
    ("path", "pattern"),
    [
        ("/.env", "/.env"),
        ("/.git/config", "/.git/config"),
        ("/wp-content/plugins/akismet/readme.TXT", "/wp-content/plugins/*.txt"),
        ("/api/v1/users/123456/items", "/api/v1/*"),
        ("/download/20261015/file", "/download/{n}/*"),
        ("/download/20261015", "/download/{n}"),
        ("//", "/"),
        ("/a?x=/b/c", "/a"),
    ],
)
def test_url_patterns(path: str, pattern: str) -> None:
    assert roles.url_pattern(path) == pattern


@given(st.text(max_size=300))
def test_a_url_pattern_is_short_and_a_pattern_of_itself(path: str) -> None:
    pattern = roles.url_pattern(path)
    if pattern is None:
        return
    assert pattern.startswith("/")
    assert len(pattern) <= 200
    assert roles.url_pattern(pattern) == pattern


@given(st.dictionaries(st.sampled_from([f for _, f in roles.FIELDS]),
                       st.lists(st.one_of(st.text(max_size=40), st.ip_addresses().map(str)),
                                max_size=5), max_size=8))  # fmt: skip
def test_roles_never_fail_and_stay_in_their_vocabulary(fields: dict[str, list[object]]) -> None:
    way, found = roles.roles(fields, CLASSIFIER, CAMPUS)
    assert way in roles.DIRECTIONS
    for e in found:
        assert isinstance(e, RoleEntity)
        assert e.kind in roles.KINDS
        assert e.role in roles.ROLES
        assert 0 < len(e.value) <= roles.MAX_VALUE
