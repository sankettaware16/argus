"""The fixture policy (config/fixtures.yaml): what it accepts and what it refuses at load time."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from argus.fixtures.policy import DEFAULT_KEEP_NAMES, FixturePolicy, load_policy
from tests.conftest import REPO_ROOT


def _load(tmp_path: Path, text: str) -> FixturePolicy:
    path = tmp_path / "fixtures.yaml"
    path.write_text(text)
    return load_policy(path)[0]


def test_the_shipped_policy_loads() -> None:
    policy, digest = load_policy(REPO_ROOT / "config" / "fixtures.yaml")
    raw = (REPO_ROOT / "config" / "fixtures.yaml").read_bytes()
    assert digest == hashlib.sha256(raw).hexdigest()
    assert policy.kind_of("host.name") == "host"
    assert policy.kind_of("threat.enrichments.matched.id") == "id"
    assert policy.kind_of("process.parent.user.name") == "user"  # a pattern
    assert policy.kind_of("message") is None


def test_defaults() -> None:
    policy = FixturePolicy()
    assert policy.keep_names == DEFAULT_KEEP_NAMES
    assert "root" in policy.keep_names
    assert policy.campus_replacement == "univ.example"
    assert policy.drop_top_level == ("fields", "_score", "_ignored", "highlight", "sort")
    assert policy.field_kinds() == {}
    assert policy.field_patterns() == ()


def test_exact_paths_win_over_patterns_and_patterns_keep_policy_order() -> None:
    policy = FixturePolicy(
        fields={"user": ("*.name", "x.*"), "host": ("a.name", "*.host*")},
    )
    assert policy.field_kinds() == {"a.name": "host"}
    assert policy.field_patterns() == (("*.name", "user"), ("x.*", "user"), ("*.host*", "host"))
    assert policy.kind_of("a.name") == "host"
    assert policy.kind_of("b.name") == "user"
    assert policy.kind_of("x.hostname") == "user"  # the first matching pattern wins
    assert policy.kind_of("y.hostname") == "host"
    assert policy.kind_of("name") is None  # "*" needs at least the dot before it here


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"fields": {"person": ["user.name"]}}, "unknown field kinds"),
        ({"fields": {"host": ["host.name"], "user": ["host.name"]}}, "two kinds"),
        ({"literals": {"  ": "x"}}, "must not be blank"),
        ({"campus_domains": ["a.ac.in", "cs.a.ac.in"]}, "is inside campus domain a.ac.in"),
        ({"campus_domains": ["a.ac.in"], "keep_domains": ["ac.in"]}, "overlaps campus domain"),
        ({"campus_domains": ["a.ac.in"], "keep_domains": ["www.A.ac.in."]}, "overlaps campus"),
        ({"campus_domains": ["a.ac.in"], "keep_domains": ["a.ac.in"]}, "overlaps campus domain"),
        (
            {"campus_domains": ["a.ac.in"], "campus_replacement": "x.a.ac.in"},
            "campus_replacement x.a.ac.in is inside",
        ),
    ],
)
def test_refused_at_load_time(data: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        FixturePolicy.model_validate(data)


def test_a_field_listed_twice_under_one_kind_is_fine() -> None:
    policy = FixturePolicy(fields={"host": ("host.name", "host.name")})
    assert policy.field_kinds() == {"host.name": "host"}


def test_unrelated_keep_and_campus_domains_are_fine() -> None:
    policy = FixturePolicy(campus_domains=("a.ac.in", "b.org"), keep_domains=("ab.ac.in",))
    assert policy.campus_domains == ("a.ac.in", "b.org")


@pytest.mark.parametrize(
    "text",
    [
        "fields:\n  host: [host.name]\n  host: [agent.name]\n",
        "literals:\n  A: b\n  A: c\n",
        "version: 1\nversion: 2\n",
    ],
)
def test_duplicate_keys_are_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key"):
        _load(tmp_path, text)


def test_an_unhashable_key_is_refused_by_yaml(tmp_path: Path) -> None:
    with pytest.raises(yaml.constructor.ConstructorError, match="unhashable"):
        _load(tmp_path, "? [a, b]\n: 1\n")


@pytest.mark.parametrize("text", ["- a\n", "just text\n", "42\n"])
def test_a_policy_must_be_a_mapping(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError, match="must contain a mapping"):
        _load(tmp_path, text)


def test_an_empty_file_is_the_default_policy(tmp_path: Path) -> None:
    assert _load(tmp_path, "") == FixturePolicy()


def test_unknown_keys_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="colour"):
        _load(tmp_path, "colour: red\n")


def test_the_default_keep_names_are_exactly_these() -> None:
    """Every default keep name is written verbatim and never denylisted, so the list is pinned:
    adding a name (or a typo in one) is a decision, not an accident."""
    assert DEFAULT_KEEP_NAMES == (
        "admin",
        "administrator",
        "anonymous",
        "apache",
        "builtin",
        "centos",
        "daemon",
        "debian",
        "default",
        "ec2-user",
        "font driver host",
        "guest",
        "local service",
        "localhost",
        "mysql",
        "network service",
        "nginx",
        "nobody",
        "nt authority",
        "nt service",
        "postgres",
        "public",
        "root",
        "squid",
        "system",
        "test",
        "ubuntu",
        "user",
        "window manager",
        "workgroup",
        "www-data",
    )


# ------------------------------------------------------------------ mutation-testing gaps (R2 gate)


def test_a_policy_is_immutable_and_versioned() -> None:
    policy = FixturePolicy()
    assert policy.version == 1
    with pytest.raises(ValidationError, match="frozen"):
        policy.version = 2  # type: ignore[misc]


def test_a_blank_literal_is_named_in_the_error() -> None:
    with pytest.raises(ValueError, match=r"Value error, a literal must not be blank"):
        FixturePolicy.model_validate({"literals": {"  ": "x"}})


@pytest.mark.parametrize("tld", ["example", "invalid", "test", "localhost"])
def test_every_reserved_tld_is_a_valid_campus_replacement(tld: str) -> None:
    assert FixturePolicy(campus_replacement=f"univ.{tld}").campus_replacement == f"univ.{tld}"


def test_the_campus_replacement_error_lists_the_reserved_tlds() -> None:
    with pytest.raises(ValueError, match=r"\(\.example, \.invalid, \.test, \.localhost\)"):
        FixturePolicy(campus_replacement="univ.ac.in")


@pytest.mark.parametrize("pattern", ["messa*", "@time*", "event.ori*", "x*", "a.b.*"])
def test_a_pattern_matching_any_canary_field_is_refused(pattern: str) -> None:
    with pytest.raises(ValueError, match="would also match unrelated fields"):
        FixturePolicy(fields={"host": (pattern,)})


def test_two_letter_literals_are_not_looked_for_inside_keep_names() -> None:
    """Like DomainMapper, the keep-list checks ignore terms under 3 characters: a 2-letter
    literal (CU) does not make ``curl`` an illegal keep name."""
    policy = FixturePolicy(literals={"CU": "EU"}, keep_names=("curl",))
    assert policy.keep_names == ("curl",)


def test_a_literal_under_a_kept_domain_is_refused() -> None:
    with pytest.raises(ValueError, match=r"literal 'a\.github\.com' is a kept domain"):
        FixturePolicy(keep_domains=("github.com",), literals={"a.github.com": "x"})


def test_a_campus_replacement_may_have_more_than_two_labels() -> None:
    policy = FixturePolicy(campus_replacement="campus.univ.example")
    assert policy.campus_replacement == "campus.univ.example"


def test_a_recursive_policy_is_refused_by_validation_naming_the_field(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("version: 1\nfields: &a\n  host: [*a]\n")
    with pytest.raises(ValidationError, match=r"fields\.host\.0"):
        load_policy(path)
