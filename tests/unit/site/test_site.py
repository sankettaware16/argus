"""The site profile (P4-D1, D-238): neutral defaults, validation, version ranges, licence facts,
the family a rule reads (by role) and the field names of a family."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from argus import site
from argus.site import (
    FIELD_ROLES,
    KibanaFeatures,
    LicenceFacts,
    LogFamily,
    Role,
    SiteError,
    SiteSettings,
    VersionRange,
    feature_ids,
    names_family,
    parse_version,
)
from tests.conftest import REPO_ROOT, example_site, shipped_config_on_the_suites_site

pytestmark = pytest.mark.unit


def family(**kw: Any) -> LogFamily:
    return LogFamily.model_validate({"role": "web", "pattern": "web-logs-*", **kw})


# --------------------------------------------------------------------------- the defaults


def test_the_defaults_are_neutral_and_work_on_a_fresh_elastic() -> None:
    s = SiteSettings()
    assert s.families == ()
    assert (s.space, s.alerts_index_name) == ("default", ".alerts-security.alerts-default")
    assert s.alerts_backing_prefix == ".internal.alerts-security.alerts-default-"
    assert (s.elastic_versions, s.kibana_versions) == (">=8.0,<10", ">=8.0,<10")
    assert (s.incident_id_prefix, s.timezone, s.own_network_noun) == (
        "IR",
        "UTC",
        "your network",
    )
    assert (s.own_networks, s.own_domains) == ((), ())
    assert s.kibana_features == KibanaFeatures(security="siemV2", cases="securitySolutionCasesV3")
    assert s.watched_sources == ()
    assert s.all_sources == ()
    assert s.checked_log_patterns == ()  # nothing is asked of logs the site does not read
    assert (s.log_patterns, s.ti_indices) == ((), ())


def test_nothing_of_acme_is_in_the_defaults() -> None:
    text = repr(SiteSettings().model_dump()).lower()
    for word in ("acme", "acme", "acme", "squid", "kolkata", "campus", "10.204"):
        assert word not in text


def test_the_active_site_is_the_one_a_block_sets_and_is_restored() -> None:
    before = site.active()
    other = SiteSettings(space="other")
    with site.using(other):
        assert site.active() is other
        assert site.source_for(Role.PROXY) == "proxy"  # no family: the role's own name
        assert site.fields_for(Role.PROXY)("action") == "event.action"  # the ECS name
    assert site.active() is before


# --------------------------------------------------------------------------- families


def test_a_family_name_defaults_to_its_role_and_a_role_may_have_two_families() -> None:
    assert family().name == "web"
    s = SiteSettings(families=(family(), family(name="nginx", pattern="nginx-*")))
    assert s.all_sources == ("web", "nginx")
    assert [f.name for f in s.of_role(Role.WEB)] == ["web", "nginx"]
    with pytest.raises(ValidationError, match="two families share a name"):
        SiteSettings(families=(family(), family(pattern="other-*")))


@pytest.mark.parametrize(
    ("pattern", "daily"),
    [
        ("web-logs-*", True),
        ("app.logs.*", True),
        ("logs_nginx_*", True),
        ("logs-nginx.access-default", False),
        ("weblogs", False),
    ],
)
def test_a_pattern_is_daily_indices_or_one_stream(pattern: str, daily: bool) -> None:
    f = family(pattern=pattern)
    assert f.daily is daily
    if daily:
        assert f.prefix == pattern[:-1]
    else:
        with pytest.raises(SiteError, match="data stream"):
            _ = f.prefix


@pytest.mark.parametrize(
    "pattern",
    ["Web-*", "web*", "*", "web-*-logs-*", "-web-*", "web logs-*", "", "web-logs-*,x", "web/logs"],
)
def test_a_bad_pattern_is_refused(pattern: str) -> None:
    with pytest.raises(ValidationError):
        family(pattern=pattern)


def test_the_alerts_role_is_not_a_log_family_and_a_field_role_must_belong_to_the_role() -> None:
    with pytest.raises(ValidationError, match=r"site\.alerts_index"):
        family(role="alerts")
    with pytest.raises(ValidationError, match="no field role"):
        family(fields={"query_name": "dns.question.name"})
    with pytest.raises(ValidationError):
        family(role="firewall")
    with pytest.raises(ValidationError):
        family(fields={"domain": "a b"})
    with pytest.raises(ValidationError):
        family(colour="red")  # unknown keys are errors


def test_a_family_has_ecs_fields_unless_the_site_names_others() -> None:
    f = family(fields={"domain": "url.domain.keyword"}).resolved()
    assert f("domain") == "url.domain.keyword"
    assert f.source("domain") == "url.domain"  # a document holds the field, not its sub-field
    assert f("url_path") == "url.path"
    assert f.time == "@timestamp"
    assert family(time_field="event.created").resolved().time == "event.created"
    with pytest.raises(SiteError, match="no field role"):
        f("query_name")


@pytest.mark.parametrize("role", [r for r in FIELD_ROLES if r is not Role.ALERTS])
def test_every_default_field_name_is_a_valid_field_name(role: Role) -> None:
    named = LogFamily(role=role, pattern="x-logs-*", fields=dict(FIELD_ROLES[role]))
    assert named.field_names() == FIELD_ROLES[role]


def test_the_index_names_a_family_owns() -> None:
    daily, stream = family(pattern="web-logs-*"), family(pattern="logs-nginx.access-default")
    assert daily.owns_index("web-logs-2026.10.30")
    assert not daily.owns_index("other-2026.10.30")
    assert stream.owns_index("logs-nginx.access-default")
    assert stream.owns_index(".ds-logs-nginx.access-default-2026.10.30-000001")
    assert not stream.owns_index("logs-nginx.access-other")
    assert daily.probe_name("2026.10.30") == "web-logs-2026.10.30"
    assert stream.probe_name("2026.10.30") == "logs-nginx.access-default"


# ---------------------------------------------------- which family a rule reads


@pytest.mark.parametrize(
    ("entry", "reads"),
    [
        ("acme-logs-squid-*", True),
        ("acme-logs-squid*", True),  # spells the name as a word
        ("acme-logs-squid-2026.10.09", True),
        ("logs-squid.access-default", True),
        ("a-logs-squid-x", True),
        ("acme-logs-nginx-*", False),
        ("acme-logs-*", False),  # broader than a family: it names none
        ("*", False),
        ("squidward-*", False),
        ("", False),
    ],
)
def test_a_rule_reads_the_proxy_family_by_its_indices(entry: str, reads: bool) -> None:
    assert site.reads([entry], Role.PROXY) is reads  # the active (ACME) site, squid


def test_the_family_selection_is_by_role_not_by_the_word_squid() -> None:
    other = SiteSettings(
        families=(
            family(role="proxy", pattern="logs-zscaler.nss-default"),
            family(role="web", pattern="logs-nginx.access-*"),
        )
    )
    with site.using(other):
        assert site.reads(["logs-zscaler.nss-default"], Role.PROXY)
        assert site.reads(["logs-nginx.access-*", "x"], Role.WEB)
        assert site.reads([".ds-logs-zscaler.nss-default-2026.10.30-000001"], Role.PROXY)
        assert not site.reads(["logs-nginx.access-*"], Role.PROXY)
        assert not site.reads(["logs-*"], Role.WEB)
        assert site.roles_read(["logs-zscaler.nss-default"], [Role.PROXY, Role.WEB]) == [Role.PROXY]
        assert site.source_for(Role.PROXY) == "proxy"
        assert site.source_of_index("logs-nginx.access-default") == "web"
        assert site.source_of_index(".ds-logs-zscaler.nss-default-2026.10.30-000001") == "proxy"
        assert site.source_of_index("elsewhere") is None


def test_acme_roles_keep_acmes_source_keys() -> None:
    assert [site.source_for(r) for r in (Role.PROXY, Role.WEB, Role.DNS, Role.MAIL, Role.AUTH)] == [
        "squid",
        "nginx",
        "dns",
        "postfix",
        "sso",
    ]
    assert site.active().watched_sources == ("squid", "dns", "nginx", "postfix")
    assert site.source_of_index("acme-logs-squid-2026.10.09") == "squid"
    assert site.source_of_index(".ds-acme-logs-nginx-2026.10.09") == "nginx"
    assert site.fields_of("nginx")("domain") == "url.domain.keyword"
    with pytest.raises(SiteError):
        site.fields_of("nope")


def test_names_family_is_case_insensitive_on_the_entry() -> None:
    assert names_family("ACME-LOGS-SQUID-*", example_site().family("squid"))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "patterns",
    [
        ["acme-logs-squid-*", "acme-logs-dns-*"],
        ["logs-nginx.access-default", "logs-system.auth-default", "logs-bind.log-default"],
        ["logs-nginx.access-default", "acme-logs-squid-*"],  # mixed (F5)
        ["alpha-*", "beta-*"],
        ["logs-nginx.access-*"],
    ],
)
def test_the_privilege_check_asks_each_familys_own_pattern(patterns: list[str]) -> None:
    """Never one guessed wider pattern: a key scoped to exactly the families passes, and one
    family is never left unchecked because another shares a prefix with it (F5)."""
    s = SiteSettings(
        families=tuple(family(name=f"f{i}", pattern=p) for i, p in enumerate(patterns))
    )
    assert s.checked_log_patterns == tuple(patterns)


def test_a_site_may_name_the_wider_pattern_its_key_is_granted() -> None:
    s = SiteSettings(
        families=(family(name="a", pattern="x-logs-a-*"),),
        log_patterns=("x-logs-*", "x-more-*"),
        ti_sources=({"index": "my-ti", "schema": "ioc", "mode": "lookup"},),
    )
    assert s.checked_log_patterns == ("x-logs-*", "x-more-*")
    assert s.ti_indices == ("my-ti",)
    for bad in ("Upper", "-lead", "sp ace", ".hidden-*", "", "a" * 256):
        with pytest.raises(ValidationError):
            SiteSettings(log_patterns=(bad,))
    for bad in ("Upper", "-lead", "sp ace", ".hidden", "", "a" * 256):
        with pytest.raises(ValidationError):
            SiteSettings(ti_sources=({"index": bad, "schema": "ioc", "mode": "lookup"},))


# ----------------------------------------------------------- the rest of the section


def test_the_alerts_index_is_a_template_over_the_space() -> None:
    s = SiteSettings(space="soc_2", alerts_index=".alerts-security.alerts-{space}")
    assert s.alerts_index_name == ".alerts-security.alerts-soc_2"
    assert s.alerts_backing_prefix == ".internal.alerts-security.alerts-soc_2-"
    fixed = SiteSettings(alerts_index="alerts-custom")
    assert (fixed.alerts_index_name, fixed.alerts_backing_prefix) == (
        "alerts-custom",
        ".internal.alerts-custom-",
    )
    for bad in ("Alerts-{space}", "alerts-{other}", "alerts {space}", ""):
        with pytest.raises(ValidationError):
            SiteSettings(alerts_index=bad)


@pytest.mark.parametrize(
    "values",
    [
        {"space": "Upper"},
        {"space": "a b"},
        {"space": ""},
        {"timezone": "Mars/Base"},
        {"incident_id_prefix": "ir"},
        {"incident_id_prefix": ""},
        {"incident_id_prefix": "X" * 40},
        {"elastic_versions": "8.19"},
        {"kibana_versions": ">=8,<"},
        {"own_domains": ["Not A Domain"]},
        {"own_networks": ["10.0.0.0/33"]},
        {"own_network_noun": ""},
        {"typo": 1},
    ],
)
def test_bad_values_are_errors(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SiteSettings.model_validate(values)


def test_good_values_are_kept() -> None:
    s = SiteSettings.model_validate(
        {
            "space": "acme",
            "timezone": "Asia/Kolkata",
            "incident_id_prefix": "ACME-IR",
            "own_domains": ["example.org"],
            "own_networks": ["203.0.113.0/24", "2001:db8::/32"],
            "own_network_noun": "campus",
        }
    )
    assert (s.timezone, s.incident_id_prefix, s.own_network_noun) == (
        "Asia/Kolkata",
        "ACME-IR",
        "campus",
    )
    assert [str(n) for n in s.own_networks] == ["203.0.113.0/24", "2001:db8::/32"]


# --------------------------------------------------------------------------- versions


@pytest.mark.parametrize(
    ("text", "version", "allowed"),
    [
        (">=8.0,<10", "8.19.12", True),
        (">=8.0,<10", "9.0.0-SNAPSHOT", True),
        (">=8.0,<10", "7.17.0", False),
        (">=8.0,<10", "10.0.0", False),
        (">=8.0,<10", "banana", False),
        ("==8.19.12", "8.19.12", True),
        ("==8.19.12", "8.19.13", False),
        (">=8.19,<8.20", "8.19.0", True),
        (">=8.19,<8.20", "8.20.0", False),
        ("!=8.5.0,>8", "8.5.0", False),
        ("*", "1.0.0", True),
        ("*", "x", False),
        # the whole text is the version, number by number (F12)
        ("==8.19.12", "8.19.12.1", False),
        ("==8.19.12", "8.19.12abc", False),
        ("==8.19.12", "8.19.012", False),
        ("==8.19.12", "\u0668.19.12", False),  # an Arabic-Indic digit is no digit here
        ("==8.19.12", "8.19.12+build5", True),  # build metadata is not a pre-release
        ("==8.19", "8.19.0", True),
        ("==8.19", "8.19.1", False),
        # a pre-release compares as its numbers and never sits on a bound
        ("==8.19.12", "8.19.12-SNAPSHOT", False),
        ("!=8.19.12", "8.19.12-SNAPSHOT", True),
        (">=8.19,<8.20", "8.19.12-SNAPSHOT", True),
        (">=8.19,<8.20", "8.19.0-rc1", False),
        (">=9.0.0", "9.0.0-rc1", False),
        ("<9.0.0", "9.0.0-rc1", False),
        ("<10", "10.0.0-rc1", False),
        ("<=10", "10.0.0-rc1", False),
        (">8", "8.0.1-rc1", True),
        (">=8.19,<8.20", "9.0.0", False),
        (">=9", ">=9", False),
        (">=8", "\n9.1.2\n", True),
    ],
)
def test_a_version_range(text: str, version: str, allowed: bool) -> None:
    assert VersionRange.parse(text).allows(version) is allowed


@pytest.mark.parametrize(
    "text",
    ["", "8", ">=", ">=a.b", ">= 8 <9", "~=8.0", ">=8.0;<9", ">=08", ">=8.19.012", ">=8.1.2.3",
     ">=\u0668", ">=8-SNAPSHOT", ">=8,,<10"],
)  # fmt: skip
def test_a_bad_version_range_is_refused(text: str) -> None:
    with pytest.raises(ValueError, match="comparators"):
        VersionRange.parse(text)


def test_a_range_describes_itself_for_a_message() -> None:
    assert VersionRange.parse("==8.19.12").describe() == "the pinned 8.19.12"
    assert VersionRange.parse(">=8.0,<10").describe() == "in the range >=8.0,<10"


version = st.tuples(st.integers(0, 12), st.integers(0, 30), st.integers(0, 30))


@given(version, version)
def test_the_comparators_agree_with_tuple_order(
    a: tuple[int, int, int], b: tuple[int, int, int]
) -> None:
    text = ".".join(map(str, b))
    for op, holds in (
        (">=", a >= b),
        (">", a > b),
        ("<=", a <= b),
        ("<", a < b),
        ("==", a == b),
        ("!=", a != b),
    ):
        assert VersionRange.parse(f"{op}{text}").allows(".".join(map(str, a))) is holds


@given(version, version, version)
def test_a_wider_range_allows_what_a_narrower_one_does(
    v: tuple[int, int, int], low: tuple[int, int, int], high: tuple[int, int, int]
) -> None:
    narrow = VersionRange.parse(f">={'.'.join(map(str, low))},<{'.'.join(map(str, high))}")
    wide = VersionRange.parse(f">={'.'.join(map(str, low))}")
    if narrow.allows(".".join(map(str, v))):
        assert wide.allows(".".join(map(str, v)))


@given(version, version)
def test_a_pre_release_is_never_equal_to_the_release_and_is_inside_only_strictly(
    a: tuple[int, int, int], b: tuple[int, int, int]
) -> None:
    pre = ".".join(map(str, a)) + "-rc1"
    text = ".".join(map(str, b))
    assert not VersionRange.parse(f"=={text}").allows(pre)
    assert VersionRange.parse(f"!={text}").allows(pre)
    assert VersionRange.parse(f">={text}").allows(pre) is (a > b)
    assert VersionRange.parse(f"<={text}").allows(pre) is (a < b)
    assert VersionRange.parse(f">{text}").allows(pre) is (a > b)
    assert VersionRange.parse(f"<{text}").allows(pre) is (a < b)


def test_parse_version() -> None:
    assert parse_version("8.19.12") == (8, 19, 12)
    assert parse_version("9") == (9, 0, 0)
    assert parse_version("8.19.12-SNAPSHOT") == (8, 19, 12)
    assert parse_version("8.19.12+b1") == (8, 19, 12)
    assert parse_version("v8") is None
    for bad in ("8.19.12.1", "8.19.12abc", "8.19.012", "\u0668.19.12", "", "8.", "-1.0.0"):
        assert parse_version(bad) is None, bad


# --------------------------------------------------------------------------- licence


@pytest.mark.parametrize(
    ("level", "status", "writes", "paid"),
    [
        ("basic", "active", True, False),
        ("gold", "active", True, False),
        ("platinum", "active", True, True),
        ("enterprise", "active", True, True),
        ("trial", "active", True, True),
        ("platinum", "expired", False, False),
        ("trial", "expired", False, False),
        ("basic", "invalid", False, False),
    ],
)
def test_licence_facts(level: str, status: str, writes: bool, paid: bool) -> None:
    facts = LicenceFacts(level, status)
    assert facts.writes_allowed is writes
    assert (facts.sub_feature_privileges, facts.case_assignment) == (paid, paid)


# --------------------------------------------------------------------------- Kibana's feature ids


@pytest.mark.parametrize(
    ("ids", "security", "cases"),
    [
        (["siemV2", "securitySolutionCasesV3", "discover"], "siemV2", "securitySolutionCasesV3"),
        (["siem", "siemV2", "siemV3", "securitySolutionCases"], "siemV3", "securitySolutionCases"),
        (["discover", "dashboard"], "siemV2", "securitySolutionCasesV3"),  # the defaults
        (["siemV10", "siemV9"], "siemV10", "securitySolutionCasesV3"),
        (["siemX", "securitySolutionCasesV2x"], "siemV2", "securitySolutionCasesV3"),
    ],
)
def test_feature_ids_come_from_kibanas_list(ids: list[str], security: str, cases: str) -> None:
    found = feature_ids([{"id": i, "name": i} for i in ids])
    assert (found.security, found.cases) == (security, cases)


@pytest.mark.parametrize(
    "answer", [None, "x", {"id": "siemV3"}, [1, 2], [{"name": "x"}], [{"id": 3}]]
)
def test_feature_ids_ignore_what_is_not_a_features_list(answer: Any) -> None:
    assert feature_ids(answer) == KibanaFeatures()


# --------------------------------------------------------------------------- ACME's own section


def test_acmes_section_is_what_the_code_used_to_hardcode() -> None:
    s = example_site()
    assert s.space == "acme-soc"
    assert s.alerts_index_name == ".alerts-security.alerts-acme-soc"
    assert s.alerts_backing_prefix == ".internal.alerts-security.alerts-acme-soc-"
    assert [(f.name, f.role.value, f.pattern, f.watch) for f in s.families] == [
        ("squid", "proxy", "acme-logs-squid-*", True),
        ("dns", "dns", "acme-logs-dns-*", True),
        ("nginx", "web", "acme-logs-nginx-*", True),
        ("postfix", "mail", "acme-logs-postfix-*", True),
        ("sso", "auth", "acme-logs-sso-*", False),
    ]
    assert s.checked_log_patterns == ("acme-logs-*",)  # ACME's key is granted this one
    assert s.ti_indices == ("abuse-ioc", "acme-threat-intel")
    assert [(t.index, t.schema_, t.mode) for t in s.ti_sources] == [
        ("abuse-ioc", "ecs", "mirror"),
        ("acme-threat-intel", "ioc", "lookup"),
    ]  # the stored source ids are the index names, as before
    assert s.ti_default_lookup is not None
    assert s.ti_default_lookup.index == "acme-threat-intel"
    assert s.kibana_range.allows("8.19.12")
    assert not s.kibana_range.allows("8.19.13")
    assert s.elastic_range.allows("8.19.3")
    assert not s.elastic_range.allows("8.20.0")
    squid = s.family("squid")
    assert squid is not None
    assert squid.resolved()("url") == "url.original.keyword"
    assert squid.resolved().source("url") == "url.original"
    assert squid.resolved()("server_ip") == "destination.ip"


def test_the_shipped_config_loads_and_activates_its_site(tmp_path: Path) -> None:
    from argus.config.settings import load_settings

    settings = load_settings(shipped_config_on_the_suites_site(tmp_path), env_file=None)
    assert settings.site == example_site()  # from the site.yaml beside it
    assert site.active() == example_site()  # load_settings made it the process's
    shipped = load_settings(REPO_ROOT / "config" / "argus.yaml", env_file=None)
    assert site.active() == shipped.site  # whatever this checkout's site.yaml holds


def test_a_missing_site_section_is_the_neutral_one(tmp_path: Path) -> None:
    from argus.config.settings import Settings, load_settings

    (tmp_path / "argus.yaml").write_text("environment: dev\n", encoding="utf-8")
    settings = load_settings(tmp_path / "argus.yaml", env_file=None)
    assert settings.site == SiteSettings() == Settings().site
    assert site.active() == SiteSettings()  # activated: ACME's is gone from this process


SECTION = """\
site:
  space: soc
  families:
    - role: web
      pattern: logs-nginx.access-default
      fields: {domain: url.domain}
"""


def _config(tmp_path: Path, text: str, name: str = "argus.yaml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_the_site_section_loads_from_yaml_and_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from argus.config.settings import load_settings

    path = _config(tmp_path, SECTION)
    settings = load_settings(path, env_file=None)
    assert settings.site.space == "soc"
    assert settings.site.families[0].pattern == "logs-nginx.access-default"
    assert settings.site.families[0].daily is False
    monkeypatch.setenv("ARGUS_SITE__SPACE", "other")
    assert load_settings(path, env_file=None).site.space == "other"


def test_the_families_come_from_a_file_or_from_the_whole_section_in_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An installer sets the families in site.yaml, or the whole section as one JSON value
    (``ARGUS_SITE='{...}'``); a list of models in a variable of its own is not a setting form
    (F19), and the error says which setting."""
    import json

    from argus.config import ConfigError
    from argus.config.settings import load_settings

    path = _config(tmp_path, "environment: dev\n")
    section = {"space": "soc", "families": [{"role": "proxy", "pattern": "x-squid-*"}]}
    monkeypatch.setenv("ARGUS_SITE", json.dumps(section))
    loaded = load_settings(path, env_file=None).site
    assert (loaded.space, [f.name for f in loaded.families]) == ("soc", ["proxy"])
    monkeypatch.delenv("ARGUS_SITE")
    monkeypatch.setenv("ARGUS_SITE__FAMILIES", json.dumps(section["families"]))
    with pytest.raises(ConfigError, match=r"site\.families"):
        load_settings(path, env_file=None)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("a", True),
        ("a" + "b" * 31, True),  # 32 characters
        ("a" + "b" * 32, False),
        ("a_1", True),
        ("1a", False),
        ("A", False),
        ("a-b", False),
        ("a b", False),
        ("", True),  # defaults to the role
    ],
)
def test_a_family_name_is_a_source_key_of_at_most_32_characters(name: str, valid: bool) -> None:
    if valid:
        assert LogFamily(role=Role.PROXY, pattern="x-*", name=name).name == (name or "proxy")
    else:
        with pytest.raises(ValidationError):
            LogFamily(role=Role.PROXY, pattern="x-*", name=name)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("site:\n  spase: x\n", "unknown setting"),
        ("site:\n  families:\n    - role: web\n      patern: x-*\n", "patern"),
        ("site:\n  families:\n    - role: web\n      pattern: Bad-*\n", "pattern"),
        ("site:\n  timezone: Mars/Base\n", "time zone"),
        ("site: 3\n", "must be a section"),
    ],
)
def test_a_bad_site_section_is_an_error_naming_it(tmp_path: Path, text: str, message: str) -> None:
    from argus.config import ConfigError
    from argus.config.settings import load_settings

    with pytest.raises(ConfigError, match=message):
        load_settings(_config(tmp_path, text), env_file=None)


def test_site_yaml_beside_the_config_is_read_below_it(tmp_path: Path) -> None:
    from argus.config.settings import load_settings

    config = _config(tmp_path, "site:\n  space: from_config\n")
    _config(tmp_path, SECTION, "site.yaml")
    settings = load_settings(config, env_file=None)
    assert settings.site.space == "from_config"  # the config file wins
    assert [f.role.value for f in settings.site.families] == ["web"]  # site.yaml fills the rest


def test_site_yaml_holds_the_site_section_only(tmp_path: Path) -> None:
    from argus.config import ConfigError
    from argus.config.settings import load_settings

    config = _config(tmp_path, "environment: dev\n")
    _config(tmp_path, "history:\n  window: 3d\nsite:\n  space: x\n", "site.yaml")
    with pytest.raises(ConfigError, match=r"site\.yaml holds the 'site' section only"):
        load_settings(config, env_file=None)


def test_the_shipped_defaults_for_a_rule_that_names_no_family() -> None:
    with site.using(SiteSettings()):
        for role in (Role.PROXY, Role.WEB, Role.DNS):
            assert not site.reads(["acme-logs-squid-*"], role)


def test_a_custom_alerts_index_reaches_every_place_that_names_it() -> None:
    from argus.gateway.gateway import Targets
    from argus.gateway.kibana.gateway import KibanaTargets
    from argus.identity import capmap
    from argus.incident.discover import Config

    custom = SiteSettings(space="soc", alerts_index="siem-alerts-{space}")
    assert custom.alerts_index_of("other") == "siem-alerts-other"
    assert custom.alerts_backing_of("other") == ".internal.siem-alerts-other-"
    with site.using(custom):
        assert Targets().alerts == "siem-alerts-soc"
        assert Targets().alerts_backing == ".internal.siem-alerts-soc-"
        assert KibanaTargets().alerts_index_prefix == ".internal.siem-alerts-soc-"
        assert capmap.Targets().alerts == ("siem-alerts-soc", ".internal.siem-alerts-soc-*")
        assert Config(space="other").alerts_index == "siem-alerts-other"
    # ACME's, as before
    assert capmap.Targets().alerts == (
        ".alerts-security.alerts-acme-soc",
        ".internal.alerts-security.alerts-acme-soc-*",
    )


@pytest.mark.parametrize(
    ("entry", "reads"),
    [
        ("logs-nginx.access-*", True),  # the pattern of Elastic's own rules
        ("logs-nginx.access-default", True),
        (".ds-logs-nginx.access-default-2026.10.30-000001", True),
        ("logs-nginx.access-default-2026.10.30-000001", True),
        ("logs-nginx.access-*,logs-system.auth-*", True),
        ("logs-nginx.access-prod", False),  # another namespace: another stream
        ("logs-nginx.*", False),  # every nginx dataset: wider than this one
        ("logs-*", False),
        ("*", False),
        ("filebeat-*", False),
        ("-logs-nginx.access-*", False),
    ],
)
def test_a_rule_reads_a_data_stream_family_when_it_names_its_dataset(
    entry: str, reads: bool
) -> None:
    with site.using(SiteSettings(families=(family(pattern="logs-nginx.access-default"),))):
        assert site.reads([entry], Role.WEB) is reads


@pytest.mark.parametrize(
    ("entry", "reads"),
    [
        ("agent-weblogs-*", True),
        ("agent-weblogs-2026.10.30", True),
        ("agent-*", False),
        ("agent-weblogs-*,other-*", True),
        ("other-weblogs-*", False),
    ],
)
def test_a_rule_reads_a_daily_family_when_it_names_its_prefix(entry: str, reads: bool) -> None:
    with site.using(SiteSettings(families=(family(name="web2", pattern="agent-weblogs-*"),))):
        assert site.reads([entry], Role.WEB) is reads
