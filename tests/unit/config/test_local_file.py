"""config/local.yaml (D-294): this installation's own values, read beside the config file, above it
and below .env and the environment; any section, unknown names are errors; the fixture policy's
private overlay; doctor reads the YAML files beside the config for write keys."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from argus.config.errors import ConfigError
from argus.config.settings import LOCAL_FILE, load_settings
from argus.fixtures.policy import load_policy

pytestmark = pytest.mark.unit


def _write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.write_text(text, encoding="utf-8")
    return path


def test_local_yaml_is_read_beside_the_config_and_above_it(tmp_path: Path) -> None:
    assert LOCAL_FILE == "local.yaml"
    config = _write(
        tmp_path, "argus.yaml", "history:\n  window: 4d\nkibana:\n  url: https://a.test\n"
    )
    _write(
        tmp_path,
        "local.yaml",
        "siem:\n  url: https://es.example.test:9200\n  api_key_expires: 2027-01-10\n"
        "kibana:\n  url: https://kibana.example.test:5601\n",
    )
    settings = load_settings(config, env_file=None)
    assert settings.siem.url == "https://es.example.test:9200"
    assert settings.siem.api_key_expires == date(2027, 1, 10)
    assert settings.kibana.url == "https://kibana.example.test:5601"  # above argus.yaml
    assert settings.history.window.days == 4  # what local.yaml leaves alone stays


def test_the_environment_and_dotenv_are_above_local_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _write(tmp_path, "argus.yaml", "")
    _write(tmp_path, "local.yaml", "kibana:\n  url: https://local.test\nhistory:\n  window: 4d\n")
    dotenv = _write(tmp_path, "test.env", "ARGUS_HISTORY__WINDOW=6d\n")
    monkeypatch.setenv("ARGUS_KIBANA__URL", "https://environment.test")
    settings = load_settings(config, env_file=dotenv)
    assert settings.kibana.url == "https://environment.test"
    assert settings.history.window.days == 6


def test_local_yaml_may_hold_any_section_and_names_its_line(tmp_path: Path) -> None:
    config = _write(tmp_path, "argus.yaml", "site:\n  space: shipped\n")
    _write(tmp_path, "site.yaml", "site:\n  space: discovered\n  timezone: Asia/Kolkata\n")
    _write(tmp_path, "local.yaml", "site:\n  space: local\n")
    settings = load_settings(config, env_file=None)
    assert settings.site.space == "local"  # local.yaml > argus.yaml > site.yaml
    assert settings.site.timezone == "Asia/Kolkata"
    _write(tmp_path, "local.yaml", "kibana:\n  ulr: https://typo.test\n")
    with pytest.raises(ConfigError, match=r"kibana\.ulr: unknown setting.*local\.yaml line 2"):
        load_settings(config, env_file=None)


def test_no_local_yaml_is_no_layer(tmp_path: Path) -> None:
    config = _write(tmp_path, "argus.yaml", "")
    assert load_settings(config, env_file=None).kibana.url is None
    other = tmp_path / "other"
    other.mkdir()
    _write(other, "local.yaml", "kibana:\n  url: https://elsewhere.test\n")
    assert load_settings(config, env_file=None).kibana.url is None  # only the one beside it


def test_a_config_file_named_local_yaml_is_read_once(tmp_path: Path) -> None:
    config = _write(tmp_path, "local.yaml", "kibana:\n  url: https://only.test\n")
    assert load_settings(config, env_file=None).kibana.url == "https://only.test"


def test_the_fixture_policy_overlay_replaces_keys_and_is_hashed(tmp_path: Path) -> None:
    shipped = _write(tmp_path, "fixtures.yaml", "version: 1\ncampus_domains: []\nliterals: {}\n")
    overlay = tmp_path / "fixtures.local.yaml"
    alone, digest = load_policy(shipped, overlay)  # no overlay file: the shipped policy
    assert (alone.campus_domains, digest) == ((), load_policy(shipped)[1])
    _write(tmp_path, "fixtures.local.yaml", "campus_domains: [campus.example]\n")
    laid, both = load_policy(shipped, overlay)
    assert laid.campus_domains == ("campus.example",)
    assert both != digest
    _write(tmp_path, "fixtures.local.yaml", "- not a mapping\n")
    with pytest.raises(ValueError, match="must contain a mapping"):
        load_policy(shipped, overlay)


def test_doctor_reads_the_yaml_files_beside_the_config(tmp_path: Path) -> None:
    from argus.ops.checks import _yaml_files

    config = _write(tmp_path, "argus.yaml", "")
    assert _yaml_files(config) == [config]
    local = _write(tmp_path, "local.yaml", "")
    site_file = _write(tmp_path, "site.yaml", "")
    assert _yaml_files(config) == [config, local, site_file]
    assert _yaml_files(None) == []
