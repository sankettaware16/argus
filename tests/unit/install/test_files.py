"""P4-D2: the files init writes. .env keeps every value it has (never overwritten, never printed,
mode 0600); the YAML files change only the names asked, and only when they differ."""

from __future__ import annotations

import stat
from datetime import date
from pathlib import Path

import pytest
import yaml

from argus.install import files
from argus.install.answers import InitError

pytestmark = pytest.mark.unit


def test_env_gets_what_it_lacks_and_keeps_what_it_has(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("# mine\nARGUS_DATABASE__PASSWORD=kept-value\nOTHER=1")
    env.chmod(0o644)
    written = files.update_env(env, {"ARGUS_DATABASE__PASSWORD": "new", "ARGUS_X": "a b'c"})
    assert written == ["ARGUS_X"]
    text = env.read_text()
    assert text.startswith("# mine\nARGUS_DATABASE__PASSWORD=kept-value\nOTHER=1\n")
    assert files.read_env(env) == {
        "ARGUS_DATABASE__PASSWORD": "kept-value", "OTHER": "1", "ARGUS_X": "a b'c",
    }  # fmt: skip
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert files.update_env(env, {"ARGUS_X": "other"}) == []
    assert files.update_env(env, {"ARGUS_X": "other"}, replace=frozenset({"ARGUS_X"})) == [
        "ARGUS_X"
    ]
    assert files.read_env(env)["ARGUS_X"] == "other"
    assert text.count("ARGUS_X") == 1


def test_a_wide_env_file_is_narrowed_even_with_nothing_to_add(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("A=1\n")
    env.chmod(0o664)
    assert files.update_env(env, {"A": "2"}) == []
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert env.read_text() == "A=1\n"


def test_new_passwords_are_long_random_and_compose_safe() -> None:
    made = {files.new_password() for _ in range(50)}
    assert len(made) == 50
    for password in made:
        assert len(password) >= 40
        assert all(c.isalnum() or c in "-_" for c in password)


def test_a_value_on_two_lines_is_refused(tmp_path: Path) -> None:
    with pytest.raises(InitError, match="one line"):
        files.update_env(tmp_path / ".env", {"A": "x\ny"})


def test_a_link_is_never_written_through(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("A=1\n")
    (tmp_path / ".env").symlink_to(target)
    with pytest.raises(InitError, match="is a link"):
        files.update_env(tmp_path / ".env", {"B": "2"})
    assert target.read_text() == "A=1\n"


def test_yaml_changes_only_what_differs_and_keeps_the_leading_comments(tmp_path: Path) -> None:
    path = tmp_path / "local.yaml"
    assert files.update_yaml(path, {"siem.url": "https://a:9200", "units.run": []}) == [
        "siem.url", "units.run",
    ]  # fmt: skip
    assert path.read_text().startswith(files.LOCAL_HEADER)
    before = path.read_bytes()
    assert files.update_yaml(path, {"siem.url": "https://a:9200"}) == []
    assert path.read_bytes() == before  # nothing changed: not rewritten
    path.write_text("# my own words\n" + path.read_text().split("\n", 3)[-1])
    assert files.update_yaml(path, {"siem.api_key_expires": date(2027, 1, 2)}) == [
        "siem.api_key_expires"
    ]
    assert path.read_text().startswith("# my own words\n")
    assert yaml.safe_load(path.read_text()) == {
        "siem": {"url": "https://a:9200", "api_key_expires": date(2027, 1, 2)},
        "units": {"run": []},
    }
    assert files.update_yaml(path, {"llm": None}) == ["llm"]  # absent and None differ


def test_a_yaml_that_is_no_mapping_stops_init(tmp_path: Path) -> None:
    path = tmp_path / "local.yaml"
    path.write_text("- a\n")
    with pytest.raises(InitError, match="not a YAML mapping"):
        files.update_yaml(path, {"a": 1})
