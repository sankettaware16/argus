"""Regression (R1 verification round 2): a .env line whose "=" is missing or misplaced.

python-dotenv then puts the value into the variable NAME. Error messages may name only known
variables; an unknown name is reported by its line number. All secrets here are synthetic.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st
from typer.testing import CliRunner

from argus.cli import app
from argus.config import ConfigError, load_settings

SECRET = "Fake-Pw-77zq"


def _error(tmp_path: Path, env_text: str) -> str:
    config = tmp_path / "argus.yaml"
    config.write_text("")
    env = tmp_path / "secret.env"
    env.write_text(env_text)
    with pytest.raises(ConfigError) as info:
        load_settings(config, env_file=env)
    return str(info.value)


@pytest.mark.parametrize("separator", ["", "_", "-", ".", ",", "/", ":"])
def test_value_typed_without_equals_is_never_printed(tmp_path: Path, separator: str) -> None:
    message = _error(
        tmp_path, f"ARGUS_HISTORY__WINDOW=5d\nARGUS_DATABASE__PASSWORD{separator}{SECRET}\n"
    )
    assert SECRET.lower() not in message.lower()
    assert "line 2" in message


def test_value_typed_before_the_equals_is_never_printed(tmp_path: Path) -> None:
    message = _error(tmp_path, f"ARGUS_DATABASE__PASSWORD{SECRET}=\n")
    assert SECRET.lower() not in message.lower()
    assert "line 1" in message


def test_unknown_section_key_never_reaches_pydantic(tmp_path: Path) -> None:
    message = _error(tmp_path, f"ARGUS_DATABASE__PASSWORD_{SECRET}=x\n")
    assert SECRET.lower() not in message.lower()
    assert "not a known setting" in message


def test_known_name_without_value_is_still_named(tmp_path: Path) -> None:
    message = _error(tmp_path, "ARGUS_DATABASE__PASSWORD\n")
    assert "ARGUS_DATABASE__PASSWORD" in message
    assert "has no value" in message


def test_typo_still_gets_a_suggestion_without_echoing_the_name(tmp_path: Path) -> None:
    message = _error(tmp_path, "ARGUS_HISTORY_WINDOW=30d\n")
    assert "did you mean ARGUS_HISTORY__WINDOW" in message


_SECRET_CHARS = st.text(
    alphabet=st.characters(min_codepoint=33, max_codepoint=126, exclude_characters="=#'\"\\$`"),
    min_size=8,
    max_size=24,
)


@given(secret=_SECRET_CHARS, separator=st.sampled_from(["", "_", "-", ".", ",", "/", ":", "+"]))
def test_property_no_mistyped_line_leaks_its_value(secret: str, separator: str) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        config = path / "argus.yaml"
        config.write_text("")
        env = path / "secret.env"

        def said(value: str) -> str:
            env.write_text(f"ARGUS_DATABASE__PASSWORD{separator}{value}\n")
            try:
                load_settings(config, env_file=env)
            except ConfigError as exc:
                return str(exc).lower()
            return ""

        # a value that is already part of the wording (e.g. "environm") proves nothing either way
        assume(secret.lower() not in said("Q7vXk2Lw9Rz"))
        assert secret.lower() not in said(secret)


def test_cli_does_not_print_the_value(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "argus.yaml").write_text("")
    (tmp_path / ".env").write_text(f"ARGUS_DATABASE__PASSWORD-{SECRET}\n")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["config", "validate", "-c", str(tmp_path / "argus.yaml")])
    assert result.exit_code == 2
    assert SECRET.lower() not in (result.output + result.stderr).lower()
