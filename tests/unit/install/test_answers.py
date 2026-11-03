"""P4-D2: where init's answers come from. An answers file answers every question and never
prompts; a missing answer stops init with its name; a key is never in the file."""

from __future__ import annotations

from pathlib import Path

import pytest

from argus.install.answers import (
    KNOWN,
    InitError,
    MissingAnswerError,
    ScriptedAnswers,
    TerminalAnswers,
    load_answers,
)

pytestmark = pytest.mark.unit


def _file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "answers.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def test_answers_are_read_by_dotted_name(tmp_path: Path) -> None:
    path = _file(tmp_path, "siem:\n  url: https://es.example.org:9200\nunits: {start: true}\n")
    assert load_answers(path) == {"siem.url": "https://es.example.org:9200", "units.start": True}
    assert load_answers(_file(tmp_path, "")) == {}


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("siem:\n  urll: x\n", "unknown answers siem.urll"),
        ("siem:\n  api_key: abc\n", "a key never goes in the answers file"),
        ("kibana: {api_key: abc}\n", "a key never goes in the answers file"),
        ("- a\n- b\n", "is not a YAML mapping"),
        ("siem: [unclosed\n", "cannot read the answers file"),
    ],
)
def test_a_bad_answers_file_stops_init(tmp_path: Path, text: str, message: str) -> None:
    with pytest.raises(InitError, match=message) as caught:
        load_answers(_file(tmp_path, text))
    assert caught.value.code == 2


def test_a_missing_answer_is_named_and_a_default_or_none_is_taken(tmp_path: Path) -> None:
    source = tmp_path / "answers.yaml"
    asker = ScriptedAnswers({"organisation.timezone": "", "kibana.url": "none"}, source)
    with pytest.raises(MissingAnswerError) as caught:
        asker.text("siem.url", "The SIEM's address")
    assert caught.value.code == 2
    assert str(caught.value) == f"{source} does not answer siem.url ({KNOWN['siem.url']})"
    assert asker.text("organisation.timezone", "zone", "UTC") == "UTC"
    assert asker.optional("kibana.url", "Kibana") is None
    assert asker.optional("organisation.timezone_label", "label", "CET") == "CET"
    assert asker.items("organisation.own_networks", "networks", ["x"]) == ["x"]
    assert not asker.given("siem.url")


def test_lists_take_a_list_or_a_comma_separated_string() -> None:
    asker = ScriptedAnswers(
        {"organisation.own_domains": "example.org, example.net", "siem.log_patterns": ["a-*"]},
        Path("a.yaml"),
    )
    assert asker.items("organisation.own_domains", "") == ["example.org", "example.net"]
    assert asker.items("siem.log_patterns", "") == ["a-*"]


def test_a_secret_comes_from_a_private_file_or_a_variable(tmp_path: Path) -> None:
    key = tmp_path / "key"
    key.write_text("c2VjcmV0LWtleS12YWx1ZQ==\n")
    key.chmod(0o600)
    asker = ScriptedAnswers({"siem.api_key_file": str(key)}, tmp_path / "a.yaml")
    assert asker.secret("siem.api_key", "key") == "c2VjcmV0LWtleS12YWx1ZQ=="
    key.chmod(0o644)
    with pytest.raises(InitError, match="readable by others"):
        asker.secret("siem.api_key", "key")
    env = ScriptedAnswers({"siem.api_key_env": "MY_KEY"}, tmp_path / "a.yaml", {"MY_KEY": "v"})
    assert env.secret("siem.api_key", "key") == "v"
    unset = ScriptedAnswers({"siem.api_key_env": "MY_KEY"}, tmp_path / "a.yaml", {})
    with pytest.raises(InitError, match="MY_KEY is not set"):
        unset.secret("siem.api_key", "key")
    nothing = ScriptedAnswers({}, tmp_path / "a.yaml")
    with pytest.raises(InitError, match=r"does not answer siem\.api_key_file or siem\.api_key_env"):
        nothing.secret("siem.api_key", "key")
    assert nothing.secret("kibana.api_key", "key", required=False) is None
    skipped = ScriptedAnswers({"kibana.api_key_file": "none"}, tmp_path / "a.yaml")
    assert skipped.secret("kibana.api_key", "key", required=False) is None
    empty = tmp_path / "empty"
    empty.write_text("\n")
    empty.chmod(0o600)
    with pytest.raises(InitError, match="is empty"):
        ScriptedAnswers({"siem.api_key_file": str(empty)}, tmp_path / "a").secret(
            "siem.api_key", ""
        )


def test_confirm_and_choose(tmp_path: Path) -> None:
    asker = ScriptedAnswers(
        {"units.start": "yes", "units.install": False, "siem.trust": "chain", "x": "maybe"},
        tmp_path / "a.yaml",
    )
    assert asker.confirm("units.start", "", False) is True
    assert asker.confirm("units.install", "", True) is False
    assert asker.confirm("discovery.accept", "", True) is True  # not given: the default
    with pytest.raises(InitError, match="true or false"):
        asker.confirm("x", "", True)
    assert asker.choose("siem.trust", "", ("file", "chain"), None) == "chain"
    with pytest.raises(InitError, match="is one of file, system"):
        asker.choose("siem.trust", "", ("file", "system"), None)


def test_the_terminal_asks_and_keeps_the_value_in_brackets() -> None:
    asked: list[tuple[str, dict[str, object]]] = []
    replies = iter(
        ["", "https://es:9200", "none", "a.org, b.org", "s3cret-key-value", "x", "chain"]
    )

    def prompt(question: str, **kw: object) -> str:
        asked.append((question, kw))
        return next(replies)

    terminal = TerminalAnswers(prompt=prompt, confirm=lambda q, default: default)
    assert terminal.text("siem.url", "address") == "https://es:9200"  # blank asked again
    assert terminal.optional("kibana.url", "Kibana") is None
    assert terminal.items("organisation.own_domains", "domains") == ["a.org", "b.org"]
    assert terminal.secret("siem.api_key", "key") == "s3cret-key-value"
    assert asked[4][1]["hide_input"] is True  # a key is never echoed
    assert terminal.choose("siem.trust", "how", ("file", "chain"), None) == "chain"
    assert terminal.confirm("units.start", "start?", False) is False
    assert not terminal.scripted


def test_the_command_refuses_a_bad_answers_file_before_any_step(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from argus.cli import app

    done = CliRunner().invoke(app, ["init", "--answers", str(tmp_path / "missing.yaml")])
    assert done.exit_code == 2
    assert "cannot read the answers file" in done.output
    assert not (tmp_path / ".env").exists()
