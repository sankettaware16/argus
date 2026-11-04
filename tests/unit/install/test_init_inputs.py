"""What a person pastes into ``argus init`` and what a copied checkout brings: a key's expiry as
Elasticsearch writes it, the ``api_key`` field pasted instead of ``encoded``, a wrong answer asked
again instead of ending init, local.yaml edited in place, a checkout moved from another machine,
the web's credentials folder, and Kibana's answer to a key it did not accept."""

from __future__ import annotations

import base64
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from argus.install import files
from argus.install.answers import TerminalAnswers
from argus.install.run import clean_key, expiry_date, key_problem
from argus.install.siem import _kibana_answer
from tests.unit.install.test_run import KIBANA_KEY, SIEM_KEY, Run

pytestmark = pytest.mark.unit

TODAY = date(2026, 11, 4)


# --------------------------------------------------------------------------- expiry


def test_expiry_takes_what_the_answer_says() -> None:
    assert expiry_date("1801550534086", TODAY) == date(2027, 2, 2)  # "expiration", ms
    assert expiry_date("1801550534", TODAY) == date(2027, 2, 2)  # seconds
    assert expiry_date("1801550534086,", TODAY) == date(2027, 2, 2)  # copied with its comma
    assert expiry_date("90d", TODAY) == date(2027, 2, 2)
    assert expiry_date("90 days", TODAY) == date(2027, 2, 2)
    assert expiry_date("2027-02-02", TODAY) == date(2027, 2, 2)


@pytest.mark.parametrize("bad", ["tomorrow", "2027-13-01", "90x", "12"])
def test_expiry_refuses_what_is_not_a_date(bad: str) -> None:
    with pytest.raises(ValueError):  # noqa: PT011 - date.fromisoformat's own message
        expiry_date(bad, TODAY)


@given(st.datetimes(min_value=datetime(2001, 1, 1), max_value=datetime(2200, 1, 1)))  # noqa: DTZ001
def test_expiration_in_milliseconds_is_its_utc_day(moment: datetime) -> None:
    moment = moment.replace(tzinfo=UTC)
    millis = str(int(moment.timestamp() * 1000))
    assert expiry_date(millis, TODAY) == moment.date()


# --------------------------------------------------------------------------- keys


def _encoded(id_: str, secret: str) -> str:
    return base64.b64encode(f"{id_}:{secret}".encode()).decode()


def test_the_api_key_field_is_named_for_what_it_is() -> None:
    problem = key_problem("Q7mZp2Lk9_wXrT4vNb8sYe")  # 22 characters: "api_key", not "encoded"
    assert problem is not None
    assert '"encoded"' in problem
    assert key_problem("aB3dEf6Gh9JkLmNoPq2R") is not None  # the "id"
    assert key_problem(_encoded("aB3dEf6Gh9JkLmNoPq2R", "Q7mZp2Lk9_wXrT4vNb8sYe")) is None
    assert key_problem("short") is not None
    assert key_problem("has a space in it, so not a key") is not None


def test_a_line_copied_from_the_console_is_cleaned() -> None:
    key = _encoded("abc", "def-ghi")
    for pasted in (key, f'"{key}"', f'"{key}",', f'  "encoded": "{key}",  ', f"'{key}'"):
        assert clean_key(pasted) == key


@given(st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
               min_size=1, max_size=40),
       st.text(alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
               min_size=8, max_size=60))  # fmt: skip
def test_every_encoded_key_is_taken(id_: str, secret: str) -> None:
    assert key_problem(clean_key(f'"{_encoded(id_, secret)}",')) is None


def _terminal(replies: dict[str, list[str]], asked: list[str]) -> TerminalAnswers:
    def prompt(question: str, **kw: Any) -> str:
        asked.append(question)
        for part, answers in replies.items():
            if part in question and answers:
                return answers.pop(0)
        if "(none to skip)" in question:
            return "none"
        raise AssertionError(f"not expected: {question}")

    return TerminalAnswers(prompt=prompt, confirm=lambda q, default: True if "Trust" in q
                           else default)  # fmt: skip


BASE_REPLIES: dict[str, list[str]] = {
    "Elasticsearch address": ["https://es.example.org:9200"],
    "trust https://es.example.org:9200": ["chain"],
    "index patterns": ["corp-logs-*"],
    "organisation's name": ["Example Corp"],
    "security team's name": ["Example SOC"],
    "kind of organisation": ["company"],
    "own domains": ["example.org"],
    "public networks": ["192.0.2.0/24"],
    "time zone": ["UTC"],
    "prefix of incident": ["SOC-IR"],
    "Kibana space": ["soc"],
}


def test_a_wrong_key_and_a_wrong_date_are_asked_again_at_the_terminal(tmp_path: Path) -> None:
    run = Run(tmp_path)
    replies = {
        **{k: list(v) for k, v in BASE_REPLIES.items()},
        "Kibana's address": ["https://es.example.org:5601"],
        "trust https://es.example.org:5601": ["same"],
        "Paste the SIEM key": ["Q7mZp2Lk9_wXrT4vNb8sYe", SIEM_KEY],
        "SIEM key expire": ["next year", "1801550534086"],
        "Paste Kibana's key": [f'"encoded": "{KIBANA_KEY}",'],
        "Kibana's key expire": ["90d"],
    }
    asked: list[str] = []
    assert run.go(_terminal(replies, asked)) == 0, run.text
    assert run.text.count("not taken:") == 2
    assert 'paste the value of "encoded"' in run.text
    local = run.local()
    assert local["siem"]["api_key_expires"] == date(2027, 2, 2)
    assert isinstance(local["kibana"]["reader_api_key_expires"], date)
    env = (run.root / ".env").read_text()
    assert f"ARGUS_KIBANA__READER_API_KEY={KIBANA_KEY}\n" in env
    assert "Q7mZp2Lk9_wXrT4vNb8sYe" not in env


def test_an_answers_file_with_the_api_key_field_stops_with_why(tmp_path: Path) -> None:
    run = Run(tmp_path)
    path = tmp_path / "wrong.key"
    path.write_text("Q7mZp2Lk9_wXrT4vNb8sYe")
    path.chmod(0o600)
    assert run.go(run.answers(**{"siem.api_key_file": str(path)})) == 2
    assert '"encoded"' in run.text
    assert "Traceback" not in run.text


def test_an_answers_file_takes_the_expiration_number(tmp_path: Path) -> None:
    run = Run(tmp_path)
    assert run.go(run.answers(**{"siem.api_key_expires": 1801550534086})) == 0, run.text
    assert run.local()["siem"]["api_key_expires"] == date(2027, 2, 2)


def test_kibana_answering_as_to_a_stranger_says_the_key_was_not_taken() -> None:
    said = _kibana_answer("Kibana's answer: a status without version or level")
    assert "did not accept the key" in said
    assert '"encoded"' in said


def test_a_kibana_key_kibana_refuses_stops_init_with_words_not_a_traceback(
    tmp_path: Path,
) -> None:
    run = Run(tmp_path)
    run.siem.kibana_problems = [_kibana_answer("a status without version or level")]
    assert run.go(run.answers()) == 1
    assert "did not accept the key" in run.text


# --------------------------------------------------------------------------- local.yaml


LOCAL = """\
# This installation's own values.
siem:
  url: https://es.example.org:9200  # the SIEM
  # when the key ends
  api_key_expires: 2027-01-10

web:
  allowed_hosts: [10.0.0.5, old-host]
  tls_pin_sha256: 4e4853aa6015dcb5e1f0c1ac609b0a4116223a4d00b35ac1ff64bff1619423fd

units:
  root: /home/someone/argus
  run:
    - argus-collector.service
    - argus-worker.service
  web:
    # HTTPS for the team
    host: 0.0.0.0
    tls_cert: data/tls/argus.crt
    tls_key: data/tls/argus.key
    allowed_networks: [10.0.0.0/8]
    allowed_hosts:
      - 10.0.0.5
      - old-host
    public_url: https://10.0.0.5:8765
    approval_key_file: /home/someone/argus/local/approval-signing.key
"""


def test_a_value_is_edited_in_place_and_every_comment_stays(tmp_path: Path) -> None:
    path = tmp_path / "local.yaml"
    path.write_text(LOCAL)
    changed = files.update_yaml(
        path,
        {
            "units.web.allowed_hosts": ["10.0.0.9", "new-host"],
            "units.web.public_url": "https://10.0.0.9:8765",
            "siem.ca_file": "data/certs/siem-ca.crt",
            "kibana.reader_api_key_expires": date(2027, 2, 2),
            "units.run": ["argus-collector.service"],
        },
    )
    assert len(changed) == 5
    text = path.read_text()
    for line in LOCAL.splitlines():
        if line.lstrip().startswith("#"):
            assert line in text
    assert "url: https://es.example.org:9200  # the SIEM" in text
    assert "    allowed_hosts: [10.0.0.9, new-host]\n" in text
    assert "  allowed_hosts: [10.0.0.5, old-host]\n" in text  # web.allowed_hosts untouched
    data = yaml.safe_load(text)
    assert data["units"]["web"]["public_url"] == "https://10.0.0.9:8765"
    assert data["units"]["run"] == ["argus-collector.service"]
    assert data["siem"]["ca_file"] == "data/certs/siem-ca.crt"
    assert data["kibana"] == {"reader_api_key_expires": date(2027, 2, 2)}
    assert data["units"]["root"] == "/home/someone/argus"


_KEY = st.sampled_from(["siem.url", "siem.ca_file", "web.tls_pin_sha256", "units.web.host",
                        "units.web.allowed_hosts", "units.run", "units.uv", "kibana.url",
                        "kibana.enabled", "new.nested.key", "units.web.public_url"])  # fmt: skip
_VALUE = st.one_of(
    st.booleans(),
    st.integers(-5, 10**6),
    st.text(alphabet="abcdefghij-./:0123456789 #'\"", max_size=20),
    st.lists(st.text(alphabet="abcdefghij-.0123456789", min_size=1, max_size=8), max_size=3),
)


@given(st.dictionaries(_KEY, _VALUE, min_size=1, max_size=5))
def test_any_edit_gives_exactly_the_values_asked(changes: dict[str, Any]) -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "local.yaml"
        path.write_text(LOCAL)
        expected = yaml.safe_load(LOCAL)
        for name, value in changes.items():
            files.put(expected, name, value)
        files.update_yaml(path, changes)
        assert yaml.safe_load(path.read_text()) == expected
        assert path.read_text().startswith("# This installation's own values.")


# --------------------------------------------------------------------------- moved, credentials


def test_a_checkout_from_another_machine_names_this_one(tmp_path: Path) -> None:
    run = Run(tmp_path)
    (run.root / "config" / "local.yaml").write_text(LOCAL)
    assert run.go(run.answers()) == 0, run.text
    local = run.local()
    assert local["units"]["root"] == str(run.root)
    assert local["units"]["web"]["approval_key_file"] == f"{run.root}/local/approval-signing.key"
    assert "moved: config/local.yaml named /home/someone/argus" in run.text
    assert "# HTTPS for the team" in (run.root / "config" / "local.yaml").read_text()


def test_bootstrap_sees_the_web_units_credentials(tmp_path: Path) -> None:
    run = Run(tmp_path)
    folder = run.root / "local" / "creds-web"
    folder.mkdir(parents=True)
    (folder / "database.api_password").write_text("a-password-for-the-web\n")
    (run.root / "config" / "local.yaml").write_text(
        yaml.safe_dump({"units": {"web": {"credentials": str(folder)}}})
    )
    # a copied .env holds the database's passwords but not the web's: that is in the folder
    (run.root / ".env").write_text("ARGUS_DATABASE__PASSWORD=copied-from-before\n")
    seen: list[str | None] = []
    host = run.host()
    host.bootstrap = lambda _c: seen.append(os.environ.get("CREDENTIALS_DIRECTORY"))
    before = os.environ.get("CREDENTIALS_DIRECTORY")
    from argus.install.run import run_init

    assert run_init(run.options(), run.answers(), host) == 0, run.text
    assert seen == [str(folder)]
    assert os.environ.get("CREDENTIALS_DIRECTORY") == before
    assert "the web's own login: its password from" in run.text
    assert "a-password-for-the-web" not in run.text


def test_the_llm_keys_file_inside_the_checkout_is_written_relative(tmp_path: Path) -> None:
    run = Run(tmp_path)
    keys = run.root / "reference" / "llm.env"
    keys.parent.mkdir()
    keys.write_text("GROQ_API_KEY=x\n")
    keys.chmod(0o600)
    assert run.go(run.answers(**{"llm.keys_file": str(keys)})) == 0, run.text
    overlay = yaml.safe_load((run.root / "config" / "llm.local.yaml").read_text())
    assert overlay["keys_file"] == "reference/llm.env"
