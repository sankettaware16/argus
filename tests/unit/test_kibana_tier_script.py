"""scripts/kibana_tier.py and the compose profile without the tier (Q-D1).

The tier shares the compose project "argus" with production's database: every docker command
the script can run names only the tier's services or volumes, never ``down`` or
``--remove-orphans``; the compose file holds no required variable (one would break every
compose command, db's included); the tier binds 127.0.0.1 on ports of its own and caps its
memory under the day-1 budget (3.5 GB beside production). Its CA and certificates verify under
Python's strict client (CERT_REQUIRED, the host name 127.0.0.1); its secrets are private and
never re-made once they exist.
"""

from __future__ import annotations

import argparse
import ast
import os
import re
import signal
import socket
import ssl
import stat
import subprocess
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from tests.conftest import PUBLIC_TREE, REPO_ROOT
from tests.kibana.tier import seed, tier_script

COMPOSE = REPO_ROOT / "docker-compose.yml"
BUDGET_MIB = tier_script.BUDGET_MIB
ACTIONS = (
    "start-es",
    "start-kibana",
    "stop",
    "remove",
    "ps",
    "stats",
    "running",
    "hash",
    "labels",
    "ids",
    "process-check",
)


def compose() -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    return data


def mib(value: str) -> int:
    number, unit = re.fullmatch(r"(\d+)([mg])", value.lower()).groups()  # type: ignore[union-attr]
    return int(number) * (1024 if unit == "g" else 1)


# --------------------------------------------------------------------------- docker commands


@pytest.mark.parametrize("action", ACTIONS)
def test_every_command_names_only_the_tier(action: str) -> None:
    for command in tier_script.commands_for(action):
        tier_script.check_command(command)  # does not raise
        assert not set(command) & tier_script.PROTECTED
        assert "down" not in command
        if command[:2] == ["docker", "compose"]:
            assert command[2:8] == [
                "--project-name",
                "argus",
                "--file",
                str(tier_script.COMPOSE_FILE),
                "--profile",
                "kibana",
            ]
            named = [w for w in command[8:] if not w.startswith("-")][1:]  # after the verb
            if command[8] == "config":  # read only; its --hash takes a comma-separated list
                named = [n for w in named for n in w.split(",")]
            assert named, command  # never every service
            assert set(named) <= set(tier_script.SERVICES), command
        if command[:3] == ["docker", "volume", "rm"]:
            assert set(command[4:]) == set(tier_script.VOLUMES)


def test_the_start_never_recreates_a_running_tier() -> None:
    """Every worktree may run `up`: a running tier is left as it is."""
    for action in ("start-es", "start-kibana"):
        (command,) = tier_script.commands_for(action)
        assert "--no-recreate" in command


@pytest.mark.parametrize(
    "command",
    [
        ["docker", "compose", "down"],
        ["docker", "compose", "--profile", "kibana", "down", "kibana"],
        ["docker", "compose", "up", "-d", "--remove-orphans", "kibana"],
        ["docker", "compose", "stop", "db"],
        ["docker", "compose", "up", "-d", "es-local"],
        ["docker", "volume", "rm", "argus_argus-pgdata"],
        ["docker", "rm", "-f", "argus-db"],
        ["docker", "volume", "rm", "argus_argus-esdata"],
        # verbs that act on every service when none (or another) is named
        ["docker", "compose", "--project-name", "argus", "--profile", "kibana", "stop"],
        ["docker", "compose", "up", "--detach"],
        ["docker", "compose", "--file", "x.yml", "restart"],
        ["docker", "compose", "rm", "--force", "--stop"],
        ["docker", "compose", "up", "-d", "kibana", "other-service"],
        ["docker", "compose", "kill", "--signal", "KILL"],
        ["docker", "volume", "rm", "--force"],
        ["docker", "volume", "rm", "argus_argus-kibana-data", "some-other-volume"],
        # short or joined global options, and options the denylist did not know
        ["docker", "compose", "-p", "argus", "stop"],
        ["docker", "compose", "--project-name=argus", "stop"],
        ["docker", "compose", "-f", "x.yml", "rm", "-f"],
        ["docker", "compose", "--project-name", "argus", "--env-file", "e", "stop"],
        # docker commands that remove or stop other things without naming them
        ["docker", "volume", "prune", "--all", "--force"],
        ["docker", "system", "prune", "--volumes", "-f"],
        ["docker", "container", "prune", "-f"],
        ["docker", "compose", "--project-name", "argus", "--profile", "kibana", "run", "kibana-es"],
    ],
)
def test_a_command_touching_production_is_refused(command: list[str]) -> None:
    with pytest.raises(RuntimeError, match="refused"):
        tier_script.check_command(command)
    with pytest.raises(RuntimeError, match="refused"):
        tier_script.run(command, tier_script.Settings.from_env({}))  # refused before running


def test_the_script_lists_every_action() -> None:
    """The guard allows the commands of these actions only; a new action is added here too."""
    assert tier_script.ACTIONS == ACTIONS


# words docker commands are made of: the tier's own, production's names, and verbs and options
# that would act on other services or volumes
_WORDS = sorted(
    {w for action in tier_script.ACTIONS for c in tier_script.commands_for(action) for w in c}
    | tier_script.PROTECTED
    | {"down", "prune", "system", "-p", "-f", "--all", "--volumes", "--remove-orphans", "run"}
)
_ALLOWED = [c for action in tier_script.ACTIONS for c in tier_script.commands_for(action)]


def _mutate(command: list[str], at: int, how: str, word: str) -> list[str]:
    words = list(command)
    i = at % (len(words) + 1)
    if how == "insert":
        words.insert(i, word)
    elif i < len(words):
        if how == "drop":
            del words[i]
        else:
            words[i] = word
    return words


@given(
    st.one_of(
        st.lists(st.sampled_from(_WORDS), min_size=1, max_size=14),
        # an allowed command with one word dropped, replaced or added
        st.builds(
            _mutate,
            st.sampled_from(_ALLOWED),
            st.integers(0, 20),
            st.sampled_from(["drop", "replace", "insert"]),
            st.sampled_from(_WORDS),
        ),
    )
)
def test_the_guard_allows_exactly_the_tiers_own_commands(command: list[str]) -> None:
    if command in _ALLOWED:
        tier_script.check_command(command)  # does not raise
    else:
        with pytest.raises(RuntimeError, match="refused"):
            tier_script.check_command(command)


def test_any_sequence_is_checked_like_a_list() -> None:
    tier_script.check_command(tuple(_ALLOWED[0]))  # does not raise
    with pytest.raises(RuntimeError, match="stops every service"):  # the reason, not only a refusal
        tier_script.check_command(("docker", "compose", "down"))


def test_an_unknown_action_has_no_command() -> None:
    with pytest.raises(ValueError, match="down"):
        tier_script.commands_for("down")


def test_docker_runs_on_the_default_context_with_the_shared_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "COMPOSE_ENV_FILES"):
        monkeypatch.setenv(name, "set-by-someone")
    monkeypatch.setenv("DOCKER_CONTEXT", "desktop-linux")
    settings = tier_script.Settings.from_env({"KIBANA_TIER_DIR": str(tmp_path)})
    env = tier_script.docker_env(settings)
    assert env["DOCKER_CONTEXT"] == "default"
    assert env["KIBANA_TIER_DIR"] == str(tmp_path.resolve())
    # no other daemon or client configuration, and no other env file
    assert {k for k in env if k.startswith("DOCKER_")} == {"DOCKER_CONTEXT"}
    assert "COMPOSE_ENV_FILES" not in env


def test_docker_env_pins_what_compose_would_read_from_the_checkouts_env_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review F4: compose reads COMPOSE_* settings from the worktree's .env too (every tier
    command reads it: db's required variables). Removing them from the process environment let
    a .env's COMPOSE_REMOVE_ORPHANS=true make the tier's own `up` remove other checkouts'
    containers; a value in the process environment wins over the .env (Compose v5.3), so the
    script sets each one itself."""
    for name in (
        "COMPOSE_REMOVE_ORPHANS",
        "COMPOSE_PROFILES",
        "COMPOSE_FILE",
        "COMPOSE_PROJECT_NAME",
        "COMPOSE_IGNORE_ORPHANS",
        "COMPOSE_PATH_SEPARATOR",
    ):
        monkeypatch.setenv(name, "true")
    env = tier_script.docker_env(tier_script.Settings.from_env({}))
    assert {k: v for k, v in env.items() if k.startswith("COMPOSE_")} == {
        "COMPOSE_REMOVE_ORPHANS": "false",
        "COMPOSE_PROFILES": "kibana",
        "COMPOSE_FILE": str(tier_script.COMPOSE_FILE),
        "COMPOSE_PROJECT_NAME": "argus",
    }


# --------------------------------------------------------------------------- compose file


def test_the_compose_file_requires_no_variable() -> None:
    """A ``${X:?...}`` anywhere fails every compose command, db's included, while X is unset;
    the tier's services must never add one."""
    tier_part = yaml.safe_dump({k: compose()["services"][k] for k in tier_script.SERVICES})
    assert ":?" not in tier_part
    assert "${KIBANA_TIER_DIR:-${HOME}/.local/share/argus-kibana-tier}" in tier_part


def test_the_tier_services_are_pinned_local_and_capped() -> None:
    services = compose()["services"]
    others = {k: v for k, v in services.items() if k not in tier_script.SERVICES}
    used_ports = {p for s in others.values() for p in s.get("ports", [])}
    used_volumes = {v.split(":")[0] for s in others.values() for v in s.get("volumes", [])}
    total = 0
    for name in tier_script.SERVICES:
        service = services[name]
        assert service["profiles"] == ["kibana"]
        assert service["container_name"] == tier_script.CONTAINERS[name]
        image, digest = service["image"].split("@sha256:")
        assert image.endswith(":8.19.12")
        assert re.fullmatch(r"[0-9a-f]{64}", digest)
        assert "restart" not in service  # on demand, never at boot
        for port in service["ports"]:
            assert port.startswith("127.0.0.1:")
            assert port not in used_ports
            assert port.split(":")[1] not in {"59200", "55432"}
        own = [v.split(":")[0] for v in service["volumes"] if not v.startswith("$")]
        assert own
        assert not set(own) & used_volumes
        assert service["memswap_limit"] == service["mem_limit"]  # no swap
        total += mib(service["mem_limit"])
        assert "healthcheck" in service
    assert total <= BUDGET_MIB

    es_env = services["kibana-es"]["environment"]
    heap = re.fullmatch(r"-Xms(\d+m) -Xmx(\d+m)", es_env["ES_JAVA_OPTS"])
    assert heap is not None
    assert heap[1] == heap[2]
    assert 768 <= mib(heap[1]) <= 1024
    assert mib(heap[1]) < mib(services["kibana-es"]["mem_limit"])
    assert es_env["xpack.security.enabled"] == "true"
    assert es_env["xpack.security.http.ssl.enabled"] == "true"
    assert es_env["xpack.license.self_generated.type"] == "basic"
    assert "ELASTIC_PASSWORD" not in es_env  # only the file

    node = re.fullmatch(
        r"--max-old-space-size=(\d+)", services["kibana"]["environment"]["NODE_OPTIONS"]
    )
    assert node is not None
    assert int(node[1]) < mib(services["kibana"]["mem_limit"])
    assert services["kibana"]["depends_on"] == {"kibana-es": {"condition": "service_healthy"}}


def test_production_services_share_nothing_with_the_tier() -> None:
    services = compose()["services"]
    assert "profiles" not in services["db"]  # production's database starts without a profile
    for name in ("db", "es-local"):
        text = yaml.safe_dump(services[name])
        assert "kibana" not in text, name
    assert {"argus-kibana-esdata", "argus-kibana-data"} <= set(compose()["volumes"])


def test_the_elastic_password_reaches_elasticsearch_through_its_keystore_only() -> None:
    """Review F3: with ELASTIC_PASSWORD_FILE the image's entrypoint exports ELASTIC_PASSWORD and
    execs Elasticsearch, so every Elasticsearch process held it. The tier's entrypoint writes
    the file into the keystore through stdin, and no variable holds it."""
    service = compose()["services"]["kibana-es"]
    assert not [k for k in service["environment"] if k.startswith("ELASTIC_PASSWORD")]
    entrypoint = service["entrypoint"]
    assert entrypoint[:5] == ["/bin/tini", "--", "/bin/bash", "-e", "-c"]
    script = entrypoint[5]
    assert (
        "elasticsearch-keystore add -x -f bootstrap.password"
        " < /usr/share/elasticsearch/config/tier/elastic-password"
    ) in script
    assert script.strip().splitlines()[-1] == "exec /usr/local/bin/docker-entrypoint.sh eswrapper"
    assert "$" not in script  # nothing for compose to interpolate, no variable to hold it


# --------------------------------------------------------------------------- settings


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:55610",
        "https://10.20.60.11:5601",
        "https://siem.example:5601",
        "ftp://x",
        # only scheme, loopback host and port: no credentials, path, query or fragment
        "https://user@127.0.0.1:55610",
        "https://127.0.0.1:55610/..",
        "https://127.0.0.1:55610/x?y=@10.20.60.11",
        "https://127.0.0.1:55610#@10.20.60.11",  # fake-secret: a fragment, not a password
        "https://127.0.0.1:99999",
    ],
)
def test_the_tier_is_reached_over_https_on_loopback_only(url: str) -> None:
    with pytest.raises(SystemExit):
        tier_script.Settings.from_env({"KIBANA_TIER_URL": url})
    with pytest.raises(SystemExit):
        tier_script.Settings.from_env({"KIBANA_TIER_ES_URL": url})


def test_the_defaults(tmp_path: Path) -> None:
    settings = tier_script.Settings.from_env({})
    assert settings.kibana_url == "https://127.0.0.1:55610"
    assert settings.es_url == "https://127.0.0.1:59210"
    assert settings.paths.root == tier_script.DEFAULT_DIR.resolve()
    other = tier_script.Settings.from_env(
        {"KIBANA_TIER_URL": "https://localhost:6601/", "KIBANA_TIER_DIR": str(tmp_path)}
    )
    assert other.kibana_url == "https://localhost:6601"
    assert other.paths.secrets == tmp_path.resolve() / "secrets.json"


# --------------------------------------------------------------------------- secrets


def test_secrets_are_made_once_private_and_long(tmp_path: Path) -> None:
    paths = tier_script.Paths(tmp_path / "tier")
    data = tier_script.ensure_secrets(paths, seed.usernames())
    assert stat.S_IMODE(os.stat(paths.secrets).st_mode) == 0o600
    passwords = data["passwords"]
    assert set(passwords) == {"elastic", "kibana_system", *seed.usernames()}
    assert all(len(p) >= tier_script.PASSWORD_MIN for p in passwords.values())
    assert len(set(passwords.values())) == len(passwords)
    assert all(len(k) >= 32 for k in data["encryption_keys"].values())
    data["api_keys"] = {"argus-reader": {"id": "x", "encoded": "y", "spec": "z"}}
    tier_script.save_secrets(paths, data)
    again = tier_script.ensure_secrets(paths, [*seed.usernames(), "tier-new"])
    assert {k: v for k, v in again["passwords"].items() if k != "tier-new"} == passwords
    assert len(again["passwords"]["tier-new"]) >= tier_script.PASSWORD_MIN
    assert again["api_keys"] == data["api_keys"]  # kept


def test_kibana_yml_quotes_every_secret_and_keeps_siem_defaults(tmp_path: Path) -> None:
    paths = tier_script.Paths(tmp_path)
    data = tier_script.ensure_secrets(paths, [])
    data["passwords"]["kibana_system"] = "p'a\"ss: #word\\"  # YAML-hostile, still one value
    settings = tier_script.Settings("https://127.0.0.1:55610", "https://127.0.0.1:59210", paths)
    config = yaml.safe_load(tier_script.kibana_yml(settings, data))
    assert config["elasticsearch.password"] == "p'a\"ss: #word\\"
    assert config["server.ssl.enabled"] is True
    assert config["elasticsearch.ssl.verificationMode"] == "full"
    assert (
        config["xpack.encryptedSavedObjects.encryptionKey"]
        == (data["encryption_keys"]["encrypted_saved_objects"])
    )
    assert config["telemetry.optIn"] is False
    # as on the SIEM (§12 #2, #5): no basePath, the rate limiter and HTTP auth at their defaults
    assert not any(k.startswith(("server.basePath", "server.rateLimiter")) for k in config)
    assert not any(k.startswith("xpack.security.authc") for k in config)


@given(st.text(st.characters(min_codepoint=0x20, max_codepoint=0x7E), min_size=1, max_size=40))
def test_kibana_yml_round_trips_any_printable_ascii_password(password: str) -> None:
    data = {
        "passwords": {"kibana_system": password},
        "encryption_keys": {
            "encrypted_saved_objects": "a" * 64,
            "security": "b" * 64,
            "reporting": "c" * 64,
        },
    }
    settings = tier_script.Settings(
        "https://127.0.0.1:55610",
        "https://127.0.0.1:59210",
        tier_script.Paths(Path("/nonexistent")),
    )
    assert yaml.safe_load(tier_script.kibana_yml(settings, data))["elasticsearch.password"] == (
        password
    )


# --------------------------------------------------------------------------- certificates


def _serve_once(certificate: Path, key: Path) -> tuple[int, threading.Thread]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))
    listener = socket.create_server(("127.0.0.1", 0))
    port = listener.getsockname()[1]

    def serve() -> None:
        with listener:
            connection, _ = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    tls.recv(1)
            except (ssl.SSLError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


def test_the_local_ca_and_certificates_verify_under_a_strict_client(tmp_path: Path) -> None:
    paths = tier_script.Paths(tmp_path / "tier")
    now = datetime.now(UTC)
    assert tier_script.ensure_certificates(paths, now=now) == ["ca", "es", "kibana"]
    assert stat.S_IMODE(os.stat(paths.ca_key).st_mode) == 0o600
    for directory in (paths.ca_crt.parent, paths.es_dir, paths.kibana_dir, paths.kibana_tls):
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(paths.kibana_tls / "kibana.key").st_mode) == 0o600
    for directory in (paths.es_dir, paths.kibana_tls):
        assert (directory / "ca.crt").read_bytes() == paths.ca_crt.read_bytes()
    for name, directory in (("es", paths.es_dir), ("kibana", paths.kibana_tls)):
        port, thread = _serve_once(directory / f"{name}.crt", directory / f"{name}.key")
        context = tier_script.tls_context(paths.ca_crt)
        with (
            socket.create_connection(("127.0.0.1", port)) as raw,
            context.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
        ):
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            tls.send(b"x")
        thread.join(5)
    # fresh: nothing re-made; the CA renewed: the leaves with it
    assert tier_script.ensure_certificates(paths, now=now) == []
    soon = now + timedelta(days=tier_script.LEAF_DAYS) - timedelta(days=10)
    assert tier_script.ensure_certificates(paths, now=soon) == ["es", "kibana"]
    assert tier_script.ensure_certificates(paths, now=now, force=True) == ["ca", "es", "kibana"]


def test_a_certificate_of_another_ca_is_refused(tmp_path: Path) -> None:
    ours = tier_script.Paths(tmp_path / "ours")
    theirs = tier_script.Paths(tmp_path / "theirs")
    now = datetime.now(UTC)
    tier_script.ensure_certificates(ours, now=now)
    tier_script.ensure_certificates(theirs, now=now)
    port, thread = _serve_once(theirs.kibana_tls / "kibana.crt", theirs.kibana_tls / "kibana.key")
    context = tier_script.tls_context(ours.ca_crt)
    with (
        socket.create_connection(("127.0.0.1", port)) as raw,
        pytest.raises(ssl.SSLCertVerificationError),
    ):
        context.wrap_socket(raw, server_hostname="127.0.0.1")
    thread.join(5)


def test_certificate_end_of_a_missing_or_bad_file(tmp_path: Path) -> None:
    assert tier_script.certificate_end(tmp_path / "none.crt") is None
    bad = tmp_path / "bad.crt"
    bad.write_text("not a certificate", encoding="utf-8")
    assert tier_script.certificate_end(bad) is None


# --------------------------------------------------------------------------- memory


@pytest.mark.parametrize(
    ("usage", "expected"),
    [("1.268GiB / 1.5GiB", 1298.432), ("748.2MiB / 1.5GiB", 748.2), ("512KiB / 1GiB", 0.5)],
)
def test_docker_stats_usage_in_mib(usage: str, expected: float) -> None:
    assert tier_script.memory_mib(usage) == pytest.approx(expected)


@pytest.mark.parametrize("usage", ["1TB / 2TB", "MiB / 1GiB", "1.2.3MiB / 1GiB", ""])
def test_an_unknown_usage_is_an_error(usage: str) -> None:
    with pytest.raises(ValueError, match="not a memory usage"):
        tier_script.memory_mib(usage)


@pytest.mark.parametrize("value", ["pässword", "line\nbreak", "tab\there", "\u2028"])
def test_kibana_yml_refuses_what_a_parser_could_read_otherwise(value: str) -> None:
    data = {
        "passwords": {"kibana_system": value},
        "encryption_keys": {
            "encrypted_saved_objects": "a" * 64,
            "security": "b" * 64,
            "reporting": "c" * 64,
        },
    }
    settings = tier_script.Settings(
        "https://127.0.0.1:55610",
        "https://127.0.0.1:59210",
        tier_script.Paths(Path("/nonexistent")),
    )
    with pytest.raises(ValueError, match="printable ASCII"):
        tier_script.kibana_yml(settings, data)


# --------------------------------------------------------------------------- clean


def test_runs_are_dated_by_their_id() -> None:
    from tests.kibana.tier import new_run_id

    moment = datetime(2026, 10, 23, 1, 2, 3, tzinfo=UTC)
    run = new_run_id(moment)
    assert tier_script.run_started(run) == moment
    assert tier_script.run_started(f"t-{run}-owner") == moment
    assert tier_script.run_started(f"argus-tier-run-{run}-3c9c79-read") == moment
    assert tier_script.run_started(f"run:{run}") == moment


@pytest.mark.parametrize(
    "name", ["argus-tier-seed", "tier-viewer", "argus", "t-x3186fd-owner", "run:kt991399999999abcd"]
)
def test_the_seed_and_foreign_names_are_never_stale(name: str) -> None:
    now = datetime(2030, 1, 1, tzinfo=UTC)
    assert not tier_script.stale(name, now=now, older_than=timedelta(hours=1))


def test_only_old_runs_are_stale() -> None:
    from tests.kibana.tier import new_run_id

    now = datetime(2026, 10, 23, 12, 0, 0, tzinfo=UTC)
    old = new_run_id(now - timedelta(hours=7))
    recent = new_run_id(now - timedelta(hours=5))
    assert tier_script.stale(f"t-{old}-x", now=now, older_than=timedelta(hours=6))
    assert not tier_script.stale(f"t-{recent}-x", now=now, older_than=timedelta(hours=6))


RUNNING = "true\ntrue\n"


def _inspections(monkeypatch: pytest.MonkeyPatch, answers: list[object]) -> list[list[str]]:
    """``docker inspect``'s answers to the tier's "running" command, in order (text, or an
    exception to raise); every docker command run is recorded."""
    ran: list[list[str]] = []
    pending = iter(answers)

    def fake_run(command: list[str], settings: object, *, capture: bool = False) -> str:
        ran.append(list(command))
        if command == tier_script.commands_for("running")[0]:
            answer = next(pending)
            if isinstance(answer, BaseException):
                raise answer
            return str(answer)
        return ""

    monkeypatch.setattr(tier_script, "run", fake_run)
    monkeypatch.setattr(tier_script.time, "sleep", lambda seconds: None)
    return ran


def _stopped(ran: list[list[str]]) -> bool:
    return tier_script.commands_for("stop")[0] in ran


def test_holding_ends_when_the_tier_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    _inspections(monkeypatch, [RUNNING, RUNNING, "false\nfalse\n"])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 0


@pytest.mark.parametrize("survivor", ["false\ntrue\n", "true\nfalse\n"])
def test_a_tier_half_stopped_is_stopped_whole(
    monkeypatch: pytest.MonkeyPatch, survivor: str
) -> None:
    """Review F1: one container gone (an OOM kill; the tier has no restart policy) must not
    leave the other running outside any heavy-task slot."""
    ran = _inspections(monkeypatch, [RUNNING, survivor])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 1
    assert _stopped(ran)


def test_half_a_tier_is_left_alone_while_someone_holds_the_tier_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exclusive test may stop one container on purpose (Kibana down while Elasticsearch
    runs), and `down` stops them one by one: while the tier's lock is held alone, the holder
    waits instead of stopping the rest."""
    ran = _inspections(monkeypatch, [RUNNING, "false\ntrue\n", "false\ntrue\n", "false\nfalse\n"])
    settings = tier_script.Settings.from_env({"KIBANA_TIER_DIR": str(tmp_path)})
    with tier_script.tier_lock(settings.paths, exclusive=True):
        assert tier_script.hold(settings, every=0) == 0
    assert not _stopped(ran)


def test_one_failed_inspect_does_not_end_the_hold(monkeypatch: pytest.MonkeyPatch) -> None:
    hiccup = subprocess.CalledProcessError(
        1, ["docker"], output="", stderr="Cannot connect to the Docker daemon"
    )
    ran = _inspections(monkeypatch, [RUNNING, hiccup, RUNNING, "false\nfalse\n"])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 0
    assert ran.count(tier_script.commands_for("running")[0]) == 4  # held on after the hiccup


def test_docker_failing_for_good_ends_the_hold_with_a_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hiccup = subprocess.CalledProcessError(1, ["docker"], output="", stderr="timeout")
    ran = _inspections(monkeypatch, [RUNNING, *[hiccup] * tier_script.HOLD_UNKNOWN_LIMIT])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 1
    assert _stopped(ran)


@pytest.mark.parametrize(
    "message",
    [
        "error: no such object: argus-kibana-es\nerror: no such object: argus-kibana\n",  # 29.7
        "Error: No such object: argus-kibana-es\nError: No such object: argus-kibana\n",
    ],
)
def test_removed_containers_end_the_hold(monkeypatch: pytest.MonkeyPatch, message: str) -> None:
    gone = subprocess.CalledProcessError(1, ["docker"], output="", stderr=message)
    ran = _inspections(monkeypatch, [RUNNING, gone])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 0  # `reset`
    assert not _stopped(ran)


def test_one_removed_container_beside_a_running_one_is_half_a_tier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    half = subprocess.CalledProcessError(
        1, ["docker"], output="true\n", stderr="error: no such object: argus-kibana\n"
    )
    ran = _inspections(monkeypatch, [RUNNING, half])
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 1
    assert _stopped(ran)


def test_an_interrupted_hold_stops_the_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    ran = _inspections(monkeypatch, [RUNNING] * 3)

    def interrupted(seconds: float) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(tier_script.time, "sleep", interrupted)
    assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 130
    assert _stopped(ran)


class _HungUpError(Exception):
    pass


def test_a_hangup_stops_the_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review F1: a closed terminal (SIGHUP) ended the holder without stopping the tier."""
    ran = _inspections(monkeypatch, [RUNNING] * 3)
    monkeypatch.setattr(
        tier_script.time, "sleep", lambda seconds: os.kill(os.getpid(), signal.SIGHUP)
    )

    def ours(signum: int, frame: object) -> None:  # never let a SIGHUP end the test run
        raise _HungUpError

    previous = signal.signal(signal.SIGHUP, ours)
    try:
        assert tier_script.hold(tier_script.Settings.from_env({}), every=0) == 130
        assert signal.getsignal(signal.SIGHUP) is ours  # put back afterwards
    finally:
        signal.signal(signal.SIGHUP, previous)
    assert _stopped(ran)


def test_the_tier_starts_only_inside_a_heavy_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review F1: a plain `up` outside scripts/heavy.sh ran the tier outside every slot."""
    monkeypatch.delenv("HEAVY_SLOT_HELD", raising=False)
    ran = _inspections(monkeypatch, [])
    monkeypatch.setattr(tier_script, "cmd_init", lambda settings, args: 0)
    settings = tier_script.Settings.from_env({"KIBANA_TIER_DIR": str(tmp_path)})
    with pytest.raises(SystemExit, match=r"scripts/heavy\.sh"):
        tier_script.cmd_up(settings, argparse.Namespace(timeout=1.0, hold=False))
    assert ran == []


# --------------------------------------------------------------------------- the tier's lock


def test_live_sessions_share_the_tier_and_exclusive_use_waits_for_them(tmp_path: Path) -> None:
    """Review F2: exclusive use of the one tier (anything that stops it or takes the security
    index away) needs every live test session gone, and keeps new ones out."""
    paths = tier_script.Paths(tmp_path)
    with (
        tier_script.tier_lock(paths, exclusive=False),
        tier_script.tier_lock(paths, exclusive=False),
        pytest.raises(tier_script.TierBusy),
        tier_script.tier_lock(paths, exclusive=True),
    ):
        pass
    with (
        tier_script.tier_lock(paths, exclusive=True),
        pytest.raises(tier_script.TierBusy),
        tier_script.tier_lock(paths, exclusive=False),
    ):
        pass
    with tier_script.tier_lock(paths, exclusive=True):
        pass  # free again


def test_a_session_takes_the_tier_alone_only_when_no_other_holds_it(tmp_path: Path) -> None:
    paths = tier_script.Paths(tmp_path)
    ours = tier_script.TierLock(paths)
    ours.acquire(exclusive=False)
    other = tier_script.TierLock(paths)
    other.acquire(exclusive=False)
    with pytest.raises(tier_script.TierBusy), ours.exclusively():
        pass
    other.release()
    with (
        ours.exclusively(),
        pytest.raises(tier_script.TierBusy),
        tier_script.tier_lock(paths, exclusive=False),
    ):
        pass
    with tier_script.tier_lock(paths, exclusive=False):  # shared again afterwards
        pass
    ours.release()


def test_down_and_reset_wait_for_live_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ran = _inspections(monkeypatch, [])
    settings = tier_script.Settings.from_env({"KIBANA_TIER_DIR": str(tmp_path)})
    with tier_script.tier_lock(settings.paths, exclusive=False):  # a live session elsewhere
        assert tier_script.cmd_down(settings, argparse.Namespace(force=False)) == 3
        assert tier_script.cmd_reset(settings, argparse.Namespace(yes=True, force=False)) == 3
        assert ran == []
        assert tier_script.cmd_down(settings, argparse.Namespace(force=True)) == 0
    assert tier_script.cmd_down(settings, argparse.Namespace(force=False)) == 0
    assert ran == tier_script.commands_for("stop") * 2


def test_one_seed_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Review F8: two seeds at once both minted argus's keys."""

    def never(*args: object, **kwargs: object) -> None:
        raise AssertionError("the seed reached the tier while another seed ran")

    monkeypatch.setattr(tier_script, "es_admin", never)
    monkeypatch.setattr(tier_script, "kibana_admin", never)
    settings = tier_script.Settings.from_env({"KIBANA_TIER_DIR": str(tmp_path)})
    with tier_script.tier_lock(settings.paths, exclusive=True, name=tier_script.SEED_LOCK):
        assert tier_script.cmd_seed(settings, argparse.Namespace(wait=0.0)) == 3


# --------------------------------------------------------------------------- stats and processes


def test_stats_with_nothing_measured_is_no_go(monkeypatch: pytest.MonkeyPatch) -> None:
    """Review F7: with the tier down every sample was empty and stats exited 0."""

    def gone(command: list[str], settings: object, **kw: object) -> str:
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(tier_script, "run", gone)
    code = tier_script.cmd_stats(
        tier_script.Settings.from_env({}), argparse.Namespace(seconds=0, interval=0, until=None)
    )
    assert code == 2


@pytest.mark.parametrize(
    ("sample", "code"),
    [
        ({"argus-kibana-es": 1400.0}, 2),  # Kibana not measured: nothing to judge
        ({"argus-kibana-es": 1400.0, "argus-kibana": 800.0}, 0),
        ({"argus-kibana-es": 2000.0, "argus-kibana": 1400.0}, 1),  # 3,400 MiB > 3.5 GB
    ],
)
def test_stats_judges_samples_of_both_containers(
    monkeypatch: pytest.MonkeyPatch, sample: dict[str, float], code: int
) -> None:
    monkeypatch.setattr(tier_script, "sample_memory", lambda settings: dict(sample))
    monkeypatch.setattr(tier_script, "cgroup_memory", lambda settings: {})
    args = argparse.Namespace(seconds=0, interval=0, until=None)
    assert tier_script.cmd_stats(tier_script.Settings.from_env({}), args) == code


def test_the_budget_is_3_5_gb() -> None:
    """The plan's 3.5 GB, in decimal units (3,338 MiB), the stricter reading."""
    assert round(tier_script.BUDGET_MIB, 3) == round(3_500_000_000 / 1024 / 1024, 3)


_PROCESS_CALLS = {
    "subprocess": {"run", "Popen", "call", "check_call", "check_output", "getoutput"},
    "os": {"system", "popen", "execv", "execvp", "execve", "spawnv", "spawnvp", "posix_spawn"},
}


def test_every_docker_call_goes_through_the_guard() -> None:
    """Review F11: cgroup_peaks (now cgroup_memory) ran `docker inspect` outside run() and its
    allowlist. Only run() (checked) and _openssl() start a process."""
    tree = ast.parse((REPO_ROOT / "scripts" / "kibana_tier.py").read_text(encoding="utf-8"))
    starts = []
    for function in ast.walk(tree):
        if not isinstance(function, ast.FunctionDef):
            continue
        for node in ast.walk(function):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.attr in _PROCESS_CALLS.get(node.func.value.id, set())
            ):
                starts.append((function.name, node.lineno))
    assert starts
    assert {name for name, _ in starts} <= {"run", "_openssl"}, starts


def test_stats_runs_only_the_tiers_own_docker_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []
    allowed = tier_script.allowed_commands()

    def fake(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        seen.append(list(argv))
        if argv[0] == "docker" and list(argv) not in allowed:
            raise AssertionError(f"not one of the tier's own commands: {argv}")
        out = "abc\n" if "{{.Id}}" in argv else ""  # no stats: the tier is down
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")

    monkeypatch.setattr(tier_script.subprocess, "run", fake)
    tier_script.cmd_stats(
        tier_script.Settings.from_env({}), argparse.Namespace(seconds=0, interval=0, until=None)
    )
    assert seen
    assert all(command in tier_script.commands_for("ids") for command in seen[1:])


def test_the_process_check_finds_a_secret_in_an_environment_or_a_command_line() -> None:
    """Review F3: the image's entrypoint exported ELASTIC_PASSWORD from its _FILE into every
    Elasticsearch process. The check runs inside each container (docker exec as the
    container's user: from the host, Elasticsearch's processes, gid 0, are unreadable), reads
    the secrets from stdin, and prints process ids only. Here it runs on this machine's /proc,
    with two children holding a token."""
    import secrets as random

    token = random.token_urlsafe(24)
    sleeper = "import time; time.sleep(30)"
    in_env = subprocess.Popen(  # noqa: S603
        ["python3", "-c", sleeper],  # noqa: S607
        env={"PATH": os.environ["PATH"], "ARGUS_TEST_TOKEN": token},
    )
    in_argv = subprocess.Popen(["python3", "-c", sleeper, f"--x={token}"])  # noqa: S603, S607
    try:
        time.sleep(0.3)
        done = subprocess.run(  # noqa: S603
            ["bash", "-c", tier_script.PROCESS_CHECK],  # noqa: S607
            input=f"{token}\n",
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
    finally:
        for child in (in_env, in_argv):
            child.kill()
            child.wait()
    assert token not in done.stdout + done.stderr
    seen, _others, found = tier_script.parse_process_check("here", done.stdout)  # others: users
    assert seen > 2
    assert ("here", in_env.pid, "environment") in found
    assert ("here", in_argv.pid, "command line") in found
    assert [f for f in found if f[1] not in (in_env.pid, in_argv.pid)] == []


def test_the_process_check_refuses_to_run_without_secrets() -> None:
    done = subprocess.run(  # noqa: S603
        ["bash", "-c", tier_script.PROCESS_CHECK],  # noqa: S607
        input="",
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 2  # an empty pattern would match every process


def test_secrets_reach_the_check_on_stdin_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], str | None]] = []

    def fake_run(
        command: list[str], settings: object, *, capture: bool = False, stdin: str | None = None
    ) -> str:
        tier_script.check_command(command)
        calls.append((list(command), stdin))
        return "seen 1\nseen 7\nunreadable 9\nfound 7 environment\n"

    monkeypatch.setattr(tier_script, "run", fake_run)
    values = ["pass-word-one-1234567890", "pass-word-two-1234567890"]  # fake-secret
    seen, unreadable, found = tier_script.secrets_in_containers(
        tier_script.Settings.from_env({}), values
    )
    assert [c for c, _ in calls] == tier_script.commands_for("process-check")
    assert all(not any(v in " ".join(c) for v in values) for c, _ in calls)
    assert all(stdin == "\n".join(values) + "\n" for _, stdin in calls)
    assert seen == 4
    assert unreadable == [("argus-kibana-es", 9), ("argus-kibana", 9)]
    assert found == [("argus-kibana-es", 7, "environment"), ("argus-kibana", 7, "environment")]


def test_drift_is_a_container_made_from_another_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    answers = {
        "hash": "kibana-es aaa\nkibana bbb\n",
        "labels": "/argus-kibana-es aaa\n/argus-kibana old\n",
    }

    def fake_run(command: list[str], settings: object, **kw: object) -> str:
        return answers["hash"] if "config" in command else answers["labels"]

    monkeypatch.setattr(tier_script, "run", fake_run)
    settings = tier_script.Settings.from_env({})
    assert tier_script.drifted(settings) == ["kibana"]
    answers["labels"] = "/argus-kibana-es aaa\n/argus-kibana bbb\n"
    assert tier_script.drifted(settings) == []


def test_no_containers_means_no_drift(monkeypatch: pytest.MonkeyPatch) -> None:
    import subprocess

    def missing(command: list[str], settings: object, **kw: object) -> str:
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(tier_script, "run", missing)
    assert tier_script.drifted(tier_script.Settings.from_env({})) == []


def test_a_test_session_takes_the_tier_alone_only_through_its_own_lock(tmp_path: Path) -> None:
    """Review F2: the runbook sent exclusive tests to "a tier of your own", which the fixed
    names, ports and volumes cannot make; they take the one tier alone instead."""
    from tests.kibana.tier import Tier

    paths = tier_script.Paths(tmp_path)
    session = tier_script.TierLock(paths)
    session.acquire(exclusive=False)
    other = tier_script.TierLock(paths)
    other.acquire(exclusive=False)  # another worktree's live session
    tier = Tier("live", "kt000000000000abcd", lock=session)
    with pytest.raises(tier_script.TierBusy), tier.exclusive():
        pass
    other.release()
    with tier.exclusive(), pytest.raises(tier_script.TierBusy):
        tier_script.TierLock(paths).acquire(exclusive=False)  # none starts meanwhile
    session.release()
    with (
        pytest.raises(RuntimeError, match="live"),
        Tier("replay", "kt000000000000abcd").exclusive(),
    ):
        pass


def test_the_record_variable() -> None:
    from tests.kibana.tier import record_requested

    assert record_requested({}) is False
    assert record_requested({"KIBANA_TIER_RECORD": "1"}) is True
    assert record_requested({"KIBANA_TIER_RECORD": "new"}) == "new"
    with pytest.raises(ValueError, match="KIBANA_TIER_RECORD"):
        record_requested({"KIBANA_TIER_RECORD": "yes"})


def test_a_second_seed_must_change_nothing() -> None:
    """The gate's idempotence check (`seed --expect-kept`)."""
    kept = {
        "space": "kept",
        "roles": {"argus_kibana_reader": "kept"},
        "keys": {"argus-reader": "kept", "argus user": "narrowed and disabled"},
        "alerts": 12,
    }
    assert tier_script.seed_changes(kept) == []
    changed = {
        **kept,
        "roles": {"argus_kibana_reader": "updated"},
        "keys": {"argus-reader": "re-minted", "surplus keys invalidated": 5},
    }
    assert tier_script.seed_changes(changed) == [
        "roles.argus_kibana_reader",
        "keys.argus-reader",
        "keys.surplus keys invalidated",
    ]


def test_the_gate_script_checks_what_the_gate_asks(tmp_path: Path) -> None:
    """Review F12: the gate's cycle and its check that no cassette was written or changed lived
    only in a scratch script."""
    script = REPO_ROOT / "scripts" / "kibana_gate.sh"
    text = script.read_text(encoding="utf-8")
    for needed in (
        "tier reset --yes",
        "tier seed --expect-kept",
        "KIBANA_TIER=live timeout 1800 uv run pytest tests/kibana",
        "git status --porcelain --untracked-files=all -- tests/kibana/cassettes",
        "tier stats --seconds 3600",
        "tier status",
        "tier down",
    ):
        assert needed in text, needed
    env = {k: v for k, v in os.environ.items() if k != "HEAVY_SLOT_HELD"}
    outside = subprocess.run(  # noqa: S603
        ["bash", str(script), "--out", str(tmp_path)],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert outside.returncode == 2
    assert "heavy.sh" in outside.stderr
    assert not list(tmp_path.iterdir())  # refused before it did anything


TIER_FILES = (
    "scripts/kibana_tier.py",
    "scripts/kibana_gate.sh",
    "docker-compose.yml",
    "tests/kibana/tier.py",
    "tests/kibana/conftest.py",
    "tests/kibana/cassette.py",
    "docs/runbooks/kibana-tier.md",
)


def test_the_tiers_variables_are_no_argus_settings() -> None:
    """Found by the full suite: ARGUS refuses every ARGUS_* variable that is not a setting, so
    `ARGUS_KIBANA_TIER=replay uv run pytest` broke 969 tests that load the configuration (and
    Q-D2's ARGUS_KIBANA__* settings would make ARGUS_KIBANA_TIER look like a typo of one). The
    tier's variables carry no ARGUS_ prefix; the old names are refused with the new ones."""
    from tests.kibana.tier import MODE_VARIABLE, RECORD_VARIABLE

    names = [MODE_VARIABLE, RECORD_VARIABLE, *tier_script.LOCATION_VARIABLES]
    assert names == [
        "KIBANA_TIER",
        "KIBANA_TIER_RECORD",
        "KIBANA_TIER_URL",
        "KIBANA_TIER_ES_URL",
        "KIBANA_TIER_DIR",
    ]
    for file in TIER_FILES:
        if PUBLIC_TREE and not (REPO_ROOT / file).exists():
            continue  # a private runbook
        text = (REPO_ROOT / file).read_text(encoding="utf-8")
        old = [n for n in re.findall(r"ARGUS_KIBANA_[A-Z_]+", text) if "__" not in n]
        assert set(old) <= set(tier_script.RENAMED), (file, old)


@pytest.mark.parametrize(
    "old", ["ARGUS_KIBANA_TIER", "ARGUS_KIBANA_TIER_DIR", "ARGUS_KIBANA_RECORD"]
)
def test_an_old_variable_name_is_refused_with_its_new_one(old: str) -> None:
    with pytest.raises(SystemExit, match=tier_script.RENAMED[old]):
        tier_script.Settings.from_env({old: "x"})
