"""Adversarial: ``argus`` CLI failure modes, and the production network guard in tests/conftest.py.

No test here sends anything to the production SIEM. Real-socket checks use a loopback stand-in
(``127.0.0.2``) that is *added* to the guarded hosts for the duration of one test, so every
connection attempt that slips past the guard lands on a local listener we control. Checks
about the SIEM itself only call the guard's decision functions.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import shlex
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner, Result

import tests.conftest as guard
from argus.cli import app
from tests.conftest import REPO_ROOT, ProductionAccessBlockedError, production_target

# Snapshot taken while pytest imports (collects) this module, before any test runs.
_GUARD_AT_IMPORT = dict(guard._GUARD_STATE)

SIEM = "10.20.60.11"  # the suite's made-up SIEM (tests.conftest.SUITE_SIEM_HOSTS)
STAND_IN = "127.0.0.2"  # loopback; treated as "production" only inside the tests that ask for it
SECRET = "Adv-Cli-Synthetic-Secret-4e1f"
OWNER_SECRET = "Adv-Cli-Synthetic-Owner-8c2d"
# Both passwords, so every command gets as far as connecting.
BOTH_PASSWORDS = (
    f"ARGUS_DATABASE__PASSWORD={SECRET}\nARGUS_DATABASE__OWNER_PASSWORD={OWNER_SECRET}\n"
)
runner = CliRunner()

ALL_COMMANDS = [
    ["config", "show"],
    ["config", "validate"],
    ["db", "upgrade"],
    ["db", "downgrade", "base", "--yes"],
    ["db", "current"],
    ["db", "check"],
    ["doctor"],
]
DB_COMMANDS = [cmd for cmd in ALL_COMMANDS if cmd[0] == "db"]
SAMPLE_COMMANDS = [["config", "validate"], ["db", "current"], ["doctor"]]


def _ids(commands: list[list[str]]) -> list[str]:
    return ["-".join(c for c in cmd if not c.startswith("-")) for cmd in commands]


# --------------------------------------------------------------------------- CLI helpers


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _good_config(write_config) -> Path:  # type: ignore[no-untyped-def]
    """Valid config pointing at a closed local port: nothing can be reached."""
    return write_config(
        f"database:\n  port: {_closed_port()}\n  connect_timeout: 1s\nlogging:\n  level: WARNING\n"
    )


def _uncaught(result: Result) -> str | None:
    exc = result.exception
    if exc is None or isinstance(exc, SystemExit):
        return None
    return f"{type(exc).__module__}.{type(exc).__name__}: {str(exc).splitlines()[0][:200]}"


def _assert_clean_error(result: Result, code: int, *, single_line: bool = True) -> str:
    """Exit code, no escaped exception (= no traceback for a real user), an 'error:' message.

    Config validation errors are multi-line by design (one bullet per problem), so callers
    checking exit-2 config errors pass ``single_line=False``. Returns all of stderr.
    """
    uncaught = _uncaught(result)
    assert uncaught is None, f"exception escaped the CLI (user sees a traceback): {uncaught}"
    assert result.exit_code == code, (result.exit_code, result.output)
    lines = [line for line in result.stderr.splitlines() if line.strip()]
    assert lines, "no error message on stderr"
    assert lines[0].startswith("error:"), lines
    if single_line:
        assert len(lines) == 1, lines
    assert "Traceback" not in result.output
    assert SECRET not in result.output
    return result.stderr


def _invoke(*args: str) -> Result:
    return runner.invoke(app, list(args))


# --------------------------------------------------------------------------- help and usage


@pytest.mark.parametrize(
    "path",
    [
        [],
        ["config"],
        ["config", "show"],
        ["config", "validate"],
        ["db"],
        ["db", "upgrade"],
        ["db", "downgrade"],
        ["db", "current"],
        ["db", "check"],
        ["doctor"],
    ],
    ids=lambda p: "-".join(p) or "root",
)
def test_every_command_has_help(path: list[str]) -> None:
    result = _invoke(*path, "--help")
    assert _uncaught(result) is None
    assert result.exit_code == 0, result.output
    assert "Usage:" in result.output
    assert "Traceback" not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["no-such-command"],
        ["db", "downgrade"],
        ["db", "upgrade", "head", "extra"],
        ["doctor", "--no-such-option"],
        ["config", "show", "--config"],
        ["db", "no-such-subcommand"],
    ],
    ids=lambda a: "-".join(a),
)
def test_usage_errors_exit_2_without_traceback(args: list[str]) -> None:
    result = _invoke(*args)
    assert _uncaught(result) is None
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output


# --------------------------------------------------------------------------- config errors -> 2

_CONFIG_FAULTS = {
    "missing-file": None,
    "unknown-key": "histroy:\n  window: 5d\n",
    "invalid-yaml": "history:\n  window: [5d\n",
    "top-level-list": "- 5d\n",
    "bare-number-window": "history:\n  window: 5\n",
}


@pytest.mark.parametrize("fault", list(_CONFIG_FAULTS))
@pytest.mark.parametrize("command", ALL_COMMANDS, ids=_ids(ALL_COMMANDS))
def test_invalid_config_is_exit_2_for_every_command(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    command: list[str],
    fault: str,
) -> None:
    text = _CONFIG_FAULTS[fault]
    path = tmp_path / "absent.yaml" if text is None else write_config(text)
    (tmp_path / ".env").write_text(f"ARGUS_DATABASE__PASSWORD={SECRET}\n")
    result = _invoke(*command, "-c", str(path))
    assert _uncaught(result) is None
    assert result.exit_code == 2, result.output
    assert result.stderr.startswith("error:"), result.stderr
    assert "Traceback" not in result.output
    assert SECRET not in result.output


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
@pytest.mark.parametrize("command", SAMPLE_COMMANDS, ids=_ids(SAMPLE_COMMANDS))
def test_unreadable_dotenv_is_a_config_error(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    command: list[str],
) -> None:
    config = _good_config(write_config)
    dotenv = tmp_path / ".env"
    dotenv.write_text(f"ARGUS_DATABASE__PASSWORD={SECRET}\n")
    dotenv.chmod(0)
    try:
        result = _invoke(*command, "-c", str(config))
    finally:
        dotenv.chmod(0o600)
    _assert_clean_error(result, 2, single_line=False)


@pytest.mark.parametrize("command", SAMPLE_COMMANDS, ids=_ids(SAMPLE_COMMANDS))
def test_non_utf8_dotenv_is_a_config_error(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    command: list[str],
) -> None:
    config = _good_config(write_config)
    # Saved as Latin-1 by an editor: 'café' is not valid UTF-8.
    (tmp_path / ".env").write_bytes(b"ARGUS_DATABASE__PASSWORD=caf\xe9-" + SECRET.encode() + b"\n")
    result = _invoke(*command, "-c", str(config))
    _assert_clean_error(result, 2, single_line=False)


@pytest.mark.parametrize("command", SAMPLE_COMMANDS, ids=_ids(SAMPLE_COMMANDS))
def test_non_utf8_config_file_is_a_config_error(tmp_path: Path, command: list[str]) -> None:
    config = tmp_path / "latin1.yaml"
    config.write_bytes(b"# r\xe9sum\xe9 of the settings\nhistory:\n  window: 5d\n")
    result = _invoke(*command, "-c", str(config))
    _assert_clean_error(result, 2, single_line=False)


@pytest.mark.parametrize(
    ("source", "key", "value", "section"),
    [
        ("dotenv", "ARGUS_DATABASE", f"postgresql://argus:{SECRET}@127.0.0.1/argus", "database"),
        ("env", "ARGUS_DATABASE", f"postgresql://argus:{SECRET}@127.0.0.1/argus", "database"),
        ("env", "ARGUS_HISTORY", "30d", "history"),
    ],
    ids=["dsn-in-dotenv", "dsn-in-env", "history-scalar"],
)
def test_scalar_value_for_a_settings_section_is_a_config_error(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
    key: str,
    value: str,
    section: str,
) -> None:
    """``ARGUS_DATABASE=<DSN>`` (DATABASE_URL habit) or ``ARGUS_HISTORY=30d`` are plain mistakes."""
    config = _good_config(write_config)
    if source == "dotenv":
        (tmp_path / ".env").write_text(f"{key}={value}\n")
    else:
        monkeypatch.setenv(key, value)
    result = _invoke("config", "validate", "-c", str(config))
    stderr = _assert_clean_error(result, 2, single_line=False)
    assert section in stderr


@pytest.mark.parametrize(
    "text", ["on: true\n", "1: x\n", "~: x\n"], ids=["yaml11-on", "int-key", "null-key"]
)
def test_non_string_top_level_yaml_key_is_a_config_error(
    write_config,  # type: ignore[no-untyped-def]
    text: str,
) -> None:
    result = _invoke("config", "validate", "-c", str(write_config(text)))
    _assert_clean_error(result, 2, single_line=False)


# --------------------------------------------------------------------------- missing password


@pytest.mark.parametrize("command", DB_COMMANDS, ids=_ids(DB_COMMANDS))
def test_db_commands_without_password_are_config_errors(
    write_config,  # type: ignore[no-untyped-def]
    command: list[str],
) -> None:
    result = _invoke(*command, "-c", str(_good_config(write_config)))
    stderr = _assert_clean_error(result, 2)
    assert "password is not set" in stderr


def _argus_script() -> list[str]:
    script = Path(sys.executable).parent / "argus"
    if script.is_file():
        return [str(script)]
    return [sys.executable, "-c", "from argus.cli import main; main()"]


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("ARGUS_")}
    env.pop("TYPER_STANDARD_TRACEBACK", None)
    env["COLUMNS"] = "120"
    return env


def test_real_cli_process_prints_no_traceback_without_password(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """What a user actually sees from ``argus db current`` before filling in .env."""
    config = _good_config(write_config)
    completed = subprocess.run(  # noqa: S603 - local console script, no network (no password)
        [*_argus_script(), "db", "current", "-c", str(config)],
        cwd=tmp_path,
        env=_clean_env(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert "Traceback" not in completed.stderr, completed.stderr[-1500:]
    assert completed.returncode == 2
    assert completed.stderr.strip().startswith("error:")


def test_real_cli_process_config_error_is_one_line(tmp_path: Path) -> None:
    completed = subprocess.run(  # noqa: S603 - local console script, no network
        [*_argus_script(), "config", "validate", "-c", str(tmp_path / "absent.yaml")],
        cwd=tmp_path,
        env=_clean_env(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 2
    lines = [line for line in completed.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, lines
    assert lines[0].startswith("error: config file not found")
    assert completed.stdout == ""


# --------------------------------------------------------------------------- unreachable DB


def test_downgrade_with_unreachable_database_is_an_operational_error(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    (tmp_path / ".env").write_text(BOTH_PASSWORDS)
    result = _invoke("db", "downgrade", "base", "--yes", "-c", str(_good_config(write_config)))
    stderr = _assert_clean_error(result, 1)
    assert "cannot connect" in stderr
    assert OWNER_SECRET not in result.output


def test_downgrade_without_yes_refuses_before_touching_the_database(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    local = _Listener("127.0.0.1")
    try:
        config = write_config(
            f"database:\n  port: {local.port}\n  connect_timeout: 1s\nlogging:\n  level: WARNING\n"
        )
        (tmp_path / ".env").write_text(BOTH_PASSWORDS)
        result = _invoke("db", "downgrade", "base", "-c", str(config))
    finally:
        connections = local.close()
    assert _uncaught(result) is None
    assert result.exit_code == 2, result.output
    assert "--yes" in result.stderr
    assert SECRET not in result.output
    assert connections == 0, "downgrade without --yes connected to the database"


@pytest.mark.parametrize("source", ["yaml", "env", "dotenv"])
def test_config_show_masks_the_password_from_every_source(
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: str,
) -> None:
    text = "logging:\n  level: WARNING\n"
    if source == "yaml":
        text += f"database:\n  password: '{SECRET}'\n  owner_password: '{OWNER_SECRET}'\n"
    elif source == "env":
        monkeypatch.setenv("ARGUS_DATABASE__PASSWORD", SECRET)
        monkeypatch.setenv("ARGUS_DATABASE__OWNER_PASSWORD", OWNER_SECRET)
    else:
        (tmp_path / ".env").write_text(BOTH_PASSWORDS)
    for command in (["config", "show"], ["config", "validate"]):
        result = _invoke(*command, "-c", str(write_config(text)))
        assert result.exit_code == 0, result.output
        assert SECRET not in result.output
        assert OWNER_SECRET not in result.output
    shown = _invoke("config", "show", "-c", str(write_config(text))).output
    assert "password: '**********'" in shown
    assert "owner_password: '**********'" in shown


# --------------------------------------------------------------------------- guard helpers


class _Listener:
    """Local TCP listener that counts every connection that reaches it."""

    def __init__(self, host: str) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((host, 0))
        self._sock.listen(16)
        self._sock.settimeout(0.05)
        self.port = int(self._sock.getsockname()[1])
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            self.accepted += 1
            conn.close()

    def close(self) -> int:
        if not self._stop.is_set():
            time.sleep(0.2)  # let any queued connection be accepted and counted
            self._stop.set()
            self._thread.join(timeout=2)
            self._sock.close()
        return self.accepted


@pytest.fixture
def guard_on(pytestconfig: pytest.Config) -> None:
    if pytestconfig.getoption("--run-live"):
        pytest.skip("the guard is intentionally off with --run-live")
    assert guard._GUARD_STATE["active"]


@pytest.fixture
def stand_in(guard_on: None, monkeypatch: pytest.MonkeyPatch) -> str:
    """Treat 127.0.0.2 as a production host for this test (the SIEM stays guarded as well)."""
    try:
        with socket.socket() as probe:
            probe.bind((STAND_IN, 0))
    except OSError:
        pytest.skip("127.0.0.2 is not a usable loopback address on this machine")
    monkeypatch.setattr(guard, "PRODUCTION_HOSTS", guard.PRODUCTION_HOSTS | {STAND_IN})
    return STAND_IN


@pytest.fixture
def listener(stand_in: str) -> Iterator[_Listener]:
    srv = _Listener(stand_in)
    try:
        yield srv
    finally:
        srv.close()


@pytest.fixture
def udp_receiver(stand_in: str) -> Iterator[socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((stand_in, 0))
    sock.settimeout(0.3)
    try:
        yield sock
    finally:
        sock.close()


def _datagram_arrived(receiver: socket.socket) -> bool:
    try:
        receiver.recvfrom(2048)
    except TimeoutError:
        return False
    return True


# --------------------------------------------------------------------------- guard: lock-in


def test_control_stand_in_is_blocked_like_production(listener: _Listener) -> None:
    """Methodology check: with the stand-in added, a plain connect is blocked before any I/O."""
    with socket.socket() as sock:
        sock.settimeout(2)
        with pytest.raises(ProductionAccessBlockedError):
            sock.connect((STAND_IN, listener.port))
    assert listener.close() == 0


@pytest.mark.parametrize(
    "encoded",
    [
        "0xa.0x14.0x3c.0xb",  # hex dotted
        "012.024.074.013",  # octal dotted
        "169098251",  # 32-bit integer (10.20.60.11)
        "0xa143c0b",  # 32-bit hex
        "10.1326091",  # a.b form
        "10.20.15371",  # a.b.c form
    ],
)
def test_numeric_encodings_of_production_are_recognised(guard_on: None, encoded: str) -> None:
    try:  # only forms the C library itself parses as numbers can reach anything
        socket.getaddrinfo(encoded, None, flags=socket.AI_NUMERICHOST)
    except socket.gaierror:
        pytest.skip(f"this libc does not parse {encoded!r} as an address")
    assert production_target((encoded, 9200)) == SIEM


@pytest.mark.parametrize(
    "mapped",
    [
        "::FFFF:10.20.60.11",
        "::ffff:a14:3c0b",
        "0:0:0:0:0:ffff:0a14:3c0b",
        "::ffff:10.20.60.11%lo",
    ],
)
def test_ipv4_mapped_forms_of_production_are_recognised(guard_on: None, mapped: str) -> None:
    assert production_target((mapped, 9200, 0, 0)) == SIEM


def test_hex_encoded_stand_in_is_blocked_on_a_real_socket(listener: _Listener) -> None:
    with socket.socket() as sock:
        sock.settimeout(2)
        with pytest.raises(ProductionAccessBlockedError):
            sock.connect(("0x7f.0.0.2", listener.port))
    assert listener.close() == 0


def test_urllib_to_production_is_blocked_before_any_io(listener: _Listener) -> None:
    with pytest.raises(urllib.error.URLError) as info:
        urllib.request.urlopen(f"http://{STAND_IN}:{listener.port}/", timeout=2)
    assert isinstance(info.value.reason, ProductionAccessBlockedError)
    assert listener.close() == 0


# --------------------------------------------------------------------------- guard: gaps


def test_udp_sendto_to_production_is_blocked(stand_in: str, udp_receiver: socket.socket) -> None:
    port = udp_receiver.getsockname()[1]
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        contextlib.suppress(ProductionAccessBlockedError),
    ):
        sock.sendto(b"syslog line", (stand_in, port))
    assert not _datagram_arrived(udp_receiver), "UDP sendto() reached the production host"


def test_udp_sendmsg_to_production_is_blocked(stand_in: str, udp_receiver: socket.socket) -> None:
    port = udp_receiver.getsockname()[1]
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock,
        contextlib.suppress(ProductionAccessBlockedError),
    ):
        sock.sendmsg([b"syslog line"], [], 0, (stand_in, port))
    assert not _datagram_arrived(udp_receiver), "UDP sendmsg() reached the production host"


async def test_asyncio_datagram_endpoint_sendto_never_reaches_production(
    stand_in: str, udp_receiver: socket.socket
) -> None:
    port = udp_receiver.getsockname()[1]
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0)
    )
    try:
        transport.sendto(b"syslog line", (stand_in, port))
        await asyncio.sleep(0.05)
    finally:
        transport.close()
    assert not _datagram_arrived(udp_receiver), "asyncio datagram reached the production host"


def _tcp_fast_open_client_enabled() -> bool:
    try:
        flags = int(Path("/proc/sys/net/ipv4/tcp_fastopen").read_text().strip())
    except (OSError, ValueError):
        return False
    return hasattr(socket, "MSG_FASTOPEN") and bool(flags & 1)


def test_tcp_fast_open_to_production_is_blocked(listener: _Listener) -> None:
    """sendto(MSG_FASTOPEN) opens a TCP connection without ever calling connect()."""
    if not _tcp_fast_open_client_enabled():
        pytest.skip("TCP Fast Open (client) is not enabled on this host")
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        contextlib.suppress(ProductionAccessBlockedError),
    ):
        sock.sendto(b"GET / HTTP/1.0\r\n\r\n", socket.MSG_FASTOPEN, (STAND_IN, listener.port))
    assert listener.close() == 0, "a TCP connection reached the production host"


@pytest.mark.parametrize("encode", [bytes, bytearray])
def test_bytes_host_is_recognised_as_production(guard_on: None, encode: type) -> None:
    """socket.connect() accepts bytes/bytearray hosts; the guard returns None for them."""
    assert production_target((encode(SIEM.encode()), 9200)) == SIEM


def test_connect_with_bytes_host_to_production_is_blocked(listener: _Listener) -> None:
    with socket.socket() as sock:
        sock.settimeout(2)
        with contextlib.suppress(ProductionAccessBlockedError):
            sock.connect((STAND_IN.encode(), listener.port))
    assert listener.close() == 0, "connect((b'host', port)) reached the production host"


def test_cli_database_connection_to_production_host_is_blocked(
    listener: _Listener,
    write_config,  # type: ignore[no-untyped-def]
    tmp_path: Path,
) -> None:
    """libpq (psycopg's C library) opens its own sockets; the audit hook never sees them."""
    config = write_config(
        f"database:\n  host: '{STAND_IN}'\n  port: {listener.port}\n  connect_timeout: 1s\n"
        "logging:\n  level: WARNING\n"
    )
    (tmp_path / ".env").write_text(BOTH_PASSWORDS)
    result = _invoke("db", "current", "-c", str(config))
    assert result.exit_code == 1, result.output  # it got as far as connecting, and was refused
    assert SECRET not in result.output
    assert OWNER_SECRET not in result.output
    assert listener.close() == 0, "argus db current opened a TCP connection to production"


_CHILD = (
    "import socket, sys\n"
    "socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=2).close()\n"
)


@pytest.mark.parametrize("spawn", ["subprocess.run", "os.system"])
def test_child_process_aimed_at_production_cannot_reach_it(listener: _Listener, spawn: str) -> None:
    argv = [sys.executable, "-c", _CHILD, STAND_IN, str(listener.port)]
    with contextlib.suppress(ProductionAccessBlockedError):
        if spawn == "subprocess.run":
            subprocess.run(argv, check=False, timeout=15, capture_output=True)  # noqa: S603
        else:
            os.system(shlex.join(argv) + " >/dev/null 2>&1")  # noqa: S605
    assert listener.close() == 0, f"a child started with {spawn} reached the production host"


@pytest.mark.parametrize(
    ("event", "args"),
    [
        (
            "subprocess.Popen",
            ("curl", ["curl", "-s", f"http://{SIEM}:9200/_cluster/health"], None, None),
        ),
        ("subprocess.Popen", ("ssh", ["ssh", f"admin@{SIEM}", "uptime"], None, None)),
        ("os.system", (f"curl -s http://{SIEM}:9200/".encode(),)),
    ],
    ids=["popen-curl", "popen-ssh", "os-system-curl"],
)
def test_spawning_a_command_aimed_at_production_is_blocked(
    guard_on: None, event: str, args: tuple[object, ...]
) -> None:
    """Decision only: the guard's audit hook is called directly, nothing is spawned."""
    with pytest.raises(ProductionAccessBlockedError):
        guard._audit_hook(event, args)


def test_guard_is_active_while_test_modules_are_imported(pytestconfig: pytest.Config) -> None:
    """Module-level code (e.g. a ``skipif`` that pings the SIEM) runs during collection."""
    if pytestconfig.getoption("--run-live"):
        pytest.skip("the guard is intentionally off with --run-live")
    assert _GUARD_AT_IMPORT["installed"], "audit hook not installed during collection"
    assert _GUARD_AT_IMPORT["active"], "guard inactive during collection"


def test_guard_probe_active_during_a_unit_test() -> None:
    """Probe used by the next test; a non-live test must always run with the guard on."""
    assert guard._GUARD_STATE["active"], "network guard is off during a non-live test"


def test_run_live_keeps_the_guard_on_for_non_live_tests(tmp_path: Path) -> None:
    """``pytest --run-live`` without ``-m live`` runs every unit test unguarded.

    test_network_guard.py then really connects to the SIEM :9200/:5601/:22. Here only the
    probe above (no network I/O) is run in a child pytest with ``--run-live``. The child has
    its own base temp directory: one that shares pytest's removes the older ones at start, and
    with another suite running at the same time that races a cleanup (``Directory not empty``)
    and fails a child whose test passed.
    """
    node = f"{Path(__file__).relative_to(REPO_ROOT)}::test_guard_probe_active_during_a_unit_test"
    # Only this one no-network probe may run: drop inherited PYTEST_ADDOPTS/PYTEST_PLUGINS.
    env = {k: v for k, v in _clean_env().items() if not k.upper().startswith("PYTEST_")}
    completed = subprocess.run(  # noqa: S603 - local pytest, one probe test, no network
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            "--run-live",
            f"--basetemp={tmp_path / 'child'}",
            node,
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout[-1500:]
