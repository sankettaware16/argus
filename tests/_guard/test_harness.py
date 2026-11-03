"""Self-tests of the test harness: the network guard and the integration database helpers.

tests/unit/test_network_guard.py and tests/unit/adversarial/test_adv_cli_guard.py cover the
production SIEM. These cover default-deny (only loopback and Unix sockets), the psycopg check
(including the developer's own database), command lines naming production, Python child
processes, the live-test switch and its lock, and keeping the database passwords out of reports.
Destinations are loopback stand-ins and RFC 5737 / RFC 3849 documentation addresses, which are
not routed even if the guard failed; passwords are made up. Nested pytest runs are in
test_nested_runs.py, the Hypothesis profiles in test_hypothesis_profiles.py.
"""

from __future__ import annotations

import contextlib
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import warnings
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import psycopg
import pytest
from pydantic import SecretStr

import tests.conftest as harness
from tests.conftest import NetworkAccessBlockedError, ProductionAccessBlockedError

netguard = harness._netguard
TEST_NET = "192.0.2.1"  # RFC 5737 documentation address
TEST_NET6 = "2001:db8::1"  # RFC 3849 documentation address
_PG_VARIABLES = ("PGHOST", "PGHOSTADDR", "PGSERVICE")
# Every variable libpq takes a connection default from, for the tests that rely on defaults.
_LIBPQ_DEFAULTS = (*_PG_VARIABLES, "PGPORT", "PGDATABASE", "PGUSER")
STAND_IN_DATABASE = "argus_guard_stand_in"  # protected like the developer's database, per test


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def closed_port() -> int:
    return _closed_port()


@pytest.fixture
def no_libpq_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PG_VARIABLES:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def no_libpq_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _LIBPQ_DEFAULTS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def liftable() -> None:
    """For tests that lift the guard: skipped in a run that a guarded process started (this
    suite run from a guarded test, or with PYTEST_ARGUS_NETGUARD set), where it is locked on."""
    if harness._GUARD_STATE["locked"]:
        pytest.skip("this run was started by a guarded process: its guard cannot be lifted")


@pytest.fixture
def protected_port(monkeypatch: pytest.MonkeyPatch, closed_port: int) -> int:
    """A closed local port on which STAND_IN_DATABASE is protected like the developer's database.

    Nothing listens there, so a connection the guard lets through fails in libpq instead.
    """
    stand_in = (STAND_IN_DATABASE, closed_port)
    monkeypatch.setattr(harness, "PROTECTED_DATABASES", harness.PROTECTED_DATABASES | {stand_in})
    return closed_port


@pytest.fixture
def password() -> SecretStr:
    """A made-up password, kept in a SecretStr so that no frame of the test shows its value."""
    return SecretStr(f"pw-{secrets.token_urlsafe(12)}")


# --------------------------------------------------------------------------- default deny


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, (TEST_NET, 9)),
        (socket.AF_INET, ("203.0.113.9", 443)),
        (socket.AF_INET6, (TEST_NET6, 9, 0, 0)),
        (socket.AF_INET6, (f"::ffff:{TEST_NET}", 9, 0, 0)),
    ],
    ids=["ipv4", "ipv4-https", "ipv6", "ipv4-mapped"],
)
@pytest.mark.parametrize("operation", ["tcp-connect", "udp-sendto", "udp-sendmsg"])
def test_non_loopback_destinations_are_refused(
    family: int, address: tuple[Any, ...], operation: str
) -> None:
    kind = socket.SOCK_STREAM if operation == "tcp-connect" else socket.SOCK_DGRAM
    try:
        sock = socket.socket(family, kind)
    except OSError:
        pytest.skip("address family not available on this machine")
    with sock:
        sock.settimeout(0.5)
        with pytest.raises(NetworkAccessBlockedError, match="not a loopback address") as info:
            _reach(sock, operation, address)
    assert not isinstance(info.value, ProductionAccessBlockedError)


def _reach(sock: socket.socket, operation: str, address: tuple[Any, ...]) -> None:
    if operation == "tcp-connect":
        sock.connect(address)
    elif operation == "udp-sendto":
        sock.sendto(b"x", address)
    else:
        sock.sendmsg([b"x"], [], 0, address)


@pytest.mark.parametrize("host", ["127.0.0.1", "127.0.0.9", "::1", "localhost", b"127.0.0.1"])
def test_loopback_hosts_are_allowed(host: object) -> None:
    netguard.check_host(host, harness.PRODUCTION_HOSTS)


@pytest.mark.parametrize(
    "host",
    [
        TEST_NET,
        TEST_NET6,
        f"::ffff:{TEST_NET}",
        "fe80::1%lo",
        "0.0.0.0",  # noqa: S104 - a destination here, nothing binds to it
        "",
        b"\xff\xfe",
        42,
    ],
    ids=["ipv4", "ipv6", "mapped", "link-local", "unspecified", "empty", "non-ascii", "int"],
)
def test_other_hosts_are_refused(host: object) -> None:
    with pytest.raises(NetworkAccessBlockedError):
        netguard.check_host(host, harness.PRODUCTION_HOSTS)


def test_a_name_that_cannot_be_resolved_is_refused() -> None:
    def failing(host: str, port: object) -> list[Any]:
        raise socket.gaierror("no such host")

    with pytest.raises(NetworkAccessBlockedError):
        netguard.check_host("db.example.test", harness.PRODUCTION_HOSTS, failing)


def test_a_name_must_resolve_to_loopback_only() -> None:
    def mixed(host: str, port: object) -> list[Any]:
        stream = (socket.AF_INET, socket.SOCK_STREAM, 6, "")
        return [(*stream, ("127.0.0.1", 0)), (*stream, (TEST_NET, 0))]

    with pytest.raises(NetworkAccessBlockedError):
        netguard.check_host("db.example.test", harness.PRODUCTION_HOSTS, mixed)


def test_loopback_and_unix_sockets_still_work(tmp_path: Path) -> None:
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2):
            pass
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(b"x", ("127.0.0.1", 9))
    path = str(tmp_path / "guard.sock")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(path)
        server.listen(1)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(path)


# --------------------------------------------------------------------------- psycopg / libpq


@pytest.mark.parametrize(
    ("conninfo", "kwargs", "env"),
    [
        ("", {"host": TEST_NET}, {}),
        ("", {"host": f"127.0.0.1,{TEST_NET}"}, {}),
        ("", {"host": "localhost", "hostaddr": TEST_NET}, {}),
        ("", {"service": "argus-prod"}, {}),
        (f"postgresql://u:p@{TEST_NET}:5432/d", {}, {}),
        (f"postgresql://u:p@127.0.0.1:1,{TEST_NET}:2/d", {}, {}),
        (f"host={TEST_NET} dbname=d", {}, {}),
        ("", {}, {"PGHOST": TEST_NET}),
        ("", {"host": "localhost"}, {"PGHOSTADDR": TEST_NET}),
        ("", {"host": "127.0.0.1"}, {"PGSERVICE": "argus-prod"}),
    ],
    ids=[
        "host",
        "host-list",
        "hostaddr",
        "service",
        "uri",
        "uri-multi-host",
        "keywords",
        "PGHOST",
        "PGHOSTADDR",
        "PGSERVICE",
    ],
)
@pytest.mark.parametrize("entry", ["psycopg.connect", "Connection", "AsyncConnection"])
async def test_psycopg_refuses_non_local_servers_before_libpq_runs(
    no_libpq_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    conninfo: str,
    kwargs: dict[str, Any],
    env: dict[str, str],
    entry: str,
) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(NetworkAccessBlockedError):
        await _connect(entry, conninfo, kwargs)


async def _connect(entry: str, conninfo: str, kwargs: dict[str, Any]) -> None:
    if entry == "psycopg.connect":
        psycopg.connect(conninfo, connect_timeout=1, **kwargs).close()
    elif entry == "Connection":
        psycopg.Connection.connect(conninfo, connect_timeout=1, **kwargs).close()
    else:
        await (await psycopg.AsyncConnection.connect(conninfo, connect_timeout=1, **kwargs)).close()


@pytest.mark.parametrize(
    ("kwargs", "env"),
    [
        ({"host": "/nonexistent-socket-dir"}, {}),
        ({"host": "db.invalid", "hostaddr": "127.0.0.1"}, {}),
        ({"host": "127.0.0.1"}, {"PGHOST": TEST_NET}),
        ({"host": "localhost"}, {}),
    ],
    ids=["unix-socket", "hostaddr-decides", "explicit-host-beats-PGHOST", "localhost"],
)
def test_psycopg_local_servers_are_left_to_libpq(
    no_libpq_environment: None,
    monkeypatch: pytest.MonkeyPatch,
    closed_port: int,
    kwargs: dict[str, Any],
    env: dict[str, str],
) -> None:
    """Nothing listens there, so libpq itself fails: the guard did not refuse it."""
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(
            port=closed_port, user="u", password="p", dbname="d", connect_timeout=1, **kwargs
        )


def test_integration_database_host_must_be_local() -> None:
    for host in ("127.0.0.1", "localhost", "::1", "/var/run/postgresql"):
        harness.check_database_host(host)
    with pytest.raises(NetworkAccessBlockedError):
        harness.check_database_host(TEST_NET)


# --------------------------------------------------------------------------- command lines


@pytest.mark.parametrize(
    "command",
    [
        ["ssh", "siemhost", "uptime"],
        ["scp", "dump.json", "admin@siemhost:/tmp/"],
        ["curl", "http://SIEMHOST.example.edu:9200/"],
        "curl -s 'http://10.20.60.11:9200/_cat/indices'",
        [b"psql", b"host=10.20.60.11"],
        [Path("/usr/bin/nc"), "10.20.60.11", "9200"],
        # The address glued to other text: anything but another digit next to it.
        ["bash", "-c", "exec 3<>/dev/tcp/10.20.60.11/9200"],
        ["psql", "-h10.20.60.11"],
        ["curl", "--resolve", "es:9200:10.20.60.11", "http://es:9200/"],
        ["curl", "--connect-to", "::10.20.60.11:9200", "http://es:9200/"],
        ["curl", "-g", "http://[::ffff:10.20.60.11]:9200/"],
        ["ssh", "admin@[10.20.60.11]"],
        ["curl", "http://app.10.20.60.11.nip.io:9200/"],
        # Other spellings the C library reads as the same address.
        ["curl", "http://169098251:9200/"],
        ["curl", "http://0xa143c0b:9200/"],
        ["curl", "http://0xa.0x14.0x3c.0xb:9200/"],
        ["ping", "-c1", "012.024.074.013"],
        ["nc", "10.1326091", "9200"],
        ["nc", "10.20.15371", "9200"],
        ["bash", "-c", "exec 3<>/dev/tcp/169098251/9200"],
        ["psql", "-h0xa143c0b"],
        ["curl", "-g", "http://[::ffff:a14:3c0b]:9200/"],
        ["ssh", "0:0:0:0:0:ffff:0a14:3c0b"],
        # Spellings curl reads as the same host: percent-escapes decoded, then IDNA's mapping
        # (compatibility forms, full stops, default-ignorable characters dropped).
        ["curl", "http://10.20.60.%31%31:9200/"],
        ["curl", "http://10%2E20%2E60%2E11:9200/"],
        ["curl", "http://%31%30.%32%30.%36%30.%31%31:9200/"],
        ["curl", "http://\uff11\uff10.\uff12\uff10.\uff16\uff10.\uff11\uff11:9200/"],
        ["curl", "http://10.20.60.%EF%BC%91%EF%BC%91:9200/"],  # fullwidth digits, escaped
        ["curl", "http://\u2469.\u2461\u24ea.\u2465\u24ea.\u246a:9200/"],  # circled numbers
        ["curl", "http://10\u300220\u300260\u300211:9200/"],  # ideographic full stop
        ["curl", "http://10\uff0e20\uff0e60\uff0e11:9200/"],  # fullwidth full stop
        ["curl", "http://10\uff6120\uff6160\uff6111:9200/"],  # halfwidth ideographic full stop
        ["curl", "http://10.20.60.1\u00ad1:9200/"],  # soft hyphen
        ["curl", "http://10.20.60.1\u200b1:9200/"],  # zero-width space
        ["curl", "http://10.20.6\u200c0.11:9200/"],  # zero-width non-joiner
        ["curl", "http://10.20.6\u200d0.11:9200/"],  # zero-width joiner
        ["curl", "http://10.20.6\u20600.11:9200/"],  # word joiner
        ["curl", "http://10.20.6\ufeff0.11:9200/"],  # zero-width no-break space
        ["curl", "http://10.20.60.1\ufe0f1:9200/"],  # variation selector
        ["curl", "http://10\uff0e1326091:9200/"],  # a numeric form, mapped first
        [b"curl", b"http://10.20.60.%31%31:9200/"],
        [
            "ssh",
            "\uff53\uff49\uff45\uff4d\uff48\uff4f\uff53\uff54",
        ],  # the alias in fullwidth letters
        ["ssh", "%73iemhost"],
        # The alias in other host positions.
        ["bash", "-c", "exec 3<>/dev/tcp/siemhost/9200"],
        ["ssh", "-Jsiemhost", "admin@db.example.test"],
        ["curl", "--connect-to", "::siemhost:9200", "http://es:9200/"],
    ],
)
def test_command_lines_naming_production_are_recognised(command: object) -> None:
    assert netguard.command_target(command, harness.PRODUCTION_HOSTS) is not None


@pytest.mark.parametrize(
    "command",
    [
        ["/home/dev/siemhost/argus/.venv/bin/argus", "doctor"],
        ["pytest", "tests/live/test_siemhost_health.py"],
        ["argus", "-c", "/tmp/pytest-of-dev/pytest-1/test_siemhost_down0/argus.yaml"],
        ["curl", "http://10.20.60.110:9200/"],
        ["ping", "110.20.60.11"],
        ["ping", "210.20.60.11"],
        ["curl", "http://10.20.60.111:9200/"],
        ["seq", "169098250"],  # 10.20.60.10 as an integer
        ["curl", "http://0xa143c0c:9200/"],  # 10.20.60.12
        ["curl", "-g", "http://[::ffff:a14:3c0c]:9200/"],  # 10.20.60.12
        ["cat", "/var/log/siemhost.log", "--siemhost-report"],
        ["curl", "http://10.20.60.%31%31%31:9200/"],  # 10.20.60.111
        ["curl", "http://1\uff11\uff10.20.60.11:9200/"],  # 110.20.60.11
        ["ls", "/home/dev/%73iemhost/"],  # still a path once decoded
    ],
)
def test_command_lines_that_only_look_alike_are_not_refused(command: object) -> None:
    assert netguard.command_target(command, harness.PRODUCTION_HOSTS) is None


def test_a_spawn_naming_production_in_another_spelling_is_refused() -> None:
    """The audit hook applies the same rule: echo would only print it, but it never starts."""
    with pytest.raises(ProductionAccessBlockedError):
        subprocess.run(["/bin/echo", "/dev/tcp/0xa143c0b/9200"], capture_output=True, check=False)
    with pytest.raises(ProductionAccessBlockedError):
        subprocess.run(["/bin/echo", "http://10.20.60.%31%31/"], capture_output=True, check=False)


@pytest.mark.parametrize(
    "argument",
    [
        "%31" * 40_000,  # every escape decoded
        "%" + "25" * 60_000 + "31",  # decoded once, as curl does: not again and again
        "%EF%BC%91" * 14_000,  # escaped fullwidth digits
        "\uff11" * 120_000,  # fullwidth digits
        "\ufdfa" * 20_000,  # NFKC turns each into 18 characters
        "1\u200b" * 60_000,  # an ignorable character between digits
        "\u3002" * 120_000,  # full stops
        "1\uff0e%32\u00ad:" * 20_000,  # all of it, with the IPv6 candidate scan
    ],
    ids=[
        "escapes",
        "nested-escapes",
        "escaped-fullwidth",
        "fullwidth",
        "expanding",
        "ignorable",
        "full-stops",
        "mixed",
    ],
)
def test_host_spellings_are_read_in_linear_time(argument: str) -> None:
    """Arguments of up to about 120,000 characters (Linux allows 128 KiB per argument): reading
    them in quadratic time would take minutes, the linear reading takes a fraction of a second."""
    import time

    started = time.perf_counter()
    assert netguard.command_target(["curl", argument], harness.PRODUCTION_HOSTS) is None
    assert time.perf_counter() - started < 1.5


# --------------------------------------------------------------------------- child processes

_CHILD = """
import json, socket, sys
import argus_netguard as guard
try:
    socket.create_connection((sys.argv[1], 9), timeout=1).close()
    outcome = "connected"
except OSError as exc:
    outcome = type(exc).__name__
print(json.dumps({"guard": guard.__file__, "active": guard.STATE["active"], "outcome": outcome}))
"""


def _run_child(host: str) -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed local script
        [sys.executable, "-c", _CHILD, host],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-1500:]
    report: dict[str, Any] = json.loads(completed.stdout)
    return report


def test_python_children_load_the_guard() -> None:
    report = _run_child(TEST_NET)
    assert Path(report["guard"]).resolve().parent == harness.GUARD_DIR
    assert report["active"] is True
    assert report["outcome"] == "NetworkAccessBlockedError"


_OTHER_PYTHON_CHILD = """
import json, socket, sys
import argus_netguard as guard
with socket.socket() as sock:
    try:
        sys.audit("socket.connect", sock, (sys.argv[1], 9))  # the decision alone, no I/O
        refused = None
    except guard.NetworkAccessBlockedError as refusal:
        refused = type(refusal).__name__
command = ["curl", "http://127.0.0.%32:9200/"]  # a stand-in: this script is a command line
print(json.dumps({
    "version": "%d.%d" % sys.version_info[:2],
    "locked": guard.STATE["locked"],
    "refused": refused,
    "command": guard.command_target(command, {"127.0.0.2"}),
}))
"""


@pytest.mark.parametrize("version", ["3.10", "3.11"])
def test_children_running_an_older_python_load_the_guard(version: str) -> None:
    """argus_netguard.py must stay importable by any Python 3.10+: where it cannot be compiled
    (a possessive regex quantifier, say), the sitecustomize fails and that child runs unguarded."""
    interpreter = shutil.which(f"python{version}")
    if interpreter is None:
        pytest.skip(f"python{version} is not installed")
    completed = subprocess.run(  # noqa: S603 - a local interpreter, a fixed local script
        [interpreter, "-c", _OTHER_PYTHON_CHILD, TEST_NET],
        env=_environment(netguard.describe()),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-1500:]
    assert "Error in sitecustomize" not in completed.stderr
    assert json.loads(completed.stdout) == {
        "version": version,
        "locked": True,
        "refused": "NetworkAccessBlockedError",
        "command": "127.0.0.2",
    }


# echo only prints its arguments, so these stay harmless even if the guard let them through.
_ECHO_PRODUCTION = ["/bin/echo", next(iter(harness.PRODUCTION_HOSTS))]


def _spawn(api: str) -> None:
    if api == "subprocess":
        subprocess.run(_ECHO_PRODUCTION, capture_output=True, check=False)  # noqa: S603
    elif api == "os.system":
        os.system(" ".join(_ECHO_PRODUCTION) + " >/dev/null")  # noqa: S605
    elif api == "os.posix_spawn":
        os.waitpid(os.posix_spawn(_ECHO_PRODUCTION[0], _ECHO_PRODUCTION, os.environ), 0)
    else:
        import pty

        pty.spawn(_ECHO_PRODUCTION)


@pytest.mark.parametrize("api", ["subprocess", "os.system", "os.posix_spawn", "pty.spawn"])
def test_every_spawn_api_is_checked(api: str) -> None:
    with pytest.raises(ProductionAccessBlockedError):
        _spawn(api)


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
def test_a_forked_child_exits_instead_of_exec_ing_a_production_command() -> None:
    """Raising in a forked child would unwind into pytest's own code; it must exit instead."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork() in a threaded process
        pid = os.fork()
    if pid == 0:
        try:
            os.execv(_ECHO_PRODUCTION[0], _ECHO_PRODUCTION)  # noqa: S606 - echo only
        finally:
            os._exit(0)  # reached only if the guard raised instead of exiting
    _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 126


# --------------------------------------------------------------------------- live switch


class _Item:
    """Just enough of a pytest.Item for the harness's live-test switch."""

    def __init__(self, area: str, *, live_marker: bool, run_live: bool) -> None:
        self.path = harness.TESTS_DIR / area / "test_probe.py"
        self.config = SimpleNamespace(getoption=lambda name: run_live)
        self._live_marker = live_marker

    def get_closest_marker(self, name: str) -> object | None:
        return object() if name == "live" and self._live_marker else None


@contextlib.contextmanager
def _running(item: _Item) -> Iterator[None]:
    """The harness's pytest_runtest_protocol wrapper, held open while the 'test' runs."""
    protocol = harness.pytest_runtest_protocol(cast(pytest.Item, item), None)
    next(protocol)
    try:
        yield
    finally:
        with pytest.raises(StopIteration):
            protocol.send(None)


@pytest.mark.parametrize(
    ("area", "live_marker", "run_live", "lifted"),
    [
        ("live", True, True, True),
        ("live", True, False, False),
        ("unit", True, True, False),  # a live marker outside tests/live/ lifts nothing
        ("unit", False, True, False),
        ("integration", False, True, False),
    ],
)
def test_only_live_tests_with_run_live_run_unguarded(
    request: pytest.FixtureRequest, area: str, live_marker: bool, run_live: bool, lifted: bool
) -> None:
    if lifted:
        request.getfixturevalue("liftable")
    with _running(_Item(area, live_marker=live_marker, run_live=run_live)):
        assert harness._GUARD_STATE["active"] is not lifted
        assert json.loads(os.environ[netguard.ENV_VAR])["active"] is not lifted
    assert harness._GUARD_STATE["active"] is True
    assert json.loads(os.environ[netguard.ENV_VAR])["active"] is True


def test_python_children_of_a_live_test_run_unguarded(liftable: None) -> None:
    with _running(_Item("live", live_marker=True, run_live=True)):
        inside = _run_child("127.0.0.1")
    assert inside["active"] is False
    assert _run_child("127.0.0.1")["active"] is True


def test_a_locked_guard_is_never_lifted(monkeypatch: pytest.MonkeyPatch) -> None:
    """In a run that a guarded process started, even a live test with --run-live stays guarded."""
    monkeypatch.setitem(harness._GUARD_STATE, "locked", True)
    with _running(_Item("live", live_marker=True, run_live=True)):
        assert harness._GUARD_STATE["active"] is True
        assert json.loads(os.environ[netguard.ENV_VAR])["active"] is True
    netguard.set_active(False)
    assert harness._GUARD_STATE["active"] is True


def _run_python(code: str, env: dict[str, str]) -> dict[str, Any]:
    completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed local script
        [sys.executable, "-c", code],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-1500:]
    report: dict[str, Any] = json.loads(completed.stdout)
    return report


def _environment(description: str | None) -> dict[str, str]:
    """This process's environment, with ``description`` as the guard a child inherits."""
    env = {name: value for name, value in os.environ.items() if name != netguard.ENV_VAR}
    if description is not None:
        env[netguard.ENV_VAR] = description
    return env


_LIFT_IN_CHILD = """
import json
import argus_netguard as guard
guard.set_active(False)  # what a nested pytest run does around its live tests
print(json.dumps({"locked": guard.STATE["locked"], "active": guard.STATE["active"]}))
"""


@pytest.mark.parametrize(
    ("description", "locked"),
    [
        ('{"active": true, "production_hosts": [], "protected_databases": []}', True),
        (None, True),  # no description: the guard is on
        ("not json", True),
        ('{"active": true, "protected_databases": "argus"}', True),  # malformed: fail closed
        ('{"active": false, "production_hosts": [], "protected_databases": []}', False),
    ],
    ids=["guarded-parent", "missing", "unreadable", "malformed", "live-test-parent"],
)
def test_a_child_cannot_lift_a_guard_it_inherited_switched_on(
    description: str | None, locked: bool
) -> None:
    """Only a parent that had lifted the guard (a live test) starts children without it."""
    report = _run_python(_LIFT_IN_CHILD, _environment(description))
    assert report == {"locked": locked, "active": locked}


_NESTED_CONFTEST_IN_CHILD = """
import argus_netguard as guard
guard.install(lambda: guard.PRODUCTION_HOSTS, lambda: frozenset())  # a nested run's conftest
print(guard.describe())
"""


def test_a_nested_run_keeps_what_its_parent_protects() -> None:
    parent = {
        "active": True,
        "production_hosts": ["127.0.0.2", *harness.PRODUCTION_HOSTS],
        "protected_databases": [[STAND_IN_DATABASE, 6543]],
    }
    report = _run_python(_NESTED_CONFTEST_IN_CHILD, _environment(json.dumps(parent)))
    assert "127.0.0.2" in report["production_hosts"]
    assert [STAND_IN_DATABASE, 6543] in report["protected_databases"]


def test_a_run_configured_inside_a_guarded_test_cannot_lift_the_guard(
    pytestconfig: pytest.Config,
) -> None:
    """pytest.main() inside a test: its live tests stay guarded, and when it ends it leaves this
    run's environment (tests/_guard on PYTHONPATH, the guard's description) as it was."""
    watched = ("PYTHONPATH", netguard.ENV_VAR)
    before = {name: os.environ.get(name) for name in watched}
    locked_before = harness._GUARD_STATE["locked"]
    harness.pytest_configure(pytestconfig)  # what the nested run does first
    try:
        assert harness._GUARD_STATE["locked"] is True
        with _running(_Item("live", live_marker=True, run_live=True)):
            assert harness._GUARD_STATE["active"] is True
    finally:
        harness.pytest_unconfigure(pytestconfig)
    assert harness._GUARD_STATE["locked"] is locked_before
    assert {name: os.environ.get(name) for name in watched} == before
    assert str(harness.GUARD_DIR) in os.environ["PYTHONPATH"].split(os.pathsep)


def _no_option(name: str, default: object = None) -> object:
    return default


def _run_config() -> pytest.Config:
    """Just enough of a pytest.Config for the harness's pytest_configure and pytest_unconfigure."""
    return cast(pytest.Config, SimpleNamespace(stash=pytest.Stash(), getoption=_no_option))


def test_a_run_nested_in_a_live_test_may_lift_the_guard_and_gives_it_back(
    liftable: None,
) -> None:
    """A live test runs without the guard, and so may a run nested in it; when that run ends the
    live test is unguarded again, as it was (its own children included)."""
    with _running(_Item("live", live_marker=True, run_live=True)):
        nested = _run_config()
        harness.pytest_configure(nested)
        try:
            assert harness._GUARD_STATE == {"active": True, "installed": True, "locked": False}
        finally:
            harness.pytest_unconfigure(nested)
        assert harness._GUARD_STATE["active"] is False
        assert json.loads(os.environ[netguard.ENV_VAR])["active"] is False
    assert harness._GUARD_STATE["active"] is True


def test_ending_a_run_that_never_began_changes_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """pytest unconfigures a run whose configuration failed before the harness's turn (a usage
    error, say): that must not end the run around it, unlocking the guard."""
    monkeypatch.setitem(harness._GUARD_STATE, "locked", True)
    monkeypatch.setenv("PYTHONPATH", "/stand-in")
    harness.pytest_unconfigure(_run_config())
    assert harness._GUARD_STATE["locked"] is True
    assert os.environ["PYTHONPATH"] == "/stand-in"


# --------------------------------------------------------------------- the developer's database


def _protected_targets(port: int) -> dict[str, tuple[str, dict[str, Any], dict[str, str]]]:
    """Ways to name STAND_IN_DATABASE on ``port``: (conninfo, keyword arguments, environment)."""
    name = STAND_IN_DATABASE
    local = {"host": "127.0.0.1"}
    return {
        "dbname": ("", {**local, "port": port, "dbname": name}, {}),
        "keywords": (f"host=127.0.0.1 port={port} dbname={name}", {}, {}),
        "uri": (f"postgresql://u@127.0.0.1:{port}/{name}", {}, {}),
        "unix-socket": ("", {"host": "/nonexistent-socket-dir", "port": port, "dbname": name}, {}),
        "user-names-the-database": ("", {**local, "port": port, "user": name}, {}),
        "empty-dbname-means-user": ("", {**local, "port": port, "user": name, "dbname": ""}, {}),
        "PGDATABASE": ("", {**local, "port": port}, {"PGDATABASE": name}),
        "PGUSER": ("", {**local, "port": port}, {"PGUSER": name}),
        "PGPORT": ("", {**local, "dbname": name}, {"PGPORT": str(port)}),
        "port-list": ("", {"host": "127.0.0.1,127.0.0.1", "port": f"1,{port}", "dbname": name}, {}),
        "zero-padded-port": ("", {**local, "port": f"0{port}", "dbname": name}, {}),
    }


@pytest.mark.parametrize("case", list(_protected_targets(0)))
@pytest.mark.parametrize("entry", ["psycopg.connect", "Connection", "AsyncConnection"])
async def test_psycopg_refuses_the_developers_database(
    no_libpq_defaults: None,
    monkeypatch: pytest.MonkeyPatch,
    protected_port: int,
    case: str,
    entry: str,
) -> None:
    """A backstop for a test that forgets its throwaway database, whatever names the database."""
    conninfo, kwargs, env = _protected_targets(protected_port)[case]
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(NetworkAccessBlockedError, match="the developer's own"):
        await _connect(entry, conninfo, {"password": "p", **kwargs})


@pytest.mark.parametrize(
    "case",
    [
        "other-database",
        "other-port",
        "explicit-port-beats-PGPORT",
        "explicit-dbname-beats-PGDATABASE",
        "explicit-user-beats-PGUSER",
    ],
)
def test_psycopg_leaves_other_databases_to_libpq(
    no_libpq_defaults: None, monkeypatch: pytest.MonkeyPatch, protected_port: int, case: str
) -> None:
    """Nothing listens on either port, so libpq itself fails: the guard did not refuse it."""
    other_port = _closed_port()
    while other_port == protected_port:  # the OS may hand out the same free port twice
        other_port = _closed_port()
    name, other = STAND_IN_DATABASE, "argus_guard_other"
    conninfo, kwargs, env = {
        "other-database": ("", {"port": protected_port, "dbname": other}, {}),
        "other-port": ("", {"port": other_port, "dbname": name}, {}),
        "explicit-port-beats-PGPORT": (
            "",
            {"port": other_port, "dbname": name},
            {"PGPORT": str(protected_port)},
        ),
        "explicit-dbname-beats-PGDATABASE": (
            "",
            {"port": protected_port, "dbname": other},
            {"PGDATABASE": name},
        ),
        "explicit-user-beats-PGUSER": (
            "",
            {"port": protected_port, "user": other},
            {"PGUSER": name},
        ),
    }[case]
    for variable, value in env.items():
        monkeypatch.setenv(variable, value)
    params: dict[str, Any] = {"host": "127.0.0.1", "user": "u", "password": "p", **kwargs}
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(conninfo, connect_timeout=1, **params)


def test_the_developers_database_is_left_to_libpq_while_the_guard_is_lifted(
    liftable: None, no_libpq_defaults: None, protected_port: int
) -> None:
    """Live tests run without the guard, and so without this backstop."""
    with (
        _running(_Item("live", live_marker=True, run_live=True)),
        pytest.raises(psycopg.OperationalError),
    ):
        psycopg.connect(
            host="127.0.0.1",
            port=protected_port,
            dbname=STAND_IN_DATABASE,
            user="u",
            password="p",
            connect_timeout=1,
        )


def test_the_developers_database_is_protected_in_this_run_and_its_children() -> None:
    developer = [harness.DEFAULT_DATABASE, harness.DEFAULT_DATABASE_PORT]
    assert tuple(developer) in harness.PROTECTED_DATABASES
    assert developer in json.loads(os.environ[netguard.ENV_VAR])["protected_databases"]
    for name, port in harness.PROTECTED_DATABASES:  # asks the guard only: nothing connects
        target = {"host": "127.0.0.1", "port": port, "dbname": name}
        assert isinstance(netguard._psycopg_refusal("", target), NetworkAccessBlockedError)


def test_the_harness_defaults_are_the_settings_defaults() -> None:
    from argus.config import DatabaseSettings

    assert DatabaseSettings.model_fields["name"].default == harness.DEFAULT_DATABASE
    assert DatabaseSettings.model_fields["port"].default == harness.DEFAULT_DATABASE_PORT


def test_the_developers_database_comes_from_the_env_file(tmp_path: Path) -> None:
    default, port = harness.DEFAULT_DATABASE, harness.DEFAULT_DATABASE_PORT
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ARGUS_DATABASE__USER=someone\n"
        "argus_database__name=devdb\n"  # the settings read names in any case
        "ARGUS_DATABASE__PORT=6543\n"
        "OTHER_TOOL_NAME=not-a-database\n",
        encoding="utf-8",
    )
    assert harness.developer_databases(env_file) == {
        (default, port),
        (default, 6543),
        ("devdb", port),
        ("devdb", 6543),
    }
    env_file.write_text('ARGUS_DATABASE={"name": "jsondb", "port": 7000}\n', encoding="utf-8")
    assert ("jsondb", 7000) in harness.developer_databases(env_file)
    assert harness.developer_databases(tmp_path / "absent.env") == {(default, port)}


_DATABASE_IN_CHILD = """
import json, sys
import psycopg
outcomes = []
for name in sys.argv[2:]:
    try:
        psycopg.connect(
            host="127.0.0.1", port=int(sys.argv[1]), dbname=name, user="u", password="p",
            connect_timeout=1,
        ).close()
        outcomes.append("connected")
    except Exception as exc:
        outcomes.append(type(exc).__name__)
print(json.dumps({"outcomes": outcomes}))
"""


def test_python_children_refuse_the_developers_database(
    no_libpq_defaults: None, protected_port: int
) -> None:
    """The protected databases travel with the guard, so the ``argus`` CLI as a child is covered."""
    names = [STAND_IN_DATABASE, "argus_guard_other"]
    completed = subprocess.run(  # noqa: S603 - this interpreter, a fixed local script
        [sys.executable, "-c", _DATABASE_IN_CHILD, str(protected_port), *names],
        env=_environment(netguard.describe()),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr[-1500:]
    outcomes = json.loads(completed.stdout)["outcomes"]
    assert outcomes == ["NetworkAccessBlockedError", "OperationalError"]


# ---------------------------------------------------------------------- the password in reports


def _rendered(info: pytest.ExceptionInfo[BaseException]) -> str:
    """The failure as pytest reports it with every option that shows more (-vv -l --tb=long
    --full-trace): each frame's arguments and locals, and every chained exception."""
    representation = info.getrepr(
        showlocals=True,
        style="long",
        tbfilter=False,
        funcargs=True,
        truncate_locals=False,
        truncate_args=False,
        chain=True,
    )
    return str(representation)


@pytest.mark.parametrize(
    ("host", "reason"),
    [
        ("127.0.0.1", "local Postgres unreachable"),
        (TEST_NET, "cannot connect to the local Postgres"),
    ],
    ids=["libpq-refuses", "guard-refuses"],
)
def test_a_refused_admin_connection_does_not_echo_the_password(
    no_libpq_defaults: None, closed_port: int, password: SecretStr, host: str, reason: str
) -> None:
    from argus.config import DatabaseSettings
    from tests.integration.conftest import admin_connect

    settings = DatabaseSettings(host=host, port=closed_port, owner_password=password)
    with pytest.raises(pytest.fail.Exception) as info:
        admin_connect(settings)  # logs in as the owner (D-029)
    assert reason in str(info.value)
    assert info.value.pytrace is False  # reported as the message alone
    assert info.value.__context__ is None  # nothing chained: psycopg's frames hold the password
    assert info.value.__cause__ is None
    assert password.get_secret_value() not in _rendered(info)


def _connect_with(entry: str, host: str, port: int, password: SecretStr) -> None:
    """Connect with the password's value only inline: this frame holds just the SecretStr."""
    if entry == "conninfo":
        psycopg.connect(
            f"host={host} port={port} user=u password={password.get_secret_value()} dbname=d"
            " connect_timeout=1"
        )
        return
    connect = psycopg.connect if entry == "psycopg.connect" else psycopg.Connection.connect
    connect(
        host=host,
        port=port,
        user="u",
        password=password.get_secret_value(),
        dbname="d",
        connect_timeout=1,
    )


@pytest.mark.parametrize("host", ["127.0.0.1", TEST_NET], ids=["libpq-refuses", "guard-refuses"])
@pytest.mark.parametrize("entry", ["psycopg.connect", "Connection.connect", "conninfo"])
def test_a_refused_psycopg_connection_does_not_echo_the_password(
    no_libpq_defaults: None, closed_port: int, password: SecretStr, host: str, entry: str
) -> None:
    """No frame of the traceback holds the connection parameters: not psycopg's, not the guard's."""
    with pytest.raises((psycopg.OperationalError, NetworkAccessBlockedError)) as info:
        _connect_with(entry, host, closed_port, password)
    assert password.get_secret_value() not in _rendered(info)


@pytest.mark.parametrize("host", ["127.0.0.1", TEST_NET], ids=["libpq-refuses", "guard-refuses"])
async def test_a_refused_async_psycopg_connection_does_not_echo_the_password(
    no_libpq_defaults: None, closed_port: int, password: SecretStr, host: str
) -> None:
    with pytest.raises((psycopg.OperationalError, NetworkAccessBlockedError)) as info:
        await psycopg.AsyncConnection.connect(
            host=host,
            port=closed_port,
            user="u",
            password=password.get_secret_value(),
            dbname="d",
            connect_timeout=1,
        )
    assert password.get_secret_value() not in _rendered(info)


def test_hidden_secrets_are_masked_in_every_part_of_a_report(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(harness, "_HIDDEN_IN_REPORTS", set())
    secret = "pw'with\\escapes-" + secrets.token_hex(4)  # repr() escapes the quote and backslash
    harness.hide_in_reports(secret)
    harness.hide_in_reports("short")  # too short to mask: it would mask ordinary words
    shown = repr({"password": secret})
    try:
        raise RuntimeError(f"connect({shown}) as {secret}")
    except RuntimeError:
        failure = pytest.ExceptionInfo.from_current()
    report = pytest.TestReport(
        nodeid="probe.py::test",
        location=("probe.py", 0, "test"),
        keywords={},
        outcome="failed",
        longrepr=failure.getrepr(style="long", funcargs=True),
        when="call",
        sections=[("Captured stdout call", f"password={secret} short\n")],
    )
    harness._hide_secrets(report)
    assert secret not in str(report.longrepr)
    assert repr(secret)[1:-1] not in str(report.longrepr)
    assert "***" in str(report.longrepr)
    assert report.sections == [("Captured stdout call", "password=*** short\n")]
    skipped = pytest.TestReport(
        nodeid="probe.py::test",
        location=("probe.py", 0, "test"),
        keywords={},
        outcome="skipped",
        longrepr=("probe.py", 1, f"Skipped: {secret}"),
        when="setup",
    )
    harness._hide_secrets(skipped)
    assert skipped.longrepr == ("probe.py", 1, "Skipped: ***")


_CUT_SECRET = "QZJXKVWYBHUMRPLNTGFDSCEA"  # made up; no other text in these reprs has capitals


def test_the_start_or_end_of_a_secret_where_saferepr_cut_is_masked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """pytest's saferepr keeps a long repr's start and end around '...' (a local with -l, an
    operand in an assertion message): wherever the cut falls in the secret, the piece left
    before or after it is masked from 4 characters on."""
    from _pytest._io.saferepr import saferepr

    monkeypatch.setattr(harness, "_HIDDEN_IN_REPORTS", set())
    harness.hide_in_reports(_CUT_SECRET)
    hidden = sorted(harness._HIDDEN_IN_REPORTS, key=len, reverse=True)
    pieces = {_CUT_SECRET[i : i + 4] for i in range(len(_CUT_SECRET) - 3)}
    cuts = 0
    for before, after in [(n, 300) for n in range(240)] + [(300, n) for n in range(240)]:
        shown = saferepr({"a": "x" * before, "password": _CUT_SECRET, "z": "y" * after})
        cuts += _CUT_SECRET not in shown and any(piece in shown for piece in pieces)
        masked = harness._masked(shown, hidden)
        assert not any(piece in masked for piece in pieces), (before, after)
        assert masked.count("...") == shown.count("...")  # the cut itself stays visible
    assert cuts >= 2 * (len(_CUT_SECRET) - 4)  # the cut did fall inside the secret, both ways
    assert harness._masked("loading... QZJ...done", hidden) == "loading... QZJ...done"


def test_a_report_full_of_dots_is_masked_quickly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run of dots (a progress line, say) has a '...' at every position; once both passwords
    are registered, every report goes through this."""
    import time

    monkeypatch.setattr(harness, "_HIDDEN_IN_REPORTS", set())
    harness.hide_in_reports(_CUT_SECRET)
    hidden = sorted(harness._HIDDEN_IN_REPORTS, key=len, reverse=True)
    text = "." * 1_000_000 + f" {_CUT_SECRET[:10]}..."
    started = time.perf_counter()
    masked = harness._masked(text, hidden)
    assert time.perf_counter() - started < 3
    assert masked == "." * 1_000_000 + " ***..."


def test_a_cut_secret_is_masked_in_every_part_of_a_report(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(harness, "_HIDDEN_IN_REPORTS", set())
    harness.hide_in_reports(_CUT_SECRET)
    start, end = _CUT_SECRET[:9], _CUT_SECRET[-7:]
    report = pytest.TestReport(
        nodeid="probe.py::test",
        location=("probe.py", 0, "test"),
        keywords={},
        outcome="failed",
        longrepr=f"cparams = {{'password': '{start}...ons': '-c TimeZone=UTC'}}",
        when="call",
        sections=[("Captured log call", f"connecting with ...{end}' as argus\n")],
    )
    harness._hide_secrets(report)
    assert report.longrepr == "cparams = {'password': '***...ons': '-c TimeZone=UTC'}"
    assert report.sections == [("Captured log call", "connecting with ...***' as argus\n")]
    collected = pytest.CollectReport(
        "probe.py", "failed", f"ImportError: assert '{start}...' == 'x'", []
    )
    harness._hide_secrets(collected)
    assert collected.longrepr == "ImportError: assert '***...' == 'x'"


def test_the_database_passwords_come_from_the_environment_and_the_env_file(
    tmp_path: Path,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "argus_database__password=from-the-file\n"  # the settings read names in any case
        'ARGUS_DATABASE={"owner_password": "from-a-json-section", "name": "devdb"}\n'
        "ARGUS_DATABASE__NAME=not-a-password\n"
        "OTHER_TOOL_PASSWORD=not-a-database-password\n",
        encoding="utf-8",
    )
    environ = {"ARGUS_DATABASE__OWNER_PASSWORD": "from-the-environment"}
    assert harness.database_passwords(env_file, environ) == {
        "from-the-file",
        "from-a-json-section",
        "from-the-environment",
    }
    assert harness.database_passwords(tmp_path / "absent.env", {}) == frozenset()


@pytest.mark.parametrize("conftest", ["root", "integration"])
def test_the_database_passwords_are_masked_from_the_moment_pytest_configures_a_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, conftest: str
) -> None:
    """Collection reports are covered too: the db_settings fixture registers the passwords only
    when the first integration test sets up, after every module was collected. The root conftest
    registers them for the whole run; the integration conftest when pytest loads it."""
    from tests.integration import conftest as integration

    app, owner = f"app-{secrets.token_hex(8)}", f"owner-{secrets.token_hex(8)}"
    (tmp_path / ".env").write_text(
        f"ARGUS_DATABASE__PASSWORD={app}\nARGUS_DATABASE__OWNER_PASSWORD={owner}\n",
        encoding="utf-8",
    )
    for name in ("ARGUS_DATABASE", "ARGUS_DATABASE__PASSWORD", "ARGUS_DATABASE__OWNER_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    module: Any = harness if conftest == "root" else integration
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    monkeypatch.setattr(harness, "_HIDDEN_IN_REPORTS", set())
    config = _run_config()
    module.pytest_configure(config)
    try:
        report = pytest.CollectReport(
            "tests/_guard/test_probe.py", "failed", f"ImportError: {app} {owner}", []
        )
        harness._hide_secrets(report)
    finally:
        module.pytest_unconfigure(config)
    assert report.longrepr == "ImportError: *** ***"


# --------------------------------------------------------------------------- integration helpers


def test_only_generated_database_names_count_as_stale_candidates() -> None:
    from tests.integration.conftest import UNSET_DATABASE, _created_at

    assert _created_at("argus_test_1760000000_deadbeef") == 1760000000
    for name in (
        "argus_testing_1760000000_deadbeef",
        "argus_tests",
        "argus-test-1760000000-deadbeef",
        "argus_test_1760000000_DEADBEEF",
        "argus_test_1760000000_deadbeef_x",
        "argus_test_1760000000_deadbee",
        "argus",
        UNSET_DATABASE,
    ):
        assert _created_at(name) is None, name


@pytest.mark.parametrize("nested", ["another-config", "same-config"])
def test_a_nested_run_leaves_the_session_database_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nested: str
) -> None:
    """A run nested in this process (pytest.main() in a test) configures the integration conftest
    again; ending it must leave UNSET_DATABASE in place for the rest of the enclosing session."""
    from tests.integration import conftest as integration

    variable = integration.DATABASE_NAME_VARIABLE
    monkeypatch.setenv(variable, "the_env_files_database")  # what the session started with
    monkeypatch.setattr(integration, "REPO_ROOT", tmp_path)  # no .env: no passwords to register
    session = cast(pytest.Config, SimpleNamespace(stash=pytest.Stash()))
    inner = cast(pytest.Config, SimpleNamespace(stash=pytest.Stash()))
    nested_run = inner if nested == "another-config" else session
    integration.pytest_configure(session)
    integration.pytest_configure(nested_run)
    integration.pytest_unconfigure(nested_run)
    assert os.environ.get(variable) == integration.UNSET_DATABASE
    integration.pytest_unconfigure(session)
    assert os.environ.get(variable) == "the_env_files_database"


def test_ipv6_candidate_scan_is_linear_on_long_hex_runs() -> None:
    """Regression (R1 verification round 2): finditer used to re-scan a long run of hex
    characters from every position — 10 s for this 40 KB command line."""
    import time

    from tests._guard import argus_netguard

    text = "a" * 20_000 + ":" + "b" * 20_000
    started = time.perf_counter()
    assert argus_netguard.command_target(["curl", text], {"10.20.60.11"}) is None
    assert time.perf_counter() - started < 0.5
