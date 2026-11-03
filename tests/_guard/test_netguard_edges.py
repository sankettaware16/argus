"""Edge cases of the network guard that the harness self-tests leave open (R1 mutation testing).

Decisions are asked for directly (audit_hook, check_host, command_target...), so nothing here
reaches production even if the guard failed: real sockets only ever use loopback, and the only
program asked to start with a production address among its arguments is /bin/echo, which just
prints it. A child process that runs without the guard (a fresh copy of it is installed there)
does no network I/O at all.
"""

from __future__ import annotations

import importlib.machinery
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import tests.conftest as harness
from tests.conftest import NetworkAccessBlockedError, ProductionAccessBlockedError

netguard = harness._netguard
SIEMHOST = "10.20.60.11"
TEST_NET = "192.0.2.1"  # RFC 5737 documentation address
GUARD_FILE = harness.GUARD_DIR / "argus_netguard.py"


def _unresolvable(host: str, port: object) -> list[Any]:
    raise socket.gaierror(f"no such host: {host}")


def _run_python(code: str, env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - this interpreter, a fixed local script
        [sys.executable, "-c", code, *args],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# --------------------------------------------------------------------------- addresses


def test_a_production_host_name_is_recognised_without_a_lookup() -> None:
    hosts = {"es.example.test"}
    target = netguard.production_target(("es.example.test", 9200), hosts, _unresolvable)
    assert target == "es.example.test"
    with pytest.raises(ProductionAccessBlockedError):
        netguard.check_host("es.example.test", hosts, _unresolvable)
    assert netguard.command_target(["ssh", "es.example.test"], hosts) == "es.example.test"


def test_a_zone_does_not_hide_a_production_address() -> None:
    address = ("2001:db8::5%eth0", 9200, 0, 0)
    assert netguard.production_target(address, {"2001:db8::5"}, _unresolvable) == "2001:db8::5"


@pytest.mark.parametrize("host", ["127.0.0.1", "::1", "::ffff:127.0.0.1"])
def test_a_loopback_literal_needs_no_lookup(host: str) -> None:
    netguard.check_host(host, harness.PRODUCTION_HOSTS, _unresolvable)


def test_a_host_that_is_not_ascii_text_is_not_a_production_target() -> None:
    assert netguard.production_target((b"\xff\xfe", 9200)) is None


def test_libpq_host_and_hostaddr_lists() -> None:
    hosts = harness.PRODUCTION_HOSTS
    # hostaddr decides where libpq connects; the names beside it are never looked up
    netguard.check_libpq_target("a.invalid,b.invalid", "127.0.0.1,::1", hosts)
    # libpq refuses lists of different lengths, but every value is checked anyway
    netguard.check_libpq_target("127.0.0.1,::1", "127.0.0.1", hosts)
    with pytest.raises(NetworkAccessBlockedError):
        netguard.check_libpq_target(f"127.0.0.1,{TEST_NET}", "127.0.0.1", hosts)
    # '@' starts an abstract Unix-domain socket, '/' a socket directory
    netguard.check_libpq_target("@argus-abstract,/run/postgresql", "", hosts)


@pytest.mark.parametrize(
    ("value", "ports"),
    [("", {5432}), ("6543", {6543}), ("6543,,x", {6543, 5432}), (" , 7000", {5432, 7000})],
)
def test_an_empty_libpq_port_means_5432(value: str, ports: set[int]) -> None:
    assert netguard._libpq_ports(value) == ports


# --------------------------------------------------------------------------- command lines


def test_command_line_arguments_of_every_kind_are_read() -> None:
    hosts = harness.PRODUCTION_HOSTS
    assert netguard.command_target([Path(f"/dev/tcp/{SIEMHOST}/9200")], hosts) == SIEMHOST
    undecodable = [b"curl", f"http://{SIEMHOST}/\xff".encode("latin-1")]
    assert netguard.command_target(undecodable, hosts) == SIEMHOST


def test_only_the_ideographic_full_stops_are_read_as_dots() -> None:
    """The '%' makes the command line be read as curl reads a host; an X stays an X."""
    command = ["curl", "http://10X20X60X11:9200/%25"]
    assert netguard.command_target(command, harness.PRODUCTION_HOSTS) is None


def test_an_ipv6_literal_with_two_colons_is_read_as_its_address() -> None:
    assert netguard.command_target(["curl", "http://[01::2]:9200/"], {"1::2"}) == "1::2"


def test_numeric_forms_are_addresses_only() -> None:
    assert set(netguard._numeric_addresses("xa:b:c 10.0.0.1")) == {"10.0.0.1"}


# --------------------------------------------------------------------------- audit events


@pytest.mark.parametrize(
    ("event", "args"),
    [
        ("subprocess.Popen", (SIEMHOST, ["true"], None, None)),
        ("subprocess.Popen", (None, ["ssh", SIEMHOST], None, None)),
        ("os.exec", (SIEMHOST, ["true"], None)),
        ("os.exec", ("/bin/true", ["ssh", SIEMHOST], None)),
        ("os.posix_spawn", (SIEMHOST, ["true"], None)),
        ("os.posix_spawn", ("/bin/true", ["ssh", SIEMHOST], None)),
        ("os.spawn", (os.P_WAIT, SIEMHOST, ["true"], None)),
        ("os.spawn", (os.P_WAIT, "/bin/true", ["ssh", SIEMHOST], None)),
        ("os.system", (f"ssh {SIEMHOST}",)),
        ("pty.spawn", (["ssh", SIEMHOST],)),
    ],
)
def test_each_spawn_event_is_read_where_it_names_the_program(
    event: str, args: tuple[object, ...]
) -> None:
    """Decision only: the audit hook is called directly, nothing is started."""
    with pytest.raises(ProductionAccessBlockedError, match=f"via {event};"):
        netguard.audit_hook(event, args)


def test_an_event_with_fewer_arguments_is_checked_by_those_it_has() -> None:
    netguard.audit_hook("subprocess.Popen", ("/bin/true",))
    with pytest.raises(ProductionAccessBlockedError):
        netguard.audit_hook("subprocess.Popen", (SIEMHOST,))


class _PacketSocket:
    family = getattr(socket, "AF_PACKET", 17)


class _InetSocket:
    family = socket.AF_INET


@pytest.mark.parametrize(
    ("sock", "address"),
    [(_PacketSocket(), ("localhost", 0)), (_InetSocket(), "localhost")],
    ids=["other-family", "not-a-tuple"],
)
def test_a_socket_address_the_guard_cannot_read_is_refused(sock: object, address: object) -> None:
    with pytest.raises(NetworkAccessBlockedError, match="address family"):
        netguard.audit_hook("socket.connect", (sock, address))


def test_sendmsg_on_a_connected_loopback_socket_is_allowed() -> None:
    """sendmsg() without an address goes where connect() went, which the guard checked."""
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
    ):
        receiver.bind(("127.0.0.1", 0))
        receiver.settimeout(5)
        sender.connect(receiver.getsockname())
        sender.sendmsg([b"datagram"])
        assert receiver.recv(64) == b"datagram"


# The production address reaches these children in a variable: on their own command line the
# guard would refuse to start them.
_EXEC_EVENT_IN_CHILD = """
import os
import argus_netguard as guard
try:
    guard.audit_hook("os.exec", ("/bin/echo", ["/bin/echo", os.environ["EDGE_HOST"]], None))
except guard.ProductionAccessBlockedError:
    print("refused")
"""

_FORKED_EXEC_IN_CHILD = """
import os
pid = os.fork()
if pid == 0:
    try:
        os.execv("/bin/echo", ["/bin/echo", os.environ["EDGE_HOST"]])
    finally:
        os._exit(0)
_, status = os.waitpid(pid, 0)
print(os.waitstatus_to_exitcode(status))
"""


def test_an_exec_in_the_process_that_installed_the_guard_raises() -> None:
    """Only a forked child exits instead: this process can unwind normally."""
    completed = _run_python(_EXEC_EVENT_IN_CHILD, {**os.environ, "EDGE_HOST": SIEMHOST})
    assert (completed.returncode, completed.stdout) == (0, "refused\n"), completed.stderr


def test_a_forked_child_says_why_it_exits() -> None:
    completed = _run_python(_FORKED_EXEC_IN_CHILD, {**os.environ, "EDGE_HOST": SIEMHOST})
    assert completed.stdout == "126\n", completed.stderr
    assert completed.stderr == (
        f"test tried to start a process aimed at the production SIEM ({SIEMHOST}) via os.exec; "
        "only live tests (tests/live/, run with --run-live) may\n"
    )


# --------------------------------------------------------------------------- psycopg


def test_the_os_user_is_libpq_s_default_user(monkeypatch: pytest.MonkeyPatch) -> None:
    import pwd

    assert netguard._os_user() == pwd.getpwuid(os.geteuid()).pw_name

    def missing(uid: int) -> Any:
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", missing)
    assert netguard._os_user() == ""


def test_a_conninfo_psycopg_cannot_read_is_left_to_psycopg() -> None:
    """psycopg rejects it itself, before any network I/O."""
    assert netguard._psycopg_refusal("this is not a conninfo", {}) is None


def test_a_connection_the_guard_cannot_check_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*args: object) -> None:
        raise RuntimeError("cannot read it")

    monkeypatch.setattr(netguard, "check_libpq_target", broken)
    refusal = netguard._psycopg_refusal("", {"host": "127.0.0.1", "port": 1})
    assert isinstance(refusal, NetworkAccessBlockedError)
    assert str(refusal) == (
        "the network guard could not check this psycopg connection (RuntimeError)"
    )


class _Connection:
    @classmethod
    def connect(cls, conninfo: str = "", **kwargs: Any) -> str:
        return "connected"


class _AsyncConnection:
    @classmethod
    async def connect(cls, conninfo: str = "", **kwargs: Any) -> str:
        return "connected"


def _fake_psycopg(connection: type, async_connection: type) -> Any:
    return SimpleNamespace(Connection=connection, AsyncConnection=async_connection, connect=None)


def test_guarding_psycopg_again_changes_nothing() -> None:
    connection = type("Connection", (_Connection,), {"connect": _Connection.__dict__["connect"]})
    async_connection = type(
        "AsyncConnection", (_AsyncConnection,), {"connect": _AsyncConnection.__dict__["connect"]}
    )
    psycopg = _fake_psycopg(connection, async_connection)
    netguard.guard_psycopg(psycopg)
    guarded = (connection.__dict__["connect"], async_connection.__dict__["connect"])
    assert guarded[0] is not _Connection.__dict__["connect"]
    netguard.guard_psycopg(psycopg)
    assert (connection.__dict__["connect"], async_connection.__dict__["connect"]) == guarded
    assert psycopg.connect == connection.connect


def test_a_psycopg_whose_connect_is_not_a_classmethod_stops_the_guard() -> None:
    def connect(conninfo: str = "") -> None:
        return None

    plain = type("Connection", (), {"connect": staticmethod(connect)})
    with pytest.raises(RuntimeError, match=r"Connection\.connect is no longer a classmethod"):
        netguard.guard_psycopg(_fake_psycopg(plain, _AsyncConnection))


class _Finder:
    def __init__(self, spec: Any) -> None:
        self.spec = spec

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        return self.spec


class _Loader:
    def exec_module(self, module: Any) -> None:
        return None


def test_the_import_hook_takes_the_first_finder_that_knows_psycopg(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hook = netguard._GuardPsycopgOnImport()
    spec = importlib.machinery.ModuleSpec("psycopg", _Loader())
    monkeypatch.setattr(sys, "meta_path", [hook, _Finder(spec), _Finder(None)])
    assert hook.find_spec("psycopg", None) is spec
    monkeypatch.setattr(sys, "meta_path", [hook, _Finder(None)])
    assert hook.find_spec("psycopg", None) is None
    monkeypatch.setattr(sys, "meta_path", [hook])
    assert hook.find_spec("psycopg", None) is None


def test_the_import_hook_refuses_a_loader_it_cannot_hook(monkeypatch: pytest.MonkeyPatch) -> None:
    hook = netguard._GuardPsycopgOnImport()
    spec = importlib.machinery.ModuleSpec("psycopg", object())
    monkeypatch.setattr(sys, "meta_path", [hook, _Finder(spec)])
    with pytest.raises(ImportError, match=r"^network guard: cannot hook the loader of psycopg$"):
        hook.find_spec("psycopg", None)


# --------------------------------------------------------------------------- installation

_FRESH_INSTALL = """
import importlib.util, json, sys
if sys.argv[1] == "psycopg-first":
    import psycopg
spec = importlib.util.spec_from_file_location("argus_netguard", sys.argv[2])
guard = importlib.util.module_from_spec(spec)
sys.modules["argus_netguard"] = guard
spec.loader.exec_module(guard)
before = dict(guard.STATE)
guard.install()
first_finder = type(sys.meta_path[0]).__name__
import psycopg
print(json.dumps({
    "before": before,
    "after": dict(guard.STATE),
    "first_finder": first_finder,
    "guarded": getattr(psycopg.Connection.connect.__func__, "_argus_netguard", False),
    "alias": psycopg.connect == psycopg.Connection.connect,
}))
"""


@pytest.mark.parametrize("order", ["psycopg-first", "psycopg-later"])
def test_installing_a_fresh_guard_switches_it_on_and_guards_psycopg(order: str) -> None:
    """A Python child without tests/_guard on its path has no guard until one is installed:
    importing the module changes nothing, install() switches it on, and psycopg is guarded
    whether it was imported before or after."""
    env = {
        name: value
        for name, value in os.environ.items()
        if name not in ("PYTHONPATH", netguard.ENV_VAR)
    }
    completed = _run_python(_FRESH_INSTALL, env, order, str(GUARD_FILE))
    assert completed.returncode == 0, completed.stderr[-2000:]
    report = json.loads(completed.stdout)
    assert report["before"] == {"active": False, "installed": False, "locked": False}
    assert report["after"] == {"active": True, "installed": True, "locked": False}
    assert (report["guarded"], report["alias"]) == (True, True)
    if order == "psycopg-later":
        assert report["first_finder"] == "_GuardPsycopgOnImport"


_STATE_IN_CHILD = """
import json
import argus_netguard as guard
print(json.dumps(guard.STATE))
"""


def test_a_child_reads_the_guard_from_pytest_argus_netguard() -> None:
    """The variable's name is the documented interface between the processes."""
    env = {name: value for name, value in os.environ.items() if name != netguard.ENV_VAR}
    env["PYTEST_ARGUS_NETGUARD"] = json.dumps(
        {"active": False, "production_hosts": [], "protected_databases": []}
    )
    completed = _run_python(_STATE_IN_CHILD, env)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert json.loads(completed.stdout) == {"active": False, "installed": True, "locked": False}


def test_a_nested_run_keeps_what_the_runs_around_it_protect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """begin_run installs the nested run's own hosts and databases on top of the enclosing
    run's, and locks the guard (the run is nested in this guarded test); end_run gives back the
    lock and the hosts, and removes a variable that was not set before."""
    # Restored after the test even if end_run is broken, so that no later test inherits a lock.
    for key in ("active", "locked"):
        monkeypatch.setitem(netguard.STATE, key, netguard.STATE[key])
    for name in ("_production_hosts", "_protected_databases", "_RUNS"):
        value = getattr(netguard, name)
        monkeypatch.setattr(netguard, name, list(value) if name == "_RUNS" else value)
    monkeypatch.delenv(netguard.ENV_VAR)
    locked, runs = netguard.STATE["locked"], len(netguard._RUNS)
    owner = object()
    stand_in = ("argus_edge_stand_in", 1)
    netguard.begin_run(owner, lambda: frozenset({"127.0.0.3"}), lambda: frozenset({stand_in}))
    try:
        os.environ[netguard.ENV_VAR] = netguard.describe()
        assert netguard.STATE["locked"] is True
        assert {"127.0.0.3", *harness.PRODUCTION_HOSTS} <= netguard._hosts()
        assert {stand_in, *harness.PROTECTED_DATABASES} <= netguard._databases()
    finally:
        netguard.end_run(owner)
    assert (netguard.STATE["locked"], len(netguard._RUNS)) == (locked, runs)
    assert netguard.ENV_VAR not in os.environ
    assert "127.0.0.3" not in netguard._hosts()


@pytest.mark.parametrize("value", [SIEMHOST, [SIEMHOST, 1], None])
def test_production_hosts_must_be_a_list_of_strings(value: object) -> None:
    with pytest.raises(TypeError, match=r"^production_hosts: expected a list of strings$"):
        netguard._hosts_from(value)


@pytest.mark.parametrize(
    "value",
    [
        "argus",
        None,
        {"argus": 55432},
        [["argus", 55432, 1]],
        [[1, 55432]],
        [["argus", "55432"]],
        [("argus", 55432)],
        [["argus"]],
    ],
)
def test_protected_databases_must_be_name_and_port_pairs(value: object) -> None:
    pairs = r"^protected_databases: expected a list of \[name, port\] pairs$"
    with pytest.raises(TypeError, match=pairs):
        netguard._databases_from(value)


def test_a_well_formed_description_is_read() -> None:
    assert netguard._hosts_from([SIEMHOST, "127.0.0.2"]) == {SIEMHOST, "127.0.0.2"}
    assert netguard._databases_from([["argus", 55432]]) == {("argus", 55432)}


# -- the local LLM's tunnel (Q-G1) ------------------------------------------------------------


@pytest.mark.parametrize(
    "address", [("127.0.0.1", 18443), ("::1", 18443, 0, 0), ("localhost", 18443)]
)
def test_the_local_llm_tunnel_port_is_refused(address: tuple[object, ...]) -> None:
    """18443 on this machine leads through the tunnel to the real model machine (D-108)."""
    import socket as _socket

    family = _socket.AF_INET6 if ":" in str(address[0]) else _socket.AF_INET
    with (
        _socket.socket(family, _socket.SOCK_STREAM) as sock,
        pytest.raises(harness.ProductionAccessBlockedError, match="local LLM's tunnel"),
    ):
        sock.connect(address)


def test_other_loopback_ports_and_the_port_number_elsewhere_pass() -> None:
    netguard.check_port(("127.0.0.1", 18444))
    netguard.check_port(("127.0.0.1", 1844))
    netguard.check_port(("127.0.0.1",))
    with pytest.raises(harness.ProductionAccessBlockedError):
        netguard.check_port(("127.0.0.2", 18443))


@pytest.mark.parametrize(
    "command",
    [["curl", "https://127.0.0.1:18443/v1/models"], ["ssh", "-p 18443", "x"],
     ["nc", "localhost", "--port=18443"], "curl -k https://localhost:18443/"],
)  # fmt: skip
def test_a_command_aimed_at_the_tunnel_is_not_started(command: object) -> None:
    # the hook itself, never a real process: something may listen on 18443 here
    args = (command, None, None) if isinstance(command, str) else ("x", command, None, None)
    event = "os.system" if isinstance(command, str) else "subprocess.Popen"
    with pytest.raises(harness.ProductionAccessBlockedError, match="local LLM's tunnel"):
        netguard._check_command(event, args)


def test_a_command_with_the_number_alone_starts() -> None:
    for text in ("size 18443 bytes", "x:184430", "port 1844", "a18443"):
        assert netguard._PORT_IN_COMMAND.search(text) is None, text
    netguard._check_command("subprocess.Popen", ("x", ["echo", "18443"], None, None))


def test_a_real_process_aimed_at_the_tunnel_is_stopped_before_it_starts() -> None:
    with pytest.raises(harness.ProductionAccessBlockedError):
        subprocess.run(["true", "https://127.0.0.1:18443/"], check=False)  # noqa: S607


# -- Q-G1's review, F5: the tunnel's port as a separate argument, and libpq ------------------


@pytest.mark.parametrize(
    "command",
    [["nc", "127.0.0.1", "18443"], ["telnet", "localhost", "18443"], "nc -z 127.0.0.1 18443",
     ["nc", "127.1", "18443"], ["socat", "-", "TCP:0x7f000001", "18443"],
     ["nc", "::1", "18443"], ["openssl", "s_client", "-connect", "[::ffff:127.0.0.1]", "18443"],
     ["nc", "2130706433", "18443"], ["nc", "0.0.0.0", "18443"]],  # noqa: S104
)  # fmt: skip
def test_a_split_command_line_aimed_at_the_tunnel_is_not_started(command: object) -> None:
    # the hook itself, never a real process: something may listen on 18443 here
    args = (command, None, None) if isinstance(command, str) else ("x", command, None, None)
    event = "os.system" if isinstance(command, str) else "subprocess.Popen"
    with pytest.raises(harness.ProductionAccessBlockedError, match="local LLM's tunnel"):
        netguard._check_command(event, args)


def test_the_number_without_a_loopback_host_still_starts() -> None:
    for command in (["echo", "18443"], ["head", "-c", "18443", "file"],
                    ["nc", "127.0.0.1", "18444"], ["nc", "127.0.0.1", "184430"]):  # fmt: skip
        netguard._check_command("subprocess.Popen", ("x", command, None, None))


@pytest.mark.parametrize(
    ("conninfo", "kwargs", "env"),
    [("host=127.0.0.1 port=18443 dbname=argus_t user=x", {}, {}),
     ("host=127.0.0.1 dbname=argus_t user=x", {"port": 18443}, {}),
     ("host=127.0.0.1,127.0.0.1 port=55432,18443 dbname=argus_t user=x", {}, {}),
     ("host=127.0.0.1 dbname=argus_t user=x", {}, {"PGPORT": "18443"})],
)  # fmt: skip
def test_a_psycopg_connection_to_the_tunnel_is_refused(
    conninfo: str, kwargs: dict[str, Any], env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    assert netguard.STATE["active"]
    refusal = netguard._psycopg_refusal(conninfo, kwargs)
    assert isinstance(refusal, ProductionAccessBlockedError), refusal
    assert "local LLM's tunnel" in str(refusal)


def test_a_psycopg_connection_to_another_loopback_port_is_not_refused() -> None:
    assert netguard._psycopg_refusal("host=127.0.0.1 port=18444 dbname=argus_t user=x", {}) is None
