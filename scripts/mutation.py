#!/usr/bin/env python3
"""Mutation testing of the R1 gate modules: config (sources, errors, settings, durations),
redaction, roles, network guard.

    uv run python scripts/mutation.py                      # every module, two workers
    uv run python scripts/mutation.py durations roles      # some of them
    uv run python scripts/mutation.py --list settings      # the mutants, without running them
    uv run python scripts/mutation.py --show roles:12      # one mutant as a diff
    uv run python scripts/mutation.py --only roles:12,roles:40   # single mutants again
    uv run python scripts/mutation.py --report             # the summary of the saved results

Results go to .mutation/results/ (gitignored, like the rest of --work).

Mutants. One small change each, found in the module's syntax tree and applied to its text:
arithmetic and bitwise operators swapped (also in augmented assignments), comparisons flipped
(< and <=, == and !=, in and not in, is and is not), ``and`` and ``or`` swapped, a ``not``
dropped, numbers increased by one, True and False swapped, string literals wrapped in "XX", and a
statement in a function body replaced by ``pass``. Docstrings, the literal text of f-strings and
annotations that are never evaluated are left alone (pydantic evaluates the annotations of its
models' fields, so those are mutated). The same source always gives the same mutants, numbered
in source order.

Runs. Each module runs the test files that execute it (TARGETS: found with per-test coverage
of the whole suite), unit tests only except for roles, whose code is mostly SQL. Each worker
(two, or one for roles: its tests rename and alter a cluster-wide role) has its own copy of the
repository under --work: its git-visible files (tracked, or untracked and not ignored) without
reference/. A mutant is written into the copy, the tests run there with ``pytest -x``
(PYTHONPATH points at the copy's src/), and the original is put back. A failing run kills the
mutant, a passing run means it survived, a run over its time limit is a timeout. Tests that
already fail on the original code (DEFECT tests of an open bug) are deselected and named. At the
end every test that killed a mutant runs on the original code: the mutants of one that fails
there, and those killed by a signal or by a Hypothesis deadline, run again.

Score: killed / (mutants - equivalent). EQUIVALENT lists, per module, the mutants that cannot
change what the code does, each with the reason.

Safety.

* roles: its integration tests log in to the local Postgres with the passwords in .env, which
  the copy links to (never copies), and they bootstrap the configured runtime login. Some
  mutants would change that login or the group role for real: renaming the runtime group role
  (a stray cluster role the login joins), dropping the password verifier's return value
  (``PASSWORD NULL``), and any value of the safe states bootstrap restores (_GROUP_STATE,
  _LOGIN_STATE: SUPERUSER or NOLOGIN on the real roles). Such mutants (``unit_only``, matched by
  their text or by the line they are on) run the module's unit tests alone, whatever order the
  tests run in; one those miss is reported as skipped.
* network guard: a mutant may switch part of the guard off while a test tries to reach the
  production SIEM (tests/unit/test_network_guard.py connects to the SIEM and expects a refusal).
  So every process of such a run also gets a safety net: this file, installed after the guard
  (by a pytest plugin in the pytest process and by the copy's sitecustomize in each Python
  child), with an unmutated copy of the guard. It refuses any socket outside loopback and the
  documentation ranges, any command line naming production, and any libpq connection off this
  machine or to a local Postgres port, by raising SafetyNetError, a BaseException no test
  expects. The guard under test decides first; the safety net only stops what it let through,
  which fails the test. Each copy proves the safety net works before its first mutant runs:
  with the guard switched off, it must stop a socket, a command line, a Python child and libpq.
"""

from __future__ import annotations

import argparse
import ast
import atexit
import bisect
import contextlib
import dataclasses
import difflib
import importlib.util
import io
import ipaddress
import json
import os
import queue
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tokenize
from collections.abc import Iterable, Sequence
from importlib.abc import MetaPathFinder
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------- safety net
# This part runs inside the test processes of a network-guard run. Keep the whole file importable
# by any Python 3.10+ with the standard library alone: a child process may run another Python.

SAFETY_MODULE = "argus_mutation_safety"
SAFETY_PLUGIN = "argus_mutation_plugin"
REFERENCE_GUARD = "argus_netguard_reference"
DATABASE_PORTS_VARIABLE = "ARGUS_MUTATION_DATABASE_PORTS"  # extra local Postgres ports to refuse
# The suite's made-up SIEM (tests/conftest.py SUITE_SIEM_HOSTS), which the guard's own tests aim
# at; the configured SIEM's hosts (argus_netguard.configured_hosts) join it when the net installs.
_PRODUCTION = frozenset({"10.20.60.11", "siemhost"})
_DOCUMENTATION = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")
)
_POSTGRES_PORTS = frozenset({5432, 55432})
_SOCKET_EVENTS = frozenset({"socket.connect", "socket.sendto", "socket.sendmsg"})
_safety: dict[str, Any] = {"installed": False, "pid": 0, "reference": None}


class SafetyNetError(BaseException):
    """Something the guard under test let through, which the unmutated guard refuses."""


def install_safety_net() -> None:
    """Install the safety net in this process, once. Call it after the guard is installed:
    audit hooks run in the order they were added, so the guard decides first."""
    if _safety["installed"]:
        return
    path = Path(__file__).with_name(f"{REFERENCE_GUARD}.py")
    spec = importlib.util.spec_from_file_location(REFERENCE_GUARD, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"mutation safety net: cannot load {path}")
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    production = _PRODUCTION | reference.configured_hosts(Path(__file__).resolve().parent.parent)
    _safety.update(installed=True, pid=os.getpid(), reference=reference, production=production)
    sys.addaudithook(_safety_hook)
    module = sys.modules.get("psycopg._connection_base")
    if module is not None:
        _check_libpq_connections(module)
    else:
        sys.meta_path.insert(0, _CheckLibpqOnImport())


def _safety_hook(event: str, args: tuple[Any, ...]) -> None:
    reference = _safety["reference"]
    if event in _SOCKET_EVENTS:
        reason = _socket_refusal(args[0], args[1])
    elif event in reference._COMMAND_ARGS:
        command = [args[i] for i in reference._COMMAND_ARGS[event] if i < len(args)]
        target = reference.command_target(command, _safety["production"])
        reason = None if target is None else f"a command line naming production ({target})"
    else:
        return
    if reason is None:
        return
    message = f"mutation safety net: refused {event}, {reason}: the guard under test let it through"
    if event == "os.exec" and os.getpid() != _safety["pid"]:
        os.write(2, message.encode() + b"\n")  # a forked child: never unwind into pytest
        os._exit(127)
    raise SafetyNetError(message)


def _socket_refusal(sock: object, address: object) -> str | None:
    if address is None:  # sendmsg() on a connected socket: its connect() was checked
        return None
    family = getattr(sock, "family", None)
    if family is not None and family == getattr(socket, "AF_UNIX", None):
        return None
    if not isinstance(address, tuple) or not address:
        return "an address it cannot read"
    reference = _safety["reference"]
    host = reference._host_text(address[0])
    if host is None:
        return "a host it cannot read"
    addresses = reference._addresses(host, socket.getaddrinfo)
    if not addresses:
        return "a host that does not resolve"
    for text in addresses:
        ip = reference._ip(text.split("%", 1)[0])
        if ip is None or not (ip.is_loopback or any(ip in net for net in _DOCUMENTATION)):
            return "a host outside loopback and the documentation ranges"
    return None


class _CheckLibpqOnImport(MetaPathFinder):
    """Patches psycopg's connection base class as soon as it is imported."""

    def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
        if fullname != "psycopg._connection_base":
            return None
        spec = None
        for finder in sys.meta_path:
            find_spec = getattr(finder, "find_spec", None)
            if finder is not self and find_spec is not None:
                spec = find_spec(fullname, path, target)
                if spec is not None:
                    break
        if spec is None:
            return None
        loader: Any = spec.loader
        exec_module = getattr(loader, "exec_module", None)
        if exec_module is None:
            raise ImportError("mutation safety net: cannot hook psycopg")

        def exec_and_check(module: Any) -> None:
            exec_module(module)
            _check_libpq_connections(module)

        loader.exec_module = exec_and_check
        return spec


def _check_libpq_connections(module: Any) -> None:
    """psycopg hands each connection attempt's conninfo to BaseConnection._connect_gen, after
    the guard's check (around connect()) and before libpq opens a socket."""
    base = module.BaseConnection
    original = base.__dict__.get("_connect_gen")
    if not isinstance(original, classmethod):
        raise RuntimeError("mutation safety net: psycopg's BaseConnection._connect_gen changed")
    connect_gen = original.__func__

    def checked(cls: Any, conninfo: str = "") -> Any:
        reason = _libpq_refusal(conninfo)
        if reason is not None:
            raise SafetyNetError(
                f"mutation safety net: refused a libpq connection to {reason}: the guard under"
                " test let it through"
            )
        return connect_gen(cls, conninfo)

    base._connect_gen = classmethod(checked)


def _libpq_refusal(conninfo: str) -> str | None:
    from psycopg.conninfo import conninfo_to_dict

    reference = _safety["reference"]
    params = conninfo_to_dict(conninfo)

    def param(name: str, variable: str) -> str:
        return str(params[name]) if name in params else os.environ.get(variable, "")

    if param("service", "PGSERVICE"):
        return "a libpq service"
    try:
        reference.check_libpq_target(param("host", "PGHOST"), param("hostaddr", "PGHOSTADDR"), [])
    except reference.NetworkAccessBlockedError:
        return "a server off this machine"
    extra = os.environ.get(DATABASE_PORTS_VARIABLE, "")
    ports = _POSTGRES_PORTS | {int(port) for port in extra.split(",") if port.strip().isdigit()}
    if reference._libpq_ports(param("port", "PGPORT")) & ports:
        return "a local Postgres port"
    return None


# The plugin that installs the safety net in the pytest process, after tests/conftest.py's guard.
_PLUGIN_SOURCE = f'''"""Installs scripts/mutation.py's safety net once the run is configured."""

import pytest

import {SAFETY_MODULE}


@pytest.hookimpl(trylast=True)
def pytest_configure(config: pytest.Config) -> None:
    {SAFETY_MODULE}.install_safety_net()
'''
# What tests/_guard/sitecustomize.py does to install the guard in a Python child, and what the copy
# does instead: the same, then the safety net, which a child that cannot install it must not run
# without.
_GUARD_STARTUP = (
    'argus_netguard = importlib.import_module("argus_netguard")\n'
    "argus_netguard.install_from_environment()\n"
)
_GUARD_AND_SAFETY_STARTUP = """try:
    argus_netguard = importlib.import_module("argus_netguard")
    argus_netguard.install_from_environment()
finally:
    try:
        _safety_spec = importlib.util.spec_from_file_location({module!r}, {path!r})
        _safety = importlib.util.module_from_spec(_safety_spec)
        sys.modules[{module!r}] = _safety
        _safety_spec.loader.exec_module(_safety)
        _safety.install_safety_net()
    except BaseException as _exc:
        sys.stderr.write("mutation safety net: not installed (%r); stopping\\n" % (_exc,))
        os._exit(3)
"""
# Run in each copy before any mutant of the guard: with the guard switched off, the safety net
# must stop a socket, a command line, a Python child and libpq. 198.18.0.1 (RFC 2544
# benchmarking) is neither loopback nor documentation, and is not routed if anything failed.
_PROBE_SOURCE = f'''"""The mutation runner's safety net works in this copy (scripts/mutation.py)."""

import json
import os
import socket
import subprocess
import sys

import psycopg
import pytest

import argus_netguard
import {SAFETY_MODULE} as safety

UNROUTED = "198.18.0.1"
CHILD = "import socket; socket.create_connection(('198.18.0.1', 9), timeout=1)"


def test_the_safety_net_stops_what_the_guard_lets_through() -> None:
    argus_netguard.set_active(False)
    try:
        with socket.socket() as sock, pytest.raises(safety.SafetyNetError):
            sock.connect((UNROUTED, 9))
        with pytest.raises(safety.SafetyNetError):
            subprocess.run(["/bin/echo", "10.20.60.11"], capture_output=True, check=False)
        with pytest.raises(safety.SafetyNetError):
            psycopg.connect(host=UNROUTED, port=9, dbname="d", user="u", connect_timeout=1)
        assert safety._libpq_refusal("host=127.0.0.1 port=55432 dbname=d") is not None
        assert safety._libpq_refusal("host=127.0.0.1 port=9 dbname=d") is None
        env = {{**os.environ, argus_netguard.ENV_VAR: json.dumps({{"active": False}})}}
        child = subprocess.run(
            [sys.executable, "-c", CHILD], env=env, capture_output=True, text=True, check=False
        )
        assert "SafetyNetError" in child.stderr, child.stderr[-2000:]
    finally:
        argus_netguard.set_active(True)
'''
_PROBE = "tests/_guard/test_mutation_safety_probe.py"

# --------------------------------------------------------------------------- targets

REPO = Path(__file__).resolve().parent.parent


@dataclasses.dataclass(frozen=True)
class Target:
    path: str  # the module, relative to the repository
    tests: tuple[str, ...]  # test files (or node ids) that execute it, run in this order
    unit_tests: tuple[str, ...] = ()  # what a unit_only mutant runs instead
    unit_only: tuple[str, ...] = ()  # the original text of mutants that must not reach the database
    unit_only_lines: tuple[str, ...] = ()  # ... or how the line they are on starts
    link_env: bool = False  # the tests need .env (integration tests)
    guard: bool = False  # the network guard itself: run with the safety net
    test_timeout: int = 30  # per test (pytest-timeout)
    max_workers: int = 2  # 1 where two runs at once could fail each other's tests


_LIVE: set[int] = set()  # process groups of the test runs going on now
_LIVE_LOCK = threading.Lock()
_STOPPING = threading.Event()


def _stop_live_runs() -> None:
    """Kill every test run still going. Each runs in its own session, so ending the runner alone
    leaves them running: one ran for 14 hours after an R2 run was stopped (2026-10-12)."""
    _STOPPING.set()
    with _LIVE_LOCK:
        groups = list(_LIVE)
    for group in groups:
        with contextlib.suppress(ProcessLookupError, PermissionError):
            os.killpg(group, signal.SIGKILL)


_CONFIG_UNIT_TESTS = (
    "tests/unit/config/test_settings.py",
    "tests/unit/config/test_web_settings.py",  # D-104
    "tests/unit/config/test_settings_exact.py",  # every default and bound, written out
    "tests/unit/config/test_sources.py",
    "tests/unit/config/test_env_name_leaks.py",
    "tests/unit/config/test_dotenv_cost.py",
    "tests/unit/config/test_config_properties.py",
    "tests/unit/adversarial/test_adv_config.py",
    "tests/unit/adversarial/test_adv_secrets.py",
    "tests/unit/test_cli.py",
    "tests/unit/adversarial/test_adv_cli_guard.py",
)
_FIXTURE_TESTS = (
    "tests/unit/fixtures",
    "tests/unit/adversarial/test_adv_fixtures_survival.py",
    "tests/unit/adversarial/test_adv_fixtures_scanner.py",
    "tests/unit/adversarial/test_adv_fixtures_ipmap.py",
    "tests/unit/adversarial/test_adv_fixtures_integrity.py",
    "tests/unit/adversarial/test_adv_fixtures_sanitizer_reattack.py",
    "tests/unit/adversarial/test_adv_fixtures_scanner_reattack.py",
    "tests/unit/adversarial/test_adv_fixtures_ipmap_tokens_reattack.py",
    "tests/unit/adversarial/test_adv_fixtures_round3.py",
    "tests/unit/adversarial/test_adv_fixtures_round3_ipmap_tokens.py",
)
_GATEWAY_UNIT = (
    "tests/unit/gateway/test_validator.py",
    "tests/unit/gateway/test_cores.py",
    "tests/unit/gateway/test_budget.py",
    "tests/unit/gateway/test_gateway.py",
    "tests/unit/gateway/test_transport.py",
    "tests/unit/gateway/test_cassettes.py",
    "tests/unit/gateway/test_review1.py",
    "tests/unit/gateway/test_validator_mutants.py",
    "tests/unit/gateway/test_cores_mutants.py",
    "tests/unit/gateway/test_gateway_mutants.py",
    "tests/unit/gateway/test_parts_mutants.py",
    "tests/unit/gateway/test_builtin_mutants.py",
    "tests/unit/gateway/test_send_check.py",
    "tests/unit/gateway/test_request_timeout.py",  # Q-A3
)
_GATEWAY_DB = (
    "tests/integration/gateway/test_pgstore.py",
    "tests/integration/gateway/test_service.py",
)
_NORMALIZE_TESTS = (
    "tests/unit/normalize/test_mutants.py",
    "tests/unit/normalize/test_parts_mutants.py",
    "tests/unit/normalize/test_parts.py",
    "tests/unit/normalize/test_normalizer.py",
    "tests/unit/normalize/test_snapshots.py",
    "tests/unit/normalize/test_fuzz.py",
    "tests/unit/normalize/test_throughput.py",
)
_CASES_UNIT = (
    "tests/unit/cases/test_machine.py",
    "tests/unit/cases/test_machine_watch.py",
    "tests/unit/cases/test_parts.py",
    "tests/unit/cases/test_closure_parts.py",
)
# Q-C3: closure approval, send-time checks, the autonomy ledger.
_CLOSURE_DB = (
    "tests/integration/cases/test_closure_approval.py",
    "tests/integration/cases/test_send_property.py",
    "tests/integration/cases/test_closure_review.py",  # the review's findings (F1-F10)
)
_CASES_DB = (
    "tests/integration/cases/test_guards.py",
    "tests/integration/cases/test_service.py",
    "tests/integration/cases/test_merge_notes.py",
    "tests/integration/cases/test_opener.py",
    "tests/integration/cases/test_crash.py",
    "tests/integration/cases/test_review.py",
)
# Q-C2: membership and the still-active watch.
_WATCH_UNIT = ("tests/unit/cases/test_membership.py", "tests/unit/cases/test_watch.py")
_WATCH_DB = (
    "tests/integration/cases/test_watch.py",
    "tests/integration/cases/test_watch_lane.py",
    "tests/integration/cases/test_watch_db.py",
)
_QA1_TESTS = (
    "tests/unit/web/test_capabilities.py",
    "tests/unit/web/test_security.py",
    "tests/unit/web/test_v1_views.py",
    "tests/unit/web/test_openapi_spec.py",
    "tests/unit/config/test_web_settings.py",
    "tests/integration/web/test_session_contract.py",
    "tests/integration/web/test_routes_declared.py",
    "tests/integration/web/test_v1.py",
    "tests/integration/web/test_v1_agree.py",
    "tests/integration/web/test_v1_b2.py",  # Q-B2: reports, since, the threat-list tile
    "tests/integration/web/test_user_cli.py",
)
# The test files that execute each module (per-test coverage of the whole suite, 2026-10-10).
# Integration tests only for roles: settings feeds the role bootstrap of every integration
# session, the safety net of a guard run refuses the local Postgres, and the unit tests reach
# durations and redaction more directly.
TARGETS: dict[str, Target] = {
    # The R1 gate names "config": its sources and its error helpers too, not only settings.
    "sources": Target(
        "src/argus/config/sources.py",
        tests=(
            "tests/unit/config/test_sources_limits.py",
            "tests/unit/config/test_sources_yaml_messages.py",
            "tests/unit/config/test_sources_env_origins.py",
            "tests/unit/config/test_sources_message_fixes.py",
            "tests/unit/config/test_sources.py",
            "tests/unit/config/test_dotenv_cost.py",
            "tests/unit/config/test_env_name_leaks.py",
            "tests/unit/config/test_settings_edges.py",
            *_CONFIG_UNIT_TESTS,
            "tests/unit/adversarial/test_adv_roles_config.py",
            "tests/unit/adversarial/test_adv_roles_config_reattack.py",
        ),
    ),
    "config_errors": Target(
        "src/argus/config/errors.py",
        tests=(
            "tests/unit/config/test_settings_edges.py",
            *_CONFIG_UNIT_TESTS,
            "tests/unit/adversarial/test_adv_roles_config.py",
        ),
    ),
    "durations": Target(
        "src/argus/config/durations.py",
        tests=(
            "tests/unit/config/test_durations_edges.py",
            "tests/unit/config/test_durations.py",
            *_CONFIG_UNIT_TESTS,
        ),
    ),
    "settings": Target(
        "src/argus/config/settings.py",
        tests=(
            "tests/unit/config/test_settings_edges.py",
            "tests/unit/ops/test_settings_q_a2.py",  # Q-A2: secrets, the web login, backups
            *_CONFIG_UNIT_TESTS,
            "tests/unit/test_db_engine.py",
            "tests/unit/adversarial/test_adv_roles_config.py",
            "tests/unit/adversarial/test_adv_roles_config_reattack.py",
            "tests/_guard/test_harness.py::test_the_harness_defaults_are_the_settings_defaults",
            "tests/_guard/test_harness.py::test_a_refused_admin_connection_does_not_echo_the_password",
        ),
    ),
    "redaction": Target(
        "src/argus/observability/redaction.py",
        tests=(
            "tests/unit/observability/test_redaction_edges.py",
            "tests/unit/observability",
            "tests/unit/adversarial/test_adv_secrets.py",
            "tests/unit/test_cli.py",
            "tests/unit/adversarial/test_adv_cli_guard.py",
            "tests/unit/config",
            "tests/unit/adversarial/test_adv_config.py",
        ),
    ),
    "roles": Target(
        "src/argus/db/roles.py",
        tests=(
            "tests/unit/test_roles_edges.py",
            "tests/unit/test_cli.py",
            "tests/unit/adversarial/test_adv_roles_config.py",
            "tests/unit/adversarial/test_adv_roles_config_reattack.py",
            "tests/integration/db/test_roles.py",
            "tests/integration/adversarial/test_adv_roles.py",
            "tests/integration/adversarial/test_adv_roles_reattack.py",
            "tests/integration/adversarial/test_adv_bootstrap.py",
            "tests/integration/adversarial/test_adv_bootstrap_reattack.py",
            "tests/integration/test_cli_db.py",
            "tests/integration/adversarial/test_adv_cli_db.py",
            "tests/integration/adversarial/test_adv_secrets_db.py",
            "tests/integration/db/test_engine.py",
            "tests/integration/ops/test_web_login.py",  # Q-A2: the web's own login
        ),
        unit_tests=(
            "tests/unit/test_roles_edges.py",
            "tests/unit/test_cli.py",
            "tests/unit/adversarial/test_adv_roles_config.py",
            "tests/unit/adversarial/test_adv_roles_config_reattack.py",
        ),
        # RUNTIME_ROLE renamed; _password_verifier returning None (PASSWORD NULL).
        unit_only=('"argus_runtime"', 'return sql.Literal(verifier.decode("ascii"))'),
        unit_only_lines=("_GROUP_STATE = ", "_LOGIN_STATE = "),
        link_env=True,
        test_timeout=60,
        # The tests rename and alter the cluster-wide role argus_runtime: one run at a time.
        max_workers=1,
    ),
    "netguard": Target(
        "tests/_guard/argus_netguard.py",
        tests=(
            "tests/_guard/test_netguard_edges.py",
            "tests/unit/test_network_guard.py",
            "tests/_guard/test_harness.py",
            "tests/unit/adversarial/test_adv_cli_guard.py",
            "tests/unit/adversarial/test_adv_secrets.py",
            "tests/unit/test_cli.py",
            "tests/_guard/test_hypothesis_profiles.py",
            "tests/_guard/test_nested_runs.py",
        ),
        guard=True,
        test_timeout=120,
    ),
    # R2: the fixture toolkit. Every module is reached by the unit tests alone.
    "fx_ipmap": Target(
        "src/argus/fixtures/ipmap.py",
        tests=(
            "tests/unit/fixtures/test_ipmap_search.py",  # exact small-width searches: fast
            "tests/unit/fixtures/test_known_answers.py",
            "tests/unit/fixtures/test_ipmap.py",
            "tests/unit/adversarial/test_adv_fixtures_ipmap.py",
            *_FIXTURE_TESTS,
        ),
        max_workers=6,
    ),
    "fx_tokens": Target(
        "src/argus/fixtures/tokens.py",
        tests=(
            "tests/unit/fixtures/test_known_answers.py",
            "tests/unit/fixtures/test_golden.py",
            "tests/unit/fixtures/test_tokens_and_sanitizer.py",
            "tests/unit/adversarial/test_adv_fixtures_integrity.py",
            *_FIXTURE_TESTS,
        ),
        max_workers=6,
    ),
    "fx_sanitizer": Target(
        "src/argus/fixtures/sanitizer.py",
        tests=(
            "tests/unit/fixtures/test_golden.py",
            "tests/unit/fixtures/test_tokens_and_sanitizer.py",
            "tests/unit/adversarial/test_adv_fixtures_survival.py",
            *_FIXTURE_TESTS,
        ),
        max_workers=6,
    ),
    "fx_leakscan": Target(
        "src/argus/fixtures/leakscan.py",
        tests=(
            "tests/unit/fixtures/test_leakscan.py",
            "tests/unit/adversarial/test_adv_fixtures_scanner.py",
            *_FIXTURE_TESTS,
        ),
        max_workers=6,
    ),
    "fx_policy": Target(
        "src/argus/fixtures/policy.py",
        tests=("tests/unit/fixtures/test_policy.py", *_FIXTURE_TESTS),
        max_workers=6,
    ),
    # R3: the normalizer and the asset map. The unit tests reach every module but the store's
    # staging and commit, which only the CLI integration test exercises (link_env).
    "nz_normalizer": Target(
        "src/argus/normalize/normalizer.py", tests=_NORMALIZE_TESTS, max_workers=6
    ),
    "nz_canon": Target("src/argus/normalize/canon.py", tests=_NORMALIZE_TESTS, max_workers=6),
    "nz_fields": Target("src/argus/normalize/fields.py", tests=_NORMALIZE_TESTS, max_workers=6),
    "nz_grouping": Target("src/argus/normalize/grouping.py", tests=_NORMALIZE_TESTS, max_workers=6),
    "nz_model": Target("src/argus/normalize/model.py", tests=_NORMALIZE_TESTS, max_workers=6),
    "nz_times": Target("src/argus/normalize/times.py", tests=_NORMALIZE_TESTS, max_workers=6),
    "as_assetmap": Target(
        "src/argus/assets/assetmap.py",
        tests=(
            "tests/unit/assets/test_assetmap_mutants.py",
            "tests/unit/assets/test_assetmap.py",
            "tests/unit/assets/test_classify.py",
            *_NORMALIZE_TESTS,
        ),
        max_workers=6,
    ),
    "as_classify": Target(
        "src/argus/assets/classify.py",
        tests=(
            "tests/unit/assets/test_classify.py",
            "tests/unit/assets/test_assetmap_mutants.py",
            "tests/unit/assets/test_assetmap.py",
            *_NORMALIZE_TESTS,
        ),
        max_workers=6,
    ),
    "as_store": Target(
        "src/argus/assets/store.py",
        tests=(
            "tests/unit/assets/test_store.py",
            "tests/unit/assets/test_assetmap.py",
            "tests/integration/test_cli_db.py::test_assets_import",
        ),
        link_env=True,
        test_timeout=60,
        max_workers=2,
    ),
    # R4: the Elastic Gateway. The gate asks >= 95% on the validator and index resolution.
    **{
        f"gw_{name}": Target(f"src/argus/gateway/{name}.py", tests=_GATEWAY_UNIT, max_workers=6)
        for name in (
            "validator",
            "indices",
            "budget",
            "breaker",
            "health",
            "responses",
            "gateway",
            "templates",
            "transport",
            "cassettes",
            "builtin",
        )
    },
    "gw_pgstore": Target(
        "src/argus/gateway/pgstore.py",
        tests=(
            *_GATEWAY_DB,
            "tests/unit/ops/test_probe_history.py",  # Q-A2: the probe readings
            "tests/integration/ops/test_probe_history.py",
            "tests/integration/measure/test_measure_db.py",  # Q-A3: the readings read back
        ),
        link_env=True,
        test_timeout=60,
        max_workers=2,
    ),
    "gw_service": Target(
        "src/argus/gateway/service.py",
        tests=(
            "tests/unit/ops/test_probe_history.py",  # Q-A2: the probe keeps its readings
            "tests/integration/gateway/test_service.py",
            "tests/unit/gateway/test_review1.py",
            "tests/unit/gateway/test_service_mutants.py",
        ),
        link_env=True,
        test_timeout=60,
        max_workers=2,
    ),
    # R5: the collector (D-050). Its tests need Postgres.
    **{
        f"co_{name}": Target(
            f"src/argus/collector/{name}.py",
            tests=(
                "tests/unit/collector/test_collector_mutants.py",
                "tests/integration/collector/test_collector.py",
                "tests/integration/collector/test_review1.py",
                "tests/integration/collector/test_mutants.py",
                "tests/integration/collector/test_resilience.py",
            ),
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name in ("collector", "store", "runner", "templates")
    },
    # R6: grouping and the job queue (D-051); the real-day replay is left to the suite.
    **{
        name: Target(
            path,
            tests=(
                "tests/integration/grouping/test_mutants.py",
                *(
                    f"tests/integration/grouping/test_grouping.py::{test}"
                    for test in (
                        "test_buckets_start_at_midnight_ist",
                        "test_duplicates_continues_and_the_first_job",
                        "test_any_order_and_batch_split_give_the_same_investigations",
                        "test_eight_concurrent_groupers_agree_with_one",
                        "test_a_lost_lease_cannot_complete",
                        "test_a_change_while_running_queues_the_job_again",
                        "test_failures_back_off_then_give_up",
                        "test_100_worker_kills_lose_and_duplicate_nothing",
                    )
                ),
                "tests/integration/context/test_runtime.py",
                "tests/integration/context/test_review1.py",
            ),
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name, path in (
            ("gr_assign", "src/argus/grouping/assign.py"),
            ("gr_store", "src/argus/grouping/store.py"),
            ("gr_regroup", "src/argus/grouping/regroup.py"),
            ("jb_queue", "src/argus/jobs/queue.py"),
        )
    },
    # R7: the Inbox (D-052); the browser and Schemathesis checks run in the suite.
    **{
        f"web_{name}": Target(
            f"src/argus/web/{name}.py",
            tests=(
                "tests/unit/web/test_web_units.py",
                "tests/integration/web/test_inbox.py",
                "tests/integration/web/test_mutants.py",
                "tests/integration/web/test_app_mutants.py",
                "tests/integration/web/test_columns.py",
                "tests/integration/web/test_r15.py",
                "tests/integration/web/test_queries_exact.py",
                "tests/integration/web/test_app_exact.py",
                "tests/integration/web/test_reviewed.py",
                "tests/integration/web/test_network.py",  # D-104
                # Phase 2's pages (P8, D-094..D-103): their routes are in app.py too
                "tests/integration/web/test_assessments.py",
                "tests/integration/web/test_assessed_exact.py",
                "tests/integration/web/test_gold.py",
                "tests/integration/web/test_gold_cases.py",
                "tests/integration/web/test_dashboard.py",
                "tests/integration/web/test_app_routes_exact.py",  # every route word for word
                *_QA1_TESTS,  # Q-A1: sessions, the route test, /api/v1
                "tests/integration/web/test_spa.py",  # Q-B1: the /app routes and headers
                "tests/integration/web/test_classic_switch.py",  # Q-B4: the switch and /classic
            ),
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name in ("auth", "queries", "reviews", "render", "app")
    },
    # Q-A1: the session contract, the capability model, the request rules, /api/v1
    **{
        f"web_{name.replace('/', '_')}": Target(
            f"src/argus/web/{name}.py",
            tests=_QA1_TESTS,
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name in (
            "capabilities",
            "security",
            "deps",
            "links",
            "openapi",
            "params",
            "cli",
            "v1/models",
            "v1/views",
            "v1/routes",
        )
    },
    # R8: the context graph (D-054). Fast unit tests first, then the graph on Postgres.
    **{
        f"cx_{name}": Target(
            f"src/argus/context/{name}.py",
            tests=(
                "tests/unit/context/test_evidence.py",
                "tests/unit/context/test_mutants.py",
                "tests/unit/context/test_packs_and_ddl.py",
                "tests/unit/context/test_capacity.py",
                "tests/integration/context/test_review1.py",
                "tests/integration/context/test_store_exact.py",
                "tests/unit/context/test_notes.py",
                "tests/integration/context/test_generic.py",
                "tests/integration/context/test_smoke.py",
                "tests/integration/context/test_runtime.py",
                "tests/integration/context/test_cli.py",
                "tests/integration/context/test_gate.py",
                "tests/unit/context/test_web_heuristics.py",
                "tests/unit/context/test_intel_units.py",
                "tests/unit/context/test_proxy_units.py",
                "tests/integration/context/test_intel.py",
                "tests/integration/context/test_proxy.py",
                "tests/integration/context/test_web.py",
                "tests/integration/context/test_graph_exact.py",
                "tests/integration/context/test_worker_exact.py",
            ),
            link_env=True,
            test_timeout=180,
            max_workers=4,
        )
        for name in (
            "evidence",
            "packs",
            "store",
            "graph",
            "worker",
            "checkpoints",
            "notes",
            "generic",
            "display",
            "intel",
            "proxy",
            "web",
            "heuristics",
        )
    },
    # Q-F4: the evidence templates of batch 1 (plan §4: 100 % on the gate, evidence status;
    # >= 85 % elsewhere). Fast unit tests first, then the gate on Postgres.
    **{
        f"cx_{name}": Target(
            f"src/argus/context/{name}.py",
            tests=(
                "tests/unit/context/test_batch1_units.py",
                "tests/unit/context/test_batch1_review.py",
                "tests/unit/context/test_batch1_review_send.py",
                "tests/integration/context/test_batch1_gate.py",
                "tests/integration/context/test_batch1_review_gate.py",
            ),
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name in ("bounds", "beacon", "dns", "paths", "source_events", "batch1")
    },
    # D-069: the log templates' first production runs; its own tests only (fast).
    "cx_live_check": Target(
        "src/argus/context/live_check.py",
        tests=("tests/integration/context/test_live_check.py",),
        link_env=True,
        test_timeout=60,
        max_workers=4,
    ),
    # R9: reference data (D-057).
    **{
        f"rf_{name}": Target(
            f"src/argus/reference/{name}.py",
            tests=(
                "tests/unit/reference/test_ti.py",
                "tests/integration/reference/test_reference.py",
                "tests/integration/reference/test_knowledge.py",
                "tests/integration/reference/test_review9.py",
            ),
            link_env=True,
            test_timeout=120,
            max_workers=4,
        )
        for name in ("ti", "store", "templates", "knowledge")
    },
    # R16/R17: the soak and the write-back outbox (D-061).
    "sk_soak": Target(
        "src/argus/soak.py",
        tests=(
            "tests/integration/test_soak.py",
            "tests/integration/test_incident_simulation.py",
            "tests/integration/web/test_reviewed.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=4,
    ),
    "wb_writeback": Target(
        "src/argus/writeback.py",
        tests=("tests/integration/writeback/test_writeback.py",),
        link_env=True,
        test_timeout=120,
        max_workers=4,
    ),
    "cx_capacity": Target(
        "src/argus/context/capacity.py",
        tests=("tests/unit/context/test_capacity.py", "tests/integration/context/test_cli.py"),
        link_env=True,
        test_timeout=120,
        max_workers=4,
    ),  # Phase 2, P1: the privacy layer (D-076). Pure code: unit tests only.
    **{
        f"llm_{name}": Target(
            f"src/argus/llm/{name}.py",
            tests=(
                "tests/unit/llm/test_detect.py",
                "tests/unit/llm/test_detect_exact.py",
                "tests/unit/llm/test_privacy.py",
                "tests/unit/llm/test_privacy_golden.py",
                "tests/unit/llm/test_privacy_exact.py",
                "tests/unit/llm/test_privacy_more.py",
                "tests/unit/llm/test_egress.py",
                "tests/unit/llm/test_arms.py",
            ),
            test_timeout=60,
            max_workers=4,
        )
        for name in ("detect", "privacy", "egress")
    },
    # P2: the gold set and the harness (D-080, D-082).
    "ev_gold": Target(
        "src/argus/evaluation/gold.py",
        tests=("tests/unit/evaluation/test_gold.py",),
        test_timeout=60,
        max_workers=4,
    ),
    "ev_harness": Target(
        "src/argus/evaluation/harness.py",
        tests=("tests/unit/evaluation/test_harness.py",),
        test_timeout=60,
        max_workers=4,
    ),
    "ev_store": Target(
        "src/argus/evaluation/store.py",
        tests=("tests/integration/web/test_gold.py",),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # P3/P4: the assessment queue, runner and decision engine (D-084, D-085).
    "as_queue": Target(
        "src/argus/assess/queue.py",
        tests=(
            "tests/integration/assess/test_queue.py",
            "tests/integration/assess/test_engine_store.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "as_runner": Target(
        "src/argus/assess/runner.py",
        tests=("tests/integration/assess/test_queue.py", "tests/unit/agent/test_triggers.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "as_engine": Target(
        "src/argus/assess/engine.py",
        tests=("tests/unit/assess/test_engine.py", "tests/integration/assess/test_engine_store.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # P2's privacy comparison (D-078): the arms and their scoring.
    "llm_arms": Target(
        "src/argus/llm/arms.py",
        tests=("tests/unit/llm/test_arms.py",),
        test_timeout=60,
        max_workers=4,
    ),
    "llm_compare": Target(
        "src/argus/llm/compare.py",
        tests=("tests/unit/llm/test_compare.py",),
        test_timeout=60,
        max_workers=4,
    ),
    # P5: the LLM gateway (D-086, D-087) and the comparison runner.
    "llm_budget": Target(
        "src/argus/llm/budget.py",
        tests=(
            "tests/unit/llm/test_budget.py",
            "tests/unit/llm/test_gateway_exact.py",
            "tests/unit/llm/test_gateway.py",
        ),
        test_timeout=180,
        max_workers=3,
    ),
    "llm_gateway": Target(
        "src/argus/llm/gateway.py",
        tests=("tests/unit/llm/test_gateway_exact.py", "tests/unit/llm/test_gateway.py"),
        test_timeout=180,
        max_workers=3,
    ),
    **{
        f"llm_{name}": Target(
            f"src/argus/llm/{name}.py",
            tests=("tests/unit/llm/test_wire.py",),
            test_timeout=60,
            max_workers=4,
        )
        for name in ("providers", "wire")
    },
    "llm_prompts": Target(
        "src/argus/llm/prompts.py",
        tests=("tests/unit/llm/test_prompts.py", "tests/unit/evaluation/test_comparison.py"),
        test_timeout=60,
        max_workers=4,
    ),
    "llm_store": Target(
        "src/argus/llm/store.py",
        tests=("tests/integration/llm/test_store.py", "tests/integration/llm/test_cli_llm.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "ev_comparison": Target(
        "src/argus/evaluation/comparison.py",
        tests=(
            "tests/unit/evaluation/test_comparison.py",
            "tests/integration/web/test_gold_cases.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # P6: the investigation agent (docs/p6-design.md).
    "ag_agent": Target(
        "src/argus/agent/agent.py",
        tests=(
            "tests/unit/agent/test_agent.py",
            "tests/unit/agent/test_runtime.py",
            "tests/unit/agent/test_parity.py",
        ),
        test_timeout=60,
        max_workers=4,
    ),
    "ag_catalogue": Target(
        "src/argus/agent/catalogue.py",
        tests=(
            "tests/unit/agent/test_catalogue.py",
            "tests/unit/agent/test_agent.py",
            "tests/unit/agent/test_loader.py",
        ),
        test_timeout=60,
        max_workers=4,
    ),
    # Q-H1: agents as Markdown, enforced at run time (plan §7.6); the plan's target: 100 %.
    "ag_registry": Target(
        "src/argus/agent/registry.py",
        tests=(
            "tests/unit/agent/test_registry.py",
            "tests/unit/agent/test_loader.py",
            "tests/unit/agent/test_parity.py",
        ),
        test_timeout=60,
        max_workers=4,
    ),
    "ag_loader": Target(
        "src/argus/agent/loader.py",
        tests=(
            "tests/unit/agent/test_loader.py",
            "tests/unit/agent/test_runtime.py",
            "tests/unit/agent/test_triggers.py",
            "tests/unit/agent/test_parity.py",
        ),
        test_timeout=60,
        max_workers=4,
    ),
    "ag_drift": Target(
        "src/argus/agent/drift.py",
        tests=("tests/unit/agent/test_drift.py",),
        test_timeout=60,
        max_workers=4,
    ),
    "ag_service": Target(
        "src/argus/agent/service.py",
        tests=("tests/integration/agent/test_service.py",),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "ev_agent_eval": Target(
        "src/argus/evaluation/agent_eval.py",
        tests=("tests/unit/evaluation/test_agent_eval.py", "tests/unit/agent/test_parity.py"),
        test_timeout=60,
        max_workers=4,
    ),
    # P7: rule tuning (D-090).
    "tu_report": Target(
        "src/argus/tuning/report.py",
        tests=(
            "tests/integration/tuning/test_report.py",
            "tests/integration/tuning/test_report_exact.py",
            "tests/unit/tuning/test_advise.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "tu_advise": Target(
        "src/argus/tuning/advise.py",
        tests=("tests/unit/tuning/test_advise.py",),
        test_timeout=60,
        max_workers=4,
    ),
    "tu_store": Target(
        "src/argus/tuning/store.py",
        tests=("tests/integration/tuning/test_report.py",),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # P8: assessments in the Inbox (D-091); P9: the Phase 2 soak report (D-092).
    "web_assessed": Target(
        "src/argus/web/assessed.py",
        tests=(
            "tests/integration/web/test_assessments.py",
            "tests/integration/web/test_assessed_exact.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # AR4 after its review (D-187): Home's patterns, counted in SQL and held to stance.recommend
    "web_patternsummary": Target(
        "src/argus/web/patternsummary.py",
        tests=("tests/integration/web/test_patterns_summary_ar4.py",),
        link_env=True,
        test_timeout=180,
        max_workers=3,
    ),
    # Q-B1: serving /app (plan §4: 85 %); its routes and headers are in app.py (web_app)
    "web_spa": Target(
        "src/argus/web/spa.py",
        tests=("tests/unit/web/test_spa.py", "tests/integration/web/test_spa.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # Q-B4: where a classic address leads in the app (plan §4: 85 %); the switch is in web_app
    "web_classic": Target(
        "src/argus/web/classic.py",
        tests=("tests/unit/web/test_classic.py", "tests/integration/web/test_classic_switch.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "web_dashboard": Target(  # D-103; Q-B2's threat-list tile
        "src/argus/web/dashboard.py",
        tests=(
            "tests/unit/web/test_dashboard.py",
            "tests/unit/web/test_threat_tile.py",
            "tests/integration/web/test_dashboard.py",
            "tests/integration/web/test_v1_b2.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # Q-B3: the case pages' reads and words, and their routes (plan §4: 85 %)
    "web_casepages": Target(
        "src/argus/web/casepages.py",
        tests=(
            "tests/unit/web/test_casepages.py",
            "tests/integration/web/test_cases_b3.py",
            "tests/integration/web/test_approvals_b3.py",
            "tests/integration/web/test_notes_checks_b3.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "web_case_routes": Target(
        "src/argus/web/v1/case_routes.py",
        tests=(
            "tests/integration/web/test_cases_b3.py",
            "tests/integration/web/test_approvals_b3.py",
            "tests/integration/web/test_notes_checks_b3.py",
            "tests/integration/web/test_routes_declared.py",
        ),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    "sk_soak2": Target(
        "src/argus/soak2.py",
        tests=("tests/integration/test_soak2.py", "tests/integration/test_soak2_exact.py"),
        link_env=True,
        test_timeout=120,
        max_workers=3,
    ),
    # Q-C1: the case record (plan §4: 100 % on the state machine, outbox, approvals and the
    # audit chain). Unit tests first, so most mutants die before a database is made.
    "ca_model": Target(
        "src/argus/cases/model.py",
        tests=(*_CASES_UNIT, "tests/integration/cases/test_service.py"),
        link_env=True,
        test_timeout=120,
    ),
    "ca_outbox": Target(
        "src/argus/cases/outbox.py",
        tests=(*_CASES_UNIT, "tests/integration/cases/test_guards.py"),
        link_env=True,
        test_timeout=120,
    ),
    "ca_kibana": Target(
        "src/argus/cases/kibana.py",
        tests=(
            *_CASES_UNIT,
            "tests/integration/cases/test_guards.py",
            "tests/integration/cases/test_review.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    "ca_machine": Target(
        "src/argus/cases/machine.py",
        tests=(*_CASES_UNIT, *_CASES_DB),
        link_env=True,
        test_timeout=120,
    ),
    "ca_approvals": Target(
        "src/argus/cases/approvals.py",
        tests=(
            *_CASES_UNIT,
            *_CLOSURE_DB,
            "tests/integration/cases/test_service.py",
            "tests/integration/cases/test_guards.py",
            "tests/integration/cases/test_review.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    # Q-C3 (plan §4: 100 % on approvals, the send-time checks, signatures and identity)
    "ca_signing": Target(
        "src/argus/cases/signing.py",
        tests=("tests/unit/cases/test_closure_parts.py", *_CLOSURE_DB),
        link_env=True,
        test_timeout=120,
    ),
    "ca_identity": Target(
        "src/argus/cases/identity.py",
        tests=(
            "tests/unit/cases/test_closure_parts.py",
            *_CLOSURE_DB,
            "tests/integration/web/test_stepup_checks.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    "ca_closure": Target(
        "src/argus/cases/closure.py",
        tests=(*_CASES_UNIT, *_CLOSURE_DB, "tests/integration/cases/test_service.py"),
        link_env=True,
        test_timeout=120,
    ),
    "ca_desk": Target(
        "src/argus/cases/desk.py",
        tests=_CLOSURE_DB,
        link_env=True,
        test_timeout=180,
    ),
    "ca_sendcheck": Target(
        "src/argus/cases/sendcheck.py",
        tests=_CLOSURE_DB,
        link_env=True,
        test_timeout=180,
    ),
    "ca_proposer": Target(
        "src/argus/cases/proposer.py",
        tests=(
            "tests/integration/cases/test_closure_review.py",
            "tests/integration/cases/test_closure_approval.py",
            "tests/integration/cases/test_cli.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    "ca_autonomy": Target(
        "src/argus/cases/autonomy.py",
        tests=(
            "tests/integration/cases/test_closure_review.py",
            "tests/unit/cases/test_closure_parts.py",
            "tests/integration/cases/test_closure_approval.py",
            "tests/integration/cases/test_cli.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    "ca_chain": Target(
        "src/argus/cases/chain.py",
        tests=(
            "tests/integration/cases/test_chain.py",
            "tests/integration/cases/test_cli.py",
            "tests/integration/cases/test_merge_notes.py",
            "tests/integration/cases/test_review.py",
        ),
        link_env=True,
        test_timeout=180,
    ),
    "ca_service": Target(
        "src/argus/cases/service.py",
        tests=(*_CASES_DB, *_CLOSURE_DB),
        link_env=True,
        test_timeout=120,
    ),
    "ca_opener": Target(
        "src/argus/cases/opener.py",
        tests=(
            *_CASES_UNIT,
            "tests/integration/cases/test_opener.py",
            "tests/integration/cases/test_cli.py",
            "tests/integration/cases/test_review.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    # Q-C2 (plan §4: 100 % on the rules that decide membership and "contained", >= 85 % on the
    # runner's wiring)
    "ca_membership": Target(
        "src/argus/cases/membership.py",
        tests=(*_WATCH_UNIT, "tests/unit/cases/test_parts.py", _WATCH_DB[0]),
        link_env=True,
        test_timeout=120,
    ),
    "ca_watch": Target(
        "src/argus/cases/watch.py",
        tests=(*_WATCH_UNIT, _WATCH_DB[0]),
        link_env=True,
        test_timeout=120,
    ),
    "ca_watchrun": Target(
        "src/argus/cases/watchrun.py",
        tests=(*_WATCH_UNIT, *_WATCH_DB, "tests/integration/cases/test_watch_cli.py"),
        link_env=True,
        test_timeout=180,
    ),
    "ca_cli": Target(
        "src/argus/cases/cli.py",
        tests=("tests/integration/cases/test_cli.py", "tests/integration/cases/test_review.py"),
        link_env=True,
        test_timeout=180,
    ),
    # Q-H4: the notices. Pure rules, words and addresses on unit tests; the triggers, the pass and
    # the command also on Postgres and the fake relay (tests/fakesmtp.py).
    "nt_address": Target(
        "src/argus/notices/address.py",
        tests=("tests/unit/notices/test_address.py", "tests/unit/notices/test_settings.py"),
        max_workers=4,
    ),
    "nt_model": Target(
        "src/argus/notices/model.py",
        tests=("tests/unit/notices/test_model.py", "tests/unit/notices/test_render.py"),
        max_workers=4,
    ),
    "nt_render": Target(
        "src/argus/notices/render.py",
        tests=("tests/unit/notices/test_render.py",),
        max_workers=4,
    ),
    "nt_mail": Target(
        "src/argus/notices/mail.py",
        tests=("tests/unit/notices/test_mail.py", "tests/unit/notices/test_address.py"),
        max_workers=4,
    ),
    "nt_triggers": Target(
        "src/argus/notices/triggers.py",
        tests=("tests/unit/notices/test_triggers.py", "tests/integration/notices/test_triggers.py"),
        link_env=True,
        test_timeout=120,
    ),
    "nt_run": Target(
        "src/argus/notices/run.py",
        tests=(
            "tests/unit/notices/test_settings.py",
            "tests/integration/notices/test_run.py",
            "tests/integration/notices/test_differential.py",
            "tests/integration/notices/test_end_to_end.py",
            "tests/integration/notices/test_cli.py",
        ),
        link_env=True,
        test_timeout=180,
    ),
    # Q-H3: the Reporter. The number extractor, the check and the prose door are the plan's
    # "100 % on number paths"; the section builders run on Postgres against the independent
    # recomputation (tests/integration/reporter/oracle.py).
    "rp_figures": Target(
        "src/argus/reporter/figures.py",
        tests=("tests/unit/reporter/test_figures.py",),
        max_workers=4,
    ),
    "rp_prose": Target(
        "src/argus/reporter/prose.py",
        tests=("tests/unit/reporter/test_report_parts.py", "tests/unit/reporter/test_figures.py"),
        max_workers=4,
    ),
    "rp_render": Target(
        "src/argus/reporter/render.py",
        tests=("tests/unit/reporter/test_report_parts.py",),
        max_workers=4,
    ),
    "rp_model": Target(
        "src/argus/reporter/model.py",
        tests=("tests/unit/reporter/test_report_parts.py",),
        max_workers=4,
    ),
    "rp_sections": Target(
        "src/argus/reporter/sections.py",
        tests=(
            "tests/unit/reporter/test_report_parts.py",
            "tests/integration/reporter/test_numbers.py",
        ),
        link_env=True,
        test_timeout=180,
    ),
    "rp_build": Target(
        "src/argus/reporter/build.py",
        tests=(
            "tests/unit/reporter/test_report_parts.py",
            "tests/integration/reporter/test_reports.py",
        ),
        link_env=True,
        test_timeout=180,
    ),
    "rp_store": Target(
        "src/argus/reporter/store.py",
        tests=(
            "tests/integration/reporter/test_reports.py",
            "tests/integration/reporter/test_web.py",
        ),
        link_env=True,
        test_timeout=180,
    ),
    "rp_cli": Target(
        "src/argus/reporter/cli.py",
        tests=("tests/integration/reporter/test_reports.py",),
        link_env=True,
        test_timeout=180,
    ),
    # Q-A2: platform and operations. The plan asks >= 85% here (100% stays on roles).
    "ops_units": Target(
        "src/argus/ops/units.py",
        tests=("tests/unit/ops/test_units.py", "tests/unit/ops/test_checks.py"),
        max_workers=4,
    ),
    "ops_certs": Target(
        "src/argus/ops/certs.py",
        tests=("tests/unit/ops/test_certs.py", "tests/unit/ops/test_checks.py"),
        max_workers=4,
    ),
    "ops_frontend": Target(
        "src/argus/ops/frontend.py",
        tests=(
            "tests/unit/ops/test_frontend.py",
            "tests/unit/ops/test_checks.py",
            "tests/unit/ops/test_scripts.py",
        ),
        max_workers=4,
    ),
    "ops_checks": Target(
        "src/argus/ops/checks.py",
        tests=(
            "tests/unit/ops/test_checks.py",
            "tests/unit/ops/test_secrets_everywhere.py",
            "tests/integration/ops/test_probe_history.py",
        ),
        link_env=True,
        test_timeout=60,
        max_workers=2,
    ),
    # Q-A5: credential custody (security list: 100 % after justified equivalents, plan §4)
    "ops_custody": Target(
        "src/argus/ops/custody.py",
        tests=(
            "tests/unit/ops/test_custody_import.py",
            "tests/unit/ops/test_custody_layout.py",
            "tests/unit/ops/test_custody_permissions.py",
        ),
        test_timeout=60,
        max_workers=3,
    ),
    # Q-A3: the budget's re-measurement (the session, its derivation, Kibana's relative costs)
    "ms_session": Target(
        "src/argus/measure/session.py",
        tests=(
            "tests/unit/measure/test_session.py",
            "tests/unit/measure/test_properties.py",
            "tests/unit/measure/test_cassette.py",
            "tests/unit/measure/test_lanes.py",
            "tests/unit/measure/test_review.py",
        ),
        max_workers=4,
    ),
    "ms_lanes": Target(
        "src/argus/measure/lanes.py",
        tests=(
            "tests/unit/measure/test_lanes.py",
            "tests/unit/measure/test_properties.py",
            "tests/unit/measure/test_review.py",
        ),
        max_workers=4,
    ),
    "ms_kibana": Target(
        "src/argus/measure/kibana.py",
        tests=("tests/unit/measure/test_kibana.py",),
        max_workers=4,
    ),
    "ms_cli": Target(
        "src/argus/measure/cli.py",
        tests=(
            "tests/integration/measure/test_measure_db.py",
            "tests/unit/measure/test_kibana.py",
            "tests/unit/measure/test_review.py",
        ),
        link_env=True,
        test_timeout=60,
        max_workers=2,
    ),
    # Q-D3, the Kibana read-back: plan §4's 100 % on the reconciliation (classify, the cycle,
    # the store); ≥ 85 % on the read model and the CLI
    "ks_classify": Target(
        "src/argus/kibana_sync/classify.py",
        tests=("tests/unit/kibana_sync/test_classify.py", "tests/unit/kibana_sync/test_cycle.py"),
        max_workers=4,
    ),
    "ks_model": Target(
        "src/argus/kibana_sync/model.py",
        tests=(
            "tests/unit/kibana_sync/test_classify.py",
            "tests/unit/kibana_sync/test_contract.py",
            "tests/unit/kibana_sync/test_cycle.py",
        ),
        max_workers=4,
    ),
    "ks_cycle": Target(
        "src/argus/kibana_sync/cycle.py",
        tests=("tests/unit/kibana_sync/test_cycle.py", "tests/unit/kibana_sync/test_week.py"),
        test_timeout=120,
        max_workers=4,
    ),
    "ks_store": Target(
        "src/argus/kibana_sync/store.py",
        tests=(
            "tests/unit/kibana_sync/test_cycle.py",
            "tests/integration/kibana_sync/test_pg_sync.py",
        ),
        link_env=True,
        test_timeout=120,
    ),
    "ks_readmodel": Target(
        "src/argus/kibana_sync/readmodel.py",
        tests=("tests/unit/kibana_sync/test_week.py", "tests/unit/kibana_sync/test_cli.py"),
        max_workers=4,
    ),
    "ks_cli": Target(
        "src/argus/kibana_sync/cli.py",
        tests=("tests/unit/kibana_sync/test_cli.py",),
        max_workers=4,
    ),
    # Q-D5, the alert status write-back: plan §4's 100 % on the sender and the planner (the
    # answer's check is in gateway/kibana/models.py). The sender's tests run on a throwaway
    # database.
    "wb_sender": Target(
        "src/argus/writeback_sender.py",
        tests=(
            "tests/integration/writeback/test_writeback.py",
            "tests/integration/writeback/test_v2.py",
            "tests/integration/writeback/test_closure.py",
            "tests/integration/writeback/test_cli_run.py",
            "tests/unit/writeback/test_answer.py",
        ),
        link_env=True,
        test_timeout=300,
        max_workers=1,
    ),
    "wb_plan": Target(
        "src/argus/writeback.py",
        tests=(
            "tests/integration/writeback/test_writeback.py",
            "tests/integration/writeback/test_v2.py",
            "tests/integration/writeback/test_closure.py",
            "tests/unit/writeback/test_cli.py",
        ),
        link_env=True,
        test_timeout=300,
        max_workers=1,
    ),
    # Q-D4, the case writer: plan §4's 100 % on the renderer, the sender and the reconciliation
    # of writes in doubt (render, plan, sender, lookup, compensation, approval, ramp, store's
    # moves); ≥ 85 % on the service and the CLI. The sender's tests run on a throwaway database.
    "wr_render": Target(
        "src/argus/writer/render.py",
        tests=("tests/unit/writer/test_render.py",),
        max_workers=4,
    ),
    "wr_plan": Target(
        "src/argus/writer/plan.py",
        tests=("tests/unit/writer/test_plan.py", "tests/integration/writer/test_w2.py"),
        link_env=True,
        test_timeout=120,
        max_workers=2,
    ),
    "wr_sender": Target(
        "src/argus/writer/sender.py",
        tests=(
            "tests/integration/writer/test_w1.py",
            "tests/integration/writer/test_w2.py",
            "tests/integration/writer/test_w3.py",
            "tests/integration/writer/test_unknown.py",
            "tests/integration/writer/test_faults.py",
            "tests/integration/writer/test_attach.py",
            "tests/integration/writer/test_gates.py",
        ),
        link_env=True,
        test_timeout=300,
        max_workers=1,
    ),
    "wr_lookup": Target(
        "src/argus/writer/lookup.py",
        tests=(
            "tests/integration/writer/test_unknown.py",
            "tests/integration/writer/test_faults.py",
            "tests/integration/writer/test_attach.py",
        ),
        link_env=True,
        test_timeout=300,
        max_workers=1,
    ),
    "wr_compensation": Target(
        "src/argus/writer/compensation.py",
        tests=("tests/integration/writer/test_compensation.py",),
        link_env=True,
        test_timeout=120,
        max_workers=1,
    ),
    "wr_approval": Target(
        "src/argus/writer/approval.py",
        tests=(
            "tests/integration/writer/test_compensation.py",
            "tests/integration/writer/test_unknown.py",
        ),
        link_env=True,
        test_timeout=180,
        max_workers=1,
    ),
    "wr_ramp": Target(
        "src/argus/writer/ramp.py",
        tests=("tests/integration/writer/test_ramp.py",),
        link_env=True,
        test_timeout=120,
        max_workers=1,
    ),
    "wr_store": Target(
        "src/argus/writer/store.py",
        tests=(
            "tests/integration/writer/test_w1.py",
            "tests/integration/writer/test_attach.py",
            "tests/integration/writer/test_database.py",
        ),
        link_env=True,
        test_timeout=300,
        max_workers=1,
    ),
    "wr_service": Target(
        "src/argus/writer/service.py",
        tests=("tests/integration/writer/test_ramp.py",),
        link_env=True,
        test_timeout=120,
        max_workers=1,
    ),
    "wr_cli": Target(
        "src/argus/writer/cli.py",
        tests=("tests/integration/writer/test_ramp.py", "tests/unit/writer/test_cli.py"),
        link_env=True,
        test_timeout=120,
        max_workers=1,
    ),
    # Q-A4: the retention purge (its selection is on the security list: 100 % after justified
    # equivalents, plan §4); one run at a time, each test writes and purges a database
    "ops_purge": Target(
        "src/argus/ops/purge.py",
        tests=(
            "tests/unit/ops/test_purge_unit.py",
            "tests/integration/ops/test_purge.py",
            "tests/integration/ops/test_purge_review.py",
            "tests/integration/cases/test_purge_holds.py",
        ),
        link_env=True,
        test_timeout=180,
        max_workers=1,
    ),
    "ops_purge_cli": Target(
        "src/argus/ops/purge_cli.py",
        tests=("tests/unit/ops/test_purge_unit.py", "tests/integration/ops/test_purge_cli.py"),
        link_env=True,
        test_timeout=120,
        max_workers=1,
    ),
    # its integration tests run pg_dump and pg_restore in containers: one run at a time
    "ops_backup": Target(
        "src/argus/ops/backup.py",
        tests=("tests/unit/ops/test_backup_units.py", "tests/integration/ops/test_backup.py"),
        link_env=True,
        test_timeout=180,
        max_workers=1,
    ),
}

# Mutants that cannot change what the code does, by target: their signature (Mutant.signature:
# scope, source line, column, change) and why. An edited line no longer matches: judge it again.
EQUIVALENT: dict[str, dict[str, str]] = {
    "web_app": {  # the Inbox app: reviewed one by one (2026-10-22)
        'create_app: outcome: Annotated[str, Form(max_length=40, pattern=CLEAN)] = "", @62: "" ->'
        ' "XXXX" #2': (
            "the gold form refuses both an empty and an unknown outcome with the same message"
        ),
        'client_of: return request.client.host if request.client else "unknown" @50: "unk'
        'nown" -> "XXunknownXX"': (
            "an ASGI server always gives the client; a request without one is refused by th"
            "e guard either way"
        ),
        'client_allowed: address = ipaddress.ip_address(host or "") @39: "" -> "XXXX"': (
            "neither is an address: both are refused"
        ),
        "reviewer_or_none: if not token or len(token) > 100: @27: > -> >=": (
            "session tokens are 43 characters: none is 100 or 101 long"
        ),
        "reviewer_or_none: if not token or len(token) > 100: @29: 100 -> 101": (
            "session tokens are 43 characters: none is 100 or 101 long"
        ),
        'create_app: app.mount("/static", StaticFiles(directory=str(HERE / "static")), na'
        'me="static") @71: "static" -> "XXstaticXX"': (
            "the mount's name is never used to build a URL"
        ),
        'create_app: @app.middleware("http") @16: "http" -> "XXhttpXX"': (
            "this FastAPI adds the middleware whatever the type's name"
        ),
        'create_app.guard: host = request.headers.get("host", "") @35: "" -> "XXXX"': (
            "the trusted-host middleware refuses a request without Host before the guard runs"
        ),
        'create_app.api_logout: await auth.logout(conn, request.cookies.get(COOKIE, ""), '
        'clock()) @52: "" -> "XXXX"': (
            "the route needs a valid session, so the cookie is always there"
        ),
        'create_app.logout_form: await auth.logout(conn, request.cookies.get(COOKIE, ""),'
        ' clock()) @52: "" -> "XXXX"': (
            "logout runs only with a valid session, so the cookie is always there"
        ),
        'create_app.investigation_page: saved = SAVED.get(request.query_params.get("saved'
        '", "")) @52: "" -> "XXXX"': ("neither is a message key: no message either way"),
        'create_app: seen_review: Annotated[str, Form(max_length=20, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX"': ("neither is digits: both mean no review seen"),
        'create_app.proposals_page: done = request.query_params.get("confirmed", "") @45:'
        ' "" -> "XXXX"': ("neither is digits and dashes: both show no confirmation"),
        "create_app.raw_page: raw = await queries.raw_alert(conn, investigation_id, alert"
        "_id[:512]) @64: 512 -> 513": ("alert IDs are 40 characters: the cut never applies"),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX"': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #2': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #3': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #4': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #5': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #6': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
        'create_app: csrf_token: Annotated[str, Form(max_length=100, pattern=CLEAN)] = ""'
        ', @66: "" -> "XXXX" #7': (
            "a missing token and XXXX are both invalid: the form is refused either way"
        ),
    },
    "web_auth": {  # R7 auth: reviewed one by one (2026-10-21)
        '<module>: _DUMMY = HASHER.hash("argus-dummy-password")  # equal work for an unknown user'
        ' @21: "argus-dummy-password" -> "XXargus-dummy-passwordXX"': (
            "the dummy hash only spends the same time for an unknown name; its password is"
            " never anyone's"
        ),
        "audit: await session.close() @0: await session.close() -> pass": (
            "closing the helper session frees it; the caller's connection holds the work"
        ),
    },
    "web_security": {  # Q-A1 request rules: reviewed one by one (2026-10-23)
        "safe_next: if parts.scheme or parts.netloc: @16: or -> and": (
            "never true either way: what reaches the parse is printable ASCII (nothing urlsplit"
            " strips) starting with one '/', so urlsplit finds no scheme (it needs a letter"
            " first) and no host (it needs '//');"
            " test_urlsplit_finds_no_host_in_what_safe_next_parses holds that premise"
        ),
        'safe_next: return "/" @0: return "/" -> pass #3': (
            "the branch never runs: urlsplit finds no scheme or host there (see the line above)"
        ),
        'safe_next: return "/" @7: "/" -> "XX/XX" #3': (
            "the branch never runs: urlsplit finds no scheme or host there (see the line above)"
        ),
        'safe_next: first = parts.path.split("/", 2)[1] @30: 2 -> 3': (
            "element [1] is the text between the first and the second '/' for any maxsplit"
            " from 1 on"
        ),
        "signin_token_ok: if not cookie or not field or len(cookie) > 100 or len(field) > 100:"
        " @44: 100 -> 101": (
            "it only lets a 101-character cookie past with a field of at most 100, and texts"
            " of different lengths never encode alike (UTF-8 with surrogatepass is one-to-one):"
            " compare_digest says False, as the size check did"
        ),
        "signin_token_ok: if not cookie or not field or len(cookie) > 100 or len(field) > 100:"
        " @64: 100 -> 101": (
            "it only lets a 101-character field past with a cookie of at most 100, and texts"
            " of different lengths never encode alike: compare_digest says False, as the size"
            " check did"
        ),
    },
    "web_capabilities": {  # Q-A1 capability model: reviewed one by one (2026-10-23)
        "effective: lacking = {c for c in have if not NEEDS[c] <= have} @43: <= -> <": (
            "c is in have and never in NEEDS[c] (test_prerequisites), so NEEDS[c] is never"
            " equal to have, and 'subset' and 'proper subset' agree"
        ),
    },
    "ev_harness": {  # P2 harness: reviewed one by one (2026-10-21)
        "Rate.text: low, high = self.interval or (0.0, 0.0) @30: 0.0 -> 1.0": (
            "text() returns early without items, and with items the interval is never None"
        ),
        "Rate.text: low, high = self.interval or (0.0, 0.0) @35: 0.0 -> 1.0": (
            "text() returns early without items, and with items the interval is never None"
        ),
    },
    "llm_detect": {  # P1/P2 privacy layer (D-076 to D-078): reviewed one by one
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @0: "ip" -> "XXipXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @13: "domain" -> "XXdomainXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @23: "name" -> "XXnameXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @31: "email" -> "XXemailXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @40: "user_path" -> "XXuser_pathXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @53: "credentials" -> "XXcredentialsXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @68: "url_token" -> "XXurl_tokenXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @6: "mac" -> "XXmacXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "ip", "mac", "domain", "name", "email", "user_path", "credentia'
        'ls", "url_token", "hex_id", @81: "hex_id" -> "XXhex_idXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "roll_number", "secret", @0: "roll_number" -> "XXroll_numberXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        '<module>: "roll_number", "secret", @15: "secret" -> "XXsecretXX"': (
            "a type alias: Literal values are not checked at run time"
        ),
        'Campus.campus_domain: host = host.lower().rstrip(".") @27: "." -> "XX.XX"': (
            "the host is lower-cased first: no upper-case X is left to strip"
        ),
        'Campus.name_index: if not words or len(" ".join(words)) < least: @20: " " -> "XX XX"': (
            "two or more words are at least three characters with any separator; one word has none"
        ),
        '_base64: bare = chunk.rstrip("=") @20: "=" -> "XX=XX"': (
            "the trims below try the last three characters away; stripping an X too only drops "
            "one more trailing character no decoded value ends in"
        ),
        "_base64: continue @0: continue -> pass": (
            "a part of length 4n+1 fails to decode and is skipped by the except below"
        ),
        "_base64: for skip in range(4): @18: 4 -> 5": (
            "a skip of 4 is the alignment of a skip of 0, one group shorter: it adds no reading"
        ),
        "_base64: for trim in range(4): @18: 4 -> 5": (
            "a trim of 4 drops one whole group: it adds no reading"
        ),
        "_base64: if len(part) < 8 or len(part) % 4 == 1: @13: < -> <=": (
            "fewer than 8 characters decode to at most 5 bytes (no 7-character run); a length o"
            "f 4n+1 never decodes: both only save work"
        ),
        "_base64: if len(part) < 8 or len(part) % 4 == 1: @15: 8 -> 9": (
            "fewer than 8 characters decode to at most 5 bytes (no 7-character run); a length o"
            "f 4n+1 never decodes: both only save work"
        ),
        "_base64: if len(part) < 8 or len(part) % 4 == 1: @17: or -> and": (
            "fewer than 8 characters decode to at most 5 bytes (no 7-character run); a length o"
            "f 4n+1 never decodes: both only save work"
        ),
        "_base64: if len(part) < 8 or len(part) % 4 == 1: @30: % -> /": (
            "fewer than 8 characters decode to at most 5 bytes (no 7-character run); a length o"
            "f 4n+1 never decodes: both only save work"
        ),
        "_base64: raw = base64.b64decode(padded, altchars=alt, validate=True) @54: True -> False": (
            "the readings only grow: the right one is made in either alphabet"
        ),
        '_domains: if at > 0 and text[at - 1] == ".": @10: and -> or': (
            "at 0 there is nothing to extend; at 1 a lone dot before is stripped again; without"
            " a dot before, a domain character there makes the match fail (left) and anything e"
            "lse stops the extension"
        ),
        '_domains: if at > 0 and text[at - 1] == ".": @6: > -> >=': (
            "at 0 there is nothing to extend; at 1 a lone dot before is stripped again; without"
            " a dot before, a domain character there makes the match fail (left) and anything e"
            "lse stops the extension"
        ),
        '_domains: if at > 0 and text[at - 1] == ".": @8: 0 -> 1': (
            "at 0 there is nothing to extend; at 1 a lone dot before is stripped again; without"
            " a dot before, a domain character there makes the match fail (left) and anything e"
            "lse stops the extension"
        ),
        '_domains: while start < at and text[start] in ".-": @12: < -> <=': (
            "text[at] is the first letter of the campus suffix, never a dot or a dash"
        ),
        "_dotted: if value is None and len(parts) in (2, 3) and (_part(parts[-1], False) or 0) "
        "> 255: @74: 0 -> 1": ("the decimal reading never returns None"),
        "_ip: return None @0: return None -> pass": ("falling off the end returns None too"),
        '_ipv6: candidate = run[s:e].rstrip(".") @28: "." -> "XX.XX"': ("the run holds no X"),
        "_ipv6: continue @0: continue -> pass": (
            "every candidate with fewer than two colons is skipped again below"
        ),
        "_ipv6: done = -1 @8: 1 -> 2": ("starts are never negative: -1 and -2 skip nothing"),
        '_ipv6: ends = sorted({len(run), *(i for i, c in enumerate(run) if c in ":.")}) @64: '
        '":." -> "XX:.XX"': (
            "the run holds only hex digits, colons and dots: the X added never occurs"
        ),
        '_ipv6: if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::"'
        ") > 1: @28: or -> and": (
            "these checks only skip candidates ipaddress refuses anyway: they save work"
        ),
        '_ipv6: if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::"'
        ') > 1: @31: ":::" -> "XX:::XX"': (
            "these checks only skip candidates ipaddress refuses anyway: they save work"
        ),
        '_ipv6: if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::"'
        ") > 1: @50: or -> and": (
            "these checks only skip candidates ipaddress refuses anyway: they save work"
        ),
        '_ipv6: if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::"'
        ') > 1: @69: "::" -> "XX::XX"': (
            "these checks only skip candidates ipaddress refuses anyway: they save work"
        ),
        '_ipv6: if candidate.count(":") < 2 or ":::" in candidate or candidate.count("::"'
        ") > 1: @77: 1 -> 2": (
            "these checks only skip candidates ipaddress refuses anyway: they save work"
        ),
        "_ipv6: lo, hi = bisect.bisect_right(ends, s), bisect.bisect_right(ends, s + 45) @69: 4"
        "5 -> 46": ("the longest IPv6 text is 45 characters (eight groups or six and an IPv4)"),
        '_ipv6: starts = [0, *(i + 1 for i, c in enumerate(run) if c in ":.")] @56: ":." ->'
        ' "XX:.XX"': ("the run holds only hex digits, colons and dots: the X added never occurs"),
        '_macs: for size, width, joins in ((6, 2, ":-"), (3, 4, ".")): @34: ":-" -> "XX:-XX"': (
            "separators are colons, dashes and dots: the X added never occurs"
        ),
        '_macs: for size, width, joins in ((6, 2, ":-"), (3, 4, ".")): @48: "." -> "XX.XX"': (
            "separators are colons, dashes and dots: the X added never occurs"
        ),
        "_names: if any(s < end and start < e for s, e in tokens): @25: < -> <=": (
            "a pseudonym needs a non-word character on both sides: a name never ends where one "
            "starts or starts where one ends"
        ),
        "_names: if any(s < end and start < e for s, e in tokens): @9: < -> <=": (
            "a pseudonym needs a non-word character on both sides: a name never ends where one "
            "starts or starts where one ends"
        ),
        "_names: if any(s.group(0).lower() != n for s, n in zip(span, name, strict=True)): @66:"
        " True -> False": ("span has name's length here (checked just above)"),
        "_names: return @0: return -> pass": ("with no names the loop below finds nothing either"),
        '_part: if octal and len(text) > 1 and text.startswith("0"): @23: > -> >=': (
            "a one-character part starting with 0 is 0, the same in octal"
        ),
        '_part: return int(text, 8) if all(c in "01234567" for c in text) else None @32: "01'
        '234567" -> "XX01234567XX"': ("the part holds digits only: an X never matches"),
        '_segments: for label in m.group(0).split(".") @30: "." -> "XX.XX"': (
            "every identifier the detector matches is ASCII and stays visible in its xn-- form;"
            " punycode decoding is defence in depth"
        ),
        '_segments: label.encode("ascii").decode("idna") if label.lower().startswith("xn--'
        '") else label @65: "xn--" -> "XXxn--XX"': (
            "every identifier the detector matches is ASCII and stays visible in its xn-- form;"
            " punycode decoding is defence in depth"
        ),
        '_segments: plain = ".".join( @8: "." -> "XX.XX"': (
            "every identifier the detector matches is ASCII and stays visible in its xn-- form;"
            " punycode decoding is defence in depth"
        ),
        '_segments: yield m.start(), m.end(), " ".join(runs) @26: " " -> "XX XX"': (
            "the runs stay separated by a blank either way"
        ),
        "canonical: break @0: break -> pass": (
            "once nothing changes, further rounds change nothing"
        ),
        "canonical: continue @0: continue -> pass": ("the loop goes on either way"),
        "outermost: for item in sorted(found, key=lambda f: (f.start, -(f.end - f.start), f.kin"
        "d)): @58: - -> +": (
            "-(end + start) orders spans of one start like -(end - start): the longest first"
        ),
    },
    "llm_egress": {  # P1/P2 privacy layer (D-076 to D-078): reviewed one by one
        'foreign: item = token.split(".", 1)[0] if "." in token else None @24: 1 -> 2': (
            "only the first part is used, the same with one split or two"
        ),
    },
    "llm_privacy": {  # P1/P2 privacy layer (D-076 to D-078): reviewed one by one
        "<module>: @lru_cache(maxsize=1) @19: 1 -> 2": (
            "one value is cached: a larger cache holds the same"
        ),
        "Item: truncated: bool = False @18: False -> True": (
            "every Item is built with its truncated flag"
        ),
        "Item: withheld: int = 0 @16: 0 -> 1": ("every Item is built with its withheld count"),
        "Privacy._campus_for: continue @0: continue -> pass": ("the loop goes on either way"),
        'Privacy._item: raise TypeError("a dossier body is a mapping") @0: raise TypeError("'
        'a dossier body is a mapping") -> pass': (
            "a body that is no mapping fails on its first .get just after: the item is left out"
            " either way"
        ),
        'Privacy._item: raise TypeError("a dossier body is a mapping") @16: "a dossier body '
        'is a mapping" -> "XXa dossier body is a mappingXX"': (
            "a body that is no mapping fails on its first .get just after: the item is left out"
            " either way"
        ),
        'Privacy._web: ("categories", "request categories", "text"), @37: "text" -> "XXtextXX"': (
            "these lists hold strings, which render the same through either path"
        ),
        'Privacy._web: ("scanner_agents", "scanner user agents", "text"), @42: "text" -'
        '> "XXtextXX"': ("these lists hold strings, which render the same through either path"),
        'Privacy._web: cx.entity(kind, v) if kind != "text" else cx.any(v) for v in values @3'
        '0: "text" -> "XXtextXX"': (
            "these lists hold strings, which render the same through either path"
        ),
        'Privacy.build: domains=tuple(d.lower().strip(".") for d in policy.campus_domains), @'
        '30: "." -> "XX.XX"': ("the domain is lower-cased first: no upper-case X is left to strip"),
        "Privacy.request: for item_id, body in zip(ids, bodies, strict=True): @45: True -> False": (
            "ids is made from bodies: the same length"
        ),
        "Request.reveal: return TOKEN.sub(lambda m: own.value(m.group(0)) or m.group(0), answer"
        ") @60: 0 -> 1": ("reveal refuses unknown pseudonyms first: every one left has a value"),
        "_Scrub._ip_legend: if ip_class is IpClass.ASSET and asset is not None: @29: and -> or": (
            "the classifier sets ASSET exactly when it has an asset match"
        ),
        "_Scrub._replace: glued = f.start > 0 and _GLUE.match(text[f.start - 1]) and shown[0].i"
        "salnum() @65: 0 -> 1": (
            "shown[0] -> shown[1]: a pseudonym's second character (a digit) is alphanumeric too"
            "; the other zero is killed"
        ),
        '_Scrub.domain: host = value.strip().lower().rstrip(".") @36: "." -> "XX.XX"': (
            "the host is lower-cased first: no upper-case X is left to strip"
        ),
        '_Scrub.exact: return f"{value:.2f}".rstrip("0").rstrip(".") if math.isfinite(val'
        'ue) else "?" @29: "0" -> "XX0XX"': (
            "a formatted number holds only digits, a sign and a dot: no X to strip"
        ),
        '_Scrub.exact: return f"{value:.2f}".rstrip("0").rstrip(".") if math.isfinite(val'
        'ue) else "?" @41: "." -> "XX.XX"': (
            "a formatted number holds only digits, a sign and a dot: no X to strip"
        ),
        "_Scrub.ip: if c.ip_class in (IpClass.PUBLIC, IpClass.SPECIAL) and not internal: @51: a"
        "nd -> or": ("an address of any other class (asset, campus, internal) is always internal"),
        '_Scrub.real: return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, '
        'float) else str(value) @29: "0" -> "XX0XX"': (
            "a formatted number holds only digits, a sign and a dot: no X to strip"
        ),
        '_Scrub.real: return f"{value:.2f}".rstrip("0").rstrip(".") if isinstance(value, '
        'float) else str(value) @41: "." -> "XX.XX"': (
            "a formatted number holds only digits, a sign and a dot: no X to strip"
        ),
        "_Scrub.text: for _ in range(4): @15: 4 -> 5": (
            "replacements converge in one pass: more rounds change nothing"
        ),
        '_Scrub.text: plain = "[withheld: could not be made safe]" @0: plain = "[withheld: c'
        'ould not be made safe]" -> pass': (
            "replacements converge in one pass: the fourth round is never reached (defence in d"
            "epth)"
        ),
        '_Scrub.text: plain = "[withheld: could not be made safe]" @8: "[withheld: could not'
        ' be made safe]" -> "XX[withheld: could not be made safe]XX"': (
            "replacements converge in one pass: the fourth round is never reached (defence in d"
            "epth)"
        ),
        '_Scrub.url: keys = [q.split("=", 1)[0] for q in query.split("&") if q] @21: 1 -> 2': (
            "only the first part is used, the same with one split or two"
        ),
        '_Scrub.url: prefix, rest = "", value.split("#", 1)[0] @36: 1 -> 2': (
            "only the first part is used, the same with one split or two"
        ),
        "_Scrub: rescan = True  # look again after replacing (a comparison arm's fakes would be"
        " found again) @9: True -> False": (
            "a second pass finds nothing on every test, fuzz and real dossier: replacements hol"
            "d no identifier; it stays as defence in depth"
        ),
        '_clean: if c in "\\n\\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs", '
        '"Co", "Cn", "Zl", "Zp") @56: "Cf" -> "XXCfXX"': (
            "format characters are already removed by detect.canonical before this"
        ),
        '_clean: if c in "\\n\\t" or unicodedata.category(c) not in ("Cc", "Cf", "Cs", '
        '"Co", "Cn", "Zl", "Zp") @8: "\\n\\t" -> "XX\\n\\tXX"': (
            "an X is a letter, kept either way"
        ),
        "_cut: break @0: break -> pass": (
            "once moved off a pseudonym, the cut lies before every later one: no other matches"
        ),
        "_cut: if m.start() < cut < m.end(): @13: < -> <=": (
            "a cut exactly at a pseudonym's start moves it to the same place"
        ),
        '_label: return "HASH" if "-" not in found.value and len(found.value) in _HASH_LENG'
        'THS else "ID" @17: "-" -> "XX-XX"': (
            "a value with a dash is a UUID of 36 characters, no hash length: ID either way"
        ),
    },
    "llm_arms": {  # P1/P2 privacy layer (D-076 to D-078): reviewed one by one
        'Fakes._fake: host = value.lower().rstrip(".") @28: "." -> "XX.XX"': (
            "the host is lower-cased first: no upper-case X is left to strip"
        ),
        'Fakes.token: self._fakes[key] = self._fake(label, value, n, legend or "") @57: "" '
        '-> "XXXX"': (
            "only 'campus public' in the legend matters: an empty legend and XXXX hold neither"
        ),
        "render: raise ValueError(f\"unknown arm {name!r}; arms: {', '.join(ARMS)}\") @0: raise"
        " ValueError(f\"unknown arm {name!r}; arms: {', '.join(ARMS)}\") -> pass": (
            "an unknown arm is no fake arm: arm() raises the same error"
        ),
    },
    "llm_compare": {  # P1/P2 privacy layer (D-076 to D-078): reviewed one by one
        "score: b = sum(1 for r, s in zip(ref_right, right, strict=True) if r and not s) @51: T"
        "rue -> False": ("both lists are made from the same items: the same length"),
        "score: c = sum(1 for r, s in zip(ref_right, right, strict=True) if s and not r) @51: T"
        "rue -> False": ("both lists are made from the same items: the same length"),
    },
    "co_store": {
        "_pop: for cut in range(len(parts) - 1, 0, -1): @28: - -> +": (
            "the extra cuts name the whole path, which the first test of the function already"
            " looked up: they find nothing and change nothing"
        ),
        "_pop: return None @0: return None -> pass": "falling off the end returns None too",
        "_row: assert isinstance(result, Quarantined) @0: assert isinstance(result,"
        " Quarantined) -> pass": "normalize returns one of two types; the assert only narrows",
        "known_ids: return set() @0: return set() -> pass": (
            "the query with an empty IN list returns no rows: the same empty set"
        ),
        "mark_missing: return 0 @0: return 0 -> pass": (
            "the update with an empty IN list changes no row and returns 0 too"
        ),
    },
    "co_collector": {
        "source_value: for cut in range(len(parts) - 1, 0, -1): @28: - -> +": (
            "the extra cuts name the whole path, already looked up first: nothing changes"
        ),
        "source_value: return None @0: return None -> pass": "falling off the end returns None",
        "Collector.poll: if cursor is None or last > cursor: @26: > -> >=": (
            "with equal times the cursor is written with the value it already has"
        ),
        "Collector.poll: if cursor is None or now > cursor: @25: > -> >=": (
            "with equal times the cursor is written with the value it already has"
        ),
    },
    "co_runner": {
        "Runner.guarded_poll: if self.reconcile_from is None or start < self.reconcile_from:"
        " @40: < -> <=": "an equal start sets reconcile_from to the value it already has",
    },
    "sources": {
        '<module>: "tag:yaml.org,2002:null": "null", @0: "tag:yaml.org,2002:null"'
        ' -> "XXtag:yaml.org,2002:nullXX"': (
            "PyYAML's null constructor never fails for a scalar, and a non-scalar raises a"
            " ConstructorError before the table is read: the null entry is never looked up"
        ),
        '<module>: "tag:yaml.org,2002:null": "null", @26: "null" -> "XXnullXX"': (
            "as above: the null entry is never looked up"
        ),
        '<module>: "<block end>", @0: "<block end>" -> "XX<block end>XX"': (
            "PyYAML never quotes '<block end>' as a token it found: every parser state that can"
            " meet one checks for it first (2.8M random inputs gave no such message)"
        ),
        '<module>: "<stream start>", @0: "<stream start>" -> "XX<stream start>XX"': (
            "the first token of every stream, consumed by the parser's first state: no message"
            " can name it"
        ),
        "section_model: return None @0: return None -> pass": (
            "the function returns None without it"
        ),
        "_read_capped: raw = handle.read(MAX_FILE_BYTES + 1) @35: 1 -> 2": (
            "reading one byte more or two bytes more past the cap accepts and refuses the same"
            " sizes"
        ),
        '_kind: return "a mapping" @0: return "a mapping" -> pass': (
            "both callers call _kind only for a value that is not a dict"
        ),
        '_kind: return "a mapping" @7: "a mapping" -> "XXa mappingXX"': (
            "both callers call _kind only for a value that is not a dict"
        ),
        "_ConfigLoader.construct_object: kind = _TAG_NAMES.get(node.tag,"
        ' "value for its tag") @32: "value for its tag" -> "XXvalue for its tagXX"': (
            "with SafeConstructor only the bool, int, float and timestamp constructors raise the"
            " caught types, and all four are in _TAG_NAMES (16 tags x 28 values swept)"
        ),
        'yaml_layer: f" not {_kind(value)}" + (f" [{origin}]" if origin else "")'
        ' @56: "" -> "XXXX"': (
            "_key_lines records every pair of the root mapping (merged ones too): a top-level"
            " key always has an origin"
        ),
        "_unknown_variable: close = difflib.get_close_matches(variable.name.upper(), names,"
        " n=1, cutoff=0.8) @66: 1 -> 2": (
            "only close[0], the best match, is used, and it is the same whatever n is"
        ),
        "_apply: if section is not None and isinstance(values, dict): @23: and -> or": (
            "in an environment or .env layer a section's value is always a dict and any other"
            " value a str, so the two conditions always agree"
        ),
        "dotenv_layer: for binding, value in zip(bindings, _expand_variables(bindings,"
        " where=where), strict=True): @85: True -> False": (
            "_expand_variables returns exactly one value per binding"
        ),
        '_expand: start = value.find("${", stop + 1)  # every "${" before this \':\' stops'
        " there too @30: + -> -": (
            "value[stop] is ':', so no '${' can start at stop - 1 or at stop"
        ),
        '_expand: close = value.find("}", stop + 2) @29: + -> -': (
            "value[stop-2:stop+2] holds the name's end and ':-', never a '}'"
        ),
        "_expand: return None @0: return None -> pass": (
            "size only grows, so the check after the loop returns None too; the early return"
            " only stops the scan sooner"
        ),
    },
    "settings": {
        "SiemHealthSettings: disk_caution: float = Field(default=85.0, gt=0, lt=100) @51:"
        " 100 -> 101": "caution < degraded < 100 is required, so caution never reaches 100",
        "SiemHealthSettings: disk_degraded: float = Field(default=90.0, gt=0, lt=100) @52:"
        " 100 -> 101": "degraded < stop <= 100 is required, so degraded never reaches 100",
        "DatabaseSettings: def url(self, *, database: str | None = None,"
        ' role: DatabaseRole = "app") -> URL: @67: "app" -> "XXappXX"': (
            "url() logs in as the runtime role for every role but 'owner', so the spelling of the"
            " default changes nothing"
        ),
        '<module>: "argus_settings_layers", default=None @0: "argus_settings_layers"'
        ' -> "XXargus_settings_layersXX"': "a ContextVar's name only shows in its repr",
        "_LayerSource.__init__: super().__init__(settings_cls) @0: super().__init__(settings_cls)"
        " -> pass": (
            "nothing reads what the base __init__ sets on these sources: pydantic-settings appends"
            " its own default source last and takes the init state from that one"
        ),
        "_LayerSource.get_field_value: return self._data.get(field_name), field_name, False @0:"
        " return self._data.get(field_name), field_name, False -> pass": (
            "pydantic-settings calls get_field_value only from the __call__ that _LayerSource"
            " replaces; it exists because the base class declares it abstract"
        ),
        "_LayerSource.get_field_value: return self._data.get(field_name), field_name, False @47:"
        " False -> True": "get_field_value is never called (see the mutant above)",
        **{
            "_validation_problems: for error in exc.errors(include_url=False, include_input=False,"
            f" include_context=False): @{column}: False -> True": (
                "the extra keys this includes (url, input, ctx) are never read: a problem is made"
                " of loc, type and msg only"
            )
            for column in (36, 57, 80)
        },
        '_unknown_setting: name = loc[-1] if loc else "" @27: "" -> "XXXX"': (
            "only an empty loc gets this default, and an empty loc has no known names to"
            " compare it with"
        ),
        "_unknown_setting: close = difflib.get_close_matches(str(name).lower(), known, n=1,"
        " cutoff=0.75) @62: 1 -> 2": (
            "only close[0] is used, the best match, which is the same however many are returned"
        ),
        "_origin: return None @0: return None -> pass": "the function returns None without it",
    },
    "redaction": {
        '<module>: *("private key", "client secret"), @17: "client secret"'
        ' -> "XXclient secretXX"': (
            "wherever the prose word 'client secret' masks a value in text, the strict word"
            " 'secret' after it does too (its assignment rule accepts everything the prose rule"
            " does), and both keep the key text, so the result is the same"
        ),
        '_first_letter_of: return "(?=[" + "".join(sorted(letters | {letter.upper() for letter'
        ' in letters})) + "])" @16: "" -> "XXXX"': (
            "the lookahead only skips positions where no word can start; joining with XXXX adds"
            " X and x to it, and no word starts with an x"
        ),
        **{
            'register_secret: forms |= {quote(value, safe=""), quote_plus(value, safe="")}'
            f' @{column}: "" -> "XXXX"': "quote() and quote_plus() never escape letters"
            for column in (28, 56)
        },
        "redact: return _FAILED @0: return _FAILED -> pass": (
            "_redact catches every Exception itself, so this handler is never reached"
        ),
        "_redact_value: for shown_key, (key, item) in zip(keys, entries, strict=True) @56:"
        " True -> False": "distinct_keys returns one name per entry: the lengths are equal",
        **{
            '<module>: collections.namedtuple("_NamedTupleReprProbe", "x").__repr__, "__code__",'
            f" None @{column}: {original} -> {replacement}": (
                "every named tuple's generated __repr__ has the same code object, whatever the"
                " class and field names"
            )
            for column, original, replacement in (
                (23, '"_NamedTupleReprProbe"', '"XX_NamedTupleReprProbeXX"'),
                (47, '"x"', '"XXxXX"'),
            )
        },
        "_shown_fields: return None @0: return None -> pass": (
            "a pydantic model is neither a dataclass nor a named tuple, so without it the"
            " function goes on to return None at its end"
        ),
        '_shown_fields: if _DATACLASS_REPR[0] is None or "__dataclass_fields__" not in'
        " vars(owner): @19: 0 -> 1": (
            "on CPython both parts of the probe's identity are set (a code object and the"
            " '<string>' file name), so the test is false either way"
        ),
        "_shown_fields: return list(zip(names, value, strict=True)) @37: True -> False": (
            "the lengths were compared just before"
        ),
        "_shown_fields: return None @0: return None -> pass #4": (
            "the function returns None without it"
        ),
    },
    "roles": {
        "ensure_roles: assert settings.password is not None @0: assert settings.password is not"
        " None -> pass": (
            "check_bootstrap_settings, the line before, already refused a missing password; the"
            " assert only tells mypy"
        ),
        "_retrying: for attempt in range(1, _ATTEMPTS + 1): @36: 1 -> 2": (
            "the loop raises at attempt _ATTEMPTS, so it never gets to the extra one"
        ),
        "_restore: assert state is not None @0: assert state is not None -> pass": (
            "_restore runs only for a role that exists (_create returned False because it does);"
            " the assert only tells mypy"
        ),
        "ensure_roles: repairs += await _revoke_memberships(conn, group, keep=None,"
        " report_missing=False) @76: False -> True": (
            "with keep=None _revoke_memberships returns before it reads report_missing"
        ),
        "runtime_role_problems: problems += [label for label, flag in zip(labels, role,"
        " strict=True) if flag] @63: True -> False": (
            "the query selects exactly one column per label: the lengths are equal"
        ),
    },
    "netguard": {
        "_ip: return None @0: return None -> pass": "the function returns None without it",
        '_normalise: ip = _ip(host.split("%", 1)[0]) @25: 1 -> 2': (
            "the text before the first '%' is the same however often the rest is split"
        ),
        "_host_text: return None @0: return None -> pass": (
            "the function goes on to its final return None"
        ),
        "_host_text: return None @0: return None -> pass #2": (
            "the function returns None without it"
        ),
        "_c_ipv4: return None @0: return None -> pass": (
            "inet_aton itself refuses any text that does not start with an ASCII digit, and"
            " the except clause returns None for it"
        ),
        "_c_ipv4: return None @0: return None -> pass #2": ("the function returns None without it"),
        "_as_host_text: return text @0: return text -> pass": (
            "a fast path: unquote, NFKC, the full stops and the ignorable characters leave ASCII"
            " text without a '%' as it is"
        ),
        "_named_host: return None @0: return None -> pass": "the function returns None without it",
        "_libpq_ports: continue @0: continue -> pass": "it is the last statement of the loop",
        "_psycopg_refusal: return None @0: return None -> pass #2": (
            "the function returns None without it"
        ),
        'install_from_environment: settings = json.loads(os.environ.get(ENV_VAR) or "{}") @49:'
        ' "{}" -> "XX{}XX"': (
            "without a description the mutant fails to parse it and takes the except branch,"
            " which sets the same defaults: no hosts, no databases, active"
        ),
    },
    "fx_ipmap": {
        "<module>: _MAX_WALK = 10_000 @12: 10_000 -> 10001": (
            "a bound no walk reaches (the search before it rules out walks that return); one"
            " step more changes nothing below it. Its exhaustion is tested with a small value"
        ),
        "<module>: _MAX_REKEY = 64 @13: 64 -> 65": (
            "a bound on re-keying no domain reaches (the first or second counter is free); one"
            " try more changes nothing below it"
        ),
        "<module>: _FIXED_POINT_SEARCH = 2_000_000  # orbit nodes; the expected search is a few"
        " thousand @22: 2_000_000 -> 2000001": (
            "a budget no search reaches (a few thousand nodes); it is in the cache key, which only"
            " separates the entries of two budgets"
        ),
        "<module>: _CACHED_LEVELS = 24  # PRF bits of prefixes shorter than this are cached"
        " (shared by many addresses) @17: 24 -> 25": (
            "which PRF bits are cached, not their values: a cached bit and a recomputed one are"
            " the same HMAC"
        ),
        "IPMapper.map_address: self._addr_cache[addr] = cached @0: self._addr_cache[addr] ="
        " cached -> pass": (
            "a cache of a pure function: every miss computes the same address again"
        ),
        "IPMapper._map_uncached: s for s, _ in self.sites if s.version == net.version and"
        " s.overlaps(net) @53: and -> or": (
            "the extra spans are sites of the same family outside the class block (another"
            " family never overlaps): the search and the walk stay inside the block, where they"
            " refuse nothing"
        ),
        "IPMapper._domain: return found @0: return found -> pass": (
            "a cache of a pure function: the search below finds the same domain again"
        ),
        "IPMapper._domain: found = _DOMAIN_CACHE.get(cache_key) @0: found ="
        " _DOMAIN_CACHE.get(cache_key) -> pass": (
            "a cache of a pure function: found stays None and the search finds the same domain"
        ),
        "IPMapper._domain: return found @0: return found -> pass #2": (
            "a cache of a pure function: the search below finds the same domain again"
        ),
        "IPMapper._lone_orbits: for first in (0, 1) if laps == 1 else (0,): @39: 0 -> 1": (
            "a doubled orbit holds both children of every member whichever bit it starts with:"
            " the same set in another order, and only the count of accepted members is used"
        ),
        "IPMapper._lone_orbits: for prefix, flip in zip(orbit, flips, strict=True): @45: True"
        " -> False": ("flips is computed from orbit, one per member: the lengths are equal"),
        "IPMapper._lone_orbits: return None @0: return None -> pass": (
            "the function returns None without it"
        ),
        "IPMapper._short_orbits: for first in (0, 1) if laps == 1 else (0,): @39: 0 -> 1": (
            "a doubled orbit holds both children of every member whichever bit it starts with:"
            " the same set in another order (callers and tests compare orbits as sets)"
        ),
        "IPMapper._short_orbits: for prefix, flip in zip(orbit, flips, strict=True): @45: True"
        " -> False": ("flips is computed from orbit, one per member: the lengths are equal"),
        "IPMapper._short_orbits: return None @0: return None -> pass": (
            "the function returns None without it"
        ),
        "IPMapper._prf_bit: cacheable = i < _CACHED_LEVELS @14: < -> <=": (
            "which PRF bits are cached, not their values: a cached bit and a recomputed one are"
            " the same HMAC"
        ),
        "IPMapper._prf_bit: return hit @0: return hit -> pass": (
            "a cache of a pure function: the HMAC below gives the same bit again"
        ),
        "IPMapper._prf_bit: self._prf_cache[cache_key] = bit @0: self._prf_cache[cache_key] ="
        " bit -> pass": ("a cache of a pure function: every miss computes the same bit again"),
        "_unwrap: addr = _unscoped(addr) @0: addr = _unscoped(addr) -> pass": (
            "region() and map_network() only test membership and compare region names, and"
            " membership ignores an IPv6 zone"
        ),
    },
    "fx_leakscan": {
        "<module>: _ALNUM = frozenset("
        '"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")'
        ' @19: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" ->'
        ' "XXABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789XX"': (
            "a set of characters: X is in it already"
        ),
        "LeakScanner._words: return [] @0: return [] -> pass": (
            "with no names indexed every lookup in self._first misses: the loop returns [] too"
        ),
        "LeakScanner._words: while first_end < count and ends[first_end] <= start: @16: < -> <=": (
            "first_end never reaches count: the word that starts at start ends after it, so the"
            " loop stops at that end first"
        ),
        "LeakScanner._words: while first_end < count and ends[first_end] <= start: @44: <= -> <": (
            "a word end never equals a word start: the character before an end is alphanumeric,"
            " the one before a start is not"
        ),
        "LeakScanner._words: if start < last or first_end >= count: @29: >= -> >": (
            "first_end < count always holds here (the word at start ends after it): both are false"
        ),
        "_parse_address: return None @0: return None -> pass": (
            "ip_address rejects the same text (an octet above 255, or digits that are not ASCII):"
            " None either way"
        ),
        "_parse_address: return None @0: return None -> pass #2": (
            "the function returns None without it"
        ),
        '_addresses_in: octets = m.group(1).rstrip(".").split(".")[::-1] @27: "." -> "XX.XX"': (
            "group 1 holds only digits and dots: no X to strip"
        ),
        '_addresses_in: nibbles = m.group(1).rstrip(".").split(".")[::-1] @28: "." -> "XX.XX"': (
            "group 1 holds only hex digits and dots: no X to strip"
        ),
        "_v6_forms: suffixes = [candidate[i + 1 :] for i, c in enumerate(candidate) if c =="
        ' ":"][:8] @78: 8 -> 9': (
            "a candidate has at most 8 colons ((?::...){2,8}): at most 8 suffixes, kept either way"
        ),
        "_network: return None @0: return None -> pass #2": "the function returns None without it",
        "_compression: return None @0: return None -> pass": (
            "the function returns None without it"
        ),
        "_decompress: zlib.decompressobj(16 + zlib.MAX_WBITS) @19: 16 -> 17": (
            "wbits 32 detects the header itself, and every stream read as gzip starts with the"
            " gzip magic (each member is checked by _compression): decoded the same, with the"
            " same window and checks (plain, concatenated, truncated, bad CRC or length, corrupt"
            " and 32 KiB-distance streams compared)"
        ),
        "_embedded_streams: if found < 0: @9: < -> <=": (
            "find from start >= 1 returns -1 or an offset >= 1: never 0"
        ),
        "_embedded_streams: if found < 0: @11: 0 -> 1": "as above: found is -1 or at least 1",
        '_printable: good = sum((c.isprintable() and c != "\\ufffd") or c in "\\t\\n\\r" for c in'
        ' text) @55: "\\t\\n\\r" -> "XX\\t\\n\\rXX"': (
            "a set of characters: X is printable, so it counts already"
        ),
        "_unescape: return text @0: return text -> pass": (
            "every alternative of _ESCAPE starts with a backslash: without one sub returns the"
            " text unchanged"
        ),
        "_embedded_json: return @0: return -> pass": (
            "without { or [ the finditer below finds no start: nothing is yielded either way"
        ),
        "_fixed_point: return text @0: return text -> pass": (
            "once decoded == text every further round leaves it unchanged; the last line returns"
            " the same text (only more rounds)"
        ),
        "_views: while queue and views < _MAX_VIEWS and budget > 0: @22: < -> <=": (
            "at views == _MAX_VIEWS the inner check skips every view, and deep views follow only"
            " a yield: nothing more is yielded"
        ),
        "LeakScanner.__init__: continue @0: continue -> pass #2": (
            "a phrase that starts before its first ASCII word is then also indexed by that word,"
            " where its pattern can never match: it needs its leading characters (É, ()"
        ),
        '_canonicals: if not text or not (text[0].isdigit() or text[0] == "[" or ":" in text):'
        " @12: or -> and": (
            "the early return only skips a parse that fails anyway: no text that starts with no"
            " digit or [ and has no colon is an address; the only caller passes no empty text"
            " (identifiers of 2 characters or more)"
        ),
        "_canonicals: return [] @0: return [] -> pass": (
            "the parse below fails for every such text (no digit or [ first, no colon), and the"
            " function then returns [] too"
        ),
        '_base64_payloads: raw = base64.b64decode(token + "=" * (-len(token) % 4),'
        " validate=True) @65: True -> False": (
            "the token holds only base64 digits (the regex, with - and _ replaced) and exactly the"
            " padding it needs: validation never refuses it, and a length of 4n + 1 is refused"
            " either way"
        ),
        "_views: queued.add(view) @0: queued.add(view) -> pass": (
            "without it a fixed point both chains reach is queued twice: its second turn finds"
            " every view in seen already and yields nothing"
        ),
        "_views: while queue and views < _MAX_VIEWS and budget > 0: @46: > -> >=": (
            "at budget == 0 the inner check (budget <= 0) skips every view: nothing more is yielded"
        ),
    },
    "fx_tokens": {
        "<module>: _FPE_MAX_BITS = 128  # ids up to this many bits get a keyed permutation (no"
        " collisions at all) @16: 128 -> 129": (
            "no id has more than 128 and at most 129 bits: hex and HEX give 4 bits a character"
            " (32: 128, 33: 132), base64url 6 (21: 126, 22: 132), decimal log2(10) (38: 126.2,"
            " 39: 129.6)"
        ),
        "<module>: _MAX_ID_STEPS = 10_000  # a cycle walk takes a handful of steps; this many"
        " means a bug @16: 10_000 -> 10001": (
            "a bound no walk reaches (each takes a handful of steps); one step more changes"
            " nothing below it. Its exhaustion is tested with a small value"
        ),
        'Tokenizer.token: b32 = base64.b32encode(self.digest(kind, value)).decode().rstrip("=")'
        '.lower() @65: "=" -> "XX=XX"': (
            "only the tail is stripped: of the 52 base32 characters at most the first 20 are"
            " used, and the 32 after them would all have to be X"
        ),
        "Tokenizer._permute_id: bits = (size - 1).bit_length()  # size is at least 10 (one"
        " decimal digit) @15: 1 -> 2": (
            "(size - 2) and (size - 1) have the same bit length unless size - 1 is a power of"
            " two, and no size is: 16^n and 64^n are powers of two (>= 16), 10^n - 1 is odd"
        ),
        "_stretch: while len(out) < length: @15: < -> <=": (
            "one block more is cut off again by out[:length]"
        ),
        'DomainMapper.map: head = name[: -len(campus)].rstrip(".") @35: "." -> "XX.XX"': (
            "the name is normalised to lower case: it holds no X to strip"
        ),
        'DomainMapper.map: head = name[: -len(kept)].rstrip(".") @33: "." -> "XX.XX"': (
            "the name is normalised to lower case: it holds no X to strip"
        ),
    },
    "fx_sanitizer": {
        **{
            "<module>: @dataclass(frozen=True) @18: True -> False" + suffix: (
                "the context markers are only created, tested with isinstance and read (.keys,"
                " .kind): nothing assigns to them, hashes them or uses them as a set member or dict"
                " key, so frozen changes nothing; __eq__ is generated either way"
            )
            for suffix in ("", " #2", " #3", " #4")
        },
        "Sanitizer.__init__: self._exact: dict[str, str] = {}  # ids and 2-character names, in"
        " their own case @0: self._exact: dict[str, str] = {} -> pass": (
            "_exact is read only by _rebuild, after assigning it, and by _entry, which runs only"
            " when _index is not empty; _index starts empty and only _rebuild fills it"
        ),
        "Sanitizer.__init__: self._aggregations: dict[str, Any] = {} @0: self._aggregations:"
        " dict[str, Any] = {} -> pass": (
            "_aggregations is read only through _context, which only harvest and sanitize reach,"
            " each after assigning it for the document at hand"
        ),
        "Sanitizer.harvest: self._seen.add((kind, part)) @0: self._seen.add((kind, part)) ->"
        " pass": (
            "a memo of work done: _harvest_field is idempotent (_remember only adds to sets and"
            " uses setdefault, the mappers are pure), so harvesting a (kind, value) again changes"
            " nothing"
        ),
        **dict.fromkeys(
            (
                'Sanitizer.harvest: if _FILESYSTEM_FIELD.search(path) and ("~", value) not in'
                ' self._seen: @39: "~" -> "XX~XX"',
                'Sanitizer.harvest: self._seen.add(("~", value)) @0: self._seen.add(("~", value))'
                " -> pass",
                'Sanitizer.harvest: self._seen.add(("~", value)) @16: "~" -> "XX~XX"',
            ),
            "the ('~', value) entries only memoize _harvest_homes, which is idempotent (it only"
            " calls _remember); '~' is never a field kind, so no other entry collides: another"
            " marker spelling, or none recorded, only repeats the work",
        ),
        "Sanitizer.harvest: self._seen_text.add(value) @0: self._seen_text.add(value) -> pass": (
            "a memo of work done: _harvest_text is idempotent (only _remember, _harvest_email and"
            " _harvest_field), so harvesting a string again changes nothing"
        ),
        'Sanitizer._harvest_field: if kind == "id" or _as_ip(value) is not None: @11: "id" ->'
        ' "XXidXX"': (
            "the early return only saves work for an id: every later step applies to the kinds"
            " user, email or host alone (e-mail parts, display name, realm, account, HOST$, FQDN"
            " label)"
        ),
        'Sanitizer._harvest_text: self._remember("span", str(ip),'
        ' format_ip(self.ips.map_address(ip))) @15: "span" -> "XXspanXX"': (
            "_remember treats 'span' specially only to call a case-only change unchanged; an IPv4"
            " address and its formatted pseudonym hold no letters, so that test equals raw =="
            " pseudonym, and neither kind is 'id' or a name kind"
        ),
        'Sanitizer._context: in_sort = path.rsplit(".", 1)[-1] == "sort"  # {"host.name": "asc"}'
        " is an order @27: 1 -> 2": (
            "the last item of rsplit is the text after the last dot whatever the maxsplit (>= 1)"
        ),
        'Sanitizer._map_string: kinds + [None] * (value.count("|") + 1 - len(kinds)), @37: 1 ->'
        " 2": (
            "the padding only has to make the kinds at least as long as the parts: one None more"
            " is cut off by zip(strict=False), which stops at the parts"
        ),
        'Sanitizer._map_string: kinds + [None] * (value.count("|") + 1 - len(kinds)), @39: - ->'
        " +": (
            "more None padding after the kinds: zip(strict=False) stops at the parts, so the pairs"
            " are the same"
        ),
        "Sanitizer._kind: return cached @0: return cached -> pass": (
            "a cache hit only skips recomputing the kind from the same path, kinds and patterns, "
            "which never change"
        ),
        'Sanitizer._kind: self._kind_cache[".".join(segments)] = kind @0: '
        'self._kind_cache[".".join(segments)] = kind -> pass': (
            "without the store every lookup recomputes the same kind: the cache only saves time"
        ),
        "Sanitizer._detect: last_end = -1 @12: 1 -> 2": (
            "every span starts at 0 or later: start >= -1 and start >= -2 accept the same first "
            "span"
        ),
        "Sanitizer._detect: for start, end, replacement in sorted(found, key=lambda s: (s[0], "
        "-(s[1] - s[0]))): @73: - -> +": (
            "spans are ordered by start first; among spans with one start, -(end + start) orders "
            "them by end exactly as -(end - start) does"
        ),
        'Sanitizer._map_ip_token: net = ipaddress.ip_network(f"{ip}/{prefixlen}", strict=False) '
        "@55: False -> True": (
            "strict parsing raises only for set host bits or an invalid prefix; the original then "
            'returns f"{mapped}/{prefixlen}" from the interface-notation branch, the mutant from '
            "the ValueError handler: the same string"
        ),
        'Sanitizer._map_ip_token: if region == "public": @13: "public" -> "XXpublicXX"': (
            "a network whose address is public reaches map_network, which always raises an "
            "IPMapError (a ValueError) for it (public, or spanning two regions; a /0 or "
            "::ffff:0:0/96 starts with a keep address), and the handler returns the same "
            'f"{mapped}/{prefixlen}"'
        ),
        'Sanitizer._map_ip_token: return f"{mapped}/{prefixlen}" @0: return '
        'f"{mapped}/{prefixlen}" -> pass #2': (
            'as for the "public" spelling: without this return a public network ends in the '
            "ValueError handler, which returns the same string"
        ),
        'Sanitizer._map_ip_token: if net.prefixlen == 0 or region == "keep": @20: 0 -> 1': (
            "a network reaching this test starts at its own address; a /0 one is 0.0.0.0/0 or "
            "::/0 (keep regions) and a /1 one is 0.0.0.0/1 or ::/1 (keep) or starts with a public "
            "address (returned before): the region test decides alone"
        ),
        'Sanitizer._map_reverse_v4: octets = octets_text.rstrip(".").split(".")[::-1] @28: "." -> '
        '"XX.XX"': (
            "rstrip takes a set of characters and the octet text holds only digits and dots: also "
            "stripping X changes nothing"
        ),
        "Sanitizer._map_reverse_v4: if len(octets) == 4: @18: 4 -> 5": (
            "a four-octet name then takes the network path with prefix 32, where every branch of "
            "_map_ip_token yields map_address of the address (keep addresses map to themselves, "
            "map_network of a /32 is the mapped address, failures fall back to it; a site-space "
            "address raises in both paths)"
        ),
        "Sanitizer._map_reverse_v4: mapped_net = self._map_ip_token(network, str(8 * "
        "len(octets))) @45: 8 -> 9": (
            "only the first len(octets) octets are kept, and with a longer prefix every branch of "
            "_map_ip_token gives the same leading octets: the mapped address or its network "
            "(prefix-preserving), or the address itself in a keep region (decided by the address "
            "alone)"
        ),
        "Sanitizer._map_reverse_v4: mapped_net = self._map_ip_token(network, str(8 * "
        "len(octets))) @47: * -> /": (
            "8 / n is a float ('8.0', '4.0', '2.666...'), never a valid prefix: the ValueError "
            "handler returns the mapped address, whose leading octets are those of every other "
            "branch (see the 8 -> 9 mutant)"
        ),
        "Sanitizer._map_reverse_v4: return None @0: return None -> pass #2": (
            "_map_ip_token returns None only for an unparseable address, and a network of at most "
            "three 0-255 octets and zeros always parses"
        ),
        'Sanitizer._map_reverse_v4: forward = mapped_net.split("/")[0].split(".")[: len(octets)] '
        '@27: "/" -> "XX/XX"': (
            "without the split the prefix stays on the fourth dotted part ('d/24'), and at most "
            "three parts are kept here"
        ),
        'Sanitizer._map_reverse_v6: nibbles = nibbles_text.rstrip(".").split(".")[::-1] @30: "." '
        '-> "XX.XX"': (
            "rstrip takes a set of characters and the nibble text holds only hex digits and dots: "
            "also stripping X changes nothing"
        ),
        "Sanitizer._map_reverse_v6: if count == 32: @9: == -> !=": (
            "both branches give the same leading nibbles: a full name on the network path (prefix "
            "128) yields the mapped address, and for a partial name map_address shares the first "
            "4 * count bits with every result of the network path (prefix-preserving map, keep "
            "addresses unchanged, failures fall back to the mapped address)"
        ),
        "Sanitizer._map_reverse_v6: if count == 32: @12: 32 -> 33": (
            "every name takes the network path, where a full name (prefix 128) yields the mapped "
            "address too (see the == -> != mutant)"
        ),
        "Sanitizer._map_reverse_v6: mapped_net = self._map_ip_token(str(address), str(4 * count)) "
        "@50: 4 -> 5": (
            "only the first count nibbles are kept: a longer prefix gives the same leading "
            "nibbles, and one past 128 is refused and falls back to the mapped address, which has "
            "them too"
        ),
        "Sanitizer._map_reverse_v6: mapped_net = self._map_ip_token(str(address), str(4 * count)) "
        "@52: * -> /": (
            "4 / count is a float, never a valid prefix: the ValueError handler returns the "
            "mapped address, which has the same leading nibbles"
        ),
        "Sanitizer._map_reverse_v6: return None @0: return None -> pass": (
            "the address built from the nibbles always parses, so _map_ip_token never returns "
            "None here"
        ),
        "Sanitizer._map_plain: return text @0: return text -> pass": (
            "the empty text passes through _replace_names and the literals unchanged"
        ),
        "_aggregation_spec: return None @0: return None -> pass #2": (
            "the function's last statement: it returns None without it"
        ),
        '_word_char: return char.isalnum() or char in "_-" @33: "_-" -> "XX_-XX"': (
            "X is alphanumeric already"
        ),
        '_pad_like: return ".".join(o.zfill(w) for o, w in zip(mapped.split("."), widths, '
        "strict=True)) @77: True -> False": (
            "_pad_like is only called for IPv4, with four dotted parts on both sides (the "
            "original was parsed as IPv4, map_address keeps the version): the lengths always "
            "agree"
        ),
        '_as_ip: if not text or len(text) > 45 or "%" in text or not (":" in text or '
        "text[:1].isdigit()): @12: or -> and": (
            "the length test only short-cuts: no address spelling is longer than 45 characters "
            "(six hextets and a dotted quad), so ipaddress refuses a longer text too; the empty "
            "text is still refused by the last clause"
        ),
        '_as_ip: if not text or len(text) > 45 or "%" in text or not (":" in text or '
        "text[:1].isdigit()): @27: 45 -> 46": (
            "no address spelling has 46 characters: ipaddress refuses one"
        ),
        "_as_ip: return None @0: return None -> pass #2": (
            "the function's last statement: it returns None without it"
        ),
        "Sanitizer.map_text: return format_ip(self.ips.map_address(whole)) @0: return"
        " format_ip(self.ips.map_address(whole)) -> pass": (
            "a fast path since 2.3.0: a whole address (ipaddress spelling, at most 45 characters,"
            " no zone) is also found by the text detectors, which map it the same (_version_like"
            " needs a letter and '/' before it). Compared on 12,000 generated addresses in up to"
            " four spellings and 22 edge spellings: no difference"
        ),
        "Sanitizer._map_key: return format_ip(self.ips.map_address(mapped_ip)) @0: return"
        " format_ip(self.ips.map_address(mapped_ip)) -> pass": (
            "as for map_text: a key that is a whole address is also found by the text detectors"
            " in _map_spans and mapped the same"
        ),
    },
    "fx_policy": {
        '_check_patterns: collapsed = re.sub(r"\\*+", "*", pattern) @27: "*" -> "XX*XX"': (
            "the collapsed form is only compared with other collapsed forms, and writing each run"
            " of * as XX*XX instead of * is one-to-one: the same patterns compare equal"
        ),
    },
    "nz_normalizer": {
        "_Normalizer.single: if len(found) > 1: @14: > -> >=": (
            "a shortcut: with one value found[1:] is empty, so the conflict test finds nothing"
            " either way"
        ),
        "_usable_id: return None @0: return None -> pass": (
            "the last statement of the function: falling off its end returns None as well"
        ),
        "_Normalizer.integer: return None @0: return None -> pass #2": (
            "the last statement of the method: falling off its end returns None as well"
        ),
        '_Normalizer.run: building_block = self.text(_ALERT + "building_block_type", 64)'
        " is not None @59: 64 -> 65": (
            "only whether the text is None is used, and capping a non-empty string at 64 or 65"
            " characters never makes it None"
        ),
        "_Normalizer.group_key: pairs = sorted(zip(fields, key_values, strict=True),"
        " key=lambda pair: pair[0]) @46: True -> False": (
            "key_values gets exactly one entry per field in the loop just above: the lengths"
            " are always equal, so strict never raises"
        ),
    },
    "nz_fields": {
        "<module>: @lru_cache(maxsize=1024) @19: 1024 -> 1025": (
            "a cache of pure results: its size changes speed, never a value"
        ),
    },
    "nz_grouping": {
        "load_grouping: f\"{'.'.join(str(part) for part in error['loc']) or '(top level)'}:"
        " {error['msg']}\" @51: '(top level)' -> 'XX(top level)XX'": (
            "read_yaml_file refuses any file that is not a mapping, and every error pydantic"
            " reports for a mapping has a location: the fallback label is never used"
        ),
        "load_grouping: for error in exc.errors(include_input=False) @38: False -> True": (
            "only each error's loc and msg are read: the extra input key is never used"
        ),
    },
    "nz_times": {
        "_duration: if match.group(1) is None: @15: 1 -> 2": (
            "groups 1 and 2 sit in the same optional group of both patterns: either both"
            " matched or neither did"
        ),
    },
    "as_assetmap": {
        "_Loader: def construct_mapping(self, node: MappingNode, deep: bool = False)"
        " -> dict[Any, Any]: @60: False -> True": (
            "deep only decides whether nested values are built at once or later by the"
            " constructor's generators: the finished document is the same"
        ),
        "_line: return mark.line + 1 if mark is not None else 0 @46: 0 -> 1": (
            "PyYAML gives every event and node it composes a start mark: the fallback is never used"
        ),
        "parse_asset_map: loader.dispose() @0: loader.dispose() -> pass": (
            "dispose only clears the loader's state for the garbage collector; the loader is not"
            " used again"
        ),
        "AssetMap.__init__: full = (1 << bits) - 1 @8: 1 -> 2": (
            "an extra mask bit above the address width: addresses never have that bit set"
        ),
        "AssetMap.__init__: full = (1 << bits) - 1 @10: << -> >>": (
            "full becomes -1 and each mask -2**(bits - length), which has the same low bits as"
            " the right mask: ANDed with an address below 2**bits it gives the same value"
        ),
        "AssetMap.match: return None @0: return None -> pass #2": (
            "the last statement of the method: falling off its end returns None as well"
        ),
        "parse_address: return None @0: return None -> pass #2": (
            "address stays a string, which is neither address type: the last line returns None"
        ),
        "parse_address: return None @0: return None -> pass #3": (
            "the last statement of the function: falling off its end returns None as well"
        ),
    },
    "as_store": {
        "read_map_bytes: os.set_blocking(descriptor, True) @0:"
        " os.set_blocking(descriptor, True) -> pass": (
            "only a regular file gets here, and reads of a regular file never block: the flag"
            " has no effect on them"
        ),
        "read_map_bytes: os.set_blocking(descriptor, True) @28: True -> False": (
            "as above: O_NONBLOCK does not change reads of a regular file"
        ),
        "read_map_bytes: raw = handle.read(MAX_MAP_BYTES + 1) @34: 1 -> 2": (
            "any read of more than MAX_MAP_BYTES is refused, so reading at most one or two bytes"
            " more decides the same"
        ),
        "stage_map: os.fchmod(descriptor, 0o600) @0: os.fchmod(descriptor, 0o600) -> pass": (
            "mkstemp already creates the file with mode 0600; the fchmod states it explicitly"
        ),
    },
    "nz_canon": {
        **{
            f'<module>: FieldKind = Literal["ip", "port", "domain", "other"] @{column}:'
            f' "{kind}" -> "XX{kind}XX"': (
                "a type alias: Literal values are not checked at run time and no model uses it"
            )
            for column, kind in ((20, "ip"), (26, "port"), (34, "domain"), (44, "other"))
        },
        'field_kind: leaf = name.rsplit(".", 1)[-1] @24: 1 -> 2': (
            "only the last part is used, and it is the same with one split or two"
        ),
        "canon_domain: return text.lower(), None @0: return text.lower(), None -> pass": (
            "a fast path: for ASCII text the label loop below lowercases every label and joins"
            " them with the same dots, which gives the same string"
        ),
    },
    "as_engine": {  # P4 decision engine (D-085): reviewed one by one
        'keys: if top and fact.get("distinct", 0) <= FEW: @32: 0 -> 1': (
            "a missing count is 0 or 1, both within FEW (3)"
        ),
        "qualified: outcome, count = Counter(x.outcome for x in labels).most_common(1)[0]"
        " @64: 1 -> 2": (
            "the first of the two most common is the most common (ties keep the same order)"
        ),
        "floor.known: return False, None @7: False -> True": (
            "every caller checks that the signal is present before it reads what known() says"
        ),
        'floor: if "proxy.hosts_to_destination" in sig and (not ok or (value or 0) <= RARE):'
        " @64: 0 -> 1": ("a missing count is 0 or 1, both within RARE (1): a rare destination"),
        'floor: severity = str((body.get("facts") or {}).get("severity") or "").lower()'
        ' @60: "" -> "XXXX"': ('a missing severity is "" or "xxxx", neither high nor critical'),
    },
    "ag_agent": {  # P6 agent: reviewed one by one (2026-10-21)
        'parse: tuple(c for c in _strings(data.get("consult"), 3, 10) if c in specialists),'
        " @50: 10 -> 11": (
            "every bound specialist name is at most 5 characters (test_registry holds them to 10)"
        ),
        '_words: return [w.rstrip(".,;:") for w in _WORD.findall(text.translate(_QUOTES)'
        '.lower())] @17: ".,;:" -> "XX.,;:XX"': "the text is lowercased: an X never ends a word",
        "Agent.run: body = dict(body) @0: body = dict(body) -> pass": (
            "the body is never changed in place, only replaced"
        ),
        "Agent.run: request: Request | None = None @0: request: Request | None = None -> pass": (
            "with no round run, the answer is None and request is never read"
        ),
        "Agent._verdict: seconds = (self.clock() - trace.began).total_seconds() if trace.began"
        " else 0.0 @75: 0.0 -> 1.0": "run() always sets began before a verdict is made",
    },
    "ag_catalogue": {  # P6 tool catalogue: reviewed one by one (2026-10-21)
        '_lookup: terms = variants("domain", value.lower().rstrip(".")) @48: "." -> "XX.XX"': (
            "the value is lowercased: an X is never stripped"
        ),
        '<module>: text: str = "", @12: "" -> "XXXX"': (
            "XXXX is no address or domain: no literal is ever shown in it"
        ),
        'build: label = entity.split(".", 1)[-1].rsplit("_", 1)[0] @26: 1 -> 2': (
            "ENTITY allows exactly one dot"
        ),
        'build: label = entity.split(".", 1)[-1].rsplit("_", 1)[0] @45: 1 -> 2': (
            "ENTITY allows exactly one underscore"
        ),
        "build: return Refusal(f\"{tool} takes {' or '.join(sorted(spec.labels))}, not {label}\")"
        " @31: ' or ' -> 'XX or XX' #2": (
            "a literal is an IP or a SITE, so only single-label tools refuse it here"
        ),
    },
    # ev_agent_eval: sort_keys=True is no longer equivalent: Q-H1's test_parity pins the
    # absolute gold run ids (registry.GOLD_RUNS), so another key order is killed.
    "tu_advise": {  # P7 tuning advice: reviewed one by one (2026-10-21)
        'advise: seen = request.text + "\\n" + shown_numbers @22: "\\n" -> "XX\\nXX"': (
            "a quote spanning the item's end and the numbers' first line is found either way:"
            " as a substring in one text, word by word on one line in the other"
        ),
    },
    "ag_service": {  # P6 evidence wiring: reviewed one by one (2026-10-21)
        "evidence.fetch: deadline=clock() + ATTEMPT, clock=clock, gate=Gate(1))  # fmt: skip"
        " @51: 1 -> 2": "one fetch is one task: it never holds more than one slot",
    },
    "sk_soak2": {  # P9 soak report: reviewed one by one (2026-10-21)
        "outages: last: datetime | None = None @0: last: datetime | None = None -> pass": (
            "last is set together with first, and only read when first is set"
        ),
        "report: met = rate.value is not None and rate.value >= 0.95 and low is not None"
        " and low >= 0.90 @80: >= -> >": (
            "a Wilson lower bound of whole counts is never exactly 0.90"
        ),
    },
    "tu_report": {  # P7 tuning report: reviewed one by one (2026-10-21)
        "build: continue  # older ones count only for the labels they carry @0: continue -> pass": (
            "an older unlabelled investigation changes nothing either way: the skip only saves work"
        ),
    },
    "as_runner": {  # P3 assessment runner (D-084): reviewed one by one
        "Assessor.assess: ) -> Verdict: ... @14: ... -> pass": (
            "a Protocol's method body is never run"
        ),
        "schedule: if limit <= 0: @9: <= -> <": (
            "at exactly 0 the query asks LIMIT 0 and queues nothing either way"
        ),
    },
    "llm_budget": {  # P5 LLM gateway (D-086): reviewed one by one
        "_next_month: first = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)"
        " @24: 1 -> 2": (
            "the 2nd plus 32 days is always in the next month, whose 1st it is then moved to"
        ),
        "_next_month: return (first + timedelta(days=32)).replace(day=1) @31: 32 -> 33": (
            "the 1st plus 33 days is always in the next month, whose 1st it is then moved to"
        ),
    },
    "llm_gateway": {  # P5 LLM gateway (D-086): reviewed one by one
        '<module>: T = TypeVar("T") @12: "T" -> "XXTXX"': (
            "a TypeVar's name is checked by mypy only"
        ),
        "LlmStore.change: async def change(self, fn: Callable[[budget.State], tuple[T, budget"
        ".State]]) -> T: ... @83: ... -> pass": "a Protocol's method body is never run",
        "LlmStore.state: async def state(self) -> budget.State: ... @39: ... -> pass": (
            "a Protocol's method body is never run"
        ),
        "LlmStore.record: async def record(self, entry: CallEntry) -> None: ... @50: ... -> pass": (
            "a Protocol's method body is never run"
        ),
    },
    "llm_store": {  # P5 LLM gateway (D-086): reviewed one by one
        '<module>: T = TypeVar("T") @12: "T" -> "XXTXX"': (
            "a TypeVar's name is checked by mypy only"
        ),
        "PgLlmStore.__init__: self.sessions = async_sessionmaker(engine, expire_on_commit=False)"
        " @60: False -> True": (
            "the sessions hold no ORM objects: nothing is read after the commit to expire"
        ),
    },
    "llm_wire": {  # P5 LLM gateway (D-086): reviewed one by one
        "LlmTransport.send: async def send(self, wire: LlmWire, key: SecretStr) -> LlmReply: ..."
        " @65: ... -> pass": "a Protocol's method body is never run",
        "LlmCassette.send: assert self.inner is not None @0: assert self.inner is not None ->"
        " pass": "the assert only narrows: __post_init__ refuses recording without a transport",
        "TransportError.__init__: super().__init__(message) @0: super().__init__(message) ->"
        " pass": "BaseException.__new__ already stores the message in args, so str() is the same",
    },
}

# --------------------------------------------------------------------------- mutants

_BINARY = {
    "+": "-",
    "-": "+",
    "*": "/",
    "/": "*",
    "//": "/",
    "%": "/",
    "**": "*",
    "<<": ">>",
    ">>": "<<",
    "|": "&",
    "&": "|",
    "^": "&",
}
_AUGMENTED = {f"{old}=": f"{new}=" for old, new in _BINARY.items()}
_COMPARISON = {
    "==": "!=",
    "!=": "==",
    "<": "<=",
    "<=": "<",
    ">": ">=",
    ">=": ">",
    "is": "is not",
    "is not": "is",
    "in": "not in",
    "not in": "in",
}
_BOOLEAN = {"and": "or", "or": "and"}
_DELETABLE = (
    ast.Assign,
    ast.AugAssign,
    ast.AnnAssign,
    ast.Expr,
    ast.Return,
    ast.Raise,
    ast.Assert,
    ast.Delete,
    ast.Break,
    ast.Continue,
    ast.Global,
    ast.Nonlocal,
)
_PYDANTIC_BASES = frozenset({"BaseModel", "BaseSettings"})


@dataclasses.dataclass(frozen=True)
class Mutant:
    target: str
    number: int
    line: int
    kind: str  # operator, comparison, boolean, constant, string, statement
    start: int  # character offsets of the replaced text
    end: int
    original: str
    replacement: str
    scope: str  # the class and function it is in, e.g. "DatabaseSettings.url"
    column: int  # where it starts on the line, indentation not counted
    source_line: str  # the line it is on, stripped
    occurrence: int = 1  # the same change on an identical line earlier in the scope: 2, 3...

    @property
    def id(self) -> str:
        return f"{self.target}:{self.number}"

    @property
    def signature(self) -> str:
        """Names the mutant while its line stays as it is (EQUIVALENT is keyed by it)."""
        change = f"{self.original} -> {self.replacement}"
        again = f" #{self.occurrence}" if self.occurrence > 1 else ""
        return f"{self.scope}: {self.source_line} @{self.column}: {change}{again}"

    def apply(self, source: str) -> str:
        return source[: self.start] + self.replacement + source[self.end :]

    def describe(self) -> str:
        change = f"{_short(self.original)} -> {_short(self.replacement)}"
        return f"{self.id} line {self.line} {self.kind}: {change}"


def _short(text: str, limit: int = 70) -> str:
    text = " ".join(text.split())
    return repr(text if len(text) <= limit else text[: limit - 3] + "...")


def _is_text(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _base_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return ""


class _Collector:
    """Finds the mutants of one module. AST columns count UTF-8 bytes, tokenize's characters:
    everything is converted to character offsets into the source."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.lines = source.splitlines(keepends=True)
        self.starts = [0]
        for line in self.lines:
            self.starts.append(self.starts[-1] + len(line))
        self.tokens: list[tuple[int, int, str]] = []  # operators and names
        self.strings: list[tuple[int, int, str]] = []
        for token in tokenize.generate_tokens(io.StringIO(source).readline):
            start = self.starts[token.start[0] - 1] + token.start[1]
            end = self.starts[token.end[0] - 1] + token.end[1]
            if token.type == tokenize.STRING:
                self.strings.append((start, end, token.string))
            elif token.type in (tokenize.OP, tokenize.NAME):
                self.tokens.append((start, end, token.string))
        self.token_starts = [token[0] for token in self.tokens]
        self.pydantic: set[str] = set()
        self.found: dict[tuple[int, int, str], tuple[str, str, str]] = {}
        self.scope: list[str] = []

    def offset(self, row: int, byte_column: int) -> int:
        return self.starts[row - 1] + len(self.lines[row - 1].encode()[:byte_column].decode())

    def span(self, node: Any) -> tuple[int, int]:
        start = self.offset(node.lineno, node.col_offset)
        return start, self.offset(node.end_lineno, node.end_col_offset)

    def add(self, start: int, end: int, kind: str, replacement: str) -> None:
        scope = ".".join(self.scope) or "<module>"
        self.found.setdefault((start, end, replacement), (kind, self.source[start:end], scope))

    def operator_between(self, left: ast.AST, right: ast.AST) -> tuple[int, int, str] | None:
        """The operator between two operands, parentheses skipped (``in``, ``not in``...)."""
        start, end = self.span(left)[1], self.span(right)[0]
        index = bisect.bisect_left(self.token_starts, start)
        found = []
        while index < len(self.tokens) and self.tokens[index][0] < end:
            if self.tokens[index][2] not in ("(", ")"):
                found.append(self.tokens[index])
            index += 1
        if not found:
            return None
        return found[0][0], found[-1][1], " ".join(token[2] for token in found)

    def swap(self, left: ast.AST, right: ast.AST, table: dict[str, str], kind: str) -> None:
        operator = self.operator_between(left, right)
        if operator is not None and operator[2] in table:
            self.add(operator[0], operator[1], kind, table[operator[2]])

    def walk(self, node: ast.AST, in_function: bool = False, annotations: bool = False) -> None:
        if isinstance(node, ast.Expr) and _is_text(node.value):
            return  # a docstring, or another bare string: no code
        declaration = isinstance(node, ast.AnnAssign) and node.value is None
        if in_function and isinstance(node, _DELETABLE) and not declaration:
            self.add(*self.span(node), "statement", "pass")
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda):
            arguments = node.args
            children: list[ast.AST] = [*arguments.defaults]
            children += [default for default in arguments.kw_defaults if default is not None]
            if isinstance(node, ast.Lambda):
                children.append(node.body)
            else:
                children = [*node.decorator_list, *children]
            for child in children:
                self.walk(child, in_function)
            if not isinstance(node, ast.Lambda):
                self.scope.append(node.name)
                for statement in node.body:
                    self.walk(statement, True)
                self.scope.pop()
            return
        if isinstance(node, ast.ClassDef):
            for child in (*node.decorator_list, *node.bases, *node.keywords):
                self.walk(child, in_function)
            known = _PYDANTIC_BASES | self.pydantic
            pydantic = any(_base_name(base) in known for base in node.bases)
            if pydantic:
                self.pydantic.add(node.name)
            self.scope.append(node.name)
            for statement in node.body:
                self.walk(statement, in_function, annotations=pydantic)
            self.scope.pop()
            return
        if isinstance(node, ast.AnnAssign):
            # Annotations are never evaluated (from __future__ import annotations), except those
            # of a pydantic model's fields.
            parts = [node.target, node.value] + ([node.annotation] if annotations else [])
            for part in parts:
                if part is not None:
                    self.walk(part, in_function)
            return
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    self.walk(value.value, in_function)
                    if value.format_spec is not None:
                        self.walk(value.format_spec, in_function)
            return
        self.mutate(node)
        for child in ast.iter_child_nodes(node):
            self.walk(child, in_function)

    def mutate(self, node: ast.AST) -> None:
        if isinstance(node, ast.BinOp):
            self.swap(node.left, node.right, _BINARY, "operator")
        elif isinstance(node, ast.AugAssign):
            self.swap(node.target, node.value, _AUGMENTED, "operator")
        elif isinstance(node, ast.Compare):
            for left, right in zip([node.left, *node.comparators], node.comparators, strict=False):
                self.swap(left, right, _COMPARISON, "comparison")
        elif isinstance(node, ast.BoolOp):
            for left, right in zip(node.values, node.values[1:], strict=False):
                self.swap(left, right, _BOOLEAN, "boolean")
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            start = self.span(node)[0]
            end = start + len("not")
            while self.source[end] in " \t":
                end += 1
            self.add(start, end, "boolean", "")
        elif isinstance(node, ast.Constant):
            self.constant(node)

    def constant(self, node: ast.Constant) -> None:
        start, end = self.span(node)
        value = node.value
        if isinstance(value, bool):
            self.add(start, end, "constant", str(not value))
        elif isinstance(value, int | float):
            self.add(start, end, "constant", repr(value + 1))
        elif isinstance(value, str | bytes):
            parts = [token for token in self.strings if start <= token[0] and token[1] <= end]
            if not parts:
                return
            opening = parts[0][0] + _quote_start(parts[0][2])
            closing = parts[-1][1] - _quote_length(parts[-1][2])
            text = self.source
            self.add(
                start,
                end,
                "string",
                f"{text[start:opening]}XX{text[opening:closing]}XX{text[closing:end]}",
            )


def _quote_length(token: str) -> int:
    body = token.lstrip("rRbBuU")
    return 3 if body[:3] in ('"""', "'''") and len(body) >= 6 else 1


def _quote_start(token: str) -> int:
    return len(token) - len(token.lstrip("rRbBuU")) + _quote_length(token)


def generate(name: str, source: str) -> list[Mutant]:
    """Every mutant of ``source``, in source order."""
    collector = _Collector(source)
    collector.walk(ast.parse(source))
    mutants: list[Mutant] = []
    seen: dict[str, int] = {}
    for number, ((start, end, replacement), (kind, original, scope)) in enumerate(
        sorted(collector.found.items()), start=1
    ):
        line = source.count("\n", 0, start) + 1
        text = collector.lines[line - 1]
        column = start - collector.starts[line - 1] - (len(text) - len(text.lstrip()))
        mutant = Mutant(
            name, number, line, kind, start, end, original, replacement, scope, column, text.strip()
        )
        try:
            compile(mutant.apply(source), name, "exec")
        except SyntaxError:  # not a program (e.g. a nonlocal's only binding became pass)
            continue
        seen[mutant.signature] = occurrence = seen.get(mutant.signature, 0) + 1
        mutant = dataclasses.replace(mutant, occurrence=occurrence)
        mutants.append(mutant)
    return mutants


# --------------------------------------------------------------------------- copies and runs


@dataclasses.dataclass
class Outcome:
    status: str  # killed, survived, timeout, skipped
    seconds: float
    detail: str = ""  # the first failing test (and why), or why it was not run
    exit_code: int | None = None


def _repository_files() -> list[str]:
    listed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],  # noqa: S607
        cwd=REPO,
        capture_output=True,
        check=True,
    ).stdout.decode()
    files = []
    for name in filter(None, listed.split("\0")):
        top = name.split("/", 1)[0]
        if top in ("reference", ".mutation") or top.startswith("tmp"):
            continue  # secrets, this tool's own output, stray temporary directories
        path = REPO / name
        if path.is_file() and not path.is_symlink():
            files.append(name)
    return files


class Worker:
    """One copy of the repository and the means to run a target's tests in it."""

    def __init__(self, work: Path, number: int, name: str, target: Target) -> None:
        self.directory = work / f"worker-{number}"
        self.copy = self.directory / "repo"
        self.target = target
        if self.directory.exists():
            shutil.rmtree(self.directory)
        for relative in _repository_files():
            destination = self.copy / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO / relative, destination)
        if target.link_env and (REPO / ".env").is_file():
            (self.copy / ".env").symlink_to(REPO / ".env")  # read in place, never copied
        self.module = self.copy / target.path
        self.original = self.module.read_bytes().decode("utf-8")
        self.stamp = int(self.module.stat().st_mtime)
        self.safety: Path | None = None
        if target.guard:
            self.safety = self._install_safety_net()
        self.log = self.directory / "last-run.log"
        (self.directory / "hypothesis").mkdir(parents=True, exist_ok=True)

    def _install_safety_net(self) -> Path:
        safety = self.directory / "safety"
        safety.mkdir(parents=True)
        shutil.copy2(Path(__file__), safety / f"{SAFETY_MODULE}.py")
        (safety / f"{REFERENCE_GUARD}.py").write_text(self.original, encoding="utf-8")
        (safety / f"{SAFETY_PLUGIN}.py").write_text(_PLUGIN_SOURCE, encoding="utf-8")
        startup = self.copy / "tests" / "_guard" / "sitecustomize.py"
        text = startup.read_text(encoding="utf-8")
        if text.count(_GUARD_STARTUP) != 1:
            raise SystemExit(
                f"cannot install the safety net: {startup} lacks the lines\n{_GUARD_STARTUP}"
            )
        module_path = str(safety / f"{SAFETY_MODULE}.py")
        patched = _GUARD_AND_SAFETY_STARTUP.format(module=SAFETY_MODULE, path=module_path)
        startup.write_text(text.replace(_GUARD_STARTUP, patched), encoding="utf-8")
        (self.copy / _PROBE).write_text(_PROBE_SOURCE, encoding="utf-8")
        return safety

    def check_safety_net(self) -> None:
        """Stop unless the safety net works in this copy (the guard is still unmutated)."""
        code, output, _ = self.run([_PROBE], first_failure=True, limit=300)
        if code != 0:
            raise SystemExit(
                f"the mutation safety net does not work in {self.copy}:\n{output[-3000:]}"
            )

    def environment(self) -> dict[str, str]:
        dropped = ("ARGUS_", "PYTEST_", "PG", "HYPOTHESIS_", "COVERAGE_")
        env = {
            key: value for key, value in os.environ.items() if not key.upper().startswith(dropped)
        }
        env.pop("PYTHONPATH", None)
        paths = [str(self.copy / "src")]
        if self.safety is not None:
            paths.insert(0, str(self.safety))
            env[DATABASE_PORTS_VARIABLE] = ",".join(str(port) for port in _configured_ports())
        env["PYTHONPATH"] = os.pathsep.join(paths)
        env["HYPOTHESIS_STORAGE_DIRECTORY"] = str(self.directory / "hypothesis")
        env["PYTHONHASHSEED"] = "0"
        env["COLUMNS"] = "4000"  # pytest cuts summary lines to the width: keep node ids whole
        return env

    def write(self, text: str, stamp: int) -> None:
        """Every version of the module gets its own modification time: Python's bytecode cache
        trusts the time and size, and two mutants may have the same size."""
        self.module.write_bytes(text.encode("utf-8"))
        os.utime(self.module, (stamp, stamp))

    def run(
        self,
        tests: Sequence[str],
        *,
        first_failure: bool,
        deselect: Iterable[str] = (),
        limit: float,
    ) -> tuple[int | None, str, float]:
        """Run ``tests`` in the copy: (exit code, None after a timeout; output; seconds)."""
        command = [sys.executable, "-m", "pytest", "-q", "-rfE", "-p", "no:cacheprovider"]
        command += ["--timeout", str(self.target.test_timeout)]
        if first_failure:
            command.append("-x")
        if self.safety is not None:
            command += ["-p", SAFETY_PLUGIN]
        for node in deselect:
            command += ["--deselect", node]
        command += _test_arguments(self.copy, tests)
        started = time.monotonic()
        with self.log.open("wb") as output:
            process = subprocess.Popen(  # noqa: S603 - this interpreter's pytest in the copy
                command,
                cwd=self.copy,
                env=self.environment(),
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            with _LIVE_LOCK:
                _LIVE.add(process.pid)
            try:
                if _STOPPING.is_set():  # started while the runner was stopping
                    os.killpg(process.pid, signal.SIGKILL)
                code: int | None = process.wait(timeout=limit)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)  # with its children (nested pytest runs)
                process.wait()
                code = None
            finally:
                with _LIVE_LOCK:
                    _LIVE.discard(process.pid)
        if _STOPPING.is_set():
            raise SystemExit("the runner is stopping")  # never record a run that was cut short
        text = self.log.read_bytes().decode("utf-8", "replace")
        return code, text, time.monotonic() - started


def _test_arguments(root: Path, tests: Sequence[str]) -> list[str]:
    """The tests in the order given, each once, a directory as its test files (sorted): pytest
    folds a file into a directory that holds it and runs both in directory order, so a fast file
    put first would not run first."""
    arguments: list[str] = []
    for test in tests:
        path = root / test.split("::")[0]
        if not path.exists():
            continue
        found = (
            [str(p.relative_to(root)) for p in sorted(path.rglob("test_*.py"))]
            if path.is_dir()
            else [test]
        )
        arguments.extend(item for item in found if item not in arguments)
    return arguments


def _configured_ports() -> list[int]:
    """Ports of the local Postgres: the settings' default and .env's ARGUS_DATABASE__PORT."""
    ports = set(_POSTGRES_PORTS)
    env_file = REPO / ".env"
    if env_file.is_file():
        from dotenv import dotenv_values

        for key, value in dotenv_values(env_file).items():
            if key.upper() == "ARGUS_DATABASE__PORT" and value and value.strip().isdigit():
                ports.add(int(value))
    return sorted(ports)


_FAILED = re.compile(r"^(?:FAILED|ERROR) (.+?)(?: - (.*))?$", re.MULTILINE)
_SUSPECT = ("DeadlineExceeded", "Flaky", "Timeout")


def _failures(output: str) -> list[tuple[str, str]]:
    return [(match[1], match[2] or "") for match in _FAILED.finditer(output)]


def _outcome(code: int | None, output: str, seconds: float) -> Outcome:
    if code is None:
        return Outcome("timeout", seconds, "over the time limit")
    failures = _failures(output)
    if code == 0:
        return Outcome("survived", seconds, exit_code=code)
    if failures and "from pytest-timeout" in failures[0][1]:
        return Outcome("timeout", seconds, f"{failures[0][0]}: over pytest-timeout's limit", code)
    if failures:
        node, reason = failures[0]
        return Outcome("killed", seconds, f"{node} - {reason}"[:300], code)
    tail = [line for line in output.splitlines() if line.strip()][-1:] or ["no output"]
    return Outcome("killed", seconds, f"exit {code}: {tail[0]}"[:300], code)


# --------------------------------------------------------------------------- one target


def run_target(name: str, args: argparse.Namespace) -> dict[str, Any]:
    target = TARGETS[name]
    source = (REPO / target.path).read_text(encoding="utf-8")
    mutants = generate(name, source)
    selected = [mutant for mutant in mutants if not args.only or mutant.id in args.only]
    results_file = args.work / "results" / f"{name}.json"
    previous = _load(results_file) if args.only else {}
    if previous and previous.get("source") != source:
        raise SystemExit(f"{name}: the module changed since the saved results; run it whole again")
    print(f"== {name}: {len(mutants)} mutants ({len(selected)} to run), {target.path}", flush=True)
    count = min(args.workers, target.max_workers)
    workers = [Worker(args.work / name, number, name, target) for number in range(count)]
    if target.guard:
        for worker in workers:
            worker.check_safety_net()
        print("   safety net checked in every copy", flush=True)
    baseline = workers[0]
    code, output, seconds = baseline.run(target.tests, first_failure=False, limit=1800)
    first_failures = _failures(output)
    deselect = sorted({node for node, _ in first_failures})
    if code not in (0, 1) or (code == 1 and not deselect):
        raise SystemExit(f"{name}: the tests fail on the original code\n{output[-3000:]}")
    if deselect:  # failing again on their own: DEFECT tests, deselected for the mutant runs
        code, output, _ = baseline.run(deselect, first_failure=False, limit=1800)
        again = {node for node, _ in _failures(output)}
        if again != set(deselect):
            why = "; ".join(f"{node}: {reason}" for node, reason in first_failures)[:2000]
            raise SystemExit(
                f"{name}: tests that fail only sometimes on the original code: {deselect}\n{why}"
            )
        code, output, seconds = baseline.run(
            target.tests, first_failure=False, deselect=deselect, limit=1800
        )
        if code != 0:
            raise SystemExit(f"{name}: the tests still fail on the original code\n{output[-3000:]}")
        print(f"   deselected (fail on the original code): {', '.join(deselect)}", flush=True)
    limit = max(120.0, 3 * seconds + 60)
    print(f"   baseline passed in {seconds:.1f}s; time limit per mutant {limit:.0f}s", flush=True)

    outcomes: dict[str, Outcome] = {}
    lock = threading.Lock()
    idle: queue.Queue[Worker] = queue.Queue()
    for worker in workers:
        idle.put(worker)

    def run_one(mutant: Mutant, tests: Sequence[str] | None = None) -> Outcome:
        worker = idle.get()
        try:
            unit_only = mutant.original in target.unit_only or (
                bool(target.unit_only_lines)
                and mutant.source_line.startswith(target.unit_only_lines)
            )
            chosen = tests or (target.unit_tests if unit_only else target.tests)
            worker.write(mutant.apply(worker.original), worker.stamp + 1000 + mutant.number)
            try:
                outcome = _outcome(
                    *worker.run(chosen, first_failure=True, deselect=deselect, limit=limit)
                )
            finally:
                worker.write(worker.original, worker.stamp)
            if unit_only and outcome.status == "survived":
                outcome = Outcome(
                    "skipped",
                    outcome.seconds,
                    "not run against the database (it would change the runtime login there);"
                    " the unit tests missed it",
                )
        finally:
            idle.put(worker)
        with lock:
            outcomes[mutant.id] = outcome
            print(
                f"   {mutant.describe()}: {outcome.status} ({outcome.seconds:.1f}s)"
                f" {outcome.detail[:120]}",
                flush=True,
            )
        return outcome

    threads = []
    pending: queue.Queue[Mutant] = queue.Queue()
    for mutant in selected:
        pending.put(mutant)

    def drain() -> None:
        while True:
            try:
                mutant = pending.get_nowait()
            except queue.Empty:
                return
            run_one(mutant)

    try:
        for _ in workers:
            thread = threading.Thread(target=drain, daemon=True)
            thread.start()
            threads.append(thread)
        for thread in threads:
            thread.join()
    finally:
        for worker in workers:
            worker.write(worker.original, worker.stamp)

    # Check the kills: each killing test must pass on the original code.
    killers = sorted(
        {
            outcome.detail.split(" - ", 1)[0]
            for outcome in outcomes.values()
            if outcome.status == "killed" and "::" in outcome.detail
        }
    )
    broken: set[str] = set()
    if killers:
        _, output, _ = baseline.run(killers, first_failure=False, deselect=deselect, limit=1800)
        broken = {node for node, _ in _failures(output)}
    again = [
        mutant
        for mutant in selected
        if outcomes[mutant.id].status == "killed"
        and (
            outcomes[mutant.id].detail.split(" - ", 1)[0] in broken
            or (outcomes[mutant.id].exit_code or 0) < 0
            or any(word in outcomes[mutant.id].detail for word in _SUSPECT)
        )
    ]
    if again:
        print(f"   running {len(again)} mutants again (their kill was not conclusive)", flush=True)
        for mutant in again:
            run_one(mutant)

    records = previous.get("mutants", {}) if previous else {}
    equivalent = EQUIVALENT.get(name, {})
    for mutant in mutants:
        if mutant.id in outcomes:
            outcome = outcomes[mutant.id]
            records[mutant.id] = {
                **dataclasses.asdict(mutant),
                "id": mutant.id,
                "status": outcome.status,
                "seconds": round(outcome.seconds, 2),
                "detail": outcome.detail,
            }
        if mutant.id in records:
            records[mutant.id]["equivalent"] = equivalent.get(mutant.signature)
    result = {
        "target": name,
        "path": target.path,
        "source": source,
        "deselected": deselect,
        "mutants": records,
    }
    results_file.parent.mkdir(parents=True, exist_ok=True)
    results_file.write_text(json.dumps(result, indent=1), encoding="utf-8")
    return result


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


# --------------------------------------------------------------------------- report


def _equivalent(target: str, record: dict[str, Any]) -> str | None:
    """Why this saved mutant cannot change behaviour, from EQUIVALENT as it is now."""
    fields = {field.name for field in dataclasses.fields(Mutant)}
    if not fields <= set(record):  # saved by an older version of this file
        return None
    mutant = Mutant(**{key: value for key, value in record.items() if key in fields})
    return EQUIVALENT.get(target, {}).get(mutant.signature)


def summarize(result: dict[str, Any]) -> dict[str, Any]:
    records = list(result["mutants"].values())
    counts = dict.fromkeys(("killed", "survived", "timeout", "skipped"), 0)
    equivalent = 0
    for record in records:
        reason = _equivalent(result["target"], record)
        if reason and record["status"] == "killed":
            print(f"warning: {record['id']} is listed as equivalent but a test killed it")
        if reason and record["status"] != "killed":
            equivalent += 1
            continue
        counts[record["status"]] += 1
    denominator = len(records) - equivalent
    score = 100.0 * counts["killed"] / denominator if denominator else 100.0
    return {
        "target": result["target"],
        "mutants": len(records),
        **counts,
        "equivalent": equivalent,
        "score": round(score, 1),
    }


def report(results: list[dict[str, Any]]) -> None:
    header = f"{'module':<10} {'mutants':>7} {'killed':>6} {'survived':>8} {'timeout':>7}"
    header += f" {'skipped':>7} {'equiv':>5} {'score':>6}"
    print(header)
    for result in results:
        row = summarize(result)
        print(
            f"{row['target']:<10} {row['mutants']:>7} {row['killed']:>6} {row['survived']:>8}"
            f" {row['timeout']:>7} {row['skipped']:>7} {row['equivalent']:>5} {row['score']:>5.1f}%"
        )
    for result in results:
        left = [
            record
            for record in result["mutants"].values()
            if record["status"] != "killed" and not _equivalent(result["target"], record)
        ]
        if left:
            print(f"\n{result['target']}: not killed")
            for record in sorted(left, key=lambda record: int(record["id"].split(":")[1])):
                print(
                    f"  {record['id']} line {record['line']} {record['kind']} {record['status']}:"
                    f" {_short(record['original'])} -> {_short(record['replacement'])}"
                )


# --------------------------------------------------------------------------- main


def main(argv: Sequence[str] | None = None) -> int:
    # Ctrl-C, SIGTERM and SIGHUP end the runner and every test run it started (not SIGKILL).
    atexit.register(_stop_live_runs)
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, lambda number, _frame: sys.exit(128 + number))
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("targets", nargs="*", metavar="module", help=f"any of {', '.join(TARGETS)}")
    parser.add_argument("--workers", type=int, default=2, help="parallel runs (default 2)")
    parser.add_argument("--work", type=Path, default=REPO / ".mutation", help="copies and results")
    parser.add_argument(
        "--only",
        type=lambda text: set(filter(None, text.split(","))),
        default=set(),
        help="mutant ids, comma-separated",
    )
    parser.add_argument("--list", action="store_true", help="print the mutants and stop")
    parser.add_argument("--show", help="print one mutant (module:number) as a diff and stop")
    parser.add_argument(
        "--report", action="store_true", help="summarize the saved results and stop"
    )
    args = parser.parse_args(argv)
    unknown = sorted(set(args.targets) - set(TARGETS))
    if unknown:
        parser.error(f"unknown module(s) {', '.join(unknown)}; choose from {', '.join(TARGETS)}")
    names = list(args.targets) or list(TARGETS)
    if args.only:
        names = [name for name in names if any(item.startswith(f"{name}:") for item in args.only)]
    if args.show:
        name = args.show.split(":", 1)[0]
        source = (REPO / TARGETS[name].path).read_text(encoding="utf-8")
        mutant = {m.id: m for m in generate(name, source)}[args.show]
        diff = difflib.unified_diff(
            source.splitlines(keepends=True),
            mutant.apply(source).splitlines(keepends=True),
            TARGETS[name].path,
            f"{TARGETS[name].path} ({mutant.id})",
        )
        sys.stdout.writelines(diff)
        return 0
    if args.list:
        for name in names:
            source = (REPO / TARGETS[name].path).read_text(encoding="utf-8")
            for mutant in generate(name, source):
                print(mutant.describe())
        return 0
    if args.report:
        loaded = [
            result for name in names if (result := _load(args.work / "results" / f"{name}.json"))
        ]
        report(loaded)
        return _status(loaded)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    args.work = args.work.resolve()
    results = [run_target(name, args) for name in names]
    print()
    report(results)
    return _status(results)


TARGET_SCORE = 85.0  # D-040: killed / (mutants - equivalent), per module


def _status(results: list[dict[str, Any]]) -> int:
    """1 if any module is under TARGET_SCORE (the gate then records a failure), else 0."""
    low = [row["target"] for row in map(summarize, results) if row["score"] < TARGET_SCORE]
    if low:
        print(f"\nunder {TARGET_SCORE:.0f}%: {', '.join(low)}")
    return 1 if low else 0


if __name__ == "__main__":
    sys.exit(main())
