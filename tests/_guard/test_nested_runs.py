"""Self-tests of the harness that start a nested pytest run, in a child process or in this one.

* A guarded test that starts ``pytest --run-live`` cannot lift the guard for the nested run's live
  tests: the nested run inherits the guard locked on, or, in this process, finds it locked by the
  run around it (whichever copy of tests/conftest.py it loads). Only a live test's nested run may
  lift it.
* The harness's own tests pass when the suite runs under a guard inherited switched on.
* The integration conftest names UNSET_DATABASE for the whole session: module-level code and
  fixtures of every scope see it, not only function-scoped fixtures.
* pytest's report of a refused database connection never shows the password, not even a piece of
  it, with the options that show the most (--tb=long, --showlocals, --full-trace) or with -l at
  the default verbosity, where saferepr cuts long reprs; nor does a collection error.

The probes do no network I/O beyond loopback ports where nothing listens, use no database, and
use made-up passwords.
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
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

import tests.conftest as harness
from tests.conftest import ProductionAccessBlockedError

netguard = harness._netguard

_PROBE_INI = """\
[pytest]
markers =
    unit: pure tests
    integration: needs the local Postgres
    live: production SIEM
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
"""


def _pytest(
    cwd: Path, env: Mapping[str, str], *args: str, quiet: bool = True
) -> subprocess.CompletedProcess[str]:
    verbosity = ["-q"] if quiet else []
    return subprocess.run(  # noqa: S603 - this interpreter's pytest on a local probe suite
        [sys.executable, "-m", "pytest", *verbosity, "-p", "no:cacheprovider", *args],
        cwd=cwd,
        env=dict(env),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _inherited_environment() -> dict[str, str]:
    """What this test's child processes inherit, minus pytest options meant for this run."""
    return {
        name: value
        for name, value in os.environ.items()
        if name not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")
    }


def _with_repo_on_path(env: dict[str, str]) -> dict[str, str]:
    paths = (str(harness.REPO_ROOT), env.get("PYTHONPATH", ""))
    return {**env, "PYTHONPATH": os.pathsep.join(filter(None, paths))}


# --------------------------------------------------------------------------- nested --run-live

_LIVE_PROBE = '''
import json
import os
import socket
import sys

import pytest

import argus_netguard as guard

pytestmark = pytest.mark.live


def test_probe() -> None:
    """No network I/O: the guard's decision is asked for through the audit event alone."""
    with socket.socket() as sock:
        try:
            sys.audit("socket.connect", sock, ("192.0.2.1", 9))
        except guard.NetworkAccessBlockedError:
            blocked = True
        else:
            blocked = False
    guarded = os.environ["NETGUARD_PROBE_EXPECT"] == "guarded"
    assert guard.STATE["active"] is guarded
    assert json.loads(os.environ[guard.ENV_VAR])["active"] is guarded  # for its own children
    assert blocked is guarded
'''


@pytest.fixture
def scratch_suite(tmp_path: Path) -> Path:
    """This harness (tests/conftest.py and tests/_guard) copied beside one test in tests/live/."""
    tests_dir = tmp_path / "tests"
    (tests_dir / "_guard").mkdir(parents=True)
    (tests_dir / "live").mkdir()
    for name in ("__init__.py", "conftest.py"):
        shutil.copy2(harness.TESTS_DIR / name, tests_dir / name)
    for name in ("__init__.py", "argus_netguard.py", "sitecustomize.py"):
        shutil.copy2(harness.GUARD_DIR / name, tests_dir / "_guard" / name)
    (tests_dir / "live" / "test_probe_live.py").write_text(_LIVE_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_PROBE_INI, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize(
    ("parent", "expected"),
    [
        ("guarded-test", "guarded"),  # inherits this test's environment as it is
        ("no-description", "guarded"),  # PYTEST_* dropped: the sitecustomize fails closed
        ("no-sitecustomize", "guarded"),  # PYTHONPATH dropped: the conftest reads the description
        ("live-test", "lifted"),  # a live test runs without the guard, and so may its nested run
    ],
)
def test_a_nested_run_lifts_the_guard_only_if_its_parent_had(
    scratch_suite: Path, parent: str, expected: str
) -> None:
    env = _inherited_environment()
    assert json.loads(env[netguard.ENV_VAR])["active"] is True  # this test is guarded
    if parent == "no-description":
        env = {name: value for name, value in env.items() if not name.upper().startswith("PYTEST_")}
    elif parent == "no-sitecustomize":
        del env["PYTHONPATH"]
    elif parent == "live-test":
        env[netguard.ENV_VAR] = json.dumps({**json.loads(env[netguard.ENV_VAR]), "active": False})
    env["NETGUARD_PROBE_EXPECT"] = expected
    completed = _pytest(scratch_suite, env, "--run-live", "tests/live/test_probe_live.py")
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "1 passed" in completed.stdout


_IN_PROCESS_INI = """\
[pytest]
markers =
    live: production SIEM
"""

_IN_PROCESS_PROBE = '''
import os
import socket
import sys

import pytest

import argus_netguard as guard

pytestmark = pytest.mark.live


def _refusal(host: str) -> str | None:
    """The guard's decision on connecting to ``host``, asked through the audit event alone."""
    with socket.socket() as sock:
        try:
            sys.audit("socket.connect", sock, (host, 9))
        except guard.NetworkAccessBlockedError as refusal:
            return type(refusal).__name__
    return None


def test_probe() -> None:
    assert guard.STATE["active"] is True
    assert guard.STATE["locked"] is True
    assert _refusal("192.0.2.1") == "NetworkAccessBlockedError"
    # A production stand-in of the run around this one still counts.
    assert _refusal(os.environ["NETGUARD_PROBE_HOST"]) == "ProductionAccessBlockedError"
'''


@contextlib.contextmanager
def _imports_restored(root: Path) -> Iterator[None]:
    """Undo what an in-process run on ``root`` leaves in sys.path and sys.modules: its conftest
    and test modules are imported under bare names such as ``conftest``."""
    path = list(sys.path)
    try:
        yield
    finally:
        sys.path[:] = path
        for name, module in list(sys.modules.items()):
            file = getattr(module, "__file__", None)
            if file and Path(file).is_relative_to(root):
                del sys.modules[name]


def test_an_in_process_run_of_a_copied_harness_cannot_lift_the_guard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """pytest.main() in a guarded test, given --run-live, on a copy of this harness: the copy's
    conftest is a module of its own, yet its live test stays guarded and still refuses this run's
    production stand-in. When it ends, the guard is as this run had it."""
    tests_dir = tmp_path / "tests"  # no __init__.py: the conftest is imported as 'conftest'
    (tests_dir / "_guard").mkdir(parents=True)
    (tests_dir / "live").mkdir()
    shutil.copy2(harness.TESTS_DIR / "conftest.py", tests_dir / "conftest.py")
    for name in ("argus_netguard.py", "sitecustomize.py"):
        shutil.copy2(harness.GUARD_DIR / name, tests_dir / "_guard" / name)
    probe = tests_dir / "live" / "test_in_process_probe_live.py"
    probe.write_text(_IN_PROCESS_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_IN_PROCESS_INI, encoding="utf-8")
    stand_in = "127.0.0.2"  # a production host for this run only
    monkeypatch.setattr(harness, "PRODUCTION_HOSTS", harness.PRODUCTION_HOSTS | {stand_in})
    monkeypatch.setenv("NETGUARD_PROBE_HOST", stand_in)
    for name in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        monkeypatch.delenv(name, raising=False)
    watched = ("PYTHONPATH", netguard.ENV_VAR)
    before = ({name: os.environ.get(name) for name in watched}, dict(harness._GUARD_STATE))
    args = ["-p", "no:cacheprovider", "-p", "no:asyncio", "--rootdir", str(tmp_path)]
    args += ["-c", str(tmp_path / "pytest.ini"), "--run-live", str(probe)]
    with _imports_restored(tmp_path), warnings.catch_warnings():
        warnings.simplefilter("default")  # its own warning filters, as at the top level
        exit_code = pytest.main(args)
    output = capsys.readouterr().out
    assert exit_code == pytest.ExitCode.OK, output[-3000:]
    assert "1 passed" in output
    assert ({name: os.environ.get(name) for name in watched}, dict(harness._GUARD_STATE)) == before
    assert netguard._production_hosts is harness._production_hosts  # not the copy's
    assert netguard._protected_databases is harness._protected_databases
    with socket.socket() as sock, pytest.raises(ProductionAccessBlockedError):
        sys.audit("socket.connect", sock, (stand_in, 9))  # this run's own hosts are back


def test_the_harness_self_tests_pass_under_an_inherited_guard() -> None:
    """Run from a guarded process (a guarded test, or with PYTEST_ARGUS_NETGUARD set), the guard
    is locked on: the self-tests that lift it skip instead of failing."""
    env = _inherited_environment()
    env[netguard.ENV_VAR] = '{"active": true}'
    module = "tests/_guard/test_harness.py"
    completed = _pytest(
        harness.REPO_ROOT,
        env,
        f"{module}::test_only_live_tests_with_run_live_run_unguarded",
        f"{module}::test_python_children_of_a_live_test_run_unguarded",
        f"{module}::test_a_run_nested_in_a_live_test_may_lift_the_guard_and_gives_it_back",
        f"{module}::test_the_developers_database_is_left_to_libpq_while_the_guard_is_lifted",
    )
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "4 passed, 4 skipped" in completed.stdout, completed.stdout[-2000:]


# --------------------------------------------------------------------------- the unset database

_SENTINEL_PROBE = '''
import os

import pytest

from tests.integration.conftest import UNSET_DATABASE

AT_IMPORT = os.environ.get("ARGUS_DATABASE__NAME")


@pytest.fixture(scope="session")
def _drop_stale_test_databases() -> None:
    """Replaces the integration conftest's: this probe uses no database."""


@pytest.fixture(scope="session")
def _runtime_roles() -> None:
    """Replaces the integration conftest's (bootstrap of the roles): no database here either."""


@pytest.fixture(scope="session")
def at_session_setup() -> str | None:
    return os.environ.get("ARGUS_DATABASE__NAME")


@pytest.fixture(scope="module")
def at_module_setup() -> str | None:
    return os.environ.get("ARGUS_DATABASE__NAME")


def test_probe(at_session_setup: str | None, at_module_setup: str | None) -> None:
    assert AT_IMPORT == UNSET_DATABASE
    assert at_session_setup == UNSET_DATABASE
    assert at_module_setup == UNSET_DATABASE
'''


def test_the_unset_database_covers_the_whole_session(tmp_path: Path) -> None:
    """Module-level code and session or module fixtures do not get .env's database either."""
    (tmp_path / "test_sentinel_probe.py").write_text(_SENTINEL_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_PROBE_INI, encoding="utf-8")
    env = _with_repo_on_path(_inherited_environment())
    env.pop("ARGUS_DATABASE__NAME", None)  # a fresh session: nothing set by this one
    completed = _pytest(tmp_path, env, "-p", "tests.integration.conftest", "test_sentinel_probe.py")
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "1 passed" in completed.stdout


# --------------------------------------------------------------------------- the password

_PASSWORD_PROBE = '''
import os
import socket

import psycopg
from pydantic import SecretStr
from sqlalchemy import text

import tests.conftest
from argus.config import DatabaseSettings
from argus.db.engine import create_engine
from tests.integration.conftest import admin_connect

PASSWORD = SecretStr(os.environ.pop("NETGUARD_PROBE_PASSWORD"))
DATABASE = "argus_test_1760082000_0a1b2c3d"  # as make_database names one
hide_in_reports = getattr(tests.conftest, "hide_in_reports", lambda secret: None)


def _closed_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _settings(host: str) -> DatabaseSettings:
    return DatabaseSettings(
        host=host, port=_closed_port(), password=PASSWORD, owner_password=PASSWORD
    )


def test_admin_connect_to_a_closed_port() -> None:
    admin_connect(_settings("127.0.0.1"))


def test_admin_connect_refused_by_the_guard() -> None:
    admin_connect(_settings("192.0.2.1"))


def test_psycopg_to_a_closed_port() -> None:
    psycopg.connect(
        host="127.0.0.1",
        port=_closed_port(),
        user="u",
        password=PASSWORD.get_secret_value(),
        dbname=DATABASE,
        connect_timeout=1,
    )


async def _connect_engine(role: str) -> None:
    """SQLAlchemy keeps the parameters in its own frames: there, the report itself is masked.
    With -l at the default verbosity saferepr cuts them, inside the password for the owner."""
    hide_in_reports(PASSWORD.get_secret_value())  # as the db_settings fixture does
    engine = create_engine(_settings("127.0.0.1"), database=DATABASE, role=role)
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    finally:
        await engine.dispose()


async def test_engine_to_a_closed_port() -> None:
    await _connect_engine("app")


async def test_owner_engine_to_a_closed_port() -> None:
    await _connect_engine("owner")


def test_an_assertion_about_the_password() -> None:
    """Like tests/integration/test_cli_db.py's check that CLI output lacks the password: if such
    an assertion failed, pytest's message would show both values."""
    hide_in_reports(PASSWORD.get_secret_value())
    output = f"error: password {PASSWORD.get_secret_value()} rejected"
    assert PASSWORD.get_secret_value() not in output


def test_an_assertion_that_cuts_the_password() -> None:
    """Below -vv, an assertion message shortens each side to a few dozen characters."""
    hide_in_reports(PASSWORD.get_secret_value())
    output = f"{PASSWORD.get_secret_value()} was rejected by the server at 127.0.0.1"
    assert PASSWORD.get_secret_value() not in output
'''


@pytest.mark.parametrize(
    "options",
    [
        ("-q", "-vv", "--tb=long", "--showlocals", "--full-trace"),
        ("-l",),  # the default verbosity: saferepr cuts long reprs
        ("-v", "--tb=long", "-l"),
    ],
    ids=["most-revealing", "showlocals", "verbose-showlocals"],
)
def test_pytest_never_reports_the_database_password(
    tmp_path: Path, options: tuple[str, ...]
) -> None:
    """Refused connections on every harness path, reported with the revealing options: no
    6-character piece of the password appears anywhere in the output."""
    (tmp_path / "test_password_probe.py").write_text(_PASSWORD_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_PROBE_INI, encoding="utf-8")
    password = f"pw-{secrets.token_urlsafe(12)}"
    env = _with_repo_on_path(_inherited_environment())
    env["NETGUARD_PROBE_PASSWORD"] = password
    completed = _pytest(
        tmp_path, env, "-p", "tests.conftest", *options, "test_password_probe.py", quiet=False
    )
    output = completed.stdout + completed.stderr
    pieces = {password[i : i + 6] for i in range(len(password) - 5)}
    shown = sum(piece in output for piece in pieces)
    assert shown == 0, f"pytest's report showed {shown} 6-character pieces of the password"
    assert "7 failed" in completed.stdout, completed.stdout[-3000:]
    assert "local Postgres unreachable" in completed.stdout
    assert "cannot connect to the local Postgres" in completed.stdout


_COLLECTION_PROBE = """
import os

raise RuntimeError("cannot log in with " + os.environ["ARGUS_DATABASE__PASSWORD"])
"""


@pytest.mark.parametrize(
    "plugins",
    [("tests.conftest",), ("tests.conftest", "tests.integration.conftest")],
    ids=["harness", "harness-and-integration"],
)
def test_a_collection_error_never_reports_the_database_password(
    tmp_path: Path, plugins: tuple[str, ...]
) -> None:
    """Both passwords are registered when pytest configures the run, before any module is
    collected (the db_settings fixture only runs at the first integration test)."""
    (tmp_path / "test_collection_probe.py").write_text(_COLLECTION_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_PROBE_INI, encoding="utf-8")
    password = f"pw-{secrets.token_urlsafe(12)}"
    env = _with_repo_on_path(_inherited_environment())
    env["ARGUS_DATABASE__PASSWORD"] = password  # the settings take it from here before .env
    loaded = [argument for plugin in plugins for argument in ("-p", plugin)]
    completed = _pytest(tmp_path, env, *loaded, "test_collection_probe.py")
    output = completed.stdout + completed.stderr
    pieces = {password[i : i + 6] for i in range(len(password) - 5)}
    shown = sum(piece in output for piece in pieces)
    assert shown == 0, f"pytest's report showed {shown} 6-character pieces of the password"
    assert completed.returncode == pytest.ExitCode.INTERRUPTED, completed.stdout[-3000:]
    assert "RuntimeError: cannot log in with ***" in completed.stdout
