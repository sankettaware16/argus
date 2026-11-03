"""Test-suite wide setup.

* Markers come from the directory: tests/unit → unit, tests/integration → integration,
  tests/live → live, tests/kibana → kibana (the local Kibana tier, Q-D1), tests/_guard (the
  harness's own tests) → unit. Live tests only run with ``--run-live``.
* **Network guard** (tests/_guard/argus_netguard.py has the details). It is installed when this
  file is imported, so it is already on while test modules are collected, and it stays on for
  every test except live tests (tests/live/) run with ``--run-live``; ``--run-live`` alone lifts
  it for nothing else. A pytest run that a guarded test starts (a nested run, in a child process
  or in this one, with this file or a copy of it) can never lift it, and leaves the guard as it
  found it. While it is on:

  - sockets may only reach loopback (127.0.0.0/8, ::1) and Unix sockets, never the production
    SIEM (the hosts the checkout's configuration names for it, and the suite's made-up one):
    connect/connect_ex, and sendto/sendmsg for UDP and TCP Fast Open;
  - psycopg connections are checked before libpq opens its own socket: the server must be on
    this machine, and the database must not be the developer's own (``PROTECTED_DATABASES``);
  - a command line naming the SIEM is not started (curl, ssh, ...);
  - Python child processes load the same guard: this file puts tests/_guard first on
    PYTHONPATH, where a sitecustomize installs it.

  A refused attempt raises ``NetworkAccessBlockedError`` (``ProductionAccessBlockedError`` for
  the SIEM) before anything is sent.
* Not covered: C code that opens its own sockets (libcurl, libuv/uvloop, ctypes), non-Python child
  processes beyond the command-line check, and Python children started with ``-I``/``-E``/``-S``
  or with an environment that drops PYTHONPATH. Only an OS-level control (a network namespace or
  a firewall rule) closes those.
* **Secrets in reports**: a value given to ``hide_in_reports`` (the database passwords) is masked
  in every test and collection report, and so is its start or end where pytest's saferepr cut a
  long repr ('...'). pytest prints the arguments of traceback frames (their locals with
  ``--showlocals``), and library code such as SQLAlchemy keeps connection parameters in its own.
* **Hypothesis profiles**: dev (100 examples, the default), ci (1,000) and gate (10,000, no
  deadline; scripts/gate.sh), chosen with the HYPOTHESIS_PROFILE variable; any other name stops
  the run. ``--hypothesis-profile`` still overrides it.
"""

from __future__ import annotations

import functools
import importlib.util
import itertools
import json
import os
import re
import socket
import sys
from collections.abc import Generator, Iterator, Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import hypothesis
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
# The sections a throwaway config file carries when its test runs `argus doctor`: the privacy
# layer refuses to run without an organisation domain (D-285), as production's check does; and a
# made-up checkout for the units, so this machine's installed units are never taken for its own.
THROWAWAY_SITE = (
    "site:\n  own_domains: [example.test]\n"
    "units:\n  root: /home/dev/argus\n  uv: /home/dev/.local/bin/uv\n"
)
TESTS_DIR = REPO_ROOT / "tests"
# The public tree (D-238) leaves out the site's private pack: its runbooks, decisions and own
# tooling. Tests that check the code against those files skip there; here a missing one fails.
PUBLIC_TREE = not (REPO_ROOT / "release" / "export_public.py").is_file()


def private_text(path: Path) -> str:
    """The text of a file of the private pack, or the test skipped in the public tree."""
    if PUBLIC_TREE and not path.exists():
        pytest.skip(f"{path.relative_to(REPO_ROOT)} is private (not in the public tree)")
    return path.read_text(encoding="utf-8")


GUARD_DIR = TESTS_DIR / "_guard"
# Directory under tests/ -> marker. tests/_guard holds the harness's own tests (no services).
_AREA_MARKERS = {
    "unit": "unit",
    "integration": "integration",
    "live": "live",
    "_guard": "unit",
    "kibana": "kibana",  # the local Kibana tier's contract tests (Q-D1): live or replayed
}
# argus.config.DatabaseSettings defaults (a harness self-test keeps them equal).
DEFAULT_DATABASE = "argus"
DEFAULT_DATABASE_PORT = 55432


def _load_netguard() -> ModuleType:
    """One guard per process: reuse the copy a sitecustomize loaded (a nested pytest run)."""
    module = sys.modules.get("argus_netguard")
    if module is None:
        spec = importlib.util.spec_from_file_location(
            "argus_netguard", GUARD_DIR / "argus_netguard.py"
        )
        assert spec is not None
        assert spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    return module


def _port(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _dotenv(env_file: Path) -> Mapping[str, str | None]:
    """``env_file`` read the way the settings read .env (python-dotenv, ${VAR} expanded). A file
    that cannot be read gives nothing; the settings would refuse it as well."""
    try:
        from dotenv import dotenv_values

        return dotenv_values(env_file) if env_file.is_file() else {}
    except Exception:
        return {}


def _database_sections(values: Mapping[str, str | None]) -> Iterator[dict[str, Any]]:
    """The database settings among ``values`` (names in any case): a whole ARGUS_DATABASE section
    as a JSON object, or one ARGUS_DATABASE__<FIELD> variable at a time."""
    for key, value in values.items():
        upper = key.upper()
        if upper == "ARGUS_DATABASE" and value:
            try:
                loaded = json.loads(value)
            except ValueError:
                continue
            if isinstance(loaded, dict):
                yield loaded
        elif upper.startswith("ARGUS_DATABASE__"):
            yield {upper.removeprefix("ARGUS_DATABASE__").lower(): value}


def developer_databases(env_file: Path) -> frozenset[tuple[str, int]]:
    """The developer's own database on the developer's server, as (name, port) pairs.

    Names: the settings default and ARGUS_DATABASE__NAME in ``env_file``; ports: the default and
    its ARGUS_DATABASE__PORT.
    """
    names = {DEFAULT_DATABASE}
    ports = {DEFAULT_DATABASE_PORT}
    for section in _database_sections(_dotenv(env_file)):
        name = section.get("name")
        if isinstance(name, str) and name:
            names.add(name)
        port = _port(section.get("port"))
        if port is not None:
            ports.add(port)
    return frozenset(itertools.product(names, ports))


def database_passwords(env_file: Path, environ: Mapping[str, str] = os.environ) -> frozenset[str]:
    """Both database passwords (``password``, ``owner_password``) wherever the settings may take
    them from: ``environ`` and ``env_file``. A missing or unreadable file adds nothing."""
    passwords = set()
    for values in (environ, _dotenv(env_file)):
        for section in _database_sections(values):
            for field in ("password", "owner_password"):
                value = section.get(field)
                if isinstance(value, str) and value:
                    passwords.add(value)
    return frozenset(passwords)


_netguard = _load_netguard()
if not _netguard.STATE["installed"] and _netguard.ENV_VAR in os.environ:
    # Started by a guarded pytest run, but without the sitecustomize (PYTHONPATH was dropped):
    # take the guard over as that run described it, locked on unless it had been switched off.
    _netguard.install_from_environment()

# The suite's made-up SIEM, refused like the configured one (D-294): the guard's own tests aim at
# it, so they hold in a checkout that configures no SIEM. A name counts in host position only.
SUITE_SIEM_HOSTS: frozenset[str] = frozenset({"10.20.60.11", "siemhost"})
# The configured SIEM's hosts (argus_netguard.configured_hosts: config/local.yaml, siem.url,
# kibana.url) and the suite's.
PRODUCTION_HOSTS: frozenset[str] = _netguard.PRODUCTION_HOSTS | SUITE_SIEM_HOSTS
PROTECTED_DATABASES: frozenset[tuple[str, int]] = developer_databases(REPO_ROOT / ".env")
NetworkAccessBlockedError: type[PermissionError] = _netguard.NetworkAccessBlockedError
ProductionAccessBlockedError: type[PermissionError] = _netguard.ProductionAccessBlockedError
_GUARD_STATE: dict[str, bool] = _netguard.STATE
_audit_hook = _netguard.audit_hook


def _production_hosts() -> frozenset[str]:
    return PRODUCTION_HOSTS  # read at every check: a test may add a loopback stand-in


def _protected_databases() -> frozenset[tuple[str, int]]:
    return PROTECTED_DATABASES  # read at every check, like PRODUCTION_HOSTS


def production_target(address: Any, resolve: Any = socket.getaddrinfo) -> str | None:
    """Return the production host ``address`` points at, or None."""
    target: str | None = _netguard.production_target(address, PRODUCTION_HOSTS, resolve)
    return target


def check_database_host(host: str) -> None:
    """Raise NetworkAccessBlockedError unless libpq would reach ``host`` on this machine."""
    _netguard.check_libpq_target(host, "", PRODUCTION_HOSTS)


if not _netguard.run_in_progress():
    _netguard.install(_production_hosts, _protected_databases)  # before any test module is imported
# Otherwise this is a nested run's copy, loaded by a test of the run in progress: that run's
# settings stay until this run is configured (pytest_configure), which saves them to restore.


# --------------------------------------------------------------------------- secrets in reports

_HIDDEN_IN_REPORTS: set[str] = set()
_MIN_HIDDEN_LENGTH = 6  # as in argus.observability.redaction: shorter values are ordinary words
_MASK = "***"
# pytest's saferepr shortens a long repr (a local with --showlocals, an operand in an assertion
# message) to its start, '...' and its end, and the cut may fall inside a secret: its start
# before the cut, or its end after it, is masked from this many characters on.
_CUT = "..."
_MIN_CUT_PIECE = 4
# A PostgreSQL password verifier (role DDL holds one, and pytest prints a failing frame's
# arguments): the whole verifier or its start, the rest of one after saferepr's '...' cut, and
# its salt and keys without the prefix (an assertion diff may skip the start). Linear-time:
# every repetition is possessive, and a piece starts only at a word boundary or after '...'.
_VERIFIER_PIECES = re.compile(
    r"SCRAM-SHA-256\$[A-Za-z0-9+/=:$]*+"
    r"|(?<=\.\.\.)[A-Za-z0-9+/=:$]{20,}+"
    r"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{20,}+\$[A-Za-z0-9+/=]{40,}+:[A-Za-z0-9+/=]{40,}+"
    r"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{40,}+:[A-Za-z0-9+/=]{40,}+"
)


def hide_in_reports(secret: str | None) -> None:
    """Mask ``secret``, and its escaped forms in reprs and JSON, in every report from now on."""
    if secret and len(secret) >= _MIN_HIDDEN_LENGTH:
        _HIDDEN_IN_REPORTS.update({secret, repr(secret)[1:-1], json.dumps(secret)[1:-1]})


def _cut_pieces(text: str, secrets: list[str]) -> list[tuple[int, int]]:
    """Spans of ``text`` that are the start of a secret just before a '...' or its end just after
    one, longest first at each '...'."""
    starts = {secret[:size] for secret in secrets for size in range(_MIN_CUT_PIECE, len(secret))}
    ends = {secret[-size:] for secret in secrets for size in range(_MIN_CUT_PIECE, len(secret))}
    last_characters = {piece[-1] for piece in starts}  # cheap test first: '....' is common
    first_characters = {piece[0] for piece in ends}
    longest = max(map(len, secrets))
    spans = []
    cut = text.find(_CUT)
    while cut != -1:
        after = cut + len(_CUT)
        if text[cut - 1 : cut] in last_characters:
            for size in range(min(longest, cut), _MIN_CUT_PIECE - 1, -1):
                if text[cut - size : cut] in starts:
                    spans.append((cut - size, cut))
                    break
        if text[after : after + 1] in first_characters:
            for size in range(longest, _MIN_CUT_PIECE - 1, -1):
                if text[after : after + size] in ends:
                    spans.append((after, after + size))
                    break
        cut = text.find(_CUT, cut + 1)
    return spans


def _masked(text: str, secrets: list[str]) -> str:
    for secret in secrets:  # longest first
        while secret in text:  # masking can splice a new occurrence; every pass shortens the text
            text = text.replace(secret, _MASK)
    if not secrets or _CUT not in text:
        return text
    parts: list[str] = []
    end = 0
    for start, stop in sorted(_cut_pieces(text, secrets)):
        if start >= end:
            parts += [text[end:start], _MASK]
        end = max(end, stop)  # overlapping pieces become one mask
    return "".join([*parts, text[end:]])


def _hidden(text: str, secrets: list[str]) -> str:
    """``text`` with the registered secrets and every password verifier masked."""
    return _VERIFIER_PIECES.sub(_MASK, _masked(text, secrets))


def _hide_secrets(report: pytest.TestReport | pytest.CollectReport) -> None:
    secrets = sorted(_HIDDEN_IN_REPORTS, key=len, reverse=True)
    longrepr = report.longrepr
    if isinstance(longrepr, tuple):  # a skip: (path, line, reason)
        path, line, reason = longrepr
        report.longrepr = (path, line, _hidden(reason, secrets))
    elif longrepr is not None:
        text = str(longrepr)
        masked = _hidden(text, secrets)
        if masked != text:
            report.longrepr = masked
    report.sections = [(title, _hidden(content, secrets)) for title, content in report.sections]


# --------------------------------------------------------------------------- Hypothesis profiles

HYPOTHESIS_PROFILE_VARIABLE = "HYPOTHESIS_PROFILE"
DEFAULT_HYPOTHESIS_PROFILE = "dev"
# docs/phase-1-pipeline.md §10. Built on Hypothesis's own defaults, so that its automatic CI
# profile (loaded when a CI variable is set) changes nothing here.
_HYPOTHESIS_DEFAULTS = hypothesis.settings.get_profile("default")
HYPOTHESIS_PROFILES = {
    "dev": hypothesis.settings(_HYPOTHESIS_DEFAULTS, max_examples=100),
    "ci": hypothesis.settings(_HYPOTHESIS_DEFAULTS, max_examples=1_000),
    "gate": hypothesis.settings(_HYPOTHESIS_DEFAULTS, max_examples=10_000, deadline=None),
}
for _name, _profile in HYPOTHESIS_PROFILES.items():
    hypothesis.settings.register_profile(_name, _profile)


def hypothesis_profile(environ: Mapping[str, str]) -> str:
    """The Hypothesis profile ``environ`` names in HYPOTHESIS_PROFILE: dev if unset or empty.

    Any other name than this suite's profiles is a usage error, so a typo cannot quietly run the
    gate with the default 100 examples.
    """
    name = environ.get(HYPOTHESIS_PROFILE_VARIABLE) or DEFAULT_HYPOTHESIS_PROFILE
    if name not in HYPOTHESIS_PROFILES:
        raise pytest.UsageError(
            f"{HYPOTHESIS_PROFILE_VARIABLE}={name!r} is not a Hypothesis profile of this suite; "
            f"use one of: {', '.join(HYPOTHESIS_PROFILES)}"
        )
    return name


# --------------------------------------------------------------------------- pytest hooks

# The Hypothesis profile before a run was configured, loaded again when it ends.
_ENCLOSING_PROFILE = pytest.StashKey[str]()


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live",
        action="store_true",
        default=False,
        help="run the read-only tests in tests/live/ against the production SIEM (the SIEM)",
    )


def pytest_configure(config: pytest.Config) -> None:
    profile = hypothesis_profile(os.environ)  # first: a usage error stops the run unchanged
    config.stash[_ENCLOSING_PROFILE] = hypothesis.settings.get_current_profile_name()
    if not config.getoption("hypothesis_profile", None):  # else the hypothesis plugin loads it
        hypothesis.settings.load_profile(profile)
    # Before anything is collected: tests/_guard is collected before tests/integration, whose
    # conftest registers them as well.
    for password in database_passwords(REPO_ROOT / ".env"):
        hide_in_reports(password)
    # The guard is on since import; this re-arms a reused process and, for a run nested in a
    # guarded test of this process, locks it (see argus_netguard.begin_run).
    _netguard.begin_run(config, _production_hosts, _protected_databases)
    pythonpath = os.environ.get("PYTHONPATH", "")
    if str(GUARD_DIR) not in pythonpath.split(os.pathsep):
        os.environ["PYTHONPATH"] = os.pathsep.join(filter(None, (str(GUARD_DIR), pythonpath)))
    _set_guard(active=True)


def pytest_unconfigure(config: pytest.Config) -> None:
    _netguard.end_run(config)
    enclosing = config.stash.get(_ENCLOSING_PROFILE, None)
    if enclosing is not None:
        hypothesis.settings.load_profile(enclosing)


def _area(item: pytest.Item) -> str | None:
    """unit, integration or live, from the directory under tests/ that holds the test."""
    try:
        parts = item.path.resolve().relative_to(TESTS_DIR).parts
    except ValueError:
        return None
    return _AREA_MARKERS.get(parts[0]) if len(parts) > 1 else None


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_live = config.getoption("--run-live")
    skip_live = pytest.mark.skip(
        reason="live test: run with --run-live (read-only, production SIEM)"
    )
    for item in items:
        area = _area(item)
        if area is not None:
            item.add_marker(area)
        if not run_live and "live" in item.keywords:
            item.add_marker(skip_live)


def _may_leave_loopback(item: pytest.Item) -> bool:
    """Only a live test in tests/live/, and only with --run-live, runs without the guard.

    Never in a run that a guarded process started: the guard is locked on there.
    """
    return (
        not _GUARD_STATE["locked"]
        and bool(item.config.getoption("--run-live"))
        and _area(item) == "live"
        and item.get_closest_marker("live") is not None
    )


def _set_guard(*, active: bool) -> None:
    _netguard.set_active(active)  # a locked guard stays on
    os.environ[_netguard.ENV_VAR] = _netguard.describe()  # inherited by Python children


@pytest.hookimpl(wrapper=True)
def pytest_runtest_protocol(
    item: pytest.Item, nextitem: pytest.Item | None
) -> Generator[None, object, object]:
    """Lift the guard around a live test's setup, call and teardown; restore it afterwards."""
    if not _may_leave_loopback(item):
        return (yield)
    _set_guard(active=False)
    try:
        return (yield)
    finally:
        _set_guard(active=True)


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: pytest.CallInfo[None]
) -> Generator[None, pytest.TestReport, pytest.TestReport]:
    report = yield
    _hide_secrets(report)
    return report


@pytest.hookimpl(wrapper=True)
def pytest_make_collect_report(
    collector: pytest.Collector,
) -> Generator[None, pytest.CollectReport, pytest.CollectReport]:
    report = yield
    _hide_secrets(report)
    return report


def cpu_limit(seconds: float) -> float:
    """A CPU-time limit for a lock-in, allowing for coverage: ``scripts/gate.sh`` measures it, and
    line tracing makes CPU-bound code 4-6 times slower (measured on two lock-ins). Under coverage
    the limit is 8 times larger; a real regression still takes minutes."""
    try:
        import coverage
    except ImportError:  # pragma: no cover - a dev dependency
        return seconds
    return seconds * 8 if coverage.Coverage.current() is not None else seconds


@pytest.fixture(autouse=True)
def _no_siem_key_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Environment beats .env: no test reads the real ``argus_reader`` key from .env. A test
    that needs a key (es-local, live) sets its own."""
    monkeypatch.setenv("ARGUS_SIEM__API_KEY", "")


def local_asset_map() -> Path:
    """This checkout's own asset map, which tests that check a real map read when it is there:
    ``assets.map_path`` of config/local.yaml (D-294), else of config/argus.yaml, else the
    default. Read as text: loading the settings would activate their site."""
    import yaml

    from argus.config.settings import AssetsSettings

    for name in ("local.yaml", "argus.yaml"):
        path = REPO_ROOT / "config" / name
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
        assets = data.get("assets") if isinstance(data, dict) else None
        if isinstance(assets, dict) and assets.get("map_path"):
            return REPO_ROOT / str(assets["map_path"])
    return REPO_ROOT / AssetsSettings().map_path


# The suite's made-up site (D-292): tests/fixtures/site.yaml.
TEST_SITE_FILE = TESTS_DIR / "fixtures" / "site.yaml"


def suite_checkout(directory: Path) -> Path:
    """``directory`` laid out as a checkout of the suite's installation: config/argus.yaml (the
    shipped one) with the suite's site.yaml and local.yaml beside it (tests/fixtures). The tests
    of a whole checkout (a CLI run from its folder) run there, in the private repository and the
    public one alike, never on this checkout's own config/site.yaml or local.yaml."""
    config = directory / "config"
    config.mkdir(parents=True, exist_ok=True)
    shipped = (REPO_ROOT / "config" / "argus.yaml").read_text(encoding="utf-8")
    (config / "argus.yaml").write_text(shipped, encoding="utf-8")
    for name in ("site.yaml", "local.yaml"):
        text = (TESTS_DIR / "fixtures" / name).read_text(encoding="utf-8")
        (config / name).write_text(text, encoding="utf-8")
    return directory


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def plain(text: str) -> str:
    """``text`` without terminal styling: typer colours its help when it thinks it may (on
    GitHub Actions, or with FORCE_COLOR), which splits an option name with escape codes."""
    return _ANSI.sub("", text)


def env_copy(directory: Path, *, without: frozenset[str]) -> Path:
    """``directory`` holding a copy of this checkout's .env (the database's passwords) without
    the named keys: a CLI run from there sees the developer's database, not values an
    installation added (``argus init`` writes the web's own password, Q-A2)."""
    source = REPO_ROOT / ".env"
    lines = source.read_text(encoding="utf-8").splitlines() if source.is_file() else []
    kept = [
        line
        for line in lines
        if line.partition("=")[0].strip().removeprefix("export ") not in without
    ]
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / ".env"
    target.write_text("\n".join(kept) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return directory


def suite_config() -> Path:
    """The config file of a fresh ``suite_checkout`` in a temporary folder: for an ``argus``
    process a test starts from this checkout's folder (for its .env), as ARGUS_CONFIG."""
    import tempfile

    return suite_checkout(Path(tempfile.mkdtemp(prefix="argus-suite-"))) / "config" / "argus.yaml"


def shipped_config_on_the_suites_site(directory: Path) -> Path:
    """The config file of ``suite_checkout(directory)``: the shipped config/argus.yaml on the
    suite's site."""
    return suite_checkout(directory) / "config" / "argus.yaml"


@functools.cache
def example_site() -> Any:
    """The suite's site: "Example University" (ACME), made up and complete
    (``tests/fixtures/site.yaml``, D-292). Every test runs on it, in the private repository and
    the public one alike; the neutral defaults have their own tests (tests/unit/site), and a real
    site's pins live beside its pack (tests/site_acme, private)."""
    import yaml

    from argus.site import SiteSettings

    if (
        not TEST_SITE_FILE.exists()
    ):  # a copied harness (tests/_guard) carries none: the neutral site
        return SiteSettings()
    data = yaml.safe_load(TEST_SITE_FILE.read_text(encoding="utf-8"))
    return SiteSettings.model_validate(data["site"])


def _activate_the_suites_site() -> None:
    from argus import site

    site.activate(example_site())


def pytest_sessionstart(session: pytest.Session) -> None:
    """The suite's site is the process's from the start, also while test modules are collected
    (some build ``Targets()`` or a capability map's targets at import)."""
    _activate_the_suites_site()


# ... and already while the conftest files of the paths a run names are loaded, which happens
# before the session starts (tests/kibana's loads the tier's seed, which reads the site).
_activate_the_suites_site()


@pytest.fixture(autouse=True)
def _site_is_the_suites() -> Iterator[None]:
    """Every test starts on the suite's site profile and leaves the process's as it found it (a
    test that calls ``load_settings`` activates the site of the file it loads)."""
    from argus import site

    with site.using(example_site()):
        yield
