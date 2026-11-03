"""The Hypothesis profiles of the suite: dev (the default), ci and gate, chosen with the
HYPOTHESIS_PROFILE variable (docs/phase-1-pipeline.md §10; scripts/gate.sh runs the gate profile).

The child runs here start pytest on a probe of trivial property tests; they use no network and no
database.
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import hypothesis
import pytest

import tests.conftest as harness

_HYPOTHESIS_DEFAULT_DEADLINE = timedelta(milliseconds=200)


@pytest.mark.parametrize(
    ("name", "max_examples", "deadline"),
    [
        ("dev", 100, _HYPOTHESIS_DEFAULT_DEADLINE),
        ("ci", 1_000, _HYPOTHESIS_DEFAULT_DEADLINE),
        ("gate", 10_000, None),
    ],
)
def test_the_profiles_have_the_planned_sizes(
    name: str, max_examples: int, deadline: timedelta | None
) -> None:
    profile = hypothesis.settings.get_profile(name)
    assert profile.max_examples == max_examples
    assert profile.deadline == deadline
    assert profile.derandomize is False  # not Hypothesis's own CI profile, whatever the machine


@pytest.mark.parametrize(
    ("environ", "name"),
    [
        ({}, "dev"),
        ({"HYPOTHESIS_PROFILE": ""}, "dev"),
        ({"HYPOTHESIS_PROFILE": "dev"}, "dev"),
        ({"HYPOTHESIS_PROFILE": "ci"}, "ci"),
        ({"HYPOTHESIS_PROFILE": "gate"}, "gate"),
    ],
)
def test_the_variable_names_the_profile(environ: dict[str, str], name: str) -> None:
    assert harness.hypothesis_profile(environ) == name


@pytest.mark.parametrize("name", ["Gate", "gate ", "default", "fuzz", "10000"])
def test_any_other_profile_name_is_a_usage_error(name: str) -> None:
    """Hypothesis's own profiles included: a typo must not quietly run 100 examples."""
    with pytest.raises(pytest.UsageError, match=r"use one of: dev, ci, gate$"):
        harness.hypothesis_profile({"HYPOTHESIS_PROFILE": name})


def test_this_run_uses_the_profile_its_environment_names(pytestconfig: pytest.Config) -> None:
    """Compared by its settings: --hypothesis-verbosity loads a copy under another name."""
    if pytestconfig.getoption("hypothesis_profile", None):
        pytest.skip("--hypothesis-profile chose the profile of this run")
    profile = hypothesis.settings.get_profile(os.environ.get("HYPOTHESIS_PROFILE") or "dev")
    current = hypothesis.settings.default
    assert current is not None
    assert current.max_examples == profile.max_examples
    assert current.deadline == profile.deadline


def test_a_nested_run_gives_back_the_profile_it_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """A run nested in this process (pytest.main() in a test) loads the profile its environment
    names; when it ends, the run around it has its own profile again."""
    enclosing = hypothesis.settings.get_current_profile_name()
    nested_profile = "ci" if enclosing == "gate" else "gate"
    monkeypatch.setenv(harness.HYPOTHESIS_PROFILE_VARIABLE, nested_profile)
    nested = SimpleNamespace(stash=pytest.Stash(), getoption=lambda name, default=None: default)
    harness.pytest_configure(cast(pytest.Config, nested))
    try:
        assert hypothesis.settings.get_current_profile_name() == nested_profile
    finally:
        harness.pytest_unconfigure(cast(pytest.Config, nested))
    assert hypothesis.settings.get_current_profile_name() == enclosing


_PROFILE_PROBE = """
import os

from hypothesis import given, settings, strategies as st

CALLS = []


@settings(deadline=None)  # a test's own settings keep the profile's number of examples
@given(st.integers())
def test_examples(number: int) -> None:
    CALLS.append(number)


def test_examples_ran() -> None:
    assert len(CALLS) == settings.default.max_examples


def test_profile() -> None:
    assert settings.get_current_profile_name() == os.environ["PROBE_PROFILE"]
    assert settings.default.max_examples == int(os.environ["PROBE_MAX_EXAMPLES"])
"""

_PROBE_INI = """\
[pytest]
asyncio_mode = auto
asyncio_default_fixture_loop_scope = function
"""


def _run_probe(
    tmp_path: Path,
    variable: str | None,
    *args: str,
    profile: str,
    max_examples: int,
    tests: str = "test_profile_probe.py",
) -> subprocess.CompletedProcess[str]:
    """pytest with this harness on ``tests`` of the probe, HYPOTHESIS_PROFILE set to ``variable``
    (None: not set); the probe expects ``profile`` with ``max_examples``."""
    (tmp_path / "test_profile_probe.py").write_text(_PROFILE_PROBE, encoding="utf-8")
    (tmp_path / "pytest.ini").write_text(_PROBE_INI, encoding="utf-8")
    dropped = ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", harness.HYPOTHESIS_PROFILE_VARIABLE)
    env = {name: value for name, value in os.environ.items() if name not in dropped}
    paths = (str(harness.REPO_ROOT), env.get("PYTHONPATH", ""))
    env["PYTHONPATH"] = os.pathsep.join(filter(None, paths))
    env.update(PROBE_PROFILE=profile, PROBE_MAX_EXAMPLES=str(max_examples))
    if variable is not None:
        env[harness.HYPOTHESIS_PROFILE_VARIABLE] = variable
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    return subprocess.run(  # noqa: S603 - this interpreter's pytest on a local probe
        [*command, "-p", "tests.conftest", *args, tests],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def test_a_run_uses_dev_unless_told_otherwise(tmp_path: Path) -> None:
    """The probe counts the examples a test with settings of its own runs."""
    completed = _run_probe(tmp_path, None, profile="dev", max_examples=100)
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "3 passed" in completed.stdout


def test_the_variable_loads_the_gate_profile(tmp_path: Path) -> None:
    """Only the settings are checked: running 10,000 examples takes several seconds."""
    completed = _run_probe(
        tmp_path,
        "gate",
        profile="gate",
        max_examples=10_000,
        tests="test_profile_probe.py::test_profile",
    )
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "1 passed" in completed.stdout


def test_the_hypothesis_profile_option_overrides_the_variable(tmp_path: Path) -> None:
    completed = _run_probe(
        tmp_path, "gate", "--hypothesis-profile=ci", profile="ci", max_examples=1_000
    )
    assert completed.returncode == 0, completed.stdout[-2000:]
    assert "3 passed" in completed.stdout


def test_an_unknown_profile_stops_the_run_before_any_test(tmp_path: Path) -> None:
    completed = _run_probe(tmp_path, "gtae", profile="gtae", max_examples=0)
    assert completed.returncode == pytest.ExitCode.USAGE_ERROR, completed.stdout[-2000:]
    message = "HYPOTHESIS_PROFILE='gtae' is not a Hypothesis profile of this suite"
    assert f"ERROR: {message}; use one of: dev, ci, gate" in completed.stderr
    assert "passed" not in completed.stdout
