"""Q-A2: tests/live exists, is skipped without --run-live, and the session it needs can be
handed to it (``argus live start`` prints a variable ARGUS does not refuse)."""

from __future__ import annotations

import subprocess
import sys

import pytest

from argus.config.settings import Settings
from argus.config.sources import environment_layer
from tests.conftest import PUBLIC_TREE, REPO_ROOT

if PUBLIC_TREE and not (REPO_ROOT / "tests" / "live").is_dir():
    pytest.skip("tests/live is private (not in the public tree)", allow_module_level=True)

from tests.live import conftest as live

pytestmark = pytest.mark.unit


def test_the_live_tests_are_collected_and_skipped_without_run_live() -> None:
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/live", "-rs"],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300, check=False,
    )  # fmt: skip
    assert done.returncode == 0, done.stdout + done.stderr
    assert "3 skipped" in done.stdout
    assert "run with --run-live" in done.stdout


def test_every_live_test_is_marked_live() -> None:
    for path in (REPO_ROOT / "tests" / "live").glob("test_*.py"):
        assert "pytestmark = pytest.mark.live" in path.read_text(), path.name


def test_the_live_session_variable_is_one_argus_accepts() -> None:
    """DEFECT (Q-A2): `argus live start` told the person to export ARGUS_LIVE_SESSION, which
    ARGUS refuses as an unknown setting: every argus command, and the live tests, then failed."""
    refused = environment_layer({"ARGUS_LIVE_SESSION": "abc"}, Settings)
    assert refused.problems
    accepted = environment_layer({live.SESSION_VARIABLE: "abc"}, Settings)
    assert accepted.problems == []
    cli = (REPO_ROOT / "src" / "argus" / "gateway" / "cli.py").read_text()
    assert f'typer.echo(f"export {live.SESSION_VARIABLE}={{session_id}}")' in cli
