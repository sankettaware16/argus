"""Startup hook for every Python process the ARGUS test suite starts.

tests/conftest.py puts this directory first on PYTHONPATH, so a Python child (subprocess,
os.system, multiprocessing, ``uv run``, a nested pytest) imports this module at startup and gets
the same network guard as the pytest process (see argus_netguard.py). Its settings arrive in the
PYTEST_ARGUS_NETGUARD variable; without them the guard is on with the default production hosts.
A guard inherited switched on stays on for the whole process.

This module shadows the interpreter's own sitecustomize (Debian and Ubuntu ship one), so that one
runs afterwards.
"""

from __future__ import annotations

import importlib
import importlib.machinery
import importlib.util
import os
import sys

# Imported by name from this directory (first on PYTHONPATH), as the top-level module the
# pytest process also registers under "argus_netguard".
argus_netguard = importlib.import_module("argus_netguard")
argus_netguard.install_from_environment()


def _run_shadowed_sitecustomize() -> None:
    here = os.path.realpath(os.path.dirname(__file__))
    path = [entry for entry in sys.path if os.path.realpath(entry or os.curdir) != here]
    spec = importlib.machinery.PathFinder.find_spec("sitecustomize", path)
    if spec is None or spec.loader is None:
        return
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)


_run_shadowed_sitecustomize()
