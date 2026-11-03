"""The property tests in this directory take their example count from the Hypothesis profile.

tests/conftest.py selects a profile with HYPOTHESIS_PROFILE (dev, ci, gate). A hardcoded
``@settings(max_examples=...)`` would override it, so a gate run would try no more examples
than a quick local run. Other settings (``deadline``, health checks) are fine.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import TypeGuard

import pytest

_TEST_FILES = sorted(Path(__file__).resolve().parent.glob("test_*.py"))


def _is_settings_call(node: ast.AST) -> TypeGuard[ast.Call]:
    if not isinstance(node, ast.Call):
        return False
    function = node.func
    return (isinstance(function, ast.Name) and function.id == "settings") or (
        isinstance(function, ast.Attribute) and function.attr == "settings"
    )


@pytest.mark.parametrize("path", _TEST_FILES, ids=[path.name for path in _TEST_FILES])
def test_no_property_test_hardcodes_its_example_count(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hardcoded = [
        node.lineno
        for node in ast.walk(tree)
        if _is_settings_call(node)
        and any(keyword.arg == "max_examples" for keyword in node.keywords)
    ]
    assert hardcoded == [], f"{path.name}: max_examples set on line(s) {hardcoded}"
