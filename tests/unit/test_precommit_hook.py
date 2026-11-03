"""The pre-commit hook's credential-shape check (scripts/hooks/pre-commit).

Every credential below is synthetic; lines that hold a literal one are marked fake-secret, the
way the hook requires of test data.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
from types import ModuleType

import pytest

from tests.conftest import REPO_ROOT


def _hook() -> ModuleType:
    path = REPO_ROOT / "scripts" / "hooks" / "pre-commit"
    loader = importlib.machinery.SourceFileLoader("argus_pre_commit_hook", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


HOOK = _hook()
MARK = "fake" + "-secret"  # spelt apart so these lines need no marker themselves


@pytest.mark.parametrize(
    "line",
    [
        'dsn = "postgresql://argus:" + "Hunter2x@db/argus"'.replace('" + "', ""),
        "https://elastic:" + "pa55w0rd" + "@10.0.0.1:9200",
        "-----BEGIN " + "PRIVATE KEY-----",
        "key = 'gsk_" + "A" * 24 + "'",
    ],
    ids=["dsn-literal", "url-literal", "pem", "groq"],
)
def test_literal_credentials_are_refused(line: str) -> None:
    assert HOOK.line_problems(line)


@pytest.mark.parametrize(
    "line",
    [
        'url = f"postgresql://argus:{SECRET}@db/argus"',
        'expected = f"https://u:{MASK}@host?email=a@b.org"',
        "masked = 'https://u:***@h:9200'",
        """'{"url":"http://h:9200","to":"a@b"}'""",
        'url = f"https://elastic:{settings.password}@h:9200"',
    ],
    ids=["f-string-field", "mask-field", "mask", "json-boundary", "dotted-field"],
)
def test_placeholders_and_string_boundaries_are_not_literal_passwords(line: str) -> None:
    assert HOOK.line_problems(line) == []


def test_a_marked_line_is_synthetic_test_data() -> None:
    line = "https://elastic:" + "pa55w0rd" + "@10.0.0.1:9200"
    assert HOOK.line_problems(line)
    assert HOOK.line_problems(f"{line}  # {MARK}") == []


def test_a_placeholder_with_literal_text_around_it_is_still_refused() -> None:
    line = 'url = f"https://elastic:a{char}{UNREG}@h:9200"'  # fake-secret
    assert HOOK.line_problems(line)
