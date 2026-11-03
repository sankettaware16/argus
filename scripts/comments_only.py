#!/usr/bin/env python3
"""Prove that a change touched comments and docstrings only.

    uv run python scripts/comments_only.py [BASE] [--help-texts]   # BASE: a git ref, default HEAD

For every Python file changed since BASE, the syntax tree with docstrings removed must equal the
one at BASE; for every YAML file, the loaded data must be equal. Exit 1, naming the files, when
anything else changed. A new or deleted file counts as a change. With ``--help-texts`` the
string given as ``help=`` to a call (a command-line option's help) may change too.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import yaml


def _bare_string(statement: ast.stmt) -> bool:
    """A string standing alone as a statement: a docstring, or an attribute's docstring under
    a field. It has no effect at run time."""
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    )


def _without_docstrings(source: str, help_texts: bool = False) -> str:
    tree = ast.parse(source)
    if help_texts:
        for call in ast.walk(tree):
            if isinstance(call, ast.Call):
                for keyword in call.keywords:
                    if keyword.arg == "help":
                        keyword.value = ast.Constant("")
    for node in ast.walk(tree):
        for name in ("body", "orelse", "finalbody"):
            body = getattr(node, name, None)
            if isinstance(body, list) and body and isinstance(body[0], ast.stmt):
                kept = [s for s in body if not _bare_string(s)]
                setattr(node, name, kept or [ast.Pass()])
    return ast.dump(tree, include_attributes=False)


def main() -> int:
    args = [a for a in sys.argv[1:] if a != "--help-texts"]
    help_texts = "--help-texts" in sys.argv[1:]
    base = args[0] if args else "HEAD"
    changed = subprocess.run(  # noqa: S603 - git with fixed arguments
        ["git", "diff", "--name-status", base],  # noqa: S607
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    bad: list[str] = []
    checked = 0
    for line in changed:
        status, _, path = line.partition("\t")
        if not path.endswith((".py", ".yaml", ".yml")) and Path(path).name != "pre-commit":
            continue
        if status != "M":
            bad.append(f"{path}: {status} (only modified files are allowed)")
            continue
        before = subprocess.run(  # noqa: S603 - git with fixed arguments
            ["git", "show", f"{base}:{path}"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        after = Path(path).read_text(encoding="utf-8")
        checked += 1
        try:
            if path.endswith((".yaml", ".yml")):
                same = yaml.safe_load(before) == yaml.safe_load(after)
            else:
                same = _without_docstrings(before, help_texts) == _without_docstrings(
                    after, help_texts
                )
        except (SyntaxError, yaml.YAMLError) as exc:
            bad.append(f"{path}: does not parse ({exc})")
            continue
        if not same:
            bad.append(f"{path}: more than comments and docstrings changed")
    for problem in bad:
        print(problem)
    print(f"comments_only: {checked} files checked, {len(bad)} problem(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
