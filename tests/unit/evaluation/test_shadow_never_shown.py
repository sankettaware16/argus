"""Shadow output is never shown (plan §3 rule 12, Q-G2): no part of the web (pages, the API,
templates, scripts) reads the shadow store or imports its code, now or in /api/v1 and the
frontend once they exist; the web's database role has no grant on it (API_GRANTS, checked
table by table by doctor); only the evaluation commands read it, and they print counts."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from argus.db import roles

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parents[3]
WEB = [ROOT / "src" / "argus" / "web", ROOT / "frontend" / "src", ROOT / "src" / "argus" / "api"]
FORBIDDEN = ("llm_shadow", "LlmShadow", "argus.evaluation.shadow", "evaluation import shadow")


def web_files() -> list[Path]:
    files = []
    for folder in WEB:
        if folder.is_dir():
            files += [p for p in folder.rglob("*") if p.is_file() and p.suffix in
                      {".py", ".html", ".js", ".ts", ".tsx", ".json", ".css"}]  # fmt: skip
    return files


def test_no_web_file_names_the_shadow() -> None:
    files = web_files()
    assert files  # the web exists: the scan is not empty
    texts = {p: p.read_text(encoding="utf-8", errors="replace") for p in files}
    found = [f"{p.relative_to(ROOT)}: {w}" for p, t in texts.items() for w in FORBIDDEN if w in t]
    assert found == []


def test_no_web_module_imports_the_evaluation_code() -> None:
    for path in (p for p in web_files() if p.suffix == ".py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module, *(f"{node.module}.{a.name}" for a in node.names)]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            assert not any(n.startswith("argus.evaluation.shadow") for n in names), path
            assert not any(n == "argus.evaluation.measures" for n in names), path


def test_the_webs_role_has_no_grant_on_the_shadow() -> None:
    assert "llm_shadow" not in roles.API_GRANTS
    grant = roles.RUNTIME_GRANTS["llm_shadow"]
    assert (grant.select, grant.update, grant.delete) == (True, (), False)
    assert {"id", "at"}.isdisjoint(grant.insert)  # the database fills them in


def test_the_shadow_code_reads_counts_only_for_the_ladder() -> None:
    """The measure selects counts and timings, never the answer column."""
    from argus.evaluation import shadow

    assert "answer" not in shadow._MEASURE
    assert "answer" not in shadow._LATENCY
