"""Sign-in account names are personal data (AR6, D-216): no module that builds what a model reads
(the investigator, the LLM gateway and its privacy layer, the context packs, the decision engine,
the outside look-ups, the reporter, the responder) reaches the sign-in tables or the sign-in
package, and the names of the sign-in logs never appear in a log line at INFO or above."""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit
SRC = Path(__file__).resolve().parents[3] / "src" / "argus"
# what a model may read, built here: nothing in these packages knows the sign-ins
MODEL_SIDE = ("agent", "llm", "context", "outside", "reporter", "evaluation", "responder",
              "investigation", "reference", "tuning")  # fmt: skip
# the assessment package is the model's too, except the loop that schedules the sign-in pass
ASSESS_EXCEPT = {"cli.py"}
TABLES = re.compile(r"signin_sightings|signin_lookups|user_name\b")


def modules(package: str) -> list[Path]:
    root = SRC / package
    found = sorted(root.rglob("*.py"))
    return [p for p in found if not (package == "assess" and p.name in ASSESS_EXCEPT)]


def imported(path: Path) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            out.update(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            out.add(node.module)
            out.update(f"{node.module}.{a.name}" for a in node.names)
    return out


@pytest.mark.parametrize("package", [*MODEL_SIDE, "assess"])
def test_no_model_side_module_imports_the_sign_ins_or_reads_their_tables(package: str) -> None:
    files = modules(package)
    assert files, package
    for path in files:
        names = imported(path)
        assert not any(n == "argus.signins" or n.startswith("argus.signins.") for n in names), path
        text = path.read_text(encoding="utf-8")
        assert not TABLES.search(text), f"{path} names a sign-in table"


def test_the_incident_reports_prose_never_reads_the_accounts() -> None:
    """The guarded prose is given facts that have a safe form and are not read from the logs; the
    accounts are facts read from the logs with no safe form. The module does not even name them."""
    text = (SRC / "incident" / "prose.py").read_text(encoding="utf-8")
    assert "report.users" not in text
    assert ".users" not in text
    assert "argus.signins" not in text
    tree = ast.parse(text)
    assert not [
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.Attribute) and n.attr in {"users", "accounts"}
    ]


def test_the_sign_in_package_logs_counts_only() -> None:
    """Every logging call in the package is a message and counters of the pass's report: no
    sighting, name, address list or answer is ever an argument."""
    counters = {"sent", "addresses", "sightings", "incomplete", "waiting"}
    seen = 0
    for path in sorted((SRC / "signins").rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"debug", "info", "warning", "error", "exception", "critical"}
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "log"
            ):
                continue
            seen += 1
            assert isinstance(node.args[0], ast.Constant), f"{path}: the message is a constant"
            for arg in node.args[1:]:
                is_counter = (
                    isinstance(arg, ast.Attribute)
                    and isinstance(arg.value, ast.Name)
                    and arg.value.id == "report"
                    and arg.attr in counters
                )
                assert is_counter, f"{path}: {ast.unparse(node)}"
    assert seen >= 1
