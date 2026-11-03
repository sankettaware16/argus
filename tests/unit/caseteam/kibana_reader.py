"""Kibana's own Markdown reader, run as a program (tests/kibana_markdown/parse.js), so a test can
ask what Kibana would make of a text rather than what CommonMark would (D-248).

The reader is the one EUI uses for case comments: ``remark-parse@8.0.3`` under ``unified@9.2.2``
with ``remark-emoji@2.2.0``. It is not CommonMark: it looks for the end of ``**bold**`` by scanning
raw characters (a code span does not hide a ``**``), it ends a table cell at any pipe that no
backslash protects (inside a code span too), and it honours a backslash only before
``\\ ` * _ { } [ ] ( ) # + - . ! > ~ |``. Where the packages are found, in this order:
``tests/kibana_markdown/node_modules`` (``npm i --prefix tests/kibana_markdown ...``, see its
README), the directory named by ``$ARGUS_REMARK_NODE_MODULES``, a sibling OpenSearch Dashboards
checkout (its EUI carries the same pins). Where they are not, ``available()`` is False and the
differential tests skip with the reason in :data:`SKIP_REASON`.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
HARNESS = HERE.parents[1] / "kibana_markdown" / "parse.js"
PINS = {"remark-parse": "8.0.3", "unified": "9.2.2", "remark-emoji": "2.2.0"}
HOW = (
    "Kibana's Markdown reader is not installed here: run `npm i --prefix tests/kibana_markdown"
    " remark-parse@8.0.3 unified@9.2.2 remark-emoji@2.2.0` (needs network), or set"
    " ARGUS_REMARK_NODE_MODULES to a node_modules directory that holds those versions"
)
# what a text of ARGUS's must not make more of than its baseline does (a link or an image is a
# click or a beacon, a reference or a definition is a link made another way, html and a heading, a
# list or a quote are structure a value could open, bold/emphasis/strike are what a value could cut)
WATCH = (
    "link",
    "image",
    "linkReference",
    "imageReference",
    "definition",
    "footnoteDefinition",
    "footnoteReference",
    "html",
    "heading",
    "list",
    "blockquote",
    "thematicBreak",
    "strong",
    "emphasis",
    "delete",
)
NEVER = ("image", "linkReference", "imageReference", "definition", "html", "blockquote")


def _holds_the_pins(directory: Path) -> bool:
    for name, version in PINS.items():
        try:
            found = json.loads((directory / name / "package.json").read_text())["version"]
        except (OSError, ValueError, KeyError):
            return False
        if found != version:
            return False
    return True


def modules() -> Path | None:
    """The node_modules directory that holds the three packages at their pinned versions."""
    named = os.environ.get("ARGUS_REMARK_NODE_MODULES")
    for directory in (
        HARNESS.parent / "node_modules",
        Path(named) if named else None,
        Path("/home/dev/code/OpenSearch-Dashboards/node_modules"),
    ):
        if directory is not None and _holds_the_pins(directory):
            return directory
    return None


def available() -> bool:
    return shutil.which("node") is not None and modules() is not None and HARNESS.is_file()


SKIP_REASON = HOW if shutil.which("node") is not None else "node is not installed: " + HOW


@dataclass(frozen=True)
class Read:
    """What Kibana's reader made of one text."""

    nodes: dict[str, int]
    tables: list[list[int]] = field(default_factory=list)  # cells in each row of each table
    urls: list[str] = field(default_factory=list)  # link and image targets

    def count(self, kind: str) -> int:
        return self.nodes.get(kind, 0)

    def beyond(self, baseline: Read) -> dict[str, int]:
        """The watched kinds this text has more of than ``baseline``."""
        return {
            k: self.count(k) - baseline.count(k) for k in WATCH if self.count(k) > baseline.count(k)
        }

    def ragged(self) -> list[list[int]]:
        """The tables whose rows differ in their number of cells."""
        return [rows for rows in self.tables if len(set(rows)) > 1]


def without_charts(text: str) -> str:
    """The text with each embedded chart (``!{lens{...}}``, a line of its own) replaced by a word.
    Kibana's cases plugin reads those blocks before the Markdown reader sees them (AR10 checks
    them with its own scanner, D-251); the plain reader would take their JSON brackets for
    references."""
    return "\n".join("(chart)" if ln.startswith("!{lens") else ln for ln in text.split("\n"))


def read(texts: Sequence[str]) -> list[Read]:
    """Kibana's reading of each text (one run of node for all of them)."""
    directory = modules()
    assert directory is not None, HOW
    done = subprocess.run(  # noqa: S603 - a fixed program and a fixed script
        [shutil.which("node") or "node", str(HARNESS), str(directory)],
        input=json.dumps([without_charts(t) for t in texts]),
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert done.returncode == 0, done.stderr[:2000]
    found: list[dict[str, Any]] = json.loads(done.stdout)
    return [Read(f["nodes"], f["tables"], f["urls"]) for f in found]
