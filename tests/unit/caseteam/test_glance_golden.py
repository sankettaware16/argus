"""Golden files for the Visualiser (P4-F V2-V4): the glance comment's Markdown in its three forms
and the four Lens charts it embeds, compared byte for byte.

The Lens JSON is the form ``data/research/p4f/visualiser.md`` checked against Kibana 8.19.12's
own parser and renderer (the ``!{lens`` brace scan, ``attributes`` and ``timeRange`` passed to the
embeddable, an ad hoc data view kept on load; whether a browser draws it is the V1 canary's to
show): P4-F changes what is around the charts, never the charts. A change to either file must be
deliberate: regenerate them
(``uv run python -m tests.unit.caseteam.test_glance_golden``) and read the diff."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from argus.caseteam import lens, visual
from argus.incident import model as m
from tests.unit.caseteam import kit

pytestmark = pytest.mark.unit
GOLDEN = Path(__file__).parent / "golden"
SPACE = "acme-soc"
SCOPE = lens.Scope(
    SPACE,
    "ACME-IR-2026-1026-01",
    datetime(2026, 10, 23, 4, 30, tzinfo=UTC),
    datetime(2026, 10, 28, 0, 30, tzinfo=UTC),
)


def _thin(report: m.IncidentReport) -> m.IncidentReport:
    """The git case as a threshold rule's alerts make it: they hold the address, not the site."""
    two = (
        report.targets[0].model_copy(update={"alerts": 18}),  # the case's 22 alerts, split
        report.targets[0].model_copy(update={"value": "lab.example.edu", "alerts": 4}),
    )
    meta = report.meta.model_copy(update={"carried": ("source.ip",)})
    return report.model_copy(update={"targets": two, "targets_total": 2, "meta": meta})


def made() -> dict[str, str]:
    """Every golden file's content, by name."""
    amadey, git = kit.amadey(), kit.git()
    before = visual.Seen(1, 19, 2, 1, 0, 1, "ongoing", "Campus sites reached")
    charts = {
        "alerts_over_time": lens.alerts_over_time(SCOPE),
        "top_actors": lens.top_values(SCOPE, "Top outside addresses", "source.ip"),
        "top_targets": lens.top_values(SCOPE, "Campus sites reached", "url.domain"),
        "rules_table": lens.rules_table(SCOPE),
    }
    blocks = [lens.block(SCOPE, charts[name]) for name in sorted(charts)]  # as the JSON is
    return {
        "glance_amadey_first.md": visual.comment(amadey, SPACE, tagged=20)[0] + "\n",
        "glance_git_edited.md": visual.comment(git, SPACE, tagged=22, since=before)[0] + "\n",
        "glance_git_lists.md": visual.comment(_thin(git), SPACE, tagged=5, since=before)[0] + "\n",
        "lens_attributes.json": json.dumps(charts, indent=2, sort_keys=True) + "\n",
        "lens_blocks.txt": "\n".join(blocks) + "\n",
    }


@pytest.mark.parametrize("name", sorted(made()))
def test_the_glance_and_its_charts_are_byte_for_byte_the_golden_ones(name: str) -> None:
    want = (GOLDEN / name).read_text(encoding="utf-8")
    assert made()[name] == want, f"{name} changed: regenerate it and read the diff"


def test_the_golden_blocks_parse_as_kibana_parses_them_and_are_the_charts_of_the_json() -> None:
    from tests.unit.caseteam.test_lens import kibana_scan

    lines = (GOLDEN / "lens_blocks.txt").read_text(encoding="utf-8").splitlines()
    charts = json.loads((GOLDEN / "lens_attributes.json").read_text(encoding="utf-8"))
    parsed = [kibana_scan(line)[0] for line in lines]
    assert [p["attributes"] for p in parsed] == [charts[name] for name in sorted(charts)]
    for p, line in zip(parsed, lines, strict=True):
        assert lens.problems(line) == []
        assert p["timeRange"] == {
            "from": "2026-10-23T03:30:00.000Z",
            "to": "2026-10-28T01:30:00.000Z",
            "mode": "absolute",
        }


if __name__ == "__main__":  # regenerate: uv run python -m tests.unit.caseteam.test_glance_golden
    from argus import site
    from tests.conftest import example_site

    site.activate(example_site())
    GOLDEN.mkdir(exist_ok=True)
    for file_name, content in made().items():
        (GOLDEN / file_name).write_text(content, encoding="utf-8")
        print(f"wrote {GOLDEN / file_name}")
