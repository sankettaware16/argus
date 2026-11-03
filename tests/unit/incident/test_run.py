"""The pass's small pure parts (AR7): what a case's check stores, the settings the query links are
built from, and how a failure is worded (one redacted line)."""

from __future__ import annotations

from datetime import timedelta

import pytest

from argus.config.settings import Settings
from argus.incident import gather, run, scene
from argus.incident import model as m
from argus.incident.build import Context
from tests.unit.incident import kit

pytestmark = pytest.mark.unit


def test_the_check_key_changes_with_the_evidence_the_time_and_the_writer() -> None:
    signal = gather.Signal("3|open|5,5,35", kit.at(4, 20))
    now = kit.ctx()
    base = run.key_of(signal, now)
    assert base.startswith("3|open|5,5,35|ongoing|")
    assert m.WRITER in base
    assert run.key_of(signal, kit.ctx()) == base
    later = kit.ctx(as_at=kit.at(4, 20) + timedelta(days=4))
    assert run.key_of(signal, later).split("|")[-3] == "quiet"  # nothing else changed
    assert run.key_of(gather.Signal("3|open|5,5,36", kit.at(4, 20)), now) != base
    assert "|unknown|" in run.key_of(gather.Signal("x", None), now)


def test_still_going_on_is_the_last_alert_within_the_active_days() -> None:
    ctx = Context(cfg=kit.CFG, as_at=kit.at(10), active_days=3)
    assert scene.standing(kit.at(10) - timedelta(days=3), ctx) == "ongoing"
    assert scene.standing(kit.at(10) - timedelta(days=3, seconds=1), ctx) == "quiet"
    assert scene.standing(None, ctx) == "unknown"


def test_the_query_links_come_from_the_settings() -> None:
    cfg = Settings(
        incident={
            "kibana_url": "https://kibana.example",
            "data_views": ["squid=abc-1", "dns=def_2"],
        },
        kibana={"base_path": "/kb"},
    )
    found = run.discover_config(cfg)
    assert found.app == "https://kibana.example/kb/s/acme-soc/app"  # the active (ACME) site
    assert found.views == {"squid": "abc-1", "dns": "def_2"}
    assert found.log_index("squid") == "acme-logs-squid-*"
    default = run.discover_config(Settings())
    assert default.kibana_url == "https://kibana.invalid"  # no address configured


@pytest.mark.parametrize(
    "bad",
    [["squid"], ["Squid=1"], ["squid=a b"], ["squid=1", "squid=2"], ["squid="]],
)
def test_a_data_view_setting_must_be_source_equals_id(bad: list[str]) -> None:
    with pytest.raises(ValueError, match=r"data view|given twice"):
        Settings(incident={"data_views": bad})


def test_a_failure_is_one_redacted_line() -> None:
    line = run.why(RuntimeError("boom\nwith a second line " + "x" * 500))
    assert "\n" not in line
    assert line.startswith("RuntimeError: boom with a second line")
    assert len(line) < 400
    assert run.why(ValueError("")) == "ValueError: "
