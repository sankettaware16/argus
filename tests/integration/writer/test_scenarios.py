"""Q-D4's gate scenario against the writable fake: every class with hostile values (the same
scenario runs against the local Kibana tier in ``tests/kibana/test_writer.py``)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.integration.cases.conftest import Person
from tests.integration.writer import scenarios
from tests.integration.writer.fake import INDEX, WritableKibana
from tests.integration.writer.kit import LINK_BASE, rig

pytestmark = pytest.mark.integration


@dataclass
class FakeView:
    k: WritableKibana

    def case(self, kibana_id: str) -> dict[str, Any]:
        return self.k.cases[kibana_id]

    def comments(self, kibana_id: str) -> list[str]:
        return [c["comment"] for c in self.k.comments.get(kibana_id, [])]

    def alert_case_ids(self, alert_id: str) -> list[str]:
        return list(self.k.alerts[alert_id]["kibana.alert.case_ids"])

    def add_tag(self, kibana_id: str, tag: str) -> None:
        self.k.cases[kibana_id]["tags"].append(tag)

    def attach_actions(self, kibana_id: str) -> int:
        return sum(
            1
            for a in self.k.actions[kibana_id]
            if a["type"] == "comment" and a["payload"]["comment"].get("type") == "alert"
        )


async def test_every_class_with_hostile_values_leaves_inert_text_in_kibana(
    api_engine: AsyncEngine, migrated_engine: AsyncEngine, writer_engine: AsyncEngine,
    people: dict[str, Person],
) -> None:  # fmt: skip
    pytest.importorskip("markdown_it")
    r = rig(migrated_engine, api_engine, writer_engine)
    alerts = [(f"alert-{n}", INDEX) for n in range(3)]
    done = await scenarios.every_class(
        r, api_engine, people, FakeView(r.kibana), alerts, later=r.advance
    )
    own = f"{LINK_BASE}/go/case/{done.case_id}"
    assert own in done.description
    scenarios.assert_inert(done.description, done.comments, own)
    assert len(done.comments) == 4  # the opening, "taken", "corrected" and the closing comment
    assert done.comments[-1].startswith("Closed by ARGUS on the approval of Mallory")
