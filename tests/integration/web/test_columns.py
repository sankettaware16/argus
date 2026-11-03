"""R15 additions (the user's request, 2026-10-13): reviewers choose which alert fields the
alerts table shows, kept per rule in their browser; missing-alert warnings grouped; related
investigations named."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.web import queries
from argus.web.app import _columns_cookie
from tests.integration.grouping.test_grouping import doc, ingest
from tests.integration.web.conftest import NOW, PASSWORD, first_investigation

pytestmark = pytest.mark.integration


def headers(page: str) -> list[str]:
    head = page.split("<thead>", 1)[1].split("</thead>", 1)[0]
    return [re.sub(r"<[^>]+>", "", h).strip() for h in re.findall(r"<th[^>]*>.*?</th>", head)]


async def logged_in(client: httpx.AsyncClient) -> dict[str, object]:
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    return await first_investigation(client)


async def test_chosen_columns_show_and_are_kept_for_the_rule(client: httpx.AsyncClient) -> None:
    inv = await logged_in(client)
    url = f"/investigations/{inv['id']}"
    plain = (await client.get(url)).text
    assert headers(plain) == ["Event time", "Entities", "Kibana status", "Raw"]
    assert "source.ip" in plain.split("Choose columns", 1)[1]  # offered, with its count
    chosen = await client.get(url, params=[("columns", "set"), ("cols", "source.ip"),
                                           ("cols", "kibana.alert.rule.name")])  # fmt: skip
    assert headers(chosen.text) == [
        "Event time", "source.ip", "kibana.alert.rule.name", "Entities", "Kibana status", "Raw",
    ]  # fmt: skip
    ip = inv["key"][0][1] if inv.get("key") else None  # type: ignore[index]
    if ip:
        assert f'<td class="mono">{ip}</td>' in chosen.text
    cookie = _columns_cookie(str(inv["rule_id"]))
    assert client.cookies.get(cookie) is not None
    again = (await client.get(url)).text  # no parameters: the remembered choice
    assert headers(again)[1:3] == ["source.ip", "kibana.alert.rule.name"]
    cleared = await client.get(url, params={"columns": "set"})
    assert headers(cleared.text) == ["Event time", "Entities", "Kibana status", "Raw"]
    assert headers((await client.get(url)).text) == ["Event time", "Entities", "Kibana status",
                                                      "Raw"]  # fmt: skip


@pytest.mark.parametrize(
    "bad", ["no.such.field", "source.ip;x", "<script>", "a" * 200, "source.ip\x00"]
)
async def test_unknown_or_odd_columns_are_ignored(client: httpx.AsyncClient, bad: str) -> None:
    inv = await logged_in(client)
    page = await client.get(f"/investigations/{inv['id']}",
                            params=[("columns", "set"), ("cols", bad)])  # fmt: skip
    assert page.status_code == 200
    assert headers(page.text) == ["Event time", "Entities", "Kibana status", "Raw"]


async def test_at_most_twelve_columns(client: httpx.AsyncClient, seeded: AsyncEngine) -> None:
    inv = await logged_in(client)
    async with seeded.connect() as conn:
        fields = [f for f, _ in await queries.alert_fields(conn, inv["id"])]  # type: ignore[arg-type]
    assert len(fields) > queries.MAX_COLUMNS
    params = [("columns", "set"), *(("cols", f) for f in fields)]
    page = await client.get(f"/investigations/{inv['id']}", params=params)
    assert len(headers(page.text)) == queries.MAX_COLUMNS + 4
    assert fields.index("kibana.alert.uuid") > fields.index("source.ip")  # bookkeeping last


async def test_hostile_field_names_and_values_are_inert(
    client: httpx.AsyncClient, seeded: AsyncEngine
) -> None:
    bad = doc(950, "rule-h", "10.9.9.8", NOW - timedelta(minutes=3))
    bad["_source"]["http"] = {"response": {"status_code": '<img src=x onerror="alert(1)">'}}
    bad["_source"]["<b>odd</b>"] = "x"
    await ingest(seeded, [bad])
    await client.post("/login", data={"username": "asha", "password": PASSWORD})
    (inv,) = (await client.get("/api/investigations", params={"view": "all", "rule": "rule-h"})
              ).json()  # fmt: skip
    params = [("columns", "set"), ("cols", "http.response.status_code")]
    page = await client.get(f"/investigations/{inv['id']}", params=params)
    assert "<img src=x" not in page.text
    assert "<b>odd</b>" not in page.text
    assert "http.response.status_code" in headers(page.text)


def test_runs_at_the_limit_are_one_warning_and_reasons_read_plainly() -> None:
    t = datetime(2026, 10, 13, 0, 16, tzinfo=UTC)
    runs = [{"kind": "truncated_execution", "start_at": t + timedelta(hours=h),
             "end_at": t + timedelta(hours=h), "detail": "100 alerts, the rule's limit is 100"}
            for h in range(9)]  # fmt: skip
    lag = {"kind": "argus_collector_lag", "start_at": t, "end_at": t + timedelta(hours=7),
           "detail": "deadline_passed"}  # fmt: skip
    got = queries.banners([lag, *runs])
    assert [g["kind"] for g in got] == ["argus_collector_lag", "truncated_execution"]
    assert got[0]["text"] == "ARGUS was not collecting (a request ran out of time)"
    assert got[1]["text"] == (
        "the rule hit its alert limit in 9 runs: more alerts may exist for those runs"
    )
    assert (got[1]["start_at"], got[1]["end_at"]) == (t, t + timedelta(hours=8))
    assert len(got[1]["runs"]) == 9
    (one,) = queries.banners(runs[:1])
    assert one["text"] == (
        "the rule hit its alert limit in 1 run (100 alerts, the rule's limit is 100): more"
        " alerts may exist for those runs"
    )
    odd = queries.banners([{**lag, "kind": "new_kind", "detail": "some_code"}])
    assert odd[0]["text"] == "new kind (some code)"
    assert queries.banners([]) == []
