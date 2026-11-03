"""Record/replay cassettes: strict replay, keys that ignore only the deadline's timeout."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from argus.gateway.builtin import AlertIds, AlertIdsParams
from argus.gateway.cassettes import CassetteMissError, CassetteTransport, cassette_key
from argus.gateway.templates import Purpose
from argus.gateway.transport import WireRequest
from tests.unit.gateway.fakes import T0, FakeTransport, make, search_answer

pytestmark = pytest.mark.unit


def request(**kw: object) -> WireRequest:
    base: dict[str, object] = {
        "method": "POST",
        "path": "/i/_search",
        "params": (("a", "1"), ("b", "2")),
        "body": json.dumps({"size": 1, "timeout": "10s"}).encode(),
        "opaque_id": "argus-collector/alerts.ids@1",
        "timeout_s": 10.0,
    }
    base.update(kw)
    return WireRequest(**base)  # type: ignore[arg-type]


def test_keys() -> None:
    key = cassette_key(request())
    assert key == cassette_key(request(body=json.dumps({"timeout": "3s", "size": 1}).encode()))
    assert key == cassette_key(request(params=(("b", "2"), ("a", "1"))))
    assert key == cassette_key(request(opaque_id="argus-other/alerts.ids@1", timeout_s=1.0))
    for change in (
        {"opaque_id": "argus-collector/alerts.ids@2"},
        {"method": "GET"},
        {"path": "/j/_search"},
        {"params": (("a", "1"),)},
        {"body": json.dumps({"size": 2}).encode()},
        {"body": None},
    ):
        assert cassette_key(request(**change)) != key, change
    assert cassette_key(request(body=b"[1]")) != cassette_key(request(body=b"[2]"))


async def test_record_then_replay(tmp_path: Path) -> None:
    path = tmp_path / "c" / "alerts.json"
    inner = FakeTransport(default=search_answer(took=9))
    recorder = CassetteTransport(path, "record", inner)
    response = await recorder.send(request())
    assert response.status == 200
    assert len(inner.calls) == 1
    recorder.save()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) & 0o077 == 0
    player = CassetteTransport(path)
    replayed = await player.send(request(body=json.dumps({"size": 1, "timeout": "2s"}).encode()))
    assert (replayed.status, json.loads(replayed.body)) == (200, search_answer(took=9))
    with pytest.raises(CassetteMissError, match=r"alerts.ids@1: no recorded answer"):
        await player.send(request(path="/other/_search"))
    player.save()  # replay never writes
    assert list(path.parent.iterdir()) == [path]


async def test_strictness_and_errors(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        CassetteTransport(tmp_path / "missing.json")
    with pytest.raises(ValueError, match="needs a transport"):
        CassetteTransport(tmp_path / "x.json", "record")
    bad = tmp_path / "old.json"
    bad.write_text(json.dumps({"format": 0, "entries": {}}))
    with pytest.raises(ValueError, match="format 0 is not 1"):
        CassetteTransport(bad)
    recorder = CassetteTransport(tmp_path / "n.json", "record", FakeTransport())
    recorder.save()  # nothing recorded: nothing written
    assert not (tmp_path / "n.json").exists()


async def test_the_gateway_runs_on_a_cassette(tmp_path: Path) -> None:
    path = tmp_path / "ids.json"
    params = AlertIdsParams(start=T0.replace(hour=11), end=T0)
    recorder = CassetteTransport(path, "record", FakeTransport(default=search_answer(took=4)))
    gateway, _, _store, clock = make()
    gateway.transport = recorder
    deadline = clock.now.replace(minute=1)
    await gateway.run(AlertIds(), params, purpose=Purpose.COLLECT, component="c", deadline=deadline)
    recorder.save()
    gateway2, _, store2, clock2 = make()
    gateway2.transport = CassetteTransport(path)
    result = await gateway2.run(
        AlertIds(),
        params,
        purpose=Purpose.COLLECT,
        component="c",
        deadline=clock2.now.replace(minute=0, second=5),
    )
    assert result.took_ms == 4
    with pytest.raises(CassetteMissError):
        await gateway2.run(
            AlertIds(), AlertIdsParams(start=T0.replace(hour=10), end=T0), purpose=Purpose.COLLECT,
            component="c", deadline=clock2.now.replace(minute=1),
        )  # fmt: skip
    assert store2.ledger[-1].outcome == "cassette_miss"
