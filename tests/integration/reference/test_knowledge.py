"""The knowledge store's seeds (R9, D-057)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.reference import knowledge

pytestmark = pytest.mark.integration

SEED = {"key": "lab-scanner", "kind": "benign_pattern", "matcher": {"ip": "10.8.1.5"},
        "assertion": "the lab scanner", "expires_at": "2026-12-31T00:00:00Z"}  # fmt: skip


def test_items_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ValidationError, match="benign pattern needs expires_at"):
        knowledge.Item.model_validate({**SEED, "expires_at": None})
    with pytest.raises(ValidationError, match="time zone"):
        knowledge.Item.model_validate({**SEED, "expires_at": "2026-12-31T00:00:00"})
    with pytest.raises(ValidationError):
        knowledge.Item.model_validate({**SEED, "surprise": 1})
    seeds = tmp_path / "k.yaml"
    seeds.write_text("items:\n  - {key: a1, kind: context, matcher: {}, assertion: x}\n"
                     "  - {key: a1, kind: context, matcher: {}, assertion: y}\n")  # fmt: skip
    with pytest.raises(ValueError, match="repeat"):
        knowledge.read(seeds)
    assert knowledge.read(tmp_path / "missing.yaml") == []
    assert knowledge.read(Path(__file__).parents[3] / "config" / "knowledge.yaml") == []


async def test_seeds_load_once_and_never_overwrite(app_engine: AsyncEngine) -> None:
    item = knowledge.Item.model_validate(SEED)
    async with app_engine.begin() as conn:
        assert await knowledge.load(conn, [item], "seeds.yaml") == 1
    changed = knowledge.Item.model_validate({**SEED, "assertion": "changed"})
    async with app_engine.begin() as conn:
        assert await knowledge.load(conn, [changed], "seeds.yaml") == 0
    async with app_engine.connect() as conn:
        row = (await conn.execute(text("SELECT * FROM knowledge_items"))).one()
    assert (row.key, row.kind, row.assertion, row.status) == (
        "lab-scanner", "benign_pattern", "the lab scanner", "proposed")  # fmt: skip
    assert row.expires_at == datetime(2026, 12, 31, tzinfo=UTC)
    assert row.provenance["source"] == "seeds.yaml"


# ----------------------------------------------------------------- exact (mutation testing)


def test_the_item_model_exactly(tmp_path: Path) -> None:
    from datetime import UTC, datetime

    from pydantic import ValidationError

    from argus.reference import knowledge

    assert Path("config/knowledge.yaml") == knowledge.SEEDS
    base = {"key": "k1", "kind": "entity_note", "matcher": {}, "assertion": "a"}
    for kind in ("entity_note", "context", "false_positive"):
        assert knowledge.Item(**{**base, "kind": kind}).status == "proposed"
    for status in ("proposed", "active", "retired"):
        knowledge.Item(**{**base, "status": status})
    for bad in ({"status": "live"}, {"kind": "rule"}, {"assertion": "x" * 2001},
                {"assertion": ""}, {"key": "K"}, {"extra": 1}):  # fmt: skip
        with pytest.raises(ValidationError):
            knowledge.Item(**{**base, **bad})
    knowledge.Item(**{**base, "assertion": "x" * 2000})
    with pytest.raises(ValidationError, match="a benign pattern needs expires_at"):
        knowledge.Item(**{**base, "kind": "benign_pattern"})
    with pytest.raises(ValidationError, match="expires_at needs a time zone"):
        knowledge.Item(**{**base, "expires_at": datetime(2027, 1, 1)})  # noqa: DTZ001
    item = knowledge.Item(**{**base, "kind": "benign_pattern",
                             "expires_at": datetime(2027, 1, 1, tzinfo=UTC)})  # fmt: skip
    with pytest.raises(ValidationError):
        item.key = "k2"  # type: ignore[misc]
    seeds = tmp_path / "k.yaml"
    seeds.write_text("items:\n  - {key: k1, kind: context, matcher: {}, assertion: a}\n"
                     "  - {key: k1, kind: context, matcher: {}, assertion: b}\n")  # fmt: skip
    with pytest.raises(ValueError, match="knowledge item keys repeat"):
        knowledge.read(seeds)
    assert knowledge.read(tmp_path / "missing.yaml") == []


async def test_seeds_record_where_they_came_from(app_engine: AsyncEngine) -> None:
    from sqlalchemy import text

    from argus.reference import knowledge

    item = knowledge.Item(key="k9", kind="context", matcher={}, assertion="a")
    async with app_engine.begin() as conn:
        assert await knowledge.load(conn, [item], "seed-file") == 1
    async with app_engine.connect() as conn:
        provenance = (await conn.execute(text(
            "SELECT provenance FROM knowledge_items WHERE key = 'k9'"))).scalar_one()  # fmt: skip
    assert provenance["source"] == "seed-file"
    assert provenance["loaded_at"].endswith("+00:00")
