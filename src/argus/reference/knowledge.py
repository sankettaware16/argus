"""The knowledge store's seeds: typed items from ``config/knowledge.yaml``, upserted by key.
Reviewers add items from the web UI; a benign pattern must always expire."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncConnection

SEEDS = Path("config/knowledge.yaml")


class Item(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    key: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{1,79}$")
    kind: Literal["benign_pattern", "entity_note", "context", "false_positive"]
    scope: dict[str, Any] = Field(default_factory=dict)
    matcher: dict[str, Any]
    assertion: str = Field(min_length=1, max_length=2000)
    guards: dict[str, Any] = Field(default_factory=dict)
    status: Literal["proposed", "active", "retired"] = "proposed"
    expires_at: datetime | None = None

    @model_validator(mode="after")
    def benign_expires(self) -> Item:
        if self.kind == "benign_pattern" and self.expires_at is None:
            raise ValueError("a benign pattern needs expires_at")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at needs a time zone")
        return self


def read(path: Path = SEEDS) -> list[Item]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) if path.is_file() else None
    items = (raw or {}).get("items") or []
    found = [Item.model_validate(item) for item in items]
    keys = [i.key for i in found]
    if len(keys) != len(set(keys)):
        raise ValueError("knowledge item keys repeat")
    return found


async def load(conn: AsyncConnection, items: list[Item], source: str) -> int:
    """Insert the seeds that are new (an existing key is never overwritten: reviewers may
    have changed it). Returns how many were added."""
    added = 0
    for item in items:
        row = await conn.execute(
            text(
                "INSERT INTO knowledge_items (key, kind, scope, matcher, assertion, guards,"
                " provenance, status, expires_at, created_at) VALUES (:key, :kind, :scope,"
                " :matcher, :assertion, :guards, :provenance, :status, :expires_at, :now)"
                " ON CONFLICT (key) DO NOTHING RETURNING 1"
            ).bindparams(
                *(bindparam(c, type_=JSONB) for c in ("scope", "matcher", "guards", "provenance"))
            ),
            {
                **item.model_dump(),
                "provenance": {"source": source, "loaded_at": datetime.now(UTC).isoformat()},
                "now": datetime.now(UTC),
            },
        )
        added += row.first() is not None
    return added
