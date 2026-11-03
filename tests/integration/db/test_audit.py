"""The audit trail as ARGUS writes it: through the runtime role (D-029), which may only insert.

The append-only triggers are tested as the schema owner, who holds every table privilege, so
only the triggers stand in the way; tests/integration/db/test_roles.py covers what the runtime
role is refused before the triggers even run.
"""

from __future__ import annotations

import asyncio
import math
import random
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine

from argus.db.audit import MAX_DETAILS_BYTES, MAX_ID_CHARS, MAX_NAME_CHARS, AuditError, record_audit
from argus.db.engine import session_factory
from argus.db.models import AuditEvent
from argus.observability.redaction import MASK, clear_registered_secrets, redact, register_secret


async def _write(engine: AsyncEngine, **kwargs: object) -> int:
    async with session_factory(engine)() as session, session.begin():
        event = await record_audit(session, **{"actor": "test", "action": "unit.test", **kwargs})  # type: ignore[arg-type]
        return event.id


async def _count(engine: AsyncEngine) -> int:
    async with session_factory(engine)() as session:
        return int(
            (await session.execute(select(func.count()).select_from(AuditEvent))).scalar_one()
        )


async def test_insert_with_defaults(app_engine: AsyncEngine) -> None:
    before = datetime.now(UTC)
    event_id = await _write(app_engine, target_type="database", target_id="argus")
    async with session_factory(app_engine)() as session:
        event = await session.get(AuditEvent, event_id)
    assert event is not None
    assert event.outcome == "success"
    assert event.details == {}
    assert event.occurred_at.tzinfo is not None
    assert event.occurred_at.utcoffset() == timedelta(0)
    assert (
        before - timedelta(seconds=5)
        <= event.occurred_at
        <= datetime.now(UTC) + timedelta(seconds=5)
    )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET actor = 'mallory'",
        "DELETE FROM audit_events",
        "TRUNCATE audit_events",
    ],
)
async def test_audit_trail_is_append_only(migrated_engine: AsyncEngine, statement: str) -> None:
    await _write(migrated_engine)
    with pytest.raises(DBAPIError, match="append-only"):
        async with migrated_engine.begin() as conn:
            await conn.execute(text(statement))
    assert await _count(migrated_engine) == 1


async def _orm_update(engine: AsyncEngine, event_id: int) -> None:
    async with session_factory(engine)() as session, session.begin():
        event = await session.get(AuditEvent, event_id)
        assert event is not None
        event.actor = "mallory"


async def _orm_delete(engine: AsyncEngine, event_id: int) -> None:
    async with session_factory(engine)() as session, session.begin():
        await session.delete(await session.get(AuditEvent, event_id))


async def test_orm_mutation_is_rejected(migrated_engine: AsyncEngine) -> None:
    event_id = await _write(migrated_engine)
    with pytest.raises(DBAPIError, match="append-only"):
        await _orm_update(migrated_engine, event_id)
    with pytest.raises(DBAPIError, match="append-only"):
        await _orm_delete(migrated_engine, event_id)
    assert await _count(migrated_engine) == 1


_RAW_INSERT = text(
    "INSERT INTO audit_events (actor, action, outcome, details) "
    "VALUES (:actor, :action, :outcome, CAST(:details AS jsonb))"
)


async def _raw_insert(engine: AsyncEngine, row: dict[str, str]) -> None:
    async with engine.begin() as conn:
        await conn.execute(_RAW_INSERT, row)


@pytest.mark.parametrize(
    "row",
    [
        {"actor": "", "action": "a", "outcome": "success", "details": "{}"},
        {"actor": "a", "action": "", "outcome": "success", "details": "{}"},
        {"actor": "a", "action": "a", "outcome": "maybe", "details": "{}"},
        {"actor": "a", "action": "a", "outcome": "success", "details": "[1, 2]"},
    ],
)
async def test_check_constraints(app_engine: AsyncEngine, row: dict[str, str]) -> None:
    with pytest.raises(IntegrityError):
        await _raw_insert(app_engine, row)
    assert await _count(app_engine) == 0


async def test_id_cannot_be_supplied(migrated_engine: AsyncEngine) -> None:
    with pytest.raises(DBAPIError):
        async with migrated_engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO audit_events (id, actor, action) VALUES (1, 'a', 'b')")
            )


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"actor": " "}, "actor"),
        ({"action": ""}, "action"),
        ({"outcome": "maybe"}, "outcome"),
        ({"details": {"x": math.nan}}, "JSON"),
        ({"details": {"blob": "x" * (MAX_DETAILS_BYTES + 1)}}, "exceed"),
    ],
)
async def test_invalid_events_are_rejected_before_the_database(
    app_engine: AsyncEngine, kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(AuditError, match=message):
        await _write(app_engine, **kwargs)
    assert await _count(app_engine) == 0


async def test_details_are_redacted_before_storage(app_engine: AsyncEngine) -> None:
    register_secret("audit-secret-123456")
    try:
        event_id = await _write(
            app_engine,
            details={
                "password": "hunter2",
                "nested": {"note": "used audit-secret-123456 today"},
                "dsn": "postgresql://argus:pw123456@host/db",  # fake-secret
                "when": datetime(2026, 10, 10, tzinfo=UTC),
            },
        )
    finally:
        clear_registered_secrets()
    async with app_engine.connect() as conn:
        raw = (
            await conn.execute(
                text("SELECT details::text FROM audit_events WHERE id = :i"), {"i": event_id}
            )
        ).scalar_one()
    assert "hunter2" not in raw
    assert "audit-secret-123456" not in raw
    assert "pw123456" not in raw
    assert MASK in raw
    assert "2026-10-10" in raw


async def _write_then_fail(engine: AsyncEngine) -> None:
    async with session_factory(engine)() as session, session.begin():
        await record_audit(session, actor="test", action="will.rollback")
        raise RuntimeError("caller failed")


async def test_rolled_back_transaction_writes_nothing(app_engine: AsyncEngine) -> None:
    with pytest.raises(RuntimeError, match="caller failed"):
        await _write_then_fail(app_engine)
    assert await _count(app_engine) == 0


async def test_concurrent_writers(app_engine: AsyncEngine) -> None:
    ids = await asyncio.gather(*(_write(app_engine, target_id=str(i)) for i in range(40)))
    assert len(set(ids)) == 40
    assert await _count(app_engine) == 40


# Names that must be refused as actor/action/target_type. Several render as nothing at all (the
# spoofing problem: an actor that shows up blank, or as "cli", in audit listings).
_BAD_NAMES: dict[str, tuple[str, str]] = {
    "129-characters": ("actor", "a" * (MAX_NAME_CHARS + 1)),
    "leading-space": ("actor", " cli"),
    "trailing-space": ("actor", "cli "),
    "inner-space": ("action", "db upgrade"),
    "trailing-newline": ("action", "db.upgrade\n"),
    "empty-target-type": ("target_type", ""),
    "blank-target-type": ("target_type", " "),
    "hangul-filler": ("actor", "\u3164"),
    "hangul-choseong-filler": ("actor", "\u115f"),
    "halfwidth-hangul-filler": ("action", "\uffa0"),
    "braille-blank": ("action", "\u2800"),
    "combining-grapheme-joiner": ("target_type", "\u034f"),
    "variation-selector-16": ("target_type", "\ufe0f"),
    "khmer-vowel-inherent-aq": ("actor", "\u17b4"),
    "invisible-suffix": ("actor", "cli\u3164"),
    "cyrillic-lookalike": ("actor", "cl\u0456"),
    "fullwidth-letters": ("actor", "\uff43\uff4c\uff49"),
    "accented-letter": ("target_type", "caf\u00e9"),
    "leading-dot": ("action", ".db"),
    "leading-underscore": ("actor", "_cli"),
    "semicolon": ("action", "db;drop"),
}


@pytest.mark.parametrize(("field", "value"), list(_BAD_NAMES.values()), ids=list(_BAD_NAMES))
async def test_names_outside_the_ascii_identifier_rule_are_rejected(
    app_engine: AsyncEngine, field: str, value: str
) -> None:
    with pytest.raises(AuditError, match=field):
        await _write(app_engine, **{field: value})
    assert await _count(app_engine) == 0


@pytest.mark.parametrize(
    "name",
    ["a" * MAX_NAME_CHARS, "Z", "7", "db.upgrade", "gateway/elastic:search@v1_x-y"],
    ids=["128-characters", "one-letter", "one-digit", "dotted", "every-separator"],
)
async def test_ascii_identifier_names_are_accepted_unchanged(
    app_engine: AsyncEngine, name: str
) -> None:
    event_id = await _write(app_engine, actor=name, action=name, target_type=name)
    async with session_factory(app_engine)() as session:
        event = await session.get(AuditEvent, event_id)
    assert event is not None
    assert (event.actor, event.action, event.target_type) == (name, name, name)


def _astral(rng: random.Random, count: int) -> str:
    """``count`` random characters that are 4 bytes each in UTF-8 (the worst case per character)."""
    return "".join(chr(rng.randrange(0x10000, 0x110000)) for _ in range(count))


async def test_overlong_ids_are_truncated_so_the_index_can_hold_them(
    app_engine: AsyncEngine,
) -> None:
    """A ~3,000-character id used to kill the caller's transaction ("index row size exceeds
    btree maximum"). Both ids are cut to MAX_ID_CHARS characters, ending in a marker."""
    rng = random.Random(20261010)
    target_id, correlation_id = _astral(rng, 3_000), _astral(rng, 3_000)
    target_type = "t" * MAX_NAME_CHARS  # the longest name, next to target_id in the index
    event_id = await _write(
        app_engine,
        target_type=target_type,
        target_id=target_id,
        correlation_id=correlation_id,
    )
    async with session_factory(app_engine)() as session:
        event = await session.get(AuditEvent, event_id)
    assert event is not None
    marker = "...[3000 chars, truncated]"
    for stored, original in ((event.target_id, target_id), (event.correlation_id, correlation_id)):
        assert stored is not None
        assert len(stored) == MAX_ID_CHARS
        assert stored == original[: MAX_ID_CHARS - len(marker)] + marker
    assert event.target_id is not None
    assert len(event.target_id.encode()) > 4 * (MAX_ID_CHARS - len(marker))  # really 4-byte data


async def test_ids_up_to_the_limit_are_stored_unchanged(app_engine: AsyncEngine) -> None:
    exact = _astral(random.Random(7), MAX_ID_CHARS)
    event_id = await _write(app_engine, target_id=exact, correlation_id=exact)
    async with session_factory(app_engine)() as session:
        event = await session.get(AuditEvent, event_id)
    assert event is not None
    assert event.target_id == exact
    assert event.correlation_id == exact


async def _stored_details(engine: AsyncEngine, event_id: int) -> Any:
    async with engine.connect() as conn:
        return (
            await conn.execute(
                text("SELECT details FROM audit_events WHERE id = :i"), {"i": event_id}
            )
        ).scalar_one()


# Keys that JSON stores as the same text: 1 and "1", None and "null", True and "true", 2.5 and
# "2.5", and a key with a NUL or a lone surrogate (both stored as U+FFFD) next to the same key
# with U+FFFD. Round 2 stored only the last of each group and dropped the others silently.
_COLLIDING_KEYS: dict[str, tuple[dict[Any, Any], dict[str, Any]]] = {
    "int": ({1: "int", "1": "str"}, {"1 (int)": "int", "1": "str"}),
    "str-first": ({"1": "str", 1: "int"}, {"1": "str", "1 (int)": "int"}),
    "none": ({None: "none", "null": "str"}, {"null (NoneType)": "none", "null": "str"}),
    "true": ({True: "bool", "true": "str"}, {"true (bool)": "bool", "true": "str"}),
    "false": ({False: "bool", "false": "str"}, {"false (bool)": "bool", "false": "str"}),
    "float": ({2.5: "float", "2.5": "str"}, {"2.5 (float)": "float", "2.5": "str"}),
    "nul": (
        {"a\x00": "nul", "a\ufffd": "replacement"},
        {"a\ufffd": "nul", "a\ufffd (str)": "replacement"},
    ),
    "lone-surrogate": (
        {"a\ud800": "surrogate", "a\ufffd": "replacement"},  # noqa: F601 - distinct in Python
        {"a\ufffd": "surrogate", "a\ufffd (str)": "replacement"},
    ),
    "new-name-taken": (
        {1: "int", "1": "str", "1 (int)": "taken"},
        {"1 (int 2)": "int", "1": "str", "1 (int)": "taken"},
    ),
    "nested": ({"outer": {1: "int", "1": "str"}}, {"outer": {"1 (int)": "int", "1": "str"}}),
    "in-lists": (
        {"rows": [{None: 1, "null": 2}, ({True: 3, "true": 4},)]},
        {"rows": [{"null (NoneType)": 1, "null": 2}, [{"true (bool)": 3, "true": 4}]]},
    ),
}


@pytest.mark.parametrize(
    ("details", "stored"), list(_COLLIDING_KEYS.values()), ids=list(_COLLIDING_KEYS)
)
async def test_detail_keys_stored_as_the_same_json_text_are_all_kept(
    app_engine: AsyncEngine, details: dict[Any, Any], stored: dict[str, Any]
) -> None:
    event_id = await _write(app_engine, details=details)
    assert await _stored_details(app_engine, event_id) == stored


_KEY_POOL: list[object] = [
    *(1, "1", None, "null", True, "true", False, "false", 2.5, "2.5"),
    *("a\x00", "a\ud800", "a\ufffd", "1 (int)", b"1", "x"),
]


def _random_details(rng: random.Random, depth: int) -> dict[Any, Any]:
    """A mapping whose keys often collide as JSON text, with nested mappings and lists."""
    details: dict[Any, Any] = {}
    for _ in range(rng.randrange(1, 8)):
        roll = rng.random()
        if depth and roll < 0.2:
            value: Any = _random_details(rng, depth - 1)
        elif depth and roll < 0.3:
            value = [_random_details(rng, depth - 1) for _ in range(rng.randrange(1, 3))]
        else:
            value = rng.randrange(1000)
        details[rng.choice(_KEY_POOL)] = value
    return details


def _entries(value: Any) -> int:
    if isinstance(value, dict):
        return len(value) + sum(_entries(item) for item in value.values())
    if isinstance(value, list | tuple):
        return sum(_entries(item) for item in value)
    return 0


async def test_random_details_with_colliding_keys_keep_every_entry(app_engine: AsyncEngine) -> None:
    rng = random.Random(20261010)
    for _ in range(25):
        details = _random_details(rng, depth=3)
        stored = await _stored_details(app_engine, await _write(app_engine, details=details))
        assert _entries(stored) == _entries(redact(details)), details
