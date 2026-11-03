"""Q-A2: the backup's parts that need no database: retention, the tools' command lines and
environment, the manifest, fingerprint comparison, the lock."""

from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import SecretStr

from argus.config.settings import BackupSettings, DatabaseSettings, Settings
from argus.ops import backup
from argus.ops.backup import BackupError, Fingerprints, Manifest, Tools

pytestmark = pytest.mark.unit

T0 = datetime(2026, 10, 23, 21, 30, tzinfo=UTC)
FP = Fingerprints({"public.t": (2, "ab")}, {"public.t_id_seq": (2, True)}, {"columns": "c"})


def manifest(folder: Path, kind: backup.Kind, at: datetime, verified: bool = False) -> Manifest:
    path = folder / kind / f"argus-{at:%Y%m%dT%H%M%S%f}.json"
    return Manifest(
        kind=kind, database="argus", created_at=at, file=path.with_suffix(".dump").name,
        bytes=1, sha256="0" * 64, revision="0022", server_version="17.11", took_s=0.1,
        fingerprints=FP, verified={"at": at.isoformat()} if verified else None, path=path,
    )  # fmt: skip


@given(
    entries=st.lists(
        st.tuples(st.sampled_from(backup.KINDS), st.integers(0, 10_000), st.booleans()),
        min_size=0,
        max_size=40,
        unique_by=lambda e: e[1],
    ),
    limits=st.tuples(*(st.integers(1, 6) for _ in range(4))),
    max_age=st.integers(8, 40),
)
def test_retention_keeps_the_newest_of_each_kind_and_the_newest_verified(
    entries: list[tuple[backup.Kind, int, bool]], limits: tuple[int, int, int, int], max_age: int
) -> None:
    keep_nightly, keep_verified, keep_migration, keep_manual = limits
    config = BackupSettings(keep_nightly=keep_nightly, keep_verified=keep_verified,
                            keep_migration=keep_migration, keep_manual=keep_manual,
                            max_age=timedelta(days=max_age))  # fmt: skip
    # made over a week of minutes; max_age ends in the middle of it: some dumps past it
    now = T0 + timedelta(days=max_age, minutes=5_000)
    found = [manifest(Path("/b"), k, T0 + timedelta(minutes=m), v) for k, m, v in entries]
    kept = backup.kept(found, config, now)
    newest = sorted(found, key=lambda m: m.created_at, reverse=True)
    expected: set[Path] = set()
    for kind, limit in (("nightly", keep_nightly), ("migration", keep_migration),
                        ("manual", keep_manual)):  # fmt: skip
        expected |= {m.path for m in [m for m in newest if m.kind == kind][:limit]}
    expected |= {m.path for m in [m for m in newest if m.verified][:keep_verified]}
    oldest = now - timedelta(days=max_age)
    expected = {m.path for m in found if m.path in expected and m.created_at >= oldest}
    restorable = [m for m in newest if m.verified] or newest
    if restorable:  # never without a dump to restore from
        expected.add(restorable[0].path)
    assert kept == expected
    assert all(m.created_at >= oldest or m is restorable[0] for m in found if m.path in kept)


@pytest.mark.parametrize("kind", ["manual", "migration"])
def test_no_dump_outlives_max_age_by_its_kind(kind: backup.Kind) -> None:
    """Review A4-R2: the first purge's `argus backup check` (a verified manual dump) and a
    checkpoint's migration dump held every raw _source for good: kept by count, never by age."""
    now = T0 + timedelta(days=60)
    pre_purge = manifest(Path("/b"), kind, T0, verified=True)
    nightly = [
        manifest(Path("/b"), "nightly", T0 + timedelta(days=d), verified=d % 7 == 0)
        for d in range(1, 61)
    ]
    kept = backup.kept([pre_purge, *nightly], BackupSettings(), now)
    assert pre_purge.path not in kept
    assert all(m.created_at >= now - timedelta(days=35) for m in nightly if m.path in kept)
    # the newest dump a drill restored is kept whatever its age: there is one to restore from
    alone = backup.kept([pre_purge], BackupSettings(), now)
    assert alone == {pre_purge.path}


def _write(made: Manifest) -> Manifest:
    made.path.parent.mkdir(parents=True, exist_ok=True)
    made.dump_path.write_bytes(b"dump")
    made.path.write_text(json.dumps(made.as_json()))
    return made


def test_prune_removes_what_retention_drops_and_only_that(tmp_path: Path) -> None:
    config = BackupSettings(keep_manual=1, keep_nightly=1, keep_verified=1)
    now = T0 + timedelta(days=2)
    old = _write(manifest(tmp_path, "manual", T0))
    new = _write(manifest(tmp_path, "manual", T0 + timedelta(hours=1)))
    proven = _write(manifest(tmp_path, "nightly", T0, verified=True))
    latest = _write(manifest(tmp_path, "nightly", T0 + timedelta(days=1)))
    orphan = tmp_path / "manual" / "argus-orphan.dump"  # no manifest: left alone
    orphan.write_bytes(b"?")
    stale = tmp_path / "manual" / ".argus-x.dump.partial"
    stale.write_bytes(b"half")
    os.utime(stale, (0, 0))
    fresh_partial = tmp_path / "nightly" / ".argus-y.dump.partial"  # a dump in progress
    fresh_partial.write_bytes(b"half")
    listed = backup.prune(tmp_path, config, apply=False, now=now)
    assert set(listed) == {old.dump_path, old.path, stale}
    assert old.dump_path.exists()  # a dry run removes nothing
    assert set(backup.prune(tmp_path, config, apply=True, now=now)) == set(listed)
    assert not old.dump_path.exists()
    assert not old.path.exists()
    assert not stale.exists()
    for still in (new.dump_path, proven.dump_path, latest.dump_path, orphan, fresh_partial):
        assert still.exists(), still


def test_manifests_round_trip_and_bad_ones_are_named(tmp_path: Path) -> None:
    made = _write(manifest(tmp_path, "nightly", T0, verified=True))
    back = backup.read_manifest(made.path)
    assert back.as_json() == made.as_json()
    assert back.fingerprints == FP
    for content in ("not json", "{}", json.dumps({**made.as_json(), "kind": "weekly"}),
                    json.dumps({**made.as_json(), "file": "../../etc/passwd.dump"}),
                    json.dumps({**made.as_json(), "file": "x.sql"}),
                    json.dumps({**made.as_json(), "format": 2})):  # fmt: skip
        made.path.write_text(content)
        with pytest.raises(BackupError, match="is not a readable backup manifest"):
            backup.read_manifest(made.path)
    assert backup.manifests(tmp_path) == []  # unreadable ones are skipped


def test_the_drill_records_survive_a_broken_line(tmp_path: Path) -> None:
    assert backup.drills(tmp_path) == []
    (tmp_path / backup.DRILLS).write_text('{"passed": true}\nbroken\n[1]\n{"passed": false}\n')
    assert backup.drills(tmp_path) == [{"passed": True}, {"passed": False}]


def test_differences_name_tables_and_never_compare_sequence_values() -> None:
    restored = Fingerprints(
        {"public.t": (3, "cd"), "public.extra": (0, "")},
        {"public.t_id_seq": (99, True)},  # moved on while pg_dump ran: not a difference
        {"columns": "other"},
    )
    assert backup.differences(FP, restored) == [
        "table public.extra: only in the restore",
        "table public.t: 2 rows dumped, 3 restored",
        "schema columns: differs",
    ]
    same_rows = Fingerprints({"public.t": (2, "zz")}, {}, {"columns": "c"})
    assert backup.differences(FP, same_rows) == [
        "table public.t: differs",
        "sequence public.t_id_seq: missing from the restore",
    ]
    assert backup.differences(FP, FP) == []


OWNER = "Synthetic-Owner-12"


def _tools(kind: str, password: str | None = OWNER) -> Tools:
    db = DatabaseSettings(owner_password=SecretStr(password) if password else None)
    return Tools(BackupSettings(tools=kind), db, Path("/repo/docker-compose.yml"))  # type: ignore[arg-type]


def test_the_compose_tools_run_in_the_db_container_over_its_socket() -> None:
    tools = _tools("compose", password=None)
    prefix = ["docker", "compose", "-f", "/repo/docker-compose.yml", "exec", "-T", "db"]
    assert tools.dump("argus", "00000003-1") == [*prefix, "pg_dump", "-U", "argus", "-d", "argus",
        "--format=custom", "--snapshot=00000003-1", "--no-password"]  # fmt: skip
    assert tools.restore("scratch") == [*prefix, "pg_restore", "-U", "argus", "-d", "scratch",
        "--no-owner", "--exit-on-error", "--no-password"]  # fmt: skip
    assert "PGPASSWORD" not in tools.environment()  # no password needed, none passed


def test_the_image_tools_pass_the_password_only_in_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PGHOST", "elsewhere.example")  # never followed
    monkeypatch.setenv("PGPASSFILE", "/tmp/x")
    tools = _tools("image")
    command = tools.dump("argus", "snap")
    assert command[:8] == ["docker", "run", "--rm", "-i", "--network", "host", "-e", "PGPASSWORD"]
    assert command[8] == BackupSettings().image
    assert command[9:] == [
        "pg_dump", "-h", "127.0.0.1", "-p", "55432", "-U", "argus", "-d", "argus",
        "--format=custom", "--snapshot=snap", "--no-password",
    ]  # fmt: skip
    assert not any("Synthetic-Owner-12" in word for word in command)
    env = tools.environment()
    assert env["PGPASSWORD"] == "Synthetic-Owner-12"
    assert "PGHOST" not in env
    assert "PGPASSFILE" not in env
    assert env["DOCKER_CONTEXT"] == "default"
    with pytest.raises(BackupError, match="needs the owner's password"):
        _tools("image", password=None).environment()


async def test_a_tool_that_fails_says_what_it_said_redacted(tmp_path: Path) -> None:
    from argus.observability.redaction import clear_registered_secrets, register_secret

    register_secret("Synthetic-Owner-Leak-3")
    try:
        with pytest.raises(BackupError) as info:
            await backup._run_tool(
                ["sh", "-c", "echo 'password=Synthetic-Owner-Leak-3 refused' >&2; exit 3"],
                dict(os.environ), what="pg_dump",
            )  # fmt: skip
    finally:
        clear_registered_secrets()
    assert str(info.value).startswith("pg_dump failed (exit 3):")
    assert "Synthetic-Owner-Leak-3" not in str(info.value)
    with pytest.raises(BackupError, match="cannot start"):
        await backup._run_tool(["/nonexistent/pg_dump"], {}, what="pg_dump")


async def test_a_tools_output_goes_to_a_new_private_file(tmp_path: Path) -> None:
    out = tmp_path / "x.dump"
    await backup._run_tool(["sh", "-c", "printf dump"], dict(os.environ), stdout=out, what="t")
    assert out.read_bytes() == b"dump"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    with pytest.raises(FileExistsError):  # never one that exists already
        await backup._run_tool(["true"], dict(os.environ), stdout=out, what="t")
    source = tmp_path / "in"
    source.write_bytes(b"restore me")
    copied = tmp_path / "copied"
    await backup._run_tool(["cat"], dict(os.environ), stdin=source, stdout=copied, what="t")
    assert copied.read_bytes() == b"restore me"


async def test_one_dump_or_drill_at_a_time(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup, "LOCK_WAIT", timedelta(seconds=2))
    order: list[str] = []

    async def hold() -> None:
        async with backup._locked(tmp_path):
            order.append("first in")
            await asyncio.sleep(0.3)
            order.append("first out")

    async def second() -> None:
        await asyncio.sleep(0.05)
        async with backup._locked(tmp_path):
            order.append("second in")

    await asyncio.gather(hold(), second())
    assert order == ["first in", "first out", "second in"]
    assert stat.S_IMODE((tmp_path / ".lock").stat().st_mode) == 0o600

    async def stuck() -> None:
        async with backup._locked(tmp_path):
            await asyncio.sleep(5)

    task = asyncio.create_task(stuck())
    await asyncio.sleep(0.1)
    with pytest.raises(BackupError, match="another dump or drill has held"):
        async with backup._locked(tmp_path):
            pass
    task.cancel()


def test_status_reads_the_newest_of_each(tmp_path: Path) -> None:
    assert backup.status(tmp_path) == backup.Status(None, None, None, None)
    _write(manifest(tmp_path, "manual", T0 + timedelta(hours=3)))
    nightly = _write(manifest(tmp_path, "nightly", T0))
    (tmp_path / backup.DRILLS).write_text('{"passed": true, "n": 1}\n{"passed": false, "n": 2}\n')
    found = backup.status(tmp_path)
    assert found.newest_nightly is not None
    assert found.newest_nightly.file == nightly.file
    assert found.newest_any is not None
    assert found.newest_any.kind == "manual"
    assert (found.last_drill, found.last_passed_drill) == (
        {"passed": False, "n": 2}, {"passed": True, "n": 1})  # fmt: skip


def test_a_dump_file_name_never_leaves_its_folder() -> None:
    assert backup._file_safe("argus") == "argus"
    assert backup._file_safe("../../etc/x") == "_.._etc_x"
    assert backup._file_safe(".hidden") == "hidden"
    assert backup._file_safe("a b\nc\x1b") == "a_b_c_"
    assert backup._file_safe("..") == "database"
    assert len(backup._file_safe("x" * 200)) == 63


async def test_a_drill_that_does_not_finish_is_recorded_as_failed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Else doctor would show the last drill that passed while the newest one broke."""
    made = _write(manifest(tmp_path, "nightly", T0))
    made.sha256 = backup._sha256(made.dump_path)
    made.path.write_text(json.dumps(made.as_json()))

    async def broken(*_: object, **__: object) -> list[str]:
        raise BackupError("pg_restore failed (exit 1): no space left on device")

    monkeypatch.setattr(backup, "_restore_and_compare", broken)
    settings = Settings(
        database=DatabaseSettings(owner_password=SecretStr(OWNER)),
        backup=BackupSettings(dir=tmp_path, tools="image"),
    )
    with pytest.raises(BackupError, match="no space left"):
        await backup.drill(settings, backup.read_manifest(made.path), now=T0)
    (record,) = backup.drills(tmp_path)
    assert record["passed"] is False
    assert record["differences"] == [
        "the drill did not finish: BackupError: pg_restore failed (exit 1): no space left on device"
    ]
    assert backup.read_manifest(made.path).verified is None
    made.dump_path.unlink()
    with pytest.raises(BackupError, match="the dump file is missing"):
        await backup.drill(settings, backup.read_manifest(made.path), now=T0)
    assert [r["passed"] for r in backup.drills(tmp_path)] == [False, False]
