"""The asset-map file store: bounded, non-blocking reads; staged, synced, atomic replacement;
no file descriptor left open on any path."""

from __future__ import annotations

import os
import stat
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from argus.assets import AssetMapError
from argus.assets.store import commit_map, read_map_bytes, stage_map

pytestmark = pytest.mark.unit

LIMIT = 16 * 1024 * 1024


def _open_fds() -> set[str]:
    return set(os.listdir("/proc/self/fd"))


@pytest.fixture
def no_fd_leak() -> Iterator[None]:
    before = _open_fds()
    yield
    assert _open_fds() <= before


def _refused(path: Path) -> str:
    with pytest.raises(AssetMapError) as info:
        read_map_bytes(path)
    return str(info.value)


def test_missing_file_is_none(tmp_path: Path, no_fd_leak: None) -> None:
    assert read_map_bytes(tmp_path / "missing.yaml") is None


def test_size_limit_is_16_mib(tmp_path: Path, no_fd_leak: None) -> None:
    path = tmp_path / "map.yaml"
    path.write_bytes(b"#" * LIMIT)
    assert read_map_bytes(path) == b"#" * LIMIT
    path.write_bytes(b"#" * (LIMIT + 1))
    assert _refused(path) == "the asset map is larger than 16777216 bytes"


def test_a_directory_is_refused(tmp_path: Path, no_fd_leak: None) -> None:
    assert _refused(tmp_path) == "the asset map is not a regular file"


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads any file")
def test_an_unreadable_file_is_refused(tmp_path: Path, no_fd_leak: None) -> None:
    path = tmp_path / "map.yaml"
    path.write_bytes(b"x")
    path.chmod(0)
    assert _refused(path) == "cannot read the asset map: Permission denied"


def test_a_fifo_without_writer_does_not_block(tmp_path: Path, no_fd_leak: None) -> None:
    fifo = tmp_path / "map.yaml"
    os.mkfifo(fifo)
    outcome: list[str] = []

    def read() -> None:
        try:
            read_map_bytes(fifo)
            outcome.append("read")
        except AssetMapError as exc:
            outcome.append(str(exc))

    worker = threading.Thread(target=read, daemon=True)
    worker.start()
    worker.join(5)
    if worker.is_alive():  # blocked in open(): give it a writer so the thread can end
        descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(descriptor)
        worker.join(5)
        pytest.fail("opening a FIFO blocked")
    assert outcome == ["the asset map is not a regular file"]


def _spy_fsync(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bool, int]]:
    """Record (is a directory, size) for every fsync the store makes."""
    calls: list[tuple[bool, int]] = []
    real = os.fsync

    def spy(descriptor: Any) -> None:
        info = os.fstat(descriptor)
        calls.append((stat.S_ISDIR(info.st_mode), info.st_size))
        real(descriptor)

    monkeypatch.setattr(os, "fsync", spy)
    return calls


def test_stage_and_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_fd_leak: None
) -> None:
    calls = _spy_fsync(monkeypatch)
    old_umask = os.umask(0o022)
    try:
        destination = tmp_path / "a" / "b" / "map.yaml"
        staged = stage_map(b"networks: []\n", destination)
    finally:
        os.umask(old_umask)
    assert staged.parent == destination.parent
    assert staged.name.startswith(".import-")
    assert stat.S_IMODE(staged.stat().st_mode) == 0o600
    assert stat.S_IMODE(destination.parent.stat().st_mode) == 0o700
    assert calls == [(False, len(b"networks: []\n"))]  # flushed before it was synced
    commit_map(staged, destination)
    assert destination.read_bytes() == b"networks: []\n"
    assert not staged.exists()
    assert calls[1:] == [(True, calls[1][1])]  # the directory, after the rename


def test_a_failed_stage_leaves_nothing_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_fd_leak: None
) -> None:
    class DiskFullError(OSError):
        pass

    def fail(descriptor: Any) -> None:
        raise DiskFullError

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(DiskFullError):
        stage_map(b"x", tmp_path / "map.yaml")
    assert list(tmp_path.iterdir()) == []
