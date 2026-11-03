"""Reading and replacing the imported asset map file."""

from __future__ import annotations

import contextlib
import os
import stat
import tempfile
from pathlib import Path

from argus.assets.assetmap import MAX_MAP_BYTES, AssetMap, AssetMapError, parse_asset_map


def read_map_bytes(path: Path) -> bytes | None:
    """The file's bytes (a regular file of at most MAX_MAP_BYTES), or None if there is none."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AssetMapError(f"cannot read the asset map: {exc.strerror}") from None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise AssetMapError("the asset map is not a regular file")
        os.set_blocking(descriptor, True)
        with open(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_MAP_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > MAX_MAP_BYTES:
        raise AssetMapError(f"the asset map is larger than {MAX_MAP_BYTES} bytes")
    return raw


def load_asset_map(path: Path) -> AssetMap | None:
    """The imported map, or None if none is imported. Raises AssetMapError if it is invalid."""
    raw = read_map_bytes(path)
    return None if raw is None else parse_asset_map(raw)


def stage_map(raw: bytes, destination: Path) -> Path:
    """Write ``raw`` next to ``destination`` (mode 0600, synced); :func:`commit_map` moves it."""
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, name = tempfile.mkstemp(prefix=".import-", dir=destination.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with open(descriptor, "wb", closefd=False) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            os.unlink(name)
        raise
    os.close(descriptor)
    return Path(name)


def commit_map(staged: Path, destination: Path) -> None:
    """Atomically replace the map with the staged file and sync the directory."""
    os.replace(staged, destination)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def discard_staged(staged: Path) -> None:
    with contextlib.suppress(OSError):
        staged.unlink()


class NoAssetMapError(Exception):
    """No asset map is imported and something would leave this machine without it."""


def map_for_privacy(path: Path, *, model_keys: bool, outside_keys: bool) -> AssetMap:
    """The imported map for the privacy view. Without one the view fails closed (asset names
    cannot be recognised) while anything could leave this machine: a model key or an outside
    service's key. With neither, nothing leaves, and an empty map stands in: the assessments
    run without asset context, as the investigations do."""
    found = load_asset_map(path)
    if found is not None:
        return found
    if model_keys or outside_keys:
        raise NoAssetMapError(
            "no asset map imported: the privacy layer needs it before any model or outside"
            " service is asked (`argus assets import FILE`)"
        )
    return AssetMap([], "none")
