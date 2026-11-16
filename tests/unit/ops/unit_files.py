"""The user units rendered for this checkout and the uv running the tests (D-295), written to a
folder: what ``systemd-analyze verify`` reads (a template's @ROOT@ is no path)."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from argus.ops import units


def render_into(folder: Path, names: Iterable[str] | None = None) -> list[Path]:
    params = units.UnitParams(
        units.REPO, units.default_uv(), {"WEB_PUBLIC_URL": "http://127.0.0.1:8765"}
    )
    rendered = units.rendered_units(params)
    folder.mkdir(parents=True, exist_ok=True)
    written = []
    for name in sorted(rendered if names is None else names):
        path = folder / name
        path.write_text(rendered[name], encoding="utf-8")
        written.append(path)
    return written
