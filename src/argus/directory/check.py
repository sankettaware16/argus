"""The account directory's saved session tested from the app (D-337): whether the directory
still accepts it, without asking about anyone."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from argus.config.settings import ConfigError, load_settings
from argus.directory import Directory, resolve

TARGET = "directory"


async def check(root: Path) -> dict[str, Any]:
    """Raises ValueError when there is nothing to test."""
    try:
        settings = load_settings(root / "config" / "argus.yaml", env_file=root / ".env").directory
    except ConfigError as exc:
        raise ValueError(f"the settings do not load: {str(exc)[:200]}") from None
    if not settings.provider:
        raise ValueError("this site names no account directory (directory.provider)")
    found = Directory(resolve(settings.provider), settings)
    answer = await found.check()
    said = {
        "found": f"{found.label} accepts the saved session",
        "expired": f"{found.label} does not accept the saved session: sign in to {found.label}"
        " and save the new session here",
        "error": f"no answer from {found.label}",
    }.get(answer.outcome, f"no answer from {found.label}")
    if answer.why and answer.outcome != "found":
        said = f"{said} ({answer.why})"
    return {"target": TARGET, "ok": answer.outcome == "found", "output": [said]}
