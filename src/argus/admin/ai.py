"""The AI's settings in the app (D-328): the providers' switches, keys and caps, the overall
caps and each AI task's own (``config/llm.admin.yaml``, over ``llm.yaml`` and ``llm.local.yaml``),
and what the app shows of the agents. ``argus-admin`` publishes the providers, which keys hold a
value (never a value) and the agents; the entries the web and ``argus-admin`` check a save
against are built from that, so the web reads no file of this host."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

from argus.admin.catalogue import Entry, Risk
from argus.llm.providers import ADMIN_OVERLAY, DEFAULT_PATH, LlmConfig, Tier, load_config, load_keys

SECTION = "llm"
RESTARTS = ("argus-web",)  # the assessments and the case team read it at their next run
APP_KEYS_FILE = Path("local/llm-keys.env")  # a key's home when no keys file is configured
_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _entry(key: str, label: str, help: str, kind: Any, risk: Risk = Risk.NORMAL, *,
           optional: bool = False, minimum: float | None = None,
           choices: tuple[str, ...] = (), default: Any = None) -> Entry:  # fmt: skip
    return Entry(key=key, section=SECTION, label=label, help=help, kind=kind, risk=risk,
                 editable=True, optional=optional, choices=choices, minimum=minimum,
                 default=default, restarts=RESTARTS)  # fmt: skip


def entries(state: Mapping[str, Any]) -> dict[str, Entry]:
    """The AI's settings, from ``argus-admin``'s published ``state`` (``snapshot()['llm']``)."""
    out = [
        _entry("llm.monthly_cap_usd", "Monthly limit (USD)",
               "The most the paid providers may cost together in a month.", "float",
               Risk.SENSITIVE, minimum=0),
        _entry("llm.daily_cap_usd", "Daily limit (USD)",
               "The most they may cost together in a day; empty: the monthly limit only.",
               "float", Risk.SENSITIVE, optional=True, minimum=0),
    ]  # fmt: skip
    for p in state.get("providers", ()):
        name = str(p.get("name", ""))
        if not _NAME.match(name):
            continue
        base = f"llm.providers.{name}"
        out += [
            _entry(f"{base}.enabled", "On", f"Whether ARGUS asks {name}.", "bool"),
            _entry(f"{base}.monthly_cap_usd", "Its monthly limit (USD)",
                   "Its own limit, under the overall one; empty: the overall one only.", "float",
                   Risk.SENSITIVE, optional=True, minimum=0),
            _entry(f"{base}.daily_cap_usd", "Its daily limit (USD)",
                   "Its own limit a day; empty: the overall daily limit only.", "float",
                   Risk.SENSITIVE, optional=True, minimum=0),
        ]  # fmt: skip
        for key in p.get("keys", ()):
            if _KEY.match(str(key.get("name", ""))):
                out.append(_entry(f"llm.keys.{key['name']}", f"{name}: {key['name']}",
                                  f"The API key {name} gave you.", "secret",
                                  Risk.SENSITIVE))  # fmt: skip
    names = tuple(str(p.get("name")) for p in state.get("providers", ()))
    for task in state.get("purposes", {}):
        if not _NAME.match(str(task)):
            continue
        base = f"llm.purposes.{task}"
        out += [
            _entry(f"{base}.calls_per_day", "Calls a day",
                   "The most attempts a day for this task; empty: no own limit.", "int",
                   optional=True, minimum=0),
            _entry(f"{base}.providers", "Providers, in order",
                   "The only providers it may use, tried in this order; empty: all.", "list",
                   optional=True, choices=names),
            _entry(f"{base}.tier", "Model size", "The model size it asks for.", "choice",
                   optional=True, choices=tuple(t.value for t in Tier)),
        ]  # fmt: skip
    return {e.key: e for e in out}


def check(entry: Entry, value: Any) -> Any:
    """``value`` as an AI setting takes it, or ValueError (None clears an optional one)."""
    if value is None:
        if not entry.optional:
            raise ValueError(f"{entry.label} cannot be empty")
        return None
    if entry.kind == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{entry.label}: on or off")
        return value
    if entry.kind in ("int", "float"):
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"{entry.label}: a number")
        if entry.kind == "int" and value != int(value):
            raise ValueError(f"{entry.label}: a whole number")
        if entry.minimum is not None and value < entry.minimum:
            raise ValueError(f"{entry.label}: at least {entry.minimum:g}")
        if value > 1_000_000:
            raise ValueError(f"{entry.label}: at most 1,000,000")
        return int(value) if entry.kind == "int" else float(value)
    if entry.kind == "list":
        if not isinstance(value, list) or not value:
            raise ValueError(f"{entry.label}: at least one provider (or empty for all)")
        if any(v not in entry.choices for v in value) or len(set(value)) != len(value):
            raise ValueError(f"{entry.label}: each of {', '.join(entry.choices)} at most once")
        return list(value)
    if entry.kind == "choice":
        if value not in entry.choices:
            raise ValueError(f"{entry.label}: one of {', '.join(entry.choices)}")
        return value
    raise ValueError(f"{entry.label}: not a setting the app may change")


def overlay_name(key: str) -> str:
    """Where ``key`` (an ``llm.*`` setting other than a key) lives in ``llm.admin.yaml``."""
    parts = key.split(".")
    if parts[1] == "providers":
        own = "provider_enabled" if parts[3] == "enabled" else "provider_caps"
        return f"{own}.{parts[2]}" if parts[3] == "enabled" else f"{own}.{parts[2]}.{parts[3]}"
    return ".".join(parts[1:])


def keys_file(root: Path, config: LlmConfig | None) -> tuple[Path, bool]:
    """Where a provider key is written (relative to ``root`` when it lies in it), and whether
    ``llm.admin.yaml`` must name it (no keys file is configured yet)."""
    if config is None or config.keys_file is None:
        return APP_KEYS_FILE, True
    path = config.keys_file
    if path.is_absolute():
        try:
            return path.relative_to(root), False
        except ValueError:
            return path, False
    return path, False


def config_of(root: Path) -> tuple[LlmConfig | None, str | None]:
    try:
        return load_config(root / "config" / DEFAULT_PATH.name), None
    except (OSError, ValueError) as exc:
        return None, " ".join(str(exc).split())[:500]


def snapshot(root: Path) -> dict[str, Any]:
    """The providers as this host has them, which keys hold a value and what the app set."""
    from argus.install import files

    config, problem = config_of(root)
    if config is None:
        return {"problem": problem, "providers": [], "purposes": {}, "in_app": []}
    names = {k for p in config.providers for k in p.keys}
    path = config.keys_file
    present = set(load_keys(None if path is None else root / path, names))
    admin = files.read_yaml(root / "config" / ADMIN_OVERLAY)
    return {
        "problem": None,
        "keys_file": str(config.keys_file) if config.keys_file else None,
        "monthly_cap_usd": config.monthly_cap_usd,
        "daily_cap_usd": config.daily_cap_usd,
        "providers": [
            {
                "name": p.name,
                "enabled": p.enabled,
                "api": p.api,
                "base_url": p.base_url,
                "trust": p.trust.value,
                "paid": any(m.input_per_m or m.output_per_m for m in p.models.values()),
                "models": {t.value: m.name for t, m in p.models.items()},
                "tasks": list(p.tasks) if p.tasks is not None else None,
                "keys": [{"name": k, "set": k in present} for k in p.keys],
                "monthly_cap_usd": p.monthly_cap_usd,
                "daily_cap_usd": p.daily_cap_usd,
            }
            for p in config.providers
        ],
        "purposes": {
            task: {
                "calls_per_day": pp.calls_per_day,
                "providers": list(pp.providers) if pp.providers is not None else None,
                "tier": pp.tier.value if pp.tier is not None else None,
            }
            for task, pp in config.purposes.items()
        },
        "in_app": sorted(_set_in(admin)),
    }


def _set_in(admin: Mapping[str, Any]) -> Iterator[str]:
    """The ``llm.*`` keys ``llm.admin.yaml`` sets."""
    for name in ("monthly_cap_usd", "daily_cap_usd"):
        if name in admin:
            yield f"llm.{name}"
    for provider, on in (admin.get("provider_enabled") or {}).items():
        if isinstance(on, bool):
            yield f"llm.providers.{provider}.enabled"
    for provider, caps in (admin.get("provider_caps") or {}).items():
        for name in caps or {}:
            yield f"llm.providers.{provider}.{name}"
    for task, own in (admin.get("purposes") or {}).items():
        for name in own or {}:
            yield f"llm.purposes.{task}.{name}"


def agents(root: Path) -> list[dict[str, Any]]:
    """Each agent's file as the app shows it: what it does, its model size, tools and triggers,
    the version it carries and whether code runs it (an agent is switched on in code only)."""
    from argus.agent import loader
    from argus.agent.registry import ENABLED, PINS

    out: list[dict[str, Any]] = []
    folder = root / "config" / "agents"
    for path in sorted(folder.glob("*.md")) if folder.is_dir() else ():
        try:
            d = loader.read(path)
        except (loader.AgentError, OSError) as exc:
            out.append({"name": path.stem, "problem": str(exc)[:300]})
            continue
        enabled = ENABLED.get(d.name)
        pin = PINS.get(d.name, {}).get(d.version)
        out.append({
            "name": d.name, "kind": d.kind.value, "version": d.version, "mission": d.mission,
            "task": d.task, "tier": d.tier.value, "tools": list(d.tools),
            "specialists": list(d.specialists), "triggers": sorted(t.value for t in d.triggers),
            "on": enabled == d.version and pin is not None and pin.file_sha256 == d.file_sha256,
            "enabled_version": enabled, "problem": None,
        })  # fmt: skip
    return out


def plan(root: Path, entry: Entry, value: Any, *, reset: bool = False) -> Any:
    """The edits that set the AI setting ``entry`` to ``value`` (already checked): a key into the
    keys file (named in ``llm.admin.yaml`` when it is the app's own), anything else into
    ``llm.admin.yaml``; a reset drops the name there."""
    from argus.admin import homes

    out = homes.Plan()
    if entry.secret:
        config, _ = config_of(root)
        path, name_it = keys_file(root, config)
        out.env[path] = {entry.key.split(".", 2)[2]: str(value)}
        if name_it:
            out.llm["keys_file"] = str(path)
        return out
    out.llm[overlay_name(entry.key)] = homes.REMOVE if reset else value
    return out
