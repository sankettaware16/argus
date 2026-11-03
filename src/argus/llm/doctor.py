"""``argus doctor``'s LLM checks (Q-G1): the configuration, the keys file, each provider's key
and pinned certificate, and the gateway's alarms. Read-only and offline: no request reaches a
provider (``argus llm probe`` asks them)."""

from __future__ import annotations

import ipaddress
import os
import ssl
from collections.abc import Collection
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from argus.gateway.transport import pinned_context
from argus.llm import budget
from argus.llm.providers import ROOT, LlmConfig, ProviderConfig, Trust
from argus.llm.wire import pem_blocks

CERT_WARN_DAYS = 30


@dataclass(frozen=True)
class Finding:
    name: str
    ok: bool
    detail: str


def _keys_file(config: LlmConfig) -> Path | None:
    path = config.keys_file
    return path if path is None or path.is_absolute() else ROOT / path


def keys_file_check(config: LlmConfig) -> Finding:
    path = _keys_file(config)
    if path is None:
        return Finding(
            "llm keys",
            True,
            "none (keys_file: null): no model is called; ARGUS investigates deterministically",
        )
    if not path.is_file():
        return Finding("llm keys", True, "no keys file: no model can be called")
    if path.stat().st_mode & 0o077:
        return Finding("llm keys", False, f"{config.keys_file} is readable by others (chmod 600)")
    return Finding("llm keys", True, f"{config.keys_file} (mode 600)")


def providers_check(config: LlmConfig, present: set[str]) -> Finding:
    parts = []
    for p in config.providers:
        state = "on" if p.enabled else "disabled"
        key = "key" if any(k in present for k in p.keys) else "no key"
        parts.append(f"{p.name} ({state}, {key})")
    return Finding("llm providers", True, ", ".join(parts))


def _names(decoded: dict[str, object], host: str) -> bool:
    """Whether the certificate's subjectAltName names ``host`` (an address, or a DNS name)."""
    sans = decoded.get("subjectAltName") or ()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(k == "DNS" and str(v).lower() == host.lower() for k, v in sans)  # type: ignore[attr-defined]
    for kind, value in sans:  # type: ignore[attr-defined]
        if kind == "IP Address":
            try:
                if ipaddress.ip_address(str(value).strip()) == address:
                    return True
            except ValueError:
                continue
    return False


def _replaceable(path: Path) -> str | None:
    """Why someone other than ARGUS's account (or root) could replace the pinned file."""
    info = path.stat()
    if info.st_mode & 0o022:
        return "is writable by others (chmod 644)"
    if info.st_uid not in (os.geteuid(), 0):
        return "is owned by another account (the import makes ARGUS's account its owner)"
    if path.parent.stat().st_mode & 0o022:
        return "its folder is writable by others (chmod 700 the folder)"
    return None


def certificate_check(provider: ProviderConfig, now: datetime) -> Finding | None:
    """The pinned certificate of a provider with a ``ca_file``: present, exactly one
    certificate (every one in the file would be trusted), that a TLS client can load, that only
    ARGUS's account can replace, naming the host it is reached at, self-signed for a campus
    machine (the setup's own), not about to expire."""
    path = provider.ca_path()
    if path is None:
        return None
    name = f"llm {provider.name} certificate"
    if not path.is_file():
        if not provider.enabled:
            return Finding(name, True, "not imported yet (setup-argus-side.sh --import)")
        return Finding(name, False, f"{provider.ca_file} does not exist (import the hand-over)")
    why = _replaceable(path)
    if why is not None:
        return Finding(name, False, f"{provider.ca_file}: {why}")
    try:
        blocks, certificates = pem_blocks(path.read_bytes())
        if blocks > 1:
            held = f"{certificates} certificates" if blocks == certificates else "other PEM blocks"
            return Finding(name, False, f"{provider.ca_file} holds {held}: exactly one is pinned")
        decoded = ssl._ssl._test_decode_cert(str(path))  # type: ignore[attr-defined]
        pinned_context(path)
    except (ssl.SSLError, OSError):
        return Finding(name, False, f"{provider.ca_file} is not a usable PEM certificate")
    not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(decoded["notAfter"]), UTC)
    days = (not_after - now).days
    host = urlsplit(provider.base_url).hostname or ""
    if not _names(decoded, host):
        return Finding(name, False, f"the certificate does not name {host}")
    if provider.trust is Trust.CAMPUS and decoded.get("subject") != decoded.get("issuer"):
        return Finding(name, False, "a campus certificate is the setup's own, self-signed one")
    if days < CERT_WARN_DAYS:
        return Finding(name, False, f"expires {not_after:%Y-%m-%d}: run the setup again")
    trust = "campus" if provider.trust is Trust.CAMPUS else "cloud"
    return Finding(name, True, f"{trust}, for {host}, valid until {not_after:%Y-%m-%d}")


def alarms_check(state: budget.State, configured: Collection[str]) -> Finding:
    """Fails on an alarm of a configured provider; one of a provider no longer in
    config/llm.yaml is only named (nothing would ever call it, or clear it)."""
    current = {p: a for p, a in state.alarms.items() if p in configured}
    stale = sorted(p for p in state.alarms if p not in configured)
    note = f"; ignored, no longer configured: {', '.join(stale)}" if stale else ""
    if not current:
        return Finding("llm alarms", True, "none" + note)
    shown = "; ".join(
        f"{p}: {a.kind} since {a.at:%Y-%m-%d %H:%M} UTC ({a.detail})"
        for p, a in sorted(current.items())
    )
    return Finding("llm alarms", False, shown + note + " (argus llm probe clears an alarm once"
                   " the provider is up)")  # fmt: skip


def offline_checks(config: LlmConfig, present: set[str], now: datetime) -> list[Finding]:
    found = [keys_file_check(config), providers_check(config, present)]
    for p in config.providers:
        cert = certificate_check(p, now)
        if cert is not None:
            found.append(cert)
    return found
