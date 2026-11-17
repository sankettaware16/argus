"""The jobs ``argus-admin`` runs for the app (D-327, D-328): ``inspect_tls`` reads the certificates
an address presents (trusting none: the person compares the fingerprint); ``setup`` runs ``argus
init`` with the first-time setup's answers, each key opened from its seal into a private file for
the run and deleted after; ``check`` runs one connection check (``argus siem selftest``, ``argus
kibana selftest``, ``argus llm probe``); ``assets`` imports an uploaded asset map (``argus assets
import``) from a private file deleted after."""

from __future__ import annotations

import re
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

from argus.install import files
from argus.install.answers import KNOWN, InitError
from argus.install.trust import RealTls, anchor, describe

# sent sealed; init reads <name>_file (the administrator's password is used once, D-330)
SECRETS = frozenset({"siem.api_key", "kibana.api_key", "elastic.admin_password"})
# sent sealed with the setup and stored by argus-admin once init has run (D-330)
AFTER = frozenset({"outside.virustotal_api_key", "outside.shodan_api_key",
                   "outside.censys_api_key"})  # fmt: skip
LLM_KEY = re.compile(r"^llm\.key\.([a-z][a-z0-9_]{0,63})$")  # llm.key.groq_api_key


def setup_key(name: str) -> bool:
    return name in SECRETS or name in AFTER or name == ASSET_MAP or bool(LLM_KEY.match(name))


ASSET_MAP = "assets.map"  # the uploaded asset map's sealed name
ASSET_MAP_MAX = 5_000_000  # characters
KIBANA_KEYS = ("reader", "cases", "alerts")
_PROVIDER = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ANSWERS = frozenset(n for n in KNOWN if not n.endswith(("_file", "_env")) or n == "llm.keys_file")
_MASK = re.compile(r"(?i)(api[_ ]?key|password|secret|token)(\S*\s*[:=]\s*)\S+")


class JobError(Exception):
    """A job that could not run; the message is for the person."""


def inspect_tls(params: Mapping[str, Any]) -> dict[str, Any]:
    url = str(params.get("url", ""))
    if not re.fullmatch(r"https://[A-Za-z0-9.\-]+(:[0-9]{1,5})?/?", url):
        raise JobError("an https:// address with a host and an optional port")
    try:
        chain = list(RealTls(timeout=10.0).presented(url))
    except InitError as exc:
        raise JobError(f"{url} could not be reached: {str(exc).split(': ', 1)[-1]}") from None
    except OSError as exc:
        why = exc.strerror or type(exc).__name__
        raise JobError(f"{url} could not be reached ({why})") from None
    if not chain:
        raise JobError(f"{url} presented no certificate")
    shown = []
    for der in chain:
        d = describe(der)
        shown.append(
            {
                "subject": d.subject,
                "issuer": d.issuer,
                "fingerprint": d.fingerprint,
                "not_after": d.not_after.isoformat(),
                "self_signed": d.self_signed,
            }
        )
    return {"url": url, "chain": shown, "anchor": describe(anchor(chain)).fingerprint}


def setup(root: Path, params: Mapping[str, Any], secrets: Mapping[str, str],
          argus: str) -> dict[str, Any]:  # fmt: skip
    answers = dict(params.get("answers") or {})
    unknown = sorted(set(answers) - ANSWERS)
    if unknown:
        raise JobError(f"not a setup answer: {', '.join(unknown)}")
    with tempfile.TemporaryDirectory(prefix="argus-setup-") as tmp:
        folder = Path(tmp)
        folder.chmod(0o700)
        for name, value in secrets.items():
            if not setup_key(name):
                raise JobError(f"not a setup key: {name}")
            if name not in SECRETS:
                continue  # stored after init (argus-admin)
            path = folder / name
            files.write_private(path, value + "\n")
            answers[f"{name}_file"] = str(path)
        answers.setdefault("units.install", True)
        answers.setdefault("units.start", True)
        answers.setdefault("database.compose", True)
        answer_file = folder / "answers.yaml"
        files.write_private(answer_file, yaml.safe_dump(answers, sort_keys=True))
        done = subprocess.run(  # noqa: S603 - our own CLI
            [argus, "init", "--answers", str(answer_file), "--start"],
            cwd=root, capture_output=True, text=True, timeout=1800, check=False,
        )  # fmt: skip
    said = (done.stdout + done.stderr).replace(str(folder), "<setup>")
    lines = [_MASK.sub(r"\1\2***", line) for line in said.splitlines() if line.strip()]
    return {"ok": done.returncode == 0, "exit": done.returncode, "output": lines[-80:]}


def check_argv(target: str) -> list[str]:
    """The command a connection check runs (after ``argus``), or JobError."""
    if target == "siem":
        return ["siem", "selftest"]
    kind, _, name = target.partition(":")
    if kind == "kibana" and name in KIBANA_KEYS:
        return ["kibana", "selftest", "--key", name]
    if kind == "llm" and _PROVIDER.match(name):
        return ["llm", "probe", "--provider", name]
    raise JobError("a check of siem, kibana:reader|cases|alerts or llm:<provider>")


def _said(done: subprocess.CompletedProcess[str], hide: str | None = None) -> list[str]:
    text = done.stdout + done.stderr
    if hide:
        text = text.replace(hide, "<upload>")
    return [_MASK.sub(r"\1\2***", line) for line in text.splitlines() if line.strip()][-60:]


def check(root: Path, params: Mapping[str, Any], argus: str) -> dict[str, Any]:
    target = str(params.get("target", ""))
    argv = check_argv(target)
    try:
        done = subprocess.run(  # noqa: S603 - our own CLI, a fixed command
            [argus, *argv], cwd=root, capture_output=True, text=True, timeout=180, check=False,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        raise JobError(f"the check of {target} took longer than 3 minutes") from None
    return {"target": target, "ok": done.returncode == 0, "exit": done.returncode,
            "output": _said(done)}  # fmt: skip


def assets(root: Path, secrets: Mapping[str, str], argus: str) -> dict[str, Any]:
    content = secrets.get(ASSET_MAP)
    if content is None or set(secrets) != {ASSET_MAP}:
        raise JobError("an asset map, uploaded")
    if len(content) > ASSET_MAP_MAX:
        raise JobError("an asset map of at most 5 MB")
    with tempfile.TemporaryDirectory(prefix="argus-assets-") as tmp:
        folder = Path(tmp)
        folder.chmod(0o700)
        path = folder / "asset-map.yaml"
        files.write_private(path, content)
        done = subprocess.run(  # noqa: S603 - our own CLI
            [argus, "assets", "import", str(path)],
            cwd=root, capture_output=True, text=True, timeout=300, check=False,
        )  # fmt: skip
    return {"ok": done.returncode == 0, "exit": done.returncode,
            "output": _said(done, str(folder))}  # fmt: skip
