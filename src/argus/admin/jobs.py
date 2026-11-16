"""The jobs ``argus-admin`` runs for the app (D-327): ``inspect_tls`` reads the certificates an
address presents (trusting none: the person compares the fingerprint), and ``setup`` runs ``argus
init`` with the first-time setup's answers, each key opened from its seal into a private file for
the run and deleted after."""

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

SECRETS = frozenset({"siem.api_key", "kibana.api_key"})  # sent sealed; init reads <name>_file
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
            if name not in SECRETS:
                raise JobError(f"not a setup key: {name}")
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
