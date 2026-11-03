#!/usr/bin/env python3
"""Fail if any real secret value appears in the given files (gate: secrets appear 0x in all output).

Also fails on any unmasked PostgreSQL password verifier (SCRAM-SHA-256$...), whoever's it is.

Secret values are read from the local secret files (.env keys containing PASSWORD/SECRET/TOKEN/KEY,
reference/llm_api_keys.env, the credential line of reference/assets.txt) together with their
common encodings (repr, JSON-escaped, URL-encoded, base64 of user:password). Only counts and file
names are printed — never the values.
"""

from __future__ import annotations

import base64
import json
import re
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
SECRET_KEY = re.compile(r"PASSWORD|SECRET|TOKEN|KEY", re.IGNORECASE)
# An unmasked PostgreSQL password verifier (redaction leaves "SCRAM-SHA-256$***"): whoever holds
# one can guess the password offline, so it counts as a secret whoever's it is.
VERIFIER = re.compile(r"SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+")


def secret_values() -> set[str]:
    values: set[str] = set()
    for name in (".env", "reference/llm_api_keys.env"):
        path = ROOT / name
        if path.is_file():
            for line in path.read_text(errors="replace").splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    if SECRET_KEY.search(key):
                        values.add(value.strip().strip("'\""))
    assets = ROOT / "reference" / "assets.txt"
    if assets.is_file():
        for line in assets.read_text(errors="replace").splitlines():
            if re.fullmatch(r"[A-Za-z0-9_.-]+:[^\s/]+", line.strip()):
                user, password = line.strip().split(":", 1)
                values.add(password)
                values.add(base64.b64encode(f"{user}:{password}".encode()).decode())
    out: set[str] = set()
    for value in values:
        if len(value) < 6:
            continue
        out |= {value, repr(value)[1:-1], json.dumps(value)[1:-1], quote(value, safe="")}
    return out


def main(paths: list[str]) -> int:
    secrets = secret_values()
    if not secrets:
        print(
            "secret_scan: no local secret files found — nothing to compare against", file=sys.stderr
        )
        return 1
    hits = 0
    for name in paths:
        text = Path(name).read_text(encoding="utf-8", errors="replace")
        found = sum(text.count(s) for s in secrets)
        if found:
            print(
                f"secret_scan: {name}: {found} occurrence(s) of a real secret value",
                file=sys.stderr,
            )
            hits += found
        verifiers = len(VERIFIER.findall(text))
        if verifiers:
            print(
                f"secret_scan: {name}: {verifiers} unmasked password verifier(s)", file=sys.stderr
            )
            hits += verifiers
    print(f"secret_scan: {len(paths)} file(s), {len(secrets)} secret forms checked, {hits} hit(s)")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
