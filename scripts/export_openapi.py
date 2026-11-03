#!/usr/bin/env python3
"""Q-A1: write the ``/api/v1`` contract to ``docs/api/openapi-v1.json``, or check it is current.

The spec is built from the app's routes alone (no database, no settings, no network): what the
code says. The app's TypeScript client (Q-B1, Hey API, DQ25) is generated from the committed
file, and ``tests/unit/web/test_openapi_spec.py`` fails when the file and the code differ.

    uv run python scripts/export_openapi.py          # write it
    uv run python scripts/export_openapi.py --check  # exit 1 if it is not current
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy.ext.asyncio import create_async_engine

from argus.web import openapi
from argus.web.app import create_app

SPEC = Path(__file__).resolve().parents[1] / "docs" / "api" / "openapi-v1.json"


def current() -> str:
    """The spec as the code builds it, in its committed form."""
    engine = create_async_engine("postgresql+psycopg://openapi@127.0.0.1:1/none")  # never used
    return openapi.canonical(openapi.v1_spec(create_app(engine)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the file is not current")
    args = parser.parse_args()
    built = current()
    if args.check:
        if not SPEC.exists() or SPEC.read_text(encoding="utf-8") != built:
            print(f"{SPEC} is not current: run scripts/export_openapi.py", file=sys.stderr)
            return 1
        print(f"{SPEC} is current")
        return 0
    SPEC.parent.mkdir(parents=True, exist_ok=True)
    SPEC.write_text(built, encoding="utf-8")
    print(f"wrote {SPEC} ({len(built.encode())} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
