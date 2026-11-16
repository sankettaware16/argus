#!/usr/bin/env bash
# Install ARGUS on this machine, then finish the setup in the browser (docs/install.md):
#   ./install.sh            the database, the web and argus-admin; prints a one-time link
# Needs: uv (https://docs.astral.sh/uv/) and Docker with compose (for the database).
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v uv >/dev/null; then
  echo "install: uv is needed first: https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 2
fi
if ! command -v docker >/dev/null; then
  echo "install: Docker with compose is needed for the database (or run: uv run argus init)" >&2
  exit 2
fi
uv sync --frozen --no-dev
exec uv run argus init --web-setup "$@"
