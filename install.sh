#!/usr/bin/env bash
# Install ARGUS on this machine, then finish everything in the browser (docs/install.md):
#   ./install.sh      uv if it is missing, the database, the web and argus-admin; prints a link
# Needs: Docker with compose (for the database) and an account in the docker group.
set -euo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.local/bin:$PATH"

say() { printf '%s\n' "$*"; }
stop() { printf '\ninstall: %s\n' "$*" >&2; exit 2; }

if ! command -v uv >/dev/null; then
  say "== uv (the Python tool ARGUS runs with) is not here: installing it for $(id -un)"
  command -v curl >/dev/null || stop "curl is needed to fetch uv: sudo apt install curl (or dnf install curl)"
  curl -LsSf https://astral.sh/uv/install.sh | sh >/dev/null
  command -v uv >/dev/null || stop "uv did not install: see https://docs.astral.sh/uv/getting-started/installation/"
fi
if ! command -v docker >/dev/null; then
  stop "Docker with its compose plugin is needed for the database:
    Ubuntu/Debian:  sudo apt install docker.io docker-compose-v2
    Fedora/RHEL:    sudo dnf install docker docker-compose-plugin
  then:             sudo usermod -aG docker $(id -un)   (log out and in once), and ./install.sh again"
fi
if ! docker info >/dev/null 2>&1; then
  stop "Docker is installed but $(id -un) may not use it:
    sudo usermod -aG docker $(id -un)   then log out and in once (or: newgrp docker), and ./install.sh again
  (or the Docker service is stopped: sudo systemctl start docker)"
fi
# ARGUS's services are this account's user services: keep them running after logout and reboot
loginctl enable-linger "$(id -un)" >/dev/null 2>&1 || true

uv sync --frozen --no-dev -q
exec uv run argus init --web-setup "$@"
