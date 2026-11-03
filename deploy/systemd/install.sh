#!/usr/bin/env bash
# Install ARGUS's systemd user units (Q-A2, D-295): the templates in this folder rendered for this
# installation (units in config/local.yaml) by `argus units install`, which this script runs from
# the checkout it lives in. Nothing is ever enabled, started, stopped or restarted here. A dry run
# unless --apply is given.
#
#   deploy/systemd/install.sh              # show what would change (dry run)
#   deploy/systemd/install.sh --apply      # write the changed units
#   deploy/systemd/install.sh --apply --reload   # ... then `systemctl --user daemon-reload`
#   deploy/systemd/install.sh --dest DIR   # another unit directory (tests)
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
exec uv run --quiet argus units install "$@"
