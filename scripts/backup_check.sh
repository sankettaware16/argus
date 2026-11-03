#!/usr/bin/env bash
# R16 and Q-A2: back up ARGUS's database and prove that a restore gives the same data: a dump,
# then a restore drill of that very dump into a scratch database, every table's fingerprint
# compared (`argus backup check`). The dump and its fingerprints come from one snapshot, so every
# service keeps running: nothing is stopped or restarted (the drill used to stop the collector
# and the worker). Local only: nothing reaches the SIEM. The dump stays in data/backups/manual/.
#   scripts/backup_check.sh [database]     # default: the configured one (database.name)
set -euo pipefail
cd "$(dirname "$0")/.."
export DOCKER_CONTEXT=${DOCKER_CONTEXT:-default}
if (( $# )); then export ARGUS_DATABASE__NAME=$1; fi
exec uv run argus backup check
