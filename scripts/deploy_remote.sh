#!/usr/bin/env bash
# Update an ARGUS installation on another machine to one commit, over SSH, the documented way
# (the "Updating production" runbook): the timers stopped, the checkout
# fast-forwarded to COMMIT (it must be on its remote branch already), `uv sync`, `argus init` with
# every answer kept (migrations after a dump, units rendered, logins repaired), the services
# restarted, every timer of units.run started, then doctor.
#   scripts/deploy_remote.sh argus@<host> <commit> [checkout, default ~/argus]
set -euo pipefail

target=${1:?usage: deploy_remote.sh user@host commit [checkout]}
commit=${2:?usage: deploy_remote.sh user@host commit [checkout]}
dir=${3:-'~/argus'}
[[ $commit =~ ^[0-9a-f]{7,40}$ ]] || { echo "commit: a hash" >&2; exit 2; }

ssh -o BatchMode=yes -o ConnectTimeout=10 "$target" bash -s -- "$dir" "$commit" <<'REMOTE'
set -euo pipefail
dir=$1 commit=$2
cd "${dir/#\~/$HOME}"
export PATH=$HOME/.local/bin:$PATH
echo "== $(date -u +%FT%TZ) from $(git log -1 --format=%h) to $commit"
timers=$(systemctl --user list-units 'argus-*.timer' --state=active --no-legend --plain | awk '{print $1}')
[[ -n $timers ]] && systemctl --user stop $timers
git fetch -q origin
git merge -q --ff-only "$commit"
git log -1 --format='%h %s'
uv sync -q
umask 077
answers=$(mktemp)
echo '{}' > "$answers"
# init ends with doctor, which fails on a unit of units.run not started yet: started below
uv run argus init --answers "$answers" | grep -v -E '^PASS' | tail -40 || true
rm -f "$answers"
systemctl --user daemon-reload
for unit in $(uv run python -c "from argus.config.settings import load_settings; print(' '.join(load_settings().units.run))"); do
  case $unit in
    *.timer) systemctl --user enable -q "$unit"; systemctl --user start "$unit" ;;
    *.service) systemctl --user enable -q "$unit"; systemctl --user restart "$unit" ;;
  esac
done
sleep 15
systemctl --user list-units 'argus-*' --no-pager --plain --no-legend | awk '{printf "  %-34s %s %s\n", $1, $3, $4}'
uv run argus doctor | grep -E '^(FAIL|WARN)' || true
REMOTE
