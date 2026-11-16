#!/usr/bin/env bash
# Update an ARGUS installation on another machine to one commit, over SSH, the documented way
# (the "Updating production" runbook): a checkout with local changes refused before anything
# stops, the timers stopped, the checkout
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
# checked before anything stops: a setting changed in the app (D-327) edits a tracked file here
git fetch -q origin
changed=$(git diff --name-only HEAD)
for path in $changed; do
  if ! git show "$commit:$path" 2>/dev/null | cmp -s - "$path"; then
    echo "deploy: this checkout has local changes (settings changed in the app?); nothing stopped:" >&2
    git status --short >&2
    echo "copy them into the repository (git diff here shows them), commit, deploy that commit" >&2
    exit 3
  fi
done
# each local change is already in the commit, word for word: the merge brings the same text
[[ -n $changed ]] && git checkout -q HEAD -- $changed && echo "   local changes already in $commit: $changed"
git merge-base --is-ancestor HEAD "$commit" \
  || { echo "deploy: $commit does not follow $(git log -1 --format=%h); nothing stopped" >&2; exit 3; }
timers=$(systemctl --user list-units 'argus-*.timer' --state=active --no-legend --plain | awk '{print $1}')
[[ -n $timers ]] && systemctl --user stop $timers
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
