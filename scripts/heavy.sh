#!/usr/bin/env bash
# Run one heavy command (a full test suite, mypy over the package, an npm build, Playwright, the
# local Kibana tier's start, a restore drill) in one of a few shared slots, under a memory cap, so
# parallel work never starves production or the desktop on this 31 GB machine (D-110). This is
# the machine's one heavy-task lock (plan §4, Q-A2); docs/runbooks/platform.md says what goes
# through it.
#   scripts/heavy.sh [--mem 3G] [--label text] command...
# Slots: $ARGUS_HEAVY_SLOTS (default 2), shared by every checkout through $ARGUS_HEAVY_DIR.
# Over its cap the command is killed, never a neighbour: the cap holds swap at 0 as well.
# Nested (a heavy command that calls heavy.sh itself, as scripts/gate.sh's steps do when the gate
# runs in a slot): the inner command runs at once, in the slot and under the cap already held; it
# never waits for a second slot, which two such gates would wait for for ever.
# The command never sees the ARGUS_HEAVY_* variables: ARGUS refuses ARGUS_ variables that are not
# settings, so they would stop every `argus` command run in the slot.
set -euo pipefail
dir=${ARGUS_HEAVY_DIR:-$HOME/.cache/argus-heavy}
# the lead may change the number of slots for everyone at once by writing $dir/slots
slots=${ARGUS_HEAVY_SLOTS:-$(cat "$dir/slots" 2>/dev/null || echo 2)}
[[ $slots =~ ^[1-9]$ ]] || slots=2
mem=${ARGUS_HEAVY_MEM:-3G}
label=""
while (( $# )); do
  case $1 in
    --mem) mem=$2; shift 2 ;;
    --label) label=$2; shift 2 ;;
    --) shift; break ;;
    *) break ;;
  esac
done
(( $# )) || { echo "usage: scripts/heavy.sh [--mem 3G] [--label text] command..." >&2; exit 2; }
clean=(env -u ARGUS_HEAVY_SLOTS -u ARGUS_HEAVY_MEM -u ARGUS_HEAVY_DIR)
if [[ -n ${HEAVY_SLOT_HELD:-} ]]; then
  exec "${clean[@]}" "$@"
fi
mkdir -p "$dir"
waited=0
while :; do
  for ((i = 1; i <= slots; i++)); do
    exec {fd}>"$dir/slot-$i.lock"
    if flock -n "$fd"; then
      printf '%s pid=%s %s: %s\n' "$(date -u +%FT%TZ)" "$$" "$PWD" "${label:-$*}" >"$dir/slot-$i.owner"
      if (( waited )); then echo "heavy: slot $i after ${waited} s" >&2; fi
      rc=0
      systemd-run --user --scope --quiet -p MemoryMax="$mem" -p MemorySwapMax=0 -- \
        "${clean[@]}" HEAVY_SLOT_HELD="$i" "$@" || rc=$?
      if (( rc == 137 )); then echo "heavy: killed (over its $mem cap?)" >&2; fi
      exit "$rc"
    fi
    exec {fd}>&-
  done
  if (( waited % 120 == 0 )); then
    echo "heavy: all $slots slots busy; waiting" >&2
    cut -c1-160 "$dir"/slot-*.owner 2>/dev/null | sed 's/^/  /' >&2 || true
  fi
  sleep 5
  waited=$((waited + 5))
done
