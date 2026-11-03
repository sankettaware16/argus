#!/usr/bin/env bash
# Q-D1's gate on the local Kibana tier (docs/runbooks/kibana-tier.md, "The gate"): N cycles,
# each from a clean volume (reset, up, seed, a second seed that must change nothing, the whole
# contract suite live against the committed cassettes, which must stay byte for byte as
# committed, with none added), memory sampled throughout against the day-1 budget, no tier
# secret in any of its processes' environment or command line; then the tier is stopped.
#   scripts/heavy.sh --label kibana-gate scripts/kibana_gate.sh [--cycles 2] [--out DIR]
# It must run inside one heavy-task slot (the tier lives as long as the job: D-110), and it
# resets the shared tier: run it only when no other stream needs the tier (`reset` and `down`
# refuse while a live test session holds it).
set -uo pipefail
cycles=2
out=""
while (( $# )); do
  case $1 in
    --cycles) cycles=$2; shift 2 ;;
    --out) out=$2; shift 2 ;;
    *) echo "usage: scripts/kibana_gate.sh [--cycles N] [--out DIR]" >&2; exit 2 ;;
  esac
done
[[ $cycles =~ ^[1-9]$ ]] || { echo "--cycles: 1 to 9" >&2; exit 2; }
[[ -n ${HEAVY_SLOT_HELD:-} ]] || { echo "run it through scripts/heavy.sh (one slot)" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root" || exit 2
out=${out:-$root/data/gate/kibana-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$out"
tier() { uv run python scripts/kibana_tier.py "$@"; }
git rev-parse HEAD > "$out/head.txt"
git status --porcelain --untracked-files=all > "$out/status-at-start.txt"
failed=0
fail() { echo "FAIL: $*" | tee -a "$out/summary.txt"; failed=1; }
note() { echo "$*" | tee -a "$out/summary.txt"; }
note "Q-D1 gate at $(cat "$out/head.txt"), $cycles cycle(s), $(date -u +%FT%TZ)"
for ((n = 1; n <= cycles; n++)); do
  run=$out/cycle$n
  mkdir -p "$run"
  rm -f "$run/stop"
  tier reset --yes > "$run/reset.txt" 2>&1 || fail "cycle $n: reset (rc $?)"
  tier stats --seconds 3600 --interval 2 --until "$run/stop" > "$run/stats.json" 2> "$run/stats.err" &
  stats=$!
  t0=$(date +%s)
  tier up > "$run/up.txt" 2>&1 || fail "cycle $n: up (rc $?)"
  t1=$(date +%s)
  tier seed > "$run/seed.txt" 2>&1 || fail "cycle $n: seed (rc $?)"
  t2=$(date +%s)
  tier seed --expect-kept > "$run/seed2.txt" 2>&1 || fail "cycle $n: the second seed changed something (rc $?)"
  t3=$(date +%s)
  KIBANA_TIER=live timeout 1800 uv run pytest tests/kibana -q -p no:cacheprovider -rs \
    > "$run/pytest.txt" 2>&1 || fail "cycle $n: the contract suite (rc $?)"
  t4=$(date +%s)
  tier status > "$run/status.txt" 2>&1 || fail "cycle $n: status (a secret in a process, or no answer)"
  touch "$run/stop"
  wait "$stats" || fail "cycle $n: memory over the budget or not measured (stats rc $?)"
  git status --porcelain --untracked-files=all -- tests/kibana/cassettes > "$run/cassettes.txt"
  [[ -s $run/cassettes.txt ]] && fail "cycle $n: cassettes written or changed: $(tr '\n' ' ' < "$run/cassettes.txt")"
  note "cycle $n: up $((t1 - t0)) s, seed $((t2 - t1)) s, second seed $((t3 - t2)) s, suite $((t4 - t3)) s: $(grep -E '[0-9]+ (passed|failed)' "$run/pytest.txt" | tail -1)"
  note "cycle $n: memory $(uv run python -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["peak_total_mib"], "MiB peak (budget", d["budget_mib"], "); per container", d["peak_mib"], "; kernel", d["cgroup"], "; host lowest available", d["host_lowest_available_mib"], "MiB")' "$run/stats.json" 2>/dev/null)"
  note "cycle $n: $(grep -E '^secrets in' "$run/status.txt")"
done
tier down > "$out/down.txt" 2>&1 || fail "down (rc $?)"
note "result: $([[ $failed == 0 ]] && echo PASS || echo FAIL) at $(date -u +%FT%TZ); files in $out"
exit "$failed"
