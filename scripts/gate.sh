#!/usr/bin/env bash
# Component gate runner: every automated check a gate report quotes, in one place.
#   scripts/gate.sh            → static checks, dependency audit, full suite (Hypothesis "gate"
#                                profile, all logs captured), secret scan of the session output,
#                                coverage, and the frontend's gate steps once frontend/ exists.
#                                Mutation testing: scripts/gate.sh --mutation
# Output: data/gate/<timestamp>/ (gitignored) — session.log, coverage, summary.txt
# Never touches the SIEM (the test harness blocks it; --run-live is not used here).
# Heavy steps (mypy over the package, the full suite, the frontend's npm steps, mutation) each
# take a slot of scripts/heavy.sh, the machine's heavy-task lock (D-110, Q-A2); run inside a
# slot already (scripts/heavy.sh scripts/gate.sh), they use that one. Memory caps:
# GATE_MEM_SUITE (default 4G), GATE_MEM_MYPY (2G), GATE_MEM_FRONTEND (3G), GATE_MEM_MUTATION (4G).
set -uo pipefail
cd "$(dirname "$0")/.."
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
OUT=data/gate/$STAMP
mkdir -p "$OUT" && chmod 700 data/gate "$OUT"
SUMMARY=$OUT/summary.txt
fail=0
step() { printf '\n== %s ==\n' "$1" | tee -a "$SUMMARY"; }
record() { if [ "$1" -eq 0 ]; then echo "PASS  $2" | tee -a "$SUMMARY"; else echo "FAIL  $2" | tee -a "$SUMMARY"; fail=1; fi; }
heavy() { # heavy MEM LABEL command...: in a slot of the heavy-task lock
  local mem=$1 label=$2; shift 2
  scripts/heavy.sh --mem "$mem" --label "gate: $label" "$@"
}

step "static checks"
uv run ruff check . >"$OUT/ruff.txt" 2>&1; record $? "ruff check"
uv run ruff format --check . >"$OUT/format.txt" 2>&1; record $? "ruff format --check"
heavy "${GATE_MEM_MYPY:-2G}" mypy uv run mypy >"$OUT/mypy.txt" 2>&1
record $? "mypy --strict ($(tail -1 "$OUT/mypy.txt"))"

step "dependency audit"
uv export --locked --format requirements-txt --no-hashes --no-emit-project >"$OUT/requirements.txt" 2>/dev/null
uvx --quiet pip-audit -r "$OUT/requirements.txt" --progress-spinner off >"$OUT/pip-audit.txt" 2>&1
record $? "pip-audit ($(tail -1 "$OUT/pip-audit.txt"))"

step "full test suite (Hypothesis profile: gate, all log output captured)"
heavy "${GATE_MEM_SUITE:-4G}" "full suite" env HYPOTHESIS_PROFILE=gate \
  uv run pytest -p no:cacheprovider -rA -o log_cli=true --log-cli-level=DEBUG \
  --cov --cov-branch --cov-report=term-missing:skip-covered --cov-report=json:"$OUT/coverage.json" \
  >"$OUT/session.log" 2>&1
rc=$?
record $rc "pytest ($(grep -E '^=+ .*(passed|failed|error).* =+$' "$OUT/session.log" | tail -1 | tr -d '='))"

step "secret scan of the whole session output"
uv run --quiet python scripts/secret_scan.py "$OUT/session.log" >"$OUT/secret-scan.txt" 2>&1
record $? "secret scan ($(tail -1 "$OUT/secret-scan.txt"))"

step "fixtures: leak scan, asset networks, regeneration (R2; needs the local raw sources)"
uv run python scripts/sanitize_fixtures.py verify >"$OUT/fixtures-verify.txt" 2>&1
record $? "fixtures verify ($(grep -h '^verify:' "$OUT/fixtures-verify.txt" | tail -1))"
uv run python scripts/sanitize_fixtures.py check-assets --samples 256 >"$OUT/check-assets.txt" 2>&1
record $? "$(tail -1 "$OUT/check-assets.txt")"
uv run python scripts/sanitize_fixtures.py samples --out "$OUT/regenerated" >"$OUT/regenerate.txt" 2>&1 \
  && diff -r tests/fixtures/alerts "$OUT/regenerated" >>"$OUT/regenerate.txt" 2>&1
record $? "fixtures regenerate byte-identical"

step "coverage"
python3 -I -c "
import json; d = json.load(open('$OUT/coverage.json'))['totals']
print(f\"branch coverage {d['percent_covered']:.1f}% ({d['covered_lines']}/{d['num_statements']} lines, {d['covered_branches']}/{d['num_branches']} branches)\")
" | tee -a "$SUMMARY"

if [ -f frontend/package.json ]; then
  step "frontend (Node 24, npm 11: DQ25)"
  heavy "${GATE_MEM_FRONTEND:-3G}" frontend scripts/frontend_gate.sh "$OUT/frontend" >"$OUT/frontend.txt" 2>&1
  rc=$?
  grep -E '^(PASS|FAIL|SKIP)' "$OUT/frontend.txt" | sed 's/^/  /' | tee -a "$SUMMARY"
  record $rc "frontend gate steps ($(grep -c '^PASS' "$OUT/frontend.txt") passed, $(grep -c '^FAIL' "$OUT/frontend.txt") failed)"
fi

if [ "${1:-}" = "--mutation" ]; then
  step "mutation testing"
  heavy "${GATE_MEM_MUTATION:-4G}" mutation uv run python scripts/mutation.py >"$OUT/mutation.txt" 2>&1
  record $? "mutation testing (D-040)"
  uv run python scripts/mutation.py --report >>"$OUT/mutation.txt" 2>&1
fi

step "result"
if [ $fail -eq 0 ]; then echo "GATE CHECKS PASSED — $OUT" | tee -a "$SUMMARY"; else echo "GATE CHECKS FAILED — see $OUT" | tee -a "$SUMMARY"; fi
exit $fail
