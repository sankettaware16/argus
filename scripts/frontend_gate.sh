#!/usr/bin/env bash
# The frontend's gate steps (Q-A2, DQ25), run by scripts/gate.sh when frontend/package.json
# exists, through scripts/heavy.sh (npm installs and builds are heavy):
#   scripts/frontend_gate.sh OUT_DIR
# Node 24 and npm 11 from $NODE24_DIR (default ~/.local/opt/node24), never the system's Node 20.
# Steps: the toolchain; the supply-chain policy (offline: exact pins, install scripts blocked, a
# 14-day release age, no banned package); `npm ci` with install scripts blocked; typecheck,
# lint, Vitest, build; `npm audit` (0 high or critical); `npm audit signatures`; an SBOM
# (CycloneDX); the build's manifest, which `argus doctor` compares with the sources. Each step is
# one PASS or FAIL line; the exit code is 1 if any failed. Output goes to OUT_DIR.
set -uo pipefail
cd "$(dirname "$0")/.."
out=${1:?usage: scripts/frontend_gate.sh OUT_DIR}
mkdir -p "$out" && out=$(cd "$out" && pwd)  # absolute: the steps run in frontend/
if [[ ! -f frontend/package.json ]]; then echo "SKIP  frontend (no frontend/package.json yet)"; exit 0; fi
node_dir=${NODE24_DIR:-$HOME/.local/opt/node24}
export PATH="$node_dir/bin:$PATH"
export npm_config_ignore_scripts=true npm_config_fund=false npm_config_update_notifier=false
fail=0
record() { if [ "$1" -eq 0 ]; then echo "PASS  $2"; else echo "FAIL  $2"; fail=1; fi; }
step() { # step NAME LOGFILE command...: runs it in frontend/, its output to OUT_DIR/LOGFILE
  local name=$1 log=$2; shift 2
  (cd frontend && "$@") >"$out/$log" 2>&1
  record $? "$name"
}

node_v=$("$node_dir/bin/node" --version 2>/dev/null || true)
npm_v=$(npm --version 2>/dev/null || true)
[[ $node_v == v24.* && $npm_v == 11.* && $(command -v node) == "$node_dir/bin/node" ]]
record $? "toolchain: Node ${node_v:-missing}, npm ${npm_v:-missing} ($node_dir)"
if (( fail )); then echo "frontend gate stopped: no Node 24 / npm 11 at $node_dir"; exit 1; fi

uv run --quiet python scripts/frontend_build.py policy >"$out/policy.txt" 2>&1
record $? "supply-chain policy ($(tail -1 "$out/policy.txt"))"
step "npm ci (install scripts blocked)" npm-ci.txt npm ci --ignore-scripts --no-audit
step "typecheck" typecheck.txt npm run --silent typecheck
step "lint" lint.txt npm run --silent lint
step "Vitest" vitest.txt npm run --silent test
step "build" build.txt npm run --silent build
step "npm audit (0 high or critical)" audit.txt npm audit --audit-level=high
step "npm audit signatures" signatures.txt npm audit signatures
# the installed tree (what `npm ci` just made from the lockfile for this machine): the lockfile
# alone fails on optional packages for other platforms whose own dependencies npm never records
# (Tailwind's wasm32 build, Q-B1)
sbom() { npm sbom --sbom-format cyclonedx >"$out/sbom.cdx.json"; }
step "SBOM (CycloneDX)" sbom.txt sbom
uv run --quiet python scripts/frontend_build.py manifest >"$out/manifest.txt" 2>&1
record $? "build manifest ($(tail -1 "$out/manifest.txt"))"
exit $fail
