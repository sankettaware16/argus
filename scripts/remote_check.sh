#!/usr/bin/env bash
# A read-only look at an ARGUS installation on another machine, over SSH:
#   scripts/remote_check.sh argus@<host> [checkout, default ~/argus] [hours, default 24]
# What runs there: git log/status, systemctl --user show/list (no start, stop or restart),
# journalctl counts, `argus doctor`, `argus llm status`, `argus collect status`, and one
# read-only query of the LLM ledger. Nothing is written on the remote machine.
set -euo pipefail

target=${1:?usage: remote_check.sh user@host [checkout] [hours]}
dir=${2:-'~/argus'}
hours=${3:-24}
[[ $hours =~ ^[0-9]+$ ]] || { echo "hours: a whole number" >&2; exit 2; }

ssh -o BatchMode=yes -o ConnectTimeout=10 "$target" bash -s -- "$dir" "$hours" <<'REMOTE'
set -uo pipefail
dir=$1 hours=$2
cd "${dir/#\~/$HOME}" || exit 1
export PATH=$HOME/.local/bin:$PATH
echo "== code";   git log -1 --format='%h %cI %s'; git status --short | head -20
echo "== load";   uptime
echo "== units"
systemctl --user list-units 'argus-*' --all --no-pager --plain --no-legend \
  | awk '{printf "  %-34s %s %s\n", $1, $3, $4}'
echo "== failures in the last ${hours} h (per unit)"
for u in $(systemctl --user list-units 'argus-*.service' --all --no-legend --plain | awk '{print $1}'); do
  n=$(journalctl --user -u "$u" --since "-${hours}h" --no-pager -o cat 2>/dev/null \
      | grep -c -E "Traceback|Failed with result|ERROR" || true)
  [[ $n -gt 0 ]] && printf "  %-34s %s\n" "$u" "$n"
done
echo "== doctor (FAIL and WARN only)"
timeout 150 uv run argus doctor 2>&1 | grep -E "^(FAIL|WARN)" | cut -c1-200
echo "== llm"
timeout 60 uv run argus llm status 2>&1 | grep -E "^(kill|this month|today)|^  [a-z]" | cut -c1-160
echo "== collector"
timeout 60 uv run argus collect status 2>&1 | head -8
echo "== ledger, last ${hours} h (provider tier outcome status: calls, USD)"
timeout 60 uv run python - "$hours" <<'PY'
import asyncio, sys
from sqlalchemy import text
from argus.config.settings import load_settings
from argus.db.engine import create_engine

async def main(hours: int) -> None:
    engine = create_engine(load_settings().database)
    async with engine.connect() as c:
        await c.execute(text("set transaction read only"))
        rows = await c.execute(text(
            "select provider, tier, outcome, http_status, count(*), round(sum(cost_usd)::numeric, 4)"
            " from llm_calls where at > now() - make_interval(hours => :h)"
            " group by 1, 2, 3, 4 order by 1, 2, 5 desc"), {"h": hours})
        for r in rows:
            print("  ", *r)
    await engine.dispose()

asyncio.run(main(int(sys.argv[1])))
PY
REMOTE
