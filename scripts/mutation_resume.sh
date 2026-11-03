#!/usr/bin/env bash
# Run mutation targets one at a time, skipping each one whose results are newer than STAMP
# (a file touched when the code under test last changed), so an interrupted run resumes at
# the target it was on. Run it detached from any editor or terminal, under a hard memory cap:
# a mutant can turn a loop into one that fills memory (one of capacity.py's reached 13 GB and
# the kernel's OOM killer took VS Code and the desktop with it, 2026-10-13). With the cap the
# runaway test is killed inside this service (it counts as detected) and nothing else is hit.
#
#   touch -d '<time of the last code change>' data/gate/r8/mutation.stamp
#   systemd-run --user --unit=argus-mutation --same-dir --collect --setenv=PATH="$PATH" \
#       -p MemoryMax=4G -p MemorySwapMax=0 -p OOMPolicy=continue -p Nice=19 -p CPUWeight=20 \
#       -p IOWeight=20 \
#       scripts/mutation_resume.sh data/gate/r8/mutation.stamp cx_store cx_worker ...
#   journalctl --user -u argus-mutation -f        # follow it
#   systemctl --user stop argus-mutation          # stop it (kills the test runs too)
set -euo pipefail
stamp=$1
shift
mkdir -p data/gate/r8
for target in "$@"; do
    result=.mutation/results/$target.json
    if [[ -f $result && $result -nt $stamp ]]; then
        echo "== $target: done already ($(date -r "$result" -u +%FT%TZ))"
        continue
    fi
    uv run python scripts/mutation.py "$target" --workers "${WORKERS:-2}" >> data/gate/r8/mutation.log 2>&1 || true  # a score under the floor is a result, not the end
    echo "== $target: finished $(date -u +%FT%TZ)"
done
uv run python scripts/mutation.py --report "$@" > data/gate/r8/mutation-report.txt 2>&1 || true
echo "== all done"
