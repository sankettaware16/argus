#!/usr/bin/env python3
"""The frontend's offline gate steps (Q-A2, DQ25), for scripts/frontend_gate.sh:

    uv run python scripts/frontend_build.py policy    # pins, scripts blocked, 14-day age, bans
    uv run python scripts/frontend_build.py manifest  # after `npm run build`: what it came from

The manifest goes into the committed build (argus.ops.frontend.BUILD_DIR); `argus doctor` compares
it with the sources to tell a stale build.
"""

from __future__ import annotations

import sys

from argus.ops import frontend


def main(argv: list[str]) -> int:
    if argv[1:] == ["policy"]:
        problems = frontend.policy_problems()
        for problem in problems:
            print(f"policy: {problem}")
        print(f"policy: {len(problems)} problems" if problems else "policy: OK")
        return 1 if problems else 0
    if argv[1:] == ["manifest"]:
        chain = frontend.toolchain()
        if chain.problem is not None or chain.node is None or chain.npm is None:
            print(f"manifest: {chain.problem}")
            return 1
        made = frontend.write_manifest(
            frontend.BUILD_DIR, frontend.FRONTEND_DIR, chain.node, chain.npm
        )
        print(f"manifest: sources {made['sources_sha256'][:12]}, Node {made['node']}")
        return 0
    print(__doc__.strip(), file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
