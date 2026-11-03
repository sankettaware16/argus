import { cleanup, configure as configureDom } from "@testing-library/react";
import fc from "fast-check";
import { afterEach, beforeEach } from "vitest";
import { setSite } from "../src/lib/site";
import { EXAMPLE_SITE } from "./exampleSite";

// The property runs follow the Python suite's profiles (plan §4): dev 100, ci 1,000, gate 10,000.
const RUNS: Record<string, number> = { dev: 100, ci: 1_000, gate: 10_000 };
fc.configureGlobal({ numRuns: RUNS[process.env.HYPOTHESIS_PROFILE ?? "dev"] ?? 100 });

// the machine runs other work: a page that is drawn in 100 ms on a quiet one may need seconds
configureDom({ asyncUtilTimeout: 8_000 });

// every test starts on the suite's site section (see exampleSite.ts), whatever the one before it set
beforeEach(() => setSite(EXAMPLE_SITE));
afterEach(() => cleanup());
