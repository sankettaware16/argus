// The logic of "AI and agents", Costs and usage and the admin jobs (D-328, D-329): money in words,
// the models by size, a provider's and a task's own settings, the change set (an emptied provider
// list is "all"), the summary, a job's outcome, an asset file's checks, the 31-day series, limits.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { AiDayOut, JobOut, SettingOut } from "../src/client/types.gen";
import { assetFileProblem, ASSET_MAP_MAX, jobOutcome } from "../src/lib/admin";
import { aiChanges, aiLabels, aiSummary, byKey, callsWords, modelsBySize, providerSettings, purposeSettings, readingSetting, spendWords } from "../src/lib/ai";
import { niceCeil } from "../src/lib/chart";
import { buildChanges } from "../src/lib/settings";
import { againstCap, aiSeries, dayLimit, lastDay, lastDays, limitWords, providerOrder, sourceSeries, sourceState, taskLabel, usd } from "../src/lib/usage";

function setting(more: Partial<SettingOut> & { key: string }): SettingOut {
  return { label: "On", help: "", kind: "bool", risk: "normal", editable: true, optional: false, choices: [], minimum: null, maximum: null, default: null, value: null, is_set: null, homes: [], in_app: false, ...more };
}
const job = (more: Partial<JobOut>): JobOut => ({ id: 1, kind: "check", state: "done", result: null, created_at: "2026-11-16T10:00:00Z", finished_at: null, ...more });

describe("money", () => {
  it("is USD with two decimals, four under a cent", () => {
    expect(usd(0)).toBe("$0.00");
    expect(usd(1.2)).toBe("$1.20");
    expect(usd(0.0042)).toBe("$0.0042");
    expect(usd(0.01)).toBe("$0.01");
    expect(usd(1234.5)).toBe("$1,234.50");
    expect(againstCap(1, 10)).toBe("$1.00 of $10.00");
    expect(againstCap(1, null)).toBe("$1.00 (no limit)");
    expect(spendWords(0.5, null)).toBe("$0.50 (no limit of its own)");
    expect(spendWords(0.5, 2, "x")).toBe("$0.50 of $2.00");
  });

  it("puts a round axis top at or above any amount", () => {
    fc.assert(
      fc.property(fc.double({ min: 0, max: 1e5, noNaN: true }), (x) => {
        const top = niceCeil(x);
        expect(top).toBeGreaterThanOrEqual(Math.max(x, 0.01));
        expect(top).toBeLessThanOrEqual(Math.max(x, 0.01) * 1.34); // the widest gap: just over 1.5 → 2
      }),
    );
    expect(niceCeil(0)).toBe(0.01);
    expect(niceCeil(0.42)).toBe(0.5);
    expect(niceCeil(3.1)).toBe(4);
    expect(niceCeil(0.015000000015)).toBeGreaterThanOrEqual(0.015000000015);
  });
});

describe("the AI page's logic", () => {
  const settings = [
    setting({ key: "llm.providers.alpha.enabled" }),
    setting({ key: "llm.providers.alpha.monthly_cap_usd", label: "Its monthly limit (USD)", kind: "float" }),
    setting({ key: "llm.keys.ALPHA_KEY", label: "alpha: ALPHA_KEY", kind: "secret" }),
    setting({ key: "llm.purposes.story.providers", label: "Providers, in order", kind: "list", optional: true, choices: ["alpha", "beta"], value: ["alpha"] }),
    setting({ key: "llm.purposes.story.tier", label: "Model size", kind: "choice", optional: true, choices: ["small", "large"], value: "small" }),
    setting({ key: "llm.monthly_cap_usd", label: "Monthly limit (USD)", kind: "float", value: 10 }),
  ];
  const all = byKey(settings);

  it("orders the models by size, an unknown size last", () => {
    expect(modelsBySize({ large: "l", other: "o", small: "s", medium: "m" })).toEqual([["small", "s"], ["medium", "m"], ["large", "l"], ["other", "o"]]);
  });

  it("finds a provider's and a task's own settings", () => {
    const own = providerSettings(all, { name: "alpha", keys: [{ name: "ALPHA_KEY", setting: "llm.keys.ALPHA_KEY", is_set: false }] });
    expect(own.enabled?.key).toBe("llm.providers.alpha.enabled");
    expect(own.daily).toBeUndefined();
    expect(own.keys[0]?.setting?.kind).toBe("secret");
    expect(purposeSettings(all, "story").tier?.value).toBe("small");
    expect(purposeSettings(all, "opinion").calls).toBeUndefined();
  });

  it("sends an emptied provider list as all (null), and anything else as typed", () => {
    const built = buildChanges(settings, { "llm.purposes.story.providers": [], "llm.purposes.story.tier": "large" }, new Set());
    expect(aiChanges(built, settings).changes).toEqual([
      { key: "llm.purposes.story.providers", value: null },
      { key: "llm.purposes.story.tier", value: "large" },
    ]);
  });

  it("labels the outcome by provider and task", () => {
    const labels = aiLabels({ settings, purposes: [{ task: "story", label: "Readings", calls_per_day: null, providers: null, tier: null, calls_today: 0 }] });
    expect(labels.get("llm.providers.alpha.enabled")).toBe("alpha: On");
    expect(labels.get("llm.purposes.story.tier")).toBe("Readings: Model size");
    expect(labels.get("llm.monthly_cap_usd")).toBe("Monthly limit (USD)");
  });

  it("makes the readings switch from the page's value, Settings' entry when there is one", () => {
    expect(readingSetting(true)).toMatchObject({ key: "risk.reading", kind: "bool", value: true, risk: "normal" });
    expect(readingSetting(false, setting({ key: "risk.reading", label: "Reading", value: true, in_app: true }))).toMatchObject({ label: "Reading", value: false, in_app: true });
  });

  it("says the state of the AI first", () => {
    const p = (name: string, enabled: boolean, set: boolean) => ({ name, enabled, keys: [{ name: "K", setting: "llm.keys.K", is_set: set }] }) as never;
    expect(aiSummary({ stopped: true, any_key: true, providers: [] })).toContain("All AI calls are stopped");
    expect(aiSummary({ stopped: false, any_key: false, providers: [] })).toBe("The AI is off: add a key for at least one provider below. ARGUS still works without it.");
    expect(aiSummary({ stopped: false, any_key: true, providers: [p("alpha", true, true), p("beta", false, true), p("gamma", true, false)] })).toBe("The AI is on: 1 provider is switched on with a key (alpha).");
    expect(callsWords(0, 0)).toBe("No calls this month");
    expect(callsWords(1, 1)).toBe("1 call this month, 1 answered");
  });
});

describe("a job's outcome", () => {
  it("is waiting until settled, then passed only when done and ok", () => {
    expect(jobOutcome(undefined).state).toBe("none");
    expect(jobOutcome(job({ state: "running" })).state).toBe("waiting");
    expect(jobOutcome(job({ result: { ok: true, output: ["a", 2] } }))).toEqual({ state: "passed", lines: ["a", "2"], error: null });
    expect(jobOutcome(job({ result: { ok: false, output: [] } })).state).toBe("failed");
    expect(jobOutcome(job({ state: "failed", result: { error: "too slow" } }))).toEqual({ state: "failed", lines: [], error: "too slow" });
    expect(jobOutcome(job({ state: "failed", result: { ok: true } })).state).toBe("failed");
  });
});

describe("an asset map file", () => {
  it("must be YAML, not empty and at most 5 MB", () => {
    expect(assetFileProblem("map.yaml", 10)).toBeNull();
    expect(assetFileProblem("MAP.YML", ASSET_MAP_MAX)).toBeNull();
    expect(assetFileProblem("map.yaml", ASSET_MAP_MAX + 1)).toContain("larger than 5 MB");
    expect(assetFileProblem("map.yaml", 0)).toBe("The file is empty.");
    expect(assetFileProblem("map.json", 10)).toBe("Choose a .yaml or .yml file.");
    expect(assetFileProblem("map.yaml.txt", 10)).toBe("Choose a .yaml or .yml file.");
  });
});

describe("the usage series", () => {
  it("has the 31 days up to the last one, every day present", () => {
    const days = lastDays("2026-03-01");
    expect(days.length).toBe(31);
    expect(days[0]).toBe("2026-01-30");
    expect(days[30]).toBe("2026-03-01");
    expect(lastDays("not a day")).toEqual([]);
    expect(lastDay(["2026-11-18", "2026-11-01"], "2026-11-17")).toBe("2026-11-18");
  });

  it("stacks the AI's spend a day by provider and keeps every day's total", () => {
    const rows: AiDayOut[] = [
      { day: "2026-11-16", provider: "beta", calls: 1, ok: 1, cost_usd: 0.1, tokens: 1 },
      { day: "2026-11-16", provider: "alpha", calls: 1, ok: 1, cost_usd: 0.3, tokens: 1 },
      { day: "2026-11-17", provider: "beta", calls: 1, ok: 1, cost_usd: 0.05, tokens: 1 },
      { day: "2026-09-01", provider: "gamma", calls: 1, ok: 1, cost_usd: 9, tokens: 1 },
    ];
    const days = lastDays("2026-11-17");
    const series = aiSeries(rows, days);
    expect(series.length).toBe(31);
    expect(series[29]).toEqual({ at: "2026-11-16T00:00:00", counts: { beta: 0.1, alpha: 0.3 } });
    expect(series[0]?.counts).toEqual({});
    expect(providerOrder(rows)).toEqual(["gamma", "alpha", "beta"]);
    expect(sourceSeries([{ day: "2026-11-17", requests: 4 }], days).at(-1)).toEqual({ at: "2026-11-17T00:00:00", counts: { lookups: 4 } });
  });

  it("says a source's limits and its state", () => {
    expect(limitWords([{ window: "minute", maximum: 3 }, { window: "day", maximum: 1000 }])).toBe("3 a minute, 1,000 a day");
    expect(limitWords([])).toBe("no limit");
    expect(dayLimit([{ window: "month", maximum: 50 }])).toBeNull();
    expect(dayLimit([{ window: "day", maximum: 10 }])).toBe(10);
    expect(sourceState(true, null)).toEqual({ on: true, words: "On" });
    expect(sourceState(false, true)).toEqual({ on: true, words: "On without a key (InternetDB)" });
    expect(sourceState(false, false).on).toBe(false);
    expect(taskLabel("opinion")).toBe("Second opinions on P1 incidents");
    expect(taskLabel("other")).toBe("other");
  });
});
