// The Settings page's logic: duration text, a draft turned back into a value, the change set that
// sends only what was edited, the typed-words gate, and what a secret may and may not do.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import type { SectionOut, SettingOut } from "../src/client/types.gen";
import { buildChanges, confirmOk, entryList, durationWords, fieldFor, formatDuration, fromDraft, outcomeWords, parseDuration, searchSettings, splitHelp, toDraft, valueWords, worst } from "../src/lib/settings";

function setting(more: Partial<SettingOut>): SettingOut {
  return { key: "history.window", label: "History window", help: "How far back.", kind: "duration", risk: "normal", editable: true, optional: false, choices: [], minimum: null, maximum: null, default: 432000, value: 432000, is_set: null, homes: [], in_app: false, ...more };
}

describe("durations", () => {
  it("are written in the shortest exact unit and read back", () => {
    expect(formatDuration(432_000)).toBe("5d");
    expect(formatDuration(129_600)).toBe("36h");
    expect(formatDuration(900)).toBe("15m");
    expect(formatDuration(90)).toBe("90s");
    expect(formatDuration(0)).toBe("0s");
    expect(parseDuration("5d")).toBe(432_000);
    expect(parseDuration(" 36 H ")).toBe(129_600);
    expect(parseDuration("five days")).toBeNull();
    expect(parseDuration("5")).toBeNull();
    expect(parseDuration("-5d")).toBeNull();
    expect(durationWords(432_000)).toBe("5 days");
    expect(durationWords(3_600)).toBe("1 hour");
  });
  it("round-trip for any whole number of seconds", () => {
    fc.assert(fc.property(fc.integer({ min: 0, max: 10_000_000 }), (n) => parseDuration(formatDuration(n)) === n));
  });
});

describe("a draft as the value to send", () => {
  it("turns each kind into its own type", () => {
    expect(fromDraft(setting({ kind: "int" }), "12")).toEqual({ ok: true, value: 12 });
    expect(fromDraft(setting({ kind: "float" }), "0.5")).toEqual({ ok: true, value: 0.5 });
    expect(fromDraft(setting({ kind: "bool" }), true)).toEqual({ ok: true, value: true });
    expect(fromDraft(setting({ kind: "duration" }), "36 h")).toEqual({ ok: true, value: "36h" });
    expect(fromDraft(setting({ kind: "list" }), ["a", " ", " b "])).toEqual({ ok: true, value: ["a", "b"] });
    expect(fromDraft(setting({ kind: "date" }), "2027-03-01")).toEqual({ ok: true, value: "2027-03-01" });
  });
  it("keeps a list of numbers numeric", () => {
    const s = setting({ kind: "list", value: [80, 443] });
    expect(fromDraft(s, ["80", "8443"])).toEqual({ ok: true, value: [80, 8443] });
    expect(fromDraft(s, ["x"]).ok).toBe(false);
  });
  it("refuses with a reason: bounds, wrong type, empty", () => {
    const n = setting({ kind: "int", minimum: 1, maximum: 10 });
    expect(fromDraft(n, "0")).toEqual({ ok: false, why: "At least 1." });
    expect(fromDraft(n, "11")).toEqual({ ok: false, why: "At most 10." });
    expect(fromDraft(n, "1.5")).toEqual({ ok: false, why: "A whole number." });
    expect(fromDraft(n, "")).toEqual({ ok: false, why: "This cannot be left empty." });
    expect(fromDraft(setting({ kind: "duration" }), "soon").ok).toBe(false);
    expect(fromDraft(setting({ kind: "choice", choices: ["a", "b"] }), "c").ok).toBe(false);
    expect(fromDraft(setting({ kind: "date" }), "1 Mar").ok).toBe(false);
  });
  it("sends null for an empty optional setting", () => {
    expect(fromDraft(setting({ kind: "int", optional: true }), "")).toEqual({ ok: true, value: null });
    expect(fromDraft(setting({ kind: "text", optional: true }), "")).toEqual({ ok: true, value: null });
  });
  it("shows a duration from its seconds and a secret as empty", () => {
    expect(toDraft(setting({ value: 129_600 }))).toBe("36h");
    expect(toDraft(setting({ kind: "secret", value: null, is_set: true }))).toBe("");
    expect(toDraft(setting({ kind: "list", value: ["a", "b"] }))).toEqual(["a", "b"]);
  });
});

describe("the change set", () => {
  const settings = [
    setting({}),
    setting({ key: "web.port", label: "Web port", kind: "int", value: 8765, default: 8765 }),
    setting({ key: "siem.api_key", label: "SIEM key", kind: "secret", value: null, is_set: true, risk: "sensitive" }),
    setting({ key: "kibana.write_classes", label: "Write classes", kind: "list", value: [], risk: "siem_write" }),
    setting({ key: "locked", label: "Locked", editable: false }),
    setting({ key: "ui.thing", label: "Thing", kind: "bool", value: true, in_app: true }),
  ];
  const none = new Set<string>();
  it("sends only the edited fields", () => {
    const out = buildChanges(settings, { "history.window": "36h", "web.port": "8765" }, none);
    expect(out.changes).toEqual([{ key: "history.window", value: "36h" }]);
    expect(out.risk).toBe("normal");
  });
  it("treats the same value written another way as no edit", () => {
    expect(buildChanges(settings, { "history.window": "120h" }, none).changes).toEqual([]);
    expect(buildChanges(settings, { "history.window": "5 d" }, none).changes).toEqual([]);
  });
  it("never sends a setting the app may not change", () => {
    expect(buildChanges(settings, { locked: "432000" }, none).changes).toEqual([]);
  });
  it("sends a typed key, nothing for an empty box, and takes the highest risk", () => {
    expect(buildChanges(settings, { "siem.api_key": "" }, none).changes).toEqual([]);
    const out = buildChanges(settings, { "siem.api_key": " abc ", "kibana.write_classes": ["W1"] }, none);
    expect(out.changes).toEqual([{ key: "siem.api_key", value: "abc" }, { key: "kibana.write_classes", value: ["W1"] }]);
    expect(out.risk).toBe("siem_write");
  });
  it("sends a reset only for a setting that is changed in the app, never for a secret", () => {
    expect(buildChanges(settings, {}, new Set(["ui.thing", "history.window", "siem.api_key"])).changes).toEqual([{ key: "ui.thing", reset: true }]);
  });
  it("reports a field that cannot be sent and sends nothing for it", () => {
    const out = buildChanges(settings, { "web.port": "abc" }, none);
    expect(out.changes).toEqual([]);
    expect(out.errors).toEqual({ "web.port": "A whole number." });
  });
  it("orders risks", () => {
    expect(worst("normal", "sensitive")).toBe("sensitive");
    expect(worst("siem_write", "sensitive")).toBe("siem_write");
  });
});

describe("the confirm words gate", () => {
  const words = "let ARGUS write to the SIEM";
  it("takes the words typed with other spacing or case, and nothing else", () => {
    expect(confirmOk("let ARGUS write to the SIEM", words)).toBe(true);
    expect(confirmOk("  LET argus  write to the siem ", words)).toBe(true);
    expect(confirmOk("let ARGUS write to the", words)).toBe(false);
    expect(confirmOk("", words)).toBe(false);
    expect(confirmOk("", "")).toBe(false);
  });
});

describe("words and search", () => {
  it("says each outcome", () => {
    expect(outcomeWords({ state: "pending", outcome: null })).toContain("Waiting");
    expect(outcomeWords({ state: "applied", outcome: "ARGUS restarted." })).toBe("Applied. ARGUS restarted.");
    expect(outcomeWords({ state: "refused", outcome: "Not a number." })).toBe("Not applied. Not a number.");
    expect(outcomeWords({ state: "rolled_back", outcome: "The web did not start." })).toContain("put back");
  });
  it("never shows a secret, and says a value plainly", () => {
    expect(valueWords(setting({ kind: "secret", value: "hunter2", is_set: true }))).toBe("Set");
    expect(valueWords(setting({ kind: "secret", value: null, is_set: false }))).toBe("Not set");
    expect(valueWords(setting({ value: 129_600 }))).toBe("36 hours");
    expect(valueWords(setting({ kind: "bool", value: false }))).toBe("Off");
  });
  it("finds a setting by label, key or help, every word", () => {
    const sections: SectionOut[] = [{ key: "a", label: "A", about: "", settings: [setting({}), setting({ key: "web.port", label: "Web port", help: "The port people open." })] }];
    expect(searchSettings(sections, "port")[0]?.settings.map((s) => s.key)).toEqual(["web.port"]);
    expect(searchSettings(sections, "history window")[0]?.settings.map((s) => s.key)).toEqual(["history.window"]);
    expect(searchSettings(sections, "").length).toBe(1);
    expect(searchSettings(sections, "nothing like it")).toEqual([]);
  });
  it("splits a long help into its first sentence and More", () => {
    expect(splitHelp("Short.")).toEqual({ short: "Short.", more: null });
    const long = `${"First sentence that is quite long and goes on for a while to explain the whole thing. "}${"Second sentence with the detail. ".repeat(4)}`;
    const { short, more } = splitHelp(long);
    expect(short.endsWith("thing.")).toBe(true);
    expect(more?.startsWith("Second")).toBe(true);
  });
  it("puts a refusal at the setting it names", () => {
    const a = setting({});
    const b = setting({ key: "web.port", label: "Web port" });
    expect(fieldFor("History window: must be at least 1h.", [a, b])).toBe("history.window");
    expect(fieldFor("Something else.", [a, b])).toBeNull();
  });
});

describe("a list of entries (objects)", () => {
  const families = setting({ key: "site.families", label: "Families", kind: "list", value: [{ name: "proxy", pattern: "logs-proxy-*" }], in_app: true });
  it("is known, drafted as readable text and never sent, not even as a reset", () => {
    expect(entryList(families)).toBe(true);
    expect(entryList(setting({ kind: "list", value: ["a"] }))).toBe(false);
    expect(entryList(setting({ kind: "list", value: [] }))).toBe(false);
    expect(toDraft(families)).toEqual(['{"name":"proxy","pattern":"logs-proxy-*"}']);
    expect(buildChanges([families], { "site.families": ["x"] }, new Set(["site.families"])).changes).toEqual([]);
  });
});

describe("the organisation's domains and ranges in Settings", () => {
  const domains = setting({ key: "site.own_domains", label: "Own domains", kind: "list", value: ["example.edu"] });
  const ranges = setting({ key: "site.own_networks", label: "Own networks", kind: "list", value: [] });
  it("refuses a shared suffix or a bare name, and a range without its prefix, before anything is sent", () => {
    expect(fromDraft(domains, ["example.edu", "ac.in"])).toEqual({ ok: false, why: "ac.in is shared by every organisation; give your own, e.g. example.ac.in." });
    expect(fromDraft(domains, ["example"])).toEqual({ ok: false, why: "Give the whole domain, e.g. example.ac.in." });
    expect(fromDraft(domains, ["example.edu", "lab.example.org"])).toEqual({ ok: true, value: ["example.edu", "lab.example.org"] });
    expect(fromDraft(ranges, ["203.0.113.0"])).toEqual({ ok: false, why: "A range is written like 203.0.113.0/24." });
    expect(buildChanges([domains], { "site.own_domains": ["co.uk"] }, new Set()).errors["site.own_domains"]).toContain("co.uk");
  });
});
