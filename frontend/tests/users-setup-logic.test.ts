// The people dialogs' checks and the setup wizard's answers, exactly as they are sent.
import { describe, expect, it } from "vitest";
import { allProblems, buildSetup, emptySetup, plainFingerprint, readInspected, reviewLines, setupOutput, stepProblems, type SetupForm } from "../src/lib/setup";
import { EMPTY_PERSON, fullLink, newPersonBody, personProblems, readOnlyWhy, roleBody, roleLabel, usernameProblem } from "../src/lib/users";

describe("a new person", () => {
  it("needs a sign-in name of the right shape", () => {
    for (const ok of ["mina", "a1", "asha.rao", "x-y_z", "a".repeat(32)]) expect(usernameProblem(ok)).toBeNull();
    for (const bad of ["", "a", "1abc", "Asha", "a b", "a@b", "a".repeat(33), ".ab"]) expect(usernameProblem(bad)).not.toBeNull();
  });
  it("needs a name, and for a custom role at least one thing", () => {
    expect(Object.keys(personProblems({ ...EMPTY_PERSON, username: "mina", display_name: " " }))).toEqual(["display_name"]);
    expect(personProblems({ ...EMPTY_PERSON, username: "mina", display_name: "Mina" })).toEqual({});
    expect(personProblems({ ...EMPTY_PERSON, username: "mina", display_name: "Mina", role: "custom", capabilities: [] }).capabilities).toBeTruthy();
  });
  it("sends a preset role alone, or the custom set with view and in a fixed order", () => {
    expect(newPersonBody({ username: "mina", display_name: " Mina Rao ", role: "lead", capabilities: ["admin"] })).toEqual({ username: "mina", display_name: "Mina Rao", role: "lead" });
    expect(roleBody("custom", ["approve", "review"])).toEqual({ capabilities: ["view", "review", "approve"] });
  });
  it("says why an ELK or emergency account is read-only", () => {
    expect(readOnlyWhy({ managed_in_elk: true, break_glass: false })).toContain("ELK");
    expect(readOnlyWhy({ managed_in_elk: false, break_glass: true })).toContain("emergency");
    expect(readOnlyWhy({ managed_in_elk: false, break_glass: false })).toBeNull();
  });
  it("names a role, and makes the link whole", () => {
    const roles = [{ key: "analyst", label: "Analyst" }];
    expect(roleLabel({ role: "analyst", capabilities: [] }, roles)).toBe("Analyst");
    expect(roleLabel({ role: "custom", capabilities: ["view", "admin"] }, roles)).toBe("Custom (2 permissions)");
    expect(fullLink("/welcome?t=abc", "https://argus.example")).toBe("https://argus.example/welcome?t=abc");
    expect(fullLink("https://x/welcome", "https://argus.example")).toBe("https://x/welcome");
  });
});

const FP = "AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89";
function filled(more: Partial<SetupForm> = {}): SetupForm {
  return {
    ...emptySetup("Asia/Kolkata"),
    name: "Example University",
    short_name: "CSOC",
    kind: "university",
    own_domains: ["example.edu", " "],
    own_networks: ["203.0.113.0/24"],
    timezone_label: "IST",
    siem_url: "https://siem.example.org:9200",
    siem_trust: "chain",
    siem_fingerprint: FP,
    siem_key: " key-1 ",
    ...more,
  };
}

describe("the setup wizard's answers", () => {
  it("sends exactly these answers and keys, with the SIEM key outside the answers", () => {
    expect(buildSetup(filled())).toEqual({
      answers: {
        "organisation.name": "Example University",
        "organisation.short_name": "CSOC",
        "organisation.kind": "university",
        "organisation.own_domains": ["example.edu"],
        "organisation.own_networks": ["203.0.113.0/24"],
        "organisation.timezone": "Asia/Kolkata",
        "organisation.timezone_label": "IST",
        "organisation.incident_id_prefix": "SOC-IR",
        "siem.url": "https://siem.example.org:9200",
        "siem.trust": "chain",
        "siem.fingerprint": FP,
        "siem.api_key_expires": "90d",
        "siem.log_patterns": ["logs-*"],
        "kibana.url": "none",
        "discovery.accept": true,
        "llm.keys_file": "none",
      },
      keys: { "siem.api_key": "key-1" },
    });
  });
  it("with the system's trust has no fingerprint; an empty label is none; no networks is an empty list", () => {
    const body = buildSetup(filled({ siem_trust: "system", siem_fingerprint: "", timezone_label: " ", own_networks: [] }));
    expect(body.answers).not.toHaveProperty("siem.fingerprint");
    expect(body.answers["siem.trust"]).toBe("system");
    expect(body.answers["organisation.timezone_label"]).toBe("none");
    expect(body.answers["organisation.own_networks"]).toEqual([]);
  });
  it("adds Kibana's answers and key when it is used, and no key means Kibana stays off", () => {
    const on = buildSetup(filled({ use_kibana: true, kibana_url: "https://siem.example.org:5601", kibana_trust: "chain", kibana_fingerprint: FP, kibana_key: "kb", space: "csoc" }));
    expect(on.answers).toMatchObject({ "kibana.url": "https://siem.example.org:5601", "kibana.trust": "chain", "kibana.fingerprint": FP, "organisation.space": "csoc", "kibana.api_key_expires": "90d" });
    expect(on.keys).toEqual({ "siem.api_key": "key-1", "kibana.api_key": "kb" });
    const keyless = buildSetup(filled({ use_kibana: true, kibana_url: "https://k:5601", kibana_trust: "same" }));
    expect(keyless.keys).toEqual({ "siem.api_key": "key-1" });
    expect(keyless.answers).not.toHaveProperty("kibana.api_key_expires");
    expect(keyless.answers).not.toHaveProperty("kibana.fingerprint");
  });
  it("puts no key in any answer and no key in the review", () => {
    const f = filled({ use_kibana: true, kibana_url: "https://k:5601", kibana_key: "kb-secret" });
    const body = buildSetup(f);
    expect(JSON.stringify(body.answers)).not.toContain("key-1");
    expect(JSON.stringify(body.answers)).not.toContain("kb-secret");
    const review = JSON.stringify(reviewLines(f));
    expect(review).not.toContain("key-1");
    expect(review).not.toContain("kb-secret");
    expect(review).toContain("set (read-only)");
  });
});

describe("the wizard's checks", () => {
  it("each step says what is missing", () => {
    expect(Object.keys(stepProblems("organisation", emptySetup("Asia/Kolkata"))).sort()).toEqual(["name", "own_domains", "short_name"]);
    expect(stepProblems("organisation", filled())).toEqual({});
    expect(stepProblems("organisation", filled({ timezone: "Mars/Olympus" })).timezone).toBeTruthy();
    expect(stepProblems("organisation", filled({ own_networks: ["not a net"] })).own_networks).toBeTruthy();
    const siem = stepProblems("siem", emptySetup());
    expect(Object.keys(siem).sort()).toEqual(["siem_key", "siem_trust", "siem_url"]);
    expect(stepProblems("siem", filled({ siem_url: "http://siem:9200" })).siem_url).toBeTruthy();
    expect(stepProblems("siem", filled({ siem_fingerprint: "" })).siem_fingerprint).toBeTruthy();
    expect(stepProblems("siem", filled({ siem_expires: "soon" })).siem_expires).toBeTruthy();
    expect(stepProblems("kibana", filled())).toEqual({});
    expect(stepProblems("kibana", filled({ use_kibana: true })).kibana_url).toBeTruthy();
  });
  it("finds the first step that is not right", () => {
    expect(allProblems(filled())).toBeNull();
    expect(allProblems(filled({ siem_key: "" }))).toBe("siem");
  });
  it("reads a fingerprint however it was written", () => {
    expect(plainFingerprint(FP)).toHaveLength(64);
  });
});

describe("the jobs' answers", () => {
  it("reads the certificate check", () => {
    const seen = readInspected({ url: "https://s:9200", anchor: FP, chain: [{ subject: "CN=siem", issuer: "CN=ca", fingerprint: "AA", not_after: "2027-01-01T00:00:00+00:00", self_signed: false }] });
    expect(seen?.anchor).toBe(FP);
    expect(seen?.chain[0]?.subject).toBe("CN=siem");
    expect(readInspected({ error: "could not be reached" })?.error).toBe("could not be reached");
    expect(readInspected(null)).toBeNull();
  });
  it("reads the setup's output", () => {
    expect(setupOutput({ ok: true, exit: 0, output: ["a", "b"] })).toEqual({ ok: true, lines: ["a", "b"], error: null });
    expect(setupOutput({ error: "boom" }).error).toBe("boom");
  });
});
