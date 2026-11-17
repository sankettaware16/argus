// The people dialogs' checks and the setup wizard's answers, exactly as they are sent.
import { describe, expect, it } from "vitest";
import { aiKeyName, allProblems, caProblem, errorChapter, loneLeafIssuer, tidyUrl, domainProblem, markSetupLeft, networkProblem, opensSetup, setupLeft, buildSetup, CASE_TEAM_USERS, elasticPlan, emptySetup, plainFingerprint, readInspected, reviewLines, runChecklist, setupOutput, stepProblems, STEPS, type SetupForm } from "../src/lib/setup";
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
    access: "paste",
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
        "elastic.admin_user": "none",
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

describe("the setup with an administrator's login (D-330)", () => {
  const login = (more: Partial<SetupForm> = {}) => filled({ access: "login", siem_key: "", admin_user: " elastic-admin ", admin_password: "pa ss", ...more });
  it("sends the user name as an answer and the password only as a key, with no pasted key", () => {
    const body = buildSetup(login());
    expect(body.answers["elastic.admin_user"]).toBe("elastic-admin");
    expect(body.keys).toEqual({ "elastic.admin_password": "pa ss" });
    expect(body.answers).not.toHaveProperty("siem.api_key_expires");
    expect(JSON.stringify(body.answers)).not.toContain("pa ss");
  });
  it("makes Kibana's key and, when asked, the case team; never sends a pasted Kibana key", () => {
    const body = buildSetup(login({ use_kibana: true, kibana_url: "https://siem.example.org:5601", kibana_key: "kb" }));
    expect(body.answers["case_team.provision"]).toBe(true);
    expect(body.keys).toEqual({ "elastic.admin_password": "pa ss" });
    expect(body.answers).not.toHaveProperty("kibana.api_key_expires");
    expect(buildSetup(login({ use_kibana: true, kibana_url: "https://k:5601", provision_team: false })).answers).not.toHaveProperty("case_team.provision");
    expect(buildSetup(login()).answers).not.toHaveProperty("case_team.provision");
  });
  it("says exactly what it will create in Elastic, and nothing for pasted keys", () => {
    expect(elasticPlan(filled())).toEqual([]);
    expect(elasticPlan(login())).toHaveLength(1);
    const all = elasticPlan(login({ use_kibana: true, kibana_url: "https://k:5601" }));
    expect(all).toHaveLength(4);
    expect(all[0]).toContain("argus-reader");
    expect(all[1]).toContain("argus-kibana-reader");
    expect(all[2]).toContain("argus_case_lead");
    for (const user of CASE_TEAM_USERS) expect(all[3]).toContain(user);
    expect(elasticPlan(login({ use_kibana: true, kibana_url: "https://k:5601", provision_team: false }))).toHaveLength(2);
  });
  it("never puts the password in the review", () => {
    const review = JSON.stringify(reviewLines(login()));
    expect(review).not.toContain("pa ss");
    expect(review).toContain("never stored");
  });
});

describe("the optional chapters", () => {
  it("sends each AI key under its setup name, the threat-intel keys and the asset map; empty ones not at all", () => {
    expect(aiKeyName("GROQ_API_KEY")).toBe("llm.key.groq_api_key");
    const body = buildSetup(filled({ ai_keys: { GROQ_API_KEY: " g1 ", OPENAI_API_KEY: " " }, intel_keys: { virustotal: "vt", shodan: "", censys: " " }, asset_map: { name: "assets.yaml", content: "networks: []\n" } }));
    expect(body.keys).toEqual({ "siem.api_key": "key-1", "llm.key.groq_api_key": "g1", "outside.virustotal_api_key": "vt" });
    expect(body.asset_map).toBe("networks: []\n");
    expect(buildSetup(filled())).not.toHaveProperty("asset_map");
    const review = reviewLines(filled({ ai_keys: { GROQ_API_KEY: "g1" }, intel_keys: { virustotal: "vt", shodan: "", censys: "" }, asset_map: { name: "assets.yaml", content: "x" } }));
    const said = Object.fromEntries(review.map((l) => [l.label, l.value]));
    expect(said["AI providers"]).toBe("1 key set");
    expect(said["Threat intel"]).toBe("VirusTotal: key set");
    expect(said["Asset map"]).toContain("assets.yaml");
    expect(JSON.stringify(review)).not.toContain("g1");
  });
  it("skipped, they say where to add them later", () => {
    const said = Object.fromEntries(reviewLines(filled()).map((l) => [l.label, l.value]));
    expect(said["AI providers"]).toContain("later in AI and agents");
    expect(said["Threat intel"]).toContain("later in Threat intel");
    expect(said["Asset map"]).toContain("Settings");
  });
  it("are marked optional and in this order", () => {
    expect(STEPS.map((s) => s.key)).toEqual(["organisation", "siem", "access", "kibana", "ai", "intel", "assets", "review"]);
    expect(STEPS.filter((s) => s.optional).map((s) => s.key)).toEqual(["ai", "intel", "assets"]);
  });
  it("the run's checklist follows what was chosen", () => {
    expect(runChecklist(filled())).toEqual(["Check the SIEM and its certificate", "Check the read-only key", "Discover your log families", "Write the configuration and start the services"]);
    const all = runChecklist(filled({ access: "login", use_kibana: true, intel_keys: { virustotal: "vt", shodan: "", censys: "" }, asset_map: { name: "a.yaml", content: "x" } }));
    expect(all).toContain("Make ARGUS's read-only keys");
    expect(all).toContain("Make the Kibana case team");
    expect(all.slice(-2)).toEqual(["Store the AI and threat-intel keys", "Import the asset map"]);
  });
});

describe("the wizard's checks", () => {
  it("each step says what is missing", () => {
    expect(Object.keys(stepProblems("organisation", emptySetup("Asia/Kolkata"))).sort()).toEqual(["name", "own_domains", "short_name"]);
    expect(stepProblems("organisation", filled())).toEqual({});
    expect(stepProblems("organisation", filled({ timezone: "Mars/Olympus" })).timezone).toBeTruthy();
    expect(stepProblems("organisation", filled({ own_networks: ["not a net"] })).own_networks).toBeTruthy();
    expect(Object.keys(stepProblems("siem", emptySetup())).sort()).toEqual(["siem_trust", "siem_url"]);
    expect(stepProblems("siem", filled({ siem_url: "http://siem:9200" })).siem_url).toBeTruthy();
    expect(stepProblems("siem", filled({ siem_fingerprint: "" })).siem_fingerprint).toBeTruthy();
    expect(Object.keys(stepProblems("access", emptySetup()))).toEqual(["access"]);
    expect(Object.keys(stepProblems("access", filled({ siem_key: "", siem_expires: "soon" }))).sort()).toEqual(["siem_expires", "siem_key"]);
    expect(Object.keys(stepProblems("access", filled({ access: "login" }))).sort()).toEqual(["admin_password", "admin_user"]);
    expect(stepProblems("access", filled({ access: "login", admin_user: "a b", admin_password: "x" })).admin_user).toBeTruthy();
    expect(stepProblems("access", filled({ access: "login", admin_user: "admin", admin_password: "x" }))).toEqual({});
    expect(stepProblems("kibana", filled())).toEqual({});
    expect(stepProblems("kibana", filled({ use_kibana: true })).kibana_url).toBeTruthy();
    expect(stepProblems("ai", filled({ ai_keys: { GROQ_API_KEY: "a\nb" } }))["ai.GROQ_API_KEY"]).toBeTruthy();
    expect(stepProblems("intel", filled({ intel_keys: { virustotal: "a\nb", shodan: "", censys: "" } }))["intel.virustotal"]).toBeTruthy();
  });
  it("finds the first step that is not right", () => {
    expect(allProblems(filled())).toBeNull();
    expect(allProblems(filled({ siem_key: "" }))).toBe("access");
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
    expect(setupOutput({ ok: true, exit: 0, output: ["a", "b"] })).toEqual({ ok: true, lines: ["a", "b"], error: null, after: [] });
    expect(setupOutput({ ok: true, output: [], after: ["Virustotal api key: stored", "asset map: imported"] }).after).toEqual(["Virustotal api key: stored", "asset map: imported"]);
    expect(setupOutput({ error: "boom" }).error).toBe("boom");
  });
});

describe("own domains and public ranges", () => {
  it("refuses a bare name and a suffix every organisation shares, whatever its case", () => {
    expect(domainProblem("example.ac.in")).toBeNull();
    expect(domainProblem("Example.EDU")).toBeNull();
    expect(domainProblem(" ")).toBeNull();
    expect(domainProblem("example")).toBe("Give the whole domain, e.g. example.ac.in.");
    expect(domainProblem("in")).toBe("Give the whole domain, e.g. example.in.");
    expect(domainProblem("ac.in")).toBe("ac.in is shared by every organisation; give your own, e.g. example.ac.in.");
    expect(domainProblem("CO.UK.")).toBe("co.uk is shared by every organisation; give your own, e.g. example.co.uk.");
    expect(domainProblem("exa mple.org")).toContain("A domain looks like");
  });
  it("takes a range as an address and a prefix", () => {
    expect(networkProblem("203.0.113.0/24")).toBeNull();
    expect(networkProblem("2001:db8::/32")).toBeNull();
    expect(networkProblem("203.0.113.0")).toBe("A range is written like 203.0.113.0/24.");
  });
  it("blocks the chapter on the first wrong row", () => {
    expect(stepProblems("organisation", filled({ own_domains: ["example.edu", "edu"] })).own_domains).toContain("edu");
    expect(stepProblems("organisation", filled({ own_networks: ["198.51.100.0/24", "x"] })).own_networks).toBeTruthy();
  });
});

describe("the setup opening by itself", () => {
  it("opens for an administrator while it is pending, not on its own page, not after they left it", () => {
    expect(opensSetup(true, true, "/", false)).toBe(true);
    expect(opensSetup(true, true, "/incidents", false)).toBe(true);
    expect(opensSetup(true, true, "/setup", false)).toBe(false);
    expect(opensSetup(true, true, "/", true)).toBe(false);
    expect(opensSetup(true, false, "/", false)).toBe(false);
    expect(opensSetup(false, true, "/", false)).toBe(false);
  });
  it("remembers leaving it for the browser session", () => {
    window.sessionStorage.clear();
    expect(setupLeft()).toBe(false);
    markSetupLeft();
    expect(setupLeft()).toBe(true);
    window.sessionStorage.clear();
  });
});

const PEM = "-----BEGIN CERTIFICATE-----\nMIIBexample\n-----END CERTIFICATE-----\n";

describe("a CA certificate uploaded in the setup", () => {
  it("is sent as the CA's text, with no trust or fingerprint (the server trusts that file)", () => {
    const body = buildSetup(filled({ siem_trust: "file", siem_ca: { name: "ca.crt", pem: PEM }, siem_fingerprint: "" }));
    expect(body.answers["siem.ca_pem"]).toBe(PEM);
    expect(body.answers).not.toHaveProperty("siem.trust");
    expect(body.answers).not.toHaveProperty("siem.fingerprint");
    const kibana = buildSetup(filled({ use_kibana: true, kibana_url: "https://k:5601", kibana_trust: "file", kibana_ca: { name: "", pem: PEM } }));
    expect(kibana.answers["kibana.ca_pem"]).toBe(PEM);
    expect(kibana.answers).not.toHaveProperty("kibana.trust");
    expect(buildSetup(filled()).answers["siem.trust"]).toBe("chain");
    expect(Object.fromEntries(reviewLines(filled({ siem_trust: "file", siem_ca: { name: "ca.crt", pem: PEM } })).map((l) => [l.label, l.value]))["SIEM certificate"]).toBe("the uploaded CA certificate (ca.crt)");
  });
  it("must be a PEM certificate of at most 64 KB in a .pem, .crt or .cer file", () => {
    expect(caProblem("ca.crt", PEM)).toBeNull();
    expect(caProblem("", PEM)).toBeNull();
    expect(caProblem("ca.der", PEM)).toBe("Choose a .pem, .crt or .cer file.");
    expect(caProblem("ca.pem", "not a certificate")).toContain("no BEGIN CERTIFICATE");
    expect(caProblem("ca.pem", PEM + "x".repeat(70_000))).toContain("64 KB");
    expect(stepProblems("siem", filled({ siem_trust: "file", siem_ca: null })).siem_ca).toBe("Upload or paste the CA's certificate, or give its path on this server.");
    expect(stepProblems("siem", filled({ siem_trust: "file", siem_ca: { name: "ca.pem", pem: PEM } }))).toEqual({});
  });
  it("is asked for when a server sends one certificate signed by someone else", () => {
    const cert = (self_signed: boolean, issuer = "CN=Elastic Certificate Tool Autogenerated CA") => ({ subject: "CN=elasticsearch", issuer, fingerprint: "AA", not_after: "2027-01-01", self_signed });
    expect(loneLeafIssuer({ chain: [cert(false)], error: null })).toBe("CN=Elastic Certificate Tool Autogenerated CA");
    expect(loneLeafIssuer({ chain: [cert(true)], error: null })).toBeNull();
    expect(loneLeafIssuer({ chain: [cert(false), cert(true)], error: null })).toBeNull();
    expect(loneLeafIssuer({ chain: [], error: "unreachable" })).toBeNull();
    expect(loneLeafIssuer(null)).toBeNull();
  });
});

describe("addresses and the run's errors", () => {
  it("drops spaces and trailing slashes from an address", () => {
    expect(tidyUrl("  https://siem.example.org:9200/ ")).toBe("https://siem.example.org:9200");
    expect(tidyUrl("https://siem.example.org:9200//")).toBe("https://siem.example.org:9200");
    expect(buildSetup(filled({ siem_url: "https://siem.example.org:9200/ ", use_kibana: true, kibana_url: " https://siem.example.org:5601/" })).answers).toMatchObject({ "siem.url": "https://siem.example.org:9200", "kibana.url": "https://siem.example.org:5601" });
    expect(stepProblems("siem", filled({ siem_url: "https://siem.example.org:9200/" })).siem_url).toBeUndefined();
  });
  it("sends Back to fix to the chapter the error names", () => {
    expect(errorChapter("siem.url: the SIEM could not be reached")).toBe("siem");
    expect(errorChapter("the certificate does not verify against siem.ca_file")).toBe("siem");
    expect(errorChapter("the SIEM's CA is not trusted")).toBe("siem");
    expect(errorChapter("kibana.ca_file does not verify")).toBe("kibana");
    expect(errorChapter("making argus-reader with the administrator's login: the login may not make API keys (manage_api_key or manage_security)")).toBe("access");
    expect(errorChapter("organisation.own_domains: ac.in: a public suffix")).toBe("organisation");
    expect(errorChapter("something else")).toBeNull();
  });
});

describe("a CA file on the ARGUS server (Elastic on the same machine)", () => {
  it("is sent as its path, only when nothing was uploaded or pasted, never with trust or a fingerprint", () => {
    const path = buildSetup(filled({ siem_trust: "file", siem_ca: null, siem_ca_path: " /etc/elasticsearch/certs/ca/ca.crt ", siem_fingerprint: "" }));
    expect(path.answers["siem.ca_path"]).toBe("/etc/elasticsearch/certs/ca/ca.crt");
    expect(path.answers).not.toHaveProperty("siem.ca_pem");
    expect(path.answers).not.toHaveProperty("siem.trust");
    expect(path.answers).not.toHaveProperty("siem.fingerprint");
    const both = buildSetup(filled({ siem_trust: "file", siem_ca: { name: "ca.crt", pem: PEM }, siem_ca_path: "/etc/x/ca.crt" }));
    expect(both.answers["siem.ca_pem"]).toBe(PEM);
    expect(both.answers).not.toHaveProperty("siem.ca_path");
    const kibana = buildSetup(filled({ use_kibana: true, kibana_url: "https://k:5601", kibana_trust: "file", kibana_ca_path: "/etc/kibana/ca.crt" }));
    expect(kibana.answers["kibana.ca_path"]).toBe("/etc/kibana/ca.crt");
    expect(kibana.answers).not.toHaveProperty("kibana.trust");
    expect(buildSetup(filled({ siem_ca_path: "/etc/x/ca.crt" })).answers).not.toHaveProperty("siem.ca_path");
  });
  it("must be an absolute path, and the review names it", () => {
    expect(stepProblems("siem", filled({ siem_trust: "file", siem_ca: null, siem_ca_path: "certs/ca.crt" })).siem_ca).toContain("starts with /");
    expect(stepProblems("siem", filled({ siem_trust: "file", siem_ca: null, siem_ca_path: "/etc/x/ca.crt" }))).toEqual({});
    const said = Object.fromEntries(reviewLines(filled({ siem_trust: "file", siem_ca: null, siem_ca_path: "/etc/x/ca.crt" })).map((l) => [l.label, l.value]));
    expect(said["SIEM certificate"]).toBe("the CA file /etc/x/ca.crt on this server");
  });
});
