/**
 * The first-time setup's answers (D-327, D-330): what each chapter asks, what is wrong with it,
 * and the exact answers and keys the setup job receives. The keys, the administrator's password
 * and the asset map stay in the form (component state) and go only in the start request's `keys`
 * and `asset_map`; they are never in the answers, a query key or storage.
 */
import type { SetupIn } from "../client/types.gen";

export type Step = "organisation" | "siem" | "access" | "kibana" | "ai" | "intel" | "assets" | "review";
/** The chapters, each with its headline and the one sentence under it. Optional ones may be skipped. */
export const STEPS: { key: Step; label: string; title: string; sub: string; optional?: boolean }[] = [
  { key: "organisation", label: "Your organisation", title: "Tell us who you are.", sub: "Your organisation's name, its domains and its time zone. ARGUS treats your own domains and networks as inside." },
  { key: "siem", label: "The SIEM", title: "Connect your SIEM.", sub: "Where your Elasticsearch is, and how ARGUS can be sure it is talking to it." },
  { key: "access", label: "Access", title: "Let ARGUS set itself up.", sub: "ARGUS only ever reads your SIEM. Choose how it gets its read-only keys." },
  { key: "kibana", label: "Kibana", title: "Add Kibana.", sub: "Optional. With Kibana, ARGUS reads your cases back; it writes nothing until you switch that on." },
  { key: "ai", label: "AI", title: "Bring your own AI. Or don't.", sub: "ARGUS works without AI. With a key it uses free providers first and caps what the paid ones cost.", optional: true },
  { key: "intel", label: "Threat intel", title: "Add threat intel.", sub: "Free personal keys for VirusTotal, Shodan or Censys let ARGUS look up public addresses and names.", optional: true },
  { key: "assets", label: "Asset map", title: "Map your network.", sub: "Which addresses are labs, offices or servers, and who owns them.", optional: true },
  { key: "review", label: "Review", title: "Ready when you are.", sub: "Check what ARGUS will do, then let it run. It takes a few minutes." },
];

export const INTEL = [
  { key: "virustotal", name: "VirusTotal", gives: "the reputation of a public address or name" },
  { key: "shodan", name: "Shodan", gives: "what a public server runs" },
  { key: "censys", name: "Censys", gives: "a public server's services and certificates" },
] as const;
export type IntelSource = (typeof INTEL)[number]["key"];

/** The Elastic case team's users (argus case team provision): two roles, one user and key each. */
export const CASE_TEAM_USERS = ["argus-lead", "argus-evidence", "argus-intel", "argus-responder", "argus-hunter", "argus-reporter", "argus-visualiser"] as const;

export interface SetupForm {
  name: string;
  short_name: string;
  kind: string;
  own_domains: string[];
  own_networks: string[];
  timezone: string;
  timezone_label: string;
  incident_id_prefix: string;
  siem_url: string;
  /** "" until the person chooses */
  siem_trust: "" | "chain" | "system" | "file";
  /** the CA certificate the person uploaded or pasted (trust "file") */
  siem_ca: { name: string; pem: string } | null;
  /** or the CA file's absolute path on the ARGUS server (Elastic on the same machine) */
  siem_ca_path: string;
  siem_fingerprint: string;
  log_patterns: string[];
  /** how ARGUS gets its keys: "" until the person chooses */
  access: "" | "login" | "paste";
  admin_user: string;
  admin_password: string;
  /** with the login: also make the Kibana case team (posting stays off) */
  provision_team: boolean;
  siem_key: string;
  siem_expires: string;
  use_kibana: boolean;
  kibana_url: string;
  kibana_trust: "same" | "chain" | "system" | "file";
  kibana_ca: { name: string; pem: string } | null;
  kibana_ca_path: string;
  kibana_fingerprint: string;
  kibana_key: string;
  kibana_expires: string;
  space: string;
  /** an AI provider key by its name (GROQ_API_KEY); empty: not given */
  ai_keys: Record<string, string>;
  intel_keys: Record<IntelSource, string>;
  asset_map: { name: string; content: string } | null;
}

/** Old IANA names browsers still report, and their current names (the server translates them
 * the same way: site.ZONE_ALIASES). */
export const ZONE_ALIASES: Readonly<Record<string, string>> = {
  "Asia/Calcutta": "Asia/Kolkata", "Asia/Katmandu": "Asia/Kathmandu", "Asia/Saigon": "Asia/Ho_Chi_Minh",
  "Asia/Rangoon": "Asia/Yangon", "Asia/Dacca": "Asia/Dhaka", "Asia/Thimbu": "Asia/Thimphu",
  "Asia/Ulan_Bator": "Asia/Ulaanbaatar", "Asia/Ujung_Pandang": "Asia/Makassar", "Asia/Macao": "Asia/Macau",
  "Asia/Chongqing": "Asia/Shanghai", "Asia/Chungking": "Asia/Shanghai", "Asia/Harbin": "Asia/Shanghai",
  "Asia/Tel_Aviv": "Asia/Jerusalem", "Europe/Kiev": "Europe/Kyiv", "Europe/Uzhgorod": "Europe/Kyiv",
  "Europe/Zaporozhye": "Europe/Kyiv", "Atlantic/Faeroe": "Atlantic/Faroe", "America/Godthab": "America/Nuuk",
  "America/Buenos_Aires": "America/Argentina/Buenos_Aires", "America/Indianapolis": "America/Indiana/Indianapolis",
  "America/Louisville": "America/Kentucky/Louisville", "Africa/Asmera": "Africa/Asmara", "Pacific/Truk": "Pacific/Chuuk",
  "Pacific/Ponape": "Pacific/Pohnpei", "Pacific/Enderbury": "Pacific/Kanton", "Australia/Canberra": "Australia/Sydney",
};

/** A time zone under its current IANA name (Asia/Calcutta → Asia/Kolkata). */
export function currentZone(name: string): string {
  const z = name.trim();
  return ZONE_ALIASES[z] ?? z;
}

export function browserZone(): string {
  try {
    return currentZone(Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
  } catch {
    return "UTC";
  }
}

/** The zones to choose from: the browser's list under current names, each once, sorted. */
export function zoneList(names?: readonly string[]): string[] {
  let all = names;
  if (all === undefined) {
    try {
      all = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];
    } catch {
      all = [];
    }
  }
  return [...new Set(all.map(currentZone))].sort();
}

export function emptySetup(zone: string = browserZone()): SetupForm {
  return {
    name: "",
    short_name: "",
    kind: "organisation",
    own_domains: [""],
    own_networks: [],
    timezone: zone,
    timezone_label: "",
    incident_id_prefix: "SOC-IR",
    siem_url: "",
    siem_trust: "",
    siem_ca: null,
    siem_ca_path: "",
    siem_fingerprint: "",
    log_patterns: ["logs-*"],
    access: "",
    admin_user: "",
    admin_password: "",
    provision_team: true,
    siem_key: "",
    siem_expires: "90d",
    use_kibana: false,
    kibana_url: "",
    kibana_trust: "same",
    kibana_ca: null,
    kibana_ca_path: "",
    kibana_fingerprint: "",
    kibana_key: "",
    kibana_expires: "90d",
    space: "",
    ai_keys: {},
    intel_keys: { virustotal: "", shodan: "", censys: "" },
    asset_map: null,
  };
}

const HTTPS = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/;
const CIDR = /^[0-9a-fA-F.:]+\/\d{1,3}$/;
const DOMAIN = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
const FINGERPRINT = /^[0-9a-fA-F]{64}$/;
const EXPIRES = /^(\d{4}-\d{2}-\d{2}|\d{1,4}d)$/;

/** Suffixes every organisation shares (a short list: the server checks the full public suffix list). */
export const PUBLIC_SUFFIXES = new Set([
  "com", "org", "net", "edu", "gov", "int", "mil", "info", "io", "co", "biz",
  "in", "ac.in", "co.in", "edu.in", "org.in", "net.in", "gov.in", "res.in", "ernet.in", "nic.in",
  "uk", "ac.uk", "co.uk", "org.uk", "gov.uk", "au", "edu.au", "com.au", "org.au", "net.au",
  "nz", "ac.nz", "co.nz", "jp", "ac.jp", "co.jp", "za", "ac.za", "co.za", "sg", "edu.sg", "com.sg",
  "kr", "ac.kr", "co.kr", "cn", "edu.cn", "com.cn", "il", "ac.il", "co.il", "de", "fr", "nl", "eu",
  "us", "ca", "br", "edu.br", "com.br",
]);

/** Why a domain cannot be one of the organisation's own, or null. */
export function domainProblem(domain: string): string | null {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (d === "") return null;
  if (!d.includes(".")) return `Give the whole domain, e.g. example.${PUBLIC_SUFFIXES.has(d) ? d : "ac.in"}.`;
  if (PUBLIC_SUFFIXES.has(d)) return `${d} is shared by every organisation; give your own, e.g. example.${d}.`;
  if (!DOMAIN.test(d)) return "A domain looks like example.edu: letters, digits and hyphens between dots.";
  return null;
}

/** Why a network cannot be one of the organisation's public ranges, or null. */
export function networkProblem(network: string): string | null {
  const n = network.trim();
  if (n === "") return null;
  return CIDR.test(n) ? null : "A range is written like 203.0.113.0/24.";
}

export function validZone(zone: string): boolean {
  try {
    new Intl.DateTimeFormat("en", { timeZone: zone });
    return zone.trim() !== "";
  } catch {
    return false;
  }
}

export const cleaned = (list: readonly string[]) => list.map((x) => x.trim()).filter((x) => x !== "");

/** The fingerprint as 64 hex digits whatever way it was written (colons, spaces, capitals). */
export function plainFingerprint(text: string): string {
  return text.replace(/[\s:]/g, "").toLowerCase();
}

/** What is wrong with a step, by field (empty when the step may be left). */
export function stepProblems(step: Step, f: SetupForm): Record<string, string> {
  const out: Record<string, string> = {};
  if (step === "organisation") {
    if (f.name.trim() === "") out.name = "Write the organisation's name.";
    if (f.short_name.trim() === "") out.short_name = "Write the security team's name.";
    if (f.kind.trim() === "") out.kind = "Write what kind of organisation it is, e.g. company, hospital, university.";
    const domains = cleaned(f.own_domains);
    const domainWhy = domains.map(domainProblem).find((x) => x !== null);
    if (domains.length === 0) out.own_domains = "Add at least one domain.";
    else if (domainWhy) out.own_domains = domainWhy;
    const networkWhy = cleaned(f.own_networks).map(networkProblem).find((x) => x !== null);
    if (networkWhy) out.own_networks = networkWhy;
    if (!validZone(f.timezone)) out.timezone = "A time zone name such as Asia/Kolkata.";
    if (f.incident_id_prefix.trim() === "") out.incident_id_prefix = "Write the prefix of incident ids, e.g. SOC-IR.";
  }
  if (step === "siem") {
    if (!HTTPS.test(tidyUrl(f.siem_url))) out.siem_url = "An https:// address with a host and port, e.g. https://siem.example.org:9200.";
    if (f.siem_trust === "") out.siem_trust = "Choose how ARGUS trusts the SIEM's certificate.";
    if (f.siem_trust === "chain" && !FINGERPRINT.test(plainFingerprint(f.siem_fingerprint))) out.siem_fingerprint = "Check the certificate first, so the fingerprint can be shown.";
    if (f.siem_trust === "file") {
      const why = caGiven(f.siem_ca, f.siem_ca_path);
      if (why) out.siem_ca = why;
    }
    if (cleaned(f.log_patterns).length === 0) out.log_patterns = "Add at least one index pattern, e.g. logs-*.";
  }
  if (step === "access") {
    if (f.access === "") out.access = "Choose how ARGUS gets its access.";
    if (f.access === "login") {
      if (f.admin_user.trim() === "") out.admin_user = "Write the administrator's user name.";
      else if (/\s/.test(f.admin_user.trim())) out.admin_user = "A user name has no spaces.";
      if (f.admin_password === "") out.admin_password = "Write the administrator's password.";
      else if (/[\r\n]/.test(f.admin_password)) out.admin_password = "One line only.";
    }
    if (f.access === "paste") {
      if (f.siem_key.trim() === "") out.siem_key = "Paste the read-only API key.";
      else if (/[\r\n]/.test(f.siem_key.trim())) out.siem_key = "One line only.";
      if (!EXPIRES.test(f.siem_expires.trim())) out.siem_expires = "A date (2027-03-01) or a number of days (90d).";
    }
  }
  if (step === "ai") {
    for (const [name, value] of Object.entries(f.ai_keys)) if (/[\r\n]/.test(value.trim())) out[`ai.${name}`] = "One line only.";
  }
  if (step === "intel") {
    for (const s of INTEL) if (/[\r\n]/.test(f.intel_keys[s.key].trim())) out[`intel.${s.key}`] = "One line only.";
  }
  if (step === "kibana" && f.use_kibana) {
    if (!HTTPS.test(tidyUrl(f.kibana_url))) out.kibana_url = "An https:// address, e.g. https://siem.example.org:5601.";
    if (f.kibana_trust === "chain" && !FINGERPRINT.test(plainFingerprint(f.kibana_fingerprint))) out.kibana_fingerprint = "Check the certificate first, so the fingerprint can be shown.";
    if (f.kibana_trust === "file") {
      const why = caGiven(f.kibana_ca, f.kibana_ca_path);
      if (why) out.kibana_ca = why;
    }
    if (f.access !== "login") {
      if (/[\r\n]/.test(f.kibana_key.trim())) out.kibana_key = "One line only.";
      if (f.kibana_key.trim() !== "" && !EXPIRES.test(f.kibana_expires.trim())) out.kibana_expires = "A date (2027-03-01) or a number of days (90d).";
    }
  }
  return out;
}

export function allProblems(f: SetupForm): Step | null {
  return STEPS.find((s) => Object.keys(stepProblems(s.key, f)).length > 0)?.key ?? null;
}

/** An address as typed, tidied: spaces and trailing slashes off. */
export function tidyUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

/** The largest CA certificate file the setup takes. */
export const CA_MAX = 64 * 1024;

/** Why a CA certificate cannot be used, or null: a .pem/.crt/.cer file (or pasted text) of at
 * most 64 KB holding a PEM certificate. */
export function caProblem(name: string, pem: string): string | null {
  if (name !== "" && !/\.(pem|crt|cer)$/i.test(name)) return "Choose a .pem, .crt or .cer file.";
  if (pem.length > CA_MAX) return "That is larger than 64 KB: a CA certificate is a few KB.";
  if (!pem.includes("BEGIN CERTIFICATE")) return "That is not a PEM certificate: it has no BEGIN CERTIFICATE line.";
  return null;
}

/** Why the "file" trust has no usable CA: an upload or paste is checked as a certificate, a path
 * as an absolute path on the server (argus-admin reads and checks the file). */
export function caGiven(ca: { name: string; pem: string } | null, path: string): string | null {
  if (ca !== null) return caProblem(ca.name, ca.pem);
  const p = path.trim();
  if (p === "") return "Upload or paste the CA's certificate, or give its path on this server.";
  if (!p.startsWith("/") || /[\r\n]/.test(p)) return "The path of a file on this server starts with /, e.g. /etc/elasticsearch/certs/ca/ca.crt.";
  return null;
}

/** The answer an uploaded CA is sent as: its text, else its path on the server (never both). */
export function caAnswer(what: "siem" | "kibana", ca: { name: string; pem: string } | null, path: string): Record<string, string> {
  return ca !== null ? { [`${what}.ca_pem`]: ca.pem } : { [`${what}.ca_path`]: path.trim() };
}

function trustWords(trust: string, fingerprint: string, ca: { name: string; pem: string } | null, path = ""): string {
  if (trust === "chain") return `trust the authority ${fingerprint.trim()}`;
  if (trust === "system") return "this system already trusts it";
  if (trust === "file") {
    if (ca !== null) return `the uploaded CA certificate${ca.name ? ` (${ca.name})` : " (pasted)"}`;
    return path.trim() !== "" ? `the CA file ${path.trim()} on this server` : "the CA certificate: not given";
  }
  return "not chosen";
}

/** The issuer of a chain that is one certificate signed by someone else (a server that sends
 * only its own certificate, not its CA's), or null: then the CA has to be uploaded. */
export function loneLeafIssuer(seen: Pick<Inspected, "chain" | "error"> | null): string | null {
  if (seen === null || seen.error !== null || seen.chain.length !== 1) return null;
  const only = seen.chain[0];
  return only && !only.self_signed ? only.issuer || "another authority" : null;
}

/** The chapter a failed run's words point to, for "Back to fix". */
export function errorChapter(text: string): Step | null {
  if (/kibana\./i.test(text)) return "kibana";
  if (/siem\.url|siem\.ca_file|does not verify|\bCA\b|certificate/i.test(text)) return "siem";
  if (/admin_user|admin_password|manage_api_key|manage_security|api key|api_key/i.test(text)) return "access";
  if (/own_domains|public suffix|organisation\./i.test(text)) return "organisation";
  return null;
}

/** The AI provider key's name as the setup sends it: GROQ_API_KEY → llm.key.groq_api_key. */
export function aiKeyName(name: string): string {
  return `llm.key.${name.toLowerCase()}`;
}

/** The setup request, exactly as it is sent: answers (no key in them), the keys, the asset map. */
export function buildSetup(f: SetupForm): SetupIn {
  const login = f.access === "login";
  const answers: Record<string, unknown> = {
    "organisation.name": f.name.trim(),
    "organisation.short_name": f.short_name.trim(),
    "organisation.kind": f.kind.trim(),
    "organisation.own_domains": cleaned(f.own_domains),
    "organisation.own_networks": cleaned(f.own_networks),
    "organisation.timezone": currentZone(f.timezone),
    "organisation.timezone_label": f.timezone_label.trim() === "" ? "none" : f.timezone_label.trim(),
    "organisation.incident_id_prefix": f.incident_id_prefix.trim(),
    "siem.url": tidyUrl(f.siem_url),
    "siem.log_patterns": cleaned(f.log_patterns),
    "elastic.admin_user": login ? f.admin_user.trim() : "none",
    "kibana.url": f.use_kibana ? tidyUrl(f.kibana_url) : "none",
    "discovery.accept": true,
    "llm.keys_file": "none",
  };
  // an uploaded CA is sent as its text: the server trusts that file (trust and fingerprint unsent)
  if (f.siem_trust === "file") Object.assign(answers, caAnswer("siem", f.siem_ca, f.siem_ca_path));
  else answers["siem.trust"] = f.siem_trust;
  if (f.siem_trust === "chain") answers["siem.fingerprint"] = f.siem_fingerprint.trim();
  const keys: Record<string, string> = {};
  if (login) keys["elastic.admin_password"] = f.admin_password;
  else {
    keys["siem.api_key"] = f.siem_key.trim();
    answers["siem.api_key_expires"] = f.siem_expires.trim();
  }
  if (f.use_kibana) {
    if (f.kibana_trust === "file") Object.assign(answers, caAnswer("kibana", f.kibana_ca, f.kibana_ca_path));
    else answers["kibana.trust"] = f.kibana_trust;
    if (f.kibana_trust === "chain") answers["kibana.fingerprint"] = f.kibana_fingerprint.trim();
    if (f.space.trim() !== "") answers["organisation.space"] = f.space.trim();
    if (login && f.provision_team) answers["case_team.provision"] = true;
    if (!login && f.kibana_key.trim() !== "") {
      keys["kibana.api_key"] = f.kibana_key.trim();
      answers["kibana.api_key_expires"] = f.kibana_expires.trim();
    }
  }
  for (const [name, value] of Object.entries(f.ai_keys)) if (value.trim() !== "") keys[aiKeyName(name)] = value.trim();
  for (const s of INTEL) if (f.intel_keys[s.key].trim() !== "") keys[`outside.${s.key}_api_key`] = f.intel_keys[s.key].trim();
  const out: SetupIn = { answers, keys };
  if (f.asset_map !== null) out.asset_map = f.asset_map.content;
  return out;
}

/** What ARGUS will make in Elastic with the administrator's login (nothing when keys are pasted). */
export function elasticPlan(f: SetupForm): string[] {
  if (f.access !== "login") return [];
  const out = ["An API key argus-reader: reads alerts, your logs and threat intel; valid a year"];
  if (f.use_kibana) {
    out.push("An API key argus-kibana-reader: reads Kibana's cases; valid a year");
    if (f.provision_team) {
      out.push("Two roles in the Kibana space: argus_case_lead and argus_case_commenter");
      out.push(`${CASE_TEAM_USERS.length} users for the case team (${CASE_TEAM_USERS.join(", ")}), each with its own key; posting stays off`);
    }
  }
  return out;
}

const given = (n: number, one: string, many: string) => (n === 0 ? "none" : `${n} ${n === 1 ? one : many}`);

/** One line per answer for the review: keys and passwords as "set", never their value. */
export function reviewLines(f: SetupForm): { label: string; value: string }[] {
  const lines = [
    { label: "Organisation", value: f.name.trim() },
    { label: "Security team", value: f.short_name.trim() },
    { label: "Kind", value: f.kind.trim() },
    { label: "Own domains", value: cleaned(f.own_domains).join(", ") },
    { label: "Own networks", value: cleaned(f.own_networks).join(", ") || "none" },
    { label: "Time zone", value: `${f.timezone.trim()}${f.timezone_label.trim() ? ` (${f.timezone_label.trim()})` : ""}` },
    { label: "Incident id prefix", value: f.incident_id_prefix.trim() },
    { label: "SIEM address", value: tidyUrl(f.siem_url) },
    { label: "SIEM certificate", value: trustWords(f.siem_trust, f.siem_fingerprint, f.siem_ca, f.siem_ca_path) },
    { label: "Log index patterns", value: cleaned(f.log_patterns).join(", ") },
    {
      label: "Access",
      value:
        f.access === "login"
          ? `ARGUS makes its own read-only keys with ${f.admin_user.trim()}'s login (used once, never stored)`
          : f.access === "paste"
            ? f.siem_key.trim() === ""
              ? "a pasted read-only key: not set"
              : "a pasted read-only key: set, expires " + f.siem_expires.trim()
            : "not chosen",
    },
    { label: "Kibana", value: f.use_kibana ? tidyUrl(f.kibana_url) : "not used" },
  ];
  if (f.use_kibana) {
    lines.push({ label: "Kibana certificate", value: f.kibana_trust === "same" ? "the SIEM's authority" : trustWords(f.kibana_trust, f.kibana_fingerprint, f.kibana_ca, f.kibana_ca_path) });
    if (f.access === "login") lines.push({ label: "Kibana key", value: "made by ARGUS (read-only)" });
    else lines.push({ label: "Kibana key", value: f.kibana_key.trim() === "" ? "none (Kibana stays off)" : "set (read-only), expires " + f.kibana_expires.trim() });
    if (f.access === "login") lines.push({ label: "Case team", value: f.provision_team ? "made now; posting stays off" : "not now (later: Settings → Kibana cases)" });
    if (f.space.trim() !== "") lines.push({ label: "Kibana space", value: f.space.trim() });
  }
  const ai = Object.values(f.ai_keys).filter((v) => v.trim() !== "").length;
  lines.push({ label: "AI providers", value: ai === 0 ? "none: ARGUS works without them; add keys later in AI and agents" : `${given(ai, "key", "keys")} set` });
  const intel = INTEL.filter((s) => f.intel_keys[s.key].trim() !== "").map((s) => s.name);
  lines.push({ label: "Threat intel", value: intel.length === 0 ? "none: add keys later in Threat intel" : `${intel.join(", ")}: key set` });
  lines.push({ label: "Asset map", value: f.asset_map === null ? "none: upload it later in Settings → Asset map" : `${f.asset_map.name}, imported after the setup` });
  return lines;
}

/** The certificate check's answer: the chain, and the anchor (the authority) to compare. */
export interface Inspected {
  url: string;
  chain: { subject: string; issuer: string; fingerprint: string; not_after: string; self_signed: boolean }[];
  anchor: string | null;
  error: string | null;
}

export function readInspected(result: Record<string, unknown> | null): Inspected | null {
  if (result === null) return null;
  if (typeof result.error === "string") return { url: "", chain: [], anchor: null, error: result.error };
  const chain = Array.isArray(result.chain) ? result.chain : [];
  return {
    url: String(result.url ?? ""),
    anchor: typeof result.anchor === "string" ? result.anchor : null,
    error: null,
    chain: chain.map((c: Record<string, unknown>) => ({ subject: String(c.subject ?? ""), issuer: String(c.issuer ?? ""), fingerprint: String(c.fingerprint ?? ""), not_after: String(c.not_after ?? ""), self_signed: c.self_signed === true })),
  };
}

export function setupOutput(result: Record<string, unknown> | null): { ok: boolean; lines: string[]; error: string | null; after: string[] } {
  if (result === null) return { ok: false, lines: [], error: null, after: [] };
  const lines = Array.isArray(result.output) ? result.output.map(String) : [];
  const after = Array.isArray(result.after) ? result.after.map(String) : [];
  return { ok: result.ok === true, lines, error: typeof result.error === "string" ? result.error : null, after };
}

/** What the run does, in order, for its checklist (the login path makes the keys first). */
export function runChecklist(f: SetupForm): string[] {
  const out = ["Check the SIEM and its certificate"];
  out.push(f.access === "login" ? "Make ARGUS's read-only keys" : "Check the read-only key");
  out.push("Discover your log families" + (f.use_kibana ? " and the Kibana space" : ""));
  if (f.access === "login" && f.use_kibana && f.provision_team) out.push("Make the Kibana case team");
  out.push("Write the configuration and start the services");
  const extra = Object.values(f.ai_keys).some((v) => v.trim() !== "") || INTEL.some((s) => f.intel_keys[s.key].trim() !== "");
  if (extra) out.push("Store the AI and threat-intel keys");
  if (f.asset_map !== null) out.push("Import the asset map");
  return out;
}

/** The browser session's note that the person left the setup (Exit setup, or it finished): the
 * app then stops opening it by itself, so there is no loop. */
export const SETUP_LEFT = "argus.setup.left";

export function setupLeft(): boolean {
  try {
    return window.sessionStorage.getItem(SETUP_LEFT) === "1";
  } catch {
    return false;
  }
}

export function markSetupLeft(): void {
  try {
    window.sessionStorage.setItem(SETUP_LEFT, "1");
  } catch {
    // storage refused: the setup opens again next time, which is harmless
  }
}

/** Whether the app opens the setup by itself: it is pending, the person may run it, they are not
 * there yet and have not left it in this browser session. */
export function opensSetup(pending: boolean, admin: boolean, path: string, left: boolean): boolean {
  return pending && admin && path !== "/setup" && path !== "/confirmed" && !left;
}
