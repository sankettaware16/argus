/**
 * The first-time setup's answers (D-327): what each step asks, what is wrong with it, and the
 * exact answers and keys the setup job receives. The keys stay in the form (component state)
 * and go only in the start request's `keys`; they are never in the answers, a query key or storage.
 */
import type { SetupIn } from "../client/types.gen";

export type Step = "organisation" | "siem" | "kibana" | "review";
export const STEPS: { key: Step; label: string }[] = [
  { key: "organisation", label: "Your organisation" },
  { key: "siem", label: "The SIEM" },
  { key: "kibana", label: "Kibana" },
  { key: "review", label: "Review and run" },
];

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
  siem_trust: "" | "chain" | "system";
  siem_fingerprint: string;
  siem_key: string;
  siem_expires: string;
  log_patterns: string[];
  use_kibana: boolean;
  kibana_url: string;
  kibana_trust: "same" | "chain" | "system";
  kibana_fingerprint: string;
  kibana_key: string;
  kibana_expires: string;
  space: string;
}

export function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
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
    siem_fingerprint: "",
    siem_key: "",
    siem_expires: "90d",
    log_patterns: ["logs-*"],
    use_kibana: false,
    kibana_url: "",
    kibana_trust: "same",
    kibana_fingerprint: "",
    kibana_key: "",
    kibana_expires: "90d",
    space: "",
  };
}

const HTTPS = /^https:\/\/[A-Za-z0-9.-]+(:\d{1,5})?\/?$/;
const CIDR = /^[0-9a-fA-F.:]+\/\d{1,3}$/;
const DOMAIN = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$/;
const FINGERPRINT = /^[0-9a-fA-F]{64}$/;
const EXPIRES = /^(\d{4}-\d{2}-\d{2}|\d{1,4}d)$/;

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
    if (f.kind.trim() === "") out.kind = "Write what kind of organisation it is, e.g. university.";
    const domains = cleaned(f.own_domains);
    if (domains.length === 0) out.own_domains = "Add at least one domain.";
    else if (domains.some((d) => !DOMAIN.test(d))) out.own_domains = "Each domain looks like example.org.";
    if (cleaned(f.own_networks).some((n) => !CIDR.test(n))) out.own_networks = "Each network is written like 203.0.113.0/24.";
    if (!validZone(f.timezone)) out.timezone = "A time zone name such as Asia/Kolkata.";
    if (f.incident_id_prefix.trim() === "") out.incident_id_prefix = "Write the prefix of incident ids, e.g. SOC-IR.";
  }
  if (step === "siem") {
    if (!HTTPS.test(f.siem_url.trim())) out.siem_url = "An https:// address with a host and port, e.g. https://siem.example.org:9200.";
    if (f.siem_trust === "") out.siem_trust = "Choose how ARGUS trusts the SIEM's certificate.";
    if (f.siem_trust === "chain" && !FINGERPRINT.test(plainFingerprint(f.siem_fingerprint))) out.siem_fingerprint = "Check the certificate first, so the fingerprint can be shown.";
    if (f.siem_key.trim() === "") out.siem_key = "Paste the read-only API key.";
    else if (/[\r\n]/.test(f.siem_key.trim())) out.siem_key = "One line only.";
    if (!EXPIRES.test(f.siem_expires.trim())) out.siem_expires = "A date (2027-03-01) or a number of days (90d).";
    if (cleaned(f.log_patterns).length === 0) out.log_patterns = "Add at least one index pattern, e.g. logs-*.";
  }
  if (step === "kibana" && f.use_kibana) {
    if (!HTTPS.test(f.kibana_url.trim())) out.kibana_url = "An https:// address, e.g. https://siem.example.org:5601.";
    if (f.kibana_trust === "chain" && !FINGERPRINT.test(plainFingerprint(f.kibana_fingerprint))) out.kibana_fingerprint = "Check the certificate first, so the fingerprint can be shown.";
    if (/[\r\n]/.test(f.kibana_key.trim())) out.kibana_key = "One line only.";
    if (f.kibana_key.trim() !== "" && !EXPIRES.test(f.kibana_expires.trim())) out.kibana_expires = "A date (2027-03-01) or a number of days (90d).";
  }
  return out;
}

export function allProblems(f: SetupForm): Step | null {
  return STEPS.find((s) => Object.keys(stepProblems(s.key, f)).length > 0)?.key ?? null;
}

/** The setup request, exactly as it is sent: answers (no key in them) and the keys. */
export function buildSetup(f: SetupForm): SetupIn {
  const answers: Record<string, unknown> = {
    "organisation.name": f.name.trim(),
    "organisation.short_name": f.short_name.trim(),
    "organisation.kind": f.kind.trim(),
    "organisation.own_domains": cleaned(f.own_domains),
    "organisation.own_networks": cleaned(f.own_networks),
    "organisation.timezone": f.timezone.trim(),
    "organisation.timezone_label": f.timezone_label.trim() === "" ? "none" : f.timezone_label.trim(),
    "organisation.incident_id_prefix": f.incident_id_prefix.trim(),
    "siem.url": f.siem_url.trim(),
    "siem.trust": f.siem_trust,
    "siem.api_key_expires": f.siem_expires.trim(),
    "siem.log_patterns": cleaned(f.log_patterns),
    "kibana.url": f.use_kibana ? f.kibana_url.trim() : "none",
    "discovery.accept": true,
    "llm.keys_file": "none",
  };
  if (f.siem_trust === "chain") answers["siem.fingerprint"] = f.siem_fingerprint.trim();
  const keys: Record<string, string> = { "siem.api_key": f.siem_key.trim() };
  if (f.use_kibana) {
    answers["kibana.trust"] = f.kibana_trust;
    if (f.kibana_trust === "chain") answers["kibana.fingerprint"] = f.kibana_fingerprint.trim();
    if (f.space.trim() !== "") answers["organisation.space"] = f.space.trim();
    if (f.kibana_key.trim() !== "") {
      keys["kibana.api_key"] = f.kibana_key.trim();
      answers["kibana.api_key_expires"] = f.kibana_expires.trim();
    }
  }
  return { answers, keys };
}

/** One line per answer for the review step: keys as "set", never their value. */
export function reviewLines(f: SetupForm): { label: string; value: string }[] {
  const lines = [
    { label: "Organisation", value: f.name.trim() },
    { label: "Security team", value: f.short_name.trim() },
    { label: "Kind", value: f.kind.trim() },
    { label: "Own domains", value: cleaned(f.own_domains).join(", ") },
    { label: "Own networks", value: cleaned(f.own_networks).join(", ") || "none" },
    { label: "Time zone", value: `${f.timezone.trim()}${f.timezone_label.trim() ? ` (${f.timezone_label.trim()})` : ""}` },
    { label: "Incident id prefix", value: f.incident_id_prefix.trim() },
    { label: "SIEM address", value: f.siem_url.trim() },
    { label: "SIEM certificate", value: f.siem_trust === "chain" ? `trust the authority ${f.siem_fingerprint.trim()}` : f.siem_trust === "system" ? "this system already trusts it" : "not chosen" },
    { label: "SIEM key", value: f.siem_key.trim() === "" ? "not set" : "set (read-only), expires " + f.siem_expires.trim() },
    { label: "Log index patterns", value: cleaned(f.log_patterns).join(", ") },
    { label: "Kibana", value: f.use_kibana ? f.kibana_url.trim() : "not used" },
  ];
  if (f.use_kibana) {
    lines.push({ label: "Kibana certificate", value: f.kibana_trust === "same" ? "the SIEM's authority" : f.kibana_trust === "chain" ? `trust the authority ${f.kibana_fingerprint.trim()}` : "this system already trusts it" });
    lines.push({ label: "Kibana key", value: f.kibana_key.trim() === "" ? "none (Kibana stays off)" : "set (read-only), expires " + f.kibana_expires.trim() });
    if (f.space.trim() !== "") lines.push({ label: "Kibana space", value: f.space.trim() });
  }
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

export function setupOutput(result: Record<string, unknown> | null): { ok: boolean; lines: string[]; error: string | null } {
  if (result === null) return { ok: false, lines: [], error: null };
  const lines = Array.isArray(result.output) ? result.output.map(String) : [];
  return { ok: result.ok === true, lines, error: typeof result.error === "string" ? result.error : null };
}
