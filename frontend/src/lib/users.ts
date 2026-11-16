/** People and roles (D-327): what the "Add a person" and "Change role" dialogs check and send. */
import type { AccountNewIn, AccountOut, AccountRoleIn } from "../client/types.gen";

export type Capability = NonNullable<AccountNewIn["capabilities"]>[number];
export type RoleKey = NonNullable<AccountNewIn["role"]>;

export const USERNAME = /^[a-z][a-z0-9_.-]{1,31}$/;
export const LINK_HOURS = 72;

/** Every capability, in plain words (the order a person reads them in). */
export const CAPABILITIES: { name: Capability; label: string }[] = [
  { name: "view", label: "See incidents, alert groups and reports" },
  { name: "see_logs", label: "See the raw log lines" },
  { name: "review", label: "Review alert groups and give a verdict" },
  { name: "answer_gold", label: "Answer the gold-set questions" },
  { name: "manage_cases", label: "Take cases and change them" },
  { name: "reopen", label: "Reopen closed cases" },
  { name: "approve", label: "Approve writes to Kibana" },
  { name: "admin", label: "Administer ARGUS: settings and people" },
];

export function capabilityWords(name: string): string {
  return CAPABILITIES.find((c) => c.name === name)?.label ?? name.replaceAll("_", " ");
}

export interface PersonForm {
  username: string;
  display_name: string;
  /** a preset role, or "custom" for the capabilities below */
  role: RoleKey | "custom";
  capabilities: readonly Capability[];
}

export const EMPTY_PERSON: PersonForm = { username: "", display_name: "", role: "analyst", capabilities: ["view"] };

export function usernameProblem(username: string): string | null {
  return USERNAME.test(username) ? null : "Start with a lower-case letter; then lower-case letters, digits, dots, dashes or underscores; 2 to 32 characters in all.";
}

/** What is wrong with the form, field by field (empty when it can be sent). */
export function personProblems(form: PersonForm): Partial<Record<"username" | "display_name" | "capabilities", string>> {
  const out: Partial<Record<"username" | "display_name" | "capabilities", string>> = {};
  const username = usernameProblem(form.username);
  if (username) out.username = username;
  if (form.display_name.trim() === "") out.display_name = "Write the person's name.";
  else if (form.display_name.trim().length > 80) out.display_name = "At most 80 characters.";
  if (form.role === "custom" && form.capabilities.length === 0) out.capabilities = "Choose at least one thing the person may do.";
  return out;
}

/** The role or capabilities part of a request: a preset role, or the custom set (always with "view"). */
export function roleBody(role: RoleKey | "custom", capabilities: readonly Capability[]): AccountRoleIn {
  if (role !== "custom") return { role };
  const set = new Set<Capability>(["view", ...capabilities]);
  return { capabilities: CAPABILITIES.map((c) => c.name).filter((n) => set.has(n)) };
}

export function newPersonBody(form: PersonForm): AccountNewIn {
  return { username: form.username, display_name: form.display_name.trim(), ...roleBody(form.role, form.capabilities) };
}

/** Why a row's account cannot be changed here, or null when it can. */
export function readOnlyWhy(user: Pick<AccountOut, "managed_in_elk" | "break_glass">): string | null {
  if (user.break_glass) return "The emergency account is kept for when sign-in is broken. It is changed only from the command line.";
  if (user.managed_in_elk) return "This person signs in with their ELK account. Their access follows their role in ELK, so it is changed there.";
  return null;
}

export function roleLabel(user: Pick<AccountOut, "role" | "capabilities">, roles: readonly { key: string; label: string }[]): string {
  if (user.role === "elk") return "ELK role";
  if (user.role === "custom") return `Custom (${user.capabilities.length} permissions)`;
  return roles.find((r) => r.key === user.role)?.label ?? user.role;
}

/** The link as a whole address (the server may answer with the path only). */
export function fullLink(link: string, origin: string): string {
  return link.startsWith("/") ? `${origin}${link}` : link;
}
