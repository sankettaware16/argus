/**
 * What a decision control needs to know about the possible incident it decides, whether it sits
 * on a Today card, in the preview pane or in the incident page's bar (docs/p4f-ui-spec.md §5.3–§5.5),
 * and how a decision is sent: the exact request the control showed, as it showed it.
 */
import type { CaseChanged, CaseDetail, DismissChoiceOut } from "../../client/types.gen";
import { sendExact } from "../../lib/api";
import { engineOf, type Alternative, type Card, type Engine, type Hold } from "../../lib/engine";
import { payloadText, type Method } from "../../lib/payload";

export interface Target {
  id: string;
  number: number;
  title: string;
  /** the case's version: sent as expected_version */
  version: number;
  engine: Engine | null;
  /** without the engine: the report's other explanations, for "Still open" (§5.4, F15) */
  alternatives?: readonly Alternative[];
  hold: Hold | null;
  /** the server's reasons, in its order (wave 1's decision.reasons) */
  reasons: readonly DismissChoiceOut[];
  /** what confirming makes possible, in the server's words (decision.after) */
  after: string;
  /** A6 and A7, when the server sends them */
  dismissEffect: string | null;
  kibanaAfterConfirm: string | null;
}

/** The reasons when only a card is loaded (the server's labels come with the case's own page). */
export const DEFAULT_REASONS: readonly DismissChoiceOut[] = [
  { reason: "benign_expected", label: "Expected activity", meaning: "It happened and it is normal here (the CC's own vulnerability scan, a lab's nightly backup)." },
  { reason: "attempt_no_impact", label: "Scan or attempt: no sign it worked", meaning: "Someone probed or tried; nothing answered or changed." },
  { reason: "benign_policy", label: "Allowed by policy", meaning: "Risky but allowed here (a sanctioned remote-access tool)." },
  { reason: "rule_false_positive", label: "Wrong rule", meaning: "The rule fired on something that was not an attack." },
  { reason: "duplicate", label: "Duplicate of…", meaning: "Another incident covers it." },
];

export const DEFAULT_AFTER = "It becomes an open incident: an owner, containment and closure become available.";
export const KIBANA_WAVE1 = "Like every case a person confirms, it waits for someone who may open it in Kibana; nothing is sent there by this.";
export const DISMISS_WAVE1 = "ARGUS does not suggest the same activity again for two weeks unless something new appears.";

function text(v: unknown): string | null {
  return typeof v === "string" && v.trim() !== "" ? v : null;
}

export function targetOfCard(c: Card): Target | null {
  if (c.id === null || c.number === null || c.version === null) return null;
  return { id: c.id, number: c.number, title: c.title, version: c.version, engine: c.engine, hold: c.hold, reasons: DEFAULT_REASONS, after: DEFAULT_AFTER, dismissEffect: null, kibanaAfterConfirm: null };
}

/** The engine block a case carries (the field engine builder C adds), or null. */
export function engineOfDetail(d: CaseDetail): Engine | null {
  const raw = d as unknown as { engine?: unknown; case: { engine?: unknown } };
  return engineOf(raw.engine ?? raw.case.engine);
}

export function targetOfDetail(d: CaseDetail): Target {
  const decision = d.decision as (CaseDetail["decision"] & { dismiss_effect?: unknown; kibana_after_confirm?: unknown }) | null;
  return {
    id: d.case.id,
    number: d.case.number,
    title: d.case.title,
    version: d.case.version,
    engine: engineOfDetail(d),
    hold: null,
    reasons: decision?.reasons.length ? decision.reasons : DEFAULT_REASONS,
    after: decision?.after ?? DEFAULT_AFTER,
    dismissEffect: text(decision?.dismiss_effect),
    kibanaAfterConfirm: text(decision?.kibana_after_confirm),
  };
}

/** The "What happens" sentence of the confirm dialog (§5.4): the server's, never a promise of a Kibana post. */
export function confirmSentence(t: Target): string {
  return t.kibanaAfterConfirm ?? `${t.after} ${KIBANA_WAVE1}`;
}

/** The consequence sentence of a dismissal (§5.5), with the own side when it is known. */
export function dismissSentence(t: Target): string {
  if (t.dismissEffect !== null) return t.dismissEffect;
  const ours = t.engine?.objects.filter((o) => o.role === "affected") ?? [];
  const first = ours[0];
  if (first === undefined) return DISMISS_WAVE1;
  const more = ours.length > 1 ? ` +${ours.length - 1}` : "";
  return `ARGUS does not suggest the same activity on ${first.label}${more} again for two weeks unless something new appears.`;
}

export interface Shown {
  method: Method;
  path: string;
  body: unknown;
}

/** Sends the request exactly as shown; the case as the server left it. Throws SendError on a refusal. */
export async function sendShown(r: Shown): Promise<CaseChanged> {
  const payload = payloadText(r.body);
  if (!payload.ok) throw new Error(payload.why);
  const sent = await sendExact({ method: r.method, path: r.path, text: payload.text });
  return sent.data as CaseChanged;
}
