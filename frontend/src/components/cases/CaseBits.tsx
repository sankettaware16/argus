import { CASE_STATE_TONE, caseStateWord } from "../../lib/cases";
import { Badge } from "../ui/badge";

/** A case's state as a badge: its word always shown. */
export function CaseStateBadge({ state }: { state: string }) {
  return <Badge tone={CASE_STATE_TONE[state] ?? "neutral"}>{caseStateWord(state)}</Badge>;
}
