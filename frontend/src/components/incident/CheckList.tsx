import { ALT_WORDS, mergedAlternatives, type Alternative, type Check } from "../../lib/engine";
import { UntrustedText } from "../UntrustedText";

/** The glyph and the word of a check (§12.2): the glyph is hidden from screen readers, the word is
 * always there, and neither is green or red. */
export const CHECK_MARK: Readonly<Record<Check["state"], [string, string]>> = {
  checked: ["✓", "Checked"],
  ruled_out: ["✗", "Ruled out"],
  unknown: ["?", "Not known"],
};

export function CheckMark({ state }: { state: Check["state"] }) {
  const [glyph, word] = CHECK_MARK[state];
  return (
    <span className="inline-flex shrink-0 items-baseline gap-1 text-text" data-testid="check-mark" data-state={state}>
      <span aria-hidden="true" className="inline-block w-3 text-center font-semibold text-text" data-testid="check-glyph">
        {glyph}
      </span>
      <span className="font-medium">{word}</span>
    </span>
  );
}

/** What ARGUS checked, one line each: glyph, word, text. `inline`: the first of each state on one line (a card). */
export function CheckList({ checks, inline = false, limit }: { checks: readonly Check[]; inline?: boolean; limit?: number }) {
  if (checks.length === 0) return null;
  if (inline) {
    const firsts = (["checked", "ruled_out", "unknown"] as const).map((s) => checks.find((c) => c.state === s)).filter((c): c is Check => c !== undefined);
    return (
      <p className="m-0 truncate text-sm" data-testid="checks-inline">
        <span className="mr-1 text-xs font-semibold text-muted">Checked</span>
        {firsts.map((c, i) => (
          <span key={i} className="mr-3">
            <CheckMark state={c.state} />: <UntrustedText value={c.text} limits={{ maxChars: 90, maxLines: 1 }} />
          </span>
        ))}
      </p>
    );
  }
  const shown = limit === undefined ? checks : checks.slice(0, limit);
  return (
    <ul className="m-0 flex list-none flex-col gap-1 p-0 text-sm" data-testid="check-list">
      {shown.map((c, i) => (
        <li key={i} className="grid grid-cols-[7.5rem_1fr] gap-2">
          <CheckMark state={c.state} />
          <span className="min-w-0">
            <UntrustedText value={c.text} limits={{ maxChars: 300, maxLines: 3 }} />
          </span>
        </li>
      ))}
    </ul>
  );
}

/** Other explanations (§7.3 rule 8): identical tests merged into one line, Ruled out · Still fits · Not tested. */
export function AlternativesList({ alternatives, limit }: { alternatives: readonly Alternative[]; limit?: number }) {
  const lines = mergedAlternatives(alternatives);
  if (lines.length === 0) return null;
  const shown = limit === undefined ? lines : lines.slice(0, limit);
  return (
    <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm" data-testid="alternatives">
      {shown.map((l, i) => (
        <li key={i} className="grid grid-cols-[7.5rem_1fr] gap-2" data-state={l.state}>
          <span className="font-medium text-text">{ALT_WORDS[l.state]}</span>
          <span className="flex min-w-0 flex-col">
            <span>
              <UntrustedText value={l.names.join("; ")} limits={{ maxChars: 300, maxLines: 2 }} />
            </span>
            {l.test !== "" && l.state !== "ruled_out" && (
              <span className="text-muted">
                The check that would decide: <UntrustedText value={l.test} limits={{ maxChars: 300, maxLines: 3 }} />
              </span>
            )}
            {l.test !== "" && l.state === "ruled_out" && (
              <span className="text-muted">
                <UntrustedText value={l.test} limits={{ maxChars: 300, maxLines: 3 }} />
              </span>
            )}
          </span>
        </li>
      ))}
    </ul>
  );
}
