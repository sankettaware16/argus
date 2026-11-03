import { shares } from "../../lib/chart";
import { count } from "../../lib/format";
import { optionText } from "../../lib/optionText";

/** One bar split into parts by share, largest first; `titles` and `fills` name and colour each part. */
export function SplitBar({ counts, titles, fills, label }: { counts: Readonly<Record<string, number>>; titles: Readonly<Record<string, string>>; fills: Readonly<Record<string, string>>; label: string }) {
  const parts = shares(counts);
  return (
    <svg viewBox="0 0 1000 18" preserveAspectRatio="none" role="img" aria-label={label} className="h-3 w-full overflow-hidden rounded-full">
      <rect x={0} y={0} width={1000} height={18} className="fill-surface-3" />
      {parts.map((p) => (
        <rect key={p.key} x={p.x} y={0} width={p.width} height={18} className={fills[p.key] ?? "fill-border-strong"}>
          <title>{`${titles[p.key] ?? optionText(p.key.replaceAll("_", " "), 60)}: ${count(p.count)}`}</title>
        </rect>
      ))}
    </svg>
  );
}

export const SEVERITY_FILL = { critical: "fill-critical", high: "fill-high", medium: "fill-medium", low: "fill-low", unknown: "fill-border-strong" } as const;
export const STATE_FILL = { unreviewed: "fill-info", follow_up: "fill-warn", changed_since_review: "fill-high", reviewed: "fill-ok" } as const;
export const VERDICT_FILL = {
  true_positive: "fill-critical",
  benign_expected: "fill-ok",
  benign_policy: "fill-low",
  rule_false_positive: "fill-medium",
  inconclusive: "fill-border-strong",
  none: "fill-surface-3",
} as const;
export const AI_FILL = { proposed_tp: "fill-critical", proposed_other: "fill-ok", no_proposal: "fill-border-strong", working: "fill-info", none: "fill-surface-3" } as const;
