import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

/** A small label. Colour carries meaning only together with its text (plan §7.5). */
export const badgeVariants = cva(
  "inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-xs font-medium",
  {
    variants: {
      tone: {
        neutral: "border-transparent bg-surface-2 text-text",
        critical: "border-critical/25 bg-critical-soft text-critical",
        high: "border-high/25 bg-high-soft text-high",
        medium: "border-medium/25 bg-medium-soft text-medium",
        low: "border-low/25 bg-low-soft text-low",
        ok: "border-ok/25 bg-ok-soft text-ok",
        warn: "border-warn/25 bg-warn-soft text-warn",
        danger: "border-danger/25 bg-danger-soft text-danger",
        info: "border-info/25 bg-info-soft text-info",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export type Tone = NonNullable<VariantProps<typeof badgeVariants>["tone"]>;

export function Badge({ className, tone, ...props }: HTMLAttributes<HTMLSpanElement> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

const SEVERITY: Record<string, Tone> = { critical: "critical", high: "high", medium: "medium", low: "low" };

/** A severity as a badge: its word always shown; an unknown one is neutral. */
export function SeverityBadge({ severity }: { severity: string | null | undefined }) {
  const key = (severity ?? "").toLowerCase();
  const tone = SEVERITY[key] ?? "neutral";
  return <Badge tone={tone}>{tone === "neutral" ? "severity unknown" : key}</Badge>;
}
