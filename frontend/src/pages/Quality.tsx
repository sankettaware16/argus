import { Link } from "@tanstack/react-router";
import type { ComponentType } from "react";

/** More › ARGUS quality (docs/p4f-ui-spec.md §4.1): the metrics and the gold set, as two tabs in the address. */
export function QualityPage({ tab, Metrics, Gold }: { tab: "metrics" | "gold"; Metrics: ComponentType; Gold: ComponentType }) {
  const tabClass = "inline-flex min-h-9 items-center rounded-t-control px-3 text-sm text-muted no-underline aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold aria-[current=page]:text-text";
  return (
    <div className="flex flex-col gap-3">
      <nav aria-label="ARGUS quality" className="flex gap-1 border-b border-border">
        <Link to="/quality" search={{ tab: "metrics" }} className={tabClass} aria-current={tab === "metrics" ? "page" : undefined} activeOptions={{ includeSearch: true }}>
          Metrics
        </Link>
        <Link to="/quality" search={{ tab: "gold" }} className={tabClass} aria-current={tab === "gold" ? "page" : undefined} activeOptions={{ includeSearch: true }}>
          Gold set
        </Link>
      </nav>
      {tab === "gold" ? <Gold /> : <Metrics />}
    </div>
  );
}
