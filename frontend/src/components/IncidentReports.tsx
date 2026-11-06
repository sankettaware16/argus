import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { listCases } from "../client/sdk.gen";
import type { CaseRowOut } from "../client/types.gen";
import { unwrap } from "../lib/call";
import { parse } from "../lib/time";
import { partsOf, shortDay } from "../lib/when";
import { restricted } from "./incident/Ciso";
import { Loading, Problem } from "./Problem";
import { UntrustedText } from "./UntrustedText";

export type Week = "This week" | "Last week" | "Earlier";

/** The site-zone Monday that starts the week of `d`, as a day number (pure). */
function weekStart(d: Date): number {
  const p = partsOf(d);
  const day = Date.UTC(p.year, p.month, p.day) / 86_400_000;
  const monday = (p.weekday + 6) % 7; // Monday 0 … Sunday 6
  return day - monday;
}

/** This week, Last week or Earlier, in IST weeks that start on Monday (§11). */
export function weekOf(d: Date, now: Date): Week {
  const diff = weekStart(now) - weekStart(d);
  return diff <= 0 ? "This week" : diff === 7 ? "Last week" : "Earlier";
}

/**
 * Incident reports (docs/p4f-ui-spec.md §11), first on Reports: the confirmed incidents, grouped
 * by week, each linking to its Report tab. The server's list of incident reports (A13) is not
 * there yet, so the rows have no PDF link and no "sent" line here; the Report tab has both.
 */
export function IncidentReports() {
  const [q, setQ] = useState("");
  const list = useQuery({ queryKey: ["cases", "reports"], queryFn: () => unwrap(listCases({ query: { view: "all", limit: 100 } })), staleTime: 60_000 });
  const now = new Date();
  const said = q.trim().toLowerCase();
  const rows = (list.data?.items ?? []).filter((c) => c.state !== "suspected" && (said === "" || c.title.toLowerCase().includes(said) || `#${c.number}` === said || String(c.number) === said));
  const groups = new Map<Week, CaseRowOut[]>();
  for (const c of rows) {
    const at = parse(c.opened_at ?? c.updated_at) ?? now;
    const w = weekOf(at, now);
    groups.set(w, [...(groups.get(w) ?? []), c]);
  }
  return (
    <section aria-labelledby="ir-h" className="flex flex-col gap-2" data-testid="incident-reports">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="ir-h" className="m-0 text-lg font-semibold">
          Incident reports
        </h2>
        <input type="search" value={q} onChange={(e) => setQ(e.target.value)} maxLength={120} aria-label="Find by IR number, title, address" placeholder="Find by IR number, title, address…" className="min-h-8 w-full max-w-xs rounded-control border border-border-strong bg-surface px-3 text-sm text-text" />
      </div>
      {list.isPending && <Loading what="the incident reports" />}
      {list.isError && <Problem error={list.error} what="The incident reports" onRetry={() => void list.refetch()} />}
      {list.data && rows.length === 0 && <p className="m-0 text-sm text-muted">{said ? "No incident report matches." : "No incident has been confirmed yet, so there is no incident report."}</p>}
      {(["This week", "Last week", "Earlier"] as const).map((w) => {
        const items = groups.get(w);
        if (!items) return null;
        return (
          <div key={w} className="flex flex-col gap-1" data-testid="report-week">
            <h3 className="m-0 text-sm font-semibold text-muted">{w}</h3>
            <ul className="m-0 flex list-none flex-col p-0">
              {items.map((c) => {
                const at = parse(c.opened_at);
                return (
                  <li key={c.id} className="flex min-h-10 flex-wrap items-center gap-x-2 border-b border-border py-1 text-sm">
                    <Link to="/incidents/$id" params={{ id: c.id }} search={{ tab: "report" }} className="min-w-0 flex-1">
                      #{c.number} · <UntrustedText value={c.title} limits={{ maxChars: 160, maxLines: 1 }} />
                    </Link>
                    <span className="text-muted">
                      {at ? shortDay(at) : ""}
                      {c.in_kibana ? " · In Kibana" : ""}
                    </span>
                  </li>
                );
              })}
            </ul>
          </div>
        );
      })}
      <p className="m-0 text-sm text-muted" data-testid="restricted">
        {restricted()}
      </p>
    </section>
  );
}
