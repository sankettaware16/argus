import { useState } from "react";
import { togetherRows, type Row } from "../../lib/incidents";
import { parse } from "../../lib/time";
import { shortDay } from "../../lib/when";
import { usePhone } from "../../lib/viewport";
import { UntrustedText } from "../UntrustedText";
import { Button } from "../ui/button";
import { BulkDismiss, BulkMerge } from "./Bulk";

/**
 * Review together (docs/p4f-ui-spec.md §6.6, F3): one row per campus-side object, what answered
 * before the outside sources (the attacker axis goes last), a "Different" word on a row whose band
 * or outcome differs from the rest, and one decision for all; rows where something answered are
 * left out of "Scan or attempt", and the line says so.
 */
export function ReviewTogether({ rows, onClose }: { rows: Row[]; onClose: () => void }) {
  const phone = usePhone();
  const [dialog, setDialog] = useState<"dismiss" | "merge" | null>(null);
  const lines = togetherRows(rows);
  const blocked = [...new Set(lines.filter((l) => l.blocked).map((l) => l.number))];
  return (
    <section data-testid="review-together" aria-labelledby="together-h" className="flex flex-col gap-3" onKeyDown={(e) => e.key === "Escape" && onClose()}>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="together-h" className="m-0 text-lg font-semibold">
          Review {rows.length} possible {rows.length === 1 ? "incident" : "incidents"} together
        </h2>
        <Button variant="ghost" onClick={onClose}>
          Back to the list
        </Button>
      </div>
      {phone ? (
        <ul className="m-0 flex list-none flex-col gap-2 p-0">
          {lines.map((l, i) => (
            <li key={i} className="flex flex-col rounded-card border border-border bg-surface p-3 text-sm" data-testid="together-row">
              <span className="font-medium">
                <UntrustedText value={l.campus} limits={{ maxChars: 120, maxLines: 1 }} />
              </span>
              <span>
                <UntrustedText value={l.outcome} limits={{ maxChars: 160, maxLines: 2 }} />
                {l.different && <strong> · Different</strong>}
              </span>
              <span className="text-muted">
                {l.band} · #{l.number} · {l.sources === null ? "outside sources not known" : `${l.sources} outside ${l.sources === 1 ? "source" : "sources"}`}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <table className="w-full border-collapse text-sm" data-testid="together-table">
          <thead>
            <tr className="border-b border-border text-left text-muted">
              <th className="py-1 pr-3 font-medium">Campus side</th>
              <th className="py-1 pr-3 font-medium">What answered</th>
              <th className="py-1 pr-3 font-medium">
                <span className="sr-only">Differs</span>
              </th>
              <th className="py-1 pr-3 font-medium">Pri</th>
              <th className="py-1 pr-3 font-medium">Incident</th>
              <th className="py-1 font-medium">Outside sources</th>
            </tr>
          </thead>
          <tbody>
            {lines.map((l, i) => {
              const last = parse(l.last);
              return (
                <tr key={i} className="border-b border-border" data-testid="together-row">
                  <td className="py-1.5 pr-3">
                    <UntrustedText value={l.campus} limits={{ maxChars: 120, maxLines: 1 }} />
                  </td>
                  <td className="py-1.5 pr-3">
                    <UntrustedText value={l.outcome} limits={{ maxChars: 160, maxLines: 2 }} />
                  </td>
                  <td className="py-1.5 pr-3 font-semibold">{l.different ? "Different" : ""}</td>
                  <td className="py-1.5 pr-3">{l.band}</td>
                  <td className="py-1.5 pr-3 tabular-nums">#{l.number}</td>
                  <td className="py-1.5 tabular-nums">
                    {l.sources === null ? <span title="Not known yet">—</span> : l.sources}
                    {last ? ` · last ${shortDay(last)}` : ""}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">One decision for all:</span>
        <Button onClick={() => setDialog("dismiss")}>Not an incident ▾</Button>
        <Button onClick={() => setDialog("merge")} aria-disabled={rows.length < 2}>
          Merge into one incident…
        </Button>
        {blocked.length > 0 && <span className="text-muted">({blocked.map((n) => `#${n}`).join(", ")} {blocked.length === 1 ? "is" : "are"} excluded from Scan or attempt: something answered)</span>}
      </div>
      {dialog === "dismiss" && <BulkDismiss rows={rows} open onOpenChange={(o) => !o && setDialog(null)} onDone={onClose} />}
      {dialog === "merge" && <BulkMerge rows={rows} open onOpenChange={(o) => !o && setDialog(null)} onDone={onClose} />}
    </section>
  );
}
