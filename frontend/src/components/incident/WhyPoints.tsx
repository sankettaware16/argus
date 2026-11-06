import { useState } from "react";
import { LANE_WORDS, pointsRows, signed, type Engine } from "../../lib/engine";
import { UntrustedText } from "../UntrustedText";

/**
 * Why ARGUS raised it (§7.3 rule 5): every point, sorted by value, negatives last; the visible
 * numbers always add up to the priority (an "Other factors and limits" row, or "Capped at 100",
 * when the stored points do not). "How the score is built" explains in words, never the formula.
 * `top` shows the first points only (the phone), with "+N more"; the total row always shows.
 */
export function WhyPoints({ engine, top }: { engine: Engine; top?: number }) {
  const rows = pointsRows(engine);
  const [all, setAll] = useState(false);
  const cut = top !== undefined && !all && rows.length > top;
  const shown = cut ? rows.slice(0, top) : rows;
  return (
    <div className="flex flex-col gap-1">
      <table className="w-full max-w-2xl border-collapse text-sm" data-testid="why-points">
        <caption className="sr-only">The points that make up the priority</caption>
        <tbody>
          {shown.map((r, i) => (
            <tr key={i} data-kind={r.kind}>
              <td className="w-14 py-0.5 pr-3 text-right align-top font-semibold tabular-nums" data-testid="why-value">
                {signed(r.value)}
              </td>
              <td className="py-0.5 align-top">{r.kind === "point" ? <UntrustedText value={r.text} limits={{ maxChars: 200, maxLines: 2 }} /> : r.text}</td>
            </tr>
          ))}
          {cut && (
            <tr>
              <td />
              <td className="py-0.5">
                <button type="button" className="cursor-pointer text-sm text-accent underline" onClick={() => setAll(true)}>
                  +{rows.length - (top ?? 0)} more
                </button>
              </td>
            </tr>
          )}
          <tr className="border-t border-border">
            <td className="py-0.5 pr-3 text-right font-bold tabular-nums" data-testid="why-total">
              {engine.priority}
            </td>
            <td className="py-0.5 font-semibold">Priority</td>
          </tr>
        </tbody>
      </table>
      <details className="text-sm">
        <summary className="cursor-pointer text-accent">How the score is built</summary>
        <div className="mt-1 flex max-w-prose flex-col gap-1 text-muted">
          {engine.lane !== null && (
            <p className="m-0">
              <span className="text-text">Kind of signal:</span> {LANE_WORDS[engine.lane]}.
            </p>
          )}
          <p className="m-0">
            Each fact ARGUS found adds points, and facts that make a harmless reading likelier take points off. Some kinds of signal are capped so that one noisy rule cannot reach the top on its own; the
            score never goes above 100.
          </p>
          <p className="m-0">ARGUS trusts a kind of activity more once a person has confirmed it before.</p>
        </div>
      </details>
    </div>
  );
}
