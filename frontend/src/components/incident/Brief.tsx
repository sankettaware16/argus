import type { IncidentReport, ReportBrief, ReportBriefAction, ReportBriefLine } from "../../client/types.gen";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";

/** Who takes a step of the brief, and by when (the server's `words.WHO_WORDS`, `WHEN_WORDS`). */
export const WHO: Record<ReportBriefAction["who"], string> = { owner: "Device owner", accounts: "Account holders", network: "Network team", soc: "Security team" };
export const WHEN: Record<ReportBriefAction["when"], string> = { now: "Immediately", today: "Today", week: "This week", after: "After the device is clean" };

export function briefOf(report: IncidentReport | null | undefined): ReportBrief | null {
  return report?.brief ?? null;
}

/** The brief's statement as one paragraph. */
export function statementOf(brief: ReportBrief): string {
  return brief.statement.map((s) => s.text).join(" ");
}

function Lines({ items }: { items: readonly ReportBriefLine[] }) {
  return (
    <ul className="m-0 flex max-w-[78ch] list-disc flex-col gap-1.5 pl-5 text-sm leading-relaxed">
      {items.map((s, i) => (
        <li key={i}>
          <UntrustedText value={s.text} limits={{ maxChars: 500, maxLines: 6 }} />
        </li>
      ))}
    </ul>
  );
}

function Section({ title, items }: { title: string; items: readonly ReportBriefLine[] }) {
  if (items.length === 0) return null;
  return (
    <div className="flex flex-col gap-1.5">
      <h3 className="m-0 text-sm font-semibold">{title}</h3>
      <Lines items={items} />
    </div>
  );
}

/**
 * The analyst brief (D-332): what is happening, the summary, why it is judged real, the impact
 * and the steps asked for, in a model's words over the report's facts. Every line was checked by
 * the server against the facts it cites; the facts are one click away.
 */
export function BriefBlock({ report }: { report: IncidentReport }) {
  const brief = briefOf(report);
  if (brief === null) {
    return report.brief_note ? (
      <p className="m-0 text-xs text-muted" data-testid="brief-note">
        No analyst brief: {report.brief_note}
      </p>
    ) : null;
  }
  const facts = Object.entries(brief.facts);
  return (
    <section aria-label="Analyst brief" data-testid="brief" className="flex flex-col gap-4 rounded-card border border-border bg-surface p-4">
      <p className="m-0 max-w-[78ch] text-base leading-relaxed" data-testid="brief-statement">
        <UntrustedText value={statementOf(brief)} limits={{ maxChars: 900, maxLines: 8 }} />
      </p>
      <Section title="Summary" items={brief.points} />
      <Section title="Why it is judged real" items={brief.why} />
      <Section title="Impact" items={brief.impact} />
      {brief.actions.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <h3 className="m-0 text-sm font-semibold">Actions asked for</h3>
          <ol className="m-0 flex max-w-[78ch] list-decimal flex-col gap-1.5 pl-5 text-sm leading-relaxed" data-testid="brief-actions">
            {brief.actions.map((a, i) => (
              <li key={i}>
                <UntrustedText value={a.text} limits={{ maxChars: 500, maxLines: 6 }} />{" "}
                <span className="text-muted">
                  ({WHO[a.who]} · {WHEN[a.when]})
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
      <p className="m-0 text-xs text-muted" data-testid="brief-by">
        Written by ARGUS&apos;s AI ({brief.by}) <Time value={brief.at} /> from this report&apos;s facts; ARGUS checked every sentence against the facts it cites. It may still be wrong: the evidence below decides, and nothing here is carried out.
      </p>
      {facts.length > 0 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted">The {facts.length} facts it rests on</summary>
          <ul className="m-0 mt-1 flex list-none flex-col gap-1 p-0">
            {facts.map(([id, text]) => (
              <li key={id}>
                <UntrustedText value={text} limits={{ maxChars: 600, maxLines: 6 }} />
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
