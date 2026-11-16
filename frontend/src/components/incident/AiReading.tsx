import type { AiReading as Reading, AiSection, Engine } from "../../lib/engine";
import { UntrustedText } from "../UntrustedText";

const SPLIT_WORDS: Record<string, string> = { one: "One incident.", two: "Probably two separate incidents.", unsure: "Not clear." };

/** The model's name as the page shows it: without the provider's prefix. */
export function modelName(model: string): string {
  const cut = model.split("/");
  return cut[cut.length - 1] || model;
}

/** Every fact the reading cites, once each, in the order first cited. */
export function citedFacts(readings: readonly (Reading | null)[]): string[] {
  const seen = new Set<string>();
  for (const r of readings) for (const s of r?.sections ?? []) for (const c of s.claims) for (const f of c.based_on) seen.add(f);
  return [...seen];
}

function Part({ section, numbered, lead }: { section: AiSection; numbered?: boolean; lead?: string }) {
  if (section.key === "differ") return null; // the disagreement line above the summary says it
  const Claims = numbered && section.claims.length > 1 ? "ol" : "p";
  return (
    <div data-testid={`ai-${section.key}`}>
      <h4 className="m-0 text-sm font-medium">{section.title}</h4>
      {Claims === "ol" ? (
        <ol className="m-0 flex flex-col gap-0.5 pl-5 text-sm">
          {section.claims.map((c, i) => (
            <li key={i}>
              <UntrustedText value={c.text} limits={{ maxChars: 400, maxLines: 4 }} />
            </li>
          ))}
        </ol>
      ) : (
        <p className="m-0 max-w-[72ch] text-sm leading-relaxed">
          {lead && <span className="font-medium">{lead} </span>}
          {section.claims.map((c, i) => (
            <span key={i}>
              <UntrustedText value={c.text} limits={{ maxChars: 400, maxLines: 4 }} />{" "}
            </span>
          ))}
        </p>
      )}
    </div>
  );
}

function One({ reading, heading }: { reading: Reading; heading?: string }) {
  return (
    <div className="flex flex-col gap-2" data-testid={`ai-${reading.kind}`}>
      {heading && (
        <h3 className="m-0 text-sm font-semibold">
          {heading} <span className="font-normal text-muted text-xs">{modelName(reading.model)}</span>
        </h3>
      )}
      {!reading.current && (
        <p className="m-0 text-xs text-muted" data-testid="ai-earlier">
          Written for an earlier version of this incident; it has changed since.
        </p>
      )}
      {reading.sections.map((s) => (
        <Part key={s.key} section={s} numbered={s.key === "next_steps" || s.key === "decide"} lead={s.key === "split" && reading.incidents ? SPLIT_WORDS[reading.incidents] : undefined} />
      ))}
    </div>
  );
}

/**
 * ARGUS AI's reading of the incident (D-324), under the summary: a model's story of it, the
 * strongest case against it, one incident or two and what to check next, and on P1 a second
 * opinion. Text only: the score, the checks and the evidence on this page decide; every claim
 * here cites the incident's own facts (listed on demand), and a disagreement with the engine is
 * the line above the summary.
 */
export function AiReadingSection({ engine }: { engine: Engine | null }) {
  const story = engine?.ai_story ?? null;
  const opinion = engine?.ai_second_opinion ?? null;
  if (story === null && opinion === null) return null;
  const facts = citedFacts([story, opinion]);
  const model = story ?? opinion;
  return (
    <section data-region="ai-reading" aria-label="ARGUS AI's reading" className="flex flex-col gap-2 rounded-control border border-border px-3 py-2.5">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="m-0 text-base font-semibold">ARGUS AI&apos;s reading</h2>
        <span className="text-xs text-muted" data-testid="ai-note">
          {model && story !== null && <>{modelName(model.model)} · </>}may be wrong; the evidence on this page decides
        </span>
      </div>
      {story && <One reading={story} />}
      {opinion && <One reading={opinion} heading="Second opinion" />}
      {facts.length > 0 && (
        <details className="text-sm">
          <summary className="cursor-pointer text-muted">The facts it cited ({facts.length})</summary>
          <ul className="m-0 mt-1 flex flex-col gap-0.5 pl-5 text-muted">
            {facts.map((f, i) => (
              <li key={i}>
                <UntrustedText value={f} limits={{ maxChars: 400, maxLines: 3 }} />
              </li>
            ))}
          </ul>
        </details>
      )}
    </section>
  );
}
