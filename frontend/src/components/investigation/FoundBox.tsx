import type { Report, Value } from "../../client/types.gen";
import { eidText, foundHeading, LINE_LABEL, LINE_TONE } from "../../lib/report";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";

/** Values read from logs or threat lists, shown beside ARGUS's sentence, never inside it. */
export function Values({ values }: { values: readonly Value[] | undefined }) {
  if (!values || values.length === 0) return null;
  return (
    <ul className="m-0 mt-0.5 flex list-none flex-wrap gap-x-4 gap-y-0.5 p-0 text-xs text-muted">
      {values.map((v, i) => (
        <li key={i}>
          <UntrustedText value={v.label} limits={{ maxChars: 60, maxLines: 1 }} />:{" "}
          <span className="font-mono text-text">
            <UntrustedText value={v.text} limits={{ maxChars: 200, maxLines: 2 }} />
          </span>
          {v.count !== null && v.count !== undefined && <> ({v.count})</>}
        </li>
      ))}
    </ul>
  );
}

export function Eids({ eids }: { eids: readonly string[] | undefined }) {
  const text = eidText(eids);
  return text === "" ? null : <span className="font-mono text-xs text-muted"> {text}</span>;
}

/**
 * "What ARGUS found with extra SIEM queries" (plan §7.3): how many checks and how much SIEM
 * server time, then a line each: New, Nothing found, Could not tell, Failed, Not checked, Still
 * open (a colour is never the only sign: every line starts with its words), each with its
 * E-numbers and short provenance.
 */
export function FoundBox({ report, headingLevel = 3 }: { report: Report; headingLevel?: 2 | 3 }) {
  const found = report.found;
  const Heading = headingLevel === 2 ? "h2" : "h3";
  return (
    <section aria-label="What ARGUS found with extra SIEM queries" className="rounded-card border border-info/40 bg-info-soft p-3">
      <Heading className="m-0 text-base font-semibold">What ARGUS found with extra SIEM queries</Heading>
      <p className="m-0 mb-2 text-sm text-muted">{foundHeading(found.checks, found.server_ms)}. Compared with what the alerts alone say.</p>
      {found.items.length === 0 ? (
        <p className="m-0 text-sm">No SIEM query was made for this investigation version.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-2 p-0 text-sm">
          {found.items.map((item, i) => (
            <li key={i}>
              <Badge tone={LINE_TONE[item.kind]} className="mr-1.5">
                {LINE_LABEL[item.kind]}
              </Badge>
              <UntrustedText value={item.sentence} limits={{ maxChars: 600, maxLines: 6 }} />
              <Eids eids={item.eids} />
              <Values values={item.values} />
              {item.note && (
                <div className="font-mono text-xs text-muted italic">
                  <UntrustedText value={item.note} limits={{ maxChars: 400, maxLines: 2 }} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
