import { useEffect, useState } from "react";
import type { Report } from "../../client/types.gen";
import { count } from "../../lib/format";
import { outcomeLabel } from "../../lib/labels";
import { confidenceText, costSentence, factSource, GRADE_LABEL, reportTab, STANCE_LABEL, strengthCounts, verdictSentence } from "../../lib/report";
import { Time } from "../Time";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";
import { Button } from "../ui/button";
import { DataTable } from "../ui/table";
import { Eids, FoundBox, Values } from "./FoundBox";

const STANCE_TONE = { supports: "info", contradicts: "warn", neutral: "neutral" } as const;
const KIND_WORD = { alert: "Alert", fact: "Fact", check: "Check", verdict: "Verdict" } as const;

function Section({ title, children, bare = false }: { title: string; children: React.ReactNode; bare?: boolean }) {
  if (bare) return <div className="flex flex-col gap-2">{children}</div>;
  return (
    <section aria-label={title} className="flex flex-col gap-2">
      <h3 className="m-0 text-base font-semibold">{title}</h3>
      {children}
    </section>
  );
}

function Verdict({ report }: { report: Report }) {
  const v = report.verdict;
  const sure = confidenceText(v);
  const s = report.strength;
  return (
    <Section title="Verdict">
      <p className="m-0 text-sm">
        <strong>{verdictSentence(v)}</strong>
        {sure && <span className="text-muted"> ({sure})</span>}
        {v.at && (
          <>
            , <Time value={v.at} />
          </>
        )}
        .
      </p>
      {(v.why ?? []).length > 0 && (
        <ul className="m-0 pl-5 text-sm">
          {(v.why ?? []).map((w, i) => (
            <li key={i}>
              <UntrustedText value={w} limits={{ maxChars: 600, maxLines: 6 }} />
            </li>
          ))}
        </ul>
      )}
      <p className="m-0 text-sm">
        <strong>Evidence strength: {GRADE_LABEL[s.grade]}.</strong>{" "}
        <span className="text-muted">
          <UntrustedText value={s.reasons.join("; ")} limits={{ maxChars: 600, maxLines: 4 }} />. This is a count of what ARGUS could check, separate from any confidence.
        </span>
      </p>
      <ul aria-label="What the strength counts" className="m-0 grid list-none grid-cols-1 gap-x-6 gap-y-0.5 p-0 text-sm text-muted sm:grid-cols-2">
        {strengthCounts(s).map((c) => (
          <li key={c.label}>
            {c.label}: <span className="text-text tabular-nums">{count(c.known)} of {count(c.of)}</span>
          </li>
        ))}
      </ul>
    </Section>
  );
}

function Summary({ report }: { report: Report }) {
  const s = report.summary;
  if (!s) return null;
  return (
    <Section title="Summary, in the AI investigator's words">
      <p className="m-0 text-sm">
        <UntrustedText value={s.text} block limits={{ maxChars: 2000, maxLines: 30 }} />
      </p>
      <p className="m-0 text-xs text-muted">
        {s.checked ? "Every quote below was found in what the model read." : "Some quotes could not be matched to what the model read."}{" "}
        <UntrustedText value={s.note} limits={{ maxChars: 300, maxLines: 2 }} />
      </p>
      {s.cites.length > 0 && (
        <ul className="m-0 pl-5 text-sm">
          {s.cites.map((c, i) => (
            <li key={i}>
              <q>
                <UntrustedText value={c.quote} limits={{ maxChars: 300, maxLines: 3 }} />
              </q>
              <Eids eids={c.eids} />
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Timeline({ report }: { report: Report }) {
  return (
    <Section title="Timeline">
      {report.timeline.length === 0 ? (
        <p className="m-0 text-sm text-muted">Nothing with a time yet.</p>
      ) : (
        <ol className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
          {report.timeline.map((e, i) => (
            <li key={i} className="grid grid-cols-[minmax(8rem,12rem)_1fr] gap-x-3">
              <span className="text-muted">
                <Time value={e.at} />
                {e.until && (
                  <>
                    {" "}
                    to <Time value={e.until} />
                  </>
                )}
              </span>
              <span>
                <Badge className="mr-1.5">{KIND_WORD[e.kind ?? "fact"]}</Badge>
                <UntrustedText value={e.sentence} limits={{ maxChars: 600, maxLines: 6 }} />
                <Eids eids={e.eids} />
                <Values values={e.values} />
              </span>
            </li>
          ))}
        </ol>
      )}
    </Section>
  );
}

export function Evidence({ report, bare = false }: { report: Report; bare?: boolean }) {
  return (
    <Section title="Evidence" bare={bare}>
      <p className="m-0 text-sm text-muted">
        Each known fact, read against {outcomeLabel(report.relative_to)}
        {report.verdict.status !== "proposed" ? " (there is no proposal)" : ""}.
      </p>
      <DataTable
        caption="Evidence: each known fact and how it bears on the verdict"
        rows={report.evidence}
        rowKey={(r, i) => `${r.fact.key}:${i}`}
        empty="No known fact yet."
        columns={[
          { key: "stance", header: "Bears on it", cell: (r) => <Badge tone={STANCE_TONE[r.stance]}>{STANCE_LABEL[r.stance]}</Badge> },
          {
            key: "fact",
            header: "Fact",
            cell: (r) => (
              <>
                <UntrustedText value={r.fact.sentence} limits={{ maxChars: 600, maxLines: 6 }} />
                <Values values={r.fact.values} />
              </>
            ),
          },
          { key: "from", header: "From", cell: (r) => <span className="font-mono text-xs"><UntrustedText value={factSource(r.fact)} limits={{ maxChars: 160, maxLines: 1 }} /></span> },
        ]}
      />
    </Section>
  );
}

export function Hypotheses({ report, bare = false }: { report: Report; bare?: boolean }) {
  const refs = (list: Report["hypotheses"][number]["support"]) =>
    (list ?? []).length === 0
      ? "—"
      : (list ?? []).map((r) => (
          <div key={r.key}>
            <UntrustedText value={r.text} limits={{ maxChars: 300, maxLines: 3 }} />
            <Eids eids={r.eids} />
          </div>
        ));
  return (
    <Section title="Hypotheses" bare={bare}>
      <DataTable
        caption="Hypotheses, with the facts for and against each"
        rows={report.hypotheses}
        rowKey={(h, i) => `${h.name}:${i}`}
        empty="None yet."
        columns={[
          {
            key: "h",
            header: "Hypothesis",
            cell: (h) => (
              <>
                <UntrustedText value={h.name} limits={{ maxChars: 200, maxLines: 2 }} /> <span className="text-xs text-muted">({h.by === "argus" ? "ARGUS" : "the model"})</span>
              </>
            ),
          },
          { key: "for", header: "For it", cell: (h) => refs(h.support) },
          { key: "against", header: "Against it", cell: (h) => refs(h.against) },
        ]}
      />
    </Section>
  );
}

export function Unknowns({ report, bare = false }: { report: Report; bare?: boolean }) {
  return (
    <Section title="Checked and unknown" bare={bare}>
      {report.unknowns.length === 0 ? (
        <p className="m-0 text-sm text-muted">Nothing open.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1.5 p-0 text-sm">
          {report.unknowns.map((g) => (
            <li key={g.key}>
              {g.floor && <Badge tone="warn" className="mr-1.5">Blocks a benign proposal</Badge>}
              <UntrustedText value={g.what} limits={{ maxChars: 300, maxLines: 3 }} /> <span className="text-muted">Why: </span>
              <UntrustedText value={g.why} limits={{ maxChars: 300, maxLines: 3 }} />. <span className="text-muted">Who can resolve it: </span>
              <UntrustedText value={g.who} limits={{ maxChars: 200, maxLines: 2 }} />.
              <Eids eids={g.eids} />
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

function Provenance({ report }: { report: Report }) {
  // a key fact on the verdict card links here by the E-number in the address: bring that line into view
  useEffect(() => {
    const wanted = window.location.hash.slice(1);
    if (wanted !== "") document.getElementById(wanted)?.scrollIntoView?.({ block: "center" });
  }, []);
  return (
    <Section title="Where each fact came from">
      <p className="m-0 text-sm text-muted">Every SIEM request behind this report, by its E-number: the query, what it returned and when.</p>
      {report.provenance.length === 0 ? (
        <p className="m-0 text-sm">No SIEM query.</p>
      ) : (
        <ul className="m-0 flex list-none flex-col gap-1 p-0 font-mono text-xs">
          {report.provenance.map((p) => (
            <li key={p.eid} id={`eid-${p.eid}`} className="scroll-mt-20 rounded-control px-1 target:bg-accent-soft">
              <UntrustedText value={p.line} limits={{ maxChars: 400, maxLines: 2 }} />
            </li>
          ))}
        </ul>
      )}
      <details>
        <summary className="cursor-pointer text-sm font-medium">The exact queries and answers (raw)</summary>
        <div className="mt-1 max-h-96 overflow-auto rounded-control border border-border bg-surface-2 p-2 font-mono text-xs">
          <UntrustedText value={JSON.stringify(report.provenance, null, 2)} block limits={{ maxChars: 30_000, maxLines: 800 }} />
        </div>
      </details>
    </Section>
  );
}

/** report@2 in full (plan §7.3): verdict and evidence strength, what the extra SIEM queries found, the timeline, evidence, hypotheses, unknowns, actions, cost and sources. */
export function ReportView({ reports }: { reports: readonly Report[] }) {
  const [chosen, setChosen] = useState(0);
  if (reports.length === 0) {
    return <p className="m-0 text-sm text-muted">No report yet: ARGUS has not built this investigation&apos;s dossier. It works through new investigations within minutes.</p>;
  }
  const report = reports[Math.min(chosen, reports.length - 1)] ?? reports[0];
  if (!report) return null;
  return (
    <div className="flex flex-col gap-4">
      <p className="m-0 text-sm text-muted">
        What ARGUS found, where each fact came from (its E-number), and what is still open. Version {report.version} of the investigation.
        {report.note && (
          <>
            {" "}
            Note: <UntrustedText value={report.note} limits={{ maxChars: 300, maxLines: 2 }} />.
          </>
        )}
      </p>
      {reports.length > 1 && (
        <div role="group" aria-label="Reports of this investigation" className="flex flex-wrap gap-2">
          {reports.map((r, i) => (
            <Button key={r.assessment_id ?? "alone"} size="sm" variant={i === chosen ? "primary" : "secondary"} aria-pressed={i === chosen} onClick={() => setChosen(i)}>
              {reportTab(r.verdict.source)}
            </Button>
          ))}
        </div>
      )}
      <Verdict report={report} />
      <Summary report={report} />
      <FoundBox report={report} />
      <Timeline report={report} />
      <Evidence report={report} />
      <Hypotheses report={report} />
      <Unknowns report={report} />
      <Section title="Actions">
        {report.actions.length === 0 ? (
          <p className="m-0 text-sm text-muted">None suggested.</p>
        ) : (
          <ul className="m-0 pl-5 text-sm">
            {report.actions.map((a, i) => (
              <li key={i}>
                <UntrustedText value={a.text} limits={{ maxChars: 300, maxLines: 3 }} />{" "}
                <span className="text-muted">
                  Who: <UntrustedText value={a.who} limits={{ maxChars: 200, maxLines: 1 }} />.
                  {a.why && (
                    <>
                      {" "}
                      Why: <UntrustedText value={a.why} limits={{ maxChars: 300, maxLines: 3 }} />.
                    </>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Section>
      <Section title="Cost">
        <p className="m-0 text-sm">{costSentence(report.cost)}.</p>
      </Section>
      <Provenance report={report} />
      {(report.hidden ?? 0) > 0 && (
        <p className="m-0 text-xs text-muted">
          The results of {report.hidden} log {report.hidden === 1 ? "check are" : "checks are"} hidden: they need log access in ELK.
        </p>
      )}
    </div>
  );
}
