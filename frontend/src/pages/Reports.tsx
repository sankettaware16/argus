// The daily and weekly reports (Q-H3): the list, and one report with every figure and how it was
// counted, to read or to download as text or JSON. Names in a report come from SIEM data: shown as
// untrusted text.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";
import type { ReportMetricOut, ReportOut, ReportRowOut, ReportSectionOut } from "../client/types.gen";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge } from "../components/ui/badge";
import { Button } from "../components/ui/button";
import { Card, CardTitle } from "../components/ui/card";
import { DataTable } from "../components/ui/table";
import { count, plural } from "../lib/format";
import { reportDetailOptions, reportListOptions } from "../lib/queries";
import { zoneLabel } from "../lib/site";
import { utcDayStart } from "../lib/time";
import { asJson, asText, fileName, save, shown, title, validReportId } from "../lib/reports";

const KINDS = [
  ["all", "All"],
  ["daily", "Daily"],
  ["weekly", "Weekly"],
] as const;
type Choice = (typeof KINDS)[number][0];

export function Reports() {
  const [kind, setKind] = useState<Choice>("all");
  const list = useQuery(reportListOptions(kind));
  if (list.isPending) return <Loading what="the reports" />;
  if (list.isError) return <Problem error={list.error} what="The reports" onRetry={() => void list.refetch()} />;
  const rows = list.data;
  const utcDay = `${utcDayStart()} ${zoneLabel()}`; // where a UTC day begins on the site's clock
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Reports</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        A daily and a weekly report of how ARGUS and its cases are doing: what waits for a person, what happened, what went wrong. Every figure is counted from ARGUS&apos;s own records and says
        how. A day is a UTC day ({utcDay} to {utcDay}); times are shown in {zoneLabel()}.
      </p>
      <nav aria-label="Kind of report" className="flex gap-1">
        {KINDS.map(([value, label]) => (
          <Button key={value} size="sm" variant={kind === value ? "primary" : "secondary"} aria-pressed={kind === value} onClick={() => setKind(value)}>
            {label}
          </Button>
        ))}
      </nav>
      <DataTable<ReportRowOut>
        caption="Reports"
        rows={rows}
        rowKey={(r) => String(r.id)}
        empty={
          kind === "all"
            ? "No report has been made yet. The first one appears after the daily report is switched on, or when an admin runs “argus report daily”."
            : "No report of this kind yet."
        }
        columns={[
          {
            key: "report",
            header: "Report",
            cell: (r) => (
              <Link to="/reports/$id" params={{ id: String(r.id) }}>
                {title(r)}
              </Link>
            ),
          },
          { key: "kind", header: "Kind", cell: (r) => <Badge tone={r.kind === "weekly" ? "info" : "neutral"}>{r.kind === "weekly" ? "Weekly" : "Daily"}</Badge> },
          { key: "made", header: "Made", cell: (r) => <Time value={r.generated_at} /> },
          { key: "prose", header: "Summary", cell: (r) => (r.has_prose ? "Written" : "Figures only") },
        ]}
      />
    </>
  );
}

function Figures({ section }: { section: ReportSectionOut }) {
  return (
    <Card aria-label={section.title}>
      <CardTitle>{section.title}</CardTitle>
      <DataTable<ReportMetricOut>
        caption={section.title}
        rows={section.metrics}
        rowKey={(m) => m.key}
        empty="Nothing could be read for this section."
        columns={[
          { key: "label", header: "Figure", cell: (m) => <UntrustedText value={m.label} limits={{ maxChars: 300, maxLines: 2 }} /> },
          { key: "value", header: "Value", numeric: true, cell: (m) => <span className={m.unit === "text" ? "break-all font-mono text-xs" : undefined}>{shown(m)}</span> },
        ]}
      />
      {section.notes.map((note) => (
        <p key={note} className="m-0 mt-2 text-sm text-muted">
          {note}
        </p>
      ))}
      {section.metrics.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-sm font-medium">How these figures are counted</summary>
          <dl className="m-0 mt-1 text-sm">
            {section.metrics.map((m) => (
              <div key={m.key} className="mb-1">
                <dt className="font-medium">
                  <UntrustedText value={m.label} limits={{ maxChars: 300, maxLines: 2 }} />
                </dt>
                <dd className="m-0 text-muted">{m.definition}</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </Card>
  );
}

function Download({ report }: { report: ReportOut }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button size="sm" variant="secondary" onClick={() => save(fileName(report, "txt"), "text/plain;charset=utf-8", asText(report))}>
        Download as text
      </Button>
      <Button size="sm" variant="secondary" onClick={() => save(fileName(report, "json"), "application/json", asJson(report))}>
        Download as JSON
      </Button>
    </div>
  );
}

export function ReportPage({ id }: { id: string }) {
  const valid = validReportId(id);
  const found = useQuery({ ...reportDetailOptions(id), enabled: valid });
  if (!valid) return <Problem error={null} what="This report" />;
  if (found.isPending) return <Loading what="the report" />;
  if (found.isError) return <Problem error={found.error} what="This report" onRetry={() => void found.refetch()} />;
  const r = found.data;
  const figures = r.sections.reduce((n, s) => n + s.metrics.length, 0);
  return (
    <>
      <p className="m-0 text-sm">
        <Link to="/reports">← All reports</Link>
      </p>
      <h1 className="m-0 text-2xl font-semibold">{title(r)}</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        Covers <Time value={r.period_start} /> to <Time value={r.period_end} />. Made <Time value={r.generated_at} />; what is waiting (cases, actions, approvals, the Kibana backlog) is as at{" "}
        <Time value={r.as_at} />, what happened is for the period. {count(figures)} {plural(figures, "figure")}.
      </p>
      <Download report={r} />
      {r.prose !== null && r.prose !== undefined && (
        <Card aria-label="Summary">
          <CardTitle>Summary</CardTitle>
          <p className="m-0 max-w-prose text-sm">
            <UntrustedText value={r.prose} limits={{ maxChars: 1500, maxLines: 12 }} />
          </p>
          <p className="m-0 mt-1 text-xs text-muted">Written by an AI from the figures below; every number in it was checked against them.</p>
        </Card>
      )}
      {r.sections.map((s) => (
        <Figures key={s.id} section={s} />
      ))}
    </>
  );
}
