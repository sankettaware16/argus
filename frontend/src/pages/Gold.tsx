// The gold set (the classic page /gold): the answer key a person confirms, item by item. A row opens
// the investigation, where the gold box takes the answer. Rule names are SIEM data: untrusted text.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { GoldRowOut } from "../client/types.gen";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { DataTable } from "../components/ui/table";
import { count } from "../lib/format";
import { outcomeLabel } from "../lib/labels";
import { goldOptions } from "../lib/queries";

const PART: Record<string, string> = { dev: "tuning", test: "test" };

export function Gold() {
  const gold = useQuery(goldOptions);
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Gold set</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        The answer key: real investigations whose correct outcome you confirm. It is used to score how often ARGUS, and later a model, is right. Open one, judge it from its evidence, and choose the correct outcome in its gold box.
      </p>
      {gold.isPending && <Loading what="the gold set" />}
      {gold.isError && <Problem error={gold.error} what="The gold set" onRetry={() => void gold.refetch()} />}
      {gold.data && (
        <>
          <p className="m-0 text-sm">
            <strong>
              {count(gold.data.progress.answered)} of {count(gold.data.progress.items)} answered
            </strong>
            {Object.entries(gold.data.progress.by_split).map(([split, n]) => (
              <span key={split}>
                {" · "}
                {PART[split] ?? split} part {count(n)}
              </span>
            ))}
          </p>
          <DataTable<GoldRowOut>
            caption="Gold set"
            rows={gold.data.items}
            rowKey={(r) => r.investigation_id}
            empty={
              <>
                No gold set is stored yet (<code>argus gold import</code>).
              </>
            }
            columns={[
              {
                key: "rule",
                header: "Rule",
                cell: (r) => (
                  <Link to="/investigations/$id" params={{ id: r.investigation_id }}>
                    <UntrustedText value={r.rule_name} limits={{ maxChars: 100, maxLines: 1 }} />
                  </Link>
                ),
              },
              { key: "answer", header: "Your answer", cell: (r) => (r.outcome != null ? outcomeLabel(r.outcome) : <em>not yet</em>) },
              { key: "by", header: "Answered", cell: (r) => (r.answered_at != null ? <Time value={r.answered_at} /> : <span className="text-muted">—</span>) },
              { key: "part", header: "Part", cell: (r) => PART[r.split] ?? r.split },
            ]}
          />
        </>
      )}
    </>
  );
}
