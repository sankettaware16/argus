// By rule and By host or IP (the classic pages /rules and /hosts): the same investigations, per
// detection rule or per entity, each row a link into the Inbox filtered to it. Rule names and
// entity values come from SIEM data: shown as untrusted text.
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import type { EntityRowOut, RuleOut } from "../client/types.gen";
import { Loading, Problem } from "../components/Problem";
import { Time } from "../components/Time";
import { UntrustedText } from "../components/UntrustedText";
import { Badge } from "../components/ui/badge";
import { DataTable } from "../components/ui/table";
import { count } from "../lib/format";
import { KIND_TITLES } from "../lib/labels";
import { KINDS, type Kind } from "../lib/inboxQuery";
import { entitiesOptions, rulesOptions } from "../lib/queries";

function Kinds({ rule }: { rule: RuleOut }) {
  if (rule.type == null && rule.interval == null) return <span className="text-muted">unknown</span>;
  return (
    <>
      {rule.type != null && <UntrustedText value={rule.type} limits={{ maxChars: 20, maxLines: 1 }} />}
      {rule.interval != null && (
        <>
          , every <UntrustedText value={rule.interval} limits={{ maxChars: 10, maxLines: 1 }} />
        </>
      )}
    </>
  );
}

export function Rules() {
  const rules = useQuery(rulesOptions);
  if (rules.isPending) return <Loading what="the rules" />;
  if (rules.isError) return <Problem error={rules.error} what="The rules" onRetry={() => void rules.refetch()} />;
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">By rule</h1>
      <p className="m-0 max-w-prose text-sm text-muted">The investigations per detection rule. Open a rule to see its investigations that nobody has reviewed yet.</p>
      <DataTable<RuleOut>
        caption="Rules"
        rows={rules.data}
        rowKey={(r) => r.rule_id}
        empty="No investigations yet."
        columns={[
          {
            key: "rule",
            header: "Rule",
            cell: (r) => (
              <Link to="/inbox" search={{ view: "open", rule: r.rule_id }}>
                <UntrustedText value={r.rule_name ?? r.rule_id} limits={{ maxChars: 120, maxLines: 1 }} />
              </Link>
            ),
          },
          { key: "open", header: "Not reviewed", numeric: true, cell: (r) => count(r.open) },
          { key: "investigations", header: "Investigations", numeric: true, cell: (r) => count(r.investigations) },
          { key: "alerts", header: "Alerts", numeric: true, cell: (r) => count(r.alerts) },
          { key: "last", header: "Last alert", cell: (r) => <Time value={r.last_event_at} /> },
          {
            key: "limit",
            header: "Runs at the limit",
            numeric: true,
            cell: (r) =>
              r.truncated > 0 ? (
                <span title={`Runs that produced the rule's maximum of ${r.max_signals ?? "its"} alerts: more matches may have been dropped`}>{count(r.truncated)}</span>
              ) : (
                "0"
              ),
          },
          { key: "kind", header: "Kind", cell: (r) => <Kinds rule={r} /> },
        ]}
      />
      <p className="m-0 text-sm text-muted">Whether a rule is still running needs Kibana&apos;s rule status, which ARGUS cannot read with its key yet.</p>
    </>
  );
}

function isKind(kind: string): kind is Kind {
  return (KINDS as readonly string[]).includes(kind);
}

export function Hosts() {
  const entities = useQuery(entitiesOptions);
  if (entities.isPending) return <Loading what="the hosts and addresses" />;
  if (entities.isError) return <Problem error={entities.error} what="The hosts and addresses" onRetry={() => void entities.refetch()} />;
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">By host or IP</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        The investigations per host, IP address, domain or user. An address seen in more than 200 investigations (a proxy, a scanner target) is marked common: it says little about any one of them.
      </p>
      <DataTable<EntityRowOut>
        caption="Hosts and addresses"
        rows={entities.data}
        rowKey={(e) => `${e.kind}:${e.value}`}
        empty="Nothing yet."
        columns={[
          {
            key: "entity",
            header: "Host or IP",
            cell: (e) => {
              const value = <UntrustedText value={e.value} limits={{ maxChars: 120, maxLines: 1 }} className="font-mono" />;
              return (
                <>
                  {isKind(e.kind) ? (
                    <Link to="/inbox" search={{ view: "all", kind: e.kind, value: e.value }}>
                      {value}
                    </Link>
                  ) : (
                    value
                  )}{" "}
                  <span className="text-xs text-muted">{KIND_TITLES[e.kind] ?? e.kind}</span>
                  {e.supernode && (
                    <>
                      {" "}
                      <Badge>common</Badge>
                    </>
                  )}
                </>
              );
            },
          },
          { key: "investigations", header: "Investigations", numeric: true, cell: (e) => count(e.investigations) },
        ]}
      />
    </>
  );
}
