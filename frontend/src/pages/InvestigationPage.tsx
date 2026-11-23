import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { InvestigationView } from "../components/investigation/InvestigationView";
import { UntrustedText } from "../components/UntrustedText";
import { stateWords } from "../lib/engine";
import type { Tab } from "../lib/inboxQuery";
import { investigationOptions } from "../lib/queries";

/**
 * The way back from an alert group: to the incident it belongs to (where it is decided), and to
 * the list of all alert groups. An alert group in no incident has only the list.
 */
function Trail({ id }: { id: string }) {
  // the same read the view below makes: one request, shared
  const found = useQuery(investigationOptions(id));
  const incident = found.data?.case ?? null;
  return (
    <nav aria-label="Where this is" className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm" data-testid="alert-trail">
      {incident && (
        <>
          <Link to="/incidents/$id" params={{ id: incident.id }} search={{ tab: "alert-groups" }} className="inline-flex min-w-0 items-center gap-1 font-medium" data-testid="back-to-incident">
            <span aria-hidden="true">←</span>
            <span className="truncate">
              Back to {stateWords({ state: incident.state, number: incident.number }).split(" · ")[0]?.toLowerCase()}: <UntrustedText value={incident.title} limits={{ maxChars: 90, maxLines: 1 }} />
            </span>
          </Link>
          <span aria-hidden="true" className="text-muted">
            ·
          </span>
        </>
      )}
      <Link to="/alerts" search={incident ? { in: "incident" } : {}} className={incident ? "text-muted" : undefined}>
        {incident ? "All alerts" : "← All alerts"}
      </Link>
    </nav>
  );
}

/** One alert group on its own page (docs/p4f-ui-spec.md §8): links from the incidents, Today, Alerts, the dashboards and proposals. */
export function InvestigationPage({ id, tab }: { id: string; tab: Tab }) {
  const navigate = useNavigate();
  return (
    <>
      <Trail id={id} />
      <InvestigationView id={id} tab={tab} level={1} queue onTab={(next) => void navigate({ to: "/alert-groups/$id", params: { id }, search: { tab: next }, replace: true })} />
    </>
  );
}
