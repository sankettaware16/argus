import { Link, useNavigate } from "@tanstack/react-router";
import { InvestigationView } from "../components/investigation/InvestigationView";
import type { Tab } from "../lib/inboxQuery";

/** One alert group on its own page (docs/p4f-ui-spec.md §8): links from the incidents, Today, the overview and proposals. */
export function InvestigationPage({ id, tab }: { id: string; tab: Tab }) {
  const navigate = useNavigate();
  return (
    <>
      <p className="m-0 text-sm">
        <Link to="/search" search={{ advanced: "1", view: "attention", id }}>
          ← Open it in the alert-group list
        </Link>
      </p>
      <InvestigationView id={id} tab={tab} level={1} queue onTab={(next) => void navigate({ to: "/alert-groups/$id", params: { id }, search: { tab: next }, replace: true })} />
    </>
  );
}
