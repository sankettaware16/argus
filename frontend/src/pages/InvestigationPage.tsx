import { Link, useNavigate } from "@tanstack/react-router";
import { InvestigationView } from "../components/investigation/InvestigationView";
import type { Tab } from "../lib/inboxQuery";

/** One investigation on its own page (links from the dashboard, proposals and other investigations). */
export function InvestigationPage({ id, tab }: { id: string; tab: Tab }) {
  const navigate = useNavigate();
  return (
    <>
      <p className="m-0 text-sm">
        <Link to="/inbox" search={{ view: "attention", id }}>
          ← Open it in the Inbox
        </Link>
      </p>
      <InvestigationView id={id} tab={tab} level={1} queue onTab={(next) => void navigate({ to: "/investigations/$id", params: { id }, search: { tab: next }, replace: true })} />
    </>
  );
}
