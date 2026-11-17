import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { settingsOptions } from "../../lib/admin";
import { can, useSession } from "../../lib/session";
import { Card, CardTitle } from "../ui/card";

/** Until ARGUS has its SIEM address and key, an administrator is asked to finish the first-time
 * setup (calm, nothing else is blocked); anyone else is told an administrator still has to. */
export function SetupCard() {
  const session = useSession();
  const admin = can(session.data, "admin");
  const settings = useQuery({ ...settingsOptions, enabled: admin });
  if (!admin) {
    if (session.data?.setup_pending !== true) return null;
    return (
      <Card aria-label="First-time setup" data-testid="setup-pending" className="border-info/40 bg-info-soft">
        <CardTitle>ARGUS is not set up yet</CardTitle>
        <p className="m-0 max-w-prose text-sm">An administrator still has to finish the first-time setup and connect ARGUS to your SIEM. Until then there is nothing to review here. Nothing is needed from you.</p>
      </Card>
    );
  }
  if (settings.data?.setup_needed !== true && session.data?.setup_pending !== true) return null;
  return (
    <Card aria-label="First-time setup" data-testid="setup-card" className="border-info/40 bg-info-soft">
      <CardTitle>The setup is not finished</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm">ARGUS is not connected to your SIEM yet, so it has nothing to watch. The setup takes a few minutes: your organisation, the SIEM&apos;s address and ARGUS&apos;s access.</p>
      <Link to="/setup" className="inline-flex min-h-8 items-center rounded-full border border-accent bg-accent px-4 text-sm font-medium text-accent-fg no-underline hover:bg-accent-hover">
        Continue the setup
      </Link>
    </Card>
  );
}
