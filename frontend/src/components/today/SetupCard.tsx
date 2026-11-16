import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { settingsOptions } from "../../lib/admin";
import { can, useSession } from "../../lib/session";
import { Card, CardTitle } from "../ui/card";

/** Until ARGUS has its SIEM address and key, an administrator is asked to finish the first-time setup (calm, nothing else is blocked). */
export function SetupCard() {
  const session = useSession();
  const admin = can(session.data, "admin");
  const settings = useQuery({ ...settingsOptions, enabled: admin });
  if (!admin || settings.data?.setup_needed !== true) return null;
  return (
    <Card aria-label="First-time setup" data-testid="setup-card" className="border-info/40 bg-info-soft">
      <CardTitle>Finish the first-time setup</CardTitle>
      <p className="m-0 mb-2 max-w-prose text-sm">ARGUS is not connected to your SIEM yet, so it has nothing to watch. It takes a few minutes: your organisation, the SIEM&apos;s address and a read-only key.</p>
      <Link to="/setup" className="inline-flex min-h-8 items-center rounded-control border border-accent bg-accent px-3 text-sm font-medium text-accent-fg no-underline hover:bg-accent-hover">
        Start the setup
      </Link>
    </Card>
  );
}
