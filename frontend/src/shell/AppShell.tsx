import { Link, Outlet } from "@tanstack/react-router";
import { useId, useState } from "react";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { Messages, useAnnounce } from "../lib/announce";
import { useBuildState } from "../lib/build";
import { cn } from "../lib/cn";
import { signOut, useSession, useSessionWatch } from "../lib/session";
import { AccessBanner } from "./AccessBanner";
import { NAV } from "./nav";
import { CostStatus, SiemStatus, SyncStatus } from "./Status";
import { organisationName } from "../lib/site";

const ITEM =
  "flex min-h-8 items-center justify-between gap-2 rounded-control px-2 text-sm text-text no-underline hover:bg-surface-3 aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold";

function Nav({ onPick }: { onPick: () => void }) {
  return (
    <nav aria-label="Main" className="flex flex-col gap-4">
      {NAV.map((group) => (
        <div key={group.label}>
          <p className="m-0 mb-1 px-2 text-xs font-semibold tracking-wide text-muted uppercase">{group.label}</p>
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
            {group.items.map((item) => (
              <li key={item.label}>
                {item.to !== undefined ? (
                  <Link to={item.to} search={item.search} title={item.hint} className={ITEM} activeOptions={{ exact: item.search === undefined, includeSearch: item.search !== undefined }} onClick={onPick}>
                    {item.label}
                  </Link>
                ) : (
                  <a href={item.href} title={item.hint} className={ITEM}>
                    {item.label}
                    {item.tag !== null && (
                      <span className="text-xs font-normal text-muted">
                        {item.tag ?? "classic"}
                        <span className="sr-only"> page</span>
                      </span>
                    )}
                  </a>
                )}
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function BuildNotice() {
  const { stale, ask } = useBuildState();
  if (!stale && !ask) return null;
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info" role="status">
      <p className="m-0">ARGUS was updated on the server. Reload the page to use the new version; nothing you saved is lost.</p>
      <Button size="sm" onClick={() => window.location.reload()}>
        Reload
      </Button>
    </div>
  );
}

function Account() {
  const session = useSession();
  const { announce } = useAnnounce();
  const [busy, setBusy] = useState(false);
  if (!session.data) return null;
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="max-w-48 truncate" title="Signed in">
        <UntrustedText value={session.data.user.display_name} limits={{ maxChars: 60, maxLines: 1 }} />
      </span>
      <Button
        size="sm"
        disabled={busy}
        onClick={() => {
          setBusy(true);
          signOut().catch((e: unknown) => {
            setBusy(false);
            announce(e instanceof Error ? e.message : "Signing out did not work; try again.", "danger");
          });
        }}
      >
        Sign out
      </Button>
    </div>
  );
}

/** The app's frame: navigation, the status bar (AI cost, SIEM, Kibana sync), messages. */
export function AppShell() {
  const session = useSession();
  useSessionWatch();
  const [open, setOpen] = useState(false);
  const navId = useId();
  if (session.isPending) {
    return (
      <div className="p-6 text-muted" aria-busy="true">
        Loading ARGUS…
      </div>
    );
  }
  if (session.isError) {
    return (
      <main id="main" className="p-6">
        <h1 className="text-xl font-semibold">ARGUS cannot start this page</h1>
        <p>Your session could not be read. If you were signed out, the sign-in page opens by itself.</p>
        <p>
          <a href="/signin?next=/app">Sign in</a> · <a href="/classic">Use the classic pages</a>
        </p>
      </main>
    );
  }
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[15rem_1fr]">
      <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-surface focus:p-2">
        Skip to content
      </a>
      <aside className="border-b border-border bg-surface-2 lg:sticky lg:top-0 lg:h-screen lg:overflow-y-auto lg:border-r lg:border-b-0">
        <div className="flex items-center justify-between gap-2 px-4 py-3">
          <Link to="/" className="flex flex-col text-text no-underline">
            <span className="text-lg font-bold tracking-wide">ARGUS</span>
            <span className="text-xs text-muted">first-line analyst · {organisationName()}</span>
          </Link>
          <Button className="lg:hidden" aria-expanded={open} aria-controls={navId} onClick={() => setOpen(!open)}>
            {open ? "Close menu" : "Menu"}
          </Button>
        </div>
        <div id={navId} className={cn("px-2 pb-4 lg:block", open ? "block" : "hidden")}>
          <Nav onPick={() => setOpen(false)} />
        </div>
      </aside>
      <div className="flex min-w-0 flex-col">
        <AccessBanner />
        <header className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2 border-b border-border bg-surface px-4 py-2">
          <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
            <CostStatus />
            <SiemStatus />
            <SyncStatus />
          </div>
          <Account />
        </header>
        <main id="main" tabIndex={-1} className="flex w-full max-w-[96rem] flex-col gap-4 px-4 py-5 focus:outline-none">
          <BuildNotice />
          <Messages />
          <Outlet />
        </main>
      </div>
    </div>
  );
}

