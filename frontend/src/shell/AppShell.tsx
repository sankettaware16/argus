import { Dialog } from "@base-ui/react/dialog";
import { Link, Outlet, useNavigate, useRouterState } from "@tanstack/react-router";
import { useCallback, useEffect, useId, useRef, useState } from "react";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { Messages, useAnnounce } from "../lib/announce";
import { useBuildState } from "../lib/build";
import { cn } from "../lib/cn";
import { DecidedProvider } from "../lib/decided";
import { can, signOut, useSession, useSessionWatch } from "../lib/session";
import { opensSetup, setupLeft } from "../lib/setup";
import { organisationName } from "../lib/site";
import { useNeedsYouCount } from "../lib/today";
import { UndoToast } from "../components/decide/UndoToast";
import { browserStorage, loadShortcuts } from "../lib/shortcuts";
import { AccessBanner } from "./AccessBanner";
import { ACCOUNT, MORE, PRIMARY, type NavItem } from "./nav";
import { SystemDot } from "./Status";
import { EntityDrawerProvider } from "../components/EntityDrawer";

const ITEM =
  "flex min-h-9 items-center justify-between gap-2 rounded-control px-2 text-sm text-text no-underline hover:bg-surface-3 aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold";

function useMoreItems(): NavItem[] {
  const session = useSession();
  const admin = can(session.data, "admin") || import.meta.env.DEV;
  return MORE.filter((m) => !m.admin || admin);
}

function NavLink({ item, onPick, badge, className = ITEM }: { item: NavItem; onPick?: () => void; badge?: number | null; className?: string }) {
  if (item.to === undefined) {
    return (
      <a href={item.href} title={item.hint} className={className}>
        {item.label}
      </a>
    );
  }
  return (
    <Link to={item.to} search={item.search} title={item.hint} className={className} activeOptions={{ exact: item.to === "/", includeSearch: false }} onClick={onPick}>
      <span>{item.label}</span>
      {badge != null && badge > 0 && (
        <span className="rounded-full bg-surface-3 px-1.5 text-xs font-semibold tabular-nums" data-testid="today-badge">
          {badge}
          <span className="sr-only"> need you</span>
        </span>
      )}
    </Link>
  );
}

/** More's entries; the classic queues and the administration pages each under their own heading. */
function MoreList({ onPick }: { onPick?: () => void }) {
  const items = useMoreItems();
  const plain = items.filter((i) => i.group === undefined);
  const groups = ["More queues", "Administration"].map((name) => ({ name, items: items.filter((i) => i.group === name) })).filter((g) => g.items.length > 0);
  return (
    <ul className="m-0 flex list-none flex-col gap-0.5 p-0" data-testid="more-list">
      {plain.map((item) => (
        <li key={item.label}>
          <NavLink item={item} onPick={onPick} />
        </li>
      ))}
      {groups.map((g) => (
        <li key={g.name}>
          <p className="m-0 mt-2 px-2 text-xs font-semibold tracking-wide text-muted uppercase">{g.name}</p>
          <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
            {g.items.map((item) => (
              <li key={item.label}>
                <NavLink item={item} onPick={onPick} />
              </li>
            ))}
          </ul>
        </li>
      ))}
    </ul>
  );
}

/** The side nav (640 px and up): the four pages, then More as an inline list. */
function SideNav() {
  const [more, setMore] = useState(false);
  const count = useNeedsYouCount();
  const id = useId();
  return (
    <nav aria-label="Main" className="flex flex-col gap-3">
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {PRIMARY.map((item) => (
          <li key={item.label}>
            <NavLink item={item} badge={item.label === "Today" ? count : null} className={cn(ITEM, "max-lg:flex-col max-lg:justify-center max-lg:gap-0 max-lg:px-1 max-lg:text-xs")} />
          </li>
        ))}
      </ul>
      <div className="border-t border-border pt-2">
        <button type="button" aria-expanded={more} aria-controls={id} onClick={() => setMore(!more)} className={cn(ITEM, "w-full cursor-pointer border-0 bg-transparent max-lg:px-1 max-lg:text-xs")}>
          More <span aria-hidden="true">{more ? "▴" : "▾"}</span>
        </button>
        {more && (
          <div id={id} className="mt-1">
            <MoreList />
          </div>
        )}
      </div>
    </nav>
  );
}

/** The phone's bottom tab bar (under 640 px). */
function BottomBar() {
  const count = useNeedsYouCount();
  return (
    <nav aria-label="Pages" className="fixed inset-x-0 bottom-0 z-30 grid h-14 grid-cols-4 border-t border-border bg-surface sm:hidden" data-testid="bottom-bar">
      {PRIMARY.map((item) => (
        <Link
          key={item.label}
          to={item.to ?? "/"}
          search={item.search}
          activeOptions={{ exact: item.to === "/", includeSearch: false }}
          className="flex flex-col items-center justify-center gap-0.5 text-xs text-text no-underline aria-[current=page]:bg-accent-soft aria-[current=page]:font-semibold"
        >
          <span>{item.label}</span>
          {item.label === "Today" && count != null && count > 0 && <span className="text-[0.6875rem] text-muted tabular-nums">{count}</span>}
        </Link>
      ))}
    </nav>
  );
}

/** The header's search box; `/` focuses it from any page (§10.3). */
function HeaderSearch() {
  const navigate = useNavigate();
  const [q, setQ] = useState("");
  const box = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const press = (e: KeyboardEvent) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName))) return;
      const own = document.querySelector<HTMLInputElement>("[data-search-box=page]");
      e.preventDefault();
      (own ?? box.current)?.focus();
    };
    document.addEventListener("keydown", press);
    return () => document.removeEventListener("keydown", press);
  }, []);
  return (
    <form
      role="search"
      aria-label="Search ARGUS"
      className="hidden min-w-0 flex-1 sm:flex"
      onSubmit={(e) => {
        e.preventDefault();
        const said = q.trim();
        void navigate({ to: "/search", search: said ? { q: said } : {} });
        setQ("");
      }}
    >
      <input
        ref={box}
        type="search"
        value={q}
        onChange={(e) => setQ(e.target.value)}
        placeholder="Search incidents, addresses, hosts…"
        aria-label="Search incidents, addresses, hosts, accounts"
        data-search-box="header"
        maxLength={200}
        className="min-h-8 w-full max-w-md rounded-control border border-border-strong bg-surface px-3 text-sm text-text"
      />
    </form>
  );
}

const KEYS: [string, string][] = [
  ["j / k", "Next / previous card or row; the preview follows"],
  ["Enter, o", "Open the incident"],
  ["Esc", "Close the pane, drawer, dialog, menu or sheet"],
  ["c", "Confirm incident… (opens the dialog)"],
  ["d", "Not an incident… (opens the menu: e, s, p, w, u; then Enter)"],
  ["x", "Select the row"],
  ["1–5", "The five outcomes, on an alert group's page only"],
  ["/", "Search"],
  ["?", "These keys"],
];

function KeysDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup className="fixed top-1/2 left-1/2 z-50 flex w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 rounded-card border border-border bg-surface p-5 text-text shadow-card">
          <Dialog.Title className="m-0 text-lg font-semibold">Keyboard shortcuts</Dialog.Title>
          <p className="m-0 text-sm text-muted">Nothing is sent on one key: c, d and the letters open a dialog or a menu, and a second, deliberate Enter sends.</p>
          <dl className="m-0 grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1 text-sm">
            {KEYS.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="font-mono font-semibold">{k}</dt>
                <dd className="m-0">{v}</dd>
              </div>
            ))}
          </dl>
          <div className="flex justify-end">
            <Dialog.Close render={<Button />}>Close</Dialog.Close>
          </div>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** The keys of every page (§13): `?` the keys' help, `g` then `t` `i` `s` `r` the four pages. */
function useGlobalKeys(onHelp: () => void) {
  const navigate = useNavigate();
  // the alert-group page and the advanced search have their own `?` (the old Inbox's keys)
  const path = useRouterState({ select: (st) => st.location.pathname });
  const ownHelp = path.startsWith("/alert-groups/") || path === "/search";
  useEffect(() => {
    let g = 0;
    const press = (e: KeyboardEvent) => {
      // the switch as it is now: a page may have turned the letters off since this shell drew
      if (e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented || !loadShortcuts(browserStorage())) return;
      const t = e.target as HTMLElement | null;
      if (t && (t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName) || t.closest("[role=dialog],[role=alertdialog],[role=menu],form"))) return;
      if (e.key === "?") {
        if (ownHelp) return;
        e.preventDefault();
        onHelp();
        return;
      }
      if (e.key === "g") {
        g = Date.now();
        return;
      }
      if (Date.now() - g < 1500) {
        const to = { t: "/", i: "/incidents", s: "/search", r: "/reports" }[e.key];
        g = 0;
        if (to) {
          e.preventDefault();
          void navigate({ to, search: to === "/incidents" ? { view: "needs-you" } : {} });
        }
      }
    };
    document.addEventListener("keydown", press);
    return () => document.removeEventListener("keydown", press);
  }, [navigate, onHelp, ownHelp]);
}

/** The person's name opens: Your access · Keyboard shortcuts · Sign out (§4.1). */
function AccountMenu({ phone = false, onPick }: { phone?: boolean; onPick?: () => void }) {
  const session = useSession();
  const { announce } = useAnnounce();
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [keys, setKeys] = useState(false);
  const id = useId();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const away = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", away);
    return () => document.removeEventListener("mousedown", away);
  }, [open]);
  if (!session.data) return null;
  const items = (
    <>
      {ACCOUNT.map((a) => (
        <a key={a.label} href={a.href} title={a.hint} className={ITEM}>
          {a.label}
        </a>
      ))}
      <button
        type="button"
        className={cn(ITEM, "w-full cursor-pointer border-0 bg-transparent text-left")}
        onClick={() => {
          setKeys(true);
          setOpen(false);
          onPick?.();
        }}
      >
        Keyboard shortcuts
      </button>
      <button
        type="button"
        className={cn(ITEM, "w-full cursor-pointer border-0 bg-transparent text-left")}
        aria-disabled={busy}
        onClick={() => {
          if (busy) return;
          setBusy(true);
          signOut().catch((e: unknown) => {
            setBusy(false);
            announce(e instanceof Error ? e.message : "Signing out did not work; try again.", "danger");
          });
        }}
      >
        Sign out
      </button>
    </>
  );
  if (phone) {
    return (
      <div className="flex flex-col gap-0.5">
        <p className="m-0 px-2 text-xs font-semibold tracking-wide text-muted uppercase">
          <UntrustedText value={session.data.user.display_name} limits={{ maxChars: 60, maxLines: 1 }} />
        </p>
        {items}
        <KeysDialog open={keys} onOpenChange={setKeys} />
      </div>
    );
  }
  return (
    <div ref={box} className="relative" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
      <button type="button" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen(!open)} className="inline-flex min-h-8 max-w-48 cursor-pointer items-center gap-1 truncate rounded-control border-0 bg-transparent px-2 text-sm text-text hover:bg-surface-2" data-testid="account-menu">
        <UntrustedText value={session.data.user.display_name} limits={{ maxChars: 60, maxLines: 1 }} /> <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div id={id} data-testid="account-items" className="absolute right-0 z-30 mt-1 flex w-56 flex-col gap-0.5 rounded-card border border-border bg-surface p-1 shadow-card">
          {items}
        </div>
      )}
      <KeysDialog open={keys} onOpenChange={setKeys} />
    </div>
  );
}

/** The phone's More: a sheet with More's entries and the account's. */
function PhoneMore() {
  const [open, setOpen] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      <Dialog.Trigger render={<Button size="sm" className="sm:hidden" />}>More</Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup className="fixed inset-x-0 bottom-0 z-50 flex max-h-[85vh] flex-col gap-3 overflow-auto rounded-t-card border border-border bg-surface p-4 text-text shadow-card">
          <Dialog.Title className="m-0 text-base font-semibold">More</Dialog.Title>
          <MoreList onPick={() => setOpen(false)} />
          <AccountMenu phone onPick={() => setOpen(false)} />
          <Dialog.Close render={<Button />}>Close</Dialog.Close>
        </Dialog.Popup>
      </Dialog.Portal>
    </Dialog.Root>
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

/**
 * The app's frame (docs/p4f-ui-spec.md §4): four pages and More in the side nav (a rail between
 * 640 and 1023 px, a bottom tab bar on a phone), the header's search, the system dot and the
 * person's menu, the messages, and the Undo toast.
 */
export function AppShell() {
  const session = useSession();
  const path = useRouterState({ select: (st) => st.location.pathname });
  const bare = path === "/setup" || path === "/confirmed";
  const navigate = useNavigate();
  const pending = session.data?.setup_pending === true;
  const admin = can(session.data, "admin");
  useEffect(() => {
    // a new installation: the first-time setup opens by itself, once per browser session
    if (opensSetup(pending, admin, path, setupLeft())) void navigate({ to: "/setup", replace: true });
  }, [pending, admin, path, navigate]);
  useSessionWatch();
  const [help, setHelp] = useState(false);
  const openHelp = useCallback(() => setHelp(true), []);
  useGlobalKeys(openHelp);
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
          <a href="/signin?next=/app">Sign in</a>
        </p>
      </main>
    );
  }
  if (bare) {
    // the first-time setup has the whole screen: its chapters and their own way back
    return (
      <main id="main" tabIndex={-1} className="focus:outline-none">
        <Outlet />
      </main>
    );
  }
  return (
    <DecidedProvider>
      <div className="min-h-screen sm:grid sm:grid-cols-[5.5rem_1fr] lg:grid-cols-[14rem_1fr]">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-surface focus:p-2">
          Skip to content
        </a>
        <aside className="hidden border-r border-border bg-surface-2 sm:sticky sm:top-0 sm:block sm:h-screen sm:overflow-y-auto">
          <div className="px-3 py-3">
            <Link to="/" className="flex flex-col text-text no-underline">
              <span className="text-lg font-bold tracking-wide">ARGUS</span>
              <span className="text-xs text-muted max-lg:hidden">first-line analyst · {organisationName()}</span>
            </Link>
          </div>
          <div className="px-2 pb-4">
            <SideNav />
          </div>
        </aside>
        <div className="flex min-w-0 flex-col">
          <AccessBanner />
          <header className="flex h-14 items-center gap-3 border-b border-border bg-surface px-4" data-testid="app-header">
            <Link to="/" className="text-base font-bold tracking-wide text-text no-underline sm:hidden">
              ARGUS
            </Link>
            <HeaderSearch />
            <span className="ml-auto flex items-center gap-1">
              <Link to="/search" className="inline-flex min-h-8 items-center rounded-control px-2 text-sm text-text no-underline sm:hidden" aria-label="Search">
                <span aria-hidden="true">⌕</span>
              </Link>
              <SystemDot />
              <span className="hidden sm:inline-flex">
                <AccountMenu />
              </span>
              <PhoneMore />
            </span>
          </header>
          <main id="main" tabIndex={-1} className="mx-auto flex w-full max-w-[75rem] flex-col gap-4 px-4 pt-3 pb-24 focus:outline-none sm:pt-5 sm:pb-6">
            <BuildNotice />
            <Messages />
            <EntityDrawerProvider>
              <Outlet />
            </EntityDrawerProvider>
          </main>
        </div>
        <BottomBar />
        <UndoToast />
        <KeysDialog open={help} onOpenChange={setHelp} />
      </div>
    </DecidedProvider>
  );
}
