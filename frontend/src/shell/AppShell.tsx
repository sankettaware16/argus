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
import { useWide } from "../lib/viewport";
import { UndoToast } from "../components/decide/UndoToast";
import { browserStorage, loadShortcuts } from "../lib/shortcuts";
import { AccessBanner } from "./AccessBanner";
import { ACCOUNT, BOTTOM, PRIMARY, SECTIONS, type NavItem, type NavSection } from "./nav";
import { NavIcon } from "./icons";
import { SystemDot } from "./Status";
import { EntityDrawerProvider } from "../components/EntityDrawer";

const ITEM =
  "flex min-h-9 items-center justify-between gap-2 rounded-control px-3 text-[0.9375rem] text-text no-underline transition-colors hover:bg-surface-2 aria-[current=page]:bg-surface-2 aria-[current=page]:font-semibold";

/** The sections a person may see: the administration's for an admin (and a development build), the account look-up where the site has a directory. */
function useSections(): NavSection[] {
  const session = useSession();
  const admin = can(session.data, "admin") || import.meta.env.DEV;
  const directory = (session.data?.directory ?? null) !== null;
  return SECTIONS.map((s) => ({ ...s, items: s.items.filter((m) => (!m.admin || admin) && (!m.directory || directory)) })).filter((s) => s.items.length > 0);
}

/** One entry: its glyph and its name side by side; `stacked`, the glyph over the name where the menu is a narrow rail. */
function NavLink({ item, onPick, badge, className = ITEM, stacked = false }: { item: NavItem; onPick?: () => void; badge?: number | null; className?: string; stacked?: boolean }) {
  if (item.to === undefined) {
    return (
      <a href={item.href} title={item.hint} className={className}>
        {item.label}
      </a>
    );
  }
  return (
    <Link to={item.to} search={item.search} title={item.hint} className={className} activeOptions={{ exact: item.to === "/", includeSearch: false }} onClick={onPick}>
      <span className={cn("flex min-w-0 items-center gap-2.5", stacked && "max-lg:flex-col max-lg:gap-0.5")}>
        <NavIcon name={item.label} />
        <span className="truncate">{item.label}</span>
      </span>
      {badge != null && badge > 0 && (
        <span className="rounded-full bg-accent px-2 text-xs font-semibold text-accent-fg tabular-nums" data-testid="today-badge">
          {badge}
          <span className="sr-only"> need you</span>
        </span>
      )}
    </Link>
  );
}

function Items({ items, onPick }: { items: NavItem[]; onPick?: () => void }) {
  return (
    <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
      {items.map((item) => (
        <li key={item.label}>
          <NavLink item={item} onPick={onPick} />
        </li>
      ))}
    </ul>
  );
}

/**
 * The menu below the daily pages: each section under its heading, every entry with its glyph so
 * the labels line up; the folded section (More: the pages opened rarely) opens on a click, and
 * by itself when the page shown is one of its own.
 */
function Sections({ onPick, open = false }: { onPick?: () => void; open?: boolean }) {
  const sections = useSections();
  const path = useRouterState({ select: (st) => st.location.pathname });
  const [asked, setAsked] = useState(open);
  const id = useId();
  return (
    <div className="flex flex-col gap-3" data-testid="nav-sections">
      {sections.map((section) => {
        if (!section.folded) {
          return (
            <section key={section.title} aria-label={section.title}>
              <p className="m-0 mb-1 px-3 text-xs font-semibold tracking-wide text-muted uppercase">{section.title}</p>
              <Items items={section.items} onPick={onPick} />
            </section>
          );
        }
        const shown = asked || section.items.some((i) => i.to !== undefined && path.startsWith(i.to));
        return (
          <section key={section.title} aria-label={section.title}>
            <button type="button" aria-expanded={shown} aria-controls={id} onClick={() => setAsked(!shown)} className={cn(ITEM, "w-full cursor-pointer border-0 bg-transparent text-left")}>
              <span className="flex items-center gap-2.5">
                <NavIcon name="More" />
                {section.title}
              </span>
              <span aria-hidden="true" className="text-muted">
                {shown ? "▴" : "▾"}
              </span>
            </button>
            {shown && (
              <div id={id} className="mt-0.5" data-testid="more-list">
                <Items items={section.items} onPick={onPick} />
              </div>
            )}
          </section>
        );
      })}
    </div>
  );
}

/** The side nav (640 px and up): the daily pages, then the sections (as a sheet on the narrow rail). */
function SideNav() {
  const count = useNeedsYouCount();
  const wide = useWide();
  return (
    <nav aria-label="Main" className="flex flex-col gap-3">
      <ul className="m-0 flex list-none flex-col gap-0.5 p-0">
        {PRIMARY.map((item) => (
          <li key={item.label}>
            <NavLink item={item} stacked badge={item.label === "Today" ? count : null} className={cn(ITEM, "max-lg:min-h-14 max-lg:flex-col max-lg:justify-center max-lg:gap-0.5 max-lg:px-1 max-lg:text-xs")} />
          </li>
        ))}
      </ul>
      {wide ? <Sections /> : <MoreSheet rail />}
    </nav>
  );
}

/** The phone's bottom tab bar (under 640 px). */
function BottomBar() {
  const count = useNeedsYouCount();
  return (
    <nav aria-label="Pages" className="glass fixed inset-x-0 bottom-0 z-30 grid h-14 grid-cols-4 border-t border-border sm:hidden" data-testid="bottom-bar">
      {BOTTOM.map((item) => (
        <Link
          key={item.label}
          to={item.to ?? "/"}
          search={item.search}
          activeOptions={{ exact: item.to === "/", includeSearch: false }}
          className="relative flex flex-col items-center justify-center gap-0.5 text-xs text-muted no-underline aria-[current=page]:font-semibold aria-[current=page]:text-link"
        >
          <NavIcon name={item.label} />
          <span>{item.label}</span>
          {item.label === "Today" && count != null && count > 0 && <span className="absolute top-1 left-[calc(50%+0.375rem)] rounded-full bg-accent px-1.5 text-[0.6875rem] leading-4 font-semibold text-accent-fg tabular-nums">{count}</span>}
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
        className="min-h-9 w-full max-w-md rounded-full border border-transparent bg-surface px-4 text-sm text-text placeholder:text-muted hover:bg-surface-2"
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
        <Dialog.Popup className="fixed top-1/2 left-1/2 z-50 flex w-[min(32rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 flex-col gap-3 rounded-card border border-border bg-raised p-6 text-text shadow-card">
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
        <p className="m-0 px-3 text-xs font-semibold text-muted">
          <UntrustedText value={session.data.user.display_name} limits={{ maxChars: 60, maxLines: 1 }} />
        </p>
        {items}
        <KeysDialog open={keys} onOpenChange={setKeys} />
      </div>
    );
  }
  return (
    <div ref={box} className="relative" onKeyDown={(e) => e.key === "Escape" && setOpen(false)}>
      <button type="button" aria-expanded={open} aria-controls={open ? id : undefined} onClick={() => setOpen(!open)} className="inline-flex min-h-8 max-w-48 cursor-pointer items-center gap-1 truncate rounded-full border-0 bg-transparent px-3 text-sm text-text hover:bg-surface" data-testid="account-menu">
        <UntrustedText value={session.data.user.display_name} limits={{ maxChars: 60, maxLines: 1 }} /> <span aria-hidden="true">▾</span>
      </button>
      {open && (
        <div id={id} data-testid="account-items" className="absolute right-0 z-30 mt-1 flex w-56 flex-col gap-0.5 rounded-card border border-border bg-raised p-1.5 shadow-card">
          {items}
        </div>
      )}
      <KeysDialog open={keys} onOpenChange={setKeys} />
    </div>
  );
}

/**
 * Everything outside the tab bar, as a sheet: on a phone from the header's More (with the daily
 * pages the bar has no room for, and the account's entries), on the narrow rail from its own More.
 */
function MoreSheet({ rail = false }: { rail?: boolean }) {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);
  const rest = PRIMARY.filter((p) => !BOTTOM.includes(p));
  return (
    <Dialog.Root open={open} onOpenChange={setOpen}>
      {rail ? (
        <Dialog.Trigger className={cn(ITEM, "min-h-14 w-full cursor-pointer flex-col justify-center gap-0.5 border-0 bg-transparent px-1 text-xs")}>
          <NavIcon name="More" />
          More
        </Dialog.Trigger>
      ) : (
        <Dialog.Trigger render={<Button size="sm" className="sm:hidden" />}>More</Dialog.Trigger>
      )}
      <Dialog.Portal>
        <Dialog.Backdrop className="fixed inset-0 z-40 bg-black/40" />
        <Dialog.Popup className="fixed inset-x-0 bottom-0 z-50 flex max-h-[85vh] flex-col gap-3 overflow-auto rounded-t-card border border-border bg-raised p-4 text-text shadow-card sm:inset-x-auto sm:inset-y-0 sm:left-[5.5rem] sm:max-h-none sm:w-72 sm:rounded-none sm:border-y-0">
          <Dialog.Title className="m-0 text-base font-semibold">More</Dialog.Title>
          {!rail && <Items items={rest} onPick={close} />}
          <Sections onPick={close} open />
          {!rail && <AccountMenu phone onPick={close} />}
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
    <div className="flex flex-wrap items-center justify-between gap-2 rounded-card bg-info-soft px-4 py-3 text-sm text-info" role="status">
      <p className="m-0">ARGUS was updated on the server. Reload the page to use the new version; nothing you saved is lost.</p>
      <Button size="sm" onClick={() => window.location.reload()}>
        Reload
      </Button>
    </div>
  );
}

/**
 * The app's frame (docs/p4f-ui-spec.md §4): the daily pages and the sections in the side nav (a rail between
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
      <div className="min-h-screen sm:grid sm:grid-cols-[5.5rem_1fr] lg:grid-cols-[15rem_1fr]">
        <a href="#main" className="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50 focus:rounded-control focus:bg-surface focus:p-2">
          Skip to content
        </a>
        <aside className="hidden bg-surface sm:sticky sm:top-0 sm:block sm:h-screen sm:overflow-y-auto">
          <div className="px-5 pt-5 pb-4 max-lg:px-2 max-lg:text-center">
            <Link to="/" className="flex flex-col gap-0.5 text-text no-underline">
              <span className="text-sm font-semibold tracking-[0.2em] max-lg:text-xs max-lg:tracking-[0.12em]">ARGUS</span>
              <span className="text-xs text-muted max-lg:hidden">first-line analyst · {organisationName()}</span>
            </Link>
          </div>
          <div className="px-2.5 pb-4 max-lg:px-1.5">
            <SideNav />
          </div>
        </aside>
        <div className="flex min-w-0 flex-col">
          <AccessBanner />
          <header className="flex h-14 items-center gap-3 px-4 sm:px-8" data-testid="app-header">
            <Link to="/" className="text-sm font-semibold tracking-[0.2em] text-text no-underline sm:hidden">
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
              <MoreSheet />
            </span>
          </header>
          <main id="main" tabIndex={-1} className="page-in mx-auto flex w-full max-w-[76rem] flex-col gap-5 px-4 pt-2 pb-24 focus:outline-none sm:px-8 sm:pt-4 sm:pb-12">
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
