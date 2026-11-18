import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { useEffect, useId, useState } from "react";
import { listCases, listInvestigations } from "../client/sdk.gen";
import type { CaseRowOut, InvestigationOut } from "../client/types.gen";
import { PriorityBadge } from "../components/incident/Parts";
import { Loading, Problem } from "../components/Problem";
import { UntrustedText } from "../components/UntrustedText";
import { Button } from "../components/ui/button";
import { unwrap } from "../lib/call";
import { engineOf, stateWords } from "../lib/engine";
import { count, plural } from "../lib/format";
import { entitiesFor, guessOf, GUESS_WORDS, GUESSES, kindsFor, recentSearches, rememberSearch, type Guess, type SearchSearch } from "../lib/searchPage";
import { parse } from "../lib/time";
import { shortDay } from "../lib/when";

const MAX = 5;

function useResults(q: string | undefined, guess: Guess) {
  const number = guess === "number" && q ? Number(q.replace("#", "")) : null;
  const kinds = q ? kindsFor(guess) : [];
  const incidents = useQuery({
    queryKey: ["search", "cases", q, guess],
    queryFn: () => unwrap(listCases({ query: number !== null ? { view: "all", number, limit: 25 } : { view: "all", q: q ?? "", limit: 25 } })),
    enabled: q !== undefined,
    staleTime: 30_000,
  });
  // at most two more requests (§10.3): the alert groups of the address, host, account or domain, or of the rule
  const groupsA = useQuery({
    queryKey: ["search", "groups", q, guess, kinds[0] ?? "rule"],
    queryFn: () => unwrap(listInvestigations({ query: kinds[0] ? { view: "all", kind: kinds[0], value: q ?? "", limit: 25 } : { view: "all", rule: q ?? "", limit: 25 } })),
    enabled: q !== undefined && (kinds.length > 0 || guess === "words"),
    staleTime: 30_000,
  });
  const groupsB = useQuery({
    queryKey: ["search", "groups", q, guess, kinds[1] ?? "none"],
    queryFn: () => unwrap(listInvestigations({ query: { view: "all", kind: kinds[1] ?? "user", value: q ?? "", limit: 25 } })),
    enabled: q !== undefined && kinds.length > 1,
    staleTime: 30_000,
  });
  const groups: InvestigationOut[] = [...(groupsA.data?.items ?? []), ...(groupsB.data?.items ?? [])];
  const pending = incidents.isPending && q !== undefined;
  return { incidents, groups, groupsMore: (groupsA.data?.has_more ?? false) || (groupsB.data?.has_more ?? false), groupsPending: (groupsA.isFetching || groupsB.isFetching) && groups.length === 0, groupsError: groupsA.error ?? groupsB.error, pending };
}

function IncidentRow({ c }: { c: CaseRowOut }) {
  const engine = engineOf((c as unknown as { engine?: unknown }).engine);
  return (
    <li className="flex min-h-10 items-center gap-2 border-b border-border py-1 text-sm">
      <PriorityBadge engine={engine} />
      <Link to="/incidents/$id" params={{ id: c.id }} className="min-w-0 flex-1 truncate">
        #{c.number} · {stateWords({ state: c.state, number: null, taken_by: c.owner ? { username: c.owner.username, name: c.owner.display_name } : null })} · <UntrustedText value={c.title} limits={{ maxChars: 160, maxLines: 1 }} />
      </Link>
    </li>
  );
}

function GroupRow({ g }: { g: InvestigationOut }) {
  const last = parse(g.last_event_at);
  return (
    <li className="flex min-h-10 flex-wrap items-center gap-x-2 border-b border-border py-1 text-sm">
      <Link to="/alert-groups/$id" params={{ id: g.id }} className="min-w-0 flex-1 truncate">
        <UntrustedText value={g.rule_name ?? g.title} limits={{ maxChars: 160, maxLines: 1 }} />
      </Link>
      <span className="text-muted tabular-nums">
        {count(g.alert_count)} {plural(g.alert_count, "alert")}
        {last ? ` · ${shortDay(last)}` : ""}
      </span>
    </li>
  );
}

/**
 * Search (docs/p4f-ui-spec.md §10): one box for an address, a host, an account, a domain, a rule,
 * an incident number or an IR number. ARGUS guesses what it is (the chip changes it) and asks at
 * most three questions; results come grouped, five a group, with Show all.
 */
export function SearchPage({ search }: { search: SearchSearch }) {
  const navigate = useNavigate();
  const id = useId();
  const [text, setText] = useState(search.q ?? "");
  const q = search.q;
  const guess = search.guess ?? (q ? guessOf(q) : "words");
  const r = useResults(q, guess);
  const [recent] = useState(recentSearches);
  useEffect(() => {
    if (q) rememberSearch(q);
  }, [q]);
  const go = (next: string, g?: Guess) => void navigate({ to: "/search", search: next.trim() ? { q: next.trim(), ...(g ? { guess: g } : {}) } : {} });
  const incidents = r.incidents.data?.items ?? [];
  const entities = q ? entitiesFor(guess, q) : [];
  const nothing = q !== undefined && !r.pending && !r.groupsPending && incidents.length === 0 && r.groups.length === 0;
  return (
    <div className="flex flex-col gap-4">
      <h1 className="page-h">Search</h1>
      <form
        role="search"
        aria-label="Search ARGUS"
        className="flex flex-wrap gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          go(text);
        }}
      >
        <label htmlFor={`${id}-q`} className="sr-only">
          Search for an address, a host, an account, a domain, a rule, an incident number or an IR number
        </label>
        <input
          id={`${id}-q`}
          type="search"
          value={text}
          maxLength={200}
          onChange={(e) => setText(e.target.value)}
          data-search-box="page"
          className="min-h-10 min-w-0 flex-1 rounded-control border border-border-strong bg-bg px-3 text-base text-text"
          placeholder="203.0.113.40, lab-pc-17, #31, IR-2026-1106-02…"
        />
        <Button type="submit" variant="primary" size="lg">
          Search
        </Button>
      </form>
      {q && (
        <p className="m-0 flex flex-wrap items-center gap-2 text-sm" data-testid="search-guess">
          <label htmlFor={`${id}-guess`}>Looks like:</label>
          <select id={`${id}-guess`} value={guess} onChange={(e) => go(q, e.target.value as Guess)} className="min-h-8 rounded-control border border-border-strong bg-bg px-2 text-sm text-text">
            {GUESSES.map((g) => (
              <option key={g} value={g}>
                {GUESS_WORDS[g]}
              </option>
            ))}
          </select>
        </p>
      )}
      {!q && (
        <div className="flex flex-col gap-2 text-sm">
          <p className="m-0 text-muted">Search for an address, a host, an account, a domain, a rule, an incident number or an IR number.</p>
          {recent.length > 0 && (
            <p className="m-0">
              Recent:{" "}
              {recent.map((x, i) => (
                <span key={x}>
                  {i > 0 && " · "}
                  <Link to="/search" search={{ q: x }}>
                    <UntrustedText value={x} limits={{ maxChars: 60, maxLines: 1 }} />
                  </Link>
                </span>
              ))}
            </p>
          )}
        </div>
      )}
      {q && entities.length > 0 && (
        <p className="m-0 flex flex-wrap gap-x-4 gap-y-1 text-sm" data-testid="search-entity">
          {entities.map((e) => (
            <span key={e.kind}>
              {e.noun} <strong><UntrustedText value={q} limits={{ maxChars: 120, maxLines: 1 }} /></strong> →{" "}
              <Link to="/entities/$kind/$value" params={{ kind: e.kind, value: q }}>
                Open its page
              </Link>
            </span>
          ))}
        </p>
      )}
      {q && r.pending && <Loading what="the results" />}
      {q && r.incidents.isError && <Problem error={r.incidents.error} what="The incidents" onRetry={() => void r.incidents.refetch()} />}
      {q && incidents.length > 0 && (
        <section data-testid="search-incidents" aria-labelledby={`${id}-inc`} className="flex flex-col gap-1">
          <h2 id={`${id}-inc`} className="m-0 text-base font-semibold">
            Incidents · {incidents.length}
            {r.incidents.data?.has_more ? "+" : ""}
          </h2>
          <ul className="m-0 list-none p-0">
            {incidents.slice(0, MAX).map((c) => (
              <IncidentRow key={c.id} c={c} />
            ))}
          </ul>
          {incidents.length > MAX && (
            <Link to="/incidents" search={{ view: "all", q }} className="text-sm">
              Show all {incidents.length}
            </Link>
          )}
        </section>
      )}
      {q && r.groups.length > 0 && (
        <section data-testid="search-groups" aria-labelledby={`${id}-grp`} className="flex flex-col gap-1">
          <h2 id={`${id}-grp`} className="m-0 text-base font-semibold">
            Alert groups · {r.groups.length}
            {r.groupsMore ? "+" : ""}
          </h2>
          <ul className="m-0 list-none p-0">
            {r.groups.slice(0, MAX).map((g) => (
              <GroupRow key={g.id} g={g} />
            ))}
          </ul>
          {r.groups.length > MAX && (
            <Link to="/search" search={{ advanced: "1", view: "all", ...(kindsFor(guess)[0] ? { kind: kindsFor(guess)[0], value: q } : { rule: q }) }} className="text-sm">
              Show all {r.groups.length}
            </Link>
          )}
        </section>
      )}
      {r.groupsError && <Problem error={r.groupsError} what="The alert groups" />}
      {nothing && <p className="m-0 text-sm" data-testid="search-nothing">Nothing in ARGUS matches “<UntrustedText value={q} limits={{ maxChars: 120, maxLines: 1 }} />”. ARGUS keeps alert detail for the last 5 days, and every incident.</p>}
      <p className="m-0 text-sm">
        <Link to="/search" search={{ advanced: "1", view: "attention" }}>
          ▸ Advanced: alert-group filters
        </Link>
      </p>
    </div>
  );
}
