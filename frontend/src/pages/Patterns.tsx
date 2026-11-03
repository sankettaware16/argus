// Patterns (the classic page /patterns): unreviewed investigations the same rule found the same
// things in, to decide together. A group is marked reviewed only after the person chose its
// outcome and saw the exact request; each member only if it is still as it was shown.
import { useQuery } from "@tanstack/react-query";
import { PatternCard } from "../components/PatternCard";
import { count } from "../lib/format";
import { Loading, Problem } from "../components/Problem";
import { patternsOptions } from "../lib/queries";

export { GROUP_MAX } from "../components/PatternCard";

export function Patterns() {
  const patterns = useQuery(patternsOptions);
  if (patterns.isPending) return <Loading what="the patterns" />;
  if (patterns.isError) return <Problem error={patterns.error} what="The patterns" onRetry={() => void patterns.refetch()} />;
  const page = patterns.data;
  return (
    <>
      <h1 className="m-0 text-2xl font-semibold">Patterns</h1>
      <p className="m-0 max-w-prose text-sm text-muted">
        Investigations not reviewed yet, grouped when the same rule found the same things (each step&apos;s outcome, a threat-list hit). Open one, and if it is what you expect, decide for the group. An investigation that changed since this page was shown is left as it is. Where ARGUS recommends closing a group, its
        recommendation is on the group.
      </p>
      {page.sampled && (
        <p role="note" className="m-0 max-w-prose rounded-control border border-info/40 bg-info-soft px-3 py-2 text-sm text-info" data-testid="patterns-sample">
          <strong>This is a sample.</strong> The groups are made from the {count(page.limit)} newest investigations that are not reviewed yet and have been looked at; older ones are in no group here. Home counts the patterns ARGUS recommends closing over all of them.
        </p>
      )}
      {page.groups.length === 0 && <p className="m-0 text-sm">No patterns: every open investigation{page.sampled ? " among the newest" : ""} stands on its own.</p>}
      <div className="flex flex-col gap-4" aria-busy={patterns.isFetching}>
        {page.groups.map((g) => (
          // keyed by its members, not its place: the group after a reviewed one of the same rule
          // takes its place in the list and must not inherit the outcome chosen for the other
          <PatternCard key={`${g.rule_id}-${g.members.map((m) => m.investigation_id).join(",")}`} g={g} />
        ))}
      </div>
    </>
  );
}
