import type { ReadingOut } from "../../client/types.gen";
import { UntrustedText } from "../UntrustedText";
import { Badge } from "../ui/badge";

/**
 * ARGUS's reading of a run that proposed nothing (AR1): what it made of the item and why that is not a
 * proposal, in plain words first; then the model's reason and the facts it relied on, each marked as
 * found in the evidence or not. It is never a proposal: nothing here can be accepted.
 */
export function Reading({ reading }: { reading: ReadingOut }) {
  return (
    <section aria-label="ARGUS's reading" className="flex flex-col gap-1.5 border-l-4 border-info/50 pl-3">
      <p className="m-0 text-sm font-semibold" data-testid="reading-headline">
        {reading.headline}
      </p>
      {reading.reason && (
        <p className="m-0 text-sm">
          <strong>Its reason.</strong> <UntrustedText value={reading.reason} limits={{ maxChars: 2000, maxLines: 30 }} />
        </p>
      )}
      {reading.facts.length > 0 && (
        <>
          <h4 className="m-0 text-sm font-semibold">Facts it relied on</h4>
          <ul className="m-0 pl-5 text-sm">
            {reading.facts.map((f, i) => (
              <li key={i}>
                <q>
                  <UntrustedText value={f.text} limits={{ maxChars: 300, maxLines: 3 }} />
                </q>{" "}
                <Badge tone={f.checked ? "ok" : "warn"}>{f.checked ? "checked, found in the evidence" : "not found in the evidence"}</Badge>
              </li>
            ))}
          </ul>
        </>
      )}
      <p className="m-0 text-xs text-muted">This is ARGUS&apos;s reading, not a proposal: nothing is proposed or closed from it. You decide.</p>
    </section>
  );
}
