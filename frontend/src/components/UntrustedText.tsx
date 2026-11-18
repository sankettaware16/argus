import { type ReactNode, useMemo, useState } from "react";
import { cn } from "../lib/cn";
import { bidiRuns, DEFAULT_LIMITS, HARD_MAX, type Limits, segments } from "../lib/untrusted";

export interface UntrustedTextProps {
  /** the value as it came: from logs, alerts, Kibana, a person or a model */
  value: unknown;
  /** caps (default 2,000 characters, 40 lines); "Show all" lifts them to HARD_MAX */
  limits?: Partial<Limits>;
  /** shown in a block (pre-wrap) rather than inline */
  block?: boolean;
  className?: string;
}

/** Text with each run of right-to-left letters in its own right-to-left isolate. */
function Directed({ text }: { text: string }): ReactNode {
  return bidiRuns(text).map((run, i) =>
    run.rtl ? (
      <bdi key={i} dir="rtl">
        {run.text}
      </bdi>
    ) : (
      run.text
    ),
  );
}

/**
 * The one renderer for untrusted text (Q-B1, plan §7.5). Text nodes, spans and isolates only:
 * never markup, never a link; the only attribute that carries anything of the value is a marker's
 * title (the hidden character's code point and name). Isolated left to right (`<bdi dir="ltr">`),
 * so no reordering character can reorder what is around it or flip a file name; each run of
 * right-to-left letters sits in its own right-to-left isolate inside it, so the numbers and words
 * around the run keep the order they were written in (review F4). See lib/untrusted.ts for what
 * it shows.
 */
export function UntrustedText({ value, limits, block = false, className }: UntrustedTextProps) {
  const [all, setAll] = useState(false);
  const maxChars = all ? HARD_MAX : (limits?.maxChars ?? DEFAULT_LIMITS.maxChars);
  const maxLines = all ? HARD_MAX : (limits?.maxLines ?? DEFAULT_LIMITS.maxLines);
  // worked out again only when the value or the caps change, not on every render (review F11)
  const parts = useMemo(() => segments(value, { maxChars, maxLines }), [value, maxChars, maxLines]);
  const Tag = block ? "div" : "span";
  return (
    <Tag className={cn("ut", block && "block", className)} data-untrusted="">
      <bdi dir="ltr">
        {parts.map((part, i) => {
          switch (part.kind) {
            case "text":
              return <Directed key={i} text={part.text} />;
            case "mark":
              return (
                <span key={i} className="ut-mark" title={part.name}>
                  {part.label}
                  <span className="sr-only"> (hidden character {part.name})</span>
                </span>
              );
            case "idn":
              return (
                <span key={i}>
                  <Directed text={part.text} />
                  <span
                    className="ut-idn"
                    title={
                      part.ascii === null
                        ? "Written with non-ASCII letters, and not a valid domain name"
                        : "How this name is really written (ASCII); look-alike letters show here"
                    }
                  >
                    {part.ascii === null ? "not a valid domain name" : part.ascii}
                  </span>
                </span>
              );
            case "cut":
              return (
                <span key={i} className="text-muted">
                  {" "}
                  … {new Intl.NumberFormat("en-IN").format(part.hidden)} more character{part.hidden === 1 ? "" : "s"}
                  {part.lines ? " (line limit)" : ""}{" "}
                  {!all && (
                    <button
                      type="button"
                      className="min-h-6 rounded-control px-1 font-medium text-link underline underline-offset-2 hover:text-accent-hover"
                      onClick={() => setAll(true)}
                    >
                      Show all
                    </button>
                  )}
                </span>
              );
          }
        })}
      </bdi>
    </Tag>
  );
}
