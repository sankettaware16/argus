import { segments } from "./untrusted";

/**
 * Untrusted text for the one place markup cannot go: an <option>'s label. It is cut at `max`
 * characters on one line, and every invisible or reordering character is written as its marker
 * in angle brackets, e.g. "‹RLO›" (never the character itself).
 */
export function optionText(value: unknown, max = 90): string {
  return segments(value, { maxChars: max, maxLines: 1 })
    .map((part) => {
      switch (part.kind) {
        case "text":
        case "idn":
          return part.text;
        case "mark":
          return `‹${part.label}›`;
        case "cut":
          return "…";
      }
    })
    .join("");
}
