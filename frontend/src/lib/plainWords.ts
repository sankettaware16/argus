/**
 * The report's machine words in the UI's own (docs/p4f-ui-spec.md §3.1, G-1): the incident report
 * says "a true positive" and "a false positive of the rule" (its PDF and Kibana keep them); a page
 * never does, least of all for a possible incident. Pure (tests/v2-tabs.test.tsx).
 */
const SWAPS: [RegExp, string][] = [
  [/\bA true positive\b/g, "Real: act on it"],
  [/\ba true positive\b/g, "real: act on it"],
  [/\btrue positives?\b/gi, "real"],
  [/\ba false positive of the rule\b/gi, "a wrong alert"],
  [/\bfalse positives?\b/gi, "wrong alert"],
  [/\bTP\b/g, "real"],
  [/\bFP\b/g, "wrong alert"],
];

export function plainWords(text: string): string {
  return SWAPS.reduce((t, [from, to]) => t.replace(from, to), text);
}
