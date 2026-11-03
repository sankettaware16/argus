/**
 * The site's own words (D-284): the time zone people read times in, the label after a time, the
 * word for the organisation's own network and the organisation's names. They come from the
 * server with the session (`SessionOut.site`, the `site` section of the settings); until the
 * session is read the neutral defaults stand, so a page never says another organisation's name.
 */
import type { SiteOut } from "../client/types.gen";
import { offsetMinutes, offsetText } from "./zone";

export type Site = SiteOut;

export const NEUTRAL_SITE: Site = {
  timezone: "UTC",
  timezone_label: "UTC",
  own_network_noun: "your network",
  organisation_name: "your organisation",
  organisation_short_name: "SOC",
  organisation_kind: "organisation",
  organisation_units: "department, team or lab",
  organisation_reviewers: "analysts",
};

let current: Site = NEUTRAL_SITE;

/**
 * Called when the session is read; the module-level state is what the page's words read. An answer
 * without a `site` (an API older than this page, or an answer that lost it) leaves the neutral
 * words, never `undefined`: a time must always be drawable. A site that lacks a field has the
 * neutral one in its place.
 */
export function setSite(site: Partial<Site> | null | undefined): void {
  current = site == null ? NEUTRAL_SITE : { ...NEUTRAL_SITE, ...site };
}

export function site(): Site {
  return current;
}

/** The IANA zone times are shown in. */
export function zone(): string {
  return current.timezone;
}

/**
 * The label after a time: the site's fixed one ("IST"), else the zone's offset at that moment
 * ("UTC-05:00" in winter, "UTC-04:00" in summer; "UTC" at no offset). It is the server's rule
 * (`argus.site.zone_label`) so the page, the PDF and the Kibana text read one way; a name such as
 * "CEST" or "GMT+2" differs between the tz database and the browser's locale data.
 */
export function zoneLabel(at: Date = new Date()): string {
  if (current.timezone_label != null) return current.timezone_label;
  try {
    return offsetLabel(offsetMinutes(current.timezone, at));
  } catch {
    return "UTC"; // a zone this browser does not know is drawn in UTC (lib/time.ts)
  }
}

/** "UTC" at no offset, else "UTC+05:30" / "UTC-04:00". */
export function offsetLabel(minutes: number): string {
  return minutes === 0 ? "UTC" : `UTC${offsetText(minutes)}`;
}

const DETERMINERS = ["the ", "your ", "our ", "my "];
const startsWithDeterminer = (word: string) => DETERMINERS.some((d) => word.toLowerCase().startsWith(d));

/** The word for the organisation's own network as a modifier: "campus device", "your network device". */
export function noun(): string {
  const word = current.own_network_noun;
  return word.toLowerCase().startsWith("the ") ? word.slice(4) : word;
}

/** With "the": "the campus", "your network" (a noun that begins with the, your, our or my is used as it stands). */
export function theNoun(): string {
  const word = current.own_network_noun;
  return startsWithDeterminer(word) ? word : `the ${word}`;
}

/** With "a": "a campus", "your network" (no article before your, our, my or the). */
export function aNoun(): string {
  const word = current.own_network_noun;
  if (startsWithDeterminer(word)) return word;
  return `${article(word)} ${word}`;
}

/** `a` or `an` before `word` by its sound (an office, an hour; a university, a unit): as argus.site.article. */
export function article(word: string): string {
  return /^(?:[aeio]|u(?!ni(?!n)|se|su|ti|r[aiu])|hour|honest|honou?r|heir)/i.test(word) && !/^(?:eu|one\b|once\b)/i.test(word) ? "an" : "a";
}

/** `noun()` with a capital first letter, for the start of a sentence or a heading. */
export function nounCapital(): string {
  const word = noun();
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** `thing` that belongs to the organisation's own network: "campus names", "names of your network". */
export function own(thing: string): string {
  const word = current.own_network_noun;
  if (/^(your|our|my) /i.test(word)) return `${thing} of ${word}`;
  return `${noun()} ${thing}`;
}

/** What kind of organisation it is, lower case: "university", "organisation". */
export function kind(): string {
  return current.organisation_kind;
}

export function kindCapital(): string {
  const word = kind();
  return word.charAt(0).toUpperCase() + word.slice(1);
}

/** With "a": "a university", "an organisation". */
export function aKind(): string {
  const word = kind();
  return `${article(word)} ${word}`;
}

/** "a department, a hostel, a lab": the units an owner may be told through, each with its article. */
export function unitsWithArticles(): string {
  return current.organisation_units
    .split(/,\s*|\s+or\s+/)
    .filter((u) => u !== "")
    .map((u) => `${article(u)} ${u}`)
    .join(", ");
}

export function organisationName(): string {
  return current.organisation_name;
}

export function teamName(): string {
  return current.organisation_short_name;
}
