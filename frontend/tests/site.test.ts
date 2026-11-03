// D-284: the zone, its label, the noun and the names come from the server's `site` section. ACME's
// values (the suite's default, tests/exampleSite.ts) give the words the pages always had; any other
// zone or noun gives its own, and the neutral defaults say nothing of ACME.
import { describe, expect, it } from "vitest";
import { istInstant, istStamp, managedWords, whenProblem } from "../src/lib/notice";
import {
  aKind,
  aNoun,
  kind,
  kindCapital,
  NEUTRAL_SITE,
  noun,
  nounCapital,
  offsetLabel,
  own,
  setSite,
  site,
  theNoun,
  unitsWithArticles,
  zoneLabel,
} from "../src/lib/site";
import { ist, utc, utcDayStart } from "../src/lib/time";
import { offsetMinutes, offsetText, wallInstant } from "../src/lib/zone";
import { EXAMPLE_SITE } from "./exampleSite";

const AT = new Date("2026-10-29T13:50:00Z");

describe("ACME's section", () => {
  it("reads as the pages always did", () => {
    expect(ist(AT)).toBe("29 Oct 2026, 7:20 PM IST");
    expect(zoneLabel(AT)).toBe("IST");
    expect(noun()).toBe("campus");
    expect(theNoun()).toBe("the campus");
    expect(aNoun()).toBe("a campus");
    expect(nounCapital()).toBe("Campus");
    expect(utcDayStart()).toBe("5:30 AM");
    expect(istInstant("2026-10-26T09:30")?.toISOString()).toBe("2026-10-26T04:00:00.000Z");
    expect(istStamp("2026-10-26T09:30")).toBe("2026-10-26T09:30:00+05:30");
    expect(whenProblem("nonsense", AT)).toBe("Write the time as a date and a time (IST).");
  });
});

describe("the neutral defaults", () => {
  it("are UTC, 'your network', and name no organisation", () => {
    setSite(NEUTRAL_SITE);
    expect(ist(AT)).toBe("29 Oct 2026, 1:50 PM UTC");
    expect(zoneLabel(AT)).toBe("UTC");
    expect(noun()).toBe("your network");
    expect(theNoun()).toBe("your network");
    expect(aNoun()).toBe("your network");
    expect(utcDayStart()).toBe("12:00 AM");
    expect(istStamp("2026-10-26T09:30")).toBe("2026-10-26T09:30:00+00:00");
    expect(JSON.stringify(NEUTRAL_SITE)).not.toMatch(/IIT|ACME|campus|Kolkata/i);
  });
});

describe("another zone", () => {
  it("shows its own time and the offset in force at that moment, as the server labels it", () => {
    setSite({ ...NEUTRAL_SITE, timezone: "America/New_York", timezone_label: null });
    expect(ist(new Date("2026-01-15T17:00:00Z"))).toBe("15 Jan 2026, 12:00 PM UTC-05:00");
    expect(ist(new Date("2026-07-15T17:00:00Z"))).toBe("15 Jul 2026, 1:00 PM UTC-04:00");
    expect(offsetMinutes("America/New_York", new Date("2026-07-15T17:00:00Z"))).toBe(-240);
    // the same label whatever the browser's locale data calls the zone (CEST, JST, GMT+2)
    setSite({ ...NEUTRAL_SITE, timezone: "Europe/Paris", timezone_label: null });
    expect(zoneLabel(new Date("2026-07-15T17:00:00Z"))).toBe("UTC+02:00");
    setSite({ ...NEUTRAL_SITE, timezone: "Asia/Kathmandu", timezone_label: null });
    expect(zoneLabel(AT)).toBe("UTC+05:45");
    setSite({ ...NEUTRAL_SITE, timezone: "UTC", timezone_label: null });
    expect(zoneLabel(AT)).toBe("UTC");
    expect(offsetLabel(0)).toBe("UTC");
    expect(offsetLabel(-90)).toBe("UTC-01:30");
  });

  it("reads a typed wall clock in its own zone, whatever the browser's", () => {
    setSite({ ...NEUTRAL_SITE, timezone: "America/New_York", timezone_label: null });
    expect(istInstant("2026-07-15T09:30")?.toISOString()).toBe("2026-07-15T13:30:00.000Z");
    expect(istInstant("2026-01-15T09:30")?.toISOString()).toBe("2026-01-15T14:30:00.000Z");
    expect(istStamp("2026-07-15T09:30")).toBe("2026-07-15T09:30:00-04:00");
    // the hour a clock change skips does not exist
    expect(wallInstant("America/New_York", "2026-03-08T02:30")).toBeUndefined();
    expect(istInstant("2026-02-31T10:00")).toBeUndefined();
    expect(istInstant("2026-10-26T24:00")).toBeUndefined();
  });

  it("reads the hour a clock change repeats as the first of the two, as the server does", () => {
    // 1:30 AM on 1 Nov 2026 happens twice in New York: 05:30Z (EDT), then 06:30Z (EST)
    expect(wallInstant("America/New_York", "2026-11-01T01:30")?.toISOString()).toBe("2026-11-01T05:30:00.000Z");
    expect(wallInstant("America/New_York", "2026-11-01T00:59")?.toISOString()).toBe("2026-11-01T04:59:00.000Z");
    expect(wallInstant("America/New_York", "2026-11-01T02:00")?.toISOString()).toBe("2026-11-01T07:00:00.000Z");
    // the southern autumn: 2:30 AM on 5 Apr 2026 in Sydney happens twice (15:30Z, then 16:30Z the day before)
    expect(wallInstant("Australia/Sydney", "2026-04-05T02:30")?.toISOString()).toBe("2026-04-04T15:30:00.000Z");
  });

  it("reads a year below 100 as that year, not as 19xx", () => {
    expect(wallInstant("UTC", "0050-06-15T09:30")?.toISOString()).toBe("0050-06-15T09:30:00.000Z");
  });

  it("names a fixed label before the zone's own", () => {
    setSite({ ...NEUTRAL_SITE, timezone: "Europe/Istanbul", timezone_label: "TRT" });
    expect(ist(AT)).toBe("29 Oct 2026, 4:50 PM TRT");
    expect(offsetText(offsetMinutes("Europe/Istanbul", AT))).toBe("+03:00");
  });
});

describe("a session without a site", () => {
  // an API older than this page answers the session with no `site`: the page must stay drawable
  it("falls back to the neutral words, never throwing in a time", () => {
    setSite(undefined);
    expect(site()).toEqual(NEUTRAL_SITE);
    expect(ist(AT)).toBe("29 Oct 2026, 1:50 PM UTC");
    expect(utc(AT)).toBe("29 Oct 2026, 1:50:00 PM UTC");
    expect(zoneLabel(AT)).toBe("UTC");
    expect(noun()).toBe("your network");
    setSite(null);
    expect(ist(AT)).toBe("29 Oct 2026, 1:50 PM UTC");
    expect(utcDayStart()).toBe("12:00 AM");
  });

  it("fills the fields a partial answer lacks with the neutral ones", () => {
    setSite({ timezone: "Asia/Kolkata", timezone_label: "IST" });
    expect(ist(AT)).toBe("29 Oct 2026, 7:20 PM IST");
    expect(noun()).toBe("your network");
    setSite(EXAMPLE_SITE);
    expect(noun()).toBe("campus");
  });
});

describe("a zone the browser does not know", () => {
  it("is drawn in UTC and labelled so, not thrown at", () => {
    setSite({ ...NEUTRAL_SITE, timezone: "Mars/Olympus_Mons", timezone_label: null });
    expect(ist(AT)).toBe("29 Oct 2026, 1:50 PM UTC");
    expect(zoneLabel(AT)).toBe("UTC");
    expect(utcDayStart()).toBe("12:00 AM");
  });
});

describe("the organisation's words", () => {
  it("are ACME's, as the pages always said", () => {
    expect([kind(), aKind(), kindCapital()]).toEqual(["university", "a university", "University"]);
    expect(unitsWithArticles()).toBe("a department, a hostel, a lab");
    expect(own("names")).toBe("campus names");
    expect(managedWords(true)).toContain("These are university-managed machines (labs");
    expect(managedWords(null)).toContain("whether these are university-managed machines or personal");
  });

  it("are neutral by default, and read as English", () => {
    setSite(NEUTRAL_SITE);
    expect([kind(), aKind(), kindCapital()]).toEqual(["organisation", "an organisation", "Organisation"]);
    expect(unitsWithArticles()).toBe("a department, a team, a lab");
    expect(own("names")).toBe("names of your network");
    expect(managedWords(true)).toContain("These are organisation-managed machines");
    expect(JSON.stringify([managedWords(true), managedWords(false), managedWords(null)])).not.toMatch(/universit|campus|hostel/i);
    setSite({ ...NEUTRAL_SITE, own_network_noun: "plant", organisation_units: "unit or site" });
    expect([own("names"), unitsWithArticles()]).toEqual(["plant names", "a unit, a site"]);
  });
});

describe("the noun", () => {
  it("is a modifier, with 'the', and with 'a'", () => {
    setSite({ ...NEUTRAL_SITE, own_network_noun: "the plant" });
    expect([noun(), theNoun(), aNoun()]).toEqual(["plant", "the plant", "the plant"]);
    setSite({ ...NEUTRAL_SITE, own_network_noun: "office network" });
    expect([noun(), theNoun(), aNoun(), nounCapital()]).toEqual(["office network", "the office network", "an office network", "Office network"]);
  });
});
