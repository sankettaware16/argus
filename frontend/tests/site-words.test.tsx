// The pages say the site's own word for its network, never one organisation's: the labels of an
// incident's two sides, the site and device nouns, the lane and filter words. Read under a site
// that is not the suite's (a manufacturer whose word is "the plant") and under the neutral
// defaults; the suite's own site still reads "Campus side".
import { screen, within } from "@testing-library/react";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import type { SiteOut } from "../src/client/types.gen";
import { LANE_WORDS, nounFor } from "../src/lib/engine";
import { SIDE_WORDS } from "../src/lib/incidents";
import { entitiesFor, GUESS_WORDS } from "../src/lib/searchPage";
import { aOwn, NEUTRAL_SITE, ownCapital, ownSide, setSite } from "../src/lib/site";
import { entityNoun } from "../src/pages/Entity";
import { EXAMPLE_SITE } from "./exampleSite";
import { BASE, mockApi, renderApp, server, SESSION, shellHandlers } from "./helpers";
import { reportOut } from "./incidentFixtures";
import { P1_ID, p1Detail, today } from "./v2Fixtures";

mockApi();

const PLANT: SiteOut = {
  ...EXAMPLE_SITE,
  own_network_noun: "the plant",
  organisation_name: "Example Works",
  organisation_short_name: "EW SOC",
  organisation_kind: "manufacturer",
  organisation_units: "line, shift or office",
  organisation_reviewers: "security engineers",
};
const SITE_OBJECT = { kind: "site", label: "www.example.org", role: "affected" } as const;

describe("the words", () => {
  it("are the suite's site's by default", () => {
    expect(ownSide()).toBe("Campus side");
    expect(ownCapital("site")).toBe("Campus site");
    expect(aOwn("site")).toBe("a campus site");
    expect(LANE_WORDS.exposure).toBe("A campus site may be exposed");
    expect(SIDE_WORDS.site).toBe("Campus sites");
    expect(GUESS_WORDS.domain).toBe("a domain or campus site");
  });

  it("follow another organisation's noun", () => {
    setSite(PLANT);
    expect(ownSide()).toBe("Plant side");
    expect(ownCapital("devices")).toBe("Plant devices");
    expect(aOwn("site")).toBe("a plant site");
    expect(LANE_WORDS.exposure).toBe("A plant site may be exposed");
    expect(SIDE_WORDS.site).toBe("Plant sites");
    expect(GUESS_WORDS.domain).toBe("a domain or plant site");
    expect(nounFor(SITE_OBJECT)).toBe("Plant site");
    expect(entityNoun("site", "www.example.org")).toBe("Plant site");
    expect(entitiesFor("domain", "www.example.org")).toEqual([{ kind: "site", noun: "Plant site" }]);
    setSite({ ...PLANT, own_network_noun: "office network" });
    expect(aOwn("site")).toBe("an office network site");
  });

  it("name no organisation by default", () => {
    setSite(NEUTRAL_SITE);
    expect(ownSide()).toBe("Your side");
    expect(ownCapital("site")).toBe("Site of your network");
    expect(aOwn("site")).toBe("a site of your network");
    expect(LANE_WORDS.exposure).toBe("A site of your network may be exposed");
    expect(SIDE_WORDS.site).toBe("Sites of your network");
    expect(nounFor(SITE_OBJECT)).toBe("Site of your network");
    setSite({ ...NEUTRAL_SITE, own_network_noun: "our offices" });
    expect(ownSide()).toBe("Our side");
  });

  it("every table of words is free of the suite's noun under another site", () => {
    setSite(PLANT);
    const said = [ownSide(), ...Object.values(LANE_WORDS), ...Object.values(SIDE_WORDS), ...Object.values(GUESS_WORDS)].join(" | ");
    expect(said).not.toMatch(/campus|universit/i);
  });
});

describe("the pages, for another organisation", () => {
  const plantSession = { ...SESSION, site: PLANT };
  // what the server sends carries the site's words already: these fixtures say "campus" in titles
  const plain = (text: string) => text.replace(/campus/gi, "plant");

  it("the incident page labels its sides with the site's word", async () => {
    const detail = p1Detail({}, { title: "Likely beaconing from 5 plant devices to 203.0.113.40" });
    server.use(
      ...shellHandlers(plantSession),
      http.get(`${BASE}/api/v1/cases/${P1_ID}`, () => HttpResponse.json(detail)),
      http.get(`${BASE}/api/v1/cases/${P1_ID}/report`, () => HttpResponse.json(reportOut({ case_id: P1_ID, case_number: 31, case_state: "suspected" }))),
    );
    renderApp(`/incidents/${P1_ID}`);
    const sides = await screen.findByTestId("sides");
    expect(sides.textContent).toContain("Plant side (affected)");
    expect(screen.queryByText(/Campus side/)).toBeNull();
  });

  it("the entities tab heads its column with it", async () => {
    server.use(
      ...shellHandlers(plantSession),
      http.get(`${BASE}/api/v1/cases/${P1_ID}`, () => HttpResponse.json(p1Detail())),
      http.get(`${BASE}/api/v1/cases/${P1_ID}/report`, () => HttpResponse.json(reportOut({ case_id: P1_ID, case_number: 31, case_state: "suspected" }))),
    );
    renderApp(`/incidents/${P1_ID}?tab=entities`);
    const column = await screen.findByTestId("own-side");
    expect(within(column).getByRole("heading", { level: 2 }).textContent).toBe("Plant side");
  });

  it("Today's cards and the queue's filter say it too", async () => {
    const body = JSON.parse(plain(JSON.stringify(today()))) as Record<string, unknown>;
    server.use(...shellHandlers(plantSession), http.get(`${BASE}/api/v1/today`, () => HttpResponse.json(body)));
    renderApp("/");
    await screen.findAllByTestId("incident-card");
    expect(document.body.textContent).toContain("Plant side");
    expect(document.body.textContent).not.toMatch(/campus|universit/i);
  });
});
