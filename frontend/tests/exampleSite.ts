// The suite runs on its made-up site (tests/fixtures/site.yaml: Example University, ACME), as the
// Python suite does: a test that expects "IST" or "campus" reads that site's words. The neutral
// defaults and other zones have their own tests (site.test.ts).
import type { SiteOut } from "../src/client/types.gen";

export const EXAMPLE_SITE: SiteOut = {
  timezone: "Asia/Kolkata",
  timezone_label: "IST",
  own_network_noun: "campus",
  organisation_name: "Example University",
  organisation_short_name: "ACME",
  organisation_kind: "university",
  organisation_units: "department, hostel or lab",
  organisation_reviewers: "research and teaching assistants",
};
