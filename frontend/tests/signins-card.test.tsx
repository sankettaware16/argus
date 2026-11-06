// "Who used this device" (AR6, D-216): the probable user with a lead-not-proof line, names only as
// untrusted text and only when the server sent them, a shared address naming no one, what is
// unknown and why, and nothing at all on a server that does not have the feature.
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { SigninDeviceOut, SigninsOut } from "../src/client/types.gen";
import { SigninsCard } from "../src/components/signins/SigninsCard";

const LEAD = "Probable user, from SSO sign-ins on this address — a lead, not proof: addresses can be reassigned.";

function device(more: Partial<SigninDeviceOut> = {}): SigninDeviceOut {
  return {
    address: "10.201.7.11",
    state: "likely",
    words: "Probable user: user-ar6-alpha.",
    accounts: [{ user: "user-ar6-alpha", first_at: "2026-10-26T03:40:00Z", last_at: "2026-10-26T12:10:00Z", events: 24, successes: 22, failures: 2, days: ["2026-10-26"], devices: ["Chrome on Windows"] }],
    account_count: 1,
    at_least: false,
    shared_days: [],
    gaps: [],
    hands: [],
    failed_only: [],
    outside_window: 0,
    ...more,
  };
}

function card(more: Partial<SigninsOut> = {}): SigninsOut {
  return { enabled: true, hidden: false, lead: LEAD, states: [{ state: "likely", devices: 1 }], devices: [device()], devices_total: 1, ...more };
}

describe("the card", () => {
  it("is not there on a server without the feature", () => {
    const { container } = render(<SigninsCard signins={null} />);
    expect(container.textContent).toBe("");
  });

  it("says the probable user, the sign-ins and the browser, and that it is a lead", () => {
    render(<SigninsCard signins={card()} />);
    const region = screen.getByRole("region", { name: "Who used this device" });
    expect(within(region).getByText(LEAD)).toBeTruthy();
    expect(within(region).getByText("Probable user")).toBeTruthy();
    expect(region.textContent).toContain("user-ar6-alpha");
    expect(region.textContent).toContain("22, 2 failed");
    expect(region.textContent).toContain("Chrome on Windows");
    expect(within(region).getByText("10.201.7.11")).toBeTruthy();
  });

  it("shows times in IST", () => {
    render(<SigninsCard signins={card()} />);
    const times = document.querySelectorAll("time");
    expect(times.length).toBe(2);
    expect(times[0]?.textContent).toMatch(/IST$/);
  });

  it("shows counts and no name to an account that may not read the logs", () => {
    const hidden = card({
      hidden: true,
      devices: [device({ words: "1 account signed in from this address — hidden: needs log access.", accounts: [] })],
    });
    render(<SigninsCard signins={hidden} />);
    const region = screen.getByRole("region", { name: "Who used this device" });
    expect(region.textContent).toContain("1 account signed in from this address — hidden: needs log access.");
    expect(region.textContent).toContain("Your account cannot read the logs in ELK");
    expect(region.textContent).not.toContain("user-ar6-alpha");
    expect(within(region).queryByRole("table")).toBeNull();
  });

  it("names no one on a shared address and says why a device is not known", () => {
    const shared = device({ state: "shared", accounts: [], words: "A shared address: 9 accounts signed in on 28 Oct. No user is guessed.", account_count: 9 });
    const unknown = device({ address: "10.198.36.231", state: "unknown", accounts: [], words: "Not known: 28 Oct: not looked up yet.", gaps: [{ day: "2026-10-28", why: "not_looked", words: "not looked up yet" }] });
    render(<SigninsCard signins={card({ states: [{ state: "unknown", devices: 1 }, { state: "shared", devices: 1 }], devices: [unknown, shared], devices_total: 2 })} />);
    const region = screen.getByRole("region", { name: "Who used these devices" });
    expect(region.textContent).toContain("No user is guessed.");
    expect(region.textContent).toContain("Not known: 28 Oct: not looked up yet.");
    expect(within(region).getByText("Shared address")).toBeTruthy();
    expect(within(region).getByText("Not known")).toBeTruthy();
  });

  it("says the address changed hands when single accounts differ by day", () => {
    const hands = device({
      state: "possible",
      words: "Possible users: user-ar6-alpha, user-ar6-beta.",
      hands: [
        { day: "2026-10-26", user: "user-ar6-alpha" },
        { day: "2026-10-28", user: "user-ar6-beta" },
      ],
    });
    render(<SigninsCard signins={card({ devices: [hands] })} />);
    expect(screen.getByText(/changed hands/)).toBeTruthy();
  });

  it("treats a hostile name as text", () => {
    const [first] = device().accounts;
    const hostile = device({ accounts: first ? [{ ...first, user: "<img src=x onerror=alert(1)>" }] : [], words: "Probable user: <img src=x onerror=alert(1)>." });
    const { container } = render(<SigninsCard signins={card({ devices: [hostile] })} />);
    expect(container.querySelector("img")).toBeNull();
    expect(container.textContent).toContain("<img src=x onerror=alert(1)>");
  });

  it("lists the first ten devices and folds the rest", () => {
    const many = Array.from({ length: 13 }, (_, i) => device({ address: `10.0.0.${i + 1}`, state: "none_seen", accounts: [], words: "No account had a successful sign-in from this address in the window." }));
    render(<SigninsCard signins={card({ states: [{ state: "none_seen", devices: 13 }], devices: many, devices_total: 13 })} />);
    expect(screen.getByText("3 more devices")).toBeTruthy();
    expect(screen.getByText("13 devices:")).toBeTruthy();
  });

  it("says it is off when the lookups are not switched on", () => {
    render(<SigninsCard signins={card({ enabled: false, states: [], devices: [], devices_total: 1 })} />);
    expect(screen.getByText(/ARGUS is not reading the sign-in logs yet/)).toBeTruthy();
  });
});
