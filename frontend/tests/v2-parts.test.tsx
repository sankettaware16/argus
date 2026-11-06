// The UI v2's shared parts (docs/p4f-ui-spec.md §12): the priority badge differs in style as well
// as colour, the certainty word is plain text, the checks' glyphs are never green or red (G-6),
// an outside address is never a Device (G-5), and the why points add up (I-6).
import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AlternativesList, CheckList } from "../src/components/incident/CheckList";
import { ActivityLine, CertaintyWord, ChangedStrip, ChipRow, EntityChip, PriorityBadge } from "../src/components/incident/Parts";
import { WhyPoints } from "../src/components/incident/WhyPoints";
import { engineOf, side, type Engine } from "../src/lib/engine";
import { p1Engine } from "./v2Fixtures";

const e = engineOf(p1Engine()) as Engine;

describe("the priority badge", () => {
  it("differs in style, not only colour, from band to band", () => {
    const classes = (["P1", "P2", "P3", "P4"] as const).map((band) => {
      const { container } = render(<PriorityBadge engine={{ band, priority: 50 }} />);
      const badge = within(container).getByTestId("priority-badge");
      expect(badge.textContent).toContain(band);
      return badge.className;
    });
    expect(classes[0]).toContain("bg-critical"); // solid fill
    expect(classes[1]).toContain("border-[1.5px]"); // soft fill with a border
    expect(classes[2]).toContain("border-transparent");
    expect(classes[3]).toContain("bg-transparent"); // text only
    expect(new Set(classes).size).toBe(4);
  });

  it("says the score and the band's time words in its tooltip; a dash when not scored", () => {
    render(<PriorityBadge engine={e} />);
    expect(screen.getByTestId("priority-badge").getAttribute("title")).toBe("Priority 82 of 100 · P1: look today, before you leave");
    render(<PriorityBadge engine={null} />);
    const none = screen.getAllByTestId("priority-badge")[1] as HTMLElement;
    expect(none.textContent).toContain("—");
    expect(none.getAttribute("title")).toBe("Not scored yet");
  });
});

describe("words, not colours", () => {
  it("the certainty is bold text with no colour", () => {
    render(<CertaintyWord value="Likely" />);
    const word = screen.getByTestId("certainty");
    expect(word.textContent).toBe("Likely");
    expect(word.className).toContain("text-text");
  });

  it("Still active is plain text, not a badge", () => {
    render(<ActivityLine engine={e} capital />);
    const line = screen.getByTestId("activity");
    expect(line.textContent).toMatch(/Still active since 4 Nov/);
    expect(line.className).not.toMatch(/rounded-full|bg-/);
  });

  it("G-6: no check glyph is green or red, and every ? says Not known", () => {
    render(<CheckList checks={e.checks} />);
    for (const glyph of screen.getAllByTestId("check-glyph")) {
      expect(glyph.className).toContain("text-text");
      expect(glyph.className).not.toMatch(/text-(ok|danger|critical|high)/);
      expect(glyph.getAttribute("aria-hidden")).toBe("true");
    }
    const unknown = screen.getAllByTestId("check-mark").filter((m) => m.getAttribute("data-state") === "unknown");
    expect(unknown).toHaveLength(2);
    for (const m of unknown) expect(m.textContent).toContain("Not known");
  });

  it("other explanations say Ruled out, Still fits and Not tested, with the deciding check", () => {
    render(<AlternativesList alternatives={e.alternatives} />);
    const list = screen.getByTestId("alternatives");
    expect(list.textContent).toContain("Ruled out");
    expect(list.textContent).toContain("Still fits");
    expect(list.textContent).toContain("Not tested");
    expect(list.textContent).toContain("The check that would decide: ask the lab admin");
  });

  it("the changed strip has no version numbers and its dot carries no meaning alone", () => {
    render(<ChangedStrip changed={e.changed} />);
    const strip = screen.getByTestId("changed-strip");
    expect(strip.textContent).toContain("New since you last looked: 2 more campus devices");
    expect(strip.textContent).not.toMatch(/\bv\d+\b/);
  });
});

describe("entity chips (G-5)", () => {
  it("call the outside address of the fixture an Outside address, never a Device", () => {
    render(<ChipRow objects={side(e, "actor")} label="Other side" />);
    const chips = screen.getAllByTestId("entity-chip");
    for (const chip of chips) {
      expect(chip.getAttribute("data-role")).toBe("actor");
      expect(chip.getAttribute("data-noun")).not.toBe("Device");
    }
    expect(chips[0]?.textContent).toBe("Outside address 203.0.113.40");
  });

  it("show the first two of a side, then +N", () => {
    render(<ChipRow objects={side(e, "affected")} label="Campus side" />);
    expect(screen.getAllByTestId("entity-chip")).toHaveLength(2);
    expect(screen.getByText("+3")).toBeTruthy();
    render(<EntityChip object={{ kind: "site", role: "affected", label: "www.dept.example.ac.in" }} />);
    expect(screen.getByText("Campus site")).toBeTruthy();
  });
});

describe("the why points (I-6)", () => {
  const sum = () => screen.getAllByTestId("why-value").reduce((s, td) => s + Number((td.textContent ?? "").replace("−", "-")), 0);

  it("add up to the shown priority when the points sum", () => {
    render(<WhyPoints engine={e} />);
    expect(sum()).toBe(Number(screen.getByTestId("why-total").textContent));
    expect(screen.getByTestId("why-points").textContent).not.toContain("Other factors");
  });

  it("add up through an Other factors row when they do not (74 of 82)", () => {
    const short = engineOf(p1Engine({ why: [{ op: "+", points: 44, text: "a" }, { op: "+", points: 30, text: "b" }] })) as Engine;
    render(<WhyPoints engine={short} />);
    expect(screen.getByText("Other factors and limits")).toBeTruthy();
    expect(sum()).toBe(82);
  });

  it("on a phone, the top three with +N more, the total always shown", () => {
    render(<WhyPoints engine={e} top={3} />);
    expect(screen.getAllByTestId("why-value")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "+2 more" })).toBeTruthy();
    expect(screen.getByTestId("why-total").textContent).toBe("82");
  });

  it("explains the kind of signal in words, never the formula", () => {
    render(<WhyPoints engine={e} />);
    expect(screen.getByText("How the score is built")).toBeTruthy();
    expect(document.body.textContent).toContain("A strong signal");
  });
});
