import { fireEvent, render, screen } from "@testing-library/react";
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { UntrustedText } from "../src/components/UntrustedText";
import { HOSTILE } from "../src/lib/hostile";
import { DEFAULT_LIMITS } from "../src/lib/untrusted";

const ALLOWED_TAGS = new Set(["SPAN", "DIV", "BDI", "BUTTON"]);
const ALLOWED_ATTRS = new Set(["class", "title", "data-untrusted", "type", "dir"]);

function inert(root: HTMLElement): void {
  for (const el of root.querySelectorAll("*")) {
    expect(ALLOWED_TAGS.has(el.tagName), el.tagName).toBe(true);
    for (const attr of el.getAttributeNames()) expect(ALLOWED_ATTRS.has(attr), attr).toBe(true);
  }
  expect(root.querySelector("a, img, script, style, svg, iframe, link")).toBeNull();
}

describe("UntrustedText", () => {
  it("renders every hostile fixture as inert text", () => {
    for (const h of HOSTILE) {
      const { container, unmount } = render(<UntrustedText value={h.value} block />);
      inert(container);
      unmount();
    }
    expect((window as unknown as { __pwned?: unknown }).__pwned).toBeUndefined();
  });

  it("is inert for any value", () => {
    fc.assert(
      fc.property(fc.string({ unit: "binary", maxLength: 80 }), (value) => {
        const { container, unmount } = render(<UntrustedText value={value} />);
        inert(container);
        unmount();
      }),
      { numRuns: 60 },
    );
  });

  it("shows markup as its own characters, markers with names, and IDNs with their ASCII form", () => {
    const { container } = render(<UntrustedText value={"<b>x</b> \u202e \u0430pple.com"} />);
    expect(container.textContent).toContain("<b>x</b>");
    const mark = container.querySelector(".ut-mark");
    expect(mark?.getAttribute("title")).toBe("U+202E right-to-left override");
    expect(mark?.textContent).toContain("RLO");
    expect(container.querySelector(".ut-idn")?.textContent).toBe("xn--pple-43d.com");
    expect(container.textContent).not.toContain("\u202e");
    expect(container.querySelector("bdi")?.getAttribute("dir")).toBe("ltr");
  });

  it("says when a name is not a valid domain", () => {
    const { container } = render(<UntrustedText value={"\u00e9\u3002\u00e9\u00e9\u00e9" + ".x".repeat(1)} />);
    const idn = container.querySelector(".ut-idn");
    expect(idn).not.toBeNull();
    const invalid = render(<UntrustedText value={"\u00e9." + "a".repeat(300) + ".\u00e9\u00e9" + "b".repeat(800)} />);
    expect(invalid.container.textContent).toMatch(/not a valid domain name|xn--/);
  });

  it("groups counts the Indian way, keeps its class, and puts a space before the cut", () => {
    const { container } = render(<UntrustedText value={"z".repeat(123_456 + 2_000)} />);
    expect(container.textContent).toContain("zz \u2026 1,23,456 more characters Show all");
    expect(container.firstElementChild?.classList.contains("ut")).toBe(true);
  });

  it("explains the ASCII form, and a name that is not valid", () => {
    const valid = render(<UntrustedText value={"\u0430pple.com"} />).container.querySelector(".ut-idn");
    expect(valid?.getAttribute("title")).toBe("How this name is really written (ASCII); look-alike letters show here");
    expect(valid?.textContent).toBe("xn--pple-43d.com");
    const invalid = render(<UntrustedText value={"\u0301x.com"} />).container.querySelector(".ut-idn");
    expect(invalid?.getAttribute("title")).toBe("Written with non-ASCII letters, and not a valid domain name");
    expect(invalid?.textContent).toBe("not a valid domain name");
  });

  it("caps, and shows all on request, once", () => {
    const value = "y".repeat(DEFAULT_LIMITS.maxChars + 1234);
    const { container } = render(<UntrustedText value={value} />);
    expect(container.textContent).toContain("… 1,234 more characters");
    fireEvent.click(screen.getByRole("button", { name: "Show all" }));
    expect(container.textContent).toBe(value);
    expect(screen.queryByRole("button", { name: "Show all" })).toBeNull();
  });

  it("names a line cut and a single hidden character", () => {
    const { container } = render(<UntrustedText value={"a\nb\nc"} limits={{ maxLines: 2 }} />);
    expect(container.textContent).toContain("2 more characters (line limit)");
    const one = render(<UntrustedText value={"abc"} limits={{ maxChars: 2 }} />);
    expect(one.container.textContent).toContain("… 1 more character Show all");
  });

  it("caps lines at 40 and characters at 2,000 by default", () => {
    const lines = render(<UntrustedText value={Array.from({ length: 45 }, () => "l").join("\n")} />);
    expect(lines.container.textContent).toContain("10 more characters (line limit)");
    const chars = render(<UntrustedText value={"c".repeat(2001)} limits={{ maxLines: 3 }} />);
    expect(chars.container.textContent).toContain("1 more character Show all");
    const both = render(<UntrustedText value={"d".repeat(10)} limits={{ maxChars: 4 }} />);
    expect(both.container.textContent).toContain("6 more characters Show all");
  });

  it("is inline by default and a block on request", () => {
    expect(render(<UntrustedText value="x" />).container.firstElementChild?.tagName).toBe("SPAN");
    const block = render(<UntrustedText value="x" block className="extra" />).container.firstElementChild;
    expect(block?.tagName).toBe("DIV");
    expect(block?.className).toContain("block");
    expect(block?.className).toContain("extra");
  });
});

// review F4: right-to-left letters in their own isolates (the outer one stays left to right)
describe("UntrustedText and right-to-left letters", () => {
  it("puts each run of them in a right-to-left isolate, the addresses around them outside", () => {
    const { container } = render(<UntrustedText value={"from \u05d0 10.0.0.1 \u05d0 192.168.1.1"} />);
    const outer = container.querySelector("bdi");
    expect(outer?.getAttribute("dir")).toBe("ltr");
    const inner = [...(outer?.querySelectorAll("bdi") ?? [])];
    expect(inner.map((b) => [b.getAttribute("dir"), b.textContent])).toEqual([
      ["rtl", "\u05d0"],
      ["rtl", "\u05d0"],
    ]);
    expect(container.textContent).toBe("from \u05d0 10.0.0.1 \u05d0 192.168.1.1");
    expect([...(outer?.childNodes ?? [])].map((n) => n.nodeName)).toEqual(["#text", "BDI", "#text", "BDI", "#text"]);
  });

  it("does the same inside a domain name, its ASCII form beside it", () => {
    const { container } = render(<UntrustedText value={"\u05e9\u05dc\u05d5\u05dd.\u05e7\u05d5\u05dd.com"} />);
    const idn = container.querySelector(".ut-idn");
    expect(idn?.textContent).toMatch(/^xn--/);
    expect([...container.querySelectorAll("bdi[dir=rtl]")].map((b) => b.textContent)).toEqual(["\u05e9\u05dc\u05d5\u05dd", "\u05e7\u05d5\u05dd"]);
  });

  it("is still inert for any value with right-to-left letters in it", () => {
    fc.assert(
      fc.property(fc.array(fc.constantFrom("\u05d0", "1", " ", "<b>", "\u202e", "a.\u05d0.com", "\u0627"), { maxLength: 12 }), (parts) => {
        const { container, unmount } = render(<UntrustedText value={parts.join("")} />);
        inert(container);
        unmount();
      }),
      { numRuns: 40 },
    );
  });
});
