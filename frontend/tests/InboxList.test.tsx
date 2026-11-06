// The Inbox's list as a grid (components/InboxList.tsx): ARIA, keys, windowing.
import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { InboxList, type InboxListProps } from "../src/components/InboxList";
import { investigation, layout, must } from "./helpers";

const rowsOf = (n: number) =>
  Array.from({ length: n }, (_, i) =>
    investigation(`00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, { rule_name: `Rule ${i}`, created_at: i === 0 ? "2026-10-25T00:00:00Z" : "2026-10-01T00:00:00Z" }),
  );

function Harness(props: Partial<InboxListProps> & { n?: number }) {
  const rows = rowsOf(props.n ?? 30);
  const [cursor, setCursor] = useState(props.cursor ?? -1);
  return (
    <InboxList
      hasMore={false}
      loadingMore={false}
      onLoadMore={() => {}}
      onOpen={() => {}}
      shortcuts
      onHelp={() => {}}
      since="2026-10-20T00:00:00Z"
      viewport={{ width: 420, height: 600 }}
      {...props}
      rows={rows}
      cursor={cursor}
      onCursor={(i) => {
        setCursor(i);
        props.onCursor?.(i);
      }}
    />
  );
}

const grid = () => screen.getByRole("grid", { name: "Investigations" });
const press = (key: string, more: KeyboardEventInit = {}) => fireEvent.keyDown(grid(), { key, ...more });

describe("the grid", () => {
  beforeEach(() => layout());

  it("is one tab stop with a grid role, its size and columns, and names its rows by position", () => {
    render(<Harness />);
    expect(grid().getAttribute("tabindex")).toBe("0");
    expect(grid().getAttribute("aria-colcount")).toBe("3");
    expect(grid().getAttribute("aria-rowcount")).toBe("31"); // 30 rows and the header
    const rows = within(grid()).getAllByRole("row");
    expect(rows[0]?.getAttribute("aria-rowindex")).toBe("1");
    expect(within(must(rows[0])).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Investigation", "Status", "Alerts and last alert"]);
    expect(rows[1]?.getAttribute("aria-rowindex")).toBe("2");
    expect(within(must(rows[1])).getAllByRole("gridcell").map((c) => c.getAttribute("aria-colindex"))).toEqual(["1", "2", "3"]); // in the order of the page, which is the order of the header (review B2-R8)
    expect(within(grid()).queryByRole("link")).toBeNull();
  });

  it("says the number of rows is not known while the server has more", () => {
    render(<Harness hasMore n={3} />);
    expect(grid().getAttribute("aria-rowcount")).toBe("-1");
    expect(screen.getByText("Loading more…")).toBeTruthy();
  });

  it("keeps only the rows near the window in the page, whatever the list's length", () => {
    render(<Harness n={10_000} />);
    const rendered = within(grid()).getAllByRole("row").length;
    expect(rendered).toBeGreaterThan(5);
    expect(rendered).toBeLessThan(30);
    expect(grid().getAttribute("aria-rowcount")).toBe("10001");
  });

  it("names the cursor row with aria-activedescendant and selects only that row", () => {
    render(<Harness cursor={2} />);
    const selected = within(grid()).getAllByRole("row", { selected: true });
    expect(selected).toHaveLength(1);
    expect(selected[0]?.getAttribute("aria-rowindex")).toBe("4"); // the header is row 1
    expect(grid().getAttribute("aria-activedescendant")).toBe(selected[0]?.id);
    expect(selected[0]?.textContent).toContain("Rule 2");
  });

  it("has no active descendant before the cursor stands on a row", () => {
    render(<Harness />);
    expect(grid().hasAttribute("aria-activedescendant")).toBe(false);
    expect(within(grid()).queryAllByRole("row", { selected: true })).toHaveLength(0);
  });

  it("marks what is new since the previous visit, in words", () => {
    render(<Harness />);
    expect(within(must(within(grid()).getAllByRole("row")[1])).getByText("new")).toBeTruthy();
    expect(within(must(within(grid()).getAllByRole("row")[2])).queryByText("new")).toBeNull();
  });
});

describe("the keys", () => {
  beforeEach(() => layout());

  it("moves the cursor with the arrows and j and k, and Home, End and the Page keys", () => {
    const seen: number[] = [];
    render(<Harness onCursor={(i) => seen.push(i)} />);
    press("ArrowDown");
    press("j");
    press("ArrowDown");
    press("k");
    press("ArrowUp");
    press("End");
    press("Home");
    press("PageDown");
    expect(seen).toEqual([0, 1, 2, 1, 0, 29, 0, 6]);
  });

  it("opens the cursor row with Enter, asking for the focus to move, and does nothing with no cursor", () => {
    const onOpen = vi.fn();
    render(<Harness cursor={3} onOpen={onOpen} />);
    press("Enter");
    expect(onOpen).toHaveBeenCalledTimes(1);
    expect(onOpen.mock.calls[0]?.[0].rule_name).toBe("Rule 3");
    expect(onOpen.mock.calls[0]?.[1]).toBe(true);
    render(<Harness onOpen={onOpen} />);
    fireEvent.keyDown(must(screen.getAllByRole("grid")[1]), { key: "Enter" });
    expect(onOpen).toHaveBeenCalledTimes(1);
  });

  it("opens a row clicked, without moving the focus into the pane", () => {
    const onOpen = vi.fn();
    const onCursor = vi.fn();
    render(<Harness onOpen={onOpen} onCursor={onCursor} />);
    fireEvent.click(must(within(grid()).getAllByRole("row")[3]));
    expect(onCursor).toHaveBeenCalledWith(2);
    expect(onOpen.mock.calls[0]?.[1]).toBe(false);
  });

  it("shows the help with ?, and with the letter keys off still moves with the arrows but not with j, k or ?", () => {
    const onHelp = vi.fn();
    const seen: number[] = [];
    render(<Harness onHelp={onHelp} shortcuts={false} onCursor={(i) => seen.push(i)} />);
    press("?", { shiftKey: true });
    press("j");
    press("k");
    expect(onHelp).not.toHaveBeenCalled();
    expect(seen).toEqual([]);
    press("ArrowDown");
    expect(seen).toEqual([0]);
    render(<Harness onHelp={onHelp} />);
    fireEvent.keyDown(must(screen.getAllByRole("grid")[1]), { key: "?", shiftKey: true });
    expect(onHelp).toHaveBeenCalledTimes(1);
  });

  it("ignores keys from inside a row's own controls and keys with Ctrl", () => {
    const seen: number[] = [];
    render(<Harness onCursor={(i) => seen.push(i)} />);
    fireEvent.keyDown(must(within(grid()).getAllByRole("row")[1]), { key: "ArrowDown", bubbles: true });
    press("j", { ctrlKey: true });
    expect(seen).toEqual([]);
  });
});

describe("reading more", () => {
  beforeEach(() => layout());

  it("asks for the next page when the window nears the end, once, and not while one is loading", () => {
    const more = vi.fn();
    const { rerender } = render(<Harness n={12} hasMore onLoadMore={more} />);
    expect(more).toHaveBeenCalled();
    more.mockClear();
    rerender(<Harness n={12} hasMore loadingMore onLoadMore={more} />);
    expect(more).not.toHaveBeenCalled();
    const far = vi.fn();
    render(<Harness n={5_000} hasMore onLoadMore={far} />);
    expect(far).not.toHaveBeenCalled();
  });
});

describe("hostile names", () => {
  beforeEach(() => layout());

  it("are shown as text, with their hidden characters marked, never as markup", () => {
    const rows = [investigation(undefined, { rule_name: '<img src=x onerror="window.__pwned=1"> \u202eevil' })];
    render(<InboxList rows={rows} hasMore={false} loadingMore={false} onLoadMore={() => {}} cursor={0} onCursor={() => {}} onOpen={() => {}} shortcuts onHelp={() => {}} since={null} viewport={{ width: 420, height: 600 }} />);
    expect(grid().querySelector("img")).toBeNull();
    expect(grid().textContent).toContain("<img src=x");
    expect(grid().querySelectorAll(".ut-mark").length).toBeGreaterThanOrEqual(1);
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });
});

describe("a cursor row scrolled out of the window", () => {
  beforeEach(() => layout());

  it("is not named as the active descendant while its element is not in the page", () => {
    render(<Harness cursor={500} n={1_000} />);
    const rendered = within(grid()).getAllByRole("row").map((r) => r.id);
    expect(rendered.length).toBeLessThan(30);
    expect(grid().hasAttribute("aria-activedescendant")).toBe(false);
    expect(within(grid()).queryAllByRole("row", { selected: true })).toHaveLength(0);
  });
});

describe("a row's title (naming v2)", () => {
  beforeEach(() => layout());

  it("says what happened from the investigation's facts, and names the rule only as the rule's", () => {
    const rows = [investigation(undefined, { rule_name: "Proxy: POST to a bare address (possible beacon)", title: "10.0.0.12 · beacon-timed", key_words: "from 10.0.0.12" })];
    render(<InboxList rows={rows} hasMore={false} loadingMore={false} onLoadMore={() => {}} cursor={0} onCursor={() => {}} onOpen={() => {}} shortcuts onHelp={() => {}} since={null} viewport={{ width: 420, height: 600 }} />);
    const row = within(grid()).getAllByRole("row")[1];
    const [first, second] = Array.from(must(row?.querySelector('[role="gridcell"]')).children);
    expect(first?.textContent).toBe("10.0.0.12 · beacon-timed");
    expect(second?.textContent).toBe("Rule: Proxy: POST to a bare address (possible beacon) · from 10.0.0.12");
    expect(grid().textContent).not.toContain("source.ip");
  });
});
