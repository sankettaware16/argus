import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import fc from "fast-check";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "../src/components/ConfirmDialog";
import { codePoints, payloadText, type ExactRequest, type PendingRequest, type Sent } from "../src/lib/payload";
import { HARD_MAX, original, segments } from "../src/lib/untrusted";

function shownBody(): string {
  // what the person reads: the markers stand for their characters
  const pre = screen.getByTestId("payload");
  let out = "";
  const walk = (node: Node) => {
    if (node.nodeType === Node.TEXT_NODE) out += node.textContent;
    else if (node instanceof HTMLElement && node.classList.contains("ut-mark")) {
      const code = /^U\+([0-9A-F]+)/.exec(node.title)?.[1];
      out += String.fromCodePoint(parseInt(code ?? "FFFD", 16));
    } else if (node instanceof HTMLElement && node.classList.contains("ut-idn")) {
      return;
    } else node.childNodes.forEach(walk);
  };
  pre.childNodes.forEach(walk);
  return out;
}

const SENT: Sent = { status: 201, data: {} };
type Send = (exact: ExactRequest) => Promise<Sent>;

function sender(impl: Send = async () => SENT) {
  return vi.fn<Send>(impl);
}

function open(request: PendingRequest, onConfirm = sender(), onSent = vi.fn<(sent: Sent) => void>()) {
  const onOpenChange = vi.fn();
  const view = render(
    <ConfirmDialog open onOpenChange={onOpenChange} title="Send it?" request={request} confirmLabel="Send" send={onConfirm} onSent={onSent} />,
  );
  return { ...view, onConfirm, onOpenChange, onSent };
}

describe("payloadText", () => {
  it("is the JSON that is sent, for any JSON value", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (body) => {
        const made = payloadText(body);
        expect(made.ok).toBe(true);
        if (made.ok) {
          expect(JSON.parse(made.text)).toEqual(JSON.parse(JSON.stringify(body)));
          expect(made.text).toBe(JSON.stringify(body, null, 2));
          expect(made.empty).toBe(false);
        }
      }),
    );
  });

  it("refuses what cannot be shown whole", () => {
    expect(payloadText(undefined)).toEqual({ ok: true, text: "", empty: true });
    const loops = "This request's body cannot be written as JSON (it loops, or holds a big integer).";
    expect(payloadText(10n)).toEqual({ ok: false, why: loops });
    const cycle: Record<string, unknown> = {};
    cycle.self = cycle;
    expect(payloadText(cycle)).toEqual({ ok: false, why: loops });
    expect(payloadText(() => 1)).toEqual({ ok: false, why: "This request's body has nothing JSON can write." });
    expect(payloadText("x".repeat(HARD_MAX))).toMatchObject({ ok: false, why: expect.stringContaining("too large") });
    expect(payloadText("x".repeat(HARD_MAX - 2))).toMatchObject({ ok: true });
  });

  it("counts code points", () => {
    expect(codePoints("")).toBe(0);
    expect(codePoints("a\u{1F600}b")).toBe(3);
    expect(codePoints("\uD800x")).toBe(2);
    expect(codePoints("\uDC00\uD800")).toBe(2);
    expect(codePoints("abcdef", 2)).toBe(3);
    // the surrogate ranges' edges
    expect(codePoints("\uD800\uDC00")).toBe(1);
    expect(codePoints("\uDBFF\uDFFF")).toBe(1);
    expect(codePoints("\uD7FF\uDC00")).toBe(2);
    expect(codePoints("\uDC00\uDC00")).toBe(2);
    expect(codePoints("\uD800\uDBFF")).toBe(2);
    expect(codePoints("\uD800\uE000")).toBe(2);
    expect(codePoints("a\uDC00")).toBe(2);
    expect(codePoints("\uDC00a")).toBe(2);
    fc.assert(
      fc.property(fc.string({ unit: "binary" }), (s) => {
        expect(codePoints(s)).toBe(Array.from(s).length);
      }),
    );
  });
});

describe("ConfirmDialog", () => {
  it("sends exactly the body it shows, for any body", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue({ maxDepth: 3 }), async (body) => {
        const { onConfirm, unmount } = open({ method: "POST", path: "/api/v1/x", body });
        const shown = shownBody();
        expect(original(segments(shown, { maxChars: HARD_MAX, maxLines: HARD_MAX }))).toBe(shown);
        fireEvent.click(screen.getByRole("button", { name: "Send" }));
        await waitFor(() => expect(onConfirm).toHaveBeenCalledTimes(1));
        expect(onConfirm.mock.calls[0]?.[0]).toEqual({ method: "POST", path: "/api/v1/x", text: shown });
        expect(JSON.parse(shown)).toEqual(JSON.parse(JSON.stringify(body)));
        unmount();
      }),
      { numRuns: 25 },
    );
  });

  it("shows hidden characters in the body and the path", () => {
    open({ method: "PATCH", path: "/api/v1/cases/\u202eabc", body: { note: "ok\u202egnp.exe" } });
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.textContent).toContain("PATCH");
    expect(dialog.querySelectorAll(".ut-mark")).toHaveLength(2);
    expect(dialog.textContent).not.toContain("\u202e");
  });

  it("sends once however often it is clicked, and closes after", async () => {
    let finish: () => void = () => {};
    const onConfirm = sender(() => new Promise<Sent>((done) => (finish = () => done(SENT))));
    const { onOpenChange, onSent } = open({ method: "POST", path: "/p", body: { a: 1 } }, onConfirm);
    const send = screen.getByRole("button", { name: "Send" });
    fireEvent.click(send);
    fireEvent.click(send);
    fireEvent.click(screen.getByRole("button", { name: "Sending…" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Sending…" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveProperty("disabled", true);
    expect(onSent).not.toHaveBeenCalled();
    await act(async () => finish());
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onSent).toHaveBeenCalledExactlyOnceWith(SENT);
  });

  it("sends once even when clicked twice before the page updates", async () => {
    let finish: () => void = () => {};
    const onConfirm = sender(() => new Promise<Sent>((done) => (finish = () => done(SENT))));
    open({ method: "POST", path: "/p", body: { a: 1 } }, onConfirm);
    const send = screen.getByRole("button", { name: "Send" });
    act(() => {
      send.click();
      send.click(); // the button is not disabled yet: React has not rendered between the two
    });
    expect(onConfirm).toHaveBeenCalledTimes(1);
    await act(async () => finish());
  });

  it("stays open and says why when sending fails, and lets the person try again", async () => {
    const onConfirm = sender(async () => {
      throw new Error("The investigation changed while you looked; read it again.");
    });
    const { onOpenChange, onSent } = open({ method: "POST", path: "/p", body: { a: 1 } }, onConfirm);
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    expect(await screen.findByRole("alert")).toHaveProperty("textContent", "The investigation changed while you looked; read it again.");
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
    expect(onSent).not.toHaveBeenCalled();
    onConfirm.mockImplementationOnce(async () => {
      throw "not an Error";
    });
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(screen.getByRole("alert").textContent).toContain("Nothing was changed by this attempt"));
    expect(onConfirm).toHaveBeenCalledTimes(2);
  });

  it("cannot confirm what it cannot show", () => {
    const onConfirm = sender();
    open({ method: "POST", path: "/p", body: "z".repeat(HARD_MAX + 1) }, onConfirm);
    const send = screen.getByRole("button", { name: "Send" });
    expect(send).toHaveProperty("disabled", true);
    expect(screen.getByRole("alert").textContent).toContain("too large to show whole");
    fireEvent.click(send);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("says when there is no body, and sends nothing else", async () => {
    const { onConfirm } = open({ method: "DELETE", path: "/api/v1/session" });
    expect(screen.getByText("No body: the request sends nothing else.")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith({ method: "DELETE", path: "/api/v1/session", text: "" }));
  });

  it("gives Cancel the focus first, and Cancel closes without sending", async () => {
    const { onConfirm, onOpenChange } = open({ method: "POST", path: "/p", body: {} });
    await waitFor(() => expect(document.activeElement?.textContent).toBe("Cancel"));
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(onConfirm).not.toHaveBeenCalled();
  });

  // review F2: what the person reads is fixed while the dialog is open
  it("keeps what the person read when the request changes while open, and sends it only after a fresh look", async () => {
    const onConfirm = sender();
    const props = { open: true, onOpenChange: () => {}, title: "t", confirmLabel: "Send", send: onConfirm };
    const view = render(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: { alerts: 3 } }} />);
    const read = shownBody();
    // the same request again (a new object with the same content): nothing changes
    view.rerender(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: { alerts: 3 } }} />);
    expect(screen.queryByText(/changed while you were reading/)).toBeNull();
    view.rerender(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: { alerts: 300 } }} />);
    expect(shownBody()).toBe(read);
    expect(screen.getByRole("status").textContent).toContain("This request changed while you were reading it.");
    const send = screen.getByRole("button", { name: "Send" });
    expect(send).toHaveProperty("disabled", true);
    fireEvent.click(send);
    expect(onConfirm).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Show the new request" }));
    expect(shownBody()).toBe('{\n  "alerts": 300\n}');
    expect(screen.queryByText(/changed while you were reading/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(onConfirm).toHaveBeenCalledExactlyOnceWith({ method: "POST", path: "/p", text: '{\n  "alerts": 300\n}' }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Send" })).toHaveProperty("disabled", false));
    expect(screen.queryByRole("alert")).toBeNull(); // no onSent given: nothing breaks
  });

  it("cannot take the new request while sending the one shown", async () => {
    let finish: () => void = () => {};
    const onConfirm = sender(() => new Promise<Sent>((done) => (finish = () => done(SENT))));
    const props = { open: true, onOpenChange: () => {}, title: "t", confirmLabel: "Send", send: onConfirm };
    const view = render(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: 1 }} />);
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    view.rerender(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: 2 }} />);
    expect(screen.getByRole("button", { name: "Show the new request" })).toHaveProperty("disabled", true);
    expect(shownBody()).toBe("1");
    await act(async () => finish());
    expect(screen.getByRole("button", { name: "Show the new request" })).toHaveProperty("disabled", false);
    expect(onConfirm).toHaveBeenCalledExactlyOnceWith({ method: "POST", path: "/p", text: "1" });
  });

  it("tells two bodies that cannot be shown apart", () => {
    const props = { open: true, onOpenChange: () => {}, title: "t", confirmLabel: "Send", send: sender() };
    const view = render(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: 10n }} />);
    view.rerender(<ConfirmDialog {...props} request={{ method: "POST", path: "/p", body: () => 1 }} />);
    expect(screen.getByRole("status").textContent).toContain("changed while you were reading");
  });

  it("counts a new method, path or unshowable body as a change too", () => {
    const props = { open: true, onOpenChange: () => {}, title: "t", confirmLabel: "Send", send: sender() };
    const base = { method: "POST" as const, path: "/p", body: 1 };
    for (const next of [
      { ...base, method: "PUT" as const },
      { ...base, path: "/q" },
      { ...base, body: 10n },
      { ...base, body: undefined },
    ]) {
      const view = render(<ConfirmDialog {...props} request={base} />);
      view.rerender(<ConfirmDialog {...props} request={next} />);
      expect(screen.getByRole("status").textContent, JSON.stringify(next.path)).toContain("changed while you were reading");
      expect(screen.getByRole("alertdialog").textContent).toContain("POST/p");
      view.unmount();
    }
  });

  it("takes a fresh copy each time it opens, and keeps one body however the object is changed in place", async () => {
    const onConfirm = sender();
    const body = { n: 1 };
    const props = { onOpenChange: () => {}, title: "t", confirmLabel: "Send", send: onConfirm };
    const view = render(<ConfirmDialog open={false} {...props} request={{ method: "POST", path: "/p", body }} />);
    view.rerender(<ConfirmDialog open {...props} request={{ method: "POST", path: "/p", body: { n: 2 } }} />);
    await waitFor(() => expect(screen.getByRole("alertdialog")).toBeTruthy());
    expect(shownBody()).toBe('{\n  "n": 2\n}');
    view.rerender(<ConfirmDialog open={false} {...props} request={{ method: "POST", path: "/p", body }} />);
    view.rerender(<ConfirmDialog open {...props} request={{ method: "POST", path: "/p", body }} />);
    await waitFor(() => expect(shownBody()).toBe('{\n  "n": 1\n}'));
    body.n = 99; // changed in place: the copy the person read is what goes
    view.rerender(<ConfirmDialog open {...props} request={{ method: "POST", path: "/p", body }} />);
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(onConfirm).toHaveBeenCalledExactlyOnceWith({ method: "POST", path: "/p", text: '{\n  "n": 1\n}' }));
  });

  it("cannot be closed while sending, and forgets an old failure when trying again", async () => {
    let finish: () => void = () => {};
    const onConfirm = sender()
      .mockImplementationOnce(async () => {
        throw new Error("first try failed");
      })
      .mockImplementationOnce(() => new Promise<Sent>((done) => (finish = () => done(SENT))));
    const { onOpenChange } = open({ method: "POST", path: "/p", body: 1 }, onConfirm);
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await screen.findByText("first try failed");
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    await waitFor(() => expect(screen.queryByText("first try failed")).toBeNull());
    fireEvent.keyDown(screen.getByRole("alertdialog"), { key: "Escape" });
    expect(onOpenChange).not.toHaveBeenCalled();
    await act(async () => finish());
    expect(onOpenChange).toHaveBeenCalledWith(false);
  });

  it("forgets a failure when it is closed, and says the plain words for an empty error", async () => {
    const onConfirm = sender(async () => {
      throw new Error("");
    });
    const onOpenChange = vi.fn();
    const props = { onOpenChange, title: "t", request: { method: "POST" as const, path: "/p", body: 1 }, confirmLabel: "Send", send: onConfirm };
    const view = render(<ConfirmDialog open {...props} />);
    fireEvent.click(screen.getByRole("button", { name: "Send" }));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "It could not be sent. Nothing was changed by this attempt; try again.",
    );
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onOpenChange).toHaveBeenCalledWith(false);
    view.rerender(<ConfirmDialog open={false} {...props} />);
    view.rerender(<ConfirmDialog open {...props} />);
    await waitFor(() => expect(screen.getByRole("alertdialog")).toBeTruthy());
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("has no description unless given one, and the main style unless destructive", () => {
    open({ method: "POST", path: "/p", body: 1 });
    expect(screen.getByRole("alertdialog").hasAttribute("aria-describedby")).toBe(false);
    expect(screen.getByRole("button", { name: "Send" }).className).toContain("bg-accent");
  });

  it("shows a long body whole, never capped", () => {
    const note = "n".repeat(5_000);
    open({ method: "POST", path: `/p/${"q".repeat(3_000)}`, body: { note } });
    const dialog = screen.getByRole("alertdialog");
    expect(dialog.textContent).not.toContain("more character");
    expect(shownBody()).toContain(note);
    expect(dialog.textContent).toContain("q".repeat(3_000));
  });

  it("uses the danger style for a destructive change", () => {
    render(
      <ConfirmDialog open onOpenChange={() => {}} title="t" request={{ method: "POST", path: "/p", body: 1 }} confirmLabel="Close the case" send={sender()} danger description="Plain words" />,
    );
    expect(screen.getByRole("button", { name: "Close the case" }).className).toContain("bg-danger");
    expect(screen.getByText("Plain words")).toBeTruthy();
  });
});
