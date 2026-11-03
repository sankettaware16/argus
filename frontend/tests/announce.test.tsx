import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it } from "vitest";
import { AnnounceProvider, Messages, useAnnounce } from "../src/lib/announce";

function wrapper({ children }: { children: ReactNode }) {
  return (
    <AnnounceProvider>
      {children}
      <Messages />
    </AnnounceProvider>
  );
}

describe("messages", () => {
  it("speaks results politely and failures assertively, and shows them until dismissed", () => {
    const { result } = renderHook(() => useAnnounce(), { wrapper });
    act(() => result.current.announce("The review was saved.", "ok"));
    expect(screen.getByTestId("live-polite").textContent).toBe("The review was saved.");
    expect(screen.getByTestId("live-polite").getAttribute("aria-live")).toBe("polite");
    act(() => result.current.announce("It could not be saved.", "danger"));
    expect(screen.getByTestId("live-assertive").textContent).toBe("It could not be saved.\u00a0");
    expect(screen.getByTestId("live-assertive").getAttribute("role")).toBe("alert");
    expect(screen.getByText("Done:")).toBeTruthy();
    expect(screen.getByText("Problem:")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Dismiss: The review was saved." }));
    expect(screen.queryByText("The review was saved.", { selector: "p" })).toBeNull();
    expect(result.current.messages).toHaveLength(1);
  });

  it("announces the same words again, keeps four, and caps long text", () => {
    const { result } = renderHook(() => useAnnounce(), { wrapper });
    act(() => result.current.announce("Saved."));
    const first = screen.getByTestId("live-polite").textContent;
    act(() => result.current.announce("Saved."));
    expect(screen.getByTestId("live-polite").textContent).not.toBe(first);
    act(() => {
      for (let i = 0; i < 6; i++) result.current.announce(`n${i}`, "warn");
    });
    expect(result.current.messages.map((m) => m.text)).toEqual(["n2", "n3", "n4", "n5"]);
    act(() => result.current.announce("y".repeat(400), "info"));
    expect(result.current.messages.at(-1)?.text).toHaveLength(301);
    expect(screen.getAllByText("Check:")).toHaveLength(3);
    expect(screen.getAllByText("Note:")).toHaveLength(1);
  });

  it("needs its provider, and shows nothing without messages", () => {
    expect(() => renderHook(() => useAnnounce())).toThrow("useAnnounce needs an AnnounceProvider");
    const { container } = render(
      <AnnounceProvider>
        <Messages />
      </AnnounceProvider>,
    );
    expect(container.querySelector("section")).toBeNull();
  });
});
