// AR4: "Next" is whatever follows this investigation in the queue; when it is reviewed it leaves the
// queue and the item that followed it stands where it stood. Never itself, never nothing by mistake.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { nextOf } from "../src/lib/queueNext";

const Q = ["a", "b", "c", "d"];

describe("the next item", () => {
  it("is the one after this in the queue, with how many are left", () => {
    expect(nextOf(Q, "a", -1)).toEqual({ id: "b", left: 3 });
    expect(nextOf(Q, "c", 2)).toEqual({ id: "d", left: 1 });
  });

  it("is nothing at the end of the queue", () => {
    expect(nextOf(Q, "d", 3)).toEqual({ id: null, left: 0 });
    expect(nextOf([], "a", -1)).toEqual({ id: null, left: 0 });
  });

  it("is whatever stands where this one stood once it left the queue (it was reviewed)", () => {
    expect(nextOf(["a", "c", "d"], "b", 1)).toEqual({ id: "c", left: 2 });
    expect(nextOf(["a", "b", "c"], "d", 3)).toEqual({ id: null, left: 0 }); // the last one was reviewed
    expect(nextOf(["a"], "b", 5)).toEqual({ id: null, left: 0 }); // the queue is shorter than it was
  });

  it("is the queue's first item for an investigation that was never in it", () => {
    expect(nextOf(Q, "z", -1)).toEqual({ id: "a", left: 4 });
  });

  it("is never the investigation itself", () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.constantFrom("a", "b", "c", "d", "e", "f"), { maxLength: 6 }), fc.constantFrom("a", "b", "c", "x"), fc.integer({ min: -1, max: 8 }), (order, id, stood) => {
        const found = nextOf(order, id, stood);
        expect(found.id).not.toBe(id);
        expect(found.left).toBeLessThanOrEqual(order.length);
        expect(found.left === 0).toBe(found.id === null);
        if (found.id !== null) expect(order).toContain(found.id);
      }),
    );
  });

  it("walks the whole queue exactly once when each item is reviewed in turn", () => {
    fc.assert(
      fc.property(fc.uniqueArray(fc.integer({ min: 0, max: 99 }).map(String), { minLength: 1, maxLength: 12 }), (all) => {
        let queue = [...all];
        let at = all[0] as string;
        let stood = 0;
        const seen: string[] = [];
        while (true) {
          seen.push(at);
          const stoodNow = queue.indexOf(at);
          queue = queue.filter((i) => i !== at); // reviewed: gone from the queue
          const found = nextOf(queue, at, stoodNow >= 0 ? stoodNow : stood);
          stood = Math.max(stoodNow, 0);
          if (found.id === null) break;
          at = found.id;
        }
        expect(seen).toEqual(all);
      }),
    );
  });
});
