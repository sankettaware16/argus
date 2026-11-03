// The address's query string (lib/search.ts): the classic pages' form, lists as repeated names.
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { first, listOf, parseSearch, stringifySearch } from "../src/lib/search";

describe("parseSearch", () => {
  it("reads one name once as text and a repeated name as a list, with or without the question mark", () => {
    expect(parseSearch("?view=open&severity=high&severity=low&rule=a%20b")).toEqual({ view: "open", severity: ["high", "low"], rule: "a b" });
    expect(parseSearch("view=open")).toEqual({ view: "open" });
    expect(parseSearch("")).toEqual({});
    expect(parseSearch("?")).toEqual({});
  });

  it("keeps an empty value, ignores an empty name, and never lets a name reach the prototype", () => {
    expect(parseSearch("?a=&=x")).toEqual({ a: "" });
    const polluted = parseSearch("?__proto__=x&constructor=y&prototype=z&toString=t&toString=u");
    expect(Object.keys(polluted)).toEqual(["toString"]);
    expect(polluted.toString).toEqual(["t", "u"]);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
    expect(Object.getPrototypeOf(polluted)).toBe(Object.prototype);
  });

  it("caps the number of names, the number of repeats and the length of a value", () => {
    const many = Array.from({ length: 100 }, (_, i) => `k${i}=v`).join("&");
    expect(Object.keys(parseSearch(many))).toHaveLength(60);
    const repeats = Array.from({ length: 100 }, () => "x=1").join("&");
    expect((parseSearch(repeats).x as string[]).length).toBe(60);
    const long = parseSearch(`a=${"z".repeat(5000)}`).a;
    expect(typeof long === "string" && long.length).toBe(2000);
  });
});

describe("stringifySearch", () => {
  it("writes lists as repeated names, skips nothing but undefined and null, and starts with ?", () => {
    expect(stringifySearch({ view: "open", severity: ["high", "low"], n: 3, ok: true, none: undefined, nil: null })).toBe("?view=open&severity=high&severity=low&n=3&ok=true");
    expect(stringifySearch({})).toBe("");
    expect(stringifySearch({ a: undefined })).toBe("");
    expect(stringifySearch({ a: "" })).toBe("?a=");
  });

  it("round-trips any names and values (a list of one comes back as its value)", () => {
    const name = fc.string({ minLength: 1, maxLength: 8 }).filter((n) => !["__proto__", "constructor", "prototype"].includes(n));
    const value = fc.string({ maxLength: 40 });
    fc.assert(
      fc.property(fc.dictionary(name, fc.oneof(value, fc.array(value, { minLength: 2, maxLength: 4 })), { maxKeys: 6 }), (search) => {
        expect(parseSearch(stringifySearch(search))).toEqual(search);
      }),
    );
  });
});

describe("first and listOf", () => {
  it("take the first text, and a list without repeats; anything else is nothing", () => {
    expect(first("a")).toBe("a");
    expect(first(["b", "c"])).toBe("b");
    expect(first(5)).toBeUndefined();
    expect(first([])).toBeUndefined();
    expect(first([1, "x"])).toBeUndefined();
    expect(listOf("a")).toEqual(["a"]);
    expect(listOf(["a", "b", "a", 3, null])).toEqual(["a", "b"]);
    expect(listOf(undefined)).toEqual([]);
    expect(listOf({ a: 1 })).toEqual([]);
  });
});
