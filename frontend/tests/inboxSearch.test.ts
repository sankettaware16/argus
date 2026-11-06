// The Inbox's Find box, checked before anything is sent (lib/inboxSearch.ts).
import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { hasControl, validateFind } from "../src/lib/inboxSearch";

const ok = (kind: string, raw: string) => {
  const found = validateFind(kind, raw);
  return found.ok ? found.value : `ERROR ${found.why}`;
};

describe("an IP address", () => {
  it("takes dotted IPv4, trimmed, with no leading zeros and nothing above 255", () => {
    expect(ok("ip", " 10.201.7.13 ")).toBe("10.201.7.13");
    expect(ok("ip", "0.0.0.0")).toBe("0.0.0.0");
    expect(ok("ip", "255.255.255.255")).toBe("255.255.255.255");
    for (const bad of ["256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "a.b.c.d", "1.2.3.4/24", "1.2.3.4:80", "10.201.7.13 x", "1..2.3"]) {
      expect(ok("ip", bad)).toMatch(/^ERROR That is not an IP address/);
    }
  });

  it("takes IPv6 written as ARGUS stores it: lower case, compressed, an IPv4-mapped one as IPv4", () => {
    expect(ok("ip", "2001:DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(ok("ip", "::1")).toBe("::1");
    expect(ok("ip", "::ffff:10.0.0.1")).toBe("10.0.0.1");
    expect(ok("ip", "::FFFF:A00:1")).toBe("10.0.0.1");
    for (const bad of ["2001:db8::1::2", "gggg::1", ":::", "2001:db8", "[::1]", "::1%eth0", "12345::1"]) {
      expect(ok("ip", bad)).toMatch(/^ERROR/);
    }
  });

  it("keeps only an IPv4-mapped address of two groups, and refuses text that is a URL in disguise", () => {
    expect(ok("ip", "::ffff:a00:1f")).toBe("10.0.0.31");
    expect(ok("ip", "::ffff:ffff:ffff")).toBe("255.255.255.255");
    expect(ok("ip", "1::ffff:a00:1")).toBe("1::ffff:a00:1");
    expect(ok("ip", "::ffff:a00:1:2")).toBe("::ffff:a00:1:2");
    for (const bad of ["x]@evil.com/::1", "::1]@evil.com/x[", "::1]@evil.com", "deadbeef", "abc", "1:2:3:4:5:6:7:8:9", "::g", ":"]) {
      expect(ok("ip", bad)).toMatch(/^ERROR/);
    }
  });

  it("never throws, and a valid answer is itself valid and unchanged when sent again", () => {
    fc.assert(fc.property(fc.string({ maxLength: 60 }), (raw) => {
      const first = validateFind("ip", raw);
      if (first.ok) {
        const again = validateFind("ip", first.value);
        expect(again.ok && again.value).toBe(first.value);
      }
    }));
    fc.assert(fc.property(fc.ipV4(), (address) => {
      expect(ok("ip", address)).toBe(address.split(".").map((p) => String(Number(p))).join("."));
    }));
  });
});

describe("a domain", () => {
  it("is written in lower case without its trailing dots", () => {
    expect(ok("domain", " Example.COM. ")).toBe("example.com");
    expect(ok("domain", "a-b.c_d.example.org")).toBe("a-b.c_d.example.org");
    expect(ok("domain", "localhost")).toBe("localhost");
  });

  it("says to type one when only dots were typed, and strips every trailing dot", () => {
    expect(ok("domain", ".")).toBe("ERROR Type a domain name, for example example.com.");
    expect(ok("domain", "...")).toBe("ERROR Type a domain name, for example example.com.");
    expect(ok("domain", "example.com..")).toBe("example.com");
    expect(ok("domain", "a b.com")).toMatch(/^ERROR That is not a valid domain name\. Letters other than a to z/);
    expect(ok("domain", "-a.com")).toMatch(/^ERROR A domain name is words of letters, digits and hyphens/);
    expect(ok("domain", `${"a".repeat(63)}.com`)).toBe(`${"a".repeat(63)}.com`);
    expect(ok("domain", `${"a".repeat(64)}.com`)).toMatch(/^ERROR/);
    const longest = `${"a".repeat(61)}.${"b".repeat(61)}.${"c".repeat(61)}.${"d".repeat(61)}`; // 247
    expect(ok("domain", longest)).toBe(longest);
  });

  it("writes letters beyond a to z in their ASCII form, and refuses what is not a name", () => {
    expect(ok("domain", "bücher.de")).toBe("xn--bcher-kva.de");
    for (const bad of ["", ".", "..", "a..b", "-a.com", "a-.com", "exa mple.com", "a/b.com", "http://example.com", "a@b.com", "x".repeat(64) + ".com"]) {
      expect(ok("domain", bad)).toMatch(/^ERROR/);
    }
    expect(ok("domain", `${"a".repeat(55)}.${"b".repeat(55)}.${"c".repeat(55)}.${"d".repeat(55)}.${"e".repeat(55)}`)).toMatch(/^ERROR A domain name has at most 253/);
  });
});

describe("a host or a user", () => {
  it("passes what a person typed, trimmed", () => {
    expect(ok("host", " PC-12 ")).toBe("PC-12");
    expect(ok("user", "CAMPUS\\asha")).toBe("CAMPUS\\asha");
    expect(ok("user", "asha@example.edu")).toBe("asha@example.edu");
  });
});

describe("every kind", () => {
  it("needs something, of a known kind, in at most 300 visible characters", () => {
    expect(ok("host", "")).toBe("ERROR Type what to find.");
    expect(ok("host", "   ")).toBe("ERROR Type what to find.");
    expect(ok("phone", "x")).toMatch(/^ERROR Choose what to find/);
    expect(ok("host", "x".repeat(300))).toBe("x".repeat(300));
    expect(ok("host", "x".repeat(301))).toBe("ERROR Use at most 300 characters.");
    expect(ok("ip", "1".repeat(301))).toBe("ERROR Use at most 300 characters.");
  });

  it("refuses control characters, line and paragraph separators, and NUL, whichever kind", () => {
    for (const kind of ["ip", "host", "domain", "user"]) {
      for (const bad of ["a\u0000b", "a\nb", "a\tb", "a\u007fb", "a\u0085b", "a\u2028b", "a\u2029b"]) {
        expect(ok(kind, bad)).toMatch(/^ERROR Remove the control characters/);
      }
    }
    expect(hasControl("plain text")).toBe(false);
    expect(hasControl(" ")).toBe(false);
    expect(hasControl("\u009f")).toBe(true);
    expect(hasControl(" \u009f")).toBe(true);
    expect(hasControl("\u001f")).toBe(true);
    expect(hasControl(" ")).toBe(false);
  });

  it("never sends the server a value it refuses (a NUL, or over 300 characters)", () => {
    fc.assert(fc.property(fc.constantFrom("ip", "host", "domain", "user"), fc.string({ maxLength: 400 }), (kind, raw) => {
      const found = validateFind(kind, raw);
      if (found.ok) {
        expect(found.value.length).toBeLessThanOrEqual(300);
        expect(found.value.includes("\u0000")).toBe(false);
        expect(found.value).toBe(found.value.trim());
      }
    }));
  });
});
