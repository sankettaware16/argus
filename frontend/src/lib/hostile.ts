/** Hostile values (Q-B1's gate: "hostile fixtures inert"): what an alert, a log line, a Kibana
 * comment or a model may hold. /app/design shows each through UntrustedText; the browser tests
 * check that none runs, links, styles or reorders anything. */
export interface Hostile {
  name: string;
  value: string;
}

export const HOSTILE: Hostile[] = [
  { name: "a script tag", value: '<script>window.__pwned = "script"</script>' },
  { name: "an image with onerror", value: '<img src=x onerror="window.__pwned = \'img\'">' },
  { name: "an SVG with onload", value: '<svg onload="window.__pwned=\'svg\'"><a href="javascript:alert(1)">x</a></svg>' },
  // eslint-disable-next-line no-restricted-syntax -- a hostile fixture, shown as text only
  { name: "a javascript: URL", value: "javascript:window.__pwned='url'" },
  { name: "a link-looking URL", value: "https://evil.example/login?next=<b>x</b>" },
  { name: "an inline style", value: '<span style="position:fixed;inset:0;background:red">cover</span>' },
  { name: "a right-to-left override in a file name", value: "invoice_\u202efdp.exe" },
  { name: "bidi isolates around a word", value: "admin\u2067 \u2066approved\u2069\u2069 the change" },
  { name: "right-to-left letters between two addresses", value: "from \u05d0 10.0.0.1 \u05d0 192.168.1.1" },
  { name: "characters drawn as nothing", value: "approved\u{E0080}\u{E00F2}\u{E00ED} pay\u2065\u{1D173}pal" },
  { name: "zero-width characters inside a domain", value: "pay\u200bpal\u200d.com" },
  { name: "hidden tag characters (ASCII smuggling)", value: "hello\u{E0069}\u{E0067}\u{E006E}\u{E006F}\u{E0072}\u{E0065} world" },
  { name: "terminal escapes and a NUL", value: "ok\u0000\u001b[31m red \u001b[0m\u0007" },
  { name: "a look-alike domain (Cyrillic \u0430)", value: "login at \u0430pple.com today" },
  { name: "a fullwidth domain", value: "\uff45\uff58\uff41\uff4d\uff50\uff4c\uff45\uff0ecom" },
  { name: "an internationalised name", value: "mail to b\u00fccher.example and \u0441\u0430\u0439\u0442.\u0440\u0444" },
  { name: "a byte order mark and a soft hyphen", value: "\ufeffinvis\u00adible" },
  { name: "broken UTF-16", value: "half \uD83D of an emoji" },
  { name: "combining marks", value: "Z\u0351\u036b\u0343\u036a\u0302\u036b\u033d\u034f\u0334\u0319\u0324\u031e\u0349a\u0310l\u0344g\u0350o" },
  { name: "a long value (capped)", value: `${"A".repeat(2400)}END` },
  { name: "many lines (capped)", value: Array.from({ length: 60 }, (_, i) => `line ${i + 1}`).join("\n") },
  { name: "a template expression", value: "{{constructor.constructor('window.__pwned=1')()}} ${7*7}" },
];
