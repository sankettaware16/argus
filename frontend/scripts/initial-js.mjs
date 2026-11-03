// The initial JavaScript budget (Q-B1's gate: <= 300 KB): the scripts /app's index.html loads
// before anything is shown (its module entry and every modulepreload), measured as gzip (what a
// compressing server sends; ARGUS's web gzips /app's assets) and raw.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const BUILD = join("..", "src", "argus", "web", "spa");
export const LIMIT = 300 * 1024;

export function initialScripts(html) {
  const found = new Set();
  for (const m of html.matchAll(/<script\b[^>]*\bsrc="([^"]+)"/g)) found.add(m[1]);
  for (const m of html.matchAll(/<link\b[^>]*\brel="modulepreload"[^>]*\bhref="([^"]+)"/g)) found.add(m[1]);
  return [...found];
}

const html = readFileSync(join(BUILD, "index.html"), "utf8");
let raw = 0;
let gzip = 0;
for (const src of initialScripts(html)) {
  const body = readFileSync(join(BUILD, src.replace(/^\/app\//, "")));
  raw += body.length;
  gzip += gzipSync(body, { level: 9 }).length;
}
const kb = (n) => `${(n / 1024).toFixed(1)} KB`;
console.log(`initial JavaScript: ${kb(gzip)} gzip, ${kb(raw)} raw (limit ${kb(LIMIT)} gzip)`);
if (gzip > LIMIT) {
  console.error("over the initial JavaScript budget");
  process.exit(1);
}
