// The build's id (Q-B1, the stale-build check): one hash of every file the build is made from,
// so a change to code, styles, the lockfile or the configuration gives a new id. Vite writes it
// into index.html (<meta name="argus-build">, which the server reads and sends back as the
// X-Argus-Build header) and into the code (__ARGUS_BUILD__); they differ only when the page in
// the browser is older than the server's build.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const INPUTS = ["src", "public", "index.html", "package-lock.json", "vite.config.ts", "tsconfig.json"];

function* files(root, path) {
  const full = join(root, path);
  let stat;
  try {
    stat = statSync(full);
  } catch {
    return;
  }
  if (stat.isDirectory()) {
    for (const name of readdirSync(full).sort()) yield* files(root, join(path, name));
  } else if (stat.isFile()) {
    yield path;
  }
}

export function buildId(root = process.cwd()) {
  const digest = createHash("sha256");
  for (const input of INPUTS) {
    for (const path of files(root, input)) {
      const name = relative(root, join(root, path)).split(sep).join("/");
      digest.update(name + "\0");
      digest.update(createHash("sha256").update(readFileSync(join(root, path))).digest());
    }
  }
  return digest.digest("hex").slice(0, 16);
}
