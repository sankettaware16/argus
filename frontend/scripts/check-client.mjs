// Fails when the committed client (src/client) is not what Hey API makes from the committed spec
// (docs/api/openapi-v1.json): regenerate with `npm run client`.
import { execFileSync } from "node:child_process";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";

function files(root) {
  const out = new Map();
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) walk(path);
      else out.set(relative(root, path), readFileSync(path, "utf8"));
    }
  };
  walk(root);
  return out;
}

const scratch = mkdtempSync(join(tmpdir(), "argus-client-"));
try {
  const config = join(scratch, "openapi-ts.config.mjs");
  const spec = join(process.cwd(), "..", "docs", "api", "openapi-v1.json");
  const out = join(scratch, "client");
  const body = `export default { input: ${JSON.stringify(spec)}, output: { path: ${JSON.stringify(out)}, postProcess: [] }, plugins: ["@hey-api/client-fetch", "@hey-api/typescript", "@hey-api/sdk"] };`;
  await import("node:fs").then((fs) => fs.writeFileSync(config, body));
  execFileSync(join("node_modules", ".bin", "openapi-ts"), ["--file", config], { stdio: "pipe" });
  const made = files(out);
  const committed = files(join("src", "client"));
  const problems = [];
  for (const [name, text] of made) {
    if (!committed.has(name)) problems.push(`missing: src/client/${name}`);
    else if (committed.get(name) !== text) problems.push(`differs: src/client/${name}`);
  }
  for (const name of committed.keys()) if (!made.has(name)) problems.push(`extra: src/client/${name}`);
  if (problems.length) {
    console.error(`The client is not the spec's (run npm run client):\n  ${problems.join("\n  ")}`);
    process.exit(1);
  }
  console.log(`client: current (${made.size} files from docs/api/openapi-v1.json)`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
