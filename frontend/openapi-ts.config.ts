// The typed client (Q-B1, DQ25: Hey API), generated from Q-A1's committed spec. `npm run client`
// regenerates it; `npm run lint` fails when the committed client differs from the spec's.
import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
  input: "../docs/api/openapi-v1.json",
  output: { path: "src/client", postProcess: [] },
  plugins: ["@hey-api/client-fetch", "@hey-api/typescript", "@hey-api/sdk"],
});
