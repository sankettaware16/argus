// The SPA at /app (Q-B1, plan §7.5). The build goes to src/argus/web/spa (committed, DQ25;
// Q-A2's argus.ops.frontend.BUILD_DIR), which FastAPI serves. No data: URIs (the CSP has no
// data:), no inline script or style, no modulepreload polyfill (every supported browser has it).
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig, type Plugin } from "vite";
import { buildId } from "./scripts/build-id.mjs";

const BUILD = buildId();

function buildMeta(): Plugin {
  return {
    name: "argus-build-id",
    transformIndexHtml: (html) => html.replace("%ARGUS_BUILD%", BUILD),
  };
}

export default defineConfig({
  base: "/app/",
  plugins: [react(), tailwindcss(), buildMeta()],
  define: { __ARGUS_BUILD__: JSON.stringify(BUILD) },
  build: {
    outDir: "../src/argus/web/spa",
    emptyOutDir: true,
    assetsDir: "assets",
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    target: "es2022",
    cssCodeSplit: true,
    reportCompressedSize: true,
  },
  server: { port: 5173, strictPort: true },
});
