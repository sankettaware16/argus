import "./styles.css";
import { CSPProvider } from "@base-ui/react/csp-provider";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { configure } from "./lib/api";
import { AnnounceProvider } from "./lib/announce";
import { onPreloadError } from "./lib/build";
import { makeQueryClient } from "./lib/session";
import { router } from "./router";

configure();
window.addEventListener("vite:preloadError", (event) => onPreloadError(event));
const queries = makeQueryClient();
const element = document.getElementById("root");
if (element) {
  createRoot(element).render(
    <StrictMode>
      <CSPProvider disableStyleElements>
        <QueryClientProvider client={queries}>
          <AnnounceProvider>
            <RouterProvider router={router} />
          </AnnounceProvider>
        </QueryClientProvider>
      </CSPProvider>
    </StrictMode>,
  );
}
