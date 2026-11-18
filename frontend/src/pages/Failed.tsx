import { Button } from "../components/ui/button";

/** A part of the app that could not load or show (a route's error). */
export function Failed() {
  return (
    <div role="alert" className="flex flex-col gap-2">
      <h1 className="page-h">This page could not be shown</h1>
      <p className="m-0 max-w-prose">
        A part of ARGUS could not be loaded, usually because ARGUS was updated a moment ago. Reload the page; nothing you
        saved is lost. If it happens again, tell an ARGUS admin.
      </p>
      <p className="m-0 flex gap-2">
        <Button variant="primary" onClick={() => window.location.reload()}>
          Reload
        </Button>
      </p>
    </div>
  );
}
