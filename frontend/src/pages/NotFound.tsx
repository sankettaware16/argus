import { Link } from "@tanstack/react-router";

export function NotFound() {
  return (
    <>
      <h1 className="page-h">Page not found</h1>
      <p className="m-0">
        This page is not part of the app (yet). Check the address, or go <Link to="/">home</Link>.
      </p>
    </>
  );
}
