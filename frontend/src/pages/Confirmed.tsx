// Where the step-up tab lands (D-330): the password is confirmed on the server's page; the tab
// that asked for it goes on by itself, so this one only says so.
export function Confirmed() {
  return (
    <section className="setup flex min-h-screen flex-col items-center justify-center px-4 py-16 text-center" aria-labelledby="confirmed-title">
      <div className="setup-chapter flex max-w-2xl flex-col items-center gap-5">
        <span className="setup-check" data-state="done" aria-hidden="true">
          ✓
        </span>
        <h1 id="confirmed-title" className="setup-h">
          Password confirmed.
        </h1>
        <p className="setup-sub">Go back to the tab you came from: it continues by itself. You can close this tab.</p>
      </div>
    </section>
  );
}
