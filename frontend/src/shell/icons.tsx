/** The four daily pages' glyphs: plain line drawings in the text's colour, decoration only. */
const PATHS: Record<string, string[]> = {
  // a sun: the day's work
  Today: ["M12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z", "M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"],
  // a shield
  Incidents: ["M12 3 4.5 6v5.5c0 4.4 3 8.3 7.5 9.5 4.5-1.200 7.5-5.100 7.500-9.500V6L12 3Z", "M12 8.500v4.500M12 16h.010"],
  Search: ["M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z", "m20 20-4.050-4.050"],
  // a page with lines
  Reports: ["M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z", "M14 3v5h5M9 13h6M9 17h6"],
};

export function NavIcon({ name }: { name: string }) {
  const paths = PATHS[name];
  if (paths === undefined) return null;
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-5 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {paths.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}
