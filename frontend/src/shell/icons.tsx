/** The menu's glyphs: plain line drawings in the text's colour, decoration only. One for every
 * entry, so the labels line up. */
const CIRCLE = "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z";
const PATHS: Record<string, string[]> = {
  // a sun: the day's work
  Today: ["M12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z", "M12 2.5v2M12 19.5v2M2.5 12h2M19.5 12h2M5.3 5.3l1.4 1.4M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4"],
  // a shield
  Incidents: ["M12 3 4.5 6v5.5c0 4.4 3 8.3 7.5 9.5 4.5-1.200 7.5-5.100 7.500-9.500V6L12 3Z", "M12 8.500v4.500M12 16h.010"],
  // a bell
  Alerts: ["M6 10a6 6 0 0 1 12 0c0 4.5 1.5 6 2 6.500H4c.5-.5 2-2 2-6.500Z", "M10 19.500a2 2 0 0 0 4 0"],
  // four panels
  Dashboards: ["M4 4h7v9H4zM13 4h7v5h-7zM13 11h7v9h-7zM4 15h7v5H4z"],
  Search: ["M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z", "m20 20-4.050-4.050"],
  // a page with lines
  Reports: ["M7 3h7l5 5v11a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2Z", "M14 3v5h5M9 13h6M9 17h6"],
  // a tick in a circle
  Approvals: [CIRCLE, "m8.500 12.200 2.400 2.400 4.600-5"],
  // three sliders
  "Rule tuning": ["M4 7h8M16 7h4M4 12h3M11 12h9M4 17h10M18 17h2", "M14 5v4M9 10v4M16 15v4"],
  // a person and a lens
  "Account look-up": ["M10 4a3.500 3.500 0 1 0 0 7 3.500 3.500 0 0 0 0-7Z", "M3.500 19.500c.5-3.200 3-5.500 6.500-5.500.9 0 1.800.2 2.600.5", "M17 14.500a2.500 2.500 0 1 0 0 5 2.500 2.500 0 0 0 0-5Z", "m19 19 2 2"],
  // a target
  "ARGUS quality": [CIRCLE, "M12 7.500a4.500 4.500 0 1 0 0 9 4.500 4.500 0 0 0 0-9Z", "M12 12h.010"],
  // a pulse
  "System health": ["M3 12h4l2.500-6.500 4.500 13 2.500-6.500H21"],
  // a cog
  Settings: [
    "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z",
    "M19.400 13.500a7.600 7.600 0 0 0 0-3l1.800-1.400-1.800-3.100-2.100.800a7.600 7.600 0 0 0-2.600-1.500L14.300 3h-3.600l-.400 2.300a7.600 7.600 0 0 0-2.600 1.500l-2.100-.800-1.800 3.100 1.800 1.400a7.600 7.600 0 0 0 0 3l-1.800 1.400 1.800 3.100 2.100-.800a7.600 7.600 0 0 0 2.600 1.500l.400 2.300h3.600l.400-2.300a7.600 7.600 0 0 0 2.600-1.500l2.100.800 1.800-3.100-1.800-1.400Z",
  ],
  // two people
  "Users and roles": ["M9 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z", "M3 19.500c.500-3.200 2.900-5.500 6-5.500s5.500 2.300 6 5.500", "M16 5.500a2.700 2.700 0 0 1 0 5.200", "M17.500 14.400c1.900.700 3.200 2.500 3.500 5.100"],
  // two sparks
  "AI and agents": ["M11 4l1.900 4.900 4.900 1.900-4.900 1.900L11 17.600l-1.900-4.900-4.900-1.900 4.900-1.900L11 4Z", "M18.500 15l.800 2 2 .800-2 .800-.800 2-.800-2-2-.800 2-.800.800-2Z"],
  // a globe
  "Threat intel": [CIRCLE, "M3 12h18", "M12 3c2.500 2.500 3.800 5.500 3.800 9s-1.300 6.500-3.800 9c-2.500-2.500-3.800-5.500-3.800-9S9.500 5.500 12 3Z"],
  // layers
  Patterns: ["m12 4 8 4-8 4-8-4 8-4Z", "m4 12 8 4 8-4", "m4 16 8 4 8-4"],
  // a lamp
  Proposals: ["M12 3a6 6 0 0 0-3.500 10.900c.600.500 1 1.200 1 2V16h5v-.100c0-.800.400-1.500 1-2A6 6 0 0 0 12 3Z", "M9.500 18.500h5M10.500 21h3"],
  // a coin
  "Costs and usage": [CIRCLE, "M14.600 9.300c-.500-.800-1.400-1.300-2.600-1.300-1.500 0-2.600.800-2.600 2s1 1.700 2.600 2 2.600.800 2.600 2-1.100 2-2.600 2c-1.200 0-2.100-.500-2.600-1.300", "M12 6.500V8M12 16v1.500"],
  // two swatches
  "Design system": ["M4 4h9v9H4z", "M11 11h9v9h-9z"],
  // a question
  "Help & glossary": [CIRCLE, "M9.500 9.500a2.500 2.500 0 1 1 3.700 2.200c-.800.400-1.200 1-1.200 1.800", "M12 16.800h.010"],
  // three dots: the folded entries
  More: ["M6 12h.010M12 12h.010M18 12h.010"],
};

export function NavIcon({ name }: { name: string }) {
  const paths = PATHS[name];
  // an entry without a glyph keeps the glyph's room, so its label lines up with the others
  if (paths === undefined) return <span aria-hidden="true" className="size-5 shrink-0" />;
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="size-5 shrink-0" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {paths.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
}
