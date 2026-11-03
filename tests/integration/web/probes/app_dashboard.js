() => {
  const rows = (table) => [...table.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((c) => c.textContent.trim()));
  const table = (name) => [...document.querySelectorAll('table')].find((t) => t.querySelector('caption')?.textContent.trim() === name) ?? null;
  const breakdown = (name) => { const t = table(name); return t ? rows(t).map((r) => [r[0], r[1]]) : []; };
  const cases = (name) => { const t = table(name); return t ? [...t.querySelectorAll('tbody tr')].map((tr) => [tr.children[0].querySelector('a').textContent.trim(), tr.children[3].textContent.trim(), tr.children[4].textContent.trim(), tr.children[5].textContent.trim()]) : []; };
  const kpis = Object.fromEntries([...document.querySelectorAll('ul[aria-label="Key numbers"] li')].map((li) => [li.querySelector('span').textContent.trim(), li.querySelector('strong').textContent.trim()]));
  const entity = (name) => { const t = table(name); return t ? rows(t) : []; };
  return {
    kpis,
    states: breakdown('Investigations by state'), severities: breakdown('Investigations by severity'),
    verdicts: breakdown("Person's verdict"), ai: breakdown("ARGUS's assessment"),
    rules: (table('Top rules by alerts') ? rows(table('Top rules by alerts')).map((r) => r.slice(0, 7)) : []),
    ip: entity('Top IP addresses'), host: entity('Top hosts'), domain: entity('Top domains'), user: entity('Top users'),
    incidents: cases('Incidents'), open: cases('Open investigations'),
  };
}
