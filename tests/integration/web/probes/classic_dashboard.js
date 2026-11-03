() => {
  const rows = (table) => [...table.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((c) => c.textContent.trim()));
  const cards = [...document.querySelectorAll('section.panel-card')];
  const by = (title) => cards.find((c) => c.querySelector('h2')?.textContent.trim() === title);
  const breakdown = (title) => [...by(title).querySelectorAll('ul.bars li:not(.empty)')].map((li) => [li.querySelector('a').textContent.trim(), li.querySelector('.num').textContent.trim()]);
  const cases = (title) => [...by(title).querySelectorAll('tbody tr')].map((tr) => [tr.children[0].querySelector('a').textContent.trim(), tr.children[3].textContent.trim(), tr.children[4].textContent.trim(), tr.children[5].textContent.trim()]);
  const kpis = Object.fromEntries([...document.querySelectorAll('ul.kpis li')].map((li) => [li.querySelector('.kpi-label').textContent.trim(), li.querySelector('strong').textContent.trim()]));
  const entity = (title) => { const t = by(title).querySelector('table'); return t ? rows(t) : []; };
  return {
    kpis,
    states: breakdown('Investigations by state'), severities: breakdown('Investigations by severity'),
    verdicts: breakdown("Person's verdict"), ai: breakdown("ARGUS's assessment"),
    rules: by('Top rules by alerts').querySelector('table') ? rows(by('Top rules by alerts').querySelector('table')).map((r) => r.slice(0, 7)) : [],
    ip: entity('Top IP addresses'), host: entity('Top hosts'), domain: entity('Top domains'), user: entity('Top users'),
    incidents: cases('Incidents: confirmed and suspected'), open: cases('Open investigations, most urgent first'),
  };
}
