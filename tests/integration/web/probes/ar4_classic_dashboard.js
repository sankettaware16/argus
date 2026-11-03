() => {
  const tile = (name) => [...document.querySelectorAll('ul.kpis li')].find((li) => li.querySelector('.kpi-label')?.textContent.trim() === name);
  const card = [...document.querySelectorAll('section.panel-card')].find((c) => c.querySelector('h2')?.textContent.trim() === 'Notified, still active');
  const number = (li) => li?.querySelector('strong').textContent.trim() ?? null;
  return {
    tile: number(tile('Notified, still active')),
    sub: tile('Notified, still active')?.querySelector('.kpi-sub').textContent.trim() ?? null,
    attention: number(tile('Needs attention')),
    rows: card ? [...card.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((c) => c.textContent.trim())) : [],
  };
}
