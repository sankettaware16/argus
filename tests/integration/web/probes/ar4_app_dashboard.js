() => {
  const tile = (name) => [...document.querySelectorAll("ul[aria-label='Key numbers'] li")].find((li) => li.querySelector('span').textContent.trim() === name);
  const table = [...document.querySelectorAll('table')].find((t) => t.querySelector('caption')?.textContent.trim() === 'Notified cases');
  const number = (li) => li?.querySelector('strong').textContent.trim() ?? null;
  return {
    tile: number(tile('Notified, still active')),
    sub: tile('Notified, still active')?.querySelectorAll('span')[1].textContent.trim() ?? null,
    attention: number(tile('Needs attention')),
    rows: table ? [...table.querySelectorAll('tbody tr')].map((tr) => [...tr.children].map((c) => c.textContent.trim())) : [],
  };
}
