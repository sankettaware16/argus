() => [...document.querySelectorAll('[role=grid] [role=row]')].slice(1).map((row) => {
  const cell = (n) => row.querySelector(`[role=gridcell][aria-colindex="${n}"]`);
  const [first, second] = cell(1).children;
  return {
    title: first.firstChild.textContent.trim(),
    rule: second.textContent.trim(),
    alerts: cell(3).firstElementChild.textContent.trim(),
    severity: cell(2).querySelectorAll('span')[0].textContent.trim(),
    state: cell(2).querySelectorAll('span')[1].textContent.trim(),
  };
})
