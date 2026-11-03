() => [...document.querySelectorAll('table.cards tbody tr')].map((tr) => ({
  name: tr.querySelector('a').textContent.trim(),
  alerts: tr.children[1].querySelector('span.sub') ? tr.children[1].childNodes[0].textContent.trim() : tr.children[1].textContent.trim(),
  severity: tr.children[3].textContent.trim(),
  state: tr.children[4].textContent.trim(),
}))
