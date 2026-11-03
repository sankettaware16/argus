() => Object.fromEntries([...document.querySelectorAll('ul.summary li')].map((li) => [li.textContent.replace(/[0-9,]+/, '').trim().split(' (')[0], li.querySelector('strong')?.textContent.trim()]))
