() => {
  const grid = document.querySelector('[role=grid]');
  const selected = [...grid.querySelectorAll('[role=row][aria-selected=true]')];
  const active = document.activeElement;
  return {
    onGrid: active === grid,
    focus: { role: active.getAttribute('role'), id: active.id, tag: active.tagName, inPane: !!active.closest('#detail-pane'), inDialog: !!active.closest('[role=dialog], [role=alertdialog]') },
    descendant: grid.getAttribute('aria-activedescendant'),
    selected: selected.map((r) => ({ id: r.id, index: r.getAttribute('aria-rowindex'), name: r.querySelector('[role=gridcell]').firstElementChild.firstChild.textContent.trim(), rule: r.querySelector('[role=gridcell]').children[1].textContent.trim() })),
    rows: grid.getAttribute('aria-rowcount'), columns: grid.getAttribute('aria-colcount'), tabindex: grid.getAttribute('tabindex'),
    indexes: [...grid.querySelectorAll('[role=row]')].map((r) => r.getAttribute('aria-rowindex')),
    headers: [...grid.querySelectorAll('[role=columnheader]')].map((h) => h.textContent.trim()),
  };
}
