/* Client-side sorting for static tables.
 * A table opts in with class "tbl" and data-sortable; each header cell is
 * sortable. Cells may carry data-sort-value for exact comparison (numbers,
 * ISO dates, severity rank); otherwise the visible text is compared. Empty
 * values always sort last in both directions. */
(function () {
  const ARROWS = { asc: '▲', desc: '▼', none: '↕' };

  function cellValue(cell) {
    if (cell.hasAttribute('data-sort-value')) return cell.getAttribute('data-sort-value');
    return cell.textContent.trim();
  }

  function compare(a, b) {
    const aEmpty = a === '' || a === null, bEmpty = b === '' || b === null;
    if (aEmpty || bEmpty) return aEmpty === bEmpty ? 0 : (aEmpty ? 1 : -1);
    const an = Number(a), bn = Number(b);
    if (a !== '' && b !== '' && !Number.isNaN(an) && !Number.isNaN(bn)) return an - bn;
    return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
  }

  function sortTable(table, index, th) {
    const body = table.tBodies[0] || table;
    const rows = Array.from(body.rows).filter(r => r.querySelector('td'));
    const current = th.getAttribute('data-sort-dir') || 'none';
    const dir = current === 'asc' ? 'desc' : 'asc';
    const sign = dir === 'asc' ? 1 : -1;

    const keyed = rows.map(row => {
      const cell = row.cells[index];
      return { row, value: cell ? cellValue(cell) : '' };
    });
    keyed.sort((x, y) => {
      const a = x.value, b = y.value;
      const aEmpty = a === '', bEmpty = b === '';
      if (aEmpty || bEmpty) return aEmpty === bEmpty ? 0 : (aEmpty ? 1 : -1);
      return sign * compare(a, b);
    });
    keyed.forEach(item => body.appendChild(item.row));

    Array.from(table.querySelectorAll('th[data-sortable-col]')).forEach(h => {
      h.setAttribute('data-sort-dir', '');
      const icon = h.querySelector('.sort-icon');
      if (icon) icon.textContent = ARROWS.none;
      h.classList.remove('sorted');
    });
    th.setAttribute('data-sort-dir', dir);
    th.classList.add('sorted');
    const icon = th.querySelector('.sort-icon');
    if (icon) icon.textContent = ARROWS[dir];
  }

  function init(table) {
    const headers = Array.from(table.querySelectorAll('tr:first-child th'));
    headers.forEach((th, index) => {
      if (th.classList.contains('nosort') || th.hasAttribute('data-static-skip')) return;
      th.setAttribute('data-sortable-col', '');
      th.setAttribute('data-static-sort', '');
      th.classList.add('sortable');
      if (!th.querySelector('.sort-icon')) {
        const icon = document.createElement('span');
        icon.className = 'sort-icon';
        icon.setAttribute('aria-hidden', 'true');
        icon.textContent = ARROWS.none;
        th.appendChild(icon);
      }
      th.addEventListener('click', () => sortTable(table, index, th));
    });
  }

  document.querySelectorAll('table.tbl[data-sortable]').forEach(init);
})();
