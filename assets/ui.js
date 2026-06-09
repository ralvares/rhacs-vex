// Shared UI components for OCP Vulnerability Intelligence

export function esc(s) {
  if (s == null) return '';
  if (typeof s === 'object') s = s.label || s.value || '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

export function statusKey(raw) {
  const s = String(raw || '').toLowerCase();
  if (s.includes('false'))         return 'False Positive';
  if (s.includes('not assessed'))  return 'Not Assessed';
  if (s.includes('positive'))      return 'Positive';
  return raw || '';
}

export function statusBadge(raw) {
  const k = statusKey(raw);
  const cls = k === 'False Positive' ? 'bg-green'
            : k === 'Positive'       ? 'bg-red'
            : k === 'Not Assessed'   ? 'bg-yellow'
            : 'bg-gray';
  return `<span class="badge ${cls}">${esc(k)}</span>`;
}

const sevColors = {
  critical:  'bg-red',
  important: 'bg-orange',
  moderate:  'bg-yellow',
  low:       'bg-gray',
  unknown:   'bg-gray',
};

export function severityBadge(sev) {
  const s = String(sev || '').toLowerCase();
  const cls = sevColors[s] || 'bg-gray';
  return `<span class="badge ${cls}">${esc(sev || 'Unknown')}</span>`;
}

export function severityCompare(vexSev, rhacsSev, isMismatch) {
  let html = severityBadge(vexSev);
  if (isMismatch && rhacsSev) {
    html += `<span class="sev-arrow">→</span>${severityBadge(rhacsSev)}`;
    html += `<span class="mismatch-warn">⚠</span>`;
  }
  return `<span class="sev-cmp">${html}</span>`;
}

export function csvCell(v) {
  const s = String(v ?? '');
  return (s.includes(',') || s.includes('"') || s.includes('\n'))
    ? '"' + s.replace(/"/g, '""') + '"'
    : s;
}

export function downloadCSV(rows, columns, filename) {
  const header = columns.map(([h]) => csvCell(h)).join(',');
  const body = rows.map(r => columns.map(([, fn]) => csvCell(fn(r))).join(',')).join('\n');
  const blob = new Blob([header + '\n' + body], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

export function createDropdown(id, label, options, onChanged) {
  const items = options.map(o => typeof o === 'object' ? o : { value: o, label: o });
  const html = `
    <div class="ms-wrap" data-filter="${id}">
      <button class="ms-btn" type="button">
        <span>${esc(label)}</span>
        <span class="ms-badge" style="display:none"></span>
        <span class="ms-caret">▾</span>
      </button>
      <div class="ms-panel">
        <input class="ms-search" type="text" placeholder="Filter…">
        <div class="ms-list">
          ${items.map(o => `
            <label class="ms-item">
              <input type="checkbox" value="${esc(o.value)}">
              <span>${esc(o.label)}</span>
            </label>
          `).join('')}
        </div>
      </div>
    </div>`;

  const container = document.createElement('div');
  container.innerHTML = html;
  const wrap = container.firstElementChild;

  const btn   = wrap.querySelector('.ms-btn');
  const panel = wrap.querySelector('.ms-panel');
  const badge = wrap.querySelector('.ms-badge');
  const search = wrap.querySelector('.ms-search');
  const itemEls = wrap.querySelectorAll('.ms-item');

  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    document.querySelectorAll('.ms-panel.open').forEach(p => { if (p !== panel) p.classList.remove('open'); });
    panel.classList.toggle('open');
    if (panel.classList.contains('open')) search.focus();
  });

  search.addEventListener('input', () => {
    const q = search.value.toLowerCase();
    itemEls.forEach(item => {
      const text = item.querySelector('span').textContent.toLowerCase();
      item.style.display = text.includes(q) ? '' : 'none';
    });
  });

  wrap.addEventListener('change', () => {
    const checked = [...wrap.querySelectorAll('input[type=checkbox]:checked')].map(cb => cb.value);
    badge.textContent = checked.length;
    badge.style.display = checked.length ? '' : 'none';
    btn.classList.toggle('active', checked.length > 0);
    onChanged?.(id, new Set(checked));
  });

  document.addEventListener('click', (e) => {
    if (!wrap.contains(e.target)) panel.classList.remove('open');
  });

  const result = {
    el: wrap,
    updateVisible(validValues) {
      itemEls.forEach(item => {
        const cb = item.querySelector('input[type=checkbox]');
        if (cb.checked) return;
        item.style.display = validValues.has(cb.value) ? '' : 'none';
      });
    }
  };
  return result;
}

export function renderExpandRow(r, i, resolvedLabel) {
  const imgBase = (r.image || r.IMAGE || '').replace(/@sha256:[0-9a-f]+$/, '');
  const sha     = ((r.image || r.IMAGE || '').match(/(@sha256:[0-9a-f]+)$/) || [])[1] || '';
  const source   = r.source || r.SOURCE || '';
  const location = r.location || r.LOCATION || '';
  const justification = r.justification || r.JUSTIFICATION || '';

  return `
    <div class="detail-item">
      <span class="detail-label">Image</span>
      <div class="detail-value">
        <code class="detail-image">${esc(imgBase)}</code>
        ${sha ? `<code class="detail-sha">${esc(sha)}</code>` : ''}
      </div>
    </div>
    ${source || location ? `<div class="detail-item" style="display:flex;gap:2rem;flex-wrap:wrap">
      ${source ? `<div><span class="detail-label">Source</span>
        <div class="detail-value"><code style="font-size:.72rem">${esc(source)}</code></div></div>` : ''}
      ${location ? `<div><span class="detail-label">Location</span>
        <div class="detail-value"><code style="font-size:.7rem;color:var(--muted)">${esc(location)}</code></div></div>` : ''}
    </div>` : ''}
    ${resolvedLabel ? `<div class="detail-item">
      <span class="detail-label">Resolved In</span>
      <div class="detail-value"><span style="font-size:.78rem;color:var(--accent);font-weight:600">${esc(resolvedLabel)}</span></div>
    </div>` : ''}
    <div class="detail-item">
      <span class="detail-label">Justification</span>
      <div class="detail-value"><span class="detail-just">${esc(justification)}</span></div>
    </div>`;
}

export function wireExpandButtons(container) {
  if (container._expandWired) return;
  container._expandWired = true;
  container.addEventListener('click', e => {
    const btn = e.target.closest('.expand-btn');
    if (!btn) return;
    const idx = btn.closest('tr.main-row')?.dataset?.idx;
    if (!idx) return;
    const detail = document.getElementById('detail-' + idx);
    if (!detail) return;
    const open = detail.hidden;
    detail.hidden = !open;
    btn.classList.toggle('expanded', open);
  });
}
