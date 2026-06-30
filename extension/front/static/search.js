
// Static: disasm, symbols, strings, cfg
function requestDisasmOpen({ forceRebuild = false } = {}) {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  const syntax = document.getElementById('disasmSyntax')?.value || 'intel';
  const section = document.getElementById('disasmSection')?.value?.trim() || '';
  const binaryMeta = _selectedRawArchMeta();
  if (binaryMeta?.kind === 'raw') {
    currentBinaryMeta = binaryMeta;
    saveBinarySelection(bp, binaryMeta);
  }
  const useCache = !forceRebuild;
  try { window.POFHubTaskProgressController?.startTask({ type: 'hubOpenDisasm', binaryPath: bp }); } catch(e) {}
  vscode.postMessage({ type: 'hubOpenDisasm', binaryPath: bp, binaryMeta, syntax, section, useCache });
}

// Persist useCache checkbox across sessions
(function initUseCacheCheckbox() {
  const el = document.getElementById('useCache');
  if (!el) return;
  const stored = _loadStorage();
  if (typeof stored.useCache === 'boolean') el.checked = stored.useCache;
  el.addEventListener('change', () => _saveStorage({ useCache: el.checked }));
})();

document.getElementById('btnOpenDisasm')?.addEventListener('click', () => {
  requestDisasmOpen();
});

document.getElementById('btnRebuildDisasm')?.addEventListener('click', () => {
  requestDisasmOpen({ forceRebuild: true });
});

document.getElementById('btnGoToMain')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: 'main' });
});

document.getElementById('btnGoToStart')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: '_start' });
});

document.getElementById('btnGoToEntry')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: '__entry__' });
});

document.getElementById('btnGoToSymbol')?.addEventListener('click', () => {
  const bp = getStaticBinaryPath();
  const sym = document.getElementById('navSymbolSelect')?.value?.trim();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez un chemin binaire.' });
    return;
  }
  if (!sym) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un symbole.' });
    return;
  }
  vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: sym });
});

function applyStringsFilter() {
  const container = document.getElementById('stringsContent');
  if (!container || stringsCache.length === 0) return;
  renderStringsTable(container, stringsCache, '', false);
}

function reloadStrings() {
  const bp = getStaticBinaryPath();
  if (!bp) return;
  setStaticLoading('stringsContent', 'Chargement des strings…');
  const enc = document.getElementById('stringsEncoding')?.value || 'auto';
  const sec = document.getElementById('stringsSection')?.value || '';
  const minLen = parseInt(document.getElementById('stringsMinLen')?.value || '4', 10);
  vscode.postMessage({ type: 'hubLoadStrings', binaryPath: bp, minLen, encoding: enc, section: sec || undefined });
}
document.getElementById('stringsEncoding')?.addEventListener('change', reloadStrings);
document.getElementById('stringsSection')?.addEventListener('change', reloadStrings);
document.getElementById('stringsMinLen')?.addEventListener('change', reloadStrings);
// ── Recherche : mode pills (A) ───────────────────────────────────────────────
let searchMode = 'text';
const modePills = document.querySelectorAll('.search-mode-pill');
modePills.forEach(pill => {
  pill.addEventListener('click', () => {
    modePills.forEach(p => p.classList.remove('active'));
    pill.classList.add('active');
    searchMode = pill.dataset.mode;
  });
});

// ── Recherche : history localStorage (B) ─────────────────────────────────────
const HISTORY_KEY = 'pof-search-history';
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]'); } catch { return []; }
}
function saveHistory(entries) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries));
}
function addToHistory(pattern, mode) {
  if (!pattern) return;
  let h = loadHistory().filter(e => !(e.pattern === pattern && e.mode === mode));
  h.unshift({ pattern, mode, ts: Date.now() });
  if (h.length > 10) h = h.slice(0, 10);
  saveHistory(h);
}

const historyDropdown = document.getElementById('searchHistoryDropdown');
function renderHistoryDropdown() {
  const h = loadHistory();
  if (!historyDropdown) return;
  if (!h.length) { historyDropdown.hidden = true; return; }
  historyDropdown.innerHTML = '';
  h.forEach((entry, i) => {
    const item = document.createElement('div');
    item.className = 'search-history-item';
    const label = document.createElement('span');
    label.textContent = `[${entry.mode}] ${entry.pattern}`;
    label.style.cursor = 'pointer';
    label.addEventListener('click', () => {
      const inp = document.getElementById('searchBinaryPattern');
      if (inp) inp.value = entry.pattern;
      if (entry.mode) {
        modePills.forEach(p => {
          p.classList.toggle('active', p.dataset.mode === entry.mode);
        });
        searchMode = entry.mode;
      }
      historyDropdown.hidden = true;
    });
    const del = document.createElement('button');
    del.className = 'search-history-item-delete';
    del.textContent = '×';
    del.title = 'Supprimer';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      let h2 = loadHistory();
      h2.splice(i, 1);
      saveHistory(h2);
      renderHistoryDropdown();
    });
    item.appendChild(label);
    item.appendChild(del);
    historyDropdown.appendChild(item);
  });
  historyDropdown.hidden = false;
}
document.getElementById('searchBinaryPattern')?.addEventListener('focus', renderHistoryDropdown);
document.addEventListener('click', (e) => {
  if (!historyDropdown) return;
  if (!historyDropdown.contains(e.target) && e.target !== document.getElementById('searchBinaryPattern')) {
    historyDropdown.hidden = true;
  }
});

// ── Recherche : filters toggle (C) ───────────────────────────────────────────
const filtersToggle = document.getElementById('searchFiltersToggle');
const filtersPanel = document.getElementById('searchFiltersPanel');
if (filtersToggle && filtersPanel) {
  filtersToggle.addEventListener('click', () => {
    const hidden = filtersPanel.hidden;
    filtersPanel.hidden = !hidden;
    filtersToggle.textContent = hidden ? '▴ Filtres avancés' : '▾ Filtres avancés';
  });
}

// ── Recherche : execution (D) ─────────────────────────────────────────────────
function doSearch() {
  const pattern = document.getElementById('searchBinaryPattern')?.value?.trim();
  if (!pattern) return;
  addToHistory(pattern, searchMode);
  if (historyDropdown) historyDropdown.hidden = true;

  const caseSensitive = document.getElementById('searchCaseSensitive')?.checked || false;
  const minLengthVal = document.getElementById('searchMinLength')?.value || '';
  const maxLengthVal = document.getElementById('searchMaxLength')?.value || '';
  const offsetStartVal = (document.getElementById('searchOffsetStart')?.value || '').trim();
  const offsetEndVal = (document.getElementById('searchOffsetEnd')?.value || '').trim();

  const msg = {
    type: 'hubSearchBinary',
    pattern,
    mode: searchMode,
    caseSensitive,
    binaryPath: getStaticBinaryPath(),
    binaryMeta: getCurrentBinaryMeta(),
  };
  if (minLengthVal) msg.minLength = parseInt(minLengthVal, 10);
  if (maxLengthVal) msg.maxLength = parseInt(maxLengthVal, 10);
  if (offsetStartVal) msg.offsetStart = parseInt(offsetStartVal, 0);
  if (offsetEndVal) msg.offsetEnd = parseInt(offsetEndVal, 0);

  vscode.postMessage(msg);
}

function setSearchMode(mode) {
  const normalized = String(mode || 'text').trim().toLowerCase();
  const nextMode = ['text', 'hex', 'regex'].includes(normalized) ? normalized : 'text';
  modePills.forEach((pill) => {
    pill.classList.toggle('active', pill.dataset.mode === nextMode);
  });
  searchMode = nextMode;
}

function openSearchWithPattern(pattern, mode = 'text') {
  const query = String(pattern || '').trim();
  if (!query) return;
  const input = document.getElementById('searchBinaryPattern');
  if (!input) return;
  input.value = query;
  setSearchMode(mode);
  showPanel('static');
  showGroup('data', 'recherche');
  requestAnimationFrame(() => {
    requestAnimationFrame(() => doSearch());
  });
}

function _clipSearchSeed(value, maxLen = 96) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
  if (!text) return '';
  return text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;
}

function getPeResourceTextSearchSeed(resource) {
  const decoded = resource?.decoded;
  if (!decoded || typeof decoded !== 'object') return '';
  if (Array.isArray(decoded.strings)) {
    const firstString = decoded.strings.map((entry) => _clipSearchSeed(entry, 80)).find(Boolean);
    if (firstString) return firstString;
  }
  if (decoded.xml) return _clipSearchSeed(String(decoded.xml).replace(/<[^>]+>/g, ' '), 120);
  if (decoded.file_version) return _clipSearchSeed(decoded.file_version, 64);
  if (decoded.product_version) return _clipSearchSeed(decoded.product_version, 64);
  if (decoded.hex) return '';
  return _clipSearchSeed(JSON.stringify(decoded), 120);
}

function getPeResourceHexSearchSeed(resource, maxBytes = 12) {
  const hex = String(resource?.hex_preview || '').trim();
  if (!hex) return '';
  return hex.split(/\s+/).filter(Boolean).slice(0, maxBytes).join(' ');
}

function renderPeResourceDetail(resource, detail) {
  if (!detail || !resource) return;
  const decoded = resource.decoded || null;
  const searchTextSeed = getPeResourceTextSearchSeed(resource);
  const searchHexSeed = getPeResourceHexSearchSeed(resource);
  const decodedBlocks = [];
  if (Array.isArray(decoded?.strings) && decoded.strings.length) {
    decodedBlocks.push(`
      <div class="resource-detail-block">
        <div class="resource-detail-title">Chaînes décodées</div>
        <ul class="resource-detail-list">
          ${decoded.strings.slice(0, 8).map((entry) => `<li>${escapeHtml(String(entry || ''))}</li>`).join('')}
        </ul>
      </div>
    `);
  }
  if (decoded?.xml) {
    decodedBlocks.push(`
      <div class="resource-detail-block">
        <div class="resource-detail-title">Manifest / XML</div>
        <pre class="resource-detail-pre">${escapeHtml(String(decoded.xml || ''))}</pre>
      </div>
    `);
  }
  if (decoded && typeof decoded === 'object' && !Array.isArray(decoded) && !decoded.xml && !decoded.strings) {
    decodedBlocks.push(`
      <div class="resource-detail-block">
        <div class="resource-detail-title">Décodage</div>
        <pre class="resource-detail-pre">${escapeHtml(JSON.stringify(decoded, null, 2))}</pre>
      </div>
    `);
  }
  detail.innerHTML = `
    <div class="resource-detail-head">
      <div>
        <div class="resource-detail-type">${escapeHtml(resource.type || 'Ressource')}</div>
        <div class="resource-detail-meta">
          <span class="resource-detail-chip">ID ${escapeHtml(resource.id || '—')}</span>
          <span class="resource-detail-chip">Lang ${escapeHtml(resource.lang || '—')}</span>
          <span class="resource-detail-chip">${escapeHtml(String(resource.size || 0))} o</span>
        </div>
      </div>
      <div class="resource-detail-actions">
        <button type="button" class="btn btn-xs btn-secondary" data-resource-action="search-text"${searchTextSeed ? '' : ' disabled'}>Recherche texte</button>
        <button type="button" class="btn btn-xs btn-secondary" data-resource-action="search-hex"${searchHexSeed ? '' : ' disabled'}>Recherche hex</button>
      </div>
    </div>
    ${decodedBlocks.join('')}
    <div class="resource-detail-block">
      <div class="resource-detail-title">Aperçu hex</div>
      <pre class="resource-detail-pre">${escapeHtml(resource.hex_preview || '—')}</pre>
    </div>
  `.trim();
  detail.style.display = '';
  detail.querySelector('[data-resource-action="search-text"]')?.addEventListener('click', () => {
    if (searchTextSeed) openSearchWithPattern(searchTextSeed, 'text');
  });
  detail.querySelector('[data-resource-action="search-hex"]')?.addEventListener('click', () => {
    if (searchHexSeed) openSearchWithPattern(searchHexSeed, 'hex');
  });
}

function renderExceptionHandlersTable(container, entries, filterStr = '') {
  if (!container) return;
  const badgeClass = (t) =>
    t === 'SEH' ? 'exc-badge-seh' : (t && t.includes('C++')) ? 'exc-badge-cpp' : 'exc-badge-dwarf';
  const filter = String(filterStr || '').trim().toLowerCase();
  const visible = filter
    ? entries.filter((entry) => {
      const haystack = [
        entry.func_start,
        entry.func_end,
        entry.handler,
        entry.handler_type,
        entry.note,
        ...(Array.isArray(entry.unwind_flags) ? entry.unwind_flags : []),
      ].filter(Boolean).join(' ').toLowerCase();
      return haystack.includes(filter);
    })
    : entries;
  const summaryByType = visible.reduce((acc, entry) => {
    const key = String(entry.handler_type || 'Autre');
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const summaryHtml = Object.entries(summaryByType)
    .map(([type, count]) => `<span class="resource-detail-chip">${escapeHtml(type)} · ${escapeHtml(String(count))}</span>`)
    .join('');
  const summaryNotes = [...new Set(visible.map((entry) => String(entry.note || '').trim()).filter(Boolean))];
  const rows = visible.map((entry, index) => {
    const flags = Array.isArray(entry.unwind_flags) ? entry.unwind_flags : [];
    const note = String(entry.note || '').trim();
    const funcAddr = escapeHtml(entry.func_start || '');
    const handlerAddr = escapeHtml(entry.handler || '');
    const rowActions = [
      entry.func_start ? `<button type="button" class="btn btn-xs btn-secondary" data-exc-open="disasm" data-exc-addr="${funcAddr}">Fonction</button>` : '',
      entry.func_start ? `<button type="button" class="btn btn-xs btn-secondary" data-exc-open="cfg" data-exc-addr="${funcAddr}">CFG</button>` : '',
      entry.func_start ? `<button type="button" class="btn btn-xs btn-secondary" data-exc-open="decompile" data-exc-addr="${funcAddr}">Pseudo-C</button>` : '',
      entry.handler ? `<button type="button" class="btn btn-xs btn-secondary" data-exc-open="handler" data-exc-addr="${handlerAddr}">Handler</button>` : '',
    ].filter(Boolean).join('');
    return `
      <tr>
        <td>${escapeHtml(String(index + 1))}</td>
        <td>${entry.func_start ? `<code class="addr-link" data-exc-open="disasm" data-exc-addr="${funcAddr}">${funcAddr}</code>` : '—'}</td>
        <td>${entry.func_end ? `<code>${escapeHtml(entry.func_end)}</code>` : '—'}</td>
        <td><span class="exc-badge ${badgeClass(entry.handler_type)}">${escapeHtml(entry.handler_type || '—')}</span></td>
        <td>${entry.handler ? `<code class="addr-link" data-exc-open="handler" data-exc-addr="${handlerAddr}">${handlerAddr}</code>` : '—'}</td>
        <td>${[
          flags.length ? `<span class="resource-detail-chip">${escapeHtml(flags.join(' · '))}</span>` : '',
          note ? `<div class="exception-note">${escapeHtml(note)}</div>` : '',
        ].filter(Boolean).join('') || '—'}</td>
        <td><div class="exception-actions">${rowActions || '<span class="resource-detail-chip">Global</span>'}</div></td>
      </tr>
    `;
  }).join('');
  container.innerHTML = `
    <div class="exception-summary">
      <div class="exception-summary-copy">
        <strong>${escapeHtml(String(visible.length))}</strong>
        <span>entrée(s) visibles</span>
      </div>
      <div class="exception-summary-tags">${summaryHtml || '<span class="resource-detail-chip">Aucun type</span>'}</div>
    </div>
    ${summaryNotes.length ? `<div class="exception-note-banner">${summaryNotes.map((note) => escapeHtml(note)).join(' ')}</div>` : ''}
    <table class="data-table">
      <thead>
        <tr>
          <th>#</th><th>Fonction</th><th>Fin</th><th>Type</th><th>Handler</th><th>Flags</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `.trim();
  container.querySelectorAll('[data-exc-open][data-exc-addr]').forEach((el) => {
    el.style.cursor = 'pointer';
    el.addEventListener('click', (event) => {
      event.preventDefault();
      const addr = el.dataset.excAddr || '';
      const action = el.dataset.excOpen || 'disasm';
      const binaryPath = getStaticBinaryPath();
      if (!addr || !binaryPath) return;
      if (action === 'cfg') {
        jumpToAddrInContextTab('cfg', addr, binaryPath, { historySource: 'Exceptions', historyTab: 'cfg' });
      } else if (action === 'decompile') {
        jumpToAddrInContextTab('decompile', addr, binaryPath, { historySource: 'Exceptions', historyTab: 'decompile' });
      } else {
        jumpToAddrInContextTab('disasm', addr, binaryPath, { historySource: 'Exceptions', historyTab: 'disasm' });
      }
    });
  });
}

document.getElementById('btnSearchBinary')?.addEventListener('click', doSearch);
document.getElementById('searchBinaryPattern')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); doSearch(); }
});

// ── Recherche : export CSV/JSON (F) ──────────────────────────────────────────
document.getElementById('btnSearchExportCsv')?.addEventListener('click', () => {
  const rows = window._searchResults || [];
  const header = 'Offset,Valeur,Taille,Contexte\n';
  const body = rows.map(r => `${r.offset_hex},${JSON.stringify(String(r.value))},${r.length},${JSON.stringify(String(r.context))}`).join('\n');
  const blob = new Blob([header + body], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'search-results.csv'; a.click();
  URL.revokeObjectURL(url);
});
document.getElementById('btnSearchExportJson')?.addEventListener('click', () => {
  const rows = window._searchResults || [];
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'search-results.json'; a.click();
  URL.revokeObjectURL(url);
});

function _renderRulesList(containerId, rules) {
  const container = document.getElementById(containerId);
  if (!container) return;
  while (container.firstChild) container.removeChild(container.firstChild);

  if (!rules.length) {
    const hint = document.createElement('p');
    hint.className = 'hint-sm rules-empty-hint';
    hint.textContent = 'Aucune règle — ajoutez-en une au projet ou au niveau global.';
    container.appendChild(hint);
    return;
  }

  rules.forEach(function(rule) {
    const row = document.createElement('div');
    row.className = 'rule-item';
    row.dataset.ruleId = rule.id;

    const main = document.createElement('div');
    main.className = 'rule-item-main';

    const labelEl = document.createElement('label');
    labelEl.style.cssText = 'display:flex;align-items:flex-start;gap:8px;cursor:pointer;flex:1;min-width:0';

    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.className = 'rule-toggle-cb';
    cb.dataset.ruleId = rule.id;
    cb.checked = rule.enabled;
    cb.addEventListener('change', function() {
      vscode.postMessage({ type: 'hubToggleRule', ruleId: rule.id, enabled: cb.checked });
    });

    const copy = document.createElement('div');
    copy.className = 'rule-item-copy';

    const nameSpan = document.createElement('span');
    nameSpan.className = 'rule-item-name';
    nameSpan.textContent = rule.name;

    const meta = document.createElement('div');
    meta.className = 'rule-item-meta';

    const scopeBadge = document.createElement('span');
    scopeBadge.className = `rule-meta-badge ${rule.scope === 'global' ? 'is-global' : 'is-project'}`;
    scopeBadge.textContent = rule.scope === 'global' ? 'global' : 'projet';
    meta.appendChild(scopeBadge);

    const typeBadge = document.createElement('span');
    typeBadge.className = `rule-meta-badge ${String(rule.type || '').toLowerCase() === 'yara' ? 'is-yara' : 'is-capa'}`;
    typeBadge.textContent = String(rule.type || '').toUpperCase();
    meta.appendChild(typeBadge);

    if (rule.path) {
      const pathEl = document.createElement('div');
      pathEl.className = 'rule-item-path';
      pathEl.textContent = rule.path;
      copy.appendChild(pathEl);
    }

    copy.insertBefore(nameSpan, copy.firstChild);
    copy.insertBefore(meta, copy.children[1] || null);

    labelEl.appendChild(cb);
    labelEl.appendChild(copy);
    main.appendChild(labelEl);

    const delBtn = document.createElement('button');
    const editBtn = document.createElement('button');
    editBtn.type = 'button';
    editBtn.className = 'btn-rule-edit';
    editBtn.title = 'Modifier';
    editBtn.textContent = '✎';
    editBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:2px 6px;opacity:0.7';
    editBtn.addEventListener('mouseenter', function() { editBtn.style.opacity = '1'; });
    editBtn.addEventListener('mouseleave', function() { editBtn.style.opacity = '0.7'; });
    editBtn.addEventListener('click', function() {
      vscode.postMessage({ type: 'hubGetRuleContent', ruleId: rule.id });
    });

    delBtn.type = 'button';
    delBtn.className = 'btn-rule-delete';
    delBtn.title = 'Supprimer';
    delBtn.textContent = '🗑';
    delBtn.style.cssText = 'background:none;border:none;cursor:pointer;padding:2px 6px;opacity:0.6';
    delBtn.addEventListener('mouseenter', function() { delBtn.style.opacity = '1'; });
    delBtn.addEventListener('mouseleave', function() { delBtn.style.opacity = '0.6'; });
    delBtn.addEventListener('click', function() {
      if (!confirm('Supprimer la règle ' + rule.name + ' ?')) return;
      vscode.postMessage({ type: 'hubDeleteUserRule', ruleId: rule.id });
    });

    const actions = document.createElement('div');
    actions.className = 'rule-item-actions';
    actions.appendChild(editBtn);
    actions.appendChild(delBtn);

    row.appendChild(main);
    row.appendChild(actions);
    container.appendChild(row);
  });
}

function getSelectedYaraMode() {
  const checked = document.querySelector('input[name="yaraRulesMode"]:checked');
  const mode = String(checked?.value || detectionUiState.yaraMode || 'library').trim().toLowerCase();
  return ['library', 'manual'].includes(mode) ? mode : 'library';
}

function setSelectedYaraMode(mode, options = {}) {
  const normalized = ['library', 'manual'].includes(mode) ? mode : 'library';
  detectionUiState.yaraMode = normalized;
  const input = document.querySelector(`input[name="yaraRulesMode"][value="${normalized}"]`);
  if (input) input.checked = true;
  if (!options.skipSave) {
    _saveStorage({ yaraRulesMode: normalized });
  }
  applyYaraModeUi();
}

function applyYaraModeUi() {
  const mode = getSelectedYaraMode();
  const manualWrap = document.getElementById('yaraManualPathWrap');
  const statusEl = document.getElementById('yaraSourceStatus');
  const managedSummaryEl = document.getElementById('yaraManagedSummary');
  const activeCount = Number(detectionUiState.activeYaraCount || 0);
  if (managedSummaryEl) {
    managedSummaryEl.textContent = activeCount
      ? `${activeCount} règle(s) YARA activée(s) seront regroupées automatiquement pour le prochain scan.`
      : 'La bibliothèque active regroupe les règles projet et globales cochées dans cette interface.';
  }
  if (manualWrap) {
    manualWrap.style.display = mode === 'manual' ? '' : 'none';
  }
  if (statusEl) {
    let label = 'À configurer';
    let variant = 'warn';
    if (mode === 'library') {
      label = activeCount ? `${activeCount} règle(s) actives` : 'Aucune règle active';
      variant = activeCount ? 'ready' : 'warn';
    } else if (mode === 'manual') {
      const manualPath = String(document.getElementById('yaraRulesPath')?.value || '').trim();
      label = manualPath ? 'Chemin prêt' : 'Chemin à choisir';
      variant = manualPath ? 'ready' : 'warn';
    }
    statusEl.textContent = label;
    statusEl.className = `soft-badge ${variant}`;
  }
}

function updateDetectionSummaries() {
  const capaEl = document.getElementById('capaSummaryCount');
  const yaraEl = document.getElementById('yaraSummaryCount');
  if (capaEl) {
    capaEl.textContent = detectionUiState.capaError
      ? 'Erreur'
      : String(detectionUiState.capaCapabilities.length || 0);
  }
  if (yaraEl) {
    const hitCount = detectionUiState.yaraMatches.reduce((acc, rule) => acc + (rule.matches || []).length, 0);
    yaraEl.textContent = detectionUiState.yaraError ? 'Erreur' : String(hitCount || 0);
  }
}

function getCapaUnsupportedReason() {
  const meta = getCurrentBinaryMeta();
  const format = String(meta?.format || '').trim().toUpperCase();
  if (!format) return '';
  if (format.includes('MACH')) {
    return 'CAPA analyse les exécutables PE et ELF. Le binaire actif est un Mach-O macOS, donc lance plutôt YARA ici ou charge un binaire Linux/Windows pour CAPA.';
  }
  if (format === 'RAW') {
    return "CAPA a besoin d'un exécutable PE ou ELF complet. Les blobs bruts restent analysables avec YARA, Hex, Strings et Désassemblage.";
  }
  return '';
}

function renderCapaUnsupported(reason = getCapaUnsupportedReason()) {
  detectionUiState.capaCapabilities = [];
  detectionUiState.capaError = '';
  updateDetectionSummaries();
  const container = document.getElementById('capaContent');
  if (container) {
    container.innerHTML = detectionEmptyHtml('CAPA non disponible pour ce format', reason);
  }
}

function detectionEmptyHtml(title, desc) {
  return `<div class="detection-empty"><strong>${escapeHtml(title)}</strong><span>${escapeHtml(desc)}</span></div>`;
}

function renderCapaResults() {
  const container = document.getElementById('capaContent');
  if (!container) return;
  updateDetectionSummaries();
  if (detectionUiState.capaError) {
    container.innerHTML = detectionEmptyHtml('Erreur CAPA', detectionUiState.capaError);
    return;
  }
  const allCaps = detectionUiState.capaCapabilities || [];
  const query = String(document.getElementById('capaFilterInput')?.value || '').trim().toLowerCase();
  const namespaceSelect = document.getElementById('capaNamespaceFilter');
  const requestedNamespace = String(namespaceSelect?.value || '').trim();
  if (namespaceSelect) {
    const namespaces = Array.from(new Set(allCaps.map((cap) => String(cap.namespace || '').trim()).filter(Boolean))).sort();
    namespaceSelect.replaceChildren(new Option('Tous les namespaces', ''));
    namespaces.forEach((ns) => namespaceSelect.appendChild(new Option(ns, ns)));
    namespaceSelect.value = namespaces.includes(requestedNamespace) ? requestedNamespace : '';
  }
  const namespace = String(namespaceSelect?.value || '').trim();
  const caps = allCaps.filter((cap) => {
    const haystack = `${cap.name || ''} ${cap.namespace || ''} ${cap.matches || ''}`.toLowerCase();
    if (namespace && String(cap.namespace || '') !== namespace) return false;
    return !query || haystack.includes(query);
  });
  if (!allCaps.length) {
    container.innerHTML = detectionEmptyHtml('Aucune capacité détectée', 'Le scan CAPA est terminé sans match exploitable.');
    return;
  }
  if (!caps.length) {
    container.innerHTML = detectionEmptyHtml('Aucun résultat filtré', 'Change le filtre ou le namespace pour revoir les capacités.');
    return;
  }
  const rows = caps.map(c => `<tr><td><code>${escapeHtml(c.name || '')}</code></td><td>${escapeHtml(c.namespace || '')}</td><td>${escapeHtml((c.matches || '').substring(0, 90))}</td></tr>`).join('');
  container.innerHTML = `<div class="detection-results-header"><span class="detection-results-count">${caps.length} / ${allCaps.length} capacité(s)</span></div><table class="data-table"><thead><tr><th>Capacité</th><th>Namespace</th><th>Match</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderYaraResults() {
  const container = document.getElementById('yaraContent');
  if (!container) return;
  updateDetectionSummaries();
  if (detectionUiState.yaraError) {
    container.innerHTML = detectionEmptyHtml('Erreur YARA', detectionUiState.yaraError);
    return;
  }
  const allMatches = detectionUiState.yaraMatches || [];
  const query = String(document.getElementById('yaraFilterInput')?.value || '').trim().toLowerCase();
  const filteredRules = allMatches
    .map((rule) => ({
      ...rule,
      matches: (rule.matches || []).filter((match) => {
        const haystack = `${rule.rule || ''} ${match.offset_hex || ''} ${match.matched || ''}`.toLowerCase();
        return !query || haystack.includes(query);
      }),
    }))
    .filter((rule) => (rule.matches || []).length > 0);
  const totalHits = allMatches.reduce((acc, r) => acc + (r.matches || []).length, 0);
  const filteredHits = filteredRules.reduce((acc, r) => acc + (r.matches || []).length, 0);
  if (!totalHits) {
    container.innerHTML = detectionEmptyHtml('Aucune règle ne correspond', 'Le scan YARA est terminé sans signature détectée.');
    return;
  }
  if (!filteredHits) {
    container.innerHTML = detectionEmptyHtml('Aucun résultat filtré', 'Change le filtre pour revoir les correspondances YARA.');
    return;
  }
  const decodeYaraPreview = (hexValue) => {
    const normalized = String(hexValue || '').replace(/[^0-9a-f]/gi, '');
    if (!normalized || normalized.length < 2) return '';
    const bytes = [];
    for (let index = 0; index < normalized.length; index += 2) {
      const value = parseInt(normalized.slice(index, index + 2), 16);
      if (!Number.isFinite(value)) continue;
      bytes.push(value);
    }
    if (!bytes.length) return '';
    const previewBytes = [];
    for (const byte of bytes) {
      if (byte === 0x00) break;
      previewBytes.push(byte);
      if (previewBytes.length >= 48) break;
    }
    if (!previewBytes.length) return '';
    const printableCount = previewBytes.filter((byte) => byte >= 0x20 && byte <= 0x7e).length;
    if ((printableCount / previewBytes.length) < 0.78) return '';
    return previewBytes
      .map((byte) => String.fromCharCode(byte))
      .join('')
      .replace(/\s+/g, ' ')
      .trim();
  };
  const summarizeHex = (hexValue) => {
    const normalized = String(hexValue || '').replace(/\s+/g, '').toLowerCase();
    if (!normalized) return '';
    return normalized.length > 48 ? `${normalized.slice(0, 48)}…` : normalized;
  };
  const cards = filteredRules.map((rule) => {
    const ruleMatches = (rule.matches || []).map((match, index) => {
      const span = getYaraMatchSpanLength(match);
      const preview = decodeYaraPreview(match.matched || '');
      const hexPreview = summarizeHex(match.matched || '');
      return `
        <div class="yara-hit-card">
          <div class="yara-hit-head">
            <button type="button" class="yara-offset-pill addr-link" data-addr="${escapeHtml(match.offset_hex)}" data-span="${escapeHtml(String(span))}">
              ${escapeHtml(match.offset_hex)}
            </button>
            <div class="yara-hit-badges">
              <span class="yara-hit-badge">match ${index + 1}</span>
              <span class="yara-hit-badge">${escapeHtml(String(span))} octet${span > 1 ? 's' : ''}</span>
            </div>
          </div>
          ${preview ? `<div class="yara-hit-preview">"${escapeHtml(preview)}"</div>` : ''}
          <div class="yara-hit-hex-wrap">
            <span class="yara-hit-hex-label">hex</span>
            <code class="yara-hit-hex" title="${escapeHtml(match.matched || '')}">${escapeHtml(hexPreview)}</code>
          </div>
        </div>
      `;
    }).join('');
    return `
      <section class="yara-rule-card">
        <div class="yara-rule-card-head">
          <div class="yara-rule-card-title-wrap">
            <span class="yara-rule-badge">${escapeHtml(rule.rule || 'Règle sans nom')}</span>
            <span class="yara-rule-hit-count">${(rule.matches || []).length} correspondance(s)</span>
          </div>
        </div>
        <div class="yara-hit-grid">${ruleMatches}</div>
      </section>
    `;
  }).join('');
  container.innerHTML = `
    <div class="yara-results-header">
      <span class="yara-results-count">${filteredHits} / ${totalHits} correspondance(s) • ${filteredRules.length} règle(s)</span>
      <span class="hint">Clique sur un offset pour ouvrir la zone correspondante</span>
    </div>
    <div class="yara-rule-results">${cards}</div>
  `;
  container.querySelectorAll('.addr-link').forEach(el => {
    el.addEventListener('click', () => {
      const a = el.dataset.addr;
      const bp = getStaticBinaryPath();
      const spanLength = normalizeSpanLength(el.dataset.span || 1);
      if (a && bp) vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: a, binaryPath: bp, spanLength });
    });
  });
}


function downloadDetectionJson(filename, payload) {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function downloadTextFile(filename, content, mimeType = 'text/plain') {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function normalizePluginPanelPayload(raw, arrayKeys = []) {
  if (Array.isArray(raw)) {
    return {
      result: {},
      items: raw,
      proofDossiers: [],
      summary: {},
      error: null,
    };
  }
  const result = raw && typeof raw === 'object' ? raw : {};
  let items = [];
  for (const key of arrayKeys) {
    if (Array.isArray(result[key])) {
      items = result[key];
      break;
    }
  }
  return {
    result,
    items,
    proofDossiers: Array.isArray(result.proof_dossiers) ? result.proof_dossiers : [],
    summary: result.summary && typeof result.summary === 'object' ? result.summary : {},
    error: result.error || null,
  };
}

function collectEvidenceSummaries(value, maxItems = 3) {
  if (Array.isArray(value)) {
    return value
      .map((entry) => {
        if (!entry) return '';
        if (typeof entry === 'string') return entry;
        if (typeof entry === 'object') {
          return String(
            entry.summary
            || entry.evidence
            || entry.description
            || entry.url
            || entry.uri
            || entry.ip
            || entry.domain
            || entry.host
            || entry.api
            || entry.value
            || ''
          ).trim();
        }
        return '';
      })
      .filter(Boolean)
      .slice(0, maxItems);
  }
  if (value && typeof value === 'object') {
    const summary = String(
      value.summary
      || value.evidence
      || value.description
      || value.url
      || value.uri
      || value.ip
      || value.domain
      || value.host
      || value.api
      || value.value
      || ''
    ).trim();
    return summary ? [summary] : [];
  }
  if (typeof value === 'string' && value.trim()) return [value.trim()];
  return [];
}

function formatPremiumEvidence(value, fallback = '—') {
  const parts = collectEvidenceSummaries(value);
  if (parts.length) return parts.join(' ; ');
  if (value === null || value === undefined || value === '') return fallback;
  return String(value);
}

function buildNavigableAddrNode(addr) {
  const text = String(addr || '').trim();
  if (!text) return document.createTextNode('—');
  if (!/^0x[0-9a-f]+$/i.test(text)) return document.createTextNode(text);
  const code = document.createElement('code');
  code.className = 'addr-link';
  code.dataset.addr = text;
  code.textContent = text;
  code.style.cursor = 'pointer';
  code.addEventListener('click', () => {
    const binaryPath = getStaticBinaryPath();
    if (!binaryPath) return;
    vscode.postMessage({ type: 'hubGoToAddress', addr: text, binaryPath });
  });
  return code;
}

function getPackerScoreBadgeClass(score) {
  const value = Number(score || 0);
  if (value >= 55) return 'critical';
  if (value >= 30) return 'high';
  return '';
}

function renderPackerAnalysisHtml(analysis) {
  if (!analysis || typeof analysis !== 'object') return '';
  const score = Number(analysis.score || 0);
  const summary = String(analysis.summary || '').trim();
  const signals = Array.isArray(analysis.signals) ? analysis.signals : [];
  const suspiciousSections = Array.isArray(analysis.suspicious_sections) ? analysis.suspicious_sections : [];
  const regions = Array.isArray(analysis.high_entropy_regions) ? analysis.high_entropy_regions : [];
  const badgeClass = getPackerScoreBadgeClass(score);
  const chips = [];
  chips.push(`<span class="score-badge ${badgeClass}">score ${escapeHtml(String(score))}/100</span>`);
  if (analysis.global_entropy !== null && analysis.global_entropy !== undefined) {
    chips.push(`<span class="count-badge">entropie globale ${escapeHtml(Number(analysis.global_entropy).toFixed(2))}</span>`);
  }
  if (analysis.import_count !== null && analysis.import_count !== undefined) {
    chips.push(`<span class="count-badge">${escapeHtml(String(analysis.import_count))} imports</span>`);
  }
  if (analysis.resource_count !== null && analysis.resource_count !== undefined) {
    chips.push(`<span class="count-badge">${escapeHtml(String(analysis.resource_count))} ressource(s)</span>`);
  }
  const signalsHtml = signals.length
    ? `<ul>${signals.map((signal) => `<li><strong>${escapeHtml(signal.label || signal.kind || 'Signal')}</strong> — ${escapeHtml(signal.detail || '—')}</li>`).join('')}</ul>`
    : '<p class="hint">Aucun signal heuristique fort relevé.</p>';
  const sectionsHtml = suspiciousSections.length
    ? `<div class="data-table-wrap"><table class="data-table"><thead><tr><th>Section</th><th>Type</th><th>Offset</th><th>Entropie</th><th>Pourquoi</th></tr></thead><tbody>${suspiciousSections.map((section) => `<tr><td><code>${escapeHtml(section.name || '')}</code></td><td>${escapeHtml(section.type || '—')}</td><td><code>${escapeHtml(section.offset_hex || '—')}</code></td><td>${section.entropy !== null && section.entropy !== undefined ? escapeHtml(Number(section.entropy).toFixed(2)) : '—'}</td><td>${escapeHtml((Array.isArray(section.reasons) ? section.reasons : []).join(' ; ') || '—')}</td></tr>`).join('')}</tbody></table></div>`
    : '<p class="hint">Aucune section ne ressort comme clairement compressée ou chiffrée.</p>';
  const yaraMatches = Array.isArray(analysis.yara_matches) ? analysis.yara_matches : [];
  const regionsHtml = regions.length
    ? `<p class="hint">Zones locales à revoir : ${regions.map((region) => `${escapeHtml(region.offset_hex || '?')} (${escapeHtml(String(region.entropy || '?'))})`).join(', ')}.</p>`
    : '';
  const hintHtml = yaraMatches.length
    ? `<p class="hint">Signature formelle identifiée (YARA) : ${escapeHtml(yaraMatches.map((m) => m.rule || m.family || '?').join(', '))}. Les patterns byte correspondent à un packer connu.</p>`
    : '<p class="hint">Lecture rapide : ces indices croisent entropie, noms de sections, imports et ressources PE. Ce n\'est pas une signature packer formelle.</p>';
  return `
    <div style="margin-top:12px">
      <div style="display:flex;justify-content:space-between;gap:12px;align-items:flex-start;flex-wrap:wrap">
        <div>
          <div class="info-key">Packing / compression</div>
          <div class="info-val" style="margin:4px 0 0 0">${escapeHtml(summary || '—')}</div>
        </div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end">${chips.join('')}</div>
      </div>
      ${hintHtml}
      <div style="margin-top:10px">
        <div class="info-key">Signaux</div>
        ${signalsHtml}
      </div>
      <div style="margin-top:10px">
        <div class="info-key">Sections suspectes</div>
        ${sectionsHtml}
      </div>
      ${regionsHtml}
    </div>`;
}

// ── Plugin shared helpers (globals consumed by plugin webviews) ───────────────
function asVI(v) {
  return (v && typeof v === 'object' ? v : {});
}

function renderVulnProofDossiers(dossiers, {
  kindLabel = {},
  confidenceColor = {},
  severityColor = {},
} = {}) {
  if (!Array.isArray(dossiers) || dossiers.length === 0) return null;
  const grid = document.createElement('div');
  grid.className = 'vuln-dossier-grid';
  const exploitClass = (level) => {
    if (level === 'HIGH') return 'is-high';
    if (level === 'MEDIUM') return 'is-medium';
    return 'is-low';
  };
  const severityClass = (level) => {
    if (level === 'CRITICAL') return 'is-critical';
    if (level === 'HIGH') return 'is-high';
    if (level === 'MEDIUM') return 'is-medium';
    return 'is-low';
  };
  const makeBadge = (label, value, extraClass = '', color = '') => {
    const badge = document.createElement('span');
    badge.className = `vuln-dossier-badge ${extraClass}`.trim();
    if (color) badge.style.color = color;
    badge.textContent = `${label} ${value}`;
    return badge;
  };
  dossiers.slice(0, 6).forEach((rawDossier) => {
    const dossier = asVI(rawDossier);
    const related = asVI(dossier.related);
    const card = document.createElement('article');
    card.className = 'modern-card vuln-dossier-card';
    const head = document.createElement('div');
    head.className = 'vuln-dossier-head';
    const titleWrap = document.createElement('div');
    const title = document.createElement('h4');
    title.className = 'vuln-dossier-title';
    title.textContent = String(dossier.function || '?');
    const subtitle = document.createElement('p');
    subtitle.className = 'vuln-dossier-subtitle';
    const findingCount = Number(dossier.finding_count || 0);
    const taintCount = Array.isArray(related.taint_flows) ? related.taint_flows.length : 0;
    const callsiteCount = Array.isArray(related.callsites) ? related.callsites.length : 0;
    const behaviorCount = Array.isArray(related.behavior) ? related.behavior.length : 0;
    const antiCount = Array.isArray(related.anti_analysis) ? related.anti_analysis.length : 0;
    subtitle.textContent = `${findingCount} signal${findingCount > 1 ? 'aux' : ''} \u00b7 ${taintCount} flux taint \u00b7 ${callsiteCount} callsite${callsiteCount > 1 ? 's' : ''} \u00b7 ${behaviorCount} behavior \u00b7 ${antiCount} anti-analysis`;
    titleWrap.append(title, subtitle);
    const badges = document.createElement('div');
    badges.className = 'vuln-dossier-badges';
    const exploitability = asVI(dossier.exploitability);
    const exploitScore = Number(exploitability.score || 0);
    const exploitLevel = String(exploitability.level || 'LOW');
    const dossierKind = String(dossier.kind || '');
    const dossierConfidence = String(dossier.confidence || '');
    const dossierSeverity = String(dossier.severity || '');
    badges.append(
      makeBadge('Preuve', kindLabel[dossierKind] || dossierKind || 'Signal'),
      makeBadge('Confiance', dossierConfidence || '?', exploitClass(dossierConfidence), confidenceColor[dossierConfidence] || ''),
      makeBadge('Exploit', exploitScore ? `${exploitLevel} ${exploitScore}` : exploitLevel, exploitClass(exploitLevel)),
      makeBadge('S\u00e9v\u00e9rit\u00e9', dossierSeverity || '?', severityClass(dossierSeverity), severityColor[dossierSeverity] || ''),
    );
    if (behaviorCount) badges.append(makeBadge('Behavior', String(behaviorCount), 'is-behavior'));
    if (antiCount) badges.append(makeBadge('Anti-analysis', String(antiCount), 'is-anti'));
    head.append(titleWrap, badges);
    card.appendChild(head);
    const relatedApis = Array.isArray(related.apis) ? related.apis.filter(Boolean) : [];
    if (relatedApis.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'APIs concern\u00e9es';
      const row = document.createElement('div');
      row.className = 'vuln-dossier-pill-row';
      relatedApis.slice(0, 6).forEach((api) => {
        const pill = document.createElement('span');
        pill.className = 'vuln-dossier-pill';
        pill.textContent = String(api);
        row.appendChild(pill);
      });
      section.append(labelEl, row);
      card.appendChild(section);
    }
    const relatedFamilies = Array.isArray(related.families) ? related.families.filter(Boolean) : [];
    if (relatedFamilies.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Familles de techniques';
      const row = document.createElement('div');
      row.className = 'vuln-dossier-pill-row';
      relatedFamilies.slice(0, 6).forEach((family) => {
        const pill = document.createElement('span');
        pill.className = 'vuln-dossier-pill';
        pill.textContent = String(family);
        row.appendChild(pill);
      });
      section.append(labelEl, row);
      card.appendChild(section);
    }
    const drivers = Array.isArray(exploitability.drivers) ? exploitability.drivers.filter(Boolean) : [];
    if (drivers.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Facteurs';
      const list = document.createElement('ul');
      list.className = 'vuln-dossier-list';
      drivers.slice(0, 4).forEach((driver) => {
        const item = document.createElement('li');
        item.textContent = String(driver);
        list.appendChild(item);
      });
      section.append(labelEl, list);
      card.appendChild(section);
    }
    const nextSteps = Array.isArray(dossier.next_steps) ? dossier.next_steps.filter(Boolean) : [];
    if (nextSteps.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = '\u00c9tapes sugg\u00e9r\u00e9es';
      const list = document.createElement('ul');
      list.className = 'vuln-dossier-list';
      nextSteps.slice(0, 4).forEach((step) => {
        const item = document.createElement('li');
        item.textContent = String(step);
        list.appendChild(item);
      });
      section.append(labelEl, list);
      card.appendChild(section);
    }
    const evidence = Array.isArray(dossier.evidence) ? dossier.evidence.filter((item) => item && typeof item === 'object' && item.summary) : [];
    if (evidence.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Preuves';
      const list = document.createElement('ul');
      list.className = 'vuln-dossier-list';
      evidence.slice(0, 4).forEach((entry) => {
        const e = asVI(entry);
        const item = document.createElement('li');
        item.textContent = String(e.summary);
        list.appendChild(item);
      });
      section.append(labelEl, list);
      card.appendChild(section);
    }
    const behaviorSignals = Array.isArray(related.behavior) ? related.behavior.filter((item) => {
      const i = asVI(item);
      return i.category || i.evidence;
    }) : [];
    if (behaviorSignals.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Corr\u00e9lation Behavior';
      const list = document.createElement('ul');
      list.className = 'vuln-dossier-list';
      behaviorSignals.slice(0, 3).forEach((rawSignal) => {
        const signal = asVI(rawSignal);
        const item = document.createElement('li');
        const evidenceText = formatPremiumEvidence(signal.evidence, '');
        item.textContent = `${signal.category || 'SIGNAL'}${evidenceText ? `: ${evidenceText}` : ''}`;
        list.appendChild(item);
      });
      section.append(labelEl, list);
      card.appendChild(section);
    }
    const antiSignals = Array.isArray(related.anti_analysis) ? related.anti_analysis.filter((item) => {
      const i = asVI(item);
      return i.technique || i.description;
    }) : [];
    if (antiSignals.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Corr\u00e9lation Anti-analysis';
      const list = document.createElement('ul');
      list.className = 'vuln-dossier-list';
      antiSignals.slice(0, 3).forEach((rawSignal) => {
        const signal = asVI(rawSignal);
        const item = document.createElement('li');
        item.textContent = `${signal.technique || 'SIGNAL'}${signal.description ? `: ${signal.description}` : ''}`;
        list.appendChild(item);
      });
      section.append(labelEl, list);
      card.appendChild(section);
    }
    const callsites = Array.isArray(related.callsites) ? related.callsites.filter((item) => {
      const i = asVI(item);
      return i.addr;
    }) : [];
    if (callsites.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Navigation rapide';
      const links = document.createElement('div');
      links.className = 'vuln-dossier-links';
      callsites.slice(0, 4).forEach((rawCallsite) => {
        const callsite = asVI(rawCallsite);
        const wrapper = document.createElement('span');
        const code = document.createElement('code');
        code.className = 'addr-link';
        const csAddr = String(callsite.addr || '');
        code.dataset.addr = csAddr;
        code.textContent = csAddr;
        wrapper.appendChild(code);
        if (callsite.line !== undefined && callsite.line !== null) wrapper.append(`:${callsite.line}`);
        links.appendChild(wrapper);
      });
      section.append(labelEl, links);
      card.appendChild(section);
    }
    const patchTargets = Array.isArray(related.patch_targets) ? related.patch_targets.filter((item) => {
      const i = asVI(item);
      return i.addr;
    }) : [];
    if (patchTargets.length) {
      const section = document.createElement('section');
      section.className = 'vuln-dossier-section';
      const labelEl = document.createElement('div');
      labelEl.className = 'vuln-dossier-label';
      labelEl.textContent = 'Offsets patchables';
      const links = document.createElement('div');
      links.className = 'vuln-dossier-links';
      patchTargets.slice(0, 4).forEach((rawTarget) => {
        const target = asVI(rawTarget);
        const wrapper = document.createElement('span');
        const node = buildNavigableAddrNode(String(target.addr || ''));
        wrapper.appendChild(node);
        links.appendChild(wrapper);
      });
      section.append(labelEl, links);
      card.appendChild(section);
    }
    if (dossier.needs_review) {
      const review = document.createElement('p');
      review.className = 'hint hint-warn';
      review.textContent = 'Revue manuelle recommand\u00e9e pour confirmer le contexte r\u00e9el.';
      card.appendChild(review);
    }
    grid.appendChild(card);
  });
  return grid;
}

function appendProofDossierSection(nodes, dossiers, {
  hintText = 'Dossiers de preuve par fonction interne. Les adresses ci-dessous sont cliquables pour naviguer dans le désassemblage.',
  kindLabel = {},
  confidenceColor = { HIGH: '#c72e2e', MEDIUM: '#c47a00', LOW: '#0e639c' },
  severityColor = { CRITICAL: '#c72e2e', HIGH: '#c47a00', MEDIUM: '#b5a000', LOW: '#0e639c' },
} = {}) {
  if (!Array.isArray(dossiers) || !dossiers.length) return;
  const hint = document.createElement('p');
  hint.className = 'hint';
  hint.textContent = hintText;
  nodes.push(hint);
  const cards = renderVulnProofDossiers(dossiers, { kindLabel, confidenceColor, severityColor });
  if (cards) nodes.push(cards);
}

function escapeHtml(s) {
  if (typeof s !== 'string') return String(s);
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function normalizeHexAddress(addr) {
  const raw = String(addr || '').trim();
  if (!raw) return '';
  const hex = raw.toLowerCase().startsWith('0x') ? raw.slice(2) : raw;
  if (!/^[0-9a-f]+$/i.test(hex)) return raw.toLowerCase();
  const trimmed = hex.replace(/^0+/, '') || '0';
  return `0x${trimmed.toLowerCase()}`;
}

function getActiveStaticTabId() {
  return document.querySelector('#panel-static .sub-tab.active')?.dataset?.subTab || '';
}

function isStaticTabActive(tabId) {
  return getActiveStaticTabId() === tabId;
}

function syncCfgActiveAddress(addr, opts = {}) {
  const container = document.getElementById('cfgContent');
  return container?._cfgState?.setActiveAddr?.(addr, opts) || null;
}

function syncCallGraphActiveAddress(addr, opts = {}) {
  const container = document.getElementById('callgraphContent');
  return container?._cgState?.setActiveAddr?.(addr, opts) || null;
}

function getGraphUiState(kind, binaryPath) {
  const state = kind === 'cfg' ? cfgUiState : callGraphUiState;
  if (binaryPath && state.binaryPath !== binaryPath) {
    const preservedViewMode = state.viewMode;
    const preservedSearch = state.search;
    Object.assign(state, {
      binaryPath,
      viewMode: preservedViewMode,
      search: preservedSearch,
      expandedAddrs: [],
      graphView: null,
      activeAddr: '',
    });
  }
  return state;
}

function findNearestFunctionStart(addr, allowedAddrs = null) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  const target = parseInt(normalized, 16);
  if (Number.isNaN(target)) return '';
  const allowed = allowedAddrs ? new Set(allowedAddrs.map((a) => normalizeHexAddress(a))) : null;
  let bestAddr = '';
  let bestValue = -1;
  (window.symbolsCache || []).forEach((sym) => {
    const type = String(sym.type || '').toLowerCase();
    if (type !== 't' && type !== 'f') return;
    const symNorm = normalizeHexAddress(sym.addr);
    if (!symNorm || (allowed && !allowed.has(symNorm))) return;
    const symValue = parseInt(symNorm, 16);
    if (Number.isNaN(symValue) || symValue > target || symValue < bestValue) return;
    bestValue = symValue;
    bestAddr = sym.addr;
  });
  if (bestAddr) return bestAddr;
  return allowed && allowed.has(normalized) ? normalized : '';
}

function findNameForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  for (const [key, ann] of Object.entries(window._annotations || {})) {
    if (normalizeHexAddress(key) === normalized && ann?.name) return ann.name;
  }
  for (const sym of window.symbolsCache || []) {
    if (normalizeHexAddress(sym.addr) === normalized && sym.name) return sym.name;
  }
  return '';
}

function findAnnotationForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return null;
  for (const [key, ann] of Object.entries(window._annotations || {})) {
    if (normalizeHexAddress(key) === normalized) return ann || null;
  }
  return null;
}

function parseAddressLikeValue(value) {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value || '').trim();
  if (!text) return Number.NaN;
  if (/^0x/i.test(text)) return parseInt(text, 16);
  if (/[a-f]/i.test(text)) return parseInt(text, 16);
  return Number(text);
}

function findSectionForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return null;
  const target = parseInt(normalized, 16);
  if (Number.isNaN(target)) return null;
  const sections = Array.isArray(window.sectionsCache) ? window.sectionsCache : [];
  for (const section of sections) {
    const start = parseAddressLikeValue(section.vma_hex || section.vma);
    const size = parseAddressLikeValue(section.size_hex || section.size);
    if (Number.isNaN(start) || Number.isNaN(size)) continue;
    if (target >= start && target < (start + size)) return section;
  }
  return null;
}

function getActiveContextSummary(addr = window._lastDisasmAddr) {
  const normalizedAddr = normalizeHexAddress(addr);
  const binaryPath = getStaticBinaryPath() || '';
  const binaryName = binaryPath ? _basenameFromPath(binaryPath) : '';
  const functionAddr = normalizedAddr ? (findNearestFunctionStart(normalizedAddr) || normalizedAddr) : '';
  const functionName = findNameForAddress(functionAddr) || findNameForAddress(normalizedAddr) || '';
  const exactName = findNameForAddress(normalizedAddr) || '';
  const annotation = findAnnotationForAddress(normalizedAddr);
  const section = findSectionForAddress(normalizedAddr);
  const meta = getCurrentBinaryMeta() || {};
  const arch = String(meta.arch || meta.rawConfig?.arch || '').trim();
  return {
    binaryPath,
    binaryName,
    addr: normalizedAddr,
    functionAddr,
    functionName,
    symbolName: exactName && exactName !== functionName ? exactName : '',
    annotationComment: String(annotation?.comment || '').trim(),
    sectionName: String(section?.name || '').trim(),
    arch,
  };
}

function getStackFrameCacheKey(binaryPath, addr) {
  const normalizedAddr = normalizeHexAddress(addr);
  const normalizedPath = String(binaryPath || '').trim();
  if (!normalizedPath || !normalizedAddr) return '';
  return `${normalizedPath}::${normalizedAddr}`;
}

function getCachedStackFrame(binaryPath, addr) {
  const key = getStackFrameCacheKey(binaryPath, addr);
  return key ? (stackFrameCache[key] || null) : null;
}

function cacheStackFrame(binaryPath, addr, frame) {
  const key = getStackFrameCacheKey(binaryPath, addr);
  if (!key || !frame) return;
  stackFrameCache[key] = frame;
  pendingStackFrameRequests.delete(key);
}

function ensureStackFrameLoaded(binaryPath, addr, opts = {}) {
  const normalizedAddr = normalizeHexAddress(addr);
  const key = getStackFrameCacheKey(binaryPath, normalizedAddr);
  if (!key) return null;
  if (!opts.force && stackFrameCache[key]) return stackFrameCache[key];
  if (pendingStackFrameRequests.has(key)) return null;
  pendingStackFrameRequests.add(key);
  vscode.postMessage({ type: 'hubLoadStackFrame', binaryPath, addr: normalizedAddr });
  return null;
}

function formatStackFrameEntryLocation(entry) {
  if (!entry) return '—';
  if (entry.location) return entry.location;
  if (typeof entry.offset === 'number') {
    const off = entry.offset >= 0
      ? `+0x${entry.offset.toString(16)}`
      : `-0x${Math.abs(entry.offset).toString(16)}`;
    return `[rbp${off}]`;
  }
  return '—';
}

function formatStackFrameEntryPreview(entry) {
  if (!entry) return '';
  const parts = [`${entry.name || 'entry'} @ ${formatStackFrameEntryLocation(entry)}`];
  if (entry.type && entry.type !== 'unknown') parts.push(`: ${entry.type}`);
  return parts.join('');
}

function normalizeStackEntryName(name) {
  return String(name || '').trim();
}

function setPendingStackEntryHighlight(name) {
  const normalized = normalizeStackEntryName(name);
  stackUiState.activeEntryName = normalized;
  stackUiState.pendingEntryName = normalized;
  return normalized;
}

function applyStackEntryHighlight(name, opts = {}) {
  const normalized = normalizeStackEntryName(name);
  const content = document.getElementById('stackContent');
  if (!content) return false;
  content.querySelectorAll('tr.addr-row-active').forEach((row) => row.classList.remove('addr-row-active'));
  if (!normalized) {
    stackUiState.activeEntryName = '';
    stackUiState.pendingEntryName = '';
    return false;
  }
  const rows = Array.from(content.querySelectorAll('tr[data-stack-entry-name]'));
  const target = rows.find((row) => normalizeStackEntryName(row.dataset.stackEntryName) === normalized);
  if (!target) return false;
  target.classList.add('addr-row-active');
  stackUiState.activeEntryName = normalized;
  stackUiState.pendingEntryName = '';
  if (opts.reveal !== false) target.scrollIntoView({ block: 'nearest' });
  return true;
}

function openStackEntryFromDecompile(name) {
  const entryName = setPendingStackEntryHighlight(name);
  if (!entryName) return;
  const targetAddr = normalizeHexAddress(decompileUiState.renderedAddr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const binaryPath = decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  if (!binaryPath || !targetAddr) return;
  window._lastDisasmAddr = targetAddr;
  showGroup('code', 'stack');
  updateActiveContextBars(targetAddr);
  requestAnimationFrame(() => {
    const cached = syncStackFrameForContext(targetAddr, { render: true });
    if (cached) applyStackEntryHighlight(entryName);
  });
}

function setPendingDecompileStackHighlight(name) {
  const normalized = normalizeStackEntryName(name);
  decompileUiState.activeStackEntryName = normalized;
  decompileUiState.pendingStackEntryName = normalized;
  return normalized;
}

function applyDecompileStackHighlight(name, opts = {}) {
  const normalized = normalizeStackEntryName(name);
  const content = document.getElementById('decompileContent');
  if (!content) return false;
  content.querySelectorAll('.decompile-stack-link.is-active, .decompile-link-chip-stack.is-active').forEach((el) => {
    el.classList.remove('is-active');
  });
  if (!normalized) {
    decompileUiState.activeStackEntryName = '';
    decompileUiState.pendingStackEntryName = '';
    return false;
  }
  const targets = Array.from(
    content.querySelectorAll('.decompile-stack-link[data-stack-name], .decompile-link-chip-stack[data-stack-name]'),
  ).filter((el) => normalizeStackEntryName(el.dataset.stackName) === normalized);
  if (!targets.length) return false;
  targets.forEach((el) => el.classList.add('is-active'));
  decompileUiState.activeStackEntryName = normalized;
  decompileUiState.pendingStackEntryName = '';
  if (opts.reveal !== false) targets[0].scrollIntoView({ block: 'nearest' });
  return true;
}

function openDecompileForStackEntry(name) {
  const entryName = setPendingDecompileStackHighlight(name);
  if (!entryName) return;
  const targetAddr = normalizeHexAddress(stackUiState.renderedAddr || decompileUiState.renderedAddr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const binaryPath = stackUiState.renderedBinaryPath || decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  if (!binaryPath || !targetAddr) return;
  window._lastDisasmAddr = targetAddr;
  updateActiveContextBars(targetAddr);
  syncDecompileSelection(targetAddr, { forceContext: true });
  const currentBinaryPath = getStaticBinaryPath() || '';
  const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
  const currentProvider = _getConfiguredDecompilerProvider();
  const shouldRefresh = decompileUiState.renderedBinaryPath !== currentBinaryPath
    || decompileUiState.renderedDecompiler !== currentDecompiler
    || decompileUiState.renderedProvider !== currentProvider
    || decompileUiState.renderedQuality !== currentQuality
    || (decompileUiState.renderedAddr || '') !== targetAddr;
  showGroup('code', 'decompile');
  requestAnimationFrame(() => {
    if (!shouldRefresh) applyDecompileStackHighlight(entryName);
  });
}

function buildHexStackContextHtml(frame) {
  if (!frame || frame.error) return '';
  const args = Array.isArray(frame.args) ? frame.args : [];
  const vars = Array.isArray(frame.vars) ? frame.vars : [];
  const metaChips = [
    frame.arch && frame.arch !== 'unknown' ? `Arch ${frame.arch}` : null,
    frame.abi && frame.abi !== 'unknown' ? `ABI ${frame.abi}` : null,
    typeof frame.frame_size === 'number' ? `Frame ${frame.frame_size}B` : null,
    `Args ${args.length}`,
    `Locals ${vars.length}`,
  ].filter(Boolean);
  const renderEntries = (title, entries, emptyLabel) => {
    const slice = entries.slice(0, 3);
    const remaining = entries.length - slice.length;
    const items = slice.map((entry) => (
      `<span class="hex-selection-stack-entry">${escapeHtml(formatStackFrameEntryPreview(entry))}</span>`
    )).join('');
    const extra = remaining > 0
      ? `<span class="hex-selection-stack-entry hex-selection-stack-entry-more">+${remaining} autre(s)</span>`
      : '';
    return `
      <div class="hex-selection-stack-block">
        <div class="hex-selection-stack-title">${escapeHtml(title)}</div>
        <div class="hex-selection-stack-entries">
          ${items || `<span class="hex-selection-stack-empty">${escapeHtml(emptyLabel)}</span>`}
          ${extra}
        </div>
      </div>
    `.trim();
  };
  const chipsHtml = metaChips.map((chip) => (
    `<span class="hex-selection-chip">${escapeHtml(chip)}</span>`
  )).join('');
  return `
    <div class="hex-selection-stack">
      <div class="hex-selection-stack-head">Contexte stack de la fonction</div>
      ${chipsHtml ? `<div class="hex-selection-chips">${chipsHtml}</div>` : ''}
      <div class="hex-selection-stack-grid">
        ${renderEntries('Arguments', args, 'Aucun argument détecté')}
        ${renderEntries('Locaux', vars, 'Aucune variable locale détectée')}
      </div>
    </div>
  `.trim();
}

function syncStackFrameForContext(addr = window._lastDisasmAddr, opts = {}) {
  const summary = getActiveContextSummary(addr);
  const targetAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  const binaryPath = summary.binaryPath || '';
  if (!binaryPath || !targetAddr || isRawBinarySelected()) return null;
  const shouldSkip = !opts.force
    && stackUiState.renderedBinaryPath === binaryPath
    && stackUiState.renderedAddr === targetAddr;
  if (shouldSkip) return getCachedStackFrame(binaryPath, targetAddr);
  const cached = getCachedStackFrame(binaryPath, targetAddr);
  if (cached) {
    if (opts.render !== false) {
      stackUiState.renderedBinaryPath = binaryPath;
      stackUiState.renderedAddr = targetAddr;
      renderStackFrame(cached);
    }
    return cached;
  }
  if (opts.render !== false) {
    setStaticLoading('stackContent', opts.loadingLabel || 'Analyse stack frame…');
  }
  ensureStackFrameLoaded(binaryPath, targetAddr);
  return null;
}

function createActiveContextBar(id) {
  const bar = document.createElement('div');
  bar.id = id;
  bar.className = 'active-context-bar active-context-bar-injected';
  bar.innerHTML = `
    <span class="active-context-chip active-context-chip-primary" data-role="function">Fonction: —</span>
    <span class="active-context-chip" data-role="address">Adresse: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="symbol" hidden>Symbole: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="section" hidden>Section: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="arch" hidden>Arch: —</span>
    <span class="active-context-chip active-context-chip-meta" data-role="binary" hidden>Binaire: —</span>
    <div class="active-context-actions">
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="disasm">Désasm</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="cfg">CFG</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="callgraph">Call Graph</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="decompile">Pseudo-C</button>
      <button type="button" class="btn btn-xs btn-secondary" data-context-jump="hex">Hex</button>
    </div>
  `.trim();
  return bar;
}

function ensureActiveContextBarDetails(bar) {
  if (!bar || bar.dataset.enrichedContextBar === 'true') return;
  const actions = bar.querySelector('.active-context-actions');
  const ensureChip = (role, label, className = 'active-context-chip active-context-chip-meta') => {
    if (bar.querySelector(`[data-role="${role}"]`)) return;
    const chip = document.createElement('span');
    chip.className = className;
    chip.dataset.role = role;
    chip.hidden = true;
    chip.textContent = `${label}: —`;
    bar.insertBefore(chip, actions || null);
  };
  ensureChip('symbol', 'Symbole');
  ensureChip('section', 'Section');
  ensureChip('arch', 'Arch');
  ensureChip('binary', 'Binaire');
  bar.dataset.enrichedContextBar = 'true';
}

function injectActiveContextBars() {
  ACTIVE_CONTEXT_INJECTED_PANELS.forEach((panelId) => {
    const panel = document.getElementById(panelId);
    if (!panel || panel.querySelector('.active-context-bar')) return;
    const bar = createActiveContextBar(`${panelId}ContextBar`);
    const first = panel.firstElementChild;
    const insertAfterFirst = !!first && (
      first.classList.contains('form-row')
      || first.classList.contains('export-bar')
      || first.classList.contains('functions-toolbar')
      || first.classList.contains('typed-data-toolbar')
      || first.classList.contains('panel-toolbar')
      || (first.tagName === 'P' && first.classList.contains('hint'))
    );
    if (insertAfterFirst) {
      panel.insertBefore(bar, first.nextSibling);
    } else {
      panel.insertBefore(bar, first || null);
    }
  });
}

function updateActiveContextBars(addr = window._lastDisasmAddr) {
  const summary = getActiveContextSummary(addr);
  const activeTab = getActiveStaticTabId();
  document.querySelectorAll('.active-context-bar').forEach((bar) => {
    ensureActiveContextBarDetails(bar);
    const funcChip = bar.querySelector('[data-role="function"]');
    const addrChip = bar.querySelector('[data-role="address"]');
    const symbolChip = bar.querySelector('[data-role="symbol"]');
    const sectionChip = bar.querySelector('[data-role="section"]');
    const archChip = bar.querySelector('[data-role="arch"]');
    const binaryChip = bar.querySelector('[data-role="binary"]');
    if (funcChip) {
      funcChip.textContent = summary.functionAddr
        ? `Fonction: ${summary.functionName ? `${summary.functionName} @ ${summary.functionAddr}` : summary.functionAddr}`
        : 'Fonction: —';
    }
    if (addrChip) {
      addrChip.textContent = summary.addr ? `Adresse: ${summary.addr}` : 'Adresse: —';
    }
    if (symbolChip) {
      const symbolText = summary.symbolName || summary.annotationComment;
      symbolChip.textContent = symbolText
        ? `Symbole: ${String(symbolText).length > 48 ? `${String(symbolText).slice(0, 48)}…` : symbolText}`
        : 'Symbole: —';
      symbolChip.hidden = !symbolText;
      if (summary.annotationComment) symbolChip.title = summary.annotationComment;
      else symbolChip.removeAttribute('title');
    }
    if (sectionChip) {
      sectionChip.textContent = summary.sectionName ? `Section: ${summary.sectionName}` : 'Section: —';
      sectionChip.hidden = !summary.sectionName;
    }
    if (archChip) {
      archChip.textContent = summary.arch ? `Arch: ${summary.arch}` : 'Arch: —';
      archChip.hidden = !summary.arch;
    }
    if (binaryChip) {
      binaryChip.textContent = summary.binaryName ? `Binaire: ${summary.binaryName}` : 'Binaire: —';
      binaryChip.hidden = !summary.binaryName;
      if (summary.binaryPath) binaryChip.title = summary.binaryPath;
      else binaryChip.removeAttribute('title');
    }
    bar.querySelectorAll('[data-context-jump]').forEach((btn) => {
      const targetTab = btn.dataset.contextJump || '';
      const visible = isStaticTabAvailable(targetTab);
      btn.hidden = !visible;
      btn.disabled = !visible || !summary.binaryPath || !summary.addr || activeTab === targetTab;
    });
  });
  updateActiveNavRows(summary.addr);
  updateDisasmSessionSummary();
}

function updateActiveNavRows(addr = window._lastDisasmAddr) {
  const summary = getActiveContextSummary(addr);
  const exactAddr = normalizeHexAddress(summary.addr);
  const exactAddrNum = parseNumericAddress(exactAddr);
  const functionAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  document.querySelectorAll('.nav-addr-row[data-addr]').forEach((row) => {
    const rowAddr = normalizeHexAddress(row.dataset.addr || '');
    const matchMode = row.dataset.addrMatch || 'exact';
    const targetAddr = matchMode === 'function' ? functionAddr : exactAddr;
    let isActive = !!rowAddr && !!targetAddr && rowAddr === targetAddr;
    if (!isActive && matchMode === 'span' && Number.isFinite(exactAddrNum)) {
      const rowAddrNum = parseNumericAddress(rowAddr);
      const spanLength = normalizeSpanLength(row.dataset.spanLength || row.dataset.span || 1);
      isActive = Number.isFinite(rowAddrNum) && exactAddrNum >= rowAddrNum && exactAddrNum < rowAddrNum + spanLength;
    }
    row.classList.toggle('addr-row-active', isActive);
    row.querySelectorAll('.addr-link').forEach((link) => {
      link.classList.toggle('addr-link-active', isActive);
    });
  });
}

function jumpToContextTab(tabId) {
  const summary = getActiveContextSummary();
  if (!summary.binaryPath || !tabId || !summary.addr) return;
  jumpToAddrInContextTab(tabId, summary.addr, summary.binaryPath);
}

function jumpToAddrInContextTab(tabId, addr, binaryPath, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  const bp = binaryPath || getStaticBinaryPath();
  if (!tabId || !normalized || !bp || !isStaticTabAvailable(tabId)) return;
  const spanLength = normalizeSpanLength(opts.spanLength || 1);
  setActiveAddressContext(normalized, spanLength);
  if (!opts.skipHistory && typeof navPush === 'function') {
    navPush(normalized, {
      tab: opts.historyTab || tabId,
      spanLength,
      source: opts.historySource || '',
    });
  }
  showPanel('static');
  showGroup('code', tabId);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      if (tabId === 'disasm') {
        vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp, spanLength });
      } else if (tabId === 'cfg') {
        syncCfgActiveAddress(normalized, {
          reveal: true,
          revealTable: document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      } else if (tabId === 'callgraph') {
        syncCallGraphActiveAddress(normalized, {
          reveal: true,
          revealTable: document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      } else if (tabId === 'decompile') {
        syncDecompileSelection(normalized || decompileUiState.selectedAddr, { forceContext: true });
        requestDecompileForCurrentSelection();
      } else if (tabId === 'hex') {
        const descriptor = buildHexSelectionDescriptor(normalized, {
          spanLength,
          endAddr: opts.endAddr || '',
          activeAddr: normalized,
          anchorAddr: normalized,
        });
        if (!hexSections.length || !tabDataCache.hex || tabDataCache.hex.binaryPath !== bp) {
          hexPendingScrollVaddr = descriptor || buildHexSelectionDescriptor(normalized, { spanLength });
          loadHexView(bp, hexCurrentOffset, hexCurrentLength);
        } else {
          scrollHexToVaddr(descriptor || { addr: normalized, spanLength });
        }
      }
    });
  });
}

function inferByteSpanFromHexText(hexText, fallback = 1) {
  const parts = String(hexText || '').trim().split(/\s+/).filter((part) => /^[0-9a-f]{2}$/i.test(part));
  return normalizeSpanLength(parts.length || fallback);
}

function getTypedDataEntrySpanLength(entry) {
  const explicitSize = Number(entry?.size || 0);
  if (Number.isFinite(explicitSize) && explicitSize > 0) {
    return normalizeSpanLength(explicitSize);
  }
  return inferByteSpanFromHexText(entry?.hex || '', 1);
}

function getSearchResultSpanLength(row) {
  const explicitLength = Number(row?.length || 0);
  if (Number.isFinite(explicitLength) && explicitLength > 0) {
    return normalizeSpanLength(explicitLength);
  }
  return inferByteSpanFromHexText(row?.value || '', 1);
}

function getYaraMatchSpanLength(match) {
  return inferByteSpanFromHexText(match?.matched || '', 1);
}

function syncTypedDataEntrySelection(entry, opts = {}) {
  const normalizedAddr = normalizeHexAddress(entry?.addr || '');
  const bp = opts.binaryPath || getStaticBinaryPath();
  if (!normalizedAddr || !bp) return;
  const spanLength = getTypedDataEntrySpanLength(entry);
  const binaryMeta = opts.binaryMeta || getCurrentBinaryMeta();
  setActiveAddressContext(normalizedAddr, spanLength, { preserveHexSelection: true });
  if (opts.openHex) {
    showPanel('static');
    showGroup('code', 'hex');
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        if (!hexSections.length || !tabDataCache.hex || tabDataCache.hex.binaryPath !== bp) {
          hexPendingScrollVaddr = buildHexSelectionDescriptor(normalizedAddr, { spanLength });
          loadHexView(bp, hexCurrentOffset, hexCurrentLength);
        } else {
          scrollHexToVaddr({ addr: normalizedAddr, spanLength });
        }
      });
    });
    return;
  }
  if (hexSections.length) {
    setHexActiveAddress(normalizedAddr, {
      spanLength,
      reveal: isStaticTabActive('hex'),
      instant: !isStaticTabActive('hex'),
    });
  }
  if (opts.openDisasm) {
    vscode.postMessage({
      type: 'hubGoToAddress',
      addr: normalizedAddr,
      binaryPath: bp,
      binaryMeta,
      spanLength,
    });
  }
}

function updateTypedDataActiveSelection(addr = window._lastDisasmAddr, spanLength = hexSelectionModel.spanLength, opts = {}) {
  const container = document.getElementById('typedDataContent');
  if (!container) return;
  const normalizedAddr = normalizeHexAddress(addr || '');
  const startNum = parseNumericAddress(normalizedAddr);
  const normalizedSpan = normalizeSpanLength(spanLength || 1);
  const endNum = Number.isFinite(startNum) ? (startNum + normalizedSpan - 1) : NaN;
  let firstMatch = null;
  container.querySelectorAll('tr[data-range-start]').forEach((row) => {
    const rowStart = parseNumericAddress(row.dataset.rangeStart || '');
    const rowEnd = parseNumericAddress(row.dataset.rangeEnd || row.dataset.rangeStart || '');
    const matches = Number.isFinite(startNum)
      && Number.isFinite(rowStart)
      && Number.isFinite(rowEnd)
      && rowStart <= endNum
      && rowEnd >= startNum;
    row.classList.toggle('addr-row-active', matches);
    if (matches && !firstMatch) firstMatch = row;
  });
  if (opts.reveal && firstMatch && isStaticTabActive('typed_data')) {
    firstMatch.scrollIntoView({ block: 'nearest' });
  }
}

function setStaticLoading(containerId, msg) {
  const el = document.getElementById(containerId);
  if (el) el.innerHTML = msg ? `<p class="loading">${escapeHtml(msg)}</p>` : '';
}

function applyHexLayoutMode() {
  const panel = document.getElementById('staticHex');
  const button = document.getElementById('btnHexToggleMeta');
  if (panel) panel.classList.toggle('hex-compact-mode', !!hexUiState.compact);
  if (button) {
    button.textContent = hexUiState.compact ? 'Voir infos' : 'Masquer infos';
    button.title = hexUiState.compact
      ? 'Afficher le contexte, les patches et la légende'
      : 'Garder un mode plus compact pour voir davantage de hex';
  }
}

function setTypedDataStructStatus(text, isError) {
  const statusEl = document.getElementById('typedDataStructStatus');
  if (!statusEl) return;
  statusEl.textContent = text || '';
  statusEl.style.color = isError ? 'var(--accent-danger, #ff6b6b)' : '';
}

function syncTypedDataStructSelect(structs, preferredName) {
  typedDataUiState.structs = Array.isArray(structs) ? structs.slice() : [];
  const select = document.getElementById('typedDataStructSelect');
  const applyBtn = document.getElementById('btnTypedApplyStruct');
  if (!select) return;
  const list = Array.isArray(structs) ? structs : [];
  const currentValue = preferredName !== undefined ? preferredName : (select.value || '');
  select.options.length = 0;
  if (list.length === 0) {
    select.add(new Option('aucun struct d\u00e9fini', ''));
    select.disabled = true;
    if (applyBtn) applyBtn.disabled = true;
    setTypedDataStructStatus('Cliquez \u201cD\u00e9finir structs\u201d pour cr\u00e9er un struct C \u00e0 appliquer sur la section.', false);
    return;
  }
  select.disabled = false;
  if (applyBtn) applyBtn.disabled = false;
  select.add(new Option('\u2014 struct \u2014', ''));
  list.forEach((entry) => {
    const name = typeof entry === 'string' ? entry : String((entry && entry.name) || '');
    if (!name) return;
    const kind = typeof entry === 'string' ? 'struct' : String((entry && entry.kind) || 'struct');
    const fieldCount = Number((entry && entry.field_count) || 0);
    const label = typeof entry === 'string'
      ? name
      : `${name} (${kind}, ${fieldCount} champ${fieldCount > 1 ? 's' : ''})`;
    select.add(new Option(label, name));
  });
  const nextValue = list.some((entry) => (typeof entry === 'string' ? entry : entry?.name) === currentValue)
    ? currentValue
    : '';
  select.value = nextValue;
  if (!nextValue && typedDataUiState.appliedStructName) {
    typedDataUiState.appliedStructName = '';
    setTypedDataStructStatus('');
  }
}

function getTypedDataActiveType() {
  return document.querySelector('.typed-type-btn.active')?.dataset.type || 'auto';
}

function buildTypedDataRequest(binaryPath, overrides) {
  const opts = overrides || {};
  const payload = {
    type: 'hubLoadTypedData',
    binaryPath,
    valueType: opts.valueType || getTypedDataActiveType(),
    page: opts.page ?? 0,
  };
  const section = opts.section !== undefined
    ? opts.section
    : document.getElementById('typedDataSection')?.value;
  if (section) payload.section = section;
  const structName = opts.structName !== undefined ? opts.structName : typedDataUiState.appliedStructName;
  const structOffset = opts.structOffset !== undefined
    ? opts.structOffset
    : (typedDataUiState.appliedStructOffset || document.getElementById('typedDataStructOffset')?.value || '0x0');
  if (structName) {
    payload.structName = structName;
    payload.structOffset = structOffset;
    const structAddr = opts.structAddr !== undefined
      ? opts.structAddr
      : typedDataUiState.appliedStructAddr;
    if (structAddr) payload.structAddr = structAddr;
  }
  return payload;
}

function getTypedStructList() {
  return Array.isArray(typedDataUiState.structs) ? typedDataUiState.structs : [];
}

function ensureTypedStructCatalogLoaded() {
  if (typedDataUiState.loadingStructs || typedDataUiState.structsLoaded) return;
  typedDataUiState.loadingStructs = true;
  vscode.postMessage({ type: 'hubLoadStructs' });
}

function getPreferredHexStructName() {
  const preferred = String(
    typedDataUiState.hexStructName
    || typedDataUiState.appliedStructName
    || document.getElementById('typedDataStructSelect')?.value
    || ''
  ).trim();
  const structs = getTypedStructList();
  if (!preferred) return '';
  return structs.some((entry) => (typeof entry === 'string' ? entry : entry?.name) === preferred)
    ? preferred
    : '';
}

function getHexStructSelectionContext(selection = null) {
  const descriptor = selection && typeof selection === 'object'
    ? buildHexSelectionDescriptor(selection.startAddr || selection.addr || selection.activeAddr || '', selection)
    : getCurrentHexSelectionDescriptor();
  if (!descriptor) return null;
  const addr = normalizeHexAddress(descriptor.startAddr || descriptor.activeAddr || '');
  const addrNum = parseNumericAddress(addr);
  if (!Number.isFinite(addrNum)) return null;
  const fileOffset = fileOffsetFromVaddr(addr);
  const section = Number.isFinite(fileOffset) ? findSectionForFileOffset(fileOffset) : null;
  const sectionVaddr = parseNumericAddress(section?.virtual_address);
  const sectionOffset = Number.isFinite(sectionVaddr) ? Math.max(0, addrNum - sectionVaddr) : null;
  return {
    descriptor,
    addr,
    addrNum,
    fileOffset,
    section,
    sectionOffset,
    sectionOffsetHex: Number.isFinite(sectionOffset) ? `0x${sectionOffset.toString(16)}` : '',
  };
}

function syncTypedDataFromActiveSelection(opts = {}) {
  const ctx = getHexStructSelectionContext();
  const targetAddr = normalizeHexAddress(opts.addr || ctx?.addr || window._lastDisasmAddr || '');
  if (!targetAddr) {
    setTypedDataStructStatus('Aucune adresse active à reprendre.', true);
    return null;
  }
  const structOffsetInput = document.getElementById('typedDataStructOffset');
  const sectionSelect = document.getElementById('typedDataSection');
  if (ctx?.section?.name && sectionSelect) sectionSelect.value = String(ctx.section.name);
  if (ctx?.sectionOffsetHex && structOffsetInput) structOffsetInput.value = ctx.sectionOffsetHex;
  typedDataUiState.appliedStructAddr = targetAddr;
  setTypedDataStructStatus(
    ctx?.section?.name
      ? `Sélection active ${targetAddr} prête dans ${ctx.section.name} @ +${ctx.sectionOffsetHex}.`
      : `Sélection active ${targetAddr} prête pour application par adresse.`,
    false,
  );
  return {
    addr: targetAddr,
    section: ctx?.section?.name || '',
    structOffset: ctx?.sectionOffsetHex || '0x0',
  };
}

function requestHexStructPreview(structName, ctx = getHexStructSelectionContext()) {
  const binaryPath = getStaticBinaryPath();
  const normalizedStruct = String(structName || '').trim();
  if (!binaryPath || !ctx?.addr || !normalizedStruct) return;
  typedDataUiState.hexStructName = normalizedStruct;
  typedDataUiState.hexStructPreview = {
    loading: true,
    structName: normalizedStruct,
    addr: ctx.addr,
    section: ctx.section?.name || '',
  };
  updateHexSelectionSummary(ctx.descriptor);
  vscode.postMessage({
    type: 'hubPreviewTypedStruct',
    binaryPath,
    structName: normalizedStruct,
    structAddr: ctx.addr,
    section: ctx.section?.name || undefined,
    structOffset: ctx.sectionOffsetHex || '0x0',
  });
}

function openTypedDataStructFromSelection(structName, ctx = getHexStructSelectionContext()) {
  const binaryPath = getStaticBinaryPath();
  const normalizedStruct = String(structName || '').trim();
  if (!binaryPath || !ctx?.addr || !normalizedStruct) return;
  typedDataUiState.hexStructName = normalizedStruct;
  typedDataUiState.appliedStructName = normalizedStruct;
  typedDataUiState.appliedStructAddr = ctx.addr;
  typedDataUiState.appliedStructOffset = ctx.sectionOffsetHex || '0x0';
  if (ctx.section?.name && document.getElementById('typedDataSection')) {
    document.getElementById('typedDataSection').value = String(ctx.section.name);
  }
  if (document.getElementById('typedDataStructSelect')) {
    document.getElementById('typedDataStructSelect').value = normalizedStruct;
  }
  if (document.getElementById('typedDataStructOffset')) {
    document.getElementById('typedDataStructOffset').value = typedDataUiState.appliedStructOffset;
  }
  showGroup('data', 'typed_data');
  setStaticLoading('typedDataContent', 'Application du type…');
  vscode.postMessage(buildTypedDataRequest(binaryPath, {
    page: 0,
    section: ctx.section?.name || undefined,
    structName: normalizedStruct,
    structOffset: typedDataUiState.appliedStructOffset,
    structAddr: ctx.addr,
  }));
}

function openTypedStructEditor(sourceText) {
  document.getElementById('pof-typed-struct-popup')?.remove();
  const popup = document.createElement('div');
  popup.id = 'pof-typed-struct-popup';
  popup.className = 'note-popup typed-data-struct-editor';
  popup.style.cssText = 'left:50%;top:84px;transform:translateX(-50%);z-index:240;';

  const head = document.createElement('div');
  head.className = 'typed-data-struct-editor-head';
  head.innerHTML = `
    <div class="typed-data-struct-editor-title">Éditeur de types C</div>
    <div class="typed-data-struct-editor-hint">Collez une ou plusieurs d\u00e9finitions C s\u00e9par\u00e9es par une ligne vide (<code>typedef struct</code>, <code>union</code>, <code>enum</code>). Tous les types d\u00e9finis ici apparaissent dans le menu d\u00e9roulant.</div>
  `;

  const textarea = document.createElement('textarea');
  textarea.className = 'note-popup-input';
  textarea.spellcheck = false;
  textarea.value = sourceText || '';

  const actions = document.createElement('div');
  actions.className = 'typed-data-struct-editor-actions';
  const cancelBtn = document.createElement('button');
  cancelBtn.className = 'btn btn-xs';
  cancelBtn.type = 'button';
  cancelBtn.textContent = 'Fermer';
  cancelBtn.addEventListener('click', () => popup.remove());

  const saveBtn = document.createElement('button');
  saveBtn.className = 'btn btn-xs btn-primary';
  saveBtn.type = 'button';
  saveBtn.textContent = 'Sauvegarder';
  saveBtn.addEventListener('click', () => {
    setTypedDataStructStatus('Sauvegarde des types C…');
    vscode.postMessage({ type: 'hubSaveStructs', sourceText: textarea.value });
    popup.remove();
  });

  actions.appendChild(cancelBtn);
  actions.appendChild(saveBtn);
  popup.appendChild(head);
  popup.appendChild(textarea);
  popup.appendChild(actions);
  document.body.appendChild(popup);
  textarea.focus();
  textarea.setSelectionRange(textarea.value.length, textarea.value.length);
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') popup.remove();
  }, { once: true });
}

function initCfgZoom(wrapEl) {
  if (!wrapEl) return;
  const state = { scale: 1 };
  let tx = 0;
  let ty = 0;
  let panning = false;
  let lastX = 0;
  let lastY = 0;
  let autoFitScheduled = false;

  const inner = wrapEl.querySelector('.cfg-svg-inner');
  if (!inner) return;

  function applyTransform() {
    inner.style.transform = `translate(${tx}px, ${ty}px) scale(${state.scale})`;
    inner.style.transformOrigin = '0 0';
    if (typeof state.onChange === 'function') state.onChange(state.getViewState());
  }

  wrapEl.addEventListener('wheel', (e) => {
    e.preventDefault();
    const oldScale = state.scale;
    const delta = e.deltaY > 0 ? -0.15 : 0.15;
    state.scale = Math.max(0.2, Math.min(4, oldScale + delta));
    // Cursor-centered zoom: keep the point under the mouse fixed in SVG space
    const rect = wrapEl.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    tx = mouseX - (mouseX - tx) * (state.scale / oldScale);
    ty = mouseY - (mouseY - ty) * (state.scale / oldScale);
    applyTransform();
  }, { passive: false });

  wrapEl.addEventListener('mousedown', (e) => {
    if (e.target.closest('.cfg-node')) return;
    panning = true;
    lastX = e.clientX;
    lastY = e.clientY;
  });
  document.addEventListener('mousemove', (e) => {
    if (!panning) return;
    tx += e.clientX - lastX;
    ty += e.clientY - lastY;
    lastX = e.clientX;
    lastY = e.clientY;
    applyTransform();
  });
  document.addEventListener('mouseup', () => { panning = false; });

  function fitToView() {
    const svg = inner.querySelector('svg');
    if (!svg) return;
    const svgW = parseFloat(svg.getAttribute('width')) || 600;
    const svgH = parseFloat(svg.getAttribute('height')) || 400;
    const wrapRect = wrapEl.getBoundingClientRect();
    if (wrapRect.width === 0 || wrapRect.height === 0) return;
    const pad = 24;
    const usableW = Math.max(80, wrapRect.width - pad * 2);
    const usableH = Math.max(80, wrapRect.height - pad * 2);
    state.scale = Math.min(usableW / svgW, usableH / svgH, 1);
    tx = Math.max(pad, (wrapRect.width - svgW * state.scale) / 2);
    ty = Math.max(pad, (wrapRect.height - svgH * state.scale) / 2);
    applyTransform();
  }

  function requestFit() {
    if (autoFitScheduled) return;
    autoFitScheduled = true;
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        autoFitScheduled = false;
        fitToView();
      });
    });
  }

  function centerOnBox(box, opts = {}) {
    if (!box) return;
    const wrapRect = wrapEl.getBoundingClientRect();
    if (wrapRect.width === 0 || wrapRect.height === 0) return;
    let targetScale = typeof opts.scale === 'number' ? opts.scale : (state.scale || 1);
    if (typeof opts.minScale === 'number') targetScale = Math.max(targetScale, opts.minScale);
    if (typeof opts.maxScale === 'number') targetScale = Math.min(targetScale, opts.maxScale);
    state.scale = Math.max(0.2, Math.min(4, targetScale));
    tx = (wrapRect.width / 2) - ((box.x + box.w / 2) * state.scale);
    ty = (wrapRect.height / 2) - ((box.y + box.h / 2) * state.scale);
    applyTransform();
  }

  function getViewState() {
    return { scale: state.scale, tx, ty };
  }

  function setViewState(next) {
    if (!next) return;
    const nextScale = typeof next.scale === 'number' ? next.scale : state.scale;
    const nextTx = typeof next.tx === 'number' ? next.tx : tx;
    const nextTy = typeof next.ty === 'number' ? next.ty : ty;
    state.scale = Math.max(0.2, Math.min(4, nextScale));
    tx = nextTx;
    ty = nextTy;
    applyTransform();
  }

  if (typeof ResizeObserver !== 'undefined') {
    const ro = new ResizeObserver(() => {
      const rect = wrapEl.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) requestFit();
    });
    ro.observe(wrapEl);
    state._resizeObserver = ro;
  }

  state.fitToView = fitToView;
  state.requestFit = requestFit;
  state.centerOnBox = centerOnBox;
  state.getViewState = getViewState;
  state.setViewState = setViewState;
  wrapEl._zoomState = state;
  return state;
}

function requestGraphFit(rootEl = document) {
  const wraps = rootEl.querySelectorAll('.cfg-svg-zoom');
  wraps.forEach((wrap) => {
    if (wrap.offsetParent === null) return;
    const rect = wrap.getBoundingClientRect();
    if (rect.width === 0 || rect.height === 0) return;
    if (wrap._zoomState?.requestFit) wrap._zoomState.requestFit();
    else if (wrap._zoomState?.fitToView) wrap._zoomState.fitToView();
  });
}

function cfgStackHintLabel(hint) {
  if (!hint || typeof hint !== 'object') return '';
  const name = String(hint.name || '').trim();
  if (!name) return '';
  return `${hint.kind === 'arg' ? 'arg' : 'var'} ${name}`;
}

function collectCfgLineMeta(ln) {
  return {
    label: String(ln?.label || '').trim(),
    comment: String(ln?.comment || '').trim(),
    stackHints: Array.isArray(ln?.stack_hints) ? ln.stack_hints.filter(Boolean) : [],
  };
}

function formatCfgLineDisplay(ln, maxLen = 56) {
  const code = String(ln?.text || '').trim();
  if (!code) return '';
  const meta = collectCfgLineMeta(ln);
  const hintLabels = meta.stackHints
    .map(cfgStackHintLabel)
    .filter(Boolean)
    .slice(0, 2);
  if (meta.stackHints.length > 2) hintLabels.push(`+${meta.stackHints.length - 2}`);
  const suffixParts = [];
  if (hintLabels.length) suffixParts.push(hintLabels.join(', '));
  if (meta.comment) suffixParts.push(meta.comment);
  const combined = suffixParts.length ? `${code} ; ${suffixParts.join(' • ')}` : code;
  return combined.length > maxLen ? `${combined.substring(0, maxLen - 1)}…` : combined;
}

function formatSwitchCaseLabel(value) {
  if (value === 'default') return 'default';
  if (typeof value === 'number') return `case ${value}`;
  if (String(value || '').trim()) return `case ${value}`;
  return '';
}

function summarizeSwitchCaseLabels(labels, opts = {}) {
  const values = Array.isArray(labels) ? labels.filter((label) => label !== null && label !== undefined) : [];
  if (!values.length) return '';
  const seen = new Set();
  const display = values
    .map((label) => formatSwitchCaseLabel(label))
    .filter((label) => {
      if (!label || seen.has(label)) return false;
      seen.add(label);
      return true;
    });
  if (!display.length) return '';
  const max = Number.isFinite(opts.max) ? opts.max : 2;
  if (display.length <= max) return display.join(' · ');
  return `${display.slice(0, max).join(' · ')} +${display.length - max}`;
}

function collectGraphNeighborhood(focusAddr, edges, radius = 1) {
  const focus = String(focusAddr || '').trim();
  if (!focus) return null;
  const depth = Math.max(0, Number(radius) || 0);
  const seen = new Set([focus]);
  let frontier = new Set([focus]);
  for (let step = 0; step < depth; step++) {
    const next = new Set();
    edges.forEach((edge) => {
      if (frontier.has(edge.from) && !seen.has(edge.to)) next.add(edge.to);
      if (frontier.has(edge.to) && !seen.has(edge.from)) next.add(edge.from);
    });
    next.forEach((addr) => seen.add(addr));
    frontier = next;
    if (frontier.size === 0) break;
  }
  return seen;
}

/**
 * Renders an interactive SVG graph (CFG or Call Graph).
 * Features: zoom/pan (via initCfgZoom), node drag, Shift+click BFS path highlight.
 *
 * @param {Array<{addr:string, label?:string, sublabel?:string, lines?:Array}>} nodes
 * @param {Array<{from:string, to:string, type?:string}>} edges
 * @param {{nodeW?:number, nodeH?:number, padX?:number, padY?:number, lanePadX?:number,
 *          onNodeClick?:Function, zoomState?:{scale:number}}} opts
 * @returns {SVGElement}
 */
function renderGraphSvg(nodes, edges, opts) {
  // Detect code mode (CFG with instructions) vs simple mode (Call Graph)
  const hasCode = nodes.some(n => n.lines && n.lines.length > 0);
  const initialExpandedSet = new Set((opts && opts.expandedAddrs) || []);
  const LINE_H = 14;
  const HEADER_H = 26;
  const PREVIEW_LINES = 4;
  const MAX_EXPANDED = 20;
  const COMPACT_H = HEADER_H + 12; // minimum block height used by preview/expanded modes
  const ADDR_X = 8;
  const CODE_X = 85;

  const longestLabel = nodes.reduce((max, n) => {
    const lengths = [
      String(n.label || '').length,
      String(n.sublabel || '').length,
    ];
    return Math.max(max, ...lengths);
  }, 0);
  const autoSimpleNodeW = Math.min(320, Math.max(220, 120 + longestLabel * 6));
  const nodeW = (opts && opts.nodeW) || (hasCode ? 360 : autoSimpleNodeW);
  const nodeH = (opts && opts.nodeH) || (hasCode ? 64 : 84);
  const padX = (opts && opts.padX) || (hasCode ? 84 : 96);
  const padY = (opts && opts.padY) || (hasCode ? 72 : 88);
  const onNodeClick = (opts && opts.onNodeClick) || null;
  const onNodeIsolate = (opts && opts.onNodeIsolate) || null;
  const zoomState = (opts && opts.zoomState) || { scale: 1 };

  // Pre-calculate per-node heights.
  // CFG blocks start in preview mode so the opening view stays readable
  // while still showing a few instructions in each block.
  const preHeights = {};
  for (const n of nodes) {
    if (hasCode && n.lines && n.lines.length > 0) {
      preHeights[n.addr] = initialExpandedSet.has(n.addr) ? expandedHeight(n) : previewHeight(n);
    } else {
      preHeights[n.addr] = nodeH;
    }
  }
  const nodeHeights = { ...preHeights };

  function previewHeight(nd) {
    const visibleLines = Math.min((nd.lines || []).length, PREVIEW_LINES);
    const extra = (nd.lines || []).length > PREVIEW_LINES ? LINE_H : 0;
    return Math.max(COMPACT_H, HEADER_H + visibleLines * LINE_H + extra + 10);
  }

  // Compute expanded height for a node
  function expandedHeight(nd) {
    const nLines = Math.min(nd.lines.length, MAX_EXPANDED);
    const extra = nd.lines.length > MAX_EXPANDED ? LINE_H : 0;
    return Math.max(60, HEADER_H + nLines * LINE_H + extra + 10);
  }

  // Use max height for layout spacing
  const maxH = Math.max(nodeH, ...Object.values(preHeights));
  const helpers = window.cfgHelpers;
  const layout = helpers.computeLayout(nodes, edges, {
    nodeW,
    nodeH: maxH,
    padX,
    padY,
    lanePadX: hasCode ? 34 : undefined,
    layoutMode: 'elk',
    maxPerRow: (opts && opts.maxPerRow) || (hasCode ? 4 : 5),
  });
  const nodePositions = {};
  for (const addr of Object.keys(layout.positions)) {
    nodePositions[addr] = { ...layout.positions[addr] };
  }

  const rowGroups = [];
  if (hasCode) {
    const rowMap = new Map();
    for (const n of nodes) {
      const l = layout.levels[n.addr];
      const p = nodePositions[n.addr];
      if (l === undefined || !p) continue;
      const key = `${l}|${p.y}`;
      if (!rowMap.has(key)) rowMap.set(key, { level: l, baseY: p.y, addrs: [] });
      rowMap.get(key).addrs.push(n.addr);
    }
    rowGroups.push(...rowMap.values());
    rowGroups.sort((a, b) => a.baseY - b.baseY || a.level - b.level);
    rowGroups.forEach((row) => {
      row.addrs.sort((a, b) => (nodePositions[a]?.x || 0) - (nodePositions[b]?.x || 0));
    });
  }

  const adj = helpers.buildAdjacency(edges);

  // Classify edges for back-edge (loop) rendering
  const { backEdges } = helpers.classifyEdges(edges, layout.levels);
  const backEdgeSet = new Set(backEdges.map(e => `${e.from}|${e.to}`));
  const forwardSourceLane = new Map();
  const forwardTargetLane = new Map();
  const backEdgeLane = new Map();
  const FORWARD_LANE_GAP = 18;
  const BACK_EDGE_LANE_GAP = 30;
  const MAX_LANE_OFFSET = Math.max(34, Math.floor(nodeW * 0.28));

  function edgeKey(from, to) {
    return `${from}|${to}`;
  }

  function centeredLane(index, count) {
    return index - (count - 1) / 2;
  }

  function clampLaneOffset(value) {
    return Math.max(-MAX_LANE_OFFSET, Math.min(MAX_LANE_OFFSET, value));
  }

  function groupEdgesBy(keySelector, list) {
    const map = new Map();
    list.forEach((edge) => {
      const key = keySelector(edge);
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(edge);
    });
    return map;
  }

  function compareNodePosition(addrA, addrB) {
    const a = nodePositions[addrA] || { x: 0, y: 0 };
    const b = nodePositions[addrB] || { x: 0, y: 0 };
    return a.y - b.y || a.x - b.x || String(addrA).localeCompare(String(addrB));
  }

  const forwardEdges = edges.filter((edge) => !backEdgeSet.has(edgeKey(edge.from, edge.to)));
  groupEdgesBy((edge) => edge.from, forwardEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.to, b.to));
    group.forEach((edge, index) => {
      forwardSourceLane.set(edgeKey(edge.from, edge.to), centeredLane(index, group.length));
    });
  });
  groupEdgesBy((edge) => edge.to, forwardEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.from, b.from));
    group.forEach((edge, index) => {
      forwardTargetLane.set(edgeKey(edge.from, edge.to), centeredLane(index, group.length));
    });
  });
  groupEdgesBy((edge) => edge.from, backEdges).forEach((group) => {
    group.sort((a, b) => compareNodePosition(a.to, b.to));
    group.forEach((edge, index) => {
      backEdgeLane.set(edgeKey(edge.from, edge.to), index);
    });
  });

  // Compute SVG dimensions from actual positions/heights
  let svgW = 600;
  let svgH = 400;
  for (const addr of Object.keys(nodePositions)) {
    const p = nodePositions[addr];
    const h = preHeights[addr] || nodeH;
    svgW = Math.max(svgW, p.x + nodeW + padX);
    svgH = Math.max(svgH, p.y + h + padY);
  }

  const NS = 'http://www.w3.org/2000/svg';
  const svgEl = document.createElementNS(NS, 'svg');
  svgEl.setAttribute('class', 'cfg-svg');
  svgEl.setAttribute('xmlns', NS);
  svgEl.setAttribute('width', svgW);
  svgEl.setAttribute('height', svgH);
  svgEl.setAttribute('viewBox', `0 0 ${svgW} ${svgH}`);
  svgEl.setAttribute('overflow', 'visible');

  const markerId = `arrow-${Date.now()}`;
  const defs = document.createElementNS(NS, 'defs');
  const marker = document.createElementNS(NS, 'marker');
  marker.id = markerId;
  marker.setAttribute('markerWidth', '10');
  marker.setAttribute('markerHeight', '7');
  marker.setAttribute('refX', '9');
  marker.setAttribute('refY', '3.5');
  marker.setAttribute('orient', 'auto');
  const arrowPoly = document.createElementNS(NS, 'polygon');
  arrowPoly.setAttribute('points', '0 0, 10 3.5, 0 7');
  arrowPoly.setAttribute('fill', '#8b949e');
  marker.appendChild(arrowPoly);
  defs.appendChild(marker);

  const backMarkerId = `arrow-back-${Date.now()}`;
  const backMarker = document.createElementNS(NS, 'marker');
  backMarker.id = backMarkerId;
  backMarker.setAttribute('markerWidth', '10');
  backMarker.setAttribute('markerHeight', '7');
  backMarker.setAttribute('refX', '9');
  backMarker.setAttribute('refY', '3.5');
  backMarker.setAttribute('orient', 'auto');
  const backArrowPoly = document.createElementNS(NS, 'polygon');
  backArrowPoly.setAttribute('points', '0 0, 10 3.5, 0 7');
  backArrowPoly.setAttribute('fill', '#d08770');
  backMarker.appendChild(backArrowPoly);
  defs.appendChild(backMarker);

  svgEl.appendChild(defs);

  if (hasCode && Array.isArray(layout.lanes) && layout.lanes.length > 0) {
    const laneGroup = document.createElementNS(NS, 'g');
    laneGroup.setAttribute('class', 'cfg-lanes');
    layout.lanes.forEach((lane) => {
      const leftX = Math.max(0, lane.x - padX * 0.35);
      const rightX = lane.x + lane.width + padX * 0.35;
      [leftX, rightX].forEach((x) => {
        const line = document.createElementNS(NS, 'line');
        line.setAttribute('x1', String(x));
        line.setAttribute('x2', String(x));
        line.setAttribute('y1', '8');
        line.setAttribute('y2', String(Math.max(0, svgH - 8)));
        line.setAttribute('stroke', 'rgba(255,255,255,0.12)');
        line.setAttribute('stroke-width', '1');
        line.setAttribute('stroke-dasharray', '4,6');
        laneGroup.appendChild(line);
      });
      const label = document.createElementNS(NS, 'text');
      label.setAttribute('x', String(lane.x + lane.width / 2));
      label.setAttribute('y', '24');
      label.setAttribute('fill', '#8b949e');
      label.setAttribute('font-size', '11');
      label.setAttribute('font-family', 'monospace');
      label.setAttribute('font-weight', '700');
      label.setAttribute('text-anchor', 'middle');
      label.textContent = lane.label;
      laneGroup.appendChild(label);
    });
    const flowLane = layout.lanes.find((lane) => lane.id === 'flow');
    if (flowLane) {
      const spineX = flowLane.x + flowLane.width / 2;
      const spine = document.createElementNS(NS, 'line');
      spine.setAttribute('x1', String(spineX));
      spine.setAttribute('x2', String(spineX));
      spine.setAttribute('y1', '32');
      spine.setAttribute('y2', String(Math.max(0, svgH - 12)));
      spine.setAttribute('stroke', 'rgba(136,216,255,0.28)');
      spine.setAttribute('stroke-width', '2');
      spine.setAttribute('stroke-dasharray', '10,8');
      laneGroup.appendChild(spine);
    }
    svgEl.appendChild(laneGroup);
  }

  const edgeGroup = document.createElementNS(NS, 'g');
  svgEl.appendChild(edgeGroup);
  const nodeGroup = document.createElementNS(NS, 'g');
  svgEl.appendChild(nodeGroup);

  function edgeColor(type) {
    return type === 'call' ? '#88c0d0'
      : type === 'jmp' ? '#b48ead'
      : type === 'jumptable' ? '#ebcb8b'
      : '#88d8ff';
  }

  // ── Orthogonal edge routing ───────────────────────────────────────────────
  // When ELK is used, edges carry `sections` with startPoint / bendPoints / endPoint.
  // We build the SVG path directly from those points (pure L segments = orthogonal).
  // For back-edges (loops) or when sections are absent, we fall back to the
  // hand-crafted routing below.

  /**
   * Build an SVG route descriptor from an ordered list of {x, y} points.
   * Returns { d, labelX, labelY, minX, maxX, minY, maxY }.
   */
  function buildEdgeRoute(points, labelPoint = null) {
    const clean = [];
    for (const pt of points) {
      if (!pt || !Number.isFinite(pt.x) || !Number.isFinite(pt.y)) continue;
      const p = { x: Math.round(pt.x * 10) / 10, y: Math.round(pt.y * 10) / 10 };
      const prev = clean[clean.length - 1];
      if (!prev || prev.x !== p.x || prev.y !== p.y) clean.push(p);
    }
    if (!clean.length) return { d: '', labelX: 0, labelY: 0, minX: 0, maxX: 0, minY: 0, maxY: 0 };
    let d = `M ${clean[0].x} ${clean[0].y}`;
    for (let i = 1; i < clean.length; i++) d += ` L ${clean[i].x} ${clean[i].y}`;
    const xs = clean.map(p => p.x);
    const ys = clean.map(p => p.y);
    const mid = clean[Math.floor(clean.length / 2)] || clean[0];
    const lp = labelPoint && Number.isFinite(labelPoint.x) && Number.isFinite(labelPoint.y)
      ? { x: Math.round(labelPoint.x * 10) / 10, y: Math.round(labelPoint.y * 10) / 10 }
      : mid;
    return { d, labelX: lp.x, labelY: lp.y, minX: Math.min(...xs), maxX: Math.max(...xs), minY: Math.min(...ys), maxY: Math.max(...ys) };
  }

  /**
   * Compute a fully dynamic orthogonal SVG path for a forward edge.
   *
   * Always uses live nodePositions + nodeHeights so the path stays connected
   * after expand/collapse, regardless of what ELK computed at layout time.
   *
   * Routing rules:
   *   - Departs from the bottom-center of the source block.
   *   - Arrives at the top-center of the target block.
   *   - A single horizontal bend at the midpoint of the vertical gap → pure orthogonal.
   *   - When multiple edges leave the same source or arrive at the same target,
   *     a small horizontal lane offset separates them so they don't overlap.
   *   - When source and target are at the same Y (or very close), detour right.
   */
  function computeEdgeD(from, to) {
    const fp = nodePositions[from];
    const tp = nodePositions[to];
    if (!fp || !tp) return buildEdgeRoute([]);

    const fromH = nodeHeights[from] || nodeH;
    const toH   = nodeHeights[to]   || nodeH;
    const key   = edgeKey(from, to);

    // Lane offsets separate parallel edges leaving/entering the same node.
    const srcLane = clampLaneOffset((forwardSourceLane.get(key) || 0) * FORWARD_LANE_GAP);
    const dstLane = clampLaneOffset((forwardTargetLane.get(key) || 0) * FORWARD_LANE_GAP);

    // Anchor points — always on the node boundary, never floating
    const x1 = fp.x + nodeW / 2 + srcLane;   // bottom-center of source (± lane offset)
    const y1 = fp.y + fromH;                   // bottom edge of source
    const x2 = tp.x + nodeW / 2 + dstLane;   // top-center of target (± lane offset)
    const y2 = tp.y;                            // top edge of target

    const spanY = y2 - y1;

    // ── Case A: same row or near-miss (spanY tiny) ──────────────────────────
    // Exit from the right side of the source and enter from the left of the target
    // to keep the path readable. Fully orthogonal: H → V → H.
    if (spanY < 16) {
      const rightEdge = Math.max(fp.x + nodeW, tp.x + nodeW);
      const detourX   = rightEdge + 48 + Math.abs(srcLane - dstLane) * 0.5;
      const midY      = (fp.y + fromH / 2 + tp.y + toH / 2) / 2;
      return buildEdgeRoute([
        { x: fp.x + nodeW, y: fp.y + fromH / 2 }, // exit right side of source
        { x: detourX,      y: fp.y + fromH / 2 }, // go right
        { x: detourX,      y: tp.y  + toH  / 2 }, // go down/up (V)
        { x: tp.x,         y: tp.y  + toH  / 2 }, // enter left side of target
      ], { x: detourX + 6, y: midY });
    }

    // ── Case B: normal forward edge — strictly orthogonal 5-point path ──────
    //
    //   x1,y1 ──(V)──> x1,channelY ──(H)──> x2,channelY ──(V)──> x2,y2
    //
    // This produces exactly two 90° turns and zero diagonal segments.
    // The horizontal channel sits halfway between the two nodes' gaps.
    const channelY = y1 + spanY / 2;

    const pts = [
      { x: x1, y: y1        },   // departure  — bottom of source
      { x: x1, y: channelY  },   // drop vertically to channel
      { x: x2, y: channelY  },   // move horizontally to target column
      { x: x2, y: y2        },   // rise vertically into target top
    ];

    const labelPt = { x: (x1 + x2) / 2, y: channelY - 10 };
    return buildEdgeRoute(pts, labelPt);
  }

  /**
   * Compute a fully dynamic orthogonal SVG path for a back-edge (loop).
   *
   * Always uses live nodePositions + nodeHeights.
   * Routes out of the right side of the source, around, and back into
   * the left side of the target to avoid overlapping forward edges.
   */
  function computeBackEdgeD(from, to) {
    const fp = nodePositions[from];
    const tp = nodePositions[to];
    if (!fp || !tp) return buildEdgeRoute([]);

    const fromH = nodeHeights[from] || nodeH;
    const toH   = nodeHeights[to]   || nodeH;
    const key   = edgeKey(from, to);
    const laneIndex = backEdgeLane.get(key) || 0;

    // Exit from bottom-right of source, enter top-left of target
    const x1 = fp.x + nodeW;                                               // right edge of source
    const y1 = fp.y + fromH - Math.min(12, fromH * 0.25);                 // near-bottom of source
    const x2 = tp.x;                                                        // left edge of target
    const y2 = tp.y + Math.min(12, toH * 0.25);                           // near-top of target

    // Detour column: far enough right to clear all nodes in both rows
    const rightEdge = Math.max(fp.x + nodeW, tp.x + nodeW);
    const detourX   = rightEdge + 48 + laneIndex * BACK_EDGE_LANE_GAP;

    return buildEdgeRoute([
      { x: x1,      y: y1 },        // exit right side of source
      { x: detourX, y: y1 },        // go right to detour column
      { x: detourX, y: y2 },        // drop/rise to target row
      { x: x2,      y: y2 },        // enter left side of target
    ], { x: detourX + 6, y: (y1 + y2) / 2 });
  }

  // Track which code nodes are expanded (collapsed by default on first render).
  const expandedNodes = new Set(nodes
    .filter((n) => hasCode && n.lines && n.lines.length > 0 && initialExpandedSet.has(n.addr))
    .map((n) => n.addr));
  let activeNodeAddr = null;
  const nodeEls = {};
  const edgeEls = {};
  const edgeRouteCache = {};
  const edgeLabelEls = [];

  function applyCodeRowLayout() {
    if (!hasCode || rowGroups.length === 0) return;
    let nextY = rowGroups[0].baseY;
    rowGroups.forEach((row) => {
      const rowMaxH = row.addrs.reduce((max, addr) => {
        return Math.max(max, nodeHeights[addr] || preHeights[addr] || nodeH);
      }, COMPACT_H);
      row.addrs.forEach((addr) => {
        const pos = nodePositions[addr];
        if (!pos) return;
        pos.y = nextY;
        nodeEls[addr]?.setAttribute('transform', `translate(${pos.x},${pos.y})`);
      });
      nextY += rowMaxH + padY;
    });
  }

  function updateEdgeGeometry(changedAddr = null) {
    Object.entries(edgeEls).forEach(([key, pathEl]) => {
      const [from, to] = key.split('|');
      if (changedAddr && from !== changedAddr && to !== changedAddr) return;
      const isBack = backEdgeSet.has(key);
      const route = isBack ? computeBackEdgeD(from, to) : computeEdgeD(from, to);
      edgeRouteCache[key] = route;
      pathEl.setAttribute('d', route.d);
    });
    edgeLabelEls.forEach(({ edge, labelEl }) => {
      if (changedAddr && edge.from !== changedAddr && edge.to !== changedAddr) return;
      const key = edgeKey(edge.from, edge.to);
      const route = edgeRouteCache[key]
        || (backEdgeSet.has(key) ? computeBackEdgeD(edge.from, edge.to) : computeEdgeD(edge.from, edge.to));
      edgeRouteCache[key] = route;
      labelEl.setAttribute('x', String(Math.round(route.labelX)));
      labelEl.setAttribute('y', String(Math.round(route.labelY)));
    });
  }

  function resolveNodeAddress(addr) {
    const normalized = normalizeHexAddress(addr);
    if (!normalized) return null;
    for (const n of nodes) {
      if (normalizeHexAddress(n.addr) === normalized) return n.addr;
      if (hasCode && Array.isArray(n.lines) && n.lines.some((ln) => normalizeHexAddress(ln.addr) === normalized)) {
        return n.addr;
      }
    }
    return null;
  }

  function applyActiveNode(addr) {
    if (activeNodeAddr && nodeEls[activeNodeAddr]) nodeEls[activeNodeAddr].classList.remove('is-active');
    activeNodeAddr = addr || null;
    if (activeNodeAddr && nodeEls[activeNodeAddr]) nodeEls[activeNodeAddr].classList.add('is-active');
    svgEl.dataset.activeNodeAddr = activeNodeAddr || '';
    return activeNodeAddr;
  }

  function getNodeBox(addr) {
    const pos = nodePositions[addr];
    if (!pos) return null;
    return {
      x: pos.x,
      y: pos.y,
      w: nodeW,
      h: nodeHeights[addr] || nodeH,
    };
  }

  function appendInstructionLine(group, ln, y) {
    const lineAddr = (ln.addr || '').replace(/^0x0*/, '0x');
    const lineText = formatCfgLineDisplay(ln);

    const addrEl = document.createElementNS(NS, 'text');
    addrEl.setAttribute('x', ADDR_X);
    addrEl.setAttribute('y', y);
    addrEl.setAttribute('fill', '#6a737d');
    addrEl.setAttribute('font-size', '10');
    addrEl.setAttribute('font-family', 'monospace');
    addrEl.textContent = lineAddr;
    group.appendChild(addrEl);

    const codeEl = document.createElementNS(NS, 'text');
    codeEl.setAttribute('x', CODE_X);
    codeEl.setAttribute('y', y);
    codeEl.setAttribute('fill', '#d4d4d4');
    codeEl.setAttribute('font-size', '10');
    codeEl.setAttribute('font-family', 'monospace');
    codeEl.textContent = lineText;
    group.appendChild(codeEl);
  }

  edges.forEach((e) => {
    const key = `${e.from}|${e.to}`;
    const isBack = backEdgeSet.has(key);
    const route = isBack ? computeBackEdgeD(e.from, e.to) : computeEdgeD(e.from, e.to);
    edgeRouteCache[key] = route;
    const pathEl = document.createElementNS(NS, 'path');
    pathEl.setAttribute('class', isBack ? 'cfg-edge cfg-back-edge' : 'cfg-edge');
    pathEl.dataset.from = e.from;
    pathEl.dataset.to = e.to;
    pathEl.setAttribute('d', route.d);
    pathEl.setAttribute('fill', 'none');
    pathEl.setAttribute('stroke', isBack ? '#d08770' : edgeColor(e.type));
    pathEl.setAttribute('stroke-width', '2');
    if (isBack) pathEl.setAttribute('stroke-dasharray', '6,3');
    pathEl.setAttribute('marker-end', `url(#${isBack ? backMarkerId : markerId})`);
    edgeGroup.appendChild(pathEl);
    edgeEls[key] = pathEl;

    if (e.type === 'jumptable' && e.case_label !== undefined && e.case_label !== null) {
      if (route.d) {
        const labelEl = document.createElementNS(NS, 'text');
        labelEl.setAttribute('x', String(Math.round(route.labelX)));
        labelEl.setAttribute('y', String(Math.round(route.labelY)));
        labelEl.setAttribute('fill', '#ebcb8b');
        labelEl.setAttribute('font-size', '9');
        labelEl.setAttribute('font-family', 'monospace');
        labelEl.setAttribute('text-anchor', 'middle');
        labelEl.setAttribute('pointer-events', 'none');
        labelEl.textContent = `case ${e.case_label}`;
        edgeGroup.appendChild(labelEl);
        edgeLabelEls.push({ edge: e, labelEl });
      }
    }
  });

  const nodeDataMap = {};
  nodes.forEach(n => { nodeDataMap[n.addr] = n; });

  nodes.forEach((n) => {
    const p = nodePositions[n.addr] || { x: 0, y: 0 };
    const h = preHeights[n.addr] || nodeH;
    nodeHeights[n.addr] = h;
    const g = document.createElementNS(NS, 'g');
    g.setAttribute('class', 'cfg-node');
    g.dataset.addr = n.addr;
    g.setAttribute('transform', `translate(${p.x},${p.y})`);
    g.setAttribute('tabindex', '0');
    g.style.cursor = 'pointer';

    const isExt = n.isExternal;
    const strokeColor = isExt ? '#88c0d0' : '#88d8ff';

    // Background rect
    const rect = document.createElementNS(NS, 'rect');
    rect.setAttribute('width', nodeW);
    rect.setAttribute('height', h);
    rect.setAttribute('rx', hasCode ? '2' : '8');
    rect.setAttribute('fill', hasCode ? '#111827' : '#1a1a2e');
    rect.setAttribute('stroke', strokeColor);
    rect.setAttribute('stroke-width', hasCode ? '1.2' : '2');
    if (isExt) rect.setAttribute('stroke-dasharray', '4,2');
    g.appendChild(rect);

    const label = n.label || n.addr.replace(/^0x/, '');

    if (hasCode && n.lines && n.lines.length > 0) {
      // ── Cutter-style: header + collapsible instructions ──
      const hasStackHints = n.lines.some((ln) => Array.isArray(ln.stack_hints) && ln.stack_hints.length > 0);
      const hasComments = n.lines.some((ln) => String(ln.comment || '').trim().length > 0);

      // Header background (accent strip at top)
      const headerBg = document.createElementNS(NS, 'rect');
      headerBg.setAttribute('x', '2');
      headerBg.setAttribute('y', '2');
      headerBg.setAttribute('width', nodeW - 4);
      headerBg.setAttribute('height', HEADER_H - 2);
      headerBg.setAttribute('rx', '1');
      headerBg.setAttribute('fill', strokeColor);
      headerBg.setAttribute('opacity', '0.15');
      g.appendChild(headerBg);

      // Header label (block addr / function name)
      const hLabel = document.createElementNS(NS, 'text');
      hLabel.setAttribute('x', ADDR_X);
      hLabel.setAttribute('y', '17');
      hLabel.setAttribute('fill', strokeColor);
      hLabel.setAttribute('font-size', '11');
      hLabel.setAttribute('font-weight', '700');
      hLabel.setAttribute('font-family', 'monospace');
      hLabel.textContent = label.length > 36 ? label.substring(0, 34) + '\u2026' : label;
      g.appendChild(hLabel);

      const badgeSpecs = [];
      if (n.is_switch) badgeSpecs.push({ text: 'switch', color: '#ebcb8b' });
      const caseSummary = summarizeSwitchCaseLabels(n.caseLabels || [], { max: 2 });
      if (caseSummary) badgeSpecs.push({ text: caseSummary, color: '#ffd166', title: summarizeSwitchCaseLabels(n.caseLabels || [], { max: 12 }) });
      if (hasStackHints) badgeSpecs.push({ text: 'stack', color: '#9cdfff' });
      if (hasComments) badgeSpecs.push({ text: 'notes', color: '#c3e88d' });
      let badgeOffset = 0;
      badgeSpecs.forEach((badge) => {
        const badgeEl = document.createElementNS(NS, 'text');
        badgeEl.setAttribute('x', String(nodeW - 6 - badgeOffset));
        badgeEl.setAttribute('y', '10');
        badgeEl.setAttribute('fill', badge.color);
        badgeEl.setAttribute('font-size', '9');
        badgeEl.setAttribute('font-family', 'monospace');
        badgeEl.setAttribute('text-anchor', 'end');
        badgeEl.setAttribute('pointer-events', 'none');
        badgeEl.textContent = badge.text;
        if (badge.title) badgeEl.setAttribute('title', badge.title);
        g.appendChild(badgeEl);
        badgeOffset += Math.max(46, badge.text.length * 6 + 10);
      });

      // Caret + instruction count (right-aligned) — double-click for more/less code
      const caretEl = document.createElementNS(NS, 'text');
      caretEl.setAttribute('x', nodeW - 6);
      caretEl.setAttribute('y', '17');
      caretEl.setAttribute('text-anchor', 'end');
      caretEl.setAttribute('fill', '#6a737d');
      caretEl.setAttribute('font-size', '11');
      caretEl.setAttribute('font-family', 'monospace');
      caretEl.setAttribute('class', 'cfg-node-caret');
      const startsExpanded = expandedNodes.has(n.addr);
      caretEl.textContent = `${n.lines.length}\u202f${startsExpanded ? '\u25be' : '\u25b8'}`;
      g.appendChild(caretEl);

      // Body group (preview instructions) — visible by default
      const bodyGroup = document.createElementNS(NS, 'g');
      bodyGroup.setAttribute('class', 'cfg-node-body');

      // Separator line inside bodyGroup
      const sep = document.createElementNS(NS, 'line');
      sep.setAttribute('x1', '4');
      sep.setAttribute('y1', HEADER_H);
      sep.setAttribute('x2', nodeW - 4);
      sep.setAttribute('y2', HEADER_H);
      sep.setAttribute('stroke', '#333');
      sep.setAttribute('stroke-width', '1');
      bodyGroup.appendChild(sep);

      const previewCount = Math.min(n.lines.length, PREVIEW_LINES);
      const expandedCount = Math.min(n.lines.length, MAX_EXPANDED);
      for (let i = 0; i < previewCount; i++) {
        const y = HEADER_H + 4 + (i + 1) * LINE_H;
        appendInstructionLine(bodyGroup, n.lines[i], y);
      }

      let previewMoreEl = null;
      if (n.lines.length > PREVIEW_LINES) {
        const moreY = HEADER_H + 4 + (previewCount + 1) * LINE_H;
        previewMoreEl = document.createElementNS(NS, 'text');
        previewMoreEl.setAttribute('x', ADDR_X);
        previewMoreEl.setAttribute('y', moreY);
        previewMoreEl.setAttribute('fill', '#6a737d');
        previewMoreEl.setAttribute('font-size', '10');
        previewMoreEl.setAttribute('font-family', 'monospace');
        previewMoreEl.setAttribute('font-style', 'italic');
        previewMoreEl.textContent = `\u2026 +${n.lines.length - PREVIEW_LINES} lignes`;
        previewMoreEl.style.display = startsExpanded ? 'none' : '';
        bodyGroup.appendChild(previewMoreEl);
      }

      g.appendChild(bodyGroup);

      const extraGroup = document.createElementNS(NS, 'g');
      extraGroup.setAttribute('class', 'cfg-node-extra');
      extraGroup.style.display = startsExpanded ? '' : 'none';

      for (let i = previewCount; i < expandedCount; i++) {
        const y = HEADER_H + 4 + (i + 1) * LINE_H;
        appendInstructionLine(extraGroup, n.lines[i], y);
      }

      let extraMoreEl = null;
      if (n.lines.length > MAX_EXPANDED) {
        const moreY = HEADER_H + 4 + (expandedCount + 1) * LINE_H;
        extraMoreEl = document.createElementNS(NS, 'text');
        extraMoreEl.setAttribute('x', ADDR_X);
        extraMoreEl.setAttribute('y', moreY);
        extraMoreEl.setAttribute('fill', '#6a737d');
        extraMoreEl.setAttribute('font-size', '10');
        extraMoreEl.setAttribute('font-family', 'monospace');
        extraMoreEl.setAttribute('font-style', 'italic');
        extraMoreEl.textContent = `\u2026 +${n.lines.length - MAX_EXPANDED} lignes`;
        extraGroup.appendChild(extraMoreEl);
      }

      g.appendChild(extraGroup);

      // Store refs for toggle handler
      g._bodyGroup = bodyGroup;
      g._extraGroup = extraGroup;
      g._caretEl = caretEl;
      g._previewMoreEl = previewMoreEl;
      g._extraMoreEl = extraMoreEl;
      g._nLines = n.lines.length;

    } else {
      // ── Simple mode: label + sublabel (Call Graph) ──
      const t1 = document.createElementNS(NS, 'text');
      t1.setAttribute('x', nodeW / 2);
      t1.setAttribute('y', h / 2 + (n.sublabel ? -4 : 4));
      t1.setAttribute('text-anchor', 'middle');
      t1.setAttribute('fill', strokeColor);
      t1.setAttribute('font-size', '12');
      t1.setAttribute('font-weight', '600');
      t1.textContent = label.length > 32 ? label.substring(0, 30) + '\u2026' : label;
      g.appendChild(t1);

      if (n.sublabel) {
        const t2 = document.createElementNS(NS, 'text');
        t2.setAttribute('x', nodeW / 2);
        t2.setAttribute('y', h / 2 + 14);
        t2.setAttribute('text-anchor', 'middle');
        t2.setAttribute('fill', '#8b949e');
        t2.setAttribute('font-size', '10');
        t2.textContent = n.sublabel;
        g.appendChild(t2);
      }
    }

    nodeGroup.appendChild(g);
    nodeEls[n.addr] = g;
  });

  // --- Dynamic SVG bounds (no invisible walls) ---
  function updateSvgBounds() {
    const addrs = Object.keys(nodePositions);
    if (addrs.length === 0) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const addr of addrs) {
      const p = nodePositions[addr];
      const h = nodeHeights[addr] || nodeH;
      if (p.x < minX) minX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.x + nodeW > maxX) maxX = p.x + nodeW;
      if (p.y + h > maxY) maxY = p.y + h;
    }
    Object.values(edgeRouteCache).forEach((route) => {
      if (!route || !route.d) return;
      if (route.minX < minX) minX = route.minX;
      if (route.minY < minY) minY = route.minY;
      if (route.maxX > maxX) maxX = route.maxX;
      if (route.maxY > maxY) maxY = route.maxY;
    });
    const pad = 40;
    const vbX = Math.min(0, minX - pad);
    const vbY = Math.min(0, minY - pad);
    const newW = Math.max(600, maxX + pad - vbX);
    const newH = Math.max(400, maxY + pad - vbY);
    if (newW !== svgW || newH !== svgH || vbX < 0 || vbY < 0) {
      svgW = newW;
      svgH = newH;
      svgEl.setAttribute('width', svgW);
      svgEl.setAttribute('height', svgH);
      svgEl.setAttribute('viewBox', `${vbX} ${vbY} ${svgW} ${svgH}`);
    }
  }

  applyCodeRowLayout();
  updateEdgeGeometry();
  updateSvgBounds();
  svgEl._resolveNodeAddress = resolveNodeAddress;
  svgEl._setActiveAddress = (addr) => applyActiveNode(resolveNodeAddress(addr));
  svgEl._setActiveNode = (addr) => applyActiveNode(addr);
  svgEl._getNodeBox = getNodeBox;

  // --- Node drag ---
  let dragAddr = null;
  let dragStart = { cx: 0, cy: 0, nx: 0, ny: 0 };
  let didDrag = false;

  nodeGroup.addEventListener('mousedown', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || e.shiftKey || e.altKey || e.metaKey || e.ctrlKey || e.button !== 0) return;
    e.stopPropagation();
    dragAddr = nodeEl.dataset.addr;
    const p = nodePositions[dragAddr] || { x: 0, y: 0 };
    dragStart = { cx: e.clientX, cy: e.clientY, nx: p.x, ny: p.y };
    didDrag = false;
  });

  document.addEventListener('mousemove', (e) => {
    if (!dragAddr) return;
    const s = zoomState.scale || 1;
    const dx = (e.clientX - dragStart.cx) / s;
    const dy = (e.clientY - dragStart.cy) / s;
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) didDrag = true;
    if (!didDrag) return;
    const nx = dragStart.nx + dx;
    const ny = dragStart.ny + dy;
    nodePositions[dragAddr] = { x: nx, y: ny };
    nodeEls[dragAddr]?.setAttribute('transform', `translate(${nx},${ny})`);
    updateEdgeGeometry(dragAddr);
    updateSvgBounds();
  });

  document.addEventListener('mouseup', () => { dragAddr = null; });

  nodeGroup.addEventListener('contextmenu', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || !onNodeIsolate) return;
    e.preventDefault();
    e.stopPropagation();
    onNodeIsolate(nodeEl.dataset.addr);
  });

  // --- Shift+click BFS path highlight ---
  const HIGHLIGHT = '#ffd700';
  let hlStart = null;

  function clearHighlight() {
    edgeGroup.querySelectorAll('.cfg-edge').forEach((pathEl) => {
      const key = `${pathEl.dataset.from}|${pathEl.dataset.to}`;
      const isBack = backEdgeSet.has(key);
      const e = edges.find((ed) => ed.from === pathEl.dataset.from && ed.to === pathEl.dataset.to);
      pathEl.setAttribute('stroke', isBack ? '#d08770' : edgeColor(e ? e.type : ''));
      pathEl.setAttribute('stroke-width', '2');
      if (isBack) {
        pathEl.setAttribute('stroke-dasharray', '6,3');
      } else {
        pathEl.removeAttribute('stroke-dasharray');
      }
    });
    Object.entries(nodeEls).forEach(([addr, g]) => {
      const nd = nodeDataMap[addr];
      const extNode = nd && nd.isExternal;
      const r = g.querySelector('rect');
      if (r) r.setAttribute('stroke', extNode ? '#88c0d0' : '#88d8ff');
    });
  }

  nodeGroup.addEventListener('click', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || didDrag) return;
    const addr = nodeEl.dataset.addr;

    if (e.altKey && onNodeIsolate) {
      e.preventDefault();
      onNodeIsolate(addr);
      return;
    }

    if (e.shiftKey) {
      if (!hlStart) {
        hlStart = addr;
        nodeEl.querySelector('rect')?.setAttribute('stroke', HIGHLIGHT);
      } else {
        const path = window.cfgHelpers.bfsPath(adj, hlStart, addr);
        clearHighlight();
        hlStart = null;
        if (path && path.length > 1) {
          path.forEach((a) => nodeEls[a]?.querySelector('rect')?.setAttribute('stroke', HIGHLIGHT));
          for (let i = 0; i < path.length - 1; i++) {
            const el = edgeEls[`${path[i]}|${path[i + 1]}`];
            if (el) { el.setAttribute('stroke', HIGHLIGHT); el.setAttribute('stroke-width', '3'); }
          }
        }
      }
      return;
    }

    clearHighlight();
    hlStart = null;
    applyActiveNode(resolveNodeAddress(addr));
    if (onNodeClick && addr !== lastDblClickAddr) onNodeClick(addr);
  });

  // --- Double-click: expand/collapse code node ---
  // Flag to prevent the two rapid clicks of a dblclick from firing onNodeClick
  let lastDblClickAddr = null;
  nodeGroup.addEventListener('dblclick', (e) => {
    if (!hasCode) return;
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl || !nodeEl._extraGroup) return;
    e.stopPropagation();
    const addr = nodeEl.dataset.addr;
    lastDblClickAddr = addr;
    setTimeout(() => { if (lastDblClickAddr === addr) lastDblClickAddr = null; }, 300);
    const nd = nodeDataMap[addr];
    if (!nd || !nd.lines || nd.lines.length === 0) return;

    const isExpanded = expandedNodes.has(addr);
    const rect = nodeEl.querySelector('rect');

    if (isExpanded) {
      expandedNodes.delete(addr);
      nodeEl._extraGroup.style.display = 'none';
      if (nodeEl._previewMoreEl) nodeEl._previewMoreEl.style.display = '';
      if (nodeEl._extraMoreEl) nodeEl._extraMoreEl.style.display = 'none';
      nodeEl._caretEl.textContent = `${nd.lines.length}\u202f\u25b8`;
      const h = previewHeight(nd);
      if (rect) rect.setAttribute('height', h);
      nodeHeights[addr] = h;
    } else {
      expandedNodes.add(addr);
      nodeEl._extraGroup.style.display = '';
      if (nodeEl._previewMoreEl) nodeEl._previewMoreEl.style.display = 'none';
      if (nodeEl._extraMoreEl) nodeEl._extraMoreEl.style.display = '';
      nodeEl._caretEl.textContent = `${nd.lines.length}\u202f\u25be`;
      const h = expandedHeight(nd);
      if (rect) rect.setAttribute('height', h);
      nodeHeights[addr] = h;
    }

    if (typeof opts?.onExpandedChange === 'function') {
      opts.onExpandedChange(Array.from(expandedNodes));
    }
    applyCodeRowLayout();
    updateEdgeGeometry();
    updateSvgBounds();
  });

  // --- Rich tooltip ---
  const tooltipEl = document.createElement('div');
  tooltipEl.className = 'cfg-tooltip';

  nodeGroup.addEventListener('mouseover', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (!nodeEl) return;
    nodeEl.querySelector('rect')?.setAttribute('stroke', '#81a1c1');
    const addr = nodeEl.dataset.addr;
    const nd = nodeDataMap[addr];
    if (!nd) return;

    // Build tooltip content
    const titleDiv = document.createElement('div');
    titleDiv.className = 'cfg-tooltip-title';
    titleDiv.textContent = nd.label || nd.addr;

    tooltipEl.replaceChildren(titleDiv);

    if (nd.sublabel) {
      const subDiv = document.createElement('div');
      subDiv.className = 'cfg-tooltip-sub';
      subDiv.textContent = nd.sublabel;
      tooltipEl.appendChild(subDiv);
    }

    if (nd.lines && nd.lines.length > 0) {
      const codeDiv = document.createElement('div');
      codeDiv.className = 'cfg-tooltip-code';
      const maxLines = Math.min(nd.lines.length, 15);
      nd.lines.slice(0, maxLines).forEach((ln) => {
        const lineEl = document.createElement('div');
        lineEl.className = 'cfg-tooltip-line';
        lineEl.textContent = formatCfgLineDisplay(ln, 90);
        codeDiv.appendChild(lineEl);
        const meta = collectCfgLineMeta(ln);
        if (meta.label || meta.comment || meta.stackHints.length) {
          const metaWrap = document.createElement('div');
          metaWrap.className = 'cfg-tooltip-meta';
          if (meta.label) {
            const labelEl = document.createElement('span');
            labelEl.className = 'cfg-tooltip-label';
            labelEl.textContent = `label ${meta.label}`;
            metaWrap.appendChild(labelEl);
          }
          if (meta.comment) {
            const commentEl = document.createElement('span');
            commentEl.className = 'cfg-tooltip-comment';
            commentEl.textContent = meta.comment;
            metaWrap.appendChild(commentEl);
          }
          if (meta.stackHints.length) {
            const hintsEl = document.createElement('div');
            hintsEl.className = 'xref-stack-hints cfg-tooltip-hints';
            meta.stackHints.slice(0, 4).forEach((hint) => {
              const chip = document.createElement('span');
              chip.className = 'xref-stack-chip';
              const label = cfgStackHintLabel(hint);
              chip.textContent = label || 'stack';
              if (hint.location) chip.title = `${chip.textContent} @ ${hint.location}`;
              hintsEl.appendChild(chip);
            });
            metaWrap.appendChild(hintsEl);
          }
          codeDiv.appendChild(metaWrap);
        }
      });
      if (nd.lines.length > maxLines) {
        const moreEl = document.createElement('div');
        moreEl.className = 'cfg-tooltip-more';
        moreEl.textContent = '\u2026';
        codeDiv.appendChild(moreEl);
      }
      tooltipEl.appendChild(codeDiv);
    }

    tooltipEl.style.display = 'block';
  });

  nodeGroup.addEventListener('mousemove', (e) => {
    if (tooltipEl.style.display !== 'block') return;
    const x = e.clientX + 12;
    const y = e.clientY + 12;
    const maxX = window.innerWidth - 380;
    const maxY = window.innerHeight - tooltipEl.offsetHeight - 10;
    tooltipEl.style.left = Math.min(x, maxX) + 'px';
    tooltipEl.style.top = Math.min(y, maxY) + 'px';
  });

  nodeGroup.addEventListener('mouseout', (e) => {
    const nodeEl = e.target.closest('.cfg-node');
    if (nodeEl && nodeEl.dataset.addr !== hlStart) {
      const nd = nodeDataMap[nodeEl.dataset.addr];
      nodeEl.querySelector('rect')?.setAttribute('stroke', (nd && nd.isExternal) ? '#88c0d0' : '#88d8ff');
    }
    tooltipEl.style.display = 'none';
  });

  svgEl._tooltip = tooltipEl;
  return svgEl;
}

function renderStringsTable(container, strings, filterText, useRegex) {
  let filtered = strings;
  let regexError = false;
  if (filterText) {
    if (useRegex) {
      try {
        const re = new RegExp(filterText);
        filtered = strings.filter((s) => re.test(String(s.value)));
      } catch {
        filtered = [];
        regexError = true;
      }
    } else {
      const q = filterText.toLowerCase();
      filtered = strings.filter((s) => String(s.value).toLowerCase().includes(q));
    }
  }
  const toShow = filtered.slice(0, 500);
  const encodingLabel = (encoding) => {
    if (encoding === 'utf-16-le') return 'UTF-16 LE';
    if (encoding === 'utf-16-be') return 'UTF-16 BE';
    return 'UTF-8 / ASCII';
  };
  const rows = toShow.map((s) => {
    const val = String(s.value);
    const display = val.length > 80 ? val.substring(0, 80) + '…' : val;
    const addr = escapeHtml(String(s.addr || ''));
    const spanLength = Math.max(1, Number(s.length || val.length || 1));
    return `<tr class="nav-addr-row" data-addr="${addr}" data-addr-match="span" data-span-length="${escapeHtml(String(spanLength))}"><td><code class="addr-link" data-addr="${addr}" data-span="${escapeHtml(String(spanLength))}">${addr}</code></td><td>${escapeHtml(encodingLabel(String(s.encoding || 'utf-8')))}</td><td>${escapeHtml(String(s.length))}</td><td>${escapeHtml(display)}</td></tr>`;
  }).join('');
  const hintCls = regexError ? 'hint error' : 'hint';
  let hint = regexError ? 'Regex invalide' : (filterText ? `${filtered.length} / ${strings.length} chaîne(s)` : `${strings.length} chaîne(s)`);
  const encodingCounts = filtered.reduce((acc, entry) => {
    const key = String(entry.encoding || 'utf-8');
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const encodingSummary = Object.entries(encodingCounts)
    .map(([encoding, count]) => `${encodingLabel(encoding)}: ${count}`)
    .join(' · ');
  hint += ' — Les adresses sont des adresses virtuelles.';
  if (encodingSummary) hint += ` — ${encodingSummary}`;
  container.innerHTML = `<table class="data-table"><thead><tr><th>Adresse</th><th>Encodage</th><th>Long.</th><th>Valeur</th></tr></thead><tbody>${rows}</tbody></table><p class="${hintCls}">${hint}</p>`;
  container.querySelectorAll('.addr-link[data-addr]').forEach((link) => {
    link.addEventListener('click', (event) => {
      event.preventDefault();
      const binaryPath = getStaticBinaryPath();
      const addr = link.dataset.addr || '';
      if (!binaryPath || !addr) return;
      vscode.postMessage({ type: 'hubGoToAddress', binaryPath, addr });
    });
  });
  updateActiveNavRows(window._lastDisasmAddr);
  if (pendingStringsFocusAddr) {
    focusStringsAddress(pendingStringsFocusAddr, { reveal: true, consume: true });
  }
}


function initSearchListeners() {
staticBinaryInput?.addEventListener('change', () => {
  syncDynamicBinaryFieldMode();
  syncStaticWorkspaceSummary();
});

document.getElementById('btnGoToAddr')?.addEventListener('click', () => {
  const val = document.getElementById('goToAddrInput')?.value?.trim();
  if (!val) return;
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  const looksLikeAddr = /^(0x)?[0-9a-fA-F]+$/.test(val);
  if (looksLikeAddr) {
    const norm = val.startsWith('0x') ? val : '0x' + val;
    window._lastDisasmAddr = norm;
    updateActiveContextBars(norm);
    if (typeof navPush === 'function') navPush(norm, { tab: 'disasm', spanLength: 1, source: 'Go to' });
    vscode.postMessage({ type: 'hubGoToAddress', addr: norm, binaryPath: bp });
  } else {
    vscode.postMessage({ type: 'hubGoToEntryPoint', binaryPath: bp, symbol: val });
  }
});

document.getElementById('btnAddAnnotation')?.addEventListener('click', () => {
  const badge = document.getElementById('annotationAddrBadge');
  const addr = badge?.dataset.addr || '';
  const comment = document.getElementById('annotationComment')?.value?.trim();
  const name = (document.getElementById('annotationName')?.value || '').trim();
  const bp = getStaticBinaryPath();
  if (!bp) {
    vscode.postMessage({ type: 'hubError', message: 'Sélectionnez un binaire.' });
    return;
  }
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Cliquez d\'abord une ligne dans le désassemblage.' });
    return;
  }
  vscode.postMessage({ type: 'hubSaveAnnotation', binaryPath: bp, addr, comment, name });
});

document.getElementById('btnXrefs')?.addEventListener('click', () => {
  const inputAddr = document.getElementById('goToAddrInput')?.value?.trim();
  const selectedAddr = document.getElementById('annotationAddrBadge')?.dataset.addr || '';
  const addr = inputAddr || selectedAddr || window._lastDisasmAddr || '';
  if (!addr) {
    vscode.postMessage({ type: 'hubError', message: 'Indiquez une adresse ou cliquez une ligne du désassemblage.' });
    return;
  }
  const el = document.getElementById('xrefsResult');
  const contentEl = document.getElementById('xrefsResultContent');
  if (el) {
    el.style.display = 'block';
    (contentEl || el).innerHTML = '<p class="xrefs-msg loading">Analyse des références croisées…</p>';
    el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  const bp = getStaticBinaryPath();
  const norm = addr.startsWith('0x') ? addr : '0x' + addr;
  const input = document.getElementById('goToAddrInput');
  if (input) input.value = norm;
  const mode = document.getElementById('xrefsMode')?.value || 'to';
  vscode.postMessage({ type: 'hubLoadXrefs', addr: norm, binaryPath: bp || '', mode });
});

document.getElementById('btnExportDisasm')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubExportDisasm', binaryPath: getStaticBinaryPath() });
});
document.getElementById('btnExportSymbolsJson')?.addEventListener('click', () => doExportData('symbols', 'json'));
document.getElementById('btnExportSymbolsCsv')?.addEventListener('click', () => doExportData('symbols', 'csv'));
document.getElementById('btnExportStringsJson')?.addEventListener('click', () => doExportData('strings', 'json'));
document.getElementById('btnExportStringsCsv')?.addEventListener('click', () => doExportData('strings', 'csv'));
document.getElementById('btnExportXrefsJson')?.addEventListener('click', () => doExportData('xrefs', 'json'));
document.getElementById('btnExportXrefsCsv')?.addEventListener('click', () => doExportData('xrefs', 'csv'));

document.getElementById('btnExportCfgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#cfgContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le graphe CFG.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCfgSvg', svg });
});

document.getElementById('btnExportCgSvg')?.addEventListener('click', () => {
  const svgEl = document.querySelector('#callgraphContent .cfg-svg');
  if (!svgEl) {
    vscode.postMessage({ type: 'hubError', message: 'Ouvrez d\'abord le call graph.' });
    return;
  }
  const svg = svgEl.outerHTML;
  vscode.postMessage({ type: 'hubExportCgSvg', svg });
});
}
