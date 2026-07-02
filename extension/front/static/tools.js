// Strings search (Outils) — utilise le binaire du projet
// Files
// Outils: sync binary label, select binary
function syncToolsBinaryLabel() {
  const bp = getStaticBinaryPath();
  const el = document.getElementById('toolsBinaryLabel');
  if (el) {
    el.textContent = bp ? `Binaire : ${bp}` : 'Binaire : sélectionnez-en un (Static ou ici)';
    el.classList.toggle('empty', !bp);
  }
}
document.getElementById('btnToolsSelectBinary')?.addEventListener('click', () => {
  pendingStaticQuickAction = '';
  vscode.postMessage({ type: 'requestBinarySelection' });
});

document.getElementById('btnRefreshFiles')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'listGeneratedFiles' });
});

document.getElementById('btnPurgeStale')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'purgeStaleCache' });
});

document.getElementById('btnCleanup')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'cleanupGeneratedFiles', confirm: true });
});

function highlightC(code) {
  // Etape 1 : echapper HTML (XSS prevention — obligatoire avant tout)
  let h = code
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

  // Placeholder system : chaque match est remplace par un token opaque
  // que les passes suivantes ne peuvent pas matcher
  const tokens = [];
  function protect(spanHtml) {
    const id = `\x00T${tokens.length}\x00`;
    tokens.push(spanHtml);
    return id;
  }
  function wrap(regex, cls) {
    h = h.replace(regex, match => protect(`<span class="${cls}">${match}</span>`));
  }

  // Etape 2 : commentaires (en premier — priorite maximale)
  wrap(/(\/\/[^\n]*)/g, 'hl-comment');
  wrap(/(\/\*[\s\S]*?\*\/)/g, 'hl-comment');

  // Etape 3 : chaines litterales (guillemets echappes en &quot;)
  wrap(/(&quot;[^&\n]*&quot;)/g, 'hl-string');

  // Etape 4 : mots-cles C
  const kw = 'if|else|for|while|do|return|break|continue|switch|case|default|goto|sizeof|typedef|struct|union|enum|void|static|extern|const|volatile|register|inline|auto';
  wrap(new RegExp(`\\b(${kw})\\b`, 'g'), 'hl-keyword');

  // Etape 5 : types C courants
  const types = 'int|char|long|short|unsigned|signed|float|double|size_t|ssize_t|uint8_t|uint16_t|uint32_t|uint64_t|int8_t|int16_t|int32_t|int64_t|bool|FILE|NULL';
  wrap(new RegExp(`\\b(${types})\\b`, 'g'), 'hl-type');

  // Etape 6 : nombres (hex et decimal)
  wrap(/\b(0x[0-9a-fA-F]+|\d+)\b/g, 'hl-number');

  // Restauration : remplacer les tokens par leur HTML final
  h = h.replace(/\x00T(\d+)\x00/g, (_, i) => tokens[Number(i)]);

  return h;
}

function cancelPendingDecompileHighlight() {
  decompileRenderToken += 1;
  if (decompileHighlightFrame) {
    cancelAnimationFrame(decompileHighlightFrame);
    decompileHighlightFrame = 0;
  }
}

function buildDecompileHighlightCacheKey(binaryPath, decompiler, addr) {
  return `${binaryPath || ''}\u0001${decompiler || ''}\u0001${addr || ''}`;
}

function scheduleDecompileHighlight(pre, code, opts = {}) {
  const cacheKey = buildDecompileHighlightCacheKey(opts.binaryPath, opts.decompiler, opts.addr);
  const token = ++decompileRenderToken;
  const applyHighlightedHtml = (html) => {
    if (token !== decompileRenderToken || !pre.isConnected) return;
    pre.innerHTML = html;
    decorateDecompileOutput(pre, opts);
  };
  pre.textContent = code;
  if (
    decompileHighlightCache.key === cacheKey &&
    decompileHighlightCache.code === code &&
    decompileHighlightCache.html
  ) {
    decompileHighlightFrame = requestAnimationFrame(() => {
      decompileHighlightFrame = 0;
      applyHighlightedHtml(decompileHighlightCache.html);
    });
    return;
  }
  decompileHighlightFrame = requestAnimationFrame(() => {
    decompileHighlightFrame = requestAnimationFrame(() => {
      decompileHighlightFrame = 0;
      if (token !== decompileRenderToken || !pre.isConnected) return;
      const html = highlightC(code);
      decompileHighlightCache = { key: cacheKey, code, html };
      applyHighlightedHtml(html);
    });
  });
}

function clearDecompileSearchHighlights(pre) {
  if (!pre) return;
  pre.querySelectorAll('.decompile-search-hit').forEach((span) => {
    span.parentNode?.replaceChild(document.createTextNode(span.textContent), span);
  });
  pre.normalize(); // merge adjacent text nodes split by the previous wrapping
}

function decorateDecompileSearch(pre, query) {
  const needle = String(query || '').trim();
  if (!pre || !needle) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return 0;
  }
  const lowerNeedle = needle.toLowerCase();
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.decompile-search-hit')) return NodeFilter.FILTER_REJECT;
        return node.nodeValue.toLowerCase().includes(lowerNeedle)
          ? NodeFilter.FILTER_ACCEPT
          : NodeFilter.FILTER_REJECT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  let count = 0;
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    const lowerText = text.toLowerCase();
    let cursor = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    while (cursor < text.length) {
      const idx = lowerText.indexOf(lowerNeedle, cursor);
      if (idx === -1) break;
      if (idx > cursor) {
        fragment.appendChild(document.createTextNode(text.slice(cursor, idx)));
      }
      const mark = document.createElement('span');
      mark.className = 'decompile-search-hit';
      mark.textContent = text.slice(idx, idx + needle.length);
      fragment.appendChild(mark);
      cursor = idx + needle.length;
      replaced = true;
      count += 1;
    }
    if (!replaced) return;
    if (cursor < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(cursor)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
  if (count <= 0) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return 0;
  }
  applyActiveDecompileSearchHit(decompileUiState.activeSearchHit >= 0 ? decompileUiState.activeSearchHit : 0, { reveal: false });
  updateDecompileSearchUi(count);
  return count;
}

function getDecompileSearchHits() {
  return Array.from(document.querySelectorAll('#decompileContent .decompile-search-hit'));
}

function applyActiveDecompileSearchHit(index, opts = {}) {
  const hits = getDecompileSearchHits();
  hits.forEach((hit) => hit.classList.remove('is-active'));
  if (!hits.length) {
    decompileUiState.activeSearchHit = -1;
    updateDecompileSearchUi(0);
    return false;
  }
  let nextIndex = Number(index);
  if (!Number.isFinite(nextIndex)) nextIndex = 0;
  if (nextIndex < 0) nextIndex = hits.length - 1;
  nextIndex = nextIndex % hits.length;
  const target = hits[nextIndex];
  if (!target) return false;
  target.classList.add('is-active');
  decompileUiState.activeSearchHit = nextIndex;
  updateDecompileSearchUi(hits.length);
  if (opts.reveal !== false) {
    target.scrollIntoView({ block: 'center' });
  }
  return true;
}

function stepDecompileSearchHit(delta) {
  const hits = getDecompileSearchHits();
  if (!hits.length) {
    updateDecompileSearchUi(0);
    return false;
  }
  const base = Number.isFinite(decompileUiState.activeSearchHit) ? decompileUiState.activeSearchHit : 0;
  return applyActiveDecompileSearchHit(base + delta);
}

function ensureDecompilePeekEl() {
  if (decompilePeekState.el?.isConnected) return decompilePeekState.el;
  const el = document.createElement('div');
  el.className = 'decompile-peek-tooltip';
  document.body.appendChild(el);
  decompilePeekState.el = el;
  return el;
}

function hideDecompilePeek() {
  if (decompilePeekState.el) decompilePeekState.el.style.display = 'none';
  decompilePeekState.target = null;
}

function positionDecompilePeek(clientX, clientY) {
  const el = ensureDecompilePeekEl();
  const pad = 14;
  const x = Math.min(clientX + 16, Math.max(8, window.innerWidth - el.offsetWidth - pad));
  const y = Math.min(clientY + 18, Math.max(8, window.innerHeight - el.offsetHeight - pad));
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
}

function renderDecompilePeek(target) {
  if (!target) return;
  const el = ensureDecompilePeekEl();
  const isStack = target.classList.contains('decompile-stack-link') || target.classList.contains('decompile-link-chip-stack');
  const isAddr = target.classList.contains('decompile-addr-link') || target.classList.contains('decompile-link-chip-addr');
  const isFn = target.classList.contains('decompile-fn-link') || (target.classList.contains('decompile-link-chip') && !isStack && !isAddr);
  let title = '';
  let subtitle = '';
  let hint = '';
  const rows = [];
  if (isStack) {
    title = target.dataset.stackName || target.textContent || 'Entrée stack';
    subtitle = target.dataset.stackKind === 'arg' ? 'Argument' : 'Variable locale';
    if (target.dataset.stackLocation) rows.push(['Emplacement', target.dataset.stackLocation]);
    if (target.dataset.stackType) rows.push(['Type', target.dataset.stackType]);
    hint = 'Clic: ouvrir Stack Frame';
  } else if (isAddr) {
    title = target.dataset.addr || target.textContent || 'Adresse';
    subtitle = 'Adresse repérée dans le pseudo-C';
    rows.push(['Adresse', target.dataset.addr || target.textContent || '—']);
    hint = 'Clic: désasm • Shift: Hex • Alt: CFG • Cmd/Ctrl: Call Graph';
  } else if (isFn) {
    title = target.dataset.name || target.textContent || 'Fonction';
    subtitle = 'Appel repéré';
    if (target.dataset.addr) rows.push(['Adresse', target.dataset.addr]);
    if (target.dataset.source) rows.push(['Source', target.dataset.source]);
    hint = 'Clic: pseudo-C • Shift: désasm • Alt: CFG • Cmd/Ctrl: Call Graph';
  } else {
    return;
  }
  const rowsHtml = rows.map(([label, value]) => (
    `<div class="decompile-peek-row"><span class="decompile-peek-key">${escapeHtml(label)}</span><span class="decompile-peek-val">${escapeHtml(value || '—')}</span></div>`
  )).join('');
  el.innerHTML = `
    <div class="decompile-peek-title">${escapeHtml(title)}</div>
    ${subtitle ? `<div class="decompile-peek-sub">${escapeHtml(subtitle)}</div>` : ''}
    ${rowsHtml ? `<div class="decompile-peek-grid">${rowsHtml}</div>` : ''}
    ${hint ? `<div class="decompile-peek-hint">${escapeHtml(hint)}</div>` : ''}
  `.trim();
  el.style.display = 'block';
}

function bindDecompilePeek(root) {
  if (!root || root.dataset.peekBound === '1') return;
  root.dataset.peekBound = '1';
  root.addEventListener('mousemove', (event) => {
    const target = event.target.closest('.decompile-fn-link, .decompile-addr-link, .decompile-stack-link, .decompile-link-chip');
    if (!target || !root.contains(target)) {
      hideDecompilePeek();
      return;
    }
    if (decompilePeekState.target !== target) {
      decompilePeekState.target = target;
      renderDecompilePeek(target);
    }
    positionDecompilePeek(event.clientX, event.clientY);
  });
  root.addEventListener('mouseleave', hideDecompilePeek);
  root.addEventListener('click', hideDecompilePeek);
}

function getNavigableDecompileAddr(text) {
  const raw = String(text || '').trim();
  if (!/^0x[0-9a-f]+$/i.test(raw)) return null;
  const normalized = normalizeHexAddress(raw);
  if (!normalized) return null;
  const addrNum = parseInt(normalized, 16);
  if (!Number.isFinite(addrNum) || addrNum < 0x1000) return null;
  if (isRawBinarySelected()) return normalized;
  if (Number.isFinite(fileOffsetFromVaddr(normalized))) return normalized;
  if ((window.symbolsCache || []).some((s) => normalizeHexAddress(s.addr) === normalized)) return normalized;
  return null;
}

function handleDecompileAddressJump(addr, event, binaryPath) {
  const normalized = normalizeHexAddress(addr);
  const bp = binaryPath || getStaticBinaryPath();
  if (!normalized || !bp) return;
  window._lastDisasmAddr = normalized;
  updateActiveContextBars(normalized);
  syncDecompileSelection(normalized, { forceContext: true });
  if (event?.metaKey || event?.ctrlKey) {
    jumpToAddrInContextTab('callgraph', normalized, bp);
    return;
  }
  if (event?.altKey) {
    jumpToAddrInContextTab('cfg', normalized, bp);
    return;
  }
  if (event?.shiftKey) {
    jumpToAddrInContextTab('hex', normalized, bp);
    return;
  }
  if (typeof navPush === 'function') navPush(normalized, { tab: 'disasm', spanLength: 1, source: 'Pseudo-C' });
  vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp });
}

function getKnownFunctionMap() {
  const map = new Map();
  (window.symbolsCache || []).forEach((sym) => {
    const addr = normalizeHexAddress(sym.addr);
    const type = String(sym.type || '').toUpperCase();
    if (!addr || !sym.name) return;
    if (!['F', 'T', 'U', 'W'].includes(type)) return;
    if (!map.has(sym.name)) map.set(sym.name, { name: sym.name, addr, source: 'symbols' });
  });
  (window.functionListCache || []).forEach((fn) => {
    const addr = normalizeHexAddress(fn.addr);
    if (!addr || !fn.name) return;
    if (!map.has(fn.name)) map.set(fn.name, { name: fn.name, addr, source: 'functions' });
  });
  (window.discoveredFunctionsCache || []).forEach((fn) => {
    const addr = normalizeHexAddress(fn.addr);
    if (!addr || !fn.name) return;
    if (!map.has(fn.name)) map.set(fn.name, { name: fn.name, addr, source: 'discovered' });
  });
  return map;
}

function extractDecompileCallTargets(code, currentAddr) {
  const functionMap = getKnownFunctionMap();
  if (!functionMap.size) return [];
  const reserved = new Set([
    'if', 'else', 'for', 'while', 'switch', 'case', 'return', 'sizeof', 'typedef',
    'struct', 'union', 'enum', 'do', 'break', 'continue', 'goto',
  ]);
  const targets = [];
  const seen = new Set();
  const regex = /\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g;
  let match;
  while ((match = regex.exec(code))) {
    const name = match[1];
    if (reserved.has(name)) continue;
    const entry = functionMap.get(name);
    if (!entry?.addr) continue;
    if (normalizeHexAddress(currentAddr) === entry.addr) continue;
    if (seen.has(entry.name)) continue;
    seen.add(entry.name);
    targets.push(entry);
    if (targets.length >= 10) break;
  }
  return targets;
}

function extractDecompileAddressTargets(code, currentAddr) {
  const current = normalizeHexAddress(currentAddr);
  const targets = [];
  const seen = new Set();
  const regex = /\b0x[0-9a-fA-F]+\b/g;
  let match;
  while ((match = regex.exec(code))) {
    const addr = getNavigableDecompileAddr(match[0]);
    if (!addr) continue;
    if (current && addr === current) continue;
    if (seen.has(addr)) continue;
    seen.add(addr);
    targets.push(addr);
    if (targets.length >= 12) break;
  }
  return targets.sort((a, b) => (parseInt(a, 16) || 0) - (parseInt(b, 16) || 0));
}

function summarizeDecompileStructure(code) {
  const source = String(code || '');
  const lines = source.split(/\r?\n/);
  const nonEmptyLines = lines.filter((line) => line.trim()).length;
  const ifCount = (source.match(/\bif\s*\(/g) || []).length;
  const switchCount = (source.match(/\bswitch\s*\(/g) || []).length;
  const loopCount = (source.match(/\bfor\s*\(|\bwhile\s*\(|\bdo\b/g) || []).length;
  const returnCount = (source.match(/^\s*return\b/gm) || []).length;
  const gotoCount = (source.match(/\bgoto\b/g) || []).length;
  const caseCount = (source.match(/^\s*(case\b|default\s*:)/gm) || []).length;
  const labelCount = lines.reduce((count, line) => {
    const trimmed = line.trim();
    if (!trimmed || /^\s*(case\b|default\s*:)/.test(trimmed)) return count;
    return /^[A-Za-z_][A-Za-z0-9_]*\s*:/.test(trimmed) ? count + 1 : count;
  }, 0);
  const chips = [
    { label: `${nonEmptyLines} lignes`, tone: 'neutral', title: 'Nombre de lignes non vides du pseudo-C courant' },
    ifCount ? { label: `${ifCount} if`, tone: 'flow', title: 'Branches conditionnelles reperees' } : null,
    switchCount ? { label: `${switchCount} switch`, tone: 'flow', title: 'Structures switch reperees' } : null,
    caseCount ? { label: `${caseCount} cas`, tone: 'flow', title: 'Labels case/default repérés' } : null,
    loopCount ? { label: `${loopCount} boucle${loopCount > 1 ? 's' : ''}`, tone: 'flow', title: 'Boucles for / while / do repérées' } : null,
    returnCount ? { label: `${returnCount} retour${returnCount > 1 ? 's' : ''}`, tone: 'data', title: 'Instructions return repérées' } : null,
    gotoCount ? { label: `${gotoCount} goto`, tone: 'warn', title: 'Sauts goto repérés' } : null,
    labelCount ? { label: `${labelCount} label${labelCount > 1 ? 's' : ''}`, tone: 'neutral', title: 'Labels locaux repérés' } : null,
  ].filter(Boolean);
  return chips;
}

function escapeRegexText(text) {
  return String(text || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function extractDecompileStackEntries(stackFrame) {
  if (!stackFrame || stackFrame.error) return [];
  const entries = [];
  const seen = new Set();
  const appendEntries = (items, kind) => {
    (Array.isArray(items) ? items : []).forEach((entry) => {
      const name = normalizeStackEntryName(entry?.name);
      if (!name || seen.has(name)) return;
      seen.add(name);
      entries.push({
        name,
        kind,
        location: formatStackFrameEntryLocation(entry),
        type: entry?.type || '',
      });
    });
  };
  appendEntries(stackFrame.args, 'arg');
  appendEntries(stackFrame.vars, 'var');
  return entries.slice(0, 10);
}

function openDecompileFunction(addr, name, event) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return;
  if (event?.metaKey || event?.ctrlKey) {
    jumpToAddrInContextTab('callgraph', normalized, getStaticBinaryPath());
    return;
  }
  if (event?.altKey) {
    jumpToAddrInContextTab('cfg', normalized, getStaticBinaryPath());
    return;
  }
  if (event?.shiftKey) {
    handleDecompileAddressJump(normalized, event, getStaticBinaryPath());
    return;
  }
  const sel = document.getElementById('decompileAddrSelect');
  if (sel) {
    let option = Array.from(sel.options).find((opt) => opt.value === normalized);
    if (!option) {
      option = document.createElement('option');
      option.value = normalized;
      option.dataset.name = name || normalized;
      option.textContent = `${normalized}  ${name || ''}`.trim();
      sel.appendChild(option);
    }
    sel.value = normalized;
  }
  decompileUiState.selectionMode = 'manual';
  _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  decompileUiState.selectedAddr = normalized;
  setActiveAddressContext(normalized, 1, { preserveHexSelection: true });
  showGroup('code', 'decompile');
  requestDecompileForCurrentSelection();
}

function decorateDecompileFunctionCalls(pre, opts = {}) {
  if (!pre) return;
  const functionMap = getKnownFunctionMap();
  if (!functionMap.size) return;
  const currentName = String(opts.currentName || '').trim();
  const currentAddr = normalizeHexAddress(opts.addr);
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.hl-comment, .hl-string, .decompile-fn-link')) return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    const regex = /\b([A-Za-z_][A-Za-z0-9_]*)\b(?=\s*\()/g;
    let lastIndex = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    let match;
    while ((match = regex.exec(text))) {
      const name = match[1];
      const entry = functionMap.get(name);
      if (!entry?.addr) continue;
      if ((currentName && name === currentName) || (currentAddr && entry.addr === currentAddr)) continue;
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }
      const span = document.createElement('span');
      span.className = 'decompile-fn-link';
      span.dataset.addr = entry.addr;
      span.dataset.name = name;
      span.dataset.source = entry.source || '';
      span.textContent = name;
      span.title = `${entry.addr} — clic: ouvrir en pseudo-C • Shift+clic: désassemblage • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      fragment.appendChild(span);
      lastIndex = match.index + name.length;
      replaced = true;
    }
    if (!replaced) return;
    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
}

function decorateDecompileStackEntries(pre, opts = {}) {
  if (!pre) return;
  const entries = Array.isArray(opts.stackEntries) ? opts.stackEntries : [];
  if (!entries.length) return;
  const stackMap = new Map();
  entries.forEach((entry) => {
    const name = normalizeStackEntryName(entry?.name);
    if (!name || stackMap.has(name)) return;
    stackMap.set(name, entry);
  });
  const names = Array.from(stackMap.keys()).sort((a, b) => b.length - a.length);
  if (!names.length) return;
  const pattern = new RegExp(`\\b(${names.map((name) => escapeRegexText(name)).join('|')})\\b`, 'g');
  const walker = document.createTreeWalker(
    pre,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        if (!node?.nodeValue || !node.nodeValue.trim()) return NodeFilter.FILTER_REJECT;
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        if (parent.closest('.hl-comment, .hl-string, .decompile-fn-link, .decompile-addr-link, .decompile-stack-link')) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    },
  );
  const textNodes = [];
  let currentNode = walker.nextNode();
  while (currentNode) {
    textNodes.push(currentNode);
    currentNode = walker.nextNode();
  }
  textNodes.forEach((node) => {
    const text = node.nodeValue || '';
    let lastIndex = 0;
    let replaced = false;
    const fragment = document.createDocumentFragment();
    let match;
    while ((match = pattern.exec(text))) {
      const name = match[1];
      const prevChar = match.index > 0 ? text[match.index - 1] : '';
      const nextChar = text[match.index + name.length] || '';
      if (prevChar === '.' || nextChar === '(') continue;
      if (match.index > lastIndex) {
        fragment.appendChild(document.createTextNode(text.slice(lastIndex, match.index)));
      }
      const entry = stackMap.get(name);
      const span = document.createElement('span');
      span.className = 'decompile-stack-link';
      span.dataset.stackName = name;
      span.dataset.stackKind = entry?.kind || '';
      span.dataset.stackLocation = entry?.location || '';
      span.dataset.stackType = entry?.type || '';
      span.textContent = name;
      span.title = `${entry?.kind === 'arg' ? 'Argument' : 'Variable locale'}${entry?.location ? ` — ${entry.location}` : ''} • clic: ouvrir Stack Frame`;
      fragment.appendChild(span);
      lastIndex = match.index + name.length;
      replaced = true;
    }
    if (!replaced) return;
    if (lastIndex < text.length) {
      fragment.appendChild(document.createTextNode(text.slice(lastIndex)));
    }
    node.parentNode?.replaceChild(fragment, node);
  });
}

function decorateDecompileOutput(pre, opts = {}) {
  if (!pre) return;
  pre.querySelectorAll('.hl-number').forEach((el) => {
    const addr = getNavigableDecompileAddr(el.textContent);
    if (!addr) return;
    el.classList.add('decompile-addr-link');
    el.dataset.addr = addr;
    el.title = 'Clic: aller au désassemblage • Shift+clic: ouvrir dans Hex • Alt+clic: centrer dans le CFG • Cmd/Ctrl+clic: Call Graph';
  });
  decorateDecompileFunctionCalls(pre, opts);
  decorateDecompileStackEntries(pre, opts);
  decorateDecompileSearch(pre, opts.searchQuery || decompileUiState.searchQuery);
  applyDecompileStackHighlight(opts.activeStackName || decompileUiState.pendingStackEntryName || decompileUiState.activeStackEntryName, { reveal: false });
  if (pre.dataset.navBound === '1') return;
  pre.dataset.navBound = '1';
  pre.addEventListener('click', (event) => {
    const fnTarget = event.target.closest('.decompile-fn-link[data-addr]');
    if (fnTarget && pre.contains(fnTarget)) {
      event.preventDefault();
      openDecompileFunction(fnTarget.dataset.addr, fnTarget.dataset.name || '', event);
      return;
    }
    const target = event.target.closest('.decompile-addr-link[data-addr]');
    if (target && pre.contains(target)) {
      event.preventDefault();
      handleDecompileAddressJump(target.dataset.addr, event, opts.binaryPath);
      return;
    }
    const stackTarget = event.target.closest('.decompile-stack-link[data-stack-name]');
    if (!stackTarget || !pre.contains(stackTarget)) return;
    event.preventDefault();
    openStackEntryFromDecompile(stackTarget.dataset.stackName);
  });
}

function buildDecompileRequestKey(binaryPath, decompiler, quality, addr, full, provider = 'auto', funcName = '') {
  return `${binaryPath || ''}\u0001${decompiler || ''}\u0001${_normalizeDecompileQuality(quality || 'normal')}\u0001${provider || 'auto'}\u0001${full ? '__full__' : (addr || '')}\u0001${String(funcName || '').trim()}`;
}

function getCurrentDecompileRequestContext() {
  const binaryPath = getStaticBinaryPath() || '';
  const quality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
  const decompiler = _getRequestedDecompilerForQuality(quality);
  const provider = _getConfiguredDecompilerProvider();
  const { addr, funcName } = getDecompileSelectionContext();
  return {
    binaryPath,
    decompiler,
    quality,
    provider,
    addr: addr || '',
    full: !addr,
    funcName: funcName || '',
  };
}

function getCachedDecompileResult(requestKey) {
  const cached = decompileResultCache.get(requestKey);
  if (!cached) return null;
  decompileResultCache.delete(requestKey);
  decompileResultCache.set(requestKey, cached);
  return cached;
}

function cacheDecompileResult(requestKey, payload) {
  if (!requestKey || !payload || payload.result?.error) return;
  if (decompileResultCache.has(requestKey)) {
    decompileResultCache.delete(requestKey);
  }
  decompileResultCache.set(requestKey, payload);
  while (decompileResultCache.size > MAX_DECOMPILE_RESULT_CACHE) {
    const oldestKey = decompileResultCache.keys().next().value;
    if (!oldestKey) break;
    decompileResultCache.delete(oldestKey);
  }
}

function clearDecompileCaches() {
  cancelPendingDecompileHighlight();
  decompileResultCache = new Map();
  pendingDecompileRequests.clear();
  decompileHighlightCache = {
    key: '',
    code: '',
    html: '',
  };
  decompileUiState.renderedProvider = _getConfiguredDecompilerProvider();
  decompileUiState.renderedQuality = _normalizeDecompileQuality(decompileUiState.quality || 'normal');
  resetDecompileHistory();
}

const _ERROR_TYPE_MESSAGES = {
  image_not_found: 'Image Docker absente — lancez make decompiler-docker-build',
  timeout: 'Timeout dépassé — le binaire est peut-être trop gros',
  tool_error: 'Erreur du décompilateur — vérifiez les logs',
  unsupported_target: 'Format ou architecture non supporté par ce décompilateur — essayez Ghidra',
};

function renderDecompilePayload(container, payload) {
  if (!container || !payload) return;
  const result = payload.result || {};
  decompileUiState.renderedAddr = payload.full ? '' : (payload.addr || '');
  decompileUiState.renderedBinaryPath = payload.binaryPath || getStaticBinaryPath() || '';
  decompileUiState.renderedQuality = _normalizeDecompileQuality(payload.quality || result.quality || decompileUiState.quality || 'normal');
  decompileUiState.renderedDecompiler = payload.decompiler || _getRequestedDecompilerForQuality(decompileUiState.renderedQuality);
  decompileUiState.renderedProvider = payload.provider || _getConfiguredDecompilerProvider();
  decompileUiState.quality = decompileUiState.renderedQuality;
  decompileUiState.selectedAddr = payload.full ? '' : (payload.addr || decompileUiState.selectedAddr);
  if (result.error) {
    cancelPendingDecompileHighlight();
    container.textContent = `Erreur : ${_ERROR_TYPE_MESSAGES[result.error_type] || result.error}`;
    return;
  }
  const code = result.code || (result.functions || []).map((f) => `// ${f.addr}\n${f.code}`).join('\n\n');
  const wrap = document.createElement('div');
  const callTargets = extractDecompileCallTargets(code, payload.addr);
  const addressTargets = extractDecompileAddressTargets(code, payload.addr);
  const structureSummary = summarizeDecompileStructure(code);
  const annotationTargets = Array.isArray(result.annotations) ? result.annotations : [];
  const typedStructTargets = Array.isArray(result.typed_structs) ? result.typed_structs : [];
  const stackFrame = result.stack_frame || null;
  const stackEntries = extractDecompileStackEntries(stackFrame);
  const qualityDetails = result.quality_details || null;
  const stackFrameAddr = normalizeHexAddress(payload.addr || decompileUiState.selectedAddr || window._lastDisasmAddr);
  const stackFrameBinaryPath = decompileUiState.renderedBinaryPath || getStaticBinaryPath() || '';
  const metaSummary = document.createElement('div');
  metaSummary.className = 'decompile-frame-summary';
  [
    _formatDecompileQualityLabel(decompileUiState.renderedQuality),
    qualityDetails?.selected_score != null ? `Score ${qualityDetails.selected_score}` : null,
    Array.isArray(qualityDetails?.backends) && qualityDetails.backends.length > 1 ? `Comparé ${qualityDetails.backends.length} backends` : null,
    annotationTargets.length ? `Annotations ${annotationTargets.length}` : null,
    typedStructTargets.length ? `Types ${typedStructTargets.length}` : null,
  ].filter(Boolean).forEach((label) => {
    const chip = document.createElement('span');
    chip.className = 'decompile-frame-chip';
    chip.textContent = label;
    metaSummary.appendChild(chip);
  });
  if (metaSummary.childElementCount) wrap.appendChild(metaSummary);
  if (Array.isArray(qualityDetails?.backends) && qualityDetails.backends.length) {
    const qualitySummary = document.createElement('div');
    qualitySummary.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = decompileUiState.renderedQuality === 'precision' ? 'Précision' : 'Qualité';
    qualitySummary.appendChild(title);
    qualityDetails.backends.forEach((entry) => {
      const chip = document.createElement('span');
      const tone = entry.selected ? 'data' : (entry.ok ? 'flow' : 'warn');
      chip.className = `decompile-outline-chip decompile-outline-chip-${tone}`;
      const backendName = entry.decompiler || 'backend';
      chip.textContent = entry.ok
        ? `${backendName} • ${entry.score ?? '—'}`
        : `${backendName} • erreur`;
      if (entry.ok && entry.metrics) {
        chip.title = [
          `Score ${entry.score ?? '—'}`,
          `lignes ${entry.metrics.lines ?? entry.metrics.functions ?? '—'}`,
          entry.metrics.calls != null ? `calls ${entry.metrics.calls}` : null,
          entry.metrics.control != null ? `control ${entry.metrics.control}` : null,
          entry.metrics.matched_calls != null ? `calls gardés ${entry.metrics.matched_calls}` : null,
          entry.metrics.missed_calls != null ? `calls perdus ${entry.metrics.missed_calls}` : null,
          entry.metrics.warnings != null ? `warnings ${entry.metrics.warnings}` : null,
          entry.metrics.placeholders != null ? `placeholders ${entry.metrics.placeholders}` : null,
          entry.metrics.errors != null ? `erreurs ${entry.metrics.errors}` : null,
        ].filter(Boolean).join(' • ');
      } else if (entry.error) {
        chip.title = String(entry.error);
      }
      qualitySummary.appendChild(chip);
    });
    wrap.appendChild(qualitySummary);
  }
  if (stackFrame) {
    cacheStackFrame(stackFrameBinaryPath, stackFrameAddr, stackFrame);
    if (isStaticTabActive('stack')) renderStackFrame(stackFrame);
    if (isStaticTabActive('hex')) updateHexSelectionSummary(window._lastDisasmAddr);
    const summary = document.createElement('div');
    summary.className = 'decompile-frame-summary';
    [
      stackFrame.arch && stackFrame.arch !== 'unknown' ? `Arch ${stackFrame.arch}` : null,
      stackFrame.abi && stackFrame.abi !== 'unknown' ? `ABI ${stackFrame.abi}` : null,
      typeof stackFrame.frame_size === 'number' ? `Frame ${stackFrame.frame_size}B` : null,
      `Args ${Array.isArray(stackFrame.args) ? stackFrame.args.length : 0}`,
      `Locals ${Array.isArray(stackFrame.vars) ? stackFrame.vars.length : 0}`,
    ].filter(Boolean).forEach((label) => {
      const chip = document.createElement('span');
      chip.className = 'decompile-frame-chip';
      chip.textContent = label;
      summary.appendChild(chip);
    });
    if (summary.childElementCount) wrap.appendChild(summary);
  }
  if (structureSummary.length) {
    const summary = document.createElement('div');
    summary.className = 'decompile-outline-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Sommaire';
    summary.appendChild(title);
    structureSummary.forEach((entry) => {
      const chip = document.createElement('span');
      chip.className = `decompile-outline-chip decompile-outline-chip-${entry.tone || 'neutral'}`;
      chip.textContent = entry.label;
      if (entry.title) chip.title = entry.title;
      summary.appendChild(chip);
    });
    wrap.appendChild(summary);
  }
  if (stackEntries.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Stack repéré';
    links.appendChild(title);
    stackEntries.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = `decompile-link-chip decompile-link-chip-stack decompile-link-chip-stack-${entry.kind}`;
      button.dataset.stackName = entry.name;
      button.dataset.stackKind = entry.kind || '';
      button.dataset.stackLocation = entry.location || '';
      button.dataset.stackType = entry.type || '';
      button.textContent = entry.name;
      button.title = `${entry.kind === 'arg' ? 'Argument' : 'Variable locale'}${entry.location ? ` — ${entry.location}` : ''} • clic: ouvrir Stack Frame`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        openStackEntryFromDecompile(entry.name);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (callTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Appels repérés';
    links.appendChild(title);
    callTargets.forEach((target) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip';
      button.dataset.addr = target.addr;
      button.dataset.name = target.name;
      button.dataset.source = target.source || '';
      button.textContent = target.name;
      button.title = `${target.addr} — clic: ouvrir en pseudo-C • Shift+clic: désassemblage • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        openDecompileFunction(target.addr, target.name, event);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (addressTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Adresses repérées';
    links.appendChild(title);
    addressTargets.forEach((addr) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = addr;
      button.textContent = addr;
      button.title = 'Clic: aller au désassemblage • Shift+clic: ouvrir dans Hex • Alt+clic: centrer dans le CFG • Cmd/Ctrl+clic: Call Graph';
      button.addEventListener('click', (event) => {
        event.preventDefault();
        handleDecompileAddressJump(addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (annotationTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Annotations repérées';
    links.appendChild(title);
    annotationTargets.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = entry.addr || '';
      button.textContent = entry.name || entry.addr || 'annotation';
      button.title = `${entry.addr || 'Adresse inconnue'}${entry.comment ? ` — ${entry.comment}` : ''} • clic: désasm • Shift+clic: Hex • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        if (entry.addr) handleDecompileAddressJump(entry.addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  if (typedStructTargets.length) {
    const links = document.createElement('div');
    links.className = 'decompile-link-summary';
    const title = document.createElement('span');
    title.className = 'decompile-link-summary-title';
    title.textContent = 'Types repérés';
    links.appendChild(title);
    typedStructTargets.slice(0, 8).forEach((entry) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'decompile-link-chip decompile-link-chip-addr';
      button.dataset.addr = entry.addr || '';
      const label = entry.name || entry.addr || 'type';
      const typeKind = entry.struct_kind || entry.kind || 'struct';
      button.textContent = label;
      const titleParts = [
        entry.struct_name ? `${typeKind} ${entry.struct_name}` : null,
        entry.field_name ? `champ ${entry.field_name}` : null,
        entry.field_type || null,
        entry.addr || null,
      ].filter(Boolean);
      button.title = `${titleParts.join(' • ')} • clic: désasm • Shift+clic: Hex • Alt+clic: CFG • Cmd/Ctrl+clic: Call Graph`;
      button.addEventListener('click', (event) => {
        event.preventDefault();
        if (entry.addr) handleDecompileAddressJump(entry.addr, event, decompileUiState.renderedBinaryPath);
      });
      links.appendChild(button);
    });
    wrap.appendChild(links);
  }
  const pre = document.createElement('pre');
  pre.className = 'decompile-output';
  wrap.appendChild(pre);
  hideDecompilePeek();
  container.replaceChildren(wrap);
  bindDecompilePeek(wrap);
  scheduleDecompileHighlight(pre, code, {
    binaryPath: decompileUiState.renderedBinaryPath,
    decompiler: decompileUiState.renderedDecompiler,
    addr: decompileUiState.renderedAddr,
    currentName: payload.funcName || '',
    activeStackName: decompileUiState.pendingStackEntryName || decompileUiState.activeStackEntryName,
    searchQuery: decompileUiState.searchQuery || '',
    stackEntries,
  });
  tabDataCache.decompile = { binaryPath: decompileUiState.renderedBinaryPath || getStaticBinaryPath() };
}

function resetHexActiveUiState() {
  (hexActiveUiState.selectedRowEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-row-selected');
  });
  if (hexActiveUiState.activeRowEl?.isConnected) {
    hexActiveUiState.activeRowEl.classList.remove('hex-row-active');
  }
  (hexActiveUiState.selectedByteEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-byte-selected');
  });
  (hexActiveUiState.selectedAsciiEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-ascii-char-selected');
  });
  (hexActiveUiState.activeByteEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-byte-active');
  });
  (hexActiveUiState.activeAsciiEls || []).forEach((el) => {
    if (el?.isConnected) el.classList.remove('hex-ascii-char-active');
  });
  hexActiveUiState = {
    selectedRowEls: [],
    activeRowEl: null,
    selectedByteEls: [],
    selectedAsciiEls: [],
    activeByteEls: [],
    activeAsciiEls: [],
    startAddr: '',
    endAddr: '',
    addr: '',
    anchorAddr: '',
    spanLength: 1,
  };
  updateHexSelectionButtons();
}

function resetHexDomState() {
  resetHexActiveUiState();
  hexDomState = {
    rowByOffset: new Map(),
    rowDataByOffset: new Map(),
    byteElsByAddr: new Map(),
    asciiElsByAddr: new Map(),
  };
}

function getHexRowByOffsetHex(rowOffsetHex) {
  const key = String(rowOffsetHex || '').toLowerCase();
  return hexDomState.rowDataByOffset.get(key)
    || (window._lastHexRows || []).find((entry) => String(entry.offset || '').toLowerCase() === key)
    || null;
}

function appendHexDomEntry(map, key, el) {
  if (!key || !el) return;
  const normalized = String(key).toLowerCase();
  const existing = map.get(normalized);
  if (existing) {
    existing.push(el);
  } else {
    map.set(normalized, [el]);
  }
}

function updateHexPatchButtons() {
  const undoBtn = document.getElementById('btnHexUndo');
  if (undoBtn) undoBtn.disabled = hexPatchHistory.length === 0;
  const redoBtn = document.getElementById('btnHexRedo');
  if (redoBtn) redoBtn.disabled = hexPatchRedoHistory.length === 0;
}

function resetHexPatchSessionState() {
  hexPatchHistory = [];
  hexPatchRedoHistory = [];
  updateHexPatchButtons();
}

function parseNumericAddress(value) {
  if (value == null) return null;
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  const text = String(value).trim().toLowerCase();
  if (!text) return null;
  const parsed = text.startsWith('0x') ? parseInt(text, 16) : parseInt(text, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function getFunctionScoreClass(level) {
  if (level === 'critical') return 'functions-score-critical';
  if (level === 'high') return 'functions-score-high';
  if (level === 'medium') return 'functions-score-medium';
  return 'functions-score-low';
}

function isAnnotationEntryEmpty(entry) {
  return !entry || (
    !entry.comment
    && !entry.name
    && !entry.bookmark
    && !entry.reviewStatus
    && !entry.reviewNotes
  );
}

function getFunctionReviewLabel(status) {
  if (status === 'important') return 'Prioritaire';
  if (status === 'todo') return 'À revoir';
  if (status === 'in_progress') return 'En cours';
  if (status === 'reviewed') return 'Reviewée';
  return 'Sans revue';
}

function getKnownSpanLengthForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return 1;
  const stringHit = getStringEntryForAddress(normalized);
  if (stringHit) {
    const explicitLength = Number(stringHit.length || 0);
    if (Number.isFinite(explicitLength) && explicitLength > 0) return explicitLength;
    const fallbackLength = String(stringHit.value || '').length;
    if (fallbackLength > 0) return fallbackLength;
  }
  return 1;
}

function getStringEntryForAddress(addr) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return null;
  const target = parseNumericAddress(normalized);
  if (!Number.isFinite(target)) return null;
  for (const entry of stringsCache || []) {
    const startAddr = normalizeHexAddress(entry?.addr || '');
    const start = parseNumericAddress(startAddr);
    if (!Number.isFinite(start)) continue;
    const explicitLength = Number(entry?.length || 0);
    const fallbackLength = String(entry?.value || '').length;
    const span = Number.isFinite(explicitLength) && explicitLength > 0 ? explicitLength : fallbackLength;
    const end = start + Math.max(1, span);
    if (target >= start && target < end) return entry;
  }
  return null;
}

function focusStringsAddress(addr, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return false;
  const entry = getStringEntryForAddress(normalized);
  if (!entry) return false;
  const entryAddr = normalizeHexAddress(entry.addr || '');
  const container = document.getElementById('stringsContent');
  if (!container) {
    pendingStringsFocusAddr = normalized;
    return false;
  }
  const target = container.querySelector(`.nav-addr-row[data-addr="${entryAddr}"]`);
  if (!target) {
    pendingStringsFocusAddr = normalized;
    return false;
  }
  pendingStringsFocusAddr = opts.consume ? '' : normalized;
  if (opts.reveal !== false) target.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  target.classList.add('addr-row-active');
  target.querySelectorAll('.addr-link').forEach((link) => link.classList.add('addr-link-active'));
  return true;
}

function getFunctionReviewNotes(entry) {
  return String(entry?.reviewNotes || entry?.review_notes || '').trim();
}

function buildFunctionReviewHint(status, notes, updated, fallbackHint = '') {
  const dateText = updated ? new Date(updated).toLocaleString('fr-FR') : '';
  const noteText = String(notes || '').trim();
  if (noteText && dateText) return `${noteText} (${dateText})`;
  if (noteText) return noteText;
  if (status && status !== 'unreviewed' && dateText) {
    return `Statut manuel ${getFunctionReviewLabel(status).toLowerCase()} enregistré le ${dateText}.`;
  }
  return String(fallbackHint || '').trim();
}

function enrichFunctionEntryWithAnnotations(entry) {
  const normalizedAddr = normalizeHexAddress(entry?.addr || '');
  if (!normalizedAddr) return { ...entry };
  const annotation = findAnnotationForAddress(normalizedAddr) || {};
  const nextEntry = { ...entry };
  if (annotation.name) nextEntry.name = annotation.name;
  const annotationPreview = Array.isArray(nextEntry.annotationPreview) ? nextEntry.annotationPreview.slice() : [];
  if (annotation.comment && !annotationPreview.includes(annotation.comment)) {
    annotationPreview.unshift(annotation.comment);
  }
  const reviewNotes = String(annotation.reviewNotes || '').trim();
  if (reviewNotes && !annotationPreview.includes(reviewNotes)) {
    annotationPreview.unshift(`Revue: ${reviewNotes}`);
  }
  nextEntry.annotationPreview = annotationPreview.slice(0, 3);
  if (annotation.comment || annotation.name || reviewNotes) {
    nextEntry.annotationCount = Math.max(Number(nextEntry.annotationCount || 0), annotation.comment ? 1 : 0, annotation.name ? 1 : 0, reviewNotes ? 1 : 0);
  }
  const manualReviewStatus = String(annotation.reviewStatus || '').trim();
  if (manualReviewStatus) {
    nextEntry.reviewStatus = manualReviewStatus;
  }
  nextEntry.reviewNotes = reviewNotes;
  nextEntry.reviewUpdated = String(annotation.reviewUpdated || '').trim();
  nextEntry.reviewHint = buildFunctionReviewHint(
    nextEntry.reviewStatus || 'unreviewed',
    reviewNotes,
    nextEntry.reviewUpdated,
    nextEntry.reviewHint || nextEntry.review_hint || '',
  );
  if ((nextEntry.reviewStatus || '') === 'important') {
    nextEntry.signalTags = Array.isArray(nextEntry.signalTags) ? nextEntry.signalTags.slice() : [];
    if (!nextEntry.signalTags.includes('Prioritaire')) nextEntry.signalTags.unshift('Prioritaire');
  }
  const proofDossiers = Array.isArray(nextEntry.proofDossiers || nextEntry.proof_dossiers)
    ? (nextEntry.proofDossiers || nextEntry.proof_dossiers).map((dossier) => ({
        ...dossier,
        function: nextEntry.name || dossier.function || normalizedAddr,
        needs_review: (nextEntry.reviewStatus || 'unreviewed') !== 'reviewed',
        review_hint: nextEntry.reviewHint || dossier.review_hint || '',
      }))
    : [];
  nextEntry.proofDossiers = proofDossiers;
  return nextEntry;
}

function enrichFunctionsRowsWithAnnotations(rows = []) {
  return (Array.isArray(rows) ? rows : []).map((entry) => enrichFunctionEntryWithAnnotations(entry));
}

function mergeFunctionsRadarWithRows(radar, rows = [], opts = {}) {
  const fallback = buildFallbackFunctionsRadarFromRows(rows, opts);
  const base = radar && typeof radar === 'object'
    ? {
        ...radar,
        summary: { ...(radar.summary || {}) },
      }
    : fallback;
  const rowsByAddr = new Map(
    (Array.isArray(rows) ? rows : [])
      .map((entry) => [normalizeHexAddress(entry?.addr || ''), entry])
      .filter((entry) => entry[0])
  );
  const mapList = (list, fallbackList) => {
    const source = Array.isArray(list) && list.length ? list : fallbackList;
    return (Array.isArray(source) ? source : [])
      .map((entry) => rowsByAddr.get(normalizeHexAddress(entry?.addr || '')) || entry)
      .filter(Boolean);
  };
  const signalCounts = new Map();
  (Array.isArray(rows) ? rows : []).forEach((entry) => {
    (Array.isArray(entry.signalTags) ? entry.signalTags : []).forEach((tag) => {
      signalCounts.set(tag, Number(signalCounts.get(tag) || 0) + 1);
    });
  });
  base.functions = Array.isArray(rows) ? rows.slice() : [];
  base.hotspots = mapList(base.hotspots, fallback.hotspots);
  base.quick_wins = mapList(base.quick_wins, fallback.quick_wins);
  base.entry_candidates = mapList(base.entry_candidates, fallback.entry_candidates);
  base.proof_dossiers = (Array.isArray(rows) ? rows : [])
    .flatMap((entry) => Array.isArray(entry?.proofDossiers || entry?.proof_dossiers) ? (entry.proofDossiers || entry.proof_dossiers).slice(0, 1) : [])
    .slice(0, 8);
  base.clusters = signalCounts.size
    ? Array.from(signalCounts.entries())
      .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
      .slice(0, 6)
      .map(([name, count]) => ({ name, count }))
    : fallback.clusters;
  base.summary = {
    ...base.summary,
    function_count: rows.length,
    hotspot_count: rows.filter((entry) => Number(entry?.priorityScore || 0) >= 52).length,
    annotated_functions: rows.filter((entry) => Number(entry?.annotationCount || 0) > 0).length,
    suspicious_import_sites: rows.reduce((sum, entry) => sum + Number((entry?.importSignals || []).length || 0), 0),
    suspicious_string_sites: rows.reduce((sum, entry) => sum + Number((entry?.stringSignals || []).length || 0), 0),
    cluster_count: Array.isArray(base.clusters) ? base.clusters.length : 0,
    source_mode: opts.rawMode ? 'raw' : String(base.summary?.source_mode || 'symbolic'),
  };
  return base;
}

function sanitizeFunctionExportName(value) {
  return String(value || 'function')
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48) || 'function';
}

function buildFunctionDossier(entry) {
  if (!entry) return null;
  const reviewStatus = String(entry.reviewStatus || entry.review_status || 'unreviewed');
  const reasonList = Array.isArray(entry.reasons) ? entry.reasons : [];
  const scoreBreakdown = Array.isArray(entry.scoreBreakdown || entry.score_breakdown) ? (entry.scoreBreakdown || entry.score_breakdown) : [];
  const importSignals = Array.isArray(entry.importSignals || entry.import_signals) ? (entry.importSignals || entry.import_signals) : [];
  const stringSignals = Array.isArray(entry.stringSignals || entry.string_signals) ? (entry.stringSignals || entry.string_signals) : [];
  const annotations = Array.isArray(entry.annotationPreview || entry.annotation_preview) ? (entry.annotationPreview || entry.annotation_preview) : [];
  const summary = getActiveContextSummary(entry.addr);
  const fallbackProofDossier = {
    kind: 'FUNCTION_RADAR',
    function: entry.name || '',
    addr: normalizeHexAddress(entry.addr || ''),
    confidence: String(entry.confidence || 'LOW'),
    severity: Number(entry.priorityScore || entry.priority_score || 0) >= 72 ? 'HIGH' : Number(entry.priorityScore || entry.priority_score || 0) >= 52 ? 'MEDIUM' : 'LOW',
    needs_review: reviewStatus !== 'reviewed',
    finding_count: reasonList.length,
    evidence: Array.isArray(entry.evidence) ? entry.evidence : [],
    next_steps: Array.isArray(entry.nextSteps) ? entry.nextSteps : [],
    related: {
      apis: importSignals.map((signal) => signal.function).filter(Boolean),
      callsites: importSignals.flatMap((signal) => Array.isArray(signal.callsites) ? signal.callsites.map((site) => ({ addr: site.callsite_addr || site.source_addr || '', text: site.text || '' })) : []),
      strings: stringSignals.map((signal) => ({ addr: signal.target_addr || '', preview: signal.preview || '', length: Number(signal.length || 1) || 1 })),
      annotations,
    },
    review_hint: String(entry.reviewHint || entry.review_hint || ''),
  };
  const proofDossiers = Array.isArray(entry.proofDossiers || entry.proof_dossiers) && (entry.proofDossiers || entry.proof_dossiers).length
    ? (entry.proofDossiers || entry.proof_dossiers)
    : [fallbackProofDossier];
  return {
    exported_at: new Date().toISOString(),
    binary_path: summary.binaryPath || getStaticBinaryPath() || '',
    function: {
      addr: normalizeHexAddress(entry.addr || ''),
      name: entry.name || '',
      type: entry.typeLabel || entry.kind || 'function',
      convention: entry.conv || '—',
      size: entry.sizeStr || '—',
      block_count: Number(entry.blockCount || 0),
      incoming_calls: Number(entry.incomingCalls || 0),
      outgoing_calls: Number(entry.outgoingCalls || 0),
    },
    radar: {
      priority_score: Number(entry.priorityScore || entry.priority_score || 0),
      priority_level: String(entry.priorityLevel || entry.priority_level || 'low'),
      focus_summary: String(entry.focusSummary || ''),
      signal_tags: Array.isArray(entry.signalTags || entry.signal_tags) ? (entry.signalTags || entry.signal_tags) : [],
      reasons: Array.isArray(entry.reasons) ? entry.reasons : [],
      score_breakdown: scoreBreakdown,
    },
    review: {
      status: reviewStatus,
      label: getFunctionReviewLabel(reviewStatus),
      notes: getFunctionReviewNotes(entry),
      hint: String(entry.reviewHint || entry.review_hint || ''),
      updated: String(entry.reviewUpdated || '').trim(),
    },
    evidence: {
      imports: importSignals,
      strings: stringSignals,
      annotations,
    },
    proof_dossiers: proofDossiers,
    primary_proof_dossier: proofDossiers[0] || null,
  };
}

function exportFunctionDossier(entry) {
  const dossier = buildFunctionDossier(entry);
  if (!dossier) return;
  const addr = normalizeHexAddress(entry?.addr || '') || 'function';
  const slug = sanitizeFunctionExportName(entry?.name || addr);
  vscode.postMessage({
    type: 'hubExportData',
    dataType: 'function_dossier',
    format: 'json',
    data: dossier,
    suggestedName: `function-dossier-${slug}-${addr.replace(/^0x/, '')}.json`,
  });
}

function persistFunctionReview(entry, reviewStatus, reviewNotes = '') {
  const addr = normalizeHexAddress(entry?.addr || '');
  const binaryPath = getStaticBinaryPath();
  if (!addr || !binaryPath) return;
  const nextStatus = String(reviewStatus || '').trim();
  const nextNotes = String(reviewNotes || '').trim();
  const existing = findAnnotationForAddress(addr) || {};
  const nextEntry = {
    ...existing,
    reviewStatus: nextStatus,
    reviewNotes: nextNotes,
    reviewUpdated: new Date().toISOString(),
  };
  if (!nextStatus) delete nextEntry.reviewStatus;
  if (!nextNotes) delete nextEntry.reviewNotes;
  if (!nextStatus && !nextNotes) delete nextEntry.reviewUpdated;
  window._annotations = { ...(window._annotations || {}) };
  if (isAnnotationEntryEmpty(nextEntry)) delete window._annotations[addr];
  else window._annotations[addr] = nextEntry;
  vscode.postMessage({
    type: 'hubSaveFunctionReview',
    binaryPath,
    addr,
    reviewStatus: nextStatus,
    reviewNotes: nextNotes,
  });
  renderCurrentFunctionsWorkspace();
  updateActiveContextBars(window._lastDisasmAddr || addr);
}

function renderCurrentFunctionsWorkspace() {
  const state = window.functionWorkspaceState;
  if (!state) return;
  renderFunctionsWorkspace(state.baseRows || [], state.radarBase || null, state.opts || {});
}

function openFunctionInView(addr, name, view, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  const bp = getStaticBinaryPath();
  if (!normalized || !bp) return;
  if (view === 'decompile') {
    openDecompileFunction(normalized, name || normalized);
    return;
  }
  jumpToAddrInContextTab(view, normalized, bp, opts);
}

function getFunctionRowByAddr(addr, rows = null) {
  const normalized = normalizeHexAddress(addr);
  const list = Array.isArray(rows) ? rows : (window.functionListCache || []);
  if (!normalized) return null;
  return list.find((entry) => normalizeHexAddress(entry?.addr || '') === normalized) || null;
}


function persistFunctionsUiState() {
  _saveStorage({
    functionsSort: functionsUiState.sort,
    functionsQuickFilter: functionsUiState.quickFilter,
    functionsReviewFilter: functionsUiState.reviewFilter,
    functionsSignalFilter: functionsUiState.signalFilter,
    functionsSelectedAddr: functionsUiState.selectedAddr,
  });
}

function buildFallbackFunctionsRadarFromRows(rows = [], opts = {}) {
  const normalizedRows = Array.isArray(rows) ? rows.slice() : [];
  const hotspots = normalizedRows
    .filter((entry) => Number(entry?.priorityScore || 0) >= 52)
    .slice(0, 6);
  const quickWins = normalizedRows
    .filter((entry) => Number(entry?.priorityScore || 0) >= 38 && (Number(entry?.blockCount || 0) <= 4 || Number(entry?.sizeNum || 0) <= 32))
    .slice(0, 4);
  const entryCandidates = normalizedRows
    .filter((entry) => /^(main|_start|start|entry|sub_)/i.test(String(entry?.name || '')) || Number(entry?.incomingCalls || 0) === 0)
    .slice(0, 4);
  const clusterCounts = new Map();
  normalizedRows.forEach((entry) => {
    (entry.signalTags || []).forEach((tag) => {
      clusterCounts.set(tag, Number(clusterCounts.get(tag) || 0) + 1);
    });
  });
  const clusters = Array.from(clusterCounts.entries())
    .sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))
    .slice(0, 6)
    .map(([name, count]) => ({ name, count }));
  const annotatedFunctions = normalizedRows.filter((entry) => Number(entry?.annotationCount || 0) > 0).length;
  const suspiciousImportSites = normalizedRows.reduce((sum, entry) => sum + Number((entry.importSignals || []).length || 0), 0);
  const suspiciousStringSites = normalizedRows.reduce((sum, entry) => sum + Number((entry.stringSignals || []).length || 0), 0);
  return {
    binary: getStaticBinaryPath(),
    cache_db: '',
    summary: {
      function_count: normalizedRows.length,
      hotspot_count: hotspots.length,
      annotated_functions: annotatedFunctions,
      suspicious_import_sites: suspiciousImportSites,
      suspicious_string_sites: suspiciousStringSites,
      cluster_count: clusters.length,
      source_mode: opts.rawMode ? 'raw' : 'symbolic',
    },
    hotspots,
    quick_wins: quickWins,
    entry_candidates: entryCandidates,
    clusters,
    functions: normalizedRows,
    error: null,
  };
}

function selectFunctionRow(addr, rows = null) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return;
  functionsUiState.selectedAddr = normalized;
  persistFunctionsUiState();
  const currentRows = Array.isArray(rows) ? rows : (window.functionListCache || []);
  renderFunctionDetails(getFunctionRowByAddr(normalized, currentRows));
}

function syncFunctionsSelectionFromContext(addr = window._lastDisasmAddr) {
  const summary = getActiveContextSummary(addr);
  const targetAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  if (!targetAddr) return '';
  const matchingEntry = getFunctionRowByAddr(targetAddr, window.functionListCache || []);
  if (!matchingEntry) return '';
  functionsUiState.selectedAddr = targetAddr;
  persistFunctionsUiState();
  document.querySelectorAll('#functionsContent tr[data-addr]').forEach((row) => {
    const rowAddr = normalizeHexAddress(row.dataset.addr || '');
    row.classList.toggle('functions-row-selected', rowAddr === targetAddr);
  });
  renderFunctionDetails(matchingEntry);
  return targetAddr;
}

function renderFunctionDetails(entry) {
  const container = document.getElementById('functionsDetails');
  if (!container) return;
  if (!entry) {
    container.innerHTML = '<p class="hint">Sélectionnez une fonction pour afficher le détail du score, les preuves et les actions de navigation.</p>';
    return;
  }
  const addr = normalizeHexAddress(entry.addr || '');
  const name = String(entry.name || addr || 'fonction').trim() || 'fonction';
  const scoreClass = getFunctionScoreClass(entry.priorityLevel || entry.priority_level);
  const reviewStatus = String(entry.reviewStatus || entry.review_status || 'unreviewed');
  const reviewHint = String(entry.reviewHint || entry.review_hint || '').trim();
  const breakdown = Array.isArray(entry.scoreBreakdown || entry.score_breakdown) ? (entry.scoreBreakdown || entry.score_breakdown) : [];
  const importSignals = Array.isArray(entry.importSignals || entry.import_signals) ? (entry.importSignals || entry.import_signals) : [];
  const stringSignals = Array.isArray(entry.stringSignals || entry.string_signals) ? (entry.stringSignals || entry.string_signals) : [];
  const annotations = Array.isArray(entry.annotationPreview || entry.annotation_preview) ? (entry.annotationPreview || entry.annotation_preview) : [];
  const reasonList = Array.isArray(entry.reasons) ? entry.reasons : [];
  const signalTags = Array.isArray(entry.signalTags || entry.signal_tags) ? (entry.signalTags || entry.signal_tags) : [];
  const reviewNotes = getFunctionReviewNotes(entry);
  const proofDossiers = Array.isArray(entry.proofDossiers || entry.proof_dossiers) ? (entry.proofDossiers || entry.proof_dossiers) : [];
  const primaryProofDossier = proofDossiers[0] || null;
  const nextSteps = Array.isArray(primaryProofDossier?.next_steps) ? primaryProofDossier.next_steps : (Array.isArray(entry.nextSteps) ? entry.nextSteps : []);
  const metaItems = [
    ['Adresse', addr],
    ['Type', String(entry.typeLabel || entry.kind || 'function')],
    ['Convention', String(entry.conv || '—')],
    ['Taille', String(entry.sizeStr || '—')],
    ['Blocs', String(entry.blockCount || 0)],
    ['Appels entrants', String(entry.incomingCalls || 0)],
    ['Appels sortants', String(entry.outgoingCalls || 0)],
    ['Confiance dossier', String(primaryProofDossier?.confidence || entry.confidence || '—')],
    ['Revue requise', primaryProofDossier?.needs_review ? 'Oui' : 'Non'],
  ];

  container.innerHTML = `
    <div class="functions-details-head">
      <div>
        <p class="static-kicker">Pourquoi</p>
        <h4 class="functions-details-title">${escapeHtml(name)}</h4>
        <p class="functions-details-subtitle">${escapeHtml(String(entry.focusSummary || reasonList[0] || 'Aucun signal fort détaillé.'))}</p>
      </div>
      <div class="functions-details-actions">
        <span class="functions-score ${scoreClass}">${escapeHtml(String(entry.priorityScore || entry.priority_score || 0))}</span>
        <span class="functions-review-badge ${escapeHtml(reviewStatus)}">${escapeHtml(getFunctionReviewLabel(reviewStatus))}</span>
        <button type="button" class="btn btn-sm btn-secondary functions-detail-action" data-view="disasm" data-addr="${escapeHtml(addr)}">Désasm</button>
        <button type="button" class="btn btn-sm btn-secondary functions-detail-action" data-view="decompile" data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">Pseudo-C</button>
        <button type="button" class="btn btn-sm btn-secondary functions-detail-action" data-view="cfg" data-addr="${escapeHtml(addr)}">CFG</button>
        <button type="button" class="btn btn-sm btn-secondary functions-detail-action" data-view="callgraph" data-addr="${escapeHtml(addr)}">Call Graph</button>
        <button type="button" class="btn btn-sm btn-secondary functions-detail-action" data-view="hex" data-addr="${escapeHtml(addr)}">Hex</button>
        <button type="button" class="btn btn-sm btn-secondary functions-export-action" data-addr="${escapeHtml(addr)}">Dossier</button>
      </div>
    </div>
    <div class="functions-details-grid">
      <div class="functions-details-card">
        <h4>Breakdown du score</h4>
        <div class="functions-breakdown-list">
          ${breakdown.length ? breakdown.map((item) => `
            <div class="functions-breakdown-item">
              <div class="functions-breakdown-main">
                <span class="functions-breakdown-label">${escapeHtml(String(item.label || 'Signal'))}</span>
                <span class="functions-breakdown-detail">${escapeHtml(String(item.detail || ''))}</span>
              </div>
              <span class="functions-breakdown-points">${Number(item.points || 0) > 0 ? '+' : ''}${escapeHtml(String(item.points || 0))}</span>
            </div>
          `).join('') : '<p class="hint">Aucun détail de score disponible.</p>'}
        </div>
        <h4>Hypothèses de lecture</h4>
        <div class="functions-evidence-list">
          ${reasonList.length ? reasonList.map((item) => `<div class="functions-evidence-item"><div class="functions-evidence-title">${escapeHtml(String(item))}</div></div>`).join('') : '<p class="hint">Aucune hypothèse synthétique.</p>'}
        </div>
      </div>
      <div class="functions-details-card">
        <h4>Preuves et contexte</h4>
        <div class="functions-meta-list">
          ${metaItems.map(([label, value]) => `<div class="functions-meta-item"><div class="functions-breakdown-label">${escapeHtml(label)}</div><div class="functions-meta-value">${escapeHtml(String(value || '—'))}</div></div>`).join('')}
          ${reviewHint ? `<div class="functions-meta-item"><div class="functions-breakdown-label">Revue</div><div class="functions-meta-value">${escapeHtml(reviewHint)}</div></div>` : ''}
        </div>
        <h4>Signaux</h4>
        <div class="functions-radar-badges">
          ${signalTags.length ? signalTags.map((tag) => `<span class="functions-radar-badge">${escapeHtml(String(tag))}</span>`).join('') : '<span class="hint">Aucun badge particulier.</span>'}
        </div>
        ${nextSteps.length ? `
          <h4>Étapes suggérées</h4>
          <div class="functions-evidence-list">
            ${nextSteps.map((step) => `<div class="functions-evidence-item"><div class="functions-evidence-desc">${escapeHtml(String(step))}</div></div>`).join('')}
          </div>
        ` : ''}
        <h4>Workflow de revue</h4>
        <div class="functions-review-panel">
          <div class="functions-review-toolbar">
            <select class="select-modern functions-review-select" data-addr="${escapeHtml(addr)}">
              <option value="unreviewed"${reviewStatus === 'unreviewed' ? ' selected' : ''}>Sans revue</option>
              <option value="todo"${reviewStatus === 'todo' ? ' selected' : ''}>À revoir</option>
              <option value="in_progress"${reviewStatus === 'in_progress' ? ' selected' : ''}>En cours</option>
              <option value="reviewed"${reviewStatus === 'reviewed' ? ' selected' : ''}>Reviewée</option>
              <option value="important"${reviewStatus === 'important' ? ' selected' : ''}>Prioritaire</option>
            </select>
            <button type="button" class="btn btn-xs btn-secondary functions-review-save" data-addr="${escapeHtml(addr)}">Enregistrer</button>
            <button type="button" class="btn btn-xs btn-secondary functions-review-clear" data-addr="${escapeHtml(addr)}">Effacer</button>
          </div>
          <textarea class="functions-review-notes" data-addr="${escapeHtml(addr)}" rows="3" placeholder="Notes de revue, next steps, hypothèses…">${escapeHtml(reviewNotes)}</textarea>
          <div class="functions-review-shortcuts">
            <button type="button" class="btn btn-xs btn-secondary functions-review-shortcut" data-status="todo">À revoir</button>
            <button type="button" class="btn btn-xs btn-secondary functions-review-shortcut" data-status="in_progress">En cours</button>
            <button type="button" class="btn btn-xs btn-secondary functions-review-shortcut" data-status="reviewed">Reviewée</button>
            <button type="button" class="btn btn-xs btn-secondary functions-review-shortcut" data-status="important">Prioritaire</button>
          </div>
        </div>
      </div>
    </div>
    <div class="functions-details-grid" style="margin-top:12px;">
      <div class="functions-details-card">
        <h4>Imports sensibles exacts</h4>
        <div class="functions-evidence-list">
          ${importSignals.length ? importSignals.map((signal) => `
            <div class="functions-evidence-item">
              <div class="functions-evidence-head">
                <span class="functions-evidence-title">${escapeHtml(String(signal.function || signal.category || 'Import'))}</span>
                <span class="functions-radar-badge">${escapeHtml(String(signal.category || 'signal'))}</span>
              </div>
              <div class="functions-evidence-desc">${escapeHtml(String(signal.description || ''))}</div>
              <div class="functions-evidence-links">
                ${(signal.callsites || []).map((site) => `
                  <button type="button" class="btn btn-xs btn-secondary functions-evidence-jump" data-addr="${escapeHtml(String(site.callsite_addr || site.source_addr || ''))}" data-span="1">
                    ${escapeHtml(String(site.callsite_addr || site.source_addr || 'callsite'))}
                  </button>
                `).join('')}
              </div>
            </div>
          `).join('') : '<p class="hint">Aucun import sensible rattaché à cette fonction.</p>'}
        </div>
      </div>
      <div class="functions-details-card">
        <h4>Chaînes et annotations</h4>
        <div class="functions-evidence-list">
          ${stringSignals.length ? stringSignals.map((signal) => `
            <div class="functions-evidence-item">
              <div class="functions-evidence-head">
                <span class="functions-evidence-title">${escapeHtml(String(signal.label || signal.category || 'Chaîne'))}</span>
                <span class="functions-radar-badge">${escapeHtml(String(signal.target_addr || ''))}</span>
              </div>
              <div class="functions-evidence-desc">${escapeHtml(String(signal.preview || ''))}</div>
              <div class="functions-evidence-links">
                <button type="button" class="btn btn-xs btn-secondary functions-evidence-jump" data-addr="${escapeHtml(String(signal.source_addr || addr))}" data-span="1">Xref ${escapeHtml(String(signal.source_addr || addr))}</button>
                <button type="button" class="btn btn-xs btn-secondary functions-evidence-jump" data-addr="${escapeHtml(String(signal.target_addr || ''))}" data-view="hex" data-span="${escapeHtml(String(signal.length || getKnownSpanLengthForAddress(signal.target_addr || '')))}">Chaîne</button>
              </div>
            </div>
          `).join('') : '<p class="hint">Aucune chaîne parlante rattachée à cette fonction.</p>'}
          ${annotations.length ? `
            <div class="functions-evidence-item">
              <div class="functions-evidence-title">Annotations locales</div>
              <div class="functions-evidence-desc">${annotations.map((item) => escapeHtml(String(item))).join('<br/>')}</div>
            </div>
          ` : ''}
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll('.functions-detail-action').forEach((button) => {
    button.addEventListener('click', () => {
      const view = button.dataset.view || 'disasm';
      openFunctionInView(button.dataset.addr || '', button.dataset.name || name, view, {
        spanLength: normalizeSpanLength(button.dataset.span || 1),
      });
    });
  });
  container.querySelector('.functions-export-action')?.addEventListener('click', () => {
    exportFunctionDossier(entry);
  });
  container.querySelectorAll('.functions-evidence-jump').forEach((button) => {
    button.addEventListener('click', () => {
      const view = button.dataset.view || 'disasm';
      openFunctionInView(button.dataset.addr || '', name, view, {
        spanLength: normalizeSpanLength(button.dataset.span || 1),
      });
    });
  });
  container.querySelectorAll('.functions-review-shortcut').forEach((button) => {
    button.addEventListener('click', () => {
      const select = container.querySelector('.functions-review-select');
      if (select) select.value = button.dataset.status || 'unreviewed';
    });
  });
  container.querySelector('.functions-review-save')?.addEventListener('click', () => {
    const select = container.querySelector('.functions-review-select');
    const notes = container.querySelector('.functions-review-notes');
    persistFunctionReview(entry, select?.value || 'unreviewed', notes?.value || '');
  });
  container.querySelector('.functions-review-clear')?.addEventListener('click', () => {
    persistFunctionReview(entry, '', '');
  });
}

function syncFunctionsSignalFilterOptions(rows = [], radar = null) {
  const signalSelect = document.getElementById('functionsSignalFilter');
  if (!signalSelect) return;
  const currentValue = String(functionsUiState.signalFilter || 'all');
  const tags = new Set();
  (Array.isArray(radar?.clusters) ? radar.clusters : []).forEach((cluster) => {
    const name = String(cluster?.name || '').trim();
    if (name) tags.add(name);
  });
  (Array.isArray(rows) ? rows : []).forEach((entry) => {
    (Array.isArray(entry?.signalTags) ? entry.signalTags : []).forEach((tag) => {
      const normalized = String(tag || '').trim();
      if (normalized) tags.add(normalized);
    });
  });
  const sortedTags = Array.from(tags).sort((a, b) => a.localeCompare(b, 'fr'));
  signalSelect.innerHTML = [
    '<option value="all">Tous signaux</option>',
    ...sortedTags.map((tag) => `<option value="${escapeHtml(tag)}">${escapeHtml(tag)}</option>`),
  ].join('');
  signalSelect.value = sortedTags.includes(currentValue) ? currentValue : 'all';
  if (signalSelect.value !== currentValue) {
    functionsUiState.signalFilter = signalSelect.value;
    persistFunctionsUiState();
  }
}

function bindFunctionsFilterControls(renderFn) {
  const pillWrap = document.getElementById('functionsFilterPills');
  const reviewSelect = document.getElementById('functionsReviewFilter');
  const signalSelect = document.getElementById('functionsSignalFilter');
  if (pillWrap) {
    pillWrap.querySelectorAll('[data-functions-filter]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.functionsFilter === functionsUiState.quickFilter);
      button.onclick = () => {
        functionsUiState.quickFilter = button.dataset.functionsFilter || 'all';
        pillWrap.querySelectorAll('[data-functions-filter]').forEach((item) => {
          item.classList.toggle('is-active', item === button);
        });
        persistFunctionsUiState();
        renderFn();
      };
    });
  }
  if (reviewSelect) {
    reviewSelect.value = functionsUiState.reviewFilter || 'all';
    reviewSelect.onchange = () => {
      functionsUiState.reviewFilter = reviewSelect.value || 'all';
      persistFunctionsUiState();
      renderFn();
    };
  }
  if (signalSelect) {
    signalSelect.value = functionsUiState.signalFilter || 'all';
    signalSelect.onchange = () => {
      functionsUiState.signalFilter = signalSelect.value || 'all';
      persistFunctionsUiState();
      renderFn();
    };
  }
}

function buildFunctionsRowsFromRadarAndSymbols(symList = [], conventions = {}, radarFunctions = []) {
  const radarByAddr = new Map(
    (Array.isArray(radarFunctions) ? radarFunctions : [])
      .map((entry) => [normalizeHexAddress(entry?.addr || ''), entry])
      .filter((entry) => entry[0])
  );
  const rowsByAddr = new Map();

  (Array.isArray(symList) ? symList : []).forEach((symbol) => {
    const addr = normalizeHexAddress(symbol?.addr || '');
    if (!addr) return;
    const radarEntry = radarByAddr.get(addr) || {};
    const convInfo = conventions[symbol.addr] || conventions[addr];
    let typeLabel;
    if (symbol.type === 'T' || symbol.type === 't') typeLabel = 'local';
    else if (symbol.type === 'U') typeLabel = 'PLT';
    else typeLabel = symbol.type || '?';
    const sizeNum = Number(symbol.size || radarEntry.size || 0) || 0;
    rowsByAddr.set(addr, {
      addr,
      name: String(radarEntry.name || symbol.name || addr),
      sizeNum,
      sizeStr: sizeNum > 0 ? `${sizeNum} B` : '—',
      typeLabel,
      conv: String((convInfo && convInfo.convention) ? convInfo.convention : '—'),
      priorityScore: Number(radarEntry.priority_score || 0),
      priorityLevel: String(radarEntry.priority_level || 'low'),
      focusSummary: String(radarEntry.focus_summary || ''),
      incomingCalls: Number(radarEntry.incoming_calls || 0),
      outgoingCalls: Number(radarEntry.outgoing_calls || 0),
      blockCount: Number(radarEntry.block_count || 0),
      annotationCount: Number(radarEntry.annotation_count || 0),
      signalTags: Array.isArray(radarEntry.signal_tags) ? radarEntry.signal_tags : [],
      reasons: Array.isArray(radarEntry.reasons) ? radarEntry.reasons : [],
      importSignals: Array.isArray(radarEntry.import_signals) ? radarEntry.import_signals : [],
      stringSignals: Array.isArray(radarEntry.string_signals) ? radarEntry.string_signals : [],
      annotationPreview: Array.isArray(radarEntry.annotation_preview) ? radarEntry.annotation_preview : [],
      scoreBreakdown: Array.isArray(radarEntry.score_breakdown) ? radarEntry.score_breakdown : [],
      reviewStatus: String(radarEntry.review_status || 'unreviewed'),
      reviewHint: String(radarEntry.review_hint || ''),
      confidence: String(radarEntry.confidence || ''),
      needsReview: !!radarEntry.needs_review,
      evidence: Array.isArray(radarEntry.evidence) ? radarEntry.evidence : [],
      nextSteps: Array.isArray(radarEntry.next_steps) ? radarEntry.next_steps : [],
      proofDossiers: Array.isArray(radarEntry.proof_dossiers) ? radarEntry.proof_dossiers : [],
      sourceMode: 'symbolic',
      kind: String(radarEntry.kind || ''),
    });
  });

  (Array.isArray(radarFunctions) ? radarFunctions : []).forEach((entry) => {
    const addr = normalizeHexAddress(entry?.addr || '');
    if (!addr || rowsByAddr.has(addr)) return;
    const sizeNum = Number(entry.size || 0) || 0;
    rowsByAddr.set(addr, {
      addr,
      name: String(entry.name || addr),
      sizeNum,
      sizeStr: sizeNum > 0 ? `${sizeNum} B` : '—',
      typeLabel: entry.kind === 'import' ? 'PLT' : 'auto',
      conv: '—',
      priorityScore: Number(entry.priority_score || 0),
      priorityLevel: String(entry.priority_level || 'low'),
      focusSummary: String(entry.focus_summary || ''),
      incomingCalls: Number(entry.incoming_calls || 0),
      outgoingCalls: Number(entry.outgoing_calls || 0),
      blockCount: Number(entry.block_count || 0),
      annotationCount: Number(entry.annotation_count || 0),
      signalTags: Array.isArray(entry.signal_tags) ? entry.signal_tags : [],
      reasons: Array.isArray(entry.reasons) ? entry.reasons : [],
      importSignals: Array.isArray(entry.import_signals) ? entry.import_signals : [],
      stringSignals: Array.isArray(entry.string_signals) ? entry.string_signals : [],
      annotationPreview: Array.isArray(entry.annotation_preview) ? entry.annotation_preview : [],
      scoreBreakdown: Array.isArray(entry.score_breakdown) ? entry.score_breakdown : [],
      reviewStatus: String(entry.review_status || 'unreviewed'),
      reviewHint: String(entry.review_hint || ''),
      confidence: String(entry.confidence || ''),
      needsReview: !!entry.needs_review,
      evidence: Array.isArray(entry.evidence) ? entry.evidence : [],
      nextSteps: Array.isArray(entry.next_steps) ? entry.next_steps : [],
      proofDossiers: Array.isArray(entry.proof_dossiers) ? entry.proof_dossiers : [],
      sourceMode: 'symbolic',
      kind: String(entry.kind || ''),
    });
  });

  return Array.from(rowsByAddr.values());
}

function buildFunctionsRowsFromDiscovered(discovered = []) {
  return (Array.isArray(discovered) ? discovered : []).map((entry) => {
    const addr = normalizeHexAddress(entry?.addr || '');
    const confidenceScore = Number(entry?.confidence_score || 0);
    const scaledScore = Math.max(10, Math.min(95, Math.round(confidenceScore * 100)));
    const reason = String(entry?.reason || '').trim();
    const confidence = String(entry?.confidence || '').trim();
    const signalTags = [];
    if (reason) signalTags.push(reason);
    if (confidence) signalTags.push(`conf:${confidence}`);
    return {
      addr,
      name: String(entry?.name || addr || 'sub'),
      sizeNum: Number(entry?.size || 0) || 0,
      sizeStr: Number(entry?.size || 0) > 0 ? `${Number(entry.size)} B` : '—',
      typeLabel: String(entry?.kind || 'auto'),
      conv: '—',
      priorityScore: scaledScore,
      priorityLevel: scaledScore >= 72 ? 'critical' : scaledScore >= 52 ? 'high' : scaledScore >= 30 ? 'medium' : 'low',
      focusSummary: String(reason || confidence || 'Fonction découverte automatiquement'),
      incomingCalls: 0,
      outgoingCalls: 0,
      blockCount: 0,
      annotationCount: 0,
      signalTags,
      reasons: [String(reason || 'Fonction découverte automatiquement')],
      importSignals: [],
      stringSignals: [],
      annotationPreview: [],
      scoreBreakdown: [
        { points: scaledScore, label: 'Confiance de découverte', detail: `${confidence || 'score heuristique'} ${Number.isFinite(confidenceScore) ? `(${Math.round(confidenceScore * 100)}%)` : ''}`.trim() },
      ],
      reviewStatus: scaledScore >= 52 ? 'todo' : 'unreviewed',
      reviewHint: scaledScore >= 52 ? 'Bonne cible brute à confirmer dans le désassemblage.' : 'À confirmer via le désassemblage.',
      confidence: scaledScore >= 72 ? 'HIGH' : scaledScore >= 40 ? 'MEDIUM' : 'LOW',
      needsReview: scaledScore >= 40,
      evidence: [
        {
          kind: 'raw_discovery',
          summary: String(reason || confidence || 'Fonction découverte automatiquement'),
          addr,
        },
      ],
      nextSteps: [
        'Valider le prologue et les callsites dans le désassemblage.',
        'Ouvrir le CFG ou le pseudo-C si la fonction semble structurée.',
      ],
      proofDossiers: [],
      sourceMode: 'raw',
      kind: String(entry?.kind || 'function'),
    };
  }).filter((entry) => entry.addr);
}

function renderFunctionsWorkspace(rows = [], radar = null, opts = {}) {
  const container = document.getElementById('functionsContent');
  const countEl = document.getElementById('functionsCount');
  const searchEl = document.getElementById('functionsSearch');
  const sortSelect = document.getElementById('functionsSortSelect');
  if (!container) return;

  const effectiveRadarBase = radar || buildFallbackFunctionsRadarFromRows(rows, opts);
  const decoratedRows = enrichFunctionsRowsWithAnnotations(rows);
  const effectiveRadar = mergeFunctionsRadarWithRows(effectiveRadarBase, decoratedRows, opts);
  window.functionWorkspaceState = {
    baseRows: Array.isArray(rows) ? rows.slice() : [],
    radarBase: effectiveRadarBase,
    opts: { ...opts },
  };
  window.functionListCache = decoratedRows.slice();
  window.functionRadarCache = effectiveRadar;
  renderFunctionsRadar(effectiveRadar);
  syncFunctionsSignalFilterOptions(decoratedRows, effectiveRadar);

  if (sortSelect) {
    const available = Array.from(sortSelect.options).map((opt) => opt.value);
    sortSelect.value = available.includes(functionsUiState.sort) ? functionsUiState.sort : 'priority_desc';
  }
  if (searchEl) {
    searchEl.oninput = () => renderTable();
  }
  if (sortSelect) {
    sortSelect.onchange = () => {
      functionsUiState.sort = sortSelect.value || 'priority_desc';
      persistFunctionsUiState();
      renderTable();
    };
  }
  bindFunctionsFilterControls(renderTable);

  function renderTable() {
    const rawFilter = String(searchEl?.value || '').trim().toLowerCase();
    const quickFilter = String(functionsUiState.quickFilter || 'all');
    const reviewFilter = String(functionsUiState.reviewFilter || 'all');
    const signalFilter = String(functionsUiState.signalFilter || 'all');
    const sortMode = String(sortSelect?.value || functionsUiState.sort || 'priority_desc');

    const filtered = decoratedRows.filter((entry) => {
      const signalTags = Array.isArray(entry.signalTags) ? entry.signalTags : [];
      const reviewStatus = String(entry.reviewStatus || 'unreviewed');
      const haystack = [
        entry.name,
        entry.addr,
        entry.focusSummary,
        reviewStatus,
        ...(Array.isArray(entry.reasons) ? entry.reasons : []),
        ...signalTags,
      ].join(' ').toLowerCase();
      if (rawFilter && !haystack.includes(rawFilter)) return false;
      if (quickFilter === 'hotspots' && Number(entry.priorityScore || 0) < 52) return false;
      if (quickFilter === 'annotated' && Number(entry.annotationCount || 0) <= 0) return false;
      if (quickFilter === 'todo' && reviewStatus !== 'todo') return false;
      if (reviewFilter !== 'all' && reviewStatus !== reviewFilter) return false;
      if (signalFilter !== 'all' && !signalTags.includes(signalFilter)) return false;
      return true;
    });

    filtered.sort((a, b) => {
      if (sortMode === 'priority_desc') {
        return (b.priorityScore - a.priorityScore)
          || (b.incomingCalls - a.incomingCalls)
          || (b.blockCount - a.blockCount)
          || ((parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0));
      }
      if (sortMode === 'size_desc') {
        return (b.sizeNum - a.sizeNum)
          || (b.priorityScore - a.priorityScore)
          || ((parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0));
      }
      if (sortMode === 'name_asc') {
        return a.name.localeCompare(b.name)
          || ((parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0));
      }
      if (sortMode === 'incoming_desc') {
        return (b.incomingCalls - a.incomingCalls)
          || (b.priorityScore - a.priorityScore)
          || ((parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0));
      }
      return (parseNumericAddress(a.addr) || 0) - (parseNumericAddress(b.addr) || 0);
    });

    if (countEl) {
      const hotCount = filtered.filter((entry) => Number(entry.priorityScore || 0) >= 52).length;
      countEl.textContent = `${filtered.length} fonction(s) · ${hotCount} chaude(s)`;
    }

      const selectedAddr = getFunctionRowByAddr(functionsUiState.selectedAddr, filtered)?.addr
      || filtered[0]?.addr
      || '';
    if (selectedAddr) {
      functionsUiState.selectedAddr = selectedAddr;
      persistFunctionsUiState();
    }

    if (!filtered.length) {
      container.innerHTML = '<p class="hint">Aucune fonction ne correspond aux filtres actifs.</p>';
      renderFunctionDetails(null);
      return;
    }

    const tbody = filtered.map((entry) => {
      const scoreClass = getFunctionScoreClass(entry.priorityLevel);
      const subtitle = entry.focusSummary || entry.reasons?.[0] || 'Signal faible';
      const metrics = [];
      if (entry.sizeStr && entry.sizeStr !== '—') metrics.push(entry.sizeStr);
      if (entry.blockCount) metrics.push(`${entry.blockCount} bloc${entry.blockCount > 1 ? 's' : ''}`);
      if (entry.incomingCalls) metrics.push(`${entry.incomingCalls} entrant${entry.incomingCalls > 1 ? 's' : ''}`);
      if (entry.annotationCount) metrics.push(`${entry.annotationCount} note${entry.annotationCount > 1 ? 's' : ''}`);
      const isSelected = normalizeHexAddress(entry.addr) === normalizeHexAddress(selectedAddr);
      return `
        <tr class="nav-addr-row ${isSelected ? 'functions-row-selected' : ''}" data-addr="${escapeHtml(entry.addr)}" data-addr-match="function">
          <td><span class="functions-score ${escapeHtml(scoreClass)}">${escapeHtml(String(entry.priorityScore || 0))}</span></td>
          <td><code class="addr-link" data-addr="${escapeHtml(entry.addr)}">${escapeHtml(entry.addr)}</code></td>
          <td>
            <div class="functions-table-name">
              <div class="functions-table-name-head">
                <span class="functions-table-name-text">${escapeHtml(entry.name)}</span>
                <span class="imports-cat-badge function">${escapeHtml(String(entry.typeLabel || 'function'))}</span>
                <span class="functions-review-badge ${escapeHtml(String(entry.reviewStatus || 'unreviewed'))}">${escapeHtml(getFunctionReviewLabel(entry.reviewStatus || 'unreviewed'))}</span>
              </div>
              <div class="functions-table-subtitle">${escapeHtml(subtitle)}</div>
              <div class="functions-table-signals">
                ${(entry.signalTags || []).slice(0, 5).map((tag) => `<span class="functions-table-signal">${escapeHtml(String(tag))}</span>`).join('')}
              </div>
            </div>
          </td>
          <td><div class="functions-table-metrics">${escapeHtml(metrics.length ? metrics.join(' · ') : entry.sizeStr)}</div></td>
          <td>${escapeHtml(String(entry.conv || '—'))}</td>
          <td class="functions-table-actions">
            <div class="functions-row-actions">
              <button type="button" class="btn btn-xs btn-secondary functions-row-action" data-view="disasm" data-addr="${escapeHtml(entry.addr)}" data-name="${escapeHtml(entry.name)}">Désasm</button>
              <button type="button" class="btn btn-xs btn-secondary functions-row-action" data-view="decompile" data-addr="${escapeHtml(entry.addr)}" data-name="${escapeHtml(entry.name)}">Pseudo-C</button>
              <button type="button" class="btn btn-xs btn-secondary functions-row-action" data-view="cfg" data-addr="${escapeHtml(entry.addr)}" data-name="${escapeHtml(entry.name)}">CFG</button>
              <button type="button" class="btn btn-xs btn-secondary functions-row-action" data-view="callgraph" data-addr="${escapeHtml(entry.addr)}" data-name="${escapeHtml(entry.name)}">Graph</button>
            </div>
          </td>
        </tr>
      `;
    }).join('');

    container.innerHTML = `
      <table class="data-table functions-table">
        <thead>
          <tr>
            <th>Priorité</th>
            <th>Adresse</th>
            <th>Fonction</th>
            <th>Métriques</th>
            <th>Convention</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>${tbody}</tbody>
      </table>
    `;

    container.querySelectorAll('tbody tr[data-addr]').forEach((rowEl) => {
      rowEl.addEventListener('click', (event) => {
        if (event.target?.closest('.addr-link, .functions-row-action')) return;
        selectFunctionRow(rowEl.dataset.addr || '', decoratedRows);
        renderTable();
      });
    });
    container.querySelectorAll('.addr-link').forEach((el) => {
      el.style.cursor = 'pointer';
      el.onclick = () => {
        const addr = el.dataset.addr || '';
        selectFunctionRow(addr, decoratedRows);
        vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() });
      };
    });
    container.querySelectorAll('.functions-row-action').forEach((el) => {
      el.onclick = () => {
        const addr = el.dataset.addr || '';
        selectFunctionRow(addr, decoratedRows);
        openFunctionInView(addr, el.dataset.name || '', el.dataset.view || 'disasm');
      };
    });

    updateActiveNavRows(window._lastDisasmAddr);
    renderFunctionDetails(getFunctionRowByAddr(selectedAddr, decoratedRows));
  }

  renderTable();
}

function renderFunctionsRadar(radar = {}) {
  const container = document.getElementById('functionsRadar');
  if (!container) return;
  if (radar?.error) {
    container.innerHTML = `<p class="hint">Radar indisponible : ${escapeHtml(String(radar.error || 'erreur inconnue'))}</p>`;
    return;
  }
  const summary = radar.summary || {};
  const hotspots = Array.isArray(radar.hotspots) ? radar.hotspots : [];
  const quickWins = Array.isArray(radar.quick_wins) ? radar.quick_wins : [];
  const entryCandidates = Array.isArray(radar.entry_candidates) ? radar.entry_candidates : [];
  const clusters = Array.isArray(radar.clusters) ? radar.clusters : [];
  const sourceMode = String(summary.source_mode || 'symbolic');
  const sourceLabel = sourceMode === 'raw' ? 'Vue brute heuristique' : 'Vue symbolique priorisée';

  const renderRow = (entry, actionLabel) => {
    const addr = normalizeHexAddress(entry?.addr || '');
    const name = String(entry?.name || addr || 'fonction').trim() || 'fonction';
    const score = Number(entry?.priority_score || 0);
    const scoreClass = getFunctionScoreClass(entry?.priority_level);
    const summaryText = String(entry?.focus_summary || entry?.reasons?.[0] || 'Signal faible').trim();
    const badges = Array.isArray(entry?.signal_tags) ? entry.signal_tags.slice(0, 4) : [];
    return `
      <div class="functions-radar-row">
        <div class="functions-radar-row-main">
          <div class="functions-radar-row-title">
            <span class="functions-radar-row-name">${escapeHtml(name)}</span>
            <code class="addr-link" data-addr="${escapeHtml(addr)}">${escapeHtml(addr)}</code>
          </div>
          <div class="functions-radar-row-summary">${escapeHtml(summaryText)}</div>
          <div class="functions-radar-badges">
            ${badges.map((tag) => `<span class="functions-radar-badge">${escapeHtml(String(tag))}</span>`).join('')}
          </div>
          <div class="functions-radar-actions">
            <button type="button" class="btn btn-xs btn-secondary functions-radar-action" data-view="disasm" data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">${escapeHtml(actionLabel)}</button>
            <button type="button" class="btn btn-xs btn-secondary functions-radar-action" data-view="decompile" data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">Pseudo-C</button>
            <button type="button" class="btn btn-xs btn-secondary functions-radar-action" data-view="cfg" data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">CFG</button>
            <button type="button" class="btn btn-xs btn-secondary functions-radar-action" data-view="callgraph" data-addr="${escapeHtml(addr)}" data-name="${escapeHtml(name)}">Graph</button>
          </div>
        </div>
        <span class="functions-score ${scoreClass}">${escapeHtml(String(score))}</span>
      </div>
    `;
  };

  const renderSection = (title, list, actionLabel, emptyLabel) => `
    <section class="functions-radar-card">
      <h4 class="functions-radar-card-title">${escapeHtml(title)}</h4>
      <div class="functions-radar-list">
        ${list.length ? list.map((entry) => renderRow(entry, actionLabel)).join('') : `<p class="hint">${escapeHtml(emptyLabel)}</p>`}
      </div>
    </section>
  `;

  container.innerHTML = `
    <div class="functions-radar-head">
      <div>
        <p class="static-kicker">Radar</p>
        <h4 class="functions-radar-title">Priorisation intelligente des fonctions</h4>
        <p class="functions-radar-desc">
          ${escapeHtml(sourceLabel)}. Le radar combine structure, centralité, imports sensibles, chaînes parlantes et annotations pour indiquer où commencer.
        </p>
      </div>
    </div>
    <div class="functions-radar-summary">
      <div class="functions-radar-stat">
        <span class="functions-radar-stat-label">Fonctions</span>
        <strong class="functions-radar-stat-value">${escapeHtml(String(summary.function_count || 0))}</strong>
      </div>
      <div class="functions-radar-stat">
        <span class="functions-radar-stat-label">Hotspots</span>
        <strong class="functions-radar-stat-value">${escapeHtml(String(summary.hotspot_count || 0))}</strong>
      </div>
      <div class="functions-radar-stat">
        <span class="functions-radar-stat-label">Imports sensibles</span>
        <strong class="functions-radar-stat-value">${escapeHtml(String(summary.suspicious_import_sites || 0))}</strong>
      </div>
      <div class="functions-radar-stat">
        <span class="functions-radar-stat-label">Chaînes parlantes</span>
        <strong class="functions-radar-stat-value">${escapeHtml(String(summary.suspicious_string_sites || 0))}</strong>
      </div>
      <div class="functions-radar-stat">
        <span class="functions-radar-stat-label">Fonctions annotées</span>
        <strong class="functions-radar-stat-value">${escapeHtml(String(summary.annotated_functions || 0))}</strong>
      </div>
    </div>
    <div class="functions-radar-grid">
      <div class="functions-radar-card">
        <h4 class="functions-radar-card-title">Signaux à attaquer en premier</h4>
        <div class="functions-radar-list">
          ${hotspots.length ? hotspots.slice(0, 5).map((entry) => renderRow(entry, 'Ouvrir')).join('') : '<p class="hint">Aucun hotspot marqué pour ce binaire.</p>'}
        </div>
      </div>
      <div class="functions-radar-card">
        <h4 class="functions-radar-card-title">Entrées rapides</h4>
        <div class="functions-radar-list">
          ${entryCandidates.length ? entryCandidates.slice(0, 4).map((entry) => renderRow(entry, 'Entrer')).join('') : '<p class="hint">Aucune entrée candidate claire.</p>'}
        </div>
        <h4 class="functions-radar-card-title">Quick wins</h4>
        <div class="functions-radar-list">
          ${quickWins.length ? quickWins.slice(0, 3).map((entry) => renderRow(entry, 'Zoomer')).join('') : '<p class="hint">Pas de petite cible à haute valeur pour le moment.</p>'}
        </div>
        <h4 class="functions-radar-card-title">Familles de signaux</h4>
        <div class="functions-radar-clusters">
          ${clusters.length ? clusters.map((cluster) => `<span class="functions-radar-cluster">${escapeHtml(String(cluster.name || 'signal'))}<strong>${escapeHtml(String(cluster.count || 0))}</strong></span>`).join('') : '<span class="hint">Aucune famille dominante</span>'}
        </div>
      </div>
    </div>
  `;

  container.querySelectorAll('.addr-link').forEach((el) => {
    el.addEventListener('click', () => {
      const addr = el.dataset.addr;
      if (addr) {
        selectFunctionRow(addr);
        vscode.postMessage({ type: 'hubGoToAddress', addr, binaryPath: getStaticBinaryPath() });
      }
    });
  });
  container.querySelectorAll('.functions-radar-action').forEach((el) => {
    el.addEventListener('click', () => {
      const addr = el.dataset.addr;
      if (addr) {
        selectFunctionRow(addr);
        openFunctionInView(addr, el.dataset.name || '', el.dataset.view || 'disasm');
      }
    });
  });
}

function normalizeSpanLength(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 1;
  return Math.max(1, Math.floor(parsed));
}

function buildHexSelectionDescriptor(addr, opts = {}) {
  const activeAddr = normalizeHexAddress(opts.activeAddr || addr);
  const anchorAddr = normalizeHexAddress(opts.anchorAddr || addr);
  const normalizedStart = normalizeHexAddress(addr);
  if (!normalizedStart) return null;
  const startNum = parseNumericAddress(normalizedStart);
  if (!Number.isFinite(startNum)) return null;

  let endAddr = normalizeHexAddress(opts.endAddr || '');
  let endNum = Number.isFinite(parseNumericAddress(endAddr)) ? parseNumericAddress(endAddr) : null;
  if (!Number.isFinite(endNum)) {
    endNum = startNum + normalizeSpanLength(opts.spanLength) - 1;
    endAddr = `0x${endNum.toString(16)}`;
  }

  const low = Math.min(startNum, endNum);
  const high = Math.max(startNum, endNum);
  return {
    startAddr: `0x${low.toString(16)}`,
    endAddr: `0x${high.toString(16)}`,
    activeAddr: activeAddr || `0x${low.toString(16)}`,
    anchorAddr: anchorAddr || `0x${low.toString(16)}`,
    startNum: low,
    endNum: high,
    spanLength: Math.max(1, (high - low) + 1),
  };
}

function getCurrentHexSelectionDescriptor() {
  if (hexSelectionModel.startAddr) {
    return buildHexSelectionDescriptor(hexSelectionModel.startAddr, {
      endAddr: hexSelectionModel.endAddr,
      activeAddr: hexSelectionModel.activeAddr || hexSelectionModel.startAddr,
      anchorAddr: hexSelectionModel.anchorAddr || hexSelectionModel.startAddr,
      spanLength: hexSelectionModel.spanLength || 1,
    });
  }
  if (!window._lastDisasmAddr) return null;
  return buildHexSelectionDescriptor(window._lastDisasmAddr, {
    activeAddr: window._lastDisasmAddr,
    anchorAddr: window._lastDisasmAddr,
    spanLength: 1,
  });
}

function setHexSelectionModel(descriptor) {
  if (!descriptor) {
    hexSelectionModel = {
      startAddr: '',
      endAddr: '',
      activeAddr: '',
      anchorAddr: '',
      spanLength: 1,
    };
    typedDataUiState.hexStructPreview = null;
    updateHexSelectionButtons();
    return;
  }
  if (
    typedDataUiState.hexStructPreview
    && normalizeHexAddress(typedDataUiState.hexStructPreview.addr || '') !== normalizeHexAddress(descriptor.startAddr)
  ) {
    typedDataUiState.hexStructPreview = null;
  }
  hexSelectionModel = {
    startAddr: descriptor.startAddr,
    endAddr: descriptor.endAddr,
    activeAddr: descriptor.activeAddr,
    anchorAddr: descriptor.anchorAddr,
    spanLength: descriptor.spanLength,
  };
  updateHexSelectionButtons();
}

function updateHexSelectionButtons() {
  const hasSelection = !!hexSelectionModel.startAddr;
  const openBtn = document.getElementById('btnHexOpenSelection');
  if (openBtn) openBtn.disabled = !hasSelection;
  const resetBtn = document.getElementById('btnHexResetSelection');
  if (resetBtn) {
    resetBtn.disabled = !hasSelection || normalizeSpanLength(hexSelectionModel.spanLength) <= 1;
  }
}

function vaddrFromFileOffset(fileOffset, sections = hexSections) {
  const fileOffsetNum = parseNumericAddress(fileOffset);
  if (!Number.isFinite(fileOffsetNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset ?? sec.offset_hex);
    const secVaddr = parseNumericAddress(sec.virtual_address ?? sec.vma ?? sec.vma_hex);
    const secSize = parseNumericAddress(sec.size ?? sec.size_hex);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secVaddr) || !Number.isFinite(secSize)) continue;
    if (fileOffsetNum >= secOffset && fileOffsetNum < secOffset + secSize) {
      return `0x${(secVaddr + (fileOffsetNum - secOffset)).toString(16)}`;
    }
  }
  return null;
}

function findSectionForFileOffset(fileOffset, sections = hexSections) {
  const fileOffsetNum = parseNumericAddress(fileOffset);
  if (!Number.isFinite(fileOffsetNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset ?? sec.offset_hex);
    const secSize = parseNumericAddress(sec.size ?? sec.size_hex);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secSize)) continue;
    if (fileOffsetNum >= secOffset && fileOffsetNum < secOffset + secSize) return sec;
  }
  return null;
}

function fileOffsetFromVaddr(vaddr, sections = hexSections) {
  const vaddrNum = parseNumericAddress(vaddr);
  if (!Number.isFinite(vaddrNum)) return null;
  for (const sec of sections || []) {
    const secOffset = parseNumericAddress(sec.offset ?? sec.offset_hex);
    const secVaddr = parseNumericAddress(sec.virtual_address ?? sec.vma ?? sec.vma_hex);
    const secSize = parseNumericAddress(sec.size ?? sec.size_hex);
    if (!Number.isFinite(secOffset) || !Number.isFinite(secVaddr) || !Number.isFinite(secSize)) continue;
    if (vaddrNum >= secVaddr && vaddrNum < secVaddr + secSize) {
      return secOffset + (vaddrNum - secVaddr);
    }
  }
  return null;
}

function getHexSelectionPreview(descriptor, maxBytes = 64) {
  if (!descriptor) return null;
  const bytes = [];
  const ascii = [];
  for (let addrNum = descriptor.startNum; addrNum <= descriptor.endNum && bytes.length < maxBytes; addrNum += 1) {
    const vaddr = `0x${addrNum.toString(16)}`;
    const fileOffset = fileOffsetFromVaddr(vaddr);
    if (!Number.isFinite(fileOffset)) break;
    const rowOffset = fileOffset - (fileOffset % 16);
    const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
    const row = getHexRowByOffsetHex(rowOffsetHex);
    if (!row) break;
    const rowHexParts = String(row.hex || '').trim().split(/\s+/).filter(Boolean);
    const byteIndex = fileOffset - rowOffset;
    bytes.push(rowHexParts[byteIndex] || '??');
    ascii.push(typeof row.ascii === 'string' ? (row.ascii[byteIndex] || '.') : '.');
  }
  if (!bytes.length) return null;
  return {
    hex: bytes.join(' '),
    ascii: ascii.join(''),
    truncated: descriptor.spanLength > bytes.length,
  };
}

function updateHexPatchInputsForSelection(descriptor) {
  const normalized = normalizeHexAddress(descriptor?.startAddr || descriptor?.activeAddr || '');
  const offsetInput = document.getElementById('hexPatchOffset');
  const status = document.getElementById('hexPatchStatus');
  if (!offsetInput) return;
  if (!normalized) {
    if (!offsetInput.value.trim()) offsetInput.value = '0x0';
    return;
  }
  const fileOffset = fileOffsetFromVaddr(normalized);
  if (!Number.isFinite(fileOffset)) return;
  offsetInput.value = `0x${fileOffset.toString(16)}`;
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const row = getHexRowByOffsetHex(rowOffsetHex);
  const byteIndex = fileOffset - rowOffset;
  const rowHexParts = String(row?.hex || '').trim().split(/\s+/).filter(Boolean);
  const byteValue = rowHexParts[byteIndex] || '';
  if (!status) return;
  status.className = 'hex-patch-status';
  if (descriptor?.spanLength > 1) {
    status.textContent = `Sélection active: ${descriptor.spanLength} octets depuis ${offsetInput.value}`;
  } else if (byteValue) {
    status.textContent = `Octet actif: ${byteValue} @ ${offsetInput.value}`;
  }
}

function buildHexStructPreviewHtml(ctx) {
  const preview = typedDataUiState.hexStructPreview;
  if (!ctx) return '';
  const preferredStruct = getPreferredHexStructName();
  const structs = getTypedStructList();
  const optionsHtml = [
    '<option value="">— type C —</option>',
    ...structs.map((entry) => {
      const name = typeof entry === 'string' ? entry : String((entry && entry.name) || '');
      if (!name) return '';
      const kind = typeof entry === 'string' ? 'struct' : String((entry && entry.kind) || 'struct');
      const fieldCount = Number((entry && entry.field_count) || 0);
      const label = typeof entry === 'string'
        ? name
        : `${name} (${kind}, ${fieldCount} champ${fieldCount > 1 ? 's' : ''})`;
      const selected = preferredStruct && preferredStruct === name ? ' selected' : '';
      return `<option value="${escapeHtml(name)}"${selected}>${escapeHtml(label)}</option>`;
    }),
  ].filter(Boolean).join('');

  let previewHtml = '';
  const previewMatches = preview
    && normalizeHexAddress(preview.addr || '') === ctx.addr
    && String(preview.structName || '') === preferredStruct;
  if (previewMatches && preview.loading) {
    previewHtml = '<p class="hint hex-struct-preview-empty">Prévisualisation du type…</p>';
  } else if (previewMatches && preview.error) {
    previewHtml = `<p class="hint hex-struct-preview-empty">${escapeHtml(preview.error)}</p>`;
  } else if (previewMatches && preview.appliedStruct) {
    const applied = preview.appliedStruct;
    const appliedKind = String(applied.kind || 'struct');
    const previewFields = (applied.fields || []).slice(0, 6).map((field) => (
      `<div class="hex-struct-preview-field">` +
      `<code>${escapeHtml(field.field_name || '')}</code>` +
      `<code>${escapeHtml(field.field_type || '')}</code>` +
      `<span>${escapeHtml(field.decoded || '')}</span>` +
      `</div>`
    )).join('');
    const overflow = (applied.fields || []).length > 6
      ? `<p class="hint hex-struct-preview-empty">${escapeHtml(String((applied.fields || []).length - 6))} champ(s) supplémentaire(s) visibles dans Données typées.</p>`
      : '';
    previewHtml = (
      `<div class="hex-struct-preview">` +
      `<div class="hex-selection-chips">` +
      `<span class="hex-selection-chip hex-selection-chip-primary">${escapeHtml(applied.name || preferredStruct)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(appliedKind)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(applied.section || ctx.section?.name || 'section inconnue')}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(applied.addr || ctx.addr)}</span>` +
      `<span class="hex-selection-chip">${escapeHtml(String((applied.fields || []).length))} champ(s)</span>` +
      `</div>` +
      previewFields +
      overflow +
      `</div>`
    );
  } else if (!preferredStruct) {
    previewHtml = '<p class="hint hex-struct-preview-empty">Choisis un type C pour prévisualiser la sélection courante.</p>';
  } else {
    previewHtml = '<p class="hint hex-struct-preview-empty">Prévisualise ou ouvre ce type dans Données typées.</p>';
  }

  const sectionHint = ctx.section?.name
    ? `${ctx.section.name} @ +${ctx.sectionOffsetHex}`
    : `adresse ${ctx.addr}`;
  return (
    `<div class="hex-struct-card">` +
    `<div class="hex-struct-head">` +
    `<span class="section-label">Type rapide</span>` +
    `<span class="hint">${escapeHtml(sectionHint)}</span>` +
    `</div>` +
    `<div class="hex-struct-controls">` +
    `<select id="hexStructSelect" class="select-modern">${optionsHtml}</select>` +
    `<button type="button" class="btn btn-xs btn-secondary" id="btnHexPreviewStruct"${preferredStruct ? '' : ' disabled'}>Aperçu</button>` +
    `<button type="button" class="btn btn-xs btn-secondary" id="btnHexOpenTypedStruct"${preferredStruct ? '' : ' disabled'}>Données typées</button>` +
    `</div>` +
    previewHtml +
    `</div>`
  );
}

function updateHexSelectionSummary(selection = null) {
  const container = document.getElementById('hexSelectionSummary');
  if (!container) return;
  ensureTypedStructCatalogLoaded();
  const descriptor = selection && typeof selection === 'object'
    ? buildHexSelectionDescriptor(selection.startAddr || selection.addr || selection.activeAddr || '', selection)
    : getCurrentHexSelectionDescriptor();
  const normalized = normalizeHexAddress(descriptor?.activeAddr || descriptor?.startAddr || '');
  if (!descriptor || !normalized) {
    container.innerHTML = '<p class="hint">Sélectionnez une ligne hex ou naviguez depuis le désassemblage pour afficher le contexte.</p>';
    return;
  }
  const fileOffset = fileOffsetFromVaddr(descriptor.startAddr);
  if (!Number.isFinite(fileOffset)) {
    container.innerHTML = `<p class="hint">Sélection active ${escapeHtml(descriptor.startAddr)} hors de la fenêtre hex actuelle ou non mappée dans les sections.</p>`;
    return;
  }
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const row = getHexRowByOffsetHex(rowOffsetHex);
  const section = findSectionForFileOffset(fileOffsetFromVaddr(descriptor.activeAddr) ?? fileOffset);
  const summary = getActiveContextSummary(normalized);
  const stackFrameAddr = normalizeHexAddress(summary.functionAddr || summary.addr);
  const stackFrameKey = getStackFrameCacheKey(summary.binaryPath, stackFrameAddr);
  let stackFrame = getCachedStackFrame(summary.binaryPath, stackFrameAddr);
  if (!stackFrame && summary.binaryPath && stackFrameAddr && !isRawBinarySelected()) {
    ensureStackFrameLoaded(summary.binaryPath, stackFrameAddr);
  }
  const byteIndex = fileOffset - rowOffset;
  const rowHexParts = String(row?.hex || '').trim().split(/\s+/).filter(Boolean);
  const byteValue = rowHexParts[byteIndex] || '';
  const asciiChar = typeof row?.ascii === 'string' ? (row.ascii[byteIndex] || '') : '';
  const chips = [
    descriptor.spanLength > 1
      ? `Plage ${descriptor.startAddr} → ${descriptor.endAddr}`
      : `Adresse ${normalized}`,
    descriptor.spanLength > 1 ? `Taille ${descriptor.spanLength} octets` : `Offset 0x${fileOffset.toString(16)}`,
    descriptor.spanLength > 1 ? `Actif ${descriptor.activeAddr}` : `Ligne ${rowOffsetHex}`,
    descriptor.spanLength > 1 ? null : (Number.isFinite(byteIndex) ? `Byte +0x${byteIndex.toString(16)}` : null),
    descriptor.spanLength > 1 ? null : (byteValue ? `Valeur ${byteValue}` : null),
    descriptor.spanLength > 1 ? null : (asciiChar ? `ASCII ${asciiChar === ' ' ? 'space' : asciiChar}` : null),
    section?.name ? `Section ${section.name}` : null,
    section?.type ? `Type ${section.type}` : null,
    summary.functionAddr ? `Fonction ${summary.functionName ? `${summary.functionName} @ ${summary.functionAddr}` : summary.functionAddr}` : null,
    stackFrame && !stackFrame.error && typeof stackFrame.frame_size === 'number' ? `Frame ${stackFrame.frame_size}B` : null,
  ].filter(Boolean);
  const chipsHtml = chips.map((chip, index) => `<span class="hex-selection-chip${index === 0 ? ' hex-selection-chip-primary' : ''}">${escapeHtml(chip)}</span>`).join('');
  const actionsHtml = `
    <div class="hex-selection-actions">
      <button type="button" class="btn btn-xs btn-secondary" id="btnHexSelectionJumpDisasm">Désasm</button>
      <button type="button" class="btn btn-xs btn-secondary" id="btnHexSelectionCollapse"${descriptor.spanLength <= 1 ? ' disabled' : ''}>Réduire</button>
      <span class="hint">Shift+clic pour étendre • double-clic pour ouvrir dans le désasm</span>
    </div>
  `;
  const previewParts = [];
  const selectionPreview = getHexSelectionPreview(descriptor);
  if (selectionPreview?.hex) previewParts.push(`Hex : ${selectionPreview.hex}${selectionPreview.truncated ? ' …' : ''}`);
  if (selectionPreview?.ascii) previewParts.push(`ASCII : ${selectionPreview.ascii}${selectionPreview.truncated ? ' …' : ''}`);
  if (!selectionPreview?.hex && row?.hex) previewParts.push(`Hex : ${row.hex}`);
  if (!selectionPreview?.ascii && row?.ascii) previewParts.push(`ASCII : ${row.ascii}`);
  const previewHtml = previewParts.length
    ? `<div class="hex-selection-preview">${escapeHtml(previewParts.join('\n'))}</div>`
    : '<p class="hint">Aperçu indisponible pour cette ligne.</p>';
  const stackHtml = stackFrame
    ? buildHexStackContextHtml(stackFrame)
    : (stackFrameKey && pendingStackFrameRequests.has(stackFrameKey)
      ? '<p class="hint">Chargement du contexte stack de la fonction…</p>'
      : '');
  const structHtml = buildHexStructPreviewHtml(getHexStructSelectionContext(descriptor));
  container.innerHTML = `<div class="hex-selection-chips">${chipsHtml}</div>${actionsHtml}${previewHtml}${stackHtml}${structHtml}`;
  document.getElementById('btnHexSelectionJumpDisasm')?.addEventListener('click', () => openHexSelectionInDisasm());
  document.getElementById('btnHexSelectionCollapse')?.addEventListener('click', () => collapseHexSelectionToActive());
  document.getElementById('hexStructSelect')?.addEventListener('change', (event) => {
    typedDataUiState.hexStructName = String(event.target?.value || '');
    typedDataUiState.hexStructPreview = null;
    updateHexSelectionSummary(descriptor);
  });
  document.getElementById('btnHexPreviewStruct')?.addEventListener('click', () => {
    requestHexStructPreview(getPreferredHexStructName(), getHexStructSelectionContext(descriptor));
  });
  document.getElementById('btnHexOpenTypedStruct')?.addEventListener('click', () => {
    openTypedDataStructFromSelection(getPreferredHexStructName(), getHexStructSelectionContext(descriptor));
  });
}

function setHexActiveAddress(addr, opts = {}) {
  const descriptor = buildHexSelectionDescriptor(addr, {
    endAddr: opts.endAddr,
    activeAddr: opts.activeAddr || addr,
    anchorAddr: opts.anchorAddr || addr,
    spanLength: opts.spanLength || 1,
  });
  resetHexActiveUiState();
  if (!descriptor) {
    setHexSelectionModel(null);
    updateHexSelectionSummary(null);
    updateHexPatchInputsForSelection(null);
    return null;
  }
  setHexSelectionModel(descriptor);
  const fileOffset = fileOffsetFromVaddr(descriptor.activeAddr);
  if (!Number.isFinite(fileOffset)) {
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    return null;
  }
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = `0x${rowOffset.toString(16).padStart(8, '0')}`;
  const rowEl = hexDomState.rowByOffset.get(rowOffsetHex.toLowerCase()) || null;
  const selectedRowEls = [];
  const selectedByteEls = [];
  const selectedAsciiEls = [];
  for (let addrNum = descriptor.startNum; addrNum <= descriptor.endNum && addrNum - descriptor.startNum < 8192; addrNum += 1) {
    const currentAddr = `0x${addrNum.toString(16)}`;
    const currentOffset = fileOffsetFromVaddr(currentAddr);
    if (!Number.isFinite(currentOffset)) continue;
    const currentRowOffset = currentOffset - (currentOffset % 16);
    const currentRowOffsetHex = `0x${currentRowOffset.toString(16).padStart(8, '0')}`;
    const currentRowEl = hexDomState.rowByOffset.get(currentRowOffsetHex.toLowerCase()) || null;
    if (currentRowEl && !selectedRowEls.includes(currentRowEl)) selectedRowEls.push(currentRowEl);
    selectedByteEls.push(...(hexDomState.byteElsByAddr.get(currentAddr.toLowerCase()) || []));
    selectedAsciiEls.push(...(hexDomState.asciiElsByAddr.get(currentAddr.toLowerCase()) || []));
  }
  if (rowEl || selectedRowEls.length) {
    selectedRowEls.forEach((el) => el.classList.add('hex-row-selected'));
    if (rowEl) rowEl.classList.add('hex-row-active');
    selectedByteEls.forEach((el) => el.classList.add('hex-byte-selected'));
    selectedAsciiEls.forEach((el) => el.classList.add('hex-ascii-char-selected'));
    const activeByteEls = hexDomState.byteElsByAddr.get(descriptor.activeAddr.toLowerCase()) || [];
    const activeAsciiEls = hexDomState.asciiElsByAddr.get(descriptor.activeAddr.toLowerCase()) || [];
    activeByteEls.forEach((el) => el.classList.add('hex-byte-active'));
    activeAsciiEls.forEach((el) => el.classList.add('hex-ascii-char-active'));
    hexActiveUiState = {
      selectedRowEls,
      activeRowEl: rowEl,
      selectedByteEls,
      selectedAsciiEls,
      activeByteEls,
      activeAsciiEls,
      startAddr: descriptor.startAddr,
      endAddr: descriptor.endAddr,
      addr: descriptor.activeAddr,
      anchorAddr: descriptor.anchorAddr,
      spanLength: descriptor.spanLength,
    };
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    if (opts.reveal && rowEl) {
      rowEl.scrollIntoView({ behavior: opts.instant ? 'auto' : 'smooth', block: 'center' });
    }
    return rowEl;
  }
  if (hexRenderInProgress) {
    if (opts.reveal) hexPendingScrollVaddr = descriptor;
    updateHexSelectionSummary(descriptor);
    updateHexPatchInputsForSelection(descriptor);
    return null;
  }
  if (opts.reveal) {
    const bp = tabDataCache.hex?.binaryPath || getStaticBinaryPath();
    if (bp) {
      hexPendingScrollVaddr = descriptor;
      loadHexView(bp, rowOffset - (rowOffset % 16), hexCurrentLength);
    }
  }
  updateHexSelectionSummary(descriptor);
  updateHexPatchInputsForSelection(descriptor);
  return null;
}

function setActiveAddressContext(addr, spanLength = 1, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return '';
  window._lastDisasmAddr = normalized;
  updateActiveContextBars(normalized);
  updateActiveNavRows(normalized);
  syncFunctionsSelectionFromContext(normalized);
  updateTypedDataActiveSelection(normalized, spanLength, { reveal: isStaticTabActive('typed_data') });
  updateDisasmSessionSummary();
  if (!opts.preserveHexSelection) {
    setHexSelectionModel(buildHexSelectionDescriptor(normalized, {
      activeAddr: normalized,
      anchorAddr: normalized,
      spanLength,
    }));
  } else if (spanLength > 0) {
    hexSelectionModel.spanLength = normalizeSpanLength(spanLength);
  }
  return normalized;
}

function openHexSelectionInDisasm(addr = hexSelectionModel.activeAddr || hexSelectionModel.startAddr) {
  const normalized = normalizeHexAddress(addr);
  const bp = getStaticBinaryPath();
  if (!normalized || !bp) return;
  vscode.postMessage({ type: 'hubGoToAddress', addr: normalized, binaryPath: bp });
}

function collapseHexSelectionToActive() {
  const activeAddr = normalizeHexAddress(hexSelectionModel.activeAddr || hexSelectionModel.startAddr || '');
  if (!activeAddr) return;
  setHexActiveAddress(activeAddr, {
    activeAddr,
    anchorAddr: activeAddr,
    spanLength: 1,
    reveal: false,
    instant: true,
  });
}

function handleHexAddressSelection(addr, event = null, opts = {}) {
  const normalized = normalizeHexAddress(addr);
  if (!normalized) return;
  const extend = !!event?.shiftKey && !!normalizeHexAddress(hexSelectionModel.anchorAddr || '');
  const anchorAddr = extend
    ? normalizeHexAddress(hexSelectionModel.anchorAddr || hexSelectionModel.startAddr || normalized)
    : normalizeHexAddress(opts.anchorAddr || normalized);
  const descriptor = buildHexSelectionDescriptor(anchorAddr, {
    endAddr: extend ? normalized : opts.endAddr,
    activeAddr: normalized,
    anchorAddr,
    spanLength: extend ? undefined : normalizeSpanLength(opts.spanLength || 1),
  });
  if (!descriptor) return;
  setActiveAddressContext(normalized, descriptor.spanLength, { preserveHexSelection: true });
  setHexActiveAddress(descriptor.startAddr, {
    endAddr: descriptor.endAddr,
    activeAddr: descriptor.activeAddr,
    anchorAddr: descriptor.anchorAddr,
    spanLength: descriptor.spanLength,
    reveal: false,
    instant: true,
  });
  document.getElementById('hexContent')?.focus();
  if (opts.openInDisasm || (event && event.detail > 1)) {
    openHexSelectionInDisasm(normalized);
  }
}

function updateHexRenderStatus(done, total, busy = false) {
  const el = document.getElementById('hexRenderStatus');
  if (!el) return;
  if (!total) {
    el.textContent = 'Prêt';
    return;
  }
  if (busy) {
    el.textContent = `Rendu ${done}/${total} lignes…`;
    return;
  }
  el.textContent = `${total} lignes`;
}

function buildHexTableRow(row, sections, tbody) {
  const rowOffNum = parseInt(row.offset, 16);
  let secType = '';
  for (const sec of sections) {
    if (rowOffNum >= sec.offset && rowOffNum < sec.offset + sec.size) {
      secType = sec.type;
      break;
    }
  }
  const tr = document.createElement('tr');
  tbody.appendChild(tr);
  tr.dataset.offset = row.offset;
  hexDomState.rowByOffset.set(String(row.offset || '').toLowerCase(), tr);
  hexDomState.rowDataByOffset.set(String(row.offset || '').toLowerCase(), row);
  const rowVaddr = vaddrFromFileOffset(rowOffNum, sections);
  if (rowVaddr) tr.dataset.vaddr = rowVaddr;
  if (secType) tr.className = 'hex-row-' + secType;
  tr.title = rowVaddr ? `Offset ${row.offset} → ${rowVaddr}` : `Offset ${row.offset}`;

  const hexParts = row.hex.split(' ');
  [
    { cls: 'hex-col-offset', text: row.offset },
    { cls: 'hex-col-vaddr',  text: rowVaddr || '—' },
    { cls: 'hex-col-hex',    text: row.hex },
    { cls: 'hex-col-ascii',  text: row.ascii },
  ].forEach(({ cls, text }, colIdx) => {
    const td = document.createElement('td');
    td.className = cls;
    tr.appendChild(td);
    const code = document.createElement('code');
    td.appendChild(code);
    if (colIdx === 0) {
      code.textContent = text;
      td.style.cursor = 'pointer';
      td.title = 'Aller au désassemblage';
      td.addEventListener('click', () => {
        if (rowVaddr) handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
        const bp = getStaticBinaryPath();
        if (row.offset && bp) vscode.postMessage({ type: 'hubGoToFileOffset', fileOffset: row.offset, binaryPath: bp });
      });
    } else if (colIdx === 1 && rowVaddr) {
      code.textContent = text;
      td.style.cursor = 'pointer';
      td.title = 'Aller au désassemblage';
      td.addEventListener('click', () => {
        handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
        const bp = getStaticBinaryPath();
        if (bp) vscode.postMessage({ type: 'hubGoToAddress', addr: rowVaddr, binaryPath: bp });
      });
    } else if (colIdx === 2) {
      hexParts.forEach((part, byteIdx) => {
        const byteVaddr = rowVaddr ? `0x${(parseNumericAddress(rowVaddr) + byteIdx).toString(16)}` : '';
        const span = document.createElement('span');
        span.className = 'hex-byte';
        span.textContent = part;
        if (byteVaddr) span.dataset.vaddr = byteVaddr;
        appendHexDomEntry(hexDomState.byteElsByAddr, byteVaddr, span);
        span.title = byteVaddr ? `${byteVaddr} • ${part}` : part;
        span.addEventListener('click', (event) => {
          event.stopPropagation();
          if (!byteVaddr) return;
          handleHexAddressSelection(byteVaddr, event, { spanLength: 1 });
        });
        code.appendChild(span);
        if (byteIdx !== hexParts.length - 1) code.appendChild(document.createTextNode(byteIdx === 7 ? '  ' : ' '));
      });
    } else if (colIdx === 3) {
      Array.from(String(row.ascii || '')).forEach((ch, byteIdx) => {
        const byteVaddr = rowVaddr ? `0x${(parseNumericAddress(rowVaddr) + byteIdx).toString(16)}` : '';
        const span = document.createElement('span');
        span.className = 'hex-ascii-char';
        span.textContent = ch;
        if (byteVaddr) span.dataset.vaddr = byteVaddr;
        appendHexDomEntry(hexDomState.asciiElsByAddr, byteVaddr, span);
        span.title = byteVaddr ? `${byteVaddr} • ${ch}` : ch;
        span.addEventListener('click', (event) => {
          event.stopPropagation();
          if (!byteVaddr) return;
          handleHexAddressSelection(byteVaddr, event, { spanLength: 1 });
        });
        code.appendChild(span);
      });
    } else {
      code.textContent = text;
    }
  });
  tr.addEventListener('click', () => {
    if (!rowVaddr) return;
    handleHexAddressSelection(rowVaddr, null, { spanLength: 1 });
  });
}

function renderHexTable(container, rows, sections) {
  window._lastHexRows = Array.isArray(rows) ? rows : [];
  resetHexDomState();
  container.replaceChildren();
  hexRenderInProgress = false;
  const renderId = ++hexRenderSessionId;
  if (!rows.length) {
    updateHexRenderStatus(0, 0, false);
    const p = document.createElement('p');
    p.className = 'hint';
    p.textContent = 'Aucune donn\u00e9e \u00e0 cet offset.';
    container.appendChild(p);
    return;
  }
  const table = document.createElement('table');
  table.className = 'hex-table';

  const thead = table.createTHead();
  const hr = thead.insertRow();
  ['Offset', 'VAddr', '00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F', 'ASCII'].forEach((h, i) => {
    const th = document.createElement('th');
    th.textContent = h;
    th.className = ['hex-col-offset', 'hex-col-vaddr', 'hex-col-hex', 'hex-col-ascii'][i];
    hr.appendChild(th);
  });

  const tbody = table.createTBody();
  container.appendChild(table);
  const totalRows = rows.length;
  const batchSize = totalRows > 512 ? 96 : totalRows > 128 ? 64 : totalRows;
  let index = 0;
  const renderBatch = () => {
    if (renderId !== hexRenderSessionId) return;
    const end = Math.min(index + batchSize, totalRows);
    for (; index < end; index += 1) {
      buildHexTableRow(rows[index], sections, tbody);
    }
    const busy = index < totalRows;
    hexRenderInProgress = busy;
    updateHexRenderStatus(index, totalRows, busy);
    if (busy) {
      requestAnimationFrame(renderBatch);
      return;
    }
    const currentSelection = getCurrentHexSelectionDescriptor();
    if (currentSelection) {
      setHexActiveAddress(currentSelection.startAddr, {
        endAddr: currentSelection.endAddr,
        activeAddr: currentSelection.activeAddr,
        anchorAddr: currentSelection.anchorAddr,
        spanLength: currentSelection.spanLength,
        reveal: false,
        instant: true,
      });
    }
    if (hexPendingScrollVaddr) {
      const pending = hexPendingScrollVaddr;
      hexPendingScrollVaddr = null;
      requestAnimationFrame(() => scrollHexToVaddr(pending));
    }
  };
  updateHexRenderStatus(0, totalRows, totalRows > batchSize);
  if (totalRows > batchSize) {
    hexRenderInProgress = true;
    requestAnimationFrame(renderBatch);
  } else {
    renderBatch();
  }
}

function renderHexSectionLegend(sections, metadata = {}) {
  const legend = document.getElementById('hexSectionLegend');
  if (!legend) return;
  legend.replaceChildren();
  const metaItems = [
    metadata.arch ? `arch ${_displayRawArchName(metadata.arch)}` : '',
    metadata.bits ? `${metadata.bits}-bit` : '',
    metadata.endianness ? _displayEndianName(metadata.endianness) : '',
    metadata.ptrSize ? `ptr ${metadata.ptrSize} o` : '',
  ].filter(Boolean);
  legend.hidden = !sections.length && !metaItems.length;
  if (metaItems.length) {
    const metaLabel = document.createElement('span');
    metaLabel.className = 'hex-legend-label';
    metaLabel.textContent = 'Vue\u00a0:';
    legend.appendChild(metaLabel);
    metaItems.forEach((item) => {
      const chip = document.createElement('span');
      chip.className = 'hex-legend-item hex-legend-meta';
      chip.textContent = item;
      legend.appendChild(chip);
    });
  }
  if (!sections.length) return;
  const label = document.createElement('span');
  label.className = 'hex-legend-label';
  label.textContent = metaItems.length ? 'Sections\u00a0:' : 'Sections\u00a0:';
  legend.appendChild(label);
  const seen = new Set();
  sections.forEach(sec => {
    if (seen.has(sec.type)) return;
    seen.add(sec.type);
    const chip = document.createElement('span');
    chip.className = 'hex-legend-item hex-legend-' + sec.type;
    chip.textContent = sec.type;
    legend.appendChild(chip);
  });
}

function scrollHexToVaddr(vaddrInput) {
  if (!hexSections.length) return;
  const descriptor = typeof vaddrInput === 'object' && vaddrInput
    ? buildHexSelectionDescriptor(vaddrInput.addr || vaddrInput.activeAddr || '', vaddrInput)
    : buildHexSelectionDescriptor(vaddrInput, { spanLength: 1 });
  const normalized = normalizeHexAddress(descriptor?.activeAddr || descriptor?.startAddr || '');
  if (!descriptor || !normalized) return;
  const fileOffset = fileOffsetFromVaddr(normalized);
  if (fileOffset == null) return;
  // Arrondir au début de la ligne (16 octets)
  const rowOffset = fileOffset - (fileOffset % 16);
  const rowOffsetHex = '0x' + rowOffset.toString(16).padStart(8, '0');
  // Chercher si la row est déjà visible dans le DOM
  const tr = document.querySelector(`#hexContent tr[data-offset="${rowOffsetHex}"]`);
  if (tr) {
    setHexActiveAddress(descriptor.startAddr, {
      endAddr: descriptor.endAddr,
      activeAddr: descriptor.activeAddr,
      anchorAddr: descriptor.anchorAddr,
      spanLength: descriptor.spanLength,
      reveal: true,
    });
    tr.classList.add('hex-row-highlight');
    setTimeout(() => tr.classList.remove('hex-row-highlight'), 1500);
  } else if (hexRenderInProgress) {
    hexPendingScrollVaddr = descriptor;
  } else if (tabDataCache.hex) {
    // La page hex ne contient pas encore cet offset — on navigue
    const bp = tabDataCache.hex.binaryPath || getStaticBinaryPath();
    loadHexView(bp, rowOffset, hexCurrentLength);
    // Après chargement, le DOM sera reconstruit — un re-scroll sera nécessaire
    // On stocke l'adresse cible pour y revenir après render
    hexPendingScrollVaddr = descriptor;
  }
}

function renderStackFrame(data) {
  const content = document.getElementById('stackContent');
  if (!content) return;
  while (content.firstChild) content.removeChild(content.firstChild);

  const sizeEl = document.getElementById('stackFrameSize');
  if (sizeEl) sizeEl.textContent = '';
  const activeSummary = getActiveContextSummary(window._lastDisasmAddr || decompileUiState.selectedAddr);
  stackUiState.renderedBinaryPath = activeSummary.binaryPath || '';
  stackUiState.renderedAddr = normalizeHexAddress(activeSummary.functionAddr || activeSummary.addr);

  if (!data || data.error) {
    const p = document.createElement('p');
    p.className = 'error-text';
    p.textContent = (data && data.error) ? data.error : 'Erreur inconnue';
    content.appendChild(p);
    return;
  }

  const args = Array.isArray(data.args) ? [...data.args] : [];
  const vars = Array.isArray(data.vars) ? [...data.vars] : [];
  const allEntries = [...args, ...vars];
  const metaParts = [`Frame: ${Number(data.frame_size)} bytes`];
  if (data.arch && data.arch !== 'unknown') metaParts.push(`Arch: ${data.arch}`);
  if (data.abi && data.abi !== 'unknown') metaParts.push(`ABI: ${data.abi}`);
  if (sizeEl) sizeEl.textContent = metaParts.join(' · ');

  if (allEntries.length === 0) {
    const p = document.createElement('p');
    p.className = 'placeholder-text';
    p.textContent = 'Aucune variable ou argument détecté.';
    content.appendChild(p);
    return;
  }

  const registerArgs = args.filter(v => v && (v.source === 'abi' || typeof v.offset !== 'number'));
  const stackArgs = args
    .filter(v => v && !registerArgs.includes(v))
    .sort((a, b) => (a.offset || 0) - (b.offset || 0));

  const summary = document.createElement('div');
  summary.className = 'stack-summary';
  [
    data.arch && data.arch !== 'unknown' ? `Arch ${data.arch}` : null,
    data.abi && data.abi !== 'unknown' ? `ABI ${data.abi}` : null,
    `Args ${args.length}`,
    `Locals ${vars.length}`,
    registerArgs.length ? `Reg ${registerArgs.length}` : null,
  ].filter(Boolean).forEach(label => {
    const chip = document.createElement('span');
    chip.className = 'stack-summary-chip';
    chip.textContent = label;
    summary.appendChild(chip);
  });
  if (summary.childElementCount) content.appendChild(summary);

  const table = document.createElement('table');
  table.className = 'stack-table';

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['Emplacement', 'Nom', 'Taille', 'Type'].forEach(h => {
    const th = document.createElement('th');
    th.textContent = h;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');

  const appendRow = (v, kind) => {
    const tr = document.createElement('tr');
    tr.className = `stack-${kind}`;
    tr.dataset.stackEntryName = normalizeStackEntryName(v.name);

    const tdOff = document.createElement('td');
    tdOff.className = 'stack-col-offset';
    if (v.location) {
      tdOff.textContent = v.location;
    } else if (typeof v.offset === 'number') {
      const off = v.offset >= 0
        ? `+0x${v.offset.toString(16)}`
        : `-0x${Math.abs(v.offset).toString(16)}`;
      tdOff.textContent = `[rbp${off}]`;
    } else {
      tdOff.textContent = '—';
    }

    const tdName = document.createElement('td');
    tdName.className = 'stack-col-name';
    const nameButton = document.createElement('button');
    nameButton.type = 'button';
    nameButton.className = 'stack-entry-link';
    nameButton.textContent = v.name;
    nameButton.title = 'Clic: ouvrir dans le pseudo-C et surligner cette entrée';
    nameButton.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      applyStackEntryHighlight(v.name, { reveal: false });
      openDecompileForStackEntry(v.name);
    });
    tdName.appendChild(nameButton);
    if (v.source === 'dwarf') {
      const badge = document.createElement('span');
      badge.className = 'stack-dwarf';
      badge.textContent = ' (DWARF)';
      tdName.appendChild(badge);
    }

    const tdSize = document.createElement('td');
    tdSize.className = 'stack-col-size';
    tdSize.textContent = `${v.size}B`;

    const tdKind = document.createElement('td');
    tdKind.className = 'stack-col-kind';
    tdKind.textContent = kind === 'arg' && v.source === 'abi' ? 'arg(reg)' : kind;

    tr.append(tdOff, tdName, tdSize, tdKind);
    tr.addEventListener('click', () => applyStackEntryHighlight(v.name, { reveal: false }));
    tbody.appendChild(tr);
  };

  registerArgs.forEach(v => appendRow(v, 'arg'));
  stackArgs.forEach(v => appendRow(v, 'arg'));
  vars.forEach(v => appendRow(v, 'var'));

  table.appendChild(tbody);
  content.appendChild(table);
  applyStackEntryHighlight(stackUiState.pendingEntryName || stackUiState.activeEntryName);
}



function initStaticToolsListeners() {
// ── Compilateur ───────────────────────────────────────────────
// Les listeners de build preview et click sont enregistrés dans payload.js.
// On s'assure ici que _buildGccCommand est appelé si elle est définie
// (payload.js peut être chargé avant ou après tools.js).
if (typeof _buildGccCommand === 'function') _buildGccCommand();

// Décompilateur : auto-décompile quand on change de fonction
document.getElementById('decompileAddrSelect')?.addEventListener('change', () => {
  decompileUiState.selectionMode = 'manual';
  _saveStorage({ decompileSelectionMode: decompileUiState.selectionMode });
  const { addr } = getDecompileSelectionContext();
  if (addr) setActiveAddressContext(addr, 1, { preserveHexSelection: true });
  requestDecompileForCurrentSelection();
  const bp = getStaticBinaryPath();
  if (bp && addr) {
    const cached = getCachedStackFrame(bp, addr);
    if (cached) renderStackFrame(cached);
    else ensureStackFrameLoaded(bp, addr);
  } else {
    decompileUiState.selectedAddr = '';
    _saveStorage({ decompileAddr: '' });
  }
});
document.getElementById('btnDecompileBack')?.addEventListener('click', () => {
  applyDecompileHistoryStep(-1);
});
document.getElementById('btnDecompileForward')?.addEventListener('click', () => {
  applyDecompileHistoryStep(1);
});
document.getElementById('btnRebuildDecompile')?.addEventListener('click', () => {
  requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true, forceRefresh: true });
});
document.getElementById('decompileSearchInput')?.addEventListener('input', (event) => {
  decompileUiState.searchQuery = String(event.target?.value || '');
  decompileUiState.activeSearchHit = decompileUiState.searchQuery.trim() ? 0 : -1;
  _saveStorage({ decompileSearch: decompileUiState.searchQuery });
  const pre = document.querySelector('#decompileContent pre');
  clearDecompileSearchHighlights(pre);
  if (decompileUiState.searchQuery.trim()) {
    decorateDecompileSearch(pre, decompileUiState.searchQuery);
  } else {
    updateDecompileSearchUi(0);
  }
});
document.getElementById('decompileSearchInput')?.addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    event.preventDefault();
    if (!decompileUiState.searchQuery) return;
    decompileUiState.searchQuery = '';
    decompileUiState.activeSearchHit = -1;
    _saveStorage({ decompileSearch: '' });
    clearDecompileSearchHighlights(document.querySelector('#decompileContent pre'));
    updateDecompileSearchUi(0);
    return;
  }
  if (event.key !== 'Enter') return;
  event.preventDefault();
  stepDecompileSearchHit(event.shiftKey ? -1 : 1);
});
document.getElementById('btnDecompileSearchPrev')?.addEventListener('click', () => {
  stepDecompileSearchHit(-1);
});
document.getElementById('btnDecompileSearchNext')?.addEventListener('click', () => {
  stepDecompileSearchHit(1);
});
updateDecompileHistoryControls();
updateDecompileSearchUi();

// ── Script panel ──────────────────────────────────────────────────
(function initScriptPanel() {
  const editor = document.getElementById('scriptEditor');
  const output = document.getElementById('scriptOutput');
  const status = document.getElementById('scriptStatus');
  const runBtn = document.getElementById('btnRunScript');
  const saveBtn = document.getElementById('btnSaveScript');
  const loadBtn = document.getElementById('btnLoadScript');
  const clearBtn = document.getElementById('btnClearScript');
  const splitter = document.getElementById('scriptSplitter');
  if (!editor) return;

  const saved = _loadStorage();
  if (saved.scriptCode) editor.value = saved.scriptCode;

  let _saveTimer;
  editor.addEventListener('input', () => {
    clearTimeout(_saveTimer);
    _saveTimer = setTimeout(() => _saveStorage({ scriptCode: editor.value }), 500);
  });

  function runScript() {
    const code = editor.value.trim();
    if (!code) return;
    runBtn.setAttribute('disabled', 'true');
    status.textContent = '⏳ Exécution…';
    output.textContent = '';
    output.className = 'sc-output';

    const binaryPath = document.querySelector('input[name="binaryPath"]')?.value || '';
    const b64 = btoa(unescape(encodeURIComponent(code)));
    vscode.postMessage({ type: 'hubRunScript', code: b64, binaryPath });
  }

  runBtn?.addEventListener('click', runScript);

  editor.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      runScript();
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const start = editor.selectionStart;
      editor.value = editor.value.substring(0, start) + '    ' + editor.value.substring(editor.selectionEnd);
      editor.selectionStart = editor.selectionEnd = start + 4;
    }
  });

  saveBtn?.addEventListener('click', () => {
    const name = prompt('Nom du script :', 'script.py');
    if (!name) return;
    vscode.postMessage({ type: 'hubSaveScript', name, content: editor.value });
  });

  loadBtn?.addEventListener('click', () => {
    vscode.postMessage({ type: 'hubLoadScript' });
  });

  clearBtn?.addEventListener('click', () => {
    editor.value = '';
    output.textContent = '';
    output.className = 'sc-output';
    status.textContent = '';
    _saveStorage({ scriptCode: '' });
  });

  if (splitter) {
    const editorWrap = editor.closest('.sc-editor-wrap');
    const outputWrap = output.closest('.sc-output-wrap');
    let dragging = false;

    splitter.addEventListener('mousedown', (e) => {
      e.preventDefault();
      dragging = true;
      document.body.style.cursor = 'row-resize';
      document.body.style.userSelect = 'none';
    });

    document.addEventListener('mousemove', (e) => {
      if (!dragging || !editorWrap || !outputWrap) return;
      const container = editorWrap.parentElement;
      const rect = container.getBoundingClientRect();
      const y = e.clientY - rect.top;
      const toolbarH = container.querySelector('.sc-toolbar')?.offsetHeight || 0;
      const splitterH = splitter.offsetHeight;
      const available = rect.height - toolbarH - splitterH;
      const editorH = Math.max(60, Math.min(available - 60, y - toolbarH));
      editorWrap.style.flex = 'none';
      editorWrap.style.height = editorH + 'px';
      outputWrap.style.flex = '1';
      _saveStorage({ scriptSplitH: editorH });
    });

    document.addEventListener('mouseup', () => {
      if (dragging) {
        dragging = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    });

    if (saved.scriptSplitH) {
      editorWrap.style.flex = 'none';
      editorWrap.style.height = saved.scriptSplitH + 'px';
    }
  }
})();

// Payload conversion
document.getElementById('btnPayloadToHex')?.addEventListener('click', doPayloadConvert);
document.getElementById('payloadInput')?.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doPayloadConvert(); } });

// Payload result: copier au clic
document.getElementById('payloadHexResult')?.addEventListener('click', function () {
  const v = this.textContent;
  if (v && v !== '—' && !v.startsWith('Error') && navigator.clipboard) {
    navigator.clipboard.writeText(v);
    this.classList.add('copied');
    setTimeout(() => this.classList.remove('copied'), 600);
  }
});

}
