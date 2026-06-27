/**
 * @file disasmPanel.js
 * @brief Rendu du panneau ASM propre et recentre sur la fonction active.
 */
import { dom } from './dom.js';
import { diagnosticKindLabel, diagnosticMatchesAddress, primaryDiagnostic } from './diagnostics.js';

// ---- Context menu (right-click → Ask AI) ----
let _ctxMenu = null;
let _ctxMenuInitialized = false;

function _getOrCreateCtxMenu() {
  if (_ctxMenu) return _ctxMenu;
  _ctxMenu = document.createElement('div');
  _ctxMenu.id = 'disasmCtxMenu';
  _ctxMenu.className = 'disasm-ctx-menu';
  _ctxMenu.setAttribute('role', 'menu');
  _ctxMenu.setAttribute('aria-hidden', 'true');
  const btn = document.createElement('button');
  btn.className = 'disasm-ctx-item';
  btn.dataset.action = 'ask-ai';
  btn.setAttribute('role', 'menuitem');
  btn.type = 'button';
  btn.textContent = 'Demander à l\'IA';
  _ctxMenu.appendChild(btn);
  document.body.appendChild(_ctxMenu);
  return _ctxMenu;
}

function _hideCtxMenu() {
  if (!_ctxMenu) return;
  _ctxMenu.classList.remove('open');
  _ctxMenu.setAttribute('aria-hidden', 'true');
}

function _showCtxMenu(x, y, addr, instrText) {
  const menu = _getOrCreateCtxMenu();
  menu.classList.add('open');
  menu.setAttribute('aria-hidden', 'false');
  menu.style.left = `${Math.min(x, window.innerWidth - 200)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - 60)}px`;
  menu.dataset.addr = addr || '';
  menu.dataset.instr = instrText || '';
}

function _openChatWithContext(addr, instr) {
  const widget = document.getElementById('ollamaChatWidget');
  if (widget) widget.classList.add('open');
  const textarea = document.getElementById('ollamaQuickPromptInput');
  if (textarea) {
    const prefix = addr ? `Analyse l'instruction à ${addr}` : 'Analyse cette instruction';
    const context = instr ? ` : \`${instr}\`` : '';
    textarea.value = `${prefix}${context}\n`;
    textarea.focus();
    textarea.selectionStart = textarea.selectionEnd = textarea.value.length;
  }
}

function parseAddr(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) {
    return BigInt(Math.trunc(value));
  }
  if (typeof value !== 'string') return null;
  const text = value.trim();
  if (!text) return null;
  try {
    if (text.startsWith('0x') || text.startsWith('0X')) return BigInt(text);
    if (/^[0-9a-fA-F]+$/.test(text)) return BigInt(`0x${text}`);
    if (/^\d+$/.test(text)) return BigInt(text);
  } catch (_) {
    return null;
  }
  return null;
}

function splitInstruction(text) {
  const raw = String(text || '').trim();
  if (!raw) return { mnemonic: '', operands: '' };
  const firstSpace = raw.search(/\s/);
  if (firstSpace < 0) return { mnemonic: raw, operands: '' };
  return {
    mnemonic: raw.slice(0, firstSpace).trim(),
    operands: raw.slice(firstSpace + 1).trim()
  };
}

function stripRawPrefix(text) {
  const raw = String(text || '').trim();
  if (!raw) return '';
  const parts = raw.split('\t').map((part) => part.trim()).filter(Boolean);
  if (parts.length >= 2) return parts[parts.length - 1];
  const objdump = raw.match(/^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+(.+)$/i);
  return objdump ? objdump[1].trim() : raw;
}

function normalizeOperandText(operands, entry, options = {}) {
  let text = String(operands || '').trim();
  if (!text) return '';

  if (/^call/i.test(String(entry?.mnemonic || ''))) {
    const siteHint = options.callSiteHints?.[String(entry?.addr || '').toLowerCase()];
    if (siteHint) return siteHint;

    const targetAddrMatch = text.match(/(0x[0-9a-f]+|[0-9a-f]{4,})/i);
    if (targetAddrMatch) {
      const normalized = targetAddrMatch[1].toLowerCase().startsWith('0x')
        ? targetAddrMatch[1].toLowerCase()
        : `0x${targetAddrMatch[1].toLowerCase()}`;
      const targetHint = options.callTargetHints?.[normalized];
      if (targetHint) return targetHint;
    }
  }

  return text.replace(/\b(?:byte|word|dword|qword)\s+ptr\s+/gi, '');
}

function extractBytesText(entry) {
  if (typeof entry?.bytes === 'string' && entry.bytes.trim()) {
    return entry.bytes.trim().replace(/\s+/g, ' ');
  }
  const raw = String(entry?.text || entry?.raw || '').trim();
  if (!raw) return '';
  const tabParts = raw.split('\t').map((part) => part.trim()).filter(Boolean);
  if (tabParts.length >= 2 && /^[0-9a-f]{2}(?:\s+[0-9a-f]{2})*$/i.test(tabParts[1])) {
    return tabParts[1];
  }
  const colonMatch = raw.match(/^\s*[0-9a-f]+:\s*((?:[0-9a-f]{2}\s+)+)/i);
  if (colonMatch?.[1]) {
    return colonMatch[1].trim().replace(/\s+/g, ' ');
  }
  const capstoneMatch = raw.match(/^((?:[0-9a-f]{2}\s+)+)\S/i);
  if (capstoneMatch?.[1]) {
    return capstoneMatch[1].trim().replace(/\s+/g, ' ');
  }
  return '';
}

function formatInstructionAddress(addrText) {
  const text = String(addrText || '').trim().toLowerCase();
  if (!text) return '';
  return text.replace(/^0x/, '');
}

function formatFunctionHeaderAddress(addrText) {
  const compact = formatInstructionAddress(addrText);
  if (!compact) return '';
  return compact.padStart(Math.max(16, compact.length), '0');
}

function normalizeRenderEntry(entry, fallbackLineNumber, options = {}) {
  if (typeof entry === 'string') {
    const text = stripRawPrefix(entry);
    const { mnemonic, operands } = splitInstruction(text);
    return {
      fileLine: fallbackLineNumber,
      addrText: '',
      headerAddrText: '',
      bytesText: '',
      mnemonic,
      operands,
      rawText: text
    };
  }

  const rawText = stripRawPrefix(entry?.text || entry?.raw || '');
  const split = splitInstruction(rawText);
  const mnemonic = String(entry?.mnemonic || split.mnemonic || '').trim();
  const operands = normalizeOperandText(entry?.operands || split.operands, entry, options);
  return {
    fileLine: Number(entry?.line) || fallbackLineNumber,
    addrText: formatInstructionAddress(entry?.addr),
    headerAddrText: formatFunctionHeaderAddress(entry?.addr),
    bytesText: extractBytesText(entry),
    mnemonic,
    operands,
    rawText
  };
}

function appendInstruction(row, normalized) {
  const code = document.createElement('div');
  code.className = 'disasm-code';

  const mnemonic = document.createElement('span');
  mnemonic.className = 'disasm-mnemonic';
  mnemonic.textContent = normalized.mnemonic || normalized.rawText || '...';
  code.appendChild(mnemonic);

  if (normalized.operands) {
    const operands = document.createElement('span');
    operands.className = 'disasm-operands';
    operands.textContent = normalized.operands;
    code.appendChild(operands);
  }

  row.appendChild(code);
}

function appendCrashBadge(row) {
  const badge = document.createElement('span');
  badge.className = 'asm-crash-badge';
  badge.textContent = 'Crash';
  badge.title = 'Crash';
  row.appendChild(badge);
}

export function findDisasmEntryForAddress(disasmLines, currentAddr) {
  if (!Array.isArray(disasmLines) || disasmLines.length === 0) return null;
  const targetAddr = parseAddr(currentAddr);
  if (targetAddr === null) return null;

  let exact = null;
  let nearestLower = null;
  let maxDisasmAddr = null;
  disasmLines.forEach((entry, index) => {
    const addr = parseAddr(entry?.addr);
    if (addr === null) return;
    if (maxDisasmAddr === null || addr > maxDisasmAddr) maxDisasmAddr = addr;
    if (addr === targetAddr) {
      exact = { entry, index, addr, exact: true };
      return;
    }
    if (addr < targetAddr && (!nearestLower || addr > nearestLower.addr)) {
      nearestLower = { entry, index, addr, exact: false };
    }
  });

  if (exact) return exact;
  // Guard: if the target is far beyond all known disasm addresses it is likely a
  // PIE rebase mismatch (snapshot RIP rebased, disasm addresses ELF-relative).
  // In that case nearestLower would be the last entry in an unrelated function,
  // which causes the wrong instruction to be highlighted (e.g. libc_csu_fini).
  if (nearestLower !== null && maxDisasmAddr !== null && targetAddr > maxDisasmAddr + 0x1000n) {
    return null;
  }
  return nearestLower;
}

export function resolveActiveDisasmFileLine(disasmLines, currentAddr) {
  const match = findDisasmEntryForAddress(disasmLines, currentAddr);
  const lineNumber = Number(match?.entry?.line);
  if (Number.isFinite(lineNumber) && lineNumber > 0) return lineNumber;
  if (match && Number.isInteger(match.index)) return match.index + 1;
  return null;
}

export function resolveDisasmJumpTarget(disasmLines, candidateAddr) {
  if (!Array.isArray(disasmLines) || disasmLines.length === 0) return null;
  const targetAddr = parseAddr(candidateAddr);
  if (targetAddr === null) return null;

  let minAddr = null;
  let maxAddr = null;
  for (const line of disasmLines) {
    const addr = parseAddr(line?.addr);
    if (addr === null) continue;
    if (minAddr === null || addr < minAddr) minAddr = addr;
    if (maxAddr === null || addr > maxAddr) maxAddr = addr;
  }
  if (minAddr === null || maxAddr === null) return null;
  if (targetAddr < minAddr || targetAddr > maxAddr + 0x20n) return null;

  const match = findDisasmEntryForAddress(disasmLines, targetAddr);
  if (!match) return null;
  if (!match.exact) {
    const gap = targetAddr - match.addr;
    if (gap < 0n || gap > 0x20n) return null;
  }

  const lineNumber = Number(match?.entry?.line);
  return {
    lineNumber: Number.isFinite(lineNumber) && lineNumber > 0 ? lineNumber : match.index + 1,
    entry: match.entry,
    exact: match.exact
  };
}

let lastJumpNode = null;

export function scrollDisasmToFileLine(lineNumber) {
  if (!dom.disasmList || !Number.isFinite(lineNumber) || lineNumber < 1) return;
  const node = [...dom.disasmList.children].find((child) => Number(child.dataset.fileLine) === lineNumber);
  if (!(node instanceof HTMLElement)) return;

  if (lastJumpNode && lastJumpNode !== node) {
    lastJumpNode.classList.remove('disasm-jump-target');
  }
  node.classList.add('disasm-jump-target');
  lastJumpNode = node;

  const container = dom.disasmList;
  const targetTop = node.offsetTop - container.clientHeight / 2 + node.clientHeight / 2;
  container.scrollTop = Math.max(0, targetTop);
}

export function renderDisasmPanel(entries, activeLineNumber, options = {}) {
  if (!dom.disasmList) return;
  dom.disasmList.replaceChildren();

  if (!Array.isArray(entries) || entries.length === 0) {
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Aucun desassemblage disponible.';
    dom.disasmList.appendChild(status);
    return;
  }

  const fragment = document.createDocumentFragment();
  let activeNode = null;
  const functionHeaders = options.functionHeaders && typeof options.functionHeaders === 'object'
    ? options.functionHeaders
    : {};
  const diagnostics = Array.isArray(options.diagnostics) ? options.diagnostics : [];
  const crashDiagnostics = Array.isArray(options.crashDiagnostics) ? options.crashDiagnostics : [];
  const appendHeader = (normalized, fallbackName = '') => {
    const name = functionHeaders[normalized.addrText] || fallbackName;
    if (!name || !normalized.headerAddrText) return;
    const header = document.createElement('div');
    header.className = 'disasm-function-header';
    header.textContent = `${normalized.headerAddrText} <${name}>:`;
    fragment.appendChild(header);
  };

  const firstEntry = normalizeRenderEntry(entries[0], 1, options);
  appendHeader(firstEntry, options.functionName || '');

  entries.forEach((entry, index) => {
    const normalized = normalizeRenderEntry(entry, index + 1, options);
    if (index > 0) {
      appendHeader(normalized);
    }
    const row = document.createElement('div');
    row.className = 'disasm-raw-line';
    row.dataset.fileLine = String(normalized.fileLine || index + 1);
    const crashDiagnostic = primaryDiagnostic(
      diagnostics.filter((diagnostic) => diagnosticMatchesAddress(diagnostic, normalized.addrText, 'instructionAddress'))
    );
    const responsibleDiagnostic = primaryDiagnostic(
      diagnostics.filter((diagnostic) => diagnosticMatchesAddress(diagnostic, normalized.addrText, 'responsibleInstructionAddress'))
    );
    const persistentCrashDiagnostic = primaryDiagnostic(
      crashDiagnostics.filter((diagnostic) => diagnosticMatchesAddress(diagnostic, normalized.addrText, 'any'))
    );
    if (responsibleDiagnostic) row.classList.add('disasm-diagnostic-responsible');
    if (crashDiagnostic) row.classList.add('disasm-diagnostic-crash');
    if (persistentCrashDiagnostic) row.classList.add('asm-line-crash');
    const rowDiagnostic = persistentCrashDiagnostic || crashDiagnostic || responsibleDiagnostic;
    if (rowDiagnostic) {
      const prefix = persistentCrashDiagnostic ? 'Crash' : diagnosticKindLabel(rowDiagnostic.kind);
      row.title = `${prefix}: ${rowDiagnostic.message || ''}`.trim();
    }

    const addr = document.createElement('div');
    addr.className = 'disasm-addr';
    addr.textContent = normalized.addrText
      ? `${normalized.addrText}:`
      : `L${normalized.fileLine || index + 1}`;
    row.appendChild(addr);

    const bytes = document.createElement('div');
    bytes.className = 'disasm-bytes';
    bytes.textContent = normalized.bytesText || '';
    row.appendChild(bytes);

    appendInstruction(row, normalized);
    if (persistentCrashDiagnostic) appendCrashBadge(row);

    if (Number(normalized.fileLine) === Number(activeLineNumber)) {
      row.classList.add('disasm-active');
      activeNode = row;
    }

    fragment.appendChild(row);
  });

  dom.disasmList.appendChild(fragment);

  if (activeNode) {
    const container = dom.disasmList;
    const targetTop = activeNode.offsetTop - container.clientHeight / 2 + activeNode.clientHeight / 2;
    container.scrollTop = Math.max(0, targetTop);
  }
}

export function initDisasmContextMenu() {
  const list = document.getElementById('disasmList');
  if (!list) return;
  if (_ctxMenuInitialized) return;
  _ctxMenuInitialized = true;

  list.addEventListener('contextmenu', (e) => {
    const row = e.target.closest('.disasm-raw-line');
    if (!row) return;
    e.preventDefault();
    const addrEl = row.querySelector('.disasm-addr');
    const instrEl = row.querySelector('.disasm-code');
    const addr = addrEl ? addrEl.textContent.replace(':', '').trim() : '';
    const instr = instrEl ? instrEl.textContent.trim() : '';
    _showCtxMenu(e.clientX, e.clientY, addr, instr);
  });

  document.addEventListener('click', (e) => {
    if (_ctxMenu && !_ctxMenu.contains(e.target)) _hideCtxMenu();
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') _hideCtxMenu();
  });

  _getOrCreateCtxMenu().addEventListener('click', (e) => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    if (btn.dataset.action === 'ask-ai') {
      const addr = _ctxMenu?.dataset.addr || '';
      const instr = _ctxMenu?.dataset.instr || '';
      _hideCtxMenu();
      _openChatWithContext(addr, instr);
    }
  });
}
