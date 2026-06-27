/**
 * @file render.js
 * @brief Helpers de rendu UI pour les panneaux lateraux.
 * @details Registres, dump memoire, frame context, et risques.
 */
import { dom } from './dom.js';
import { diagnosticKindLabel, diagnosticRegisters } from './diagnostics.js';
import { resolveStackAddress, toBytes, toHex } from './utils.js';

function parseByteString(text) {
  if (typeof text !== 'string') return [];
  return text
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .map((part) => Number.parseInt(part, 16))
    .filter((value) => Number.isFinite(value) && value >= 0 && value <= 0xff);
}

/**
 * @brief Rend la liste des registres.
 * @param registerItems Liste de registres.
 */
export function renderRegisters(registerItems, diagnostics = []) {
  if (!dom.registers) return;
  dom.registers.innerHTML = '';
  const highlightedRegisters = diagnosticRegisters(diagnostics);

  // Empty-state.
  if (!Array.isArray(registerItems) || registerItems.length === 0) {
    dom.registers.innerHTML = '<div class="status">Aucun registre pour cette étape.</div>';
    return;
  }

  // Sort by UI position index.
  const sorted = [...registerItems].sort((a, b) => {
    const offsetA = typeof a.pos === 'number' ? a.pos : a.posi ?? 0;
    const offsetB = typeof b.pos === 'number' ? b.pos : b.posi ?? 0;
    return offsetA - offsetB;
  });

  sorted.forEach((reg) => {
    const row = document.createElement('div');
    row.className = 'register';
    const regName = String(reg.name || '').trim().toLowerCase();
    const diagnostic = highlightedRegisters.get(regName);
    if (diagnostic) {
      row.classList.add('register-diagnostic', `register-diagnostic-${diagnostic.severity || 'warning'}`);
      row.title = `${diagnosticKindLabel(diagnostic.kind)}: ${diagnostic.message || ''}`.trim();
    }

    row.innerHTML = `
      <span class="register-name">${reg.name ?? '?'}</span>
      <span class="register-value">${reg.value ?? '??'}</span>
    `;

    dom.registers.appendChild(row);
  });
}

/**
 * @brief Rend un hexdump a partir de la pile.
 * @param stackItems Entrees de pile.
 * @param regMap Mapping de registres.
 * @param meta Metadonnees de trace.
 */
export function renderMemoryDump(stackItems, regMap, meta, snapshot = null) {
  if (!dom.memoryDump) return;
  dom.memoryDump.textContent = '';

  const memory = snapshot && typeof snapshot.memory === 'object' ? snapshot.memory : {};
  const windowStart = typeof memory.window_start === 'string' && memory.window_start.startsWith('0x')
    ? Number.parseInt(memory.window_start, 16)
    : null;
  const windowBytes = parseByteString(memory.window_bytes);

  let startAddr = windowStart;
  let bytes = windowBytes;

  if (!(Number.isFinite(startAddr) && bytes.length)) {
    if (!Array.isArray(stackItems) || stackItems.length === 0) {
      dom.memoryDump.textContent = '(no data)';
      return;
    }

    const rsp = regMap.rsp ?? regMap.esp ?? null;
    const wordSize =
      typeof meta.word_size === 'number'
        ? meta.word_size
        : regMap.eax !== undefined
        ? 4
        : 8;

    const items = stackItems
      .map((item) => {
        const addr = resolveStackAddress(item, rsp);
        return {
          addr,
          bytes: toBytes(item.value, wordSize)
        };
      })
      .filter((item) => item.addr !== null)
      .sort((a, b) => a.addr - b.addr);

    if (!items.length) {
      dom.memoryDump.textContent = '(no data)';
      return;
    }

    startAddr = items[0].addr;
    bytes = [];
    items.forEach((item) => {
      bytes.push(...item.bytes);
    });
  }

  const lines = [];
  const lineSize = 16;
  for (let i = 0; i < bytes.length; i += lineSize) {
    const slice = bytes.slice(i, i + lineSize);
    const addr = startAddr + i;
    const hexBytes = slice.map((b) => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = slice
      .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'))
      .join('');
    lines.push(`${toHex(addr)}: ${hexBytes.padEnd(47, ' ')} |${ascii}|`);
  }

  dom.memoryDump.textContent = lines.join('\n');
}

/**
 * @brief Rend le contexte SP/BP pour l'instruction.
 * @param snap Snapshot courant.
 * @param regMap Mapping de registres.
 */
export function renderFrameContext(snap, regMap, analysis = null) {
  if (!dom.frameContext) return;
  const rsp = regMap.rsp ?? regMap.esp ?? null;
  const rbp = regMap.rbp ?? regMap.ebp ?? null;
  const is32 = regMap.esp !== undefined || regMap.ebp !== undefined;
  const spName = is32 ? 'ESP' : 'RSP';
  const bpName = is32 ? 'EBP' : 'RBP';
  const instr = typeof snap.instr === 'string' ? snap.instr : '';
  const effects = snap && typeof snap.effects === 'object' ? snap.effects : {};
  const overflow = analysis && typeof analysis.overflow === 'object' ? analysis.overflow : null;

  if (rsp === null && rbp === null) {
    dom.frameContext.textContent = 'Aucun registre SP/BP disponible.';
    return;
  }

  const spLabel = rsp !== null ? `${spName}=${toHex(rsp)}` : '';
  const bpLabel = rbp !== null ? `${bpName}=${toHex(rbp)}` : '';
  const effect = explainStackEffect(instr);
  const parts = [spLabel, bpLabel].filter(Boolean);
  const spDelta = Number.isFinite(effects.sp_delta) ? effects.sp_delta : null;
  const effectKind = typeof effects.kind === 'string' && effects.kind
    ? effects.kind.replace(/_/g, ' ')
    : null;
  if (effectKind) parts.push(effectKind);
  if (spDelta !== null && spDelta !== 0) {
    const sign = spDelta > 0 ? '+' : '';
    parts.push(`${spName} ${sign}${spDelta}`);
  }
  if (overflow && overflow.active) {
    const reached = Array.isArray(overflow.reached) && overflow.reached.length
      ? overflow.reached.join(', ')
      : 'zone adjacente';
    parts.push(`overflow -> ${reached}`);
  }
  const prefix = parts.join(' • ');
  dom.frameContext.textContent = prefix ? `${prefix} • ${effect}` : effect;
}

/**
 * @brief Donne une explication simple de l'effet stack.
 * @param instr Instruction texte.
 * @return Phrase descriptive.
 */
export function explainStackEffect(instr) {
  if (!instr) return 'Instruction courante inconnue.';
  const text = instr.trim();
  const lower = text.toLowerCase();
  const mnemonic = lower.split(/\s+/)[0];

  // Small heuristic for the most common stack-affecting mnemonics.
  if (mnemonic === 'push') {
    return 'push: réserve 4/8 octets et écrit une valeur sur la pile.';
  }
  if (mnemonic === 'pop') {
    return 'pop: lit une valeur sur la pile puis libère 4/8 octets.';
  }
  if (mnemonic === 'call') {
    return 'call: empile l’adresse de retour puis saute à la fonction.';
  }
  if (mnemonic === 'ret') {
    return 'ret: dépile l’adresse de retour et saute.';
  }
  if (mnemonic === 'leave') {
    return 'leave: remet SP sur BP puis dépile l’ancien BP.';
  }
  if (mnemonic === 'sub' && lower.includes('sp')) {
    return 'sub sp, X: réserve X octets pour les variables locales.';
  }
  if (mnemonic === 'add' && lower.includes('sp')) {
    return 'add sp, X: libère X octets (fin de frame ou nettoyage arguments).';
  }
  if (mnemonic === 'mov' && (lower.includes('sp') || lower.includes('bp'))) {
    return 'mov sp/bp: ajuste les pointeurs de frame (prologue/épilogue).';
  }

  return 'Aucun effet direct sur la pile détecté.';
}

/**
 * @brief Rend la liste des risques.
 * @param riskItems Liste de risques.
 * @param activeLine Ligne selectionnee.
 */
export function renderRisks(riskItems, activeLine) {
  if (!dom.risks) return;
  dom.risks.innerHTML = '';

  // Empty-state.
  if (!Array.isArray(riskItems) || riskItems.length === 0) {
    dom.risks.innerHTML = '<div class="status">Aucun risque détecté.</div>';
    return;
  }

  // Each risk becomes a clickable row.
  riskItems.forEach((risk) => {
    const line = typeof risk.line === 'number' ? risk.line : null;
    const row = document.createElement('button');
    row.type = 'button';
    row.className = `risk risk-${risk.severity ?? 'low'}`;
    if (line !== null && activeLine === line) {
      row.classList.add('risk-active');
    }

    const fileLabel = risk.file ? ` • ${risk.file}` : '';
    const lineLabel = line !== null ? `L${line}` : 'L?';
    row.textContent = `${lineLabel} ${risk.kind ?? 'risk'}${fileLabel} — ${risk.message ?? ''}`;

    dom.risks.appendChild(row);
  });
}
