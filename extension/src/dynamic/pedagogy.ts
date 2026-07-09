// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file pedagogy.js
 * @brief Helpers deterministes pour focus function, modele de fonction et explications debutant.
 */

const {
  applySourceHintsToFunctionModel,
  resolveSourceFunction
} = require('./sourceCEnrichment');

const STACK_REF_RE = /\[((?:r|e)?bp|(?:r|e)?sp)([^\]]*)\]/i;
const STACK_STORE_RE = /^\s*mov(?:zx|sx|sxd)?\s+(?:[a-z]+\s+ptr\s+)?\[((?:r|e)?bp|(?:r|e)?sp)[^\]]*\]\s*,\s*(.+)\s*$/i;
const STACK_LOAD_RE = /^\s*mov(?:zx|sx|sxd)?\s+([a-z0-9]+)\s*,\s*(?:[a-z]+\s+ptr\s+)?\[((?:r|e)?bp|(?:r|e)?sp)[^\]]*\]\s*$/i;
const ARGC_SAVE_RE = /^\s*mov\s+dword\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*(?:edi|rdi)\s*$/i;
const ARGV_SAVE_RE = /^\s*mov\s+(?:qword|dword)\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*(?:rsi|esi)\s*$/i;
const MODIFIED_INIT_RE = /^\s*mov\s+dword\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*0(?:x0+)?\s*$/i;
const MODIFIED_CMP_RE = /^\s*cmp\s+dword\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*(0x43434343|1128481603)\s*$/i;
const MODIFIED_REG_CMP_RE = /^\s*cmp\s+([a-z0-9]+)\s*,\s*(0x43434343|1128481603)\s*$/i;
const LEA_BUFFER_RE = /^\s*lea\s+([a-z0-9]+)\s*,\s*\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*$/i;
const STACK_DWORD_IMM_STORE_RE = /^\s*mov\s+dword\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*(0x[0-9a-f]+|\d+)\s*$/i;
const STACK_DWORD_IMM_CMP_RE = /^\s*cmp\s+dword\s+ptr\s+\[(?:rbp|ebp)\s*-\s*(0x[0-9a-f]+|\d+)\]\s*,\s*(0x[0-9a-f]+|\d+)\s*$/i;
const CALL_RE = /\bcallq?\b\s+(.+)$/i;
const BRANCH_RE = /^\s*j(?:mp|[a-z]{1,3})\b/i;
const PROLOGUE_PUSH_RE = /^\s*push\s+(?:rbp|ebp)\b/i;
const PROLOGUE_MOV_RE = /^\s*mov\s+(?:rbp|ebp)\s*,\s*(?:rsp|esp)\b/i;
const PROLOGUE_SAVED_REG_PUSH_RE = /^\s*push\s+([a-z][a-z0-9]*)\b/i;
const STACK_ALLOC_RE = /^\s*sub\s+(?:rsp|esp)\s*,\s*(0x[0-9a-f]+|\d+)\b/i;
const LEAVE_RE = /^\s*leave\b/i;
const RET_RE = /^\s*ret[q]?\b/i;
const UNSAFE_CALLS = new Set([
  'strcpy', 'strncpy', 'gets', 'scanf', '__isoc99_scanf', 'sprintf',
  'snprintf', 'memcpy', 'memmove', 'strcat', 'read'
]);
const IGNORE_FOCUS_FUNCTIONS = new Set([
  '_start', 'start', '__libc_start_main', '__libc_start_call_main',
  '__libc_csu_init', '__libc_csu_fini', 'frame_dummy', 'register_tm_clones',
  'deregister_tm_clones', 'init', 'fini'
]);

function parseSignedImmediate(raw) {
  const text = String(raw || '').trim().toLowerCase();
  if (!text) return null;
  if (/^-0x[0-9a-f]+$/.test(text)) return -Number.parseInt(text.slice(3), 16);
  if (/^0x[0-9a-f]+$/.test(text)) return Number.parseInt(text, 16);
  if (/^-?\d+$/.test(text)) return Number.parseInt(text, 10);
  return null;
}

function formatOffset(offset) {
  if (!Number.isFinite(offset)) return 'inconnu';
  return `${offset < 0 ? '-' : '+'}0x${Math.abs(offset).toString(16)}`;
}

function normalizeFunctionName(name) {
  const raw = String(name || '').trim();
  if (!raw) return '';
  return raw
    .replace(/^_+/, '')
    .replace(/@.*/, '')
    .replace(/<|>/g, '')
    .toLowerCase();
}

function displayFunctionName(name) {
  const raw = String(name || '').trim();
  if (!raw) return '';
  const stripped = raw.replace(/@.*/, '').replace(/<|>/g, '');
  if (stripped.startsWith('_') && stripped.length > 1) return stripped.slice(1);
  return stripped;
}

function sameFunction(left, right) {
  const a = normalizeFunctionName(left);
  const b = normalizeFunctionName(right);
  return Boolean(a && b && a === b);
}

function slotHumanLabel(slot, payloadText = '', payloadLabel = 'argv[1]', payloadHex = '') {
  const rawLabel = String(slot?.label || '').toLowerCase();
  const role = String(slot?.role || '').toLowerCase();
  if (rawLabel === 'argc') return 'copie locale de argc';
  if (rawLabel === 'argv') return 'pointeur argv';
  if (rawLabel === 'modified' || rawLabel.includes('modified')) return 'variable modified';
  if (role === 'saved_bp') return 'ancienne base';
  if (role === 'return_address' || rawLabel.includes('ret')) return 'adresse de retour';
  if (role === 'buffer') return 'buffer local';
  if (role === 'argument' && slotLooksLikePayload(slot, payloadText, payloadHex)) return `contenu de ${payloadLabel}`;
  if (role === 'argument') return 'zone argument';
  if (role === 'padding') return 'zone intermédiaire';
  if (role === 'unknown') return 'zone intermédiaire';
  if (role === 'local') return 'variable locale';
  return 'zone de pile';
}

function humanizeOverflowTarget(target) {
  const raw = String(target || '').toLowerCase();
  if (raw === 'saved_bp' || raw === 'saved_rbp') return "l'ancienne base";
  if (raw === 'return_address' || raw === 'ret_addr') return "l'adresse de retour";
  if (raw.includes('buffer')) return 'le buffer local';
  if (raw.includes('modified')) return 'la variable modified';
  return String(target || 'la pile');
}

function parseStackRef(instrText) {
  const match = String(instrText || '').match(STACK_REF_RE);
  if (!match) return null;
  const base = match[1].toLowerCase();
  const offset = parseBracketOffset(match[2]);
  if (offset === null) return null;
  return { base, offset };
}

function parseBracketOffset(expr) {
  const tail = String(expr || '').replace(/\s+/g, '');
  if (!tail) return 0;
  let total = 0;
  let matched = false;
  const termRe = /([+-])(0x[0-9a-f]+|\d+)/gi;
  let match = termRe.exec(tail);
  while (match) {
    const value = parseSignedImmediate(match[2]);
    if (value !== null) {
      total += match[1] === '-' ? -Math.abs(value) : Math.abs(value);
      matched = true;
    }
    match = termRe.exec(tail);
  }
  termRe.lastIndex = 0;
  return matched ? total : null;
}

function getSnapshot(traceData, step) {
  const snapshots = Array.isArray(traceData?.snapshots) ? traceData.snapshots : [];
  return snapshots[step - 1] ?? null;
}

function getAnalysis(traceData, step) {
  const analysisByStep = traceData?.analysisByStep && typeof traceData.analysisByStep === 'object'
    ? traceData.analysisByStep
    : {};
  return analysisByStep[String(step)] ?? null;
}

function getDisasmEntries(traceData) {
  return Array.isArray(traceData?.meta?.disasm) ? traceData.meta.disasm : [];
}

function buildFunctionRangeIndex(traceData) {
  const map = new Map();
  const snapshots = Array.isArray(traceData?.snapshots) ? traceData.snapshots : [];
  snapshots.forEach((snap, index) => {
    const step = Number(snap?.step) || index + 1;
    const analysis = getAnalysis(traceData, step);
    const functionInfo = analysis?.function && typeof analysis.function === 'object' ? analysis.function : {};
    const rawName = String(functionInfo.name || snap?.func || '').trim();
    const normalized = normalizeFunctionName(rawName);
    if (!normalized) return;

    const start = parseSignedImmediate(functionInfo.range_start || functionInfo.addr);
    const end = parseSignedImmediate(functionInfo.range_end);
    const current = map.get(normalized) || {
      name: displayFunctionName(rawName) || rawName,
      normalized,
      rangeStart: null,
      rangeEnd: null,
      steps: []
    };
    current.steps.push(step);
    if (start !== null && (current.rangeStart === null || start < current.rangeStart)) {
      current.rangeStart = start;
    }
    if (end !== null && (current.rangeEnd === null || end > current.rangeEnd)) {
      current.rangeEnd = end;
    }
    if (!current.name && rawName) current.name = displayFunctionName(rawName);
    map.set(normalized, current);
  });
  return map;
}

function chooseFocusFunction(traceData) {
  const snapshots = Array.isArray(traceData?.snapshots) ? traceData.snapshots : [];
  const requested = displayFunctionName(traceData?.meta?.start_symbol || '');
  if (requested) {
    const wanted = normalizeFunctionName(requested);
    const matching = snapshots.find((snap) => sameFunction(snap?.func, requested));
    if (matching?.func) return displayFunctionName(matching.func);
    if (wanted) return requested;
  }

  const counts = new Map();
  snapshots.forEach((snap) => {
    const rawName = displayFunctionName(snap?.func || '');
    const normalized = normalizeFunctionName(rawName);
    if (!normalized) return;
    const current = counts.get(normalized) || { rawName, count: 0 };
    current.count += 1;
    if (!current.rawName && rawName) current.rawName = rawName;
    counts.set(normalized, current);
  });

  if (counts.has('main')) return counts.get('main').rawName || 'main';

  let best = null;
  counts.forEach((entry, normalized) => {
    if (IGNORE_FOCUS_FUNCTIONS.has(normalized)) return;
    if (!best || entry.count > best.count) {
      best = { normalized, rawName: entry.rawName, count: entry.count };
    }
  });
  if (best?.rawName) return best.rawName;

  const firstNamed = snapshots.find((snap) => String(snap?.func || '').trim());
  return displayFunctionName(firstNamed?.func || 'main') || 'main';
}

function looksLikeUnsafeCall(name) {
  return UNSAFE_CALLS.has(normalizeFunctionName(name));
}

function createLocal(offset, next = {}) {
  return {
    name: next.name || '',
    offset,
    size: Number.isFinite(next.size) && next.size > 0 ? Math.trunc(next.size) : 1,
    role: next.role || 'local',
    cType: next.cType || '',
    confidence: Number.isFinite(next.confidence) ? Number(next.confidence) : 0.5,
    rawLabel: next.rawLabel || '',
    // Provenance: 'backend' for a local built from a real analysisByStep
    // slot (buildFunctionModel's first pass), 'pedagogy_fallback' for
    // every disassembly-regex/CTF-pattern guess below -- mergeLocal uses
    // this to make sure a fallback guess can never resize, reclassify, or
    // re-score a backend-confirmed local, regardless of confidence.
    source: next.source || 'pedagogy_fallback',
    // Passthrough only, never derived here: whether the backend proved
    // this size exact or only drew it to an estimated bound.
    sizeExact: next.sizeExact,
    evidence: Array.isArray(next.evidence) ? [...next.evidence] : []
  };
}

function localSemanticScore(local) {
  const role = String(local?.role || '').toLowerCase();
  const name = String(local?.name || '').toLowerCase();
  if (name === 'argc' || name === 'argv' || name === 'buffer' || name === 'modified') return 4;
  if (role === 'buffer' || role === 'modified' || role === 'arg') return 3;
  if (name && !/^var_[0-9a-f]+$/i.test(name) && !/^stack_[0-9a-f]+h$/i.test(name)) return 2;
  if (role === 'local') return 1;
  return 0;
}

function mergeLocal(existing, next) {
  // A backend-sourced local (real Evidence Model data: role, size,
  // confidence already resolved by the trace) is authoritative. A
  // pedagogy_fallback guess at the same offset must never resize it,
  // reclassify it into/out of 'buffer', or touch its confidence -- and a
  // genuine backend local arriving after a fallback guess always replaces
  // it outright.
  if (existing?.source === 'backend' && next?.source !== 'backend') {
    if (existing.role === 'buffer' || next.role === 'buffer') {
      // Role/size/confidence stay backend-owned, but the fallback's
      // evidence (e.g. a corroborating lea) is still recorded -- source C
      // enrichment (a stronger authority than either side here) can use it
      // later to recognize this offset as address-taken.
      return {
        ...existing,
        evidence: [...new Set([...(existing.evidence || []), ...(next.evidence || [])])]
      };
    }
    // Neither side is a buffer: the fallback may still refine the
    // pedagogical display name (argc/argv/modified) for a backend local
    // the backend only gave a generic name to, but size/confidence stay
    // backend-owned.
    return {
      ...existing,
      name: next.name || existing.name,
      role: next.role || existing.role,
      cType: next.cType || existing.cType,
      evidence: [...new Set([...(existing.evidence || []), ...(next.evidence || [])])]
    };
  }
  if (next?.source === 'backend' && existing?.source !== 'backend') return { ...next };

  const merged = {
    ...existing,
    size: Math.max(existing.size || 1, next.size || 1),
    evidence: [...new Set([...(existing.evidence || []), ...(next.evidence || [])])]
  };
  const nextConfidence = Number(next.confidence || 0);
  const existingConfidence = Number(existing.confidence || 0);
  const nextSemanticScore = localSemanticScore(next);
  const existingSemanticScore = localSemanticScore(existing);
  const shouldAdoptNext = nextConfidence > existingConfidence
    || (
      nextConfidence === existingConfidence
      && nextSemanticScore > existingSemanticScore
    )
    || (
      nextConfidence >= existingConfidence - 0.12
      && nextSemanticScore >= 3
      && existingSemanticScore <= 1
    );
  if (shouldAdoptNext) {
    merged.name = next.name || existing.name;
    merged.role = next.role || existing.role;
    merged.cType = next.cType || existing.cType;
    merged.confidence = nextConfidence || existing.confidence;
  }
  if (!merged.rawLabel && next.rawLabel) merged.rawLabel = next.rawLabel;
  return merged;
}

function inferLocalRole(rawRole, rawLabel) {
  const role = String(rawRole || '').toLowerCase();
  const label = String(rawLabel || '').toLowerCase();
  if (role === 'buffer') return 'buffer';
  if (role === 'argument') return 'arg';
  if (role === 'local' && label.includes('modified')) return 'modified';
  if (role === 'local') return 'local';
  return '';
}

function inferLocalType(name, role, wordSize) {
  const lowered = String(name || '').toLowerCase();
  if (lowered === 'argc' || lowered === 'modified') return 'int';
  if (lowered === 'argv') return wordSize === 8 ? 'char **' : 'char **';
  if (role === 'buffer') return 'char[]';
  if (role === 'arg') return 'argument';
  return '';
}

function seedLocalsFromDisasm(disasmEntries, meta, localsByOffset) {
  const bufferOffset = parseSignedImmediate(meta?.buffer_offset);
  const bufferSize = parseSignedImmediate(meta?.buffer_size);
  const wordSize = Number.isFinite(Number(meta?.word_size))
    ? Number(meta.word_size)
    : Number(meta?.arch_bits) === 32
    ? 4
    : 8;
  const leaBufferOffsets = new Set();
  let trackingPrologueSavedRegs = false;
  let savedRegisterOffset = 0;
  if (bufferOffset !== null && bufferSize !== null && bufferSize > 0) {
    const seeded = createLocal(bufferOffset, {
      name: 'buffer',
      role: 'buffer',
      size: bufferSize,
      cType: 'char[]',
      confidence: 0.5,
      evidence: ['trace buffer_offset']
    });
    localsByOffset.set(bufferOffset, mergeLocal(localsByOffset.get(bufferOffset) || seeded, seeded));
  }

  disasmEntries.forEach((entry, index) => {
    const instr = extractInstrText(entry);
    const nextInstr = extractInstrText(disasmEntries[index + 1]);
    if (PROLOGUE_MOV_RE.test(instr)) {
      trackingPrologueSavedRegs = true;
      savedRegisterOffset = 0;
      return;
    }

    if (trackingPrologueSavedRegs && STACK_ALLOC_RE.test(instr)) {
      trackingPrologueSavedRegs = false;
    }

    const savedRegMatch = trackingPrologueSavedRegs ? instr.match(PROLOGUE_SAVED_REG_PUSH_RE) : null;
    if (savedRegMatch) {
      const reg = String(savedRegMatch[1] || '').toLowerCase();
      if (reg && reg !== 'rbp' && reg !== 'ebp') {
        savedRegisterOffset -= wordSize;
        const next = createLocal(savedRegisterOffset, {
          name: `saved ${reg}`,
          role: 'padding',
          size: wordSize,
          cType: '',
          confidence: 0.5,
          evidence: [`prologue saved ${reg}`]
        });
        localsByOffset.set(savedRegisterOffset, mergeLocal(localsByOffset.get(savedRegisterOffset) || next, next));
      }
      return;
    }

    const argcMatch = instr.match(ARGC_SAVE_RE);
    if (argcMatch) {
      const offset = -Math.abs(parseSignedImmediate(argcMatch[1]) || 0);
      if (offset) {
        const next = createLocal(offset, {
          name: 'argc',
          role: 'local',
          size: 4,
          cType: 'int',
          confidence: 0.5,
          evidence: ['main arg save from edi/rdi']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const argvMatch = instr.match(ARGV_SAVE_RE);
    if (argvMatch) {
      const offset = -Math.abs(parseSignedImmediate(argvMatch[1]) || 0);
      if (offset) {
        const next = createLocal(offset, {
          name: 'argv',
          role: 'local',
          size: Number.isFinite(Number(meta?.word_size)) ? Number(meta.word_size) : 8,
          cType: 'char **',
          confidence: 0.5,
          evidence: ['main arg save from rsi/esi']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const initMatch = instr.match(MODIFIED_INIT_RE);
    if (initMatch) {
      const offset = -Math.abs(parseSignedImmediate(initMatch[1]) || 0);
      if (offset) {
        const next = createLocal(offset, {
          name: 'modified',
          role: 'modified',
          size: 4,
          cType: 'int',
          confidence: 0.35,
          evidence: ['local zero-init']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const cmpMatch = instr.match(MODIFIED_CMP_RE);
    if (cmpMatch) {
      const offset = -Math.abs(parseSignedImmediate(cmpMatch[1]) || 0);
      if (offset) {
        // A comparison against a CTF sentinel is a strong hint for the
        // pedagogical explanation, but it is not backend evidence of
        // anything -- kept as a low-confidence fallback only, never used
        // to create/confirm a buffer (see LEA_BUFFER_RE below).
        const next = createLocal(offset, {
          name: 'modified',
          role: 'modified',
          size: 4,
          cType: 'int',
          confidence: 0.3,
          evidence: ['compare against 0x43434343']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const bufferMatch = instr.match(LEA_BUFFER_RE);
    if (bufferMatch) {
      const destination = String(bufferMatch[1] || '').toLowerCase();
      if (destination === 'esp' || destination === 'rsp') return;
      const offset = -Math.abs(parseSignedImmediate(bufferMatch[2]) || 0);
      if (offset) {
        leaBufferOffsets.add(offset);
        // `lea` only materializes an address -- it proves neither the
        // size nor even that this is a buffer at all. Kept as a weak
        // fallback signal only; mergeLocal ensures this can never
        // override a backend-confirmed local/buffer at the same offset.
        const next = createLocal(offset, {
          name: 'buffer',
          role: 'buffer',
          size: Number.isFinite(Number(meta?.buffer_size)) && Number(meta.buffer_size) > 0
            ? Number(meta.buffer_size)
            : 32,
          cType: 'char[]',
          confidence: 0.3,
          evidence: ['lea to local stack address']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const genericStoreMatch = instr.match(STACK_DWORD_IMM_STORE_RE);
    if (genericStoreMatch) {
      const offset = -Math.abs(parseSignedImmediate(genericStoreMatch[1]) || 0);
      if (offset) {
        const next = createLocal(offset, {
          name: `var_${Math.abs(offset).toString(16)}`,
          role: 'local',
          size: 4,
          cType: 'int',
          confidence: 0.3,
          evidence: ['local immediate init']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const genericCmpMatch = instr.match(STACK_DWORD_IMM_CMP_RE);
    if (genericCmpMatch) {
      const offset = -Math.abs(parseSignedImmediate(genericCmpMatch[1]) || 0);
      if (offset) {
        const next = createLocal(offset, {
          name: `var_${Math.abs(offset).toString(16)}`,
          role: 'local',
          size: 4,
          cType: 'int',
          confidence: 0.35,
          evidence: [`stack compare immediate ${genericCmpMatch[2].toLowerCase()}`]
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
      return;
    }

    const loadMatch = instr.match(STACK_LOAD_RE);
    const nextCmpMatch = nextInstr.match(MODIFIED_REG_CMP_RE);
    if (loadMatch && nextCmpMatch && loadMatch[1].toLowerCase() === nextCmpMatch[1].toLowerCase()) {
      const stackRef = parseStackRef(instr);
      const offset = Number(stackRef?.offset);
      if (Number.isFinite(offset) && offset < 0) {
        const next = createLocal(offset, {
          name: 'modified',
          role: 'modified',
          size: 4,
          cType: 'int',
          confidence: 0.3,
          evidence: ['load then compare against 0x43434343']
        });
        localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
      }
    }
  });

  if (leaBufferOffsets.size) {
    [...localsByOffset.entries()].forEach(([offset, local]) => {
      if (leaBufferOffsets.has(offset)) return;
      if (String(local?.role || '').toLowerCase() !== 'buffer') return;
      // A buffer classification is only exempt from this cleanup when the
      // backend proved it with an exact (source/DWARF) size. Anything
      // else -- a runtime/estimated guess, or our own trace-metadata seed
      // -- is stale once disassembly shows the real buffer address lives
      // at a different, lea-confirmed offset. Judged on source/size_exact,
      // never on the label text.
      const isEvidenceConfirmedBuffer = local?.source === 'backend' && local?.sizeExact === true;
      if (!isEvidenceConfirmedBuffer) {
        localsByOffset.delete(offset);
      }
    });
  }
}

function collectDisasmEntriesForFunction(traceData, focusFunctionName) {
  const disasmEntries = getDisasmEntries(traceData);
  if (!disasmEntries.length) return [];
  const ranges = buildFunctionRangeIndex(traceData);
  const focusRange = ranges.get(normalizeFunctionName(focusFunctionName));
  if (!focusRange || focusRange.rangeStart === null || focusRange.rangeEnd === null) {
    return disasmEntries;
  }

  return disasmEntries.filter((entry) => {
    const addr = parseSignedImmediate(entry?.addr);
    return addr !== null && addr >= focusRange.rangeStart && addr < focusRange.rangeEnd;
  });
}

function buildFunctionModel(traceData, focusFunctionName = '') {
  const focusName = displayFunctionName(focusFunctionName || chooseFocusFunction(traceData)) || 'main';
  const localsByOffset = new Map();
  const snapshots = Array.isArray(traceData?.snapshots) ? traceData.snapshots : [];
  const wordSize = Number.isFinite(Number(traceData?.meta?.word_size))
    ? Number(traceData.meta.word_size)
    : Number(traceData?.meta?.arch_bits) === 32
    ? 4
    : 8;

  snapshots.forEach((snap, index) => {
    const step = Number(snap?.step) || index + 1;
    const analysis = getAnalysis(traceData, step);
    const snapFunctionName = snap?.func || analysis?.function?.name || '';
    if (!sameFunction(snapFunctionName, focusName)) return;
    const slots = Array.isArray(analysis?.frame?.slots) ? analysis.frame.slots : [];
    slots.forEach((slot) => {
      const offset = Number(slot?.offsetFromBp);
      if (!Number.isFinite(offset) || offset >= 0) return;
      const role = inferLocalRole(slot?.role, slot?.label);
      if (!role) return;
      const next = createLocal(offset, {
        name: role === 'modified'
          ? 'modified'
          : role === 'buffer'
          ? 'buffer'
          : String(slot?.label || ''),
        role,
        size: Number(slot?.size) || 1,
        cType: inferLocalType(String(slot?.label || ''), role, wordSize),
        // Real backend confidence, verbatim -- never inflated (previously
        // buffers were floored at 0.9 regardless of what the backend said).
        confidence: Number.isFinite(Number(slot?.confidence)) ? Number(slot.confidence) : 0.7,
        rawLabel: String(slot?.label || ''),
        source: 'backend',
        sizeExact: typeof slot?.size_exact === 'boolean' ? slot.size_exact : undefined,
        evidence: [String(slot?.source || 'dynamic slot')]
      });
      localsByOffset.set(offset, mergeLocal(localsByOffset.get(offset) || next, next));
    });
  });

  seedLocalsFromDisasm(collectDisasmEntriesForFunction(traceData, focusName), traceData?.meta || {}, localsByOffset);

  const locals = [...localsByOffset.values()]
    .map((local) => ({
      ...local,
      name: local.name || local.rawLabel || `var_${Math.abs(local.offset).toString(16)}`,
      cType: local.cType || inferLocalType(local.name, local.role, wordSize)
    }))
    .sort((left, right) => left.offset - right.offset);

  const callNames = new Set();
  snapshots.forEach((snap, index) => {
    const step = Number(snap?.step) || index + 1;
    const analysis = getAnalysis(traceData, step);
    const snapFunctionName = snap?.func || analysis?.function?.name || '';
    if (!sameFunction(snapFunctionName, focusName)) return;
    const external = displayFunctionName(snap?.effects?.external_symbol || '');
    if (external) callNames.add(external);
  });

  const baseModel = {
    name: focusName,
    arch: wordSize === 4 ? 'x86' : 'x86_64',
    wordSize,
    hasFramePointer: true,
    locals,
    calls: [...callNames],
    notes: [`focus function: ${focusName}`]
  };

  const sourceFunction = resolveSourceFunction(traceData?.meta?.source_enrichment, focusName);
  if (!sourceFunction) return baseModel;

  return applySourceHintsToFunctionModel(baseModel, sourceFunction, {
    archBits: Number(traceData?.meta?.arch_bits) === 32 ? 32 : 64
  });
}

function extractInstrText(entryOrText) {
  if (typeof entryOrText === 'string') return entryOrText.trim();
  if (!entryOrText || typeof entryOrText !== 'object') return '';
  const mnemonic = String(entryOrText.mnemonic || '').trim();
  const operands = String(entryOrText.operands || '').trim();
  if (mnemonic) return `${mnemonic} ${operands}`.trim();
  if (typeof entryOrText.text === 'string' && entryOrText.text.trim()) {
    const text = entryOrText.text.trim();
    const capstoneMatch = text.match(/^(?:[0-9a-f]{2}\s+)+(.*)$/i);
    return (capstoneMatch?.[1] || text).trim();
  }
  if (typeof entryOrText.raw === 'string' && entryOrText.raw.trim()) {
    const parts = entryOrText.raw.split('\t').map((part) => part.trim()).filter(Boolean);
    return (parts[2] || parts[1] || entryOrText.raw).trim();
  }
  return '';
}

function findLocalForOffset(model, offset) {
  if (!Number.isFinite(offset) || !Array.isArray(model?.locals)) return null;
  return model.locals.find((local) => {
    const size = Math.max(1, Number(local?.size) || 1);
    return offset >= local.offset && offset < local.offset + size;
  }) || null;
}

function detectCallSymbol(instrText, snap) {
  const external = displayFunctionName(snap?.effects?.external_symbol || '');
  if (external) return external;
  const match = String(instrText || '').match(CALL_RE);
  if (!match) return '';
  const operand = match[1].trim();
  const symbol = operand.match(/<([^>]+)>/);
  if (symbol) return displayFunctionName(symbol[1]);
  return displayFunctionName(operand.replace(/^0x[0-9a-f]+\s+/i, ''));
}

function buildInstructionAnalysis(traceData, stepIndex, model) {
  const snap = getSnapshot(traceData, stepIndex);
  const prevSnap = stepIndex > 1 ? getSnapshot(traceData, stepIndex - 1) : null;
  const analysis = getAnalysis(traceData, stepIndex);
  const instrText = String(snap?.instr || '').trim();
  const prevInstrText = String(prevSnap?.instr || '').trim();
  const stackRef = parseStackRef(instrText);
  const variable = stackRef ? findLocalForOffset(model, stackRef.offset) : null;
  const callSymbol = detectCallSymbol(instrText, snap);
  const writeCount = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes.length : 0;
  const readCount = Array.isArray(analysis?.delta?.reads) ? analysis.delta.reads.length : 0;
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;

  if (PROLOGUE_PUSH_RE.test(instrText) || PROLOGUE_MOV_RE.test(instrText)) {
    return {
      kind: 'prologue',
      summary: `Le programme entre dans ${model?.name || 'la fonction'}.`,
      details: ['mise en place du cadre de pile'],
      variable,
      stackRef,
      callSymbol
    };
  }

  const allocMatch = instrText.match(STACK_ALLOC_RE);
  if (allocMatch) {
    return {
      kind: 'frame_alloc',
      summary: `Le programme reserve ${allocMatch[1]} sur la pile pour les variables locales.`,
      details: ['allocation du stack frame'],
      variable,
      stackRef,
      callSymbol
    };
  }

  if (LEAVE_RE.test(instrText) || RET_RE.test(instrText)) {
    return {
      kind: 'epilogue',
      summary: 'Le programme termine la fonction et prepare le retour.',
      details: ['fin du stack frame'],
      variable,
      stackRef,
      callSymbol
    };
  }

  if (callSymbol) {
    return {
      kind: looksLikeUnsafeCall(callSymbol) ? 'unsafe_call' : 'call',
      summary: `Le programme appelle ${callSymbol}.`,
      details: [callSymbol],
      variable,
      stackRef,
      callSymbol
    };
  }

  const regCmpMatch = instrText.match(MODIFIED_REG_CMP_RE);
  const prevLoadMatch = prevInstrText.match(STACK_LOAD_RE);
  if (
    regCmpMatch
    && prevLoadMatch
    && regCmpMatch[1].toLowerCase() === prevLoadMatch[1].toLowerCase()
  ) {
    const previousStackRef = parseStackRef(prevInstrText);
    const previousVariable = previousStackRef ? findLocalForOffset(model, previousStackRef.offset) : null;
    return {
      kind: 'compare_modified',
      summary: "Le programme compare la variable 'modified' avec 0x43434343.",
      details: ['comparaison critique de modified'],
      variable: previousVariable || variable || findLocalForOffset(model, -4),
      stackRef: previousStackRef || stackRef,
      callSymbol
    };
  }

  if (MODIFIED_CMP_RE.test(instrText)) {
    return {
      kind: 'compare_modified',
      summary: "Le programme compare la variable 'modified' avec 0x43434343.",
      details: ['comparaison critique de modified'],
      variable: variable || findLocalForOffset(model, -4),
      stackRef,
      callSymbol
    };
  }

  if (LEA_BUFFER_RE.test(instrText) && variable?.role === 'buffer') {
    return {
      kind: 'buffer_address',
      summary: "Le programme calcule l'adresse du buffer local.",
      details: ['preparation du pointeur de destination'],
      variable,
      stackRef,
      callSymbol
    };
  }

  if (STACK_STORE_RE.test(instrText) && stackRef) {
    return {
      kind: 'stack_store',
      summary: `Le programme ecrit une valeur dans ${variable?.name || 'une case de pile'}.`,
      details: [writeCount ? `${writeCount} ecriture(s) de pile` : 'ecriture locale'],
      variable,
      stackRef,
      callSymbol
    };
  }

  if (STACK_LOAD_RE.test(instrText) && stackRef) {
    return {
      kind: 'stack_load',
      summary: `Le programme relit ${variable?.name || 'une valeur de pile'}.`,
      details: [readCount ? `${readCount} lecture(s) de pile` : 'lecture locale'],
      variable,
      stackRef,
      callSymbol
    };
  }

  if (BRANCH_RE.test(instrText)) {
    return {
      kind: 'branch',
      summary: 'Le programme choisit la suite du controle de flux.',
      details: [overflow?.active ? 'la branche suit un etat de pile critique' : 'saut conditionnel'],
      variable,
      stackRef,
      callSymbol
    };
  }

  return {
    kind: 'other',
    summary: 'Le programme poursuit la logique de la fonction courante.',
    details: [],
    variable,
    stackRef,
    callSymbol
  };
}

function slotText(slot) {
  return [
    slot?.valueDisplay,
    slot?.ascii,
    slot?.bytesHex,
    slot?.label
  ]
    .map((part) => String(part || ''))
    .join(' ')
    .toLowerCase();
}

function payloadChunks(payloadText) {
  const text = String(payloadText || '').trim();
  if (!text) return [];
  const out = new Set();
  if (text.length >= 4) {
    out.add(text.slice(0, Math.min(8, text.length)).toLowerCase());
    out.add(text.slice(Math.max(0, text.length - 8)).toLowerCase());
  }
  for (let index = 0; index <= text.length - 4; index += 4) {
    out.add(text.slice(index, index + Math.min(8, text.length - index)).toLowerCase());
  }
  return [...out].filter(Boolean);
}

function payloadHexChunks(payloadHex) {
  const hex = String(payloadHex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (hex.length < 8) return [];
  const out = new Set();
  out.add(hex.slice(0, Math.min(16, hex.length)));
  out.add(hex.slice(Math.max(0, hex.length - 16)));
  for (let index = 0; index <= hex.length - 8; index += 8) {
    out.add(hex.slice(index, index + 8));
    out.add(hex.slice(index, Math.min(index + 16, hex.length)));
  }
  return [...out].filter(Boolean);
}

function slotLooksLikePayload(slot, payloadText = '', payloadHex = '') {
  const haystack = slotText(slot);
  const hexHaystack = String(slot?.bytesHex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (!haystack && !hexHaystack) return false;
  const chunks = payloadChunks(payloadText);
  const hexChunks = payloadHexChunks(payloadHex);
  if (!chunks.length && !hexChunks.length) {
    return String(slot?.role || '').toLowerCase() === 'argument' && haystack.includes('arg_');
  }
  return chunks.some((chunk) => haystack.includes(chunk))
    || hexChunks.some((chunk) => hexHaystack.includes(chunk));
}

function findPayloadSlots(analysis, payloadText = '', payloadHex = '') {
  const slots = Array.isArray(analysis?.frame?.slots) ? analysis.frame.slots : [];
  return slots.filter((slot) => slotLooksLikePayload(slot, payloadText, payloadHex));
}

function buildCurrentMessage(instructionAnalysis, model) {
  const variableName = instructionAnalysis?.variable?.name || '';
  switch (instructionAnalysis?.kind) {
    case 'prologue':
      return `On entre dans ${model?.name || 'la fonction'} et le programme installe son cadre de pile.`;
    case 'frame_alloc':
      return 'Le programme reserve de la place sur la pile pour ses variables locales.';
    case 'stack_store':
      if (variableName === 'argv') return "Le programme sauvegarde le pointeur vers argv dans la frame de main.";
      if (variableName === 'argc') return "Le programme sauvegarde argc dans la frame de main.";
      if (variableName === 'modified') return "Le programme initialise la variable 'modified' dans la pile.";
      return `Le programme ecrit dans ${variableName || 'une variable locale'}.`;
    case 'stack_load':
      return `Le programme relit ${variableName || 'une valeur locale'} depuis la pile pour la suite du code.`;
    case 'unsafe_call':
      return `Le programme appelle ${instructionAnalysis.callSymbol} pour copier des donnees dans le buffer local.`;
    case 'buffer_address':
      return "Le programme prepare l'adresse du buffer local avant l'appel de copie.";
    case 'call':
      return `Le programme appelle ${instructionAnalysis.callSymbol || 'une fonction'}.`;
    case 'compare_modified':
      return "Le programme verifie si 'modified' vaut 0x43434343.";
    case 'branch':
      return 'Le programme choisit maintenant quelle branche executer.';
    case 'epilogue':
      return `Le programme sort de ${model?.name || 'la fonction'} et prepare le retour.`;
    default:
      return 'Le programme continue les instructions de la fonction courante.';
  }
}

function buildStackMessage(traceData, stepIndex, analysis, instructionAnalysis) {
  const writes = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  const reads = Array.isArray(analysis?.delta?.reads) ? analysis.delta.reads : [];
  const buffer = analysis?.buffer && typeof analysis.buffer === 'object' ? analysis.buffer : null;

  if (instructionAnalysis?.kind === 'frame_alloc') {
    return 'La pile descend pour reserver la zone des variables locales.';
  }
  if (instructionAnalysis?.kind === 'prologue') {
    return 'RBP devient le repere fixe de la frame et les variables locales seront adressees par offset.';
  }
  if (instructionAnalysis?.kind === 'unsafe_call' && buffer?.name) {
    return "L'appel ecrit dans le buffer local et modifie directement son contenu.";
  }
  if (instructionAnalysis?.kind === 'buffer_address') {
    return "La pile ne change pas encore: le programme pointe simplement vers le buffer local qui recevra la copie.";
  }
  if (writes.length) {
    const first = writes[0];
    return `Cette etape ecrit ${first.size || 0} octet(s) dans la pile autour de ${first.addr || 'la frame courante'}.`;
  }
  if (reads.length) {
    const first = reads[0];
    return `Cette etape lit ${first.size || 0} octet(s) dans la pile autour de ${first.addr || 'la frame courante'}.`;
  }
  const snapshot = getSnapshot(traceData, stepIndex);
  const line = Number(snapshot?.line);
  if (Number.isFinite(line) && line > 0) {
    return `La pile reste stable pendant cette instruction de la ligne C ${line}.`;
  }
  return 'Cette instruction ne change pas visiblement la pile a cette etape.';
}

function buildPayloadMessage(traceData, analysis, instructionAnalysis) {
  const payloadText = String(traceData?.meta?.payload_text || traceData?.meta?.argv1 || '').trim();
  const payloadHex = String(traceData?.meta?.payload_hex || traceData?.meta?.input?.previewHex || '').trim();
  const payloadLabel = String(traceData?.meta?.payload_label || (
    traceData?.meta?.payload_target === 'stdin'
      ? 'stdin'
      : traceData?.meta?.payload_target === 'both'
        ? 'stdin + argv[1]'
        : 'argv[1]'
  ));
  const payloadSlots = findPayloadSlots(analysis, payloadText, payloadHex);
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  const copiedIntoFrame = payloadSlots.some((slot) => String(slot?.role || '').toLowerCase() !== 'argument');

  if (overflow?.active) {
    const reached = Array.isArray(overflow.reached) && overflow.reached.length
      ? overflow.reached.map(humanizeOverflowTarget).join(', ')
      : 'les zones de controle';
    return `Le contenu de ${payloadLabel} a deja depasse le buffer et atteint ${reached}.`;
  }

  if (instructionAnalysis?.kind === 'unsafe_call') {
    return payloadText
      ? `${payloadLabel} = "${payloadText}" est en train d'etre copie dans le buffer local.`
      : `${payloadLabel} est en train d'etre copie dans le buffer local.`;
  }

  if (payloadSlots.length) {
    if (instructionAnalysis?.kind === 'prologue' || instructionAnalysis?.kind === 'frame_alloc') {
      return `${payloadLabel} est deja present au lancement du programme, mais pas encore copie dans le buffer local.`;
    }
    if (!copiedIntoFrame) {
      return `${payloadLabel} est deja present, mais pas encore copie dans le buffer local.`;
    }
    if (instructionAnalysis?.variable?.name === 'modified' || instructionAnalysis?.kind === 'compare_modified') {
      return "On voit maintenant que la copie a atteint la variable 'modified'.";
    }
    if (instructionAnalysis?.variable?.name === 'buffer' || instructionAnalysis?.kind === 'buffer_address') {
      return `Le contenu de ${payloadLabel} est en train de se preparer pour la copie dans le buffer local.`;
    }
    const slot = payloadSlots[0];
    const label = slotHumanLabel(slot, payloadText, payloadLabel, payloadHex);
    return payloadText
      ? `On retrouve encore des morceaux de ${payloadLabel} dans ${label}.`
      : `Le contenu injecte est visible dans ${label}.`;
  }

  const hasArgv = Array.isArray(analysis?.frame?.slots)
    && analysis.frame.slots.some((slot) => String(slot?.label || '').toLowerCase() === 'argv');
  if (hasArgv && payloadLabel === 'argv[1]') {
    return "Le pointeur vers argv est deja en place, mais argv[1] n'a pas encore ete copie dans le buffer.";
  }

  return `${payloadLabel} n'a pas encore d'effet visible sur la pile a cette etape.`;
}

function buildBeginnerExplanation(traceData, stepIndex, model, instructionAnalysis) {
  const analysis = getAnalysis(traceData, stepIndex);
  const sections = [
    { label: 'Maintenant', text: buildCurrentMessage(instructionAnalysis, model) },
    { label: 'Pile', text: buildStackMessage(traceData, stepIndex, analysis, instructionAnalysis) },
    {
      label: String(traceData?.meta?.payload_label || (
        traceData?.meta?.payload_target === 'stdin'
          ? 'stdin'
          : traceData?.meta?.payload_target === 'both'
            ? 'stdin + argv[1]'
            : 'argv[1]'
      )),
      text: buildPayloadMessage(traceData, analysis, instructionAnalysis)
    }
  ];
  return {
    title: 'Explications',
    sections,
    bullets: sections.map((section) => `${section.label}: ${section.text}`)
  };
}

function buildMcpPayload(traceData, stepIndex, cachedModel = null) {
  const modelSummary = cachedModel || buildFunctionModel(traceData, chooseFocusFunction(traceData));
  const instructionAnalysis = buildInstructionAnalysis(traceData, stepIndex, modelSummary);
  const explanation = buildBeginnerExplanation(traceData, stepIndex, modelSummary, instructionAnalysis);
  return {
    stepIndex,
    modelSummary,
    instructionAnalysis,
    explanation
  };
}

module.exports = {
  buildBeginnerExplanation,
  buildFunctionModel,
  buildFunctionRangeIndex,
  buildInstructionAnalysis,
  buildMcpPayload,
  chooseFocusFunction,
  collectDisasmEntriesForFunction,
  displayFunctionName,
  extractInstrText,
  findPayloadSlots,
  normalizeFunctionName,
  sameFunction,
  slotHumanLabel,
  slotLooksLikePayload
};
