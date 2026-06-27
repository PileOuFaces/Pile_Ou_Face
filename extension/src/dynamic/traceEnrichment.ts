// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file traceEnrichment.js
 * @brief Enrichissement statique minimal des adresses runtime.
 */

function parseAddress(value) {
  if (typeof value === 'bigint') return value >= 0n ? value : null;
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || value < 0) return null;
    return BigInt(Math.trunc(value));
  }
  if (typeof value !== 'string') return null;
  const text = value.trim().toLowerCase();
  if (!text) return null;
  try {
    if (text.startsWith('0x')) return BigInt(text);
    if (/^[0-9a-f]+$/i.test(text)) return BigInt(`0x${text}`);
    if (/^\d+$/.test(text)) return BigInt(text);
  } catch (_) {
    return null;
  }
  return null;
}

function formatAddress(value) {
  const addr = parseAddress(value);
  return addr === null ? null : `0x${addr.toString(16)}`;
}

function toSafeNumber(value) {
  if (typeof value !== 'bigint') return null;
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

function cleanName(name) {
  return String(name || '').trim();
}

function displayFunctionName(name) {
  const raw = cleanName(name);
  if (!raw) return '';
  const stripped = raw.replace(/@.*/, '').replace(/<|>/g, '');
  return stripped.startsWith('_') && stripped.length > 1 ? stripped.slice(1) : stripped;
}

const DANGEROUS_DESTINATION_CALLS = [
  'strcpy',
  'strncpy',
  'gets',
  'fgets',
  'memcpy',
  'memmove',
  'scanf',
  '__isoc99_scanf',
  '__isoc23_scanf',
  'sscanf',
  'sprintf',
  'snprintf',
  'strcat',
  'read'
];

const REGISTER_ALIASES = new Map([
  ['eax', 'rax'], ['ax', 'rax'], ['al', 'rax'],
  ['ebx', 'rbx'], ['bx', 'rbx'], ['bl', 'rbx'],
  ['ecx', 'rcx'], ['cx', 'rcx'], ['cl', 'rcx'],
  ['edx', 'rdx'], ['dx', 'rdx'], ['dl', 'rdx'],
  ['edi', 'rdi'], ['di', 'rdi'], ['dil', 'rdi'],
  ['esi', 'rsi'], ['si', 'rsi'], ['sil', 'rsi'],
  ['ebp', 'rbp'], ['bp', 'rbp'], ['bpl', 'rbp'],
  ['esp', 'rsp'], ['sp', 'rsp'], ['spl', 'rsp'],
  ['r8d', 'r8'], ['r8w', 'r8'], ['r8b', 'r8'],
  ['r9d', 'r9'], ['r9w', 'r9'], ['r9b', 'r9'],
  ['r10d', 'r10'], ['r10w', 'r10'], ['r10b', 'r10'],
  ['r11d', 'r11'], ['r11w', 'r11'], ['r11b', 'r11'],
  ['r12d', 'r12'], ['r12w', 'r12'], ['r12b', 'r12'],
  ['r13d', 'r13'], ['r13w', 'r13'], ['r13b', 'r13'],
  ['r14d', 'r14'], ['r14w', 'r14'], ['r14b', 'r14'],
  ['r15d', 'r15'], ['r15w', 'r15'], ['r15b', 'r15']
]);

function normalizeFunctionNameForCompare(name) {
  return displayFunctionName(name).replace(/^_+/, '').toLowerCase();
}

function canonicalRegister(registerName) {
  const raw = String(registerName || '').trim().toLowerCase().replace(/^%/, '');
  return REGISTER_ALIASES.get(raw) || raw;
}

function parseSignedImmediate(raw) {
  const text = String(raw || '').replace(/\s+/g, '').toLowerCase();
  if (!text) return null;
  const sign = text.startsWith('-') ? -1 : 1;
  const unsigned = text.replace(/^[+-]/, '');
  if (!unsigned) return null;
  if (/^0x[0-9a-f]+$/.test(unsigned)) return sign * Number.parseInt(unsigned.slice(2), 16);
  if (/^\d+$/.test(unsigned)) return sign * Number.parseInt(unsigned, 10);
  return null;
}

function splitOperands(operands) {
  const parts = [];
  let current = '';
  let bracketDepth = 0;
  String(operands || '').split('').forEach((char) => {
    if (char === '[') bracketDepth += 1;
    if (char === ']') bracketDepth = Math.max(0, bracketDepth - 1);
    if (char === ',' && bracketDepth === 0) {
      if (current.trim()) parts.push(current.trim());
      current = '';
      return;
    }
    current += char;
  });
  if (current.trim()) parts.push(current.trim());
  return parts;
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

function readDisasmAddress(entry) {
  return parseAddress(entry?.addr ?? entry?.address ?? entry?.ip ?? entry?.offset);
}

function parseStackAddressOperand(operand) {
  const text = String(operand || '').toLowerCase();
  const match = text.match(/\[\s*((?:r|e)bp)\s*([+-]\s*(?:0x[0-9a-f]+|\d+))?/i);
  if (!match) return null;
  const base = canonicalRegister(match[1]);
  const offset = parseSignedImmediate(match[2] || '0');
  if (offset === null) return null;
  return { base, offset };
}

function parseStackAddressAssignment(instr) {
  const match = String(instr || '').trim().match(/^(lea|mov(?:abs|zx|sx|sxd)?)\s+(.+)$/i);
  if (!match) return null;
  const mnemonic = String(match[1] || '').toLowerCase();
  const operands = splitOperands(match[2]);
  if (operands.length < 2) return null;
  const destination = canonicalRegister(operands[0]);
  if (!destination || destination.includes('[')) return null;

  if (mnemonic.startsWith('lea')) {
    const stackAddress = parseStackAddressOperand(operands[1]);
    return stackAddress ? { destination, stackAddress } : null;
  }

  const sourceRegister = canonicalRegister(operands[1]);
  const stackAddress = parseStackAddressOperand(operands[1]);
  return { destination, sourceRegister, stackAddress };
}

function detectDangerousCall(instr) {
  const text = String(instr || '').trim().toLowerCase();
  const match = text.match(/^callq?\s+(.+)$/i);
  if (!match) return null;
  const target = String(match[1] || '').replace(/[<>]/g, ' ').toLowerCase();
  return DANGEROUS_DESTINATION_CALLS.find((name) => {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return new RegExp(`(^|[^a-z0-9_])${escaped}(@|$|[^a-z0-9_])`, 'i').test(target);
  }) || null;
}

function destinationRegisterForCall(callName) {
  const normalized = String(callName || '').toLowerCase();
  if (normalized === 'read') return 'rsi';
  if (normalized.includes('scanf')) return 'rsi';
  if (normalized === 'fgets') return 'rdi';
  return 'rdi';
}

function formatStackOffset(base, offset) {
  const safeOffset = Number(offset);
  const register = canonicalRegister(base) || 'rbp';
  if (!Number.isFinite(safeOffset) || safeOffset === 0) return register;
  const sign = safeOffset < 0 ? '-' : '+';
  return `${register}${sign}0x${Math.abs(safeOffset).toString(16)}`;
}

function buildBufferHint({ stackAddress, functionName, callName, callAddress }) {
  if (!stackAddress || !Number.isFinite(stackAddress.offset)) return null;
  return {
    kind: 'buffer',
    label: 'buffer',
    function: functionName || '',
    base: stackAddress.base || 'rbp',
    offset: stackAddress.offset,
    offsetLabel: formatStackOffset(stackAddress.base || 'rbp', stackAddress.offset),
    call: callName || '',
    callAddress: formatAddress(callAddress),
    source: 'static',
    confidence: 'high'
  };
}

function readSnapshotIp(snapshot) {
  const direct = parseAddress(snapshot?.rip ?? snapshot?.eip ?? snapshot?.ip);
  if (direct !== null) return direct;
  const instrAddr = parseAddress(snapshot?.instruction?.address);
  if (instrAddr !== null) return instrAddr;
  const registers = Array.isArray(snapshot?.registers)
    ? snapshot.registers
    : Array.isArray(snapshot?.regs)
    ? snapshot.regs
    : [];
  const ipRegister = registers.find((entry) => {
    const name = String(entry?.name || '').trim().toLowerCase();
    return name === 'rip' || name === 'eip' || name === 'ip';
  });
  return parseAddress(ipRegister?.value);
}

function addRange(ranges, entry, source = 'static') {
  const name = cleanName(entry?.name || entry?.functionName || entry?.function_name || entry?.symbol || '');
  const start = parseAddress(entry?.range_start ?? entry?.start ?? entry?.addr ?? entry?.address);
  if (!name || start === null) return;
  let end = parseAddress(entry?.range_end ?? entry?.end ?? entry?.end_addr);
  const size = parseAddress(entry?.size);
  if (end === null && size !== null && size > 0n) end = start + size;
  ranges.push({
    name: displayFunctionName(name) || name,
    rawName: name,
    start,
    end,
    source
  });
}

function buildFunctionRanges(trace, symbols = []) {
  const ranges = [];
  const analysisByStep = trace?.analysisByStep && typeof trace.analysisByStep === 'object'
    ? trace.analysisByStep
    : {};
  Object.values(analysisByStep).forEach((analysis) => {
    const fn = analysis?.function && typeof analysis.function === 'object' ? analysis.function : null;
    if (fn) addRange(ranges, fn, 'analysis');
  });

  const metaFunctions = Array.isArray(trace?.meta?.functions) ? trace.meta.functions : [];
  metaFunctions.forEach((entry) => addRange(ranges, entry, 'meta'));

  symbols
    .filter((symbol) => /^(t|T|W)$/i.test(String(symbol?.type || '')))
    .forEach((symbol) => addRange(ranges, symbol, 'symbol'));

  const seen = new Set();
  return ranges
    .filter((range) => range.start !== null)
    .sort((left, right) => {
      if (left.start < right.start) return -1;
      if (left.start > right.start) return 1;
      const leftSize = left.end !== null ? left.end - left.start : 0n;
      const rightSize = right.end !== null ? right.end - right.start : 0n;
      return leftSize > rightSize ? -1 : leftSize < rightSize ? 1 : 0;
    })
    .filter((range) => {
      const key = `${range.name}:${range.start.toString(16)}:${range.end ? range.end.toString(16) : ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
}

function buildExactSymbolMap(symbols = []) {
  const exact = new Map();
  symbols.forEach((symbol) => {
    const addr = parseAddress(symbol?.addr ?? symbol?.address);
    const name = cleanName(symbol?.name);
    if (addr === null || addr === 0n || !name) return;
    exact.set(addr.toString(16), name);
  });
  return exact;
}

function findFunctionRange(ranges, addr) {
  let best = null;
  ranges.forEach((range) => {
    if (addr < range.start) return;
    if (range.end !== null && addr >= range.end) return;
    if (range.end === null && addr !== range.start) return;
    if (!best || range.start > best.start) best = range;
  });
  return best;
}

function lookupRuntimeAddress(address, { symbols = [], functionRanges = null } = {}) {
  const rip = parseAddress(address);
  if (rip === null) return null;

  const ranges = functionRanges || buildFunctionRanges({}, symbols);
  const exactSymbols = buildExactSymbolMap(symbols);
  const symbol = exactSymbols.get(rip.toString(16)) || null;
  const range = findFunctionRange(ranges, rip);
  const offset = range ? rip - range.start : null;

  const result = { rip: formatAddress(rip) };
  if (range?.name) result.functionName = range.name;
  if (offset !== null) {
    const safeOffset = toSafeNumber(offset);
    if (safeOffset !== null) result.functionOffset = safeOffset;
  }
  if (symbol) result.symbol = symbol;
  if (!result.functionName && symbol) {
    result.functionName = displayFunctionName(symbol) || symbol;
    result.functionOffset = 0;
  }
  return Object.keys(result).length > 1 ? result : result;
}

function detectDangerousLocalBufferHints(trace, { functionRanges = null } = {}) {
  const disasm = Array.isArray(trace?.meta?.disasm) ? trace.meta.disasm : [];
  if (!disasm.length) return [];
  const ranges = functionRanges || buildFunctionRanges(trace, []);
  const sorted = disasm
    .map((entry, index) => ({ entry, index, addr: readDisasmAddress(entry), instr: extractInstrText(entry) }))
    .filter((item) => item.instr)
    .sort((left, right) => {
      if (left.addr !== null && right.addr !== null && left.addr !== right.addr) {
        return left.addr < right.addr ? -1 : 1;
      }
      return left.index - right.index;
    });

  const hints = [];
  const seen = new Set();
  const registerStackTargets = new Map();
  let activeFunctionKey = '';
  let activeFunctionName = '';

  sorted.forEach((item) => {
    const range = item.addr !== null ? findFunctionRange(ranges, item.addr) : null;
    const functionName = displayFunctionName(range?.name || item.entry?.functionName || item.entry?.function || activeFunctionName);
    const functionKey = normalizeFunctionNameForCompare(functionName);
    if (functionKey && functionKey !== activeFunctionKey) {
      registerStackTargets.clear();
      activeFunctionKey = functionKey;
      activeFunctionName = functionName;
    }

    const assignment = parseStackAddressAssignment(item.instr);
    if (assignment) {
      if (assignment.stackAddress) {
        registerStackTargets.set(assignment.destination, assignment.stackAddress);
      } else if (assignment.sourceRegister && registerStackTargets.has(assignment.sourceRegister)) {
        registerStackTargets.set(assignment.destination, registerStackTargets.get(assignment.sourceRegister));
      } else {
        registerStackTargets.delete(assignment.destination);
      }
    }

    const callName = detectDangerousCall(item.instr);
    if (!callName) return;
    const destinationRegister = destinationRegisterForCall(callName);
    const stackAddress = registerStackTargets.get(destinationRegister);
    const hint = buildBufferHint({
      stackAddress,
      functionName: functionName || activeFunctionName,
      callName,
      callAddress: item.addr
    });
    if (!hint) return;
    const key = [
      normalizeFunctionNameForCompare(hint.function),
      hint.base,
      hint.offset,
      hint.call,
      hint.callAddress || ''
    ].join(':');
    if (seen.has(key)) return;
    seen.add(key);
    hints.push(hint);
  });

  return hints;
}

function buildTraceAddressEnrichment(trace, { symbols = [] } = {}) {
  const snapshots = Array.isArray(trace?.snapshots) ? trace.snapshots : [];
  const functionRanges = buildFunctionRanges(trace, symbols);
  const stackHints = detectDangerousLocalBufferHints(trace, { functionRanges });
  const byStep = {};

  snapshots.forEach((snapshot, index) => {
    const step = Number(snapshot?.step) || index + 1;
    const ip = readSnapshotIp(snapshot);
    const entry = lookupRuntimeAddress(ip, { symbols, functionRanges });
    if (!entry) return;
    const currentFunction = entry.functionName || findFunctionRange(functionRanges, ip)?.name || snapshot?.func || '';
    const matchingStackHints = stackHints.filter((hint) => {
      const hintFunction = normalizeFunctionNameForCompare(hint.function);
      const stepFunction = normalizeFunctionNameForCompare(currentFunction);
      return hintFunction && stepFunction && hintFunction === stepFunction;
    });
    if (matchingStackHints.length) entry.stackHints = matchingStackHints;
    byStep[String(step)] = entry;
  });

  return { byStep, stackHints };
}

function attachTraceAddressEnrichment(trace, options = {}) {
  if (!trace || typeof trace !== 'object') return trace;
  const addressEnrichment = buildTraceAddressEnrichment(trace, options);
  trace.enrichment = trace.enrichment && typeof trace.enrichment === 'object'
    ? trace.enrichment
    : {};
  trace.enrichment.byStep = {
    ...(trace.enrichment.byStep && typeof trace.enrichment.byStep === 'object' ? trace.enrichment.byStep : {}),
    ...addressEnrichment.byStep
  };
  if (Array.isArray(addressEnrichment.stackHints) && addressEnrichment.stackHints.length) {
    trace.enrichment.stackHints = addressEnrichment.stackHints;
  }
  return trace;
}

module.exports = {
  parseAddress,
  formatAddress,
  readSnapshotIp,
  buildFunctionRanges,
  lookupRuntimeAddress,
  detectDangerousLocalBufferHints,
  buildTraceAddressEnrichment,
  attachTraceAddressEnrichment
};
