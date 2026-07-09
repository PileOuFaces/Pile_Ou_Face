/**
 * @file diagnostics.js
 * @brief Helpers purs pour filtrer et projeter les diagnostics runtime.
 */

const SEVERITY_RANK = {
  success: -1,
  error: 0,
  warning: 1,
  info: 2
};

const KIND_REGISTERS = {
  return_address_corrupted: ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp'],
  saved_bp_corrupted: ['rbp', 'ebp'],
  invalid_control_flow: ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp'],
  fatal_crash: ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp'],
  control_hijack: ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp'],
  ret2win_success: ['rip', 'eip'],
  runtime_crash: ['rip', 'eip', 'rsp', 'esp', 'rbp', 'ebp']
};

const CRASH_KINDS = new Set([
  'runtime_crash',
  'invalid_control_flow',
  'fatal_crash',
  'control_hijack',
  'ret2win_success'
]);

export function diagnosticsForStep(diagnostics, step) {
  const wanted = Number(step);
  return (Array.isArray(diagnostics) ? diagnostics : [])
    .filter((diagnostic) => Number(diagnostic?.step) === wanted)
    .sort(compareDiagnostics);
}

export function crashDiagnosticForStep(crash, step) {
  if (!crash || typeof crash !== 'object') return null;
  const crashStep = Number(crash.step);
  if (!Number.isFinite(crashStep) || crashStep !== Number(step)) return null;
  const instructionText = String(crash.instructionText || '').trim().toLowerCase();
  const crashType = String(crash.type || '').trim().toLowerCase();
  const classification = String(crash.classification || '').trim().toLowerCase();

  let kind, severity, confidence;
  if (classification === 'ret2win_success') {
    kind = 'ret2win_success';
    severity = 'success';
    confidence = 0.99;
  } else if (classification === 'control_hijack') {
    kind = 'control_hijack';
    severity = 'warning';
    confidence = 0.92;
  } else if (classification === 'fatal_crash') {
    kind = 'fatal_crash';
    severity = 'error';
    confidence = 0.96;
  } else if (classification === 'benign_termination' || classification === 'emulator_stop') {
    // Backend already proved there is no corruption evidence (no overflow
    // reaching a control slot, no flagged write, no payload match) for this
    // crash -- never reclassify it as fatal_crash from raw instruction/type
    // heuristics below.
    kind = classification;
    severity = 'info';
    confidence = 0.5;
  } else {
    kind = crashType === 'unmapped_fetch'
      || instructionText.startsWith('ret')
      || instructionText.startsWith('jmp')
      || instructionText.startsWith('call')
      ? 'fatal_crash'
      : 'runtime_crash';
    severity = 'error';
    confidence = kind === 'fatal_crash' ? 0.96 : 0.88;
  }

  const afterValue = (classification === 'ret2win_success' || classification === 'control_hijack')
    ? (crash.retTarget || crash.memoryAddress || crash.rip || crash.eip || null)
    : (crash.memoryAddress || crash.rip || crash.eip || null);

  return {
    severity,
    kind,
    classification: classification || null,
    step: crashStep,
    function: crash.function || null,
    instructionAddress: crash.instructionAddress || null,
    responsibleInstructionAddress: crash.instructionAddress || null,
    message: crash.reason || 'Crash runtime.',
    slot: crash.suspectOverwrittenSlot || null,
    before: null,
    after: afterValue,
    bytes: crash.suspectBytes || '',
    probableSource: crash.probableSource || null,
    payloadOffset: crash.payloadOffset,
    confidence,
    registers: crash.registers && typeof crash.registers === 'object' ? crash.registers : {},
    crashType: crashType || null,
    retTarget: crash.retTarget || null,
  };
}

export function mergeCrashDiagnostic(diagnostics, crash, step) {
  const raw = Array.isArray(diagnostics) ? diagnostics : [];
  const current = raw.some((diagnostic) => diagnostic?.step !== undefined && Number(diagnostic.step) !== Number(step))
    ? diagnosticsForStep(raw, step)
    : [...raw].sort(compareDiagnostics);
  const crashDiagnostic = crashDiagnosticForStep(crash, step);
  if (!crashDiagnostic) return current;
  const crashAddress = parseAddress(crashDiagnostic.instructionAddress);
  const alreadyPresent = current.some((diagnostic) => {
    const sameAddress = crashAddress !== null
      && parseAddress(diagnostic?.instructionAddress) === crashAddress;
    return sameAddress && ['runtime_crash', 'invalid_control_flow', 'ret2win_success', 'control_hijack', 'fatal_crash'].includes(String(diagnostic?.kind || ''));
  });
  return (alreadyPresent ? current : [crashDiagnostic, ...current]).sort(compareDiagnostics);
}

export function persistentCrashDiagnostics(crash, diagnostics = []) {
  if (!crash || typeof crash !== 'object') return [];
  const items = [];
  const crashStep = Number(crash.step);
  const crashDiagnostic = Number.isFinite(crashStep)
    ? crashDiagnosticForStep(crash, crashStep)
    : null;
  if (crashDiagnostic) items.push(crashDiagnostic);

  (Array.isArray(diagnostics) ? diagnostics : []).forEach((diagnostic) => {
    const kind = String(diagnostic?.kind || '');
    const stepMatchesCrash = Number.isFinite(crashStep) && Number(diagnostic?.step) === crashStep;
    const hasAsmAddress = parseAddress(diagnostic?.instructionAddress) !== null
      || parseAddress(diagnostic?.responsibleInstructionAddress) !== null;
    if (hasAsmAddress && (stepMatchesCrash || CRASH_KINDS.has(kind))) {
      items.push(diagnostic);
    }
  });

  const seen = new Set();
  return items.filter((diagnostic) => {
    const key = [
      String(diagnostic?.kind || ''),
      String(diagnostic?.step || ''),
      String(diagnostic?.instructionAddress || ''),
      String(diagnostic?.responsibleInstructionAddress || '')
    ].join('|');
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).sort(compareDiagnostics);
}

export function primaryDiagnostic(diagnostics) {
  const items = Array.isArray(diagnostics) ? diagnostics : [];
  return [...items].sort(compareDiagnostics)[0] || null;
}

export function compareDiagnostics(left, right) {
  const leftRank = SEVERITY_RANK[String(left?.severity || 'info')] ?? 9;
  const rightRank = SEVERITY_RANK[String(right?.severity || 'info')] ?? 9;
  if (leftRank !== rightRank) return leftRank - rightRank;
  return Number(right?.confidence || 0) - Number(left?.confidence || 0);
}

export function diagnosticMatchesAddress(diagnostic, address, field = 'any') {
  const target = parseAddress(address);
  if (target === null || !diagnostic) return false;
  const fields = field === 'any'
    ? ['instructionAddress', 'responsibleInstructionAddress']
    : [field];
  return fields.some((name) => parseAddress(diagnostic?.[name]) === target);
}

export function diagnosticsForStackSlot(diagnostics, slot) {
  const address = parseAddress(slot?.address || slot?.addressLabel || slot?.start);
  const kind = normalizeKind(slot?.kind || slot?.semanticRole || slot?.rawRole);
  return (Array.isArray(diagnostics) ? diagnostics : []).filter((diagnostic) => {
    const diagSlot = diagnostic?.slot && typeof diagnostic.slot === 'object' ? diagnostic.slot : {};
    const diagAddress = parseAddress(diagSlot.address);
    const diagKind = normalizeKind(diagSlot.kind);
    if (address !== null && diagAddress !== null && address === diagAddress) return true;
    return Boolean(kind && diagKind && kind === diagKind);
  }).sort(compareDiagnostics);
}

export function diagnosticRegisters(diagnostics) {
  const out = new Map();
  (Array.isArray(diagnostics) ? diagnostics : []).forEach((diagnostic) => {
    const kind = String(diagnostic?.kind || '');
    const explicit = diagnostic?.registers && typeof diagnostic.registers === 'object'
      ? Object.keys(diagnostic.registers)
      : [];
    [...(KIND_REGISTERS[kind] || []), ...explicit].forEach((name) => {
      const key = String(name || '').trim().toLowerCase();
      if (!key) return;
      const previous = out.get(key);
      if (!previous || compareDiagnostics(diagnostic, previous) < 0) {
        out.set(key, diagnostic);
      }
    });
  });
  return out;
}

export function diagnosticKindLabel(kind) {
  switch (String(kind || '')) {
    case 'return_address_corrupted':
      return 'Adresse de retour corrompue';
    case 'saved_bp_corrupted':
      return 'Saved BP corrompu';
    case 'buffer_overflow':
      return 'Debordement de buffer';
    case 'invalid_control_flow':
      return 'Flux de controle invalide';
    case 'fatal_crash':
      return 'Crash fatal';
    case 'control_hijack':
      return 'Detournement de flot de controle';
    case 'ret2win_success':
      return 'Acces a la fonction cible';
    case 'runtime_crash':
      return 'Crash runtime';
    case 'benign_termination':
      return "Fin d'execution normale";
    case 'emulator_stop':
      return "Limite de l'emulateur";
    case 'max_steps_reached':
      return "Limite de pas d'execution atteinte";
    default:
      return 'Diagnostic runtime';
  }
}

export function parseAddress(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
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

function normalizeKind(kind) {
  const raw = String(kind || '').trim().toLowerCase();
  if (raw === 'ret' || raw === 'return_address') return 'return_address';
  if (raw === 'saved_bp' || raw === 'control') return 'saved_bp';
  return raw;
}
