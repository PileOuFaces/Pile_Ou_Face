import {
  addressesEqual,
  cleanValue,
  hasCorruptionSignal,
  normalizeEntryKind,
  parseBigIntAddr,
  readPositiveInt,
  resolveSourcePriority,
  uniqueStrings
} from './stackWorkspaceUtils.js';

// Corruption of a control slot (saved_bp / return_address) is decided
// EXCLUSIVELY by the backend (return_address_corrupted / saved_bp_corrupted
// / control_hijack / fatal_crash diagnostics, gated on real crossing-write
// evidence -- see diagnostics.py::_overflow_has_runtime_evidence). This
// function must never emit a corruption verdict itself: it only surfaces a
// non-authoritative "suspect" signal (a write/change was observed on this
// slot's memory this step) for informative display. The only place allowed
// to promote a slot to CORROMPU is annotateEntriesWithDiagnostics below,
// from an actual backend diagnostic.
export function validateReturnAddressIntegrity({ kind, start, size, observations } = {}) {
  if (normalizeEntryKind(kind) !== 'return_address') {
    return { suspect: false, exactObservation: null };
  }
  const slotAddress = parseBigIntAddr(start);
  const width = readPositiveInt(size);
  if (slotAddress === null || width === null) {
    return { suspect: false, exactObservation: null };
  }

  const exactObservation = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => addressesEqual(item?.start, slotAddress) && readPositiveInt(item?.size) === width)
    .sort((left, right) => resolveSourcePriority(right?.source) - resolveSourcePriority(left?.source))[0] ?? null;

  if (!exactObservation) {
    return { suspect: false, exactObservation: null };
  }

  return {
    suspect: hasCorruptionSignal([exactObservation]),
    exactObservation
  };
}

// Non-verdict, informative badges only. CORROMPU is never added here --
// see annotateEntriesWithDiagnostics, the sole source of truth for control
// slot corruption.
export function buildEntryBadges(entry) {
  const badges = [];
  if (Array.isArray(entry?.flags) && entry.flags.includes('changed')) badges.push('CHANGED');
  else if (Array.isArray(entry?.flags) && entry.flags.includes('recent_write')) badges.push('WRITE');
  else if (Array.isArray(entry?.flags) && entry.flags.includes('recent_read')) badges.push('READ');
  if (normalizeEntryKind(entry?.kind) === 'return_address') badges.push('RET');
  return uniqueStrings(badges).slice(0, 2);
}

export function annotateEntriesWithDiagnostics(entries, diagnostics = []) {
  const safeDiagnostics = Array.isArray(diagnostics) ? diagnostics : [];
  if (!safeDiagnostics.length) return Array.isArray(entries) ? entries : [];

  return (Array.isArray(entries) ? entries : []).map((entry) => {
    const matches = safeDiagnostics
      .filter((diagnostic) => diagnosticMatchesEntry(diagnostic, entry))
      .sort(compareDiagnostics);
    if (!matches.length) return entry;

    const primary = matches[0];
    const primarySlotKind = normalizeEntryKind(primary?.slot?.kind);
    const isCorrupted = primary.kind === 'return_address_corrupted'
      || primary.kind === 'saved_bp_corrupted'
      || (primary.kind === 'runtime_crash' && (primarySlotKind === 'return_address' || primarySlotKind === 'saved_bp'))
      || (['invalid_control_flow', 'fatal_crash', 'control_hijack'].includes(primary.kind) && primarySlotKind === 'return_address');
    const hasOverflow = matches.some((diagnostic) => diagnostic?.kind === 'buffer_overflow');
    const rows = Array.isArray(entry?.detailPayload?.rows)
      ? entry.detailPayload.rows.map((row) => ({ ...row }))
      : [];

    upsertDiagnosticRow(rows, 'Diagnostic', diagnosticKindLabel(primary.kind));
    if (primary.message) upsertDiagnosticRow(rows, 'Cause probable', primary.message);
    if (primary.before) upsertDiagnosticRow(rows, 'Valeur attendue', primary.before);
    if (primary.after) upsertDiagnosticRow(rows, 'Valeur actuelle', primary.after);
    if (primary.bytes) upsertDiagnosticRow(rows, 'Bytes', primary.bytes);
    if (primary.probableSource) upsertDiagnosticRow(rows, 'Source probable', primary.probableSource);
    if (Number.isFinite(Number(primary.payloadOffset))) {
      upsertDiagnosticRow(rows, 'Offset payload', String(primary.payloadOffset));
    }

    const badges = uniqueStrings([
      isCorrupted ? 'CORROMPU' : hasOverflow ? 'OVERFLOW' : '',
      ...(Array.isArray(entry?.badges) ? entry.badges : [])
    ]).slice(0, 3);

    return {
      ...entry,
      diagnostic: primary,
      diagnostics: matches,
      diagnosticSeverity: primary.severity || 'warning',
      diagnosticCorrupted: isCorrupted,
      isSensitive: Boolean(entry?.isSensitive || isCorrupted),
      badges,
      detailPayload: {
        ...(entry?.detailPayload || {}),
        rows
      }
    };
  });
}

export function diagnosticMatchesEntry(diagnostic, entry) {
  if (!diagnostic || !entry) return false;
  const diagSlot = diagnostic.slot && typeof diagnostic.slot === 'object' ? diagnostic.slot : {};
  const diagAddress = parseBigIntAddr(diagSlot.address);
  const entryAddress = parseBigIntAddr(entry.address);
  if (diagAddress !== null && entryAddress !== null && diagAddress === entryAddress) return true;
  const diagKind = normalizeEntryKind(diagSlot.kind);
  const entryKind = normalizeEntryKind(entry.kind);
  return Boolean(diagKind && entryKind && diagKind === entryKind);
}

export function compareDiagnostics(left, right) {
  const leftRank = diagnosticSeverityRank(left?.severity);
  const rightRank = diagnosticSeverityRank(right?.severity);
  if (leftRank !== rightRank) return leftRank - rightRank;
  return Number(right?.confidence || 0) - Number(left?.confidence || 0);
}

export function diagnosticSeverityRank(severity) {
  switch (String(severity || 'info')) {
    case 'success':
      return -1;
    case 'error':
      return 0;
    case 'warning':
      return 1;
    default:
      return 2;
  }
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
    default:
      return 'Diagnostic runtime';
  }
}

export function upsertDiagnosticRow(rows, label, value) {
  if (!Array.isArray(rows)) return;
  const cleanValue = String(value || '').trim();
  if (!cleanValue) return;
  const normalizedLabel = String(label || '').trim().toLowerCase();
  const index = rows.findIndex((row) => String(row?.label || '').trim().toLowerCase() === normalizedLabel);
  if (index >= 0) {
    rows[index] = { label, value: cleanValue };
    return;
  }
  rows.push({ label, value: cleanValue });
}

export function buildCommentHints({ kind, probableBuffer } = {}) {
  const hints = [];
  if (normalizeEntryKind(kind) === 'local' && probableBuffer) {
    hints.push('probable buffer');
  }
  return hints;
}
