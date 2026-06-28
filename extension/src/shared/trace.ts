// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file trace.js
 * @brief Gestion des traces JSON (lecture, écriture, load).
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');
const { getTempDir, resolveProjectRoot } = require('./utils');

function parseNumericStep(value, fallback = null) {
  const num = Number(value);
  return Number.isFinite(num) && num > 0 ? Math.trunc(num) : fallback;
}

function parseHexAddress(value) {
  if (typeof value !== 'string') return null;
  const text = value.trim().toLowerCase();
  if (!text) return null;
  if (/^0x[0-9a-f]+$/i.test(text)) return text;
  if (/^[0-9a-f]+$/i.test(text)) return `0x${text}`;
  return null;
}

function parseBigIntAddress(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  if (value === null || value === undefined) return null;
  const text = parseHexAddress(String(value));
  if (!text) return null;
  try {
    return BigInt(text);
  } catch (_) {
    return null;
  }
}

function firstFrameSlotByRole(analysis, role) {
  const slots = Array.isArray(analysis?.frame?.slots) ? analysis.frame.slots : [];
  return slots.find((slot) => String(slot?.role || '').toLowerCase() === role) || null;
}

function slotOffsetLabel(slot) {
  return String(
    slot?.offsetFromBpHex
    || slot?.offset
    || slot?.offsetLabel
    || ''
  ).trim() || null;
}

function slotAddressLabel(slot) {
  return parseHexAddress(slot?.start || slot?.address || slot?.addr || '');
}

function readInstructionAddress(snapshot) {
  return parseHexAddress(snapshot?.rip || snapshot?.eip || '');
}

function traceProbableSource(trace) {
  const meta = trace?.meta && typeof trace.meta === 'object' ? trace.meta : {};
  const inputMode = String(meta?.input?.mode || '').trim().toLowerCase();
  if (inputMode === 'file') return 'file';
  const target = String(meta.payload_target || '').trim().toLowerCase();
  if (target === 'stdin') return 'stdin';
  if (target === 'both') return 'stdin + argv[1]';
  if (target === 'argv1') return 'argv[1]';
  return 'payload';
}

function firstWriteBytes(snapshot) {
  const writes = Array.isArray(snapshot?.memory?.writes) ? snapshot.memory.writes : [];
  return String(writes.find((entry) => String(entry?.bytes || '').trim())?.bytes || '').trim() || null;
}

function analysisWrites(analysis, snapshot = null) {
  const deltaWrites = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  if (deltaWrites.length > 0) return deltaWrites;
  return Array.isArray(snapshot?.memory?.writes) ? snapshot.memory.writes : [];
}

function analysisHasWrites(analysis, snapshot = null) {
  return analysisWrites(analysis, snapshot).length > 0;
}

function slotHasCurrentWriteSignal(slot, analysis, snapshot = null) {
  const flags = Array.isArray(slot?.flags) ? slot.flags : [];
  return Boolean(
    slot?.recentWrite
    || flags.includes('recent_write')
    || (analysisHasWrites(analysis, snapshot) && (slot?.changed || flags.includes('changed')))
  );
}

function writeCrossesBuffer(analysis, snapshot = null) {
  const bufferStart = parseBigIntAddress(analysis?.buffer?.start);
  const bufferEnd = parseBigIntAddress(analysis?.buffer?.end);
  if (bufferEnd === null) return false;
  return analysisWrites(analysis, snapshot).some((write) => {
    const addr = parseBigIntAddress(write?.addr);
    const rawSize = Number(write?.size);
    const size = BigInt(Number.isFinite(rawSize) && rawSize > 0 ? Math.trunc(rawSize) : 1);
    if (addr === null) return false;
    const end = addr + size;
    return addr < bufferEnd && end > bufferEnd && (bufferStart === null || end > bufferStart);
  });
}

function overflowHasRuntimeEvidence(analysis, snapshot = null) {
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  if (!overflow?.active) return false;
  const progress = Number(overflow.progressBytes);
  if (Number.isFinite(progress) && progress <= 0) return false;
  return writeCrossesBuffer(analysis, snapshot);
}

function overflowReaches(analysis, slotKind, snapshot = null) {
  if (!overflowHasRuntimeEvidence(analysis, snapshot)) return false;
  const reached = Array.isArray(analysis?.overflow?.reached) ? analysis.overflow.reached : [];
  return reached.includes(slotKind);
}

function buildSyntheticDiagnostic(trace, snapshot, analysis, step, kind) {
  const instructionAddress = readInstructionAddress(snapshot);
  const functionName = String(
    analysis?.function?.name
    || snapshot?.func
    || ''
  ).trim() || null;
  const probableSource = traceProbableSource(trace);
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  const bufferSlot = firstFrameSlotByRole(analysis, 'buffer');
  const savedBpSlot = firstFrameSlotByRole(analysis, 'saved_bp');
  const retSlot = firstFrameSlotByRole(analysis, 'return_address');
  const writesBytes = firstWriteBytes(snapshot);

  if (kind === 'buffer_overflow' && overflowHasRuntimeEvidence(analysis, snapshot)) {
    const reached = Array.isArray(overflow.reached) ? overflow.reached : [];
    const reachedLabel = reached.length
      ? reached.join(', ')
      : 'des zones adjacentes';
    return {
      severity: 'warning',
      kind,
      step,
      function: functionName,
      instructionAddress,
      responsibleInstructionAddress: instructionAddress,
      message: `Le debordement de ${overflow.bufferName || bufferSlot?.label || 'buffer'} atteint ${reachedLabel}`,
      slot: bufferSlot ? {
        kind: 'buffer',
        offset: slotOffsetLabel(bufferSlot),
        address: slotAddressLabel(bufferSlot)
      } : undefined,
      after: overflow.frontier || null,
      bytes: writesBytes || bufferSlot?.bytesHex || null,
      probableSource,
      confidence: 0.7
    };
  }

  if (
    kind === 'saved_bp_corrupted'
    && savedBpSlot
    && (slotHasCurrentWriteSignal(savedBpSlot, analysis, snapshot) || overflowReaches(analysis, 'saved_bp', snapshot))
  ) {
    return {
      severity: 'warning',
      kind,
      step,
      function: functionName,
      instructionAddress,
      responsibleInstructionAddress: instructionAddress,
      message: 'Le saved BP a ete ecrase par une ecriture hors limites',
      slot: {
        kind: 'saved_bp',
        offset: slotOffsetLabel(savedBpSlot),
        address: slotAddressLabel(savedBpSlot)
      },
      after: savedBpSlot.valueHex || savedBpSlot.valueDisplay || null,
      bytes: savedBpSlot.bytesHex || writesBytes || null,
      probableSource,
      confidence: 0.68
    };
  }

  if (
    kind === 'return_address_corrupted'
    && retSlot
    && (slotHasCurrentWriteSignal(retSlot, analysis, snapshot) || overflowReaches(analysis, 'return_address', snapshot))
  ) {
    return {
      severity: 'error',
      kind,
      step,
      function: functionName,
      instructionAddress,
      responsibleInstructionAddress: instructionAddress,
      message: "L'adresse de retour a ete ecrasee par le payload",
      slot: {
        kind: 'return_address',
        offset: slotOffsetLabel(retSlot),
        address: slotAddressLabel(retSlot)
      },
      after: retSlot.valueHex || retSlot.valueDisplay || null,
      bytes: retSlot.bytesHex || writesBytes || null,
      probableSource,
      confidence: 0.76
    };
  }

  return null;
}

function diagnosticKey(diagnostic) {
  const slot = diagnostic?.slot && typeof diagnostic.slot === 'object' ? diagnostic.slot : {};
  return [
    String(diagnostic?.step || ''),
    String(diagnostic?.kind || ''),
    String(diagnostic?.instructionAddress || ''),
    String(slot.address || ''),
    String(slot.kind || '')
  ].join('|');
}

function attachDiagnosticsToAnalysis(analysisByStep, diagnostics) {
  if (!analysisByStep || typeof analysisByStep !== 'object') return;
  diagnostics.forEach((diagnostic) => {
    const stepKey = String(diagnostic?.step || '');
    if (!stepKey || !analysisByStep[stepKey] || typeof analysisByStep[stepKey] !== 'object') return;
    const bucket = Array.isArray(analysisByStep[stepKey].diagnostics)
      ? analysisByStep[stepKey].diagnostics
      : [];
    if (!bucket.some((entry) => diagnosticKey(entry) === diagnosticKey(diagnostic))) {
      bucket.push(diagnostic);
    }
    analysisByStep[stepKey].diagnostics = bucket;
  });
}

function resetAnalysisDiagnostics(analysisByStep) {
  if (!analysisByStep || typeof analysisByStep !== 'object') return;
  Object.values(analysisByStep).forEach((analysis) => {
    if (analysis && typeof analysis === 'object' && 'diagnostics' in analysis) {
      delete analysis.diagnostics;
    }
  });
}

function keepExistingDiagnostic(trace, diagnostic) {
  const analysisByStep = trace?.analysisByStep && typeof trace.analysisByStep === 'object'
    ? trace.analysisByStep
    : {};
  const step = parseNumericStep(diagnostic?.step);
  const analysis = analysisByStep[String(step)];
  const snapshots = Array.isArray(trace?.snapshots) ? trace.snapshots : [];
  const snapshot = snapshots.find((entry, index) => parseNumericStep(entry?.step, index + 1) === step) || null;
  if (!analysis || typeof analysis !== 'object') return false;

  switch (String(diagnostic?.kind || '')) {
    case 'buffer_overflow':
      return overflowHasRuntimeEvidence(analysis, snapshot);
    case 'saved_bp_corrupted':
      return overflowReaches(analysis, 'saved_bp', snapshot)
        || slotHasCurrentWriteSignal(firstFrameSlotByRole(analysis, 'saved_bp'), analysis, snapshot);
    case 'return_address_corrupted':
      return overflowReaches(analysis, 'return_address', snapshot)
        || slotHasCurrentWriteSignal(firstFrameSlotByRole(analysis, 'return_address'), analysis, snapshot);
    default:
      return true;
  }
}

function ensureTraceDiagnostics(trace) {
  if (!trace || typeof trace !== 'object') return trace;
  const analysisByStep = trace.analysisByStep && typeof trace.analysisByStep === 'object'
    ? trace.analysisByStep
    : {};
  const existingTopLevel = Array.isArray(trace.diagnostics) ? trace.diagnostics : [];
  if (existingTopLevel.length > 0) {
    const filtered = existingTopLevel.filter((diagnostic) => keepExistingDiagnostic(trace, diagnostic));
    trace.diagnostics = filtered;
    resetAnalysisDiagnostics(analysisByStep);
    attachDiagnosticsToAnalysis(analysisByStep, filtered);
    return trace;
  }

  const snapshots = Array.isArray(trace.snapshots) ? trace.snapshots : [];
  const synthesized = [];
  const seen = new Set();

  snapshots.forEach((snapshot, index) => {
    const step = parseNumericStep(snapshot?.step, index + 1);
    const analysis = analysisByStep[String(step)];
    if (!analysis || typeof analysis !== 'object') return;

    const existingStepDiagnostics = Array.isArray(analysis.diagnostics) ? analysis.diagnostics : [];
    existingStepDiagnostics.forEach((diagnostic) => {
      const key = diagnosticKey(diagnostic);
      if (seen.has(key)) return;
      seen.add(key);
      synthesized.push(diagnostic);
    });
    if (existingStepDiagnostics.length > 0) return;

    [
      buildSyntheticDiagnostic(trace, snapshot, analysis, step, 'buffer_overflow'),
      buildSyntheticDiagnostic(trace, snapshot, analysis, step, 'saved_bp_corrupted'),
      buildSyntheticDiagnostic(trace, snapshot, analysis, step, 'return_address_corrupted')
    ].filter(Boolean).forEach((diagnostic) => {
      const key = diagnosticKey(diagnostic);
      if (seen.has(key)) return;
      seen.add(key);
      synthesized.push(diagnostic);
    });
  });

  trace.diagnostics = synthesized;
  resetAnalysisDiagnostics(analysisByStep);
  attachDiagnosticsToAnalysis(analysisByStep, synthesized);
  return trace;
}

function normalizeTraceData(data, jsonPath = '') {
  if (Array.isArray(data)) return { snapshots: data, risks: [], meta: {}, diagnostics: [] };
  if (!data || typeof data !== 'object') return { snapshots: [], risks: [], meta: {}, diagnostics: [] };

  const trace = { ...data };
  trace.snapshots = Array.isArray(trace.snapshots) ? trace.snapshots : [];
  trace.risks = Array.isArray(trace.risks) ? trace.risks : [];
  trace.meta = trace.meta && typeof trace.meta === 'object' ? trace.meta : {};
  trace.analysisByStep = trace.analysisByStep && typeof trace.analysisByStep === 'object'
    ? trace.analysisByStep
    : {};
  trace.diagnostics = Array.isArray(trace.diagnostics) ? trace.diagnostics : [];
  trace.crash = trace.crash && typeof trace.crash === 'object' ? trace.crash : null;

  if (!trace.meta.disasm_path && jsonPath && jsonPath.endsWith('.json')) {
    const candidate = jsonPath.slice(0, -5) + '.disasm.asm';
    if (fs.existsSync(candidate)) trace.meta.disasm_path = candidate;
  }

  ensureTraceDiagnostics(trace);
  return trace;
}

function resolveOutputJsonPath(storageDir?) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showErrorMessage('Aucun workspace ouvert.');
    return null;
  }
  const root = resolveProjectRoot(folders[0].uri.fsPath);
  const tempOutput = storageDir ? path.join(storageDir, 'output.json') : path.join(getTempDir(root), 'output.json');
  if (fs.existsSync(tempOutput)) return tempOutput;
  let current = root;
  for (let i = 0; i < 4; i += 1) {
    const candidate = path.join(current, 'output.json');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return tempOutput;
}

function loadTraceFromWorkspace() {
  const jsonPath = resolveOutputJsonPath();
  if (!jsonPath) return { snapshots: [], risks: [], meta: {} };
  if (!fs.existsSync(jsonPath)) {
    vscode.window.showErrorMessage(`output.json introuvable (${jsonPath}).`);
    return { snapshots: [], risks: [], meta: {} };
  }
  try {
    const raw = fs.readFileSync(jsonPath, 'utf8');
    const data = JSON.parse(raw);
    if (Array.isArray(data)) return normalizeTraceData(data, jsonPath);
    if (data && Array.isArray(data.snapshots)) return normalizeTraceData(data, jsonPath);
    vscode.window.showErrorMessage('output.json doit contenir { snapshots, risks }.');
    return { snapshots: [], risks: [], meta: {} };
  } catch (err) {
    vscode.window.showErrorMessage('Erreur lecture output.json.');
    return { snapshots: [], risks: [], meta: {} };
  }
}

function readTraceJson(jsonPath) {
  const raw = fs.readFileSync(jsonPath, 'utf8');
  const data = JSON.parse(raw);
  return normalizeTraceData(data, jsonPath);
}

function writeTraceJson(jsonPath, trace) {
  fs.writeFileSync(jsonPath, JSON.stringify(trace, null, 2), 'utf8');
}

function setViewMode(trace, mode) {
  if (!trace.meta || typeof trace.meta !== 'object') trace.meta = {};
  trace.meta.view_mode = mode;
  return trace;
}

module.exports = {
  resolveOutputJsonPath,
  loadTraceFromWorkspace,
  readTraceJson,
  writeTraceJson,
  setViewMode,
  ensureTraceDiagnostics
};
