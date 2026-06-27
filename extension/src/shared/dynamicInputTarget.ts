// SPDX-License-Identifier: AGPL-3.0-only
const VALID_EFFECTIVE_TARGETS = new Set(['argv1', 'stdin', 'both']);
const VALID_TARGET_MODES = new Set(['auto', 'argv1', 'stdin', 'both']);

function normalizePayloadTargetMode(value, fallback = 'auto') {
  const normalized = String(value || '').trim().toLowerCase();
  if (VALID_TARGET_MODES.has(normalized)) return normalized;
  return VALID_TARGET_MODES.has(fallback) ? fallback : 'auto';
}

function normalizeEffectivePayloadTarget(value, fallback = 'argv1') {
  const normalized = String(value || '').trim().toLowerCase();
  if (VALID_EFFECTIVE_TARGETS.has(normalized)) return normalized;
  return VALID_EFFECTIVE_TARGETS.has(fallback) ? fallback : 'argv1';
}

function payloadTargetLabel(target) {
  const normalized = normalizeEffectivePayloadTarget(target);
  if (normalized === 'stdin') return 'stdin';
  if (normalized === 'both') return 'stdin + argv[1]';
  return 'argv[1]';
}

function stripSourceNoise(sourceText) {
  return String(sourceText || '')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/\/\/[^\r\n]*/g, ' ')
    .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, ' ');
}

function detectPayloadTargetFromSourceText(sourceText) {
  const source = stripSourceNoise(sourceText);
  const stdinEvidence = [];
  const argvEvidence = [];

  const addIf = (regex, target, label) => {
    if (regex.test(source)) target.push(label);
  };

  addIf(/\bargv\s*\[\s*1\s*\]/i, argvEvidence, 'argv[1]');

  addIf(/\bfgets\s*\([^;]{0,180}\bstdin\b/i, stdinEvidence, 'fgets');
  addIf(/(?:^|[^a-zA-Z0-9_])gets\s*\(/i, stdinEvidence, 'gets');
  addIf(/(?:^|[^a-zA-Z0-9_])scanf\s*\(/i, stdinEvidence, 'scanf');
  addIf(/\bfscanf\s*\(\s*stdin\b/i, stdinEvidence, 'fscanf');
  addIf(/\bgetc\s*\(\s*stdin\s*\)/i, stdinEvidence, 'getc');
  addIf(/\bgetchar\s*\(/i, stdinEvidence, 'getchar');
  addIf(/\bread\s*\(\s*(?:0|STDIN_FILENO)\s*,/i, stdinEvidence, 'read');

  const hasStdin = stdinEvidence.length > 0;
  const hasArgv = argvEvidence.length > 0;
  const evidence = {
    stdin: [...new Set(stdinEvidence)],
    argv1: [...new Set(argvEvidence)]
  };

  if (hasStdin && hasArgv) {
    return {
      target: 'both',
      reason: `stdin + argv[1] detectes via ${[...evidence.stdin, ...evidence.argv1].join(', ')}`,
      evidence,
      fallback: false
    };
  }

  if (hasStdin) {
    return {
      target: 'stdin',
      reason: `stdin detecte via ${evidence.stdin.join(', ')}`,
      evidence,
      fallback: false
    };
  }

  if (hasArgv) {
    return {
      target: 'argv1',
      reason: `argv[1] detecte via ${evidence.argv1.join(', ')}`,
      evidence,
      fallback: false
    };
  }

  return {
    target: 'argv1',
    reason: 'aucune source claire, fallback sur argv[1]',
    evidence,
    fallback: true
  };
}

function normalizeBinarySymbolName(name) {
  return String(name || '')
    .trim()
    .split('@')[0]
    .replace(/^_+/, '')
    .toLowerCase();
}

function detectPayloadTargetFromBinarySymbols(symbols = []) {
  const stdinEvidence = [];
  const entries = Array.isArray(symbols) ? symbols : [];
  const addEvidence = (label) => {
    if (!stdinEvidence.includes(label)) stdinEvidence.push(label);
  };

  entries.forEach((entry) => {
    const name = normalizeBinarySymbolName(
      typeof entry === 'string' ? entry : entry?.name
    );
    if (!name) return;

    if (/^(?:isoc\d+_)?scanf(?:_s)?$/.test(name)) addEvidence('scanf import');
    if (/^vscanf(?:_s)?$/.test(name)) addEvidence('vscanf import');
    if (/^gets(?:_s)?$/.test(name)) addEvidence('gets import');
    if (/^getchar(?:_unlocked)?$/.test(name)) addEvidence('getchar import');
  });

  const evidence = {
    stdin: stdinEvidence,
    argv1: []
  };

  if (stdinEvidence.length > 0) {
    return {
      target: 'stdin',
      reason: `stdin detecte via ${stdinEvidence.join(', ')}`,
      evidence,
      fallback: false
    };
  }

  return {
    target: 'argv1',
    reason: 'aucun import stdin clair, fallback sur argv[1]',
    evidence,
    fallback: true
  };
}

function pickAutoPayloadTarget(sourceAuto, binaryAuto) {
  if (sourceAuto && sourceAuto.fallback === false) return sourceAuto;
  if (binaryAuto && binaryAuto.fallback === false) return binaryAuto;
  return sourceAuto || binaryAuto || {
    target: 'argv1',
    reason: 'aucune source claire, fallback sur argv[1]',
    evidence: { stdin: [], argv1: [] },
    fallback: true
  };
}

function resolvePayloadTarget({ mode = 'auto', sourceText = '', binarySymbols = [] } = {}) {
  const normalizedMode = normalizePayloadTargetMode(mode);
  const sourceAuto = detectPayloadTargetFromSourceText(sourceText);
  const binaryAuto = detectPayloadTargetFromBinarySymbols(binarySymbols);
  const auto = pickAutoPayloadTarget(sourceAuto, binaryAuto);

  if (normalizedMode !== 'auto') {
    return {
      mode: normalizedMode,
      target: normalizeEffectivePayloadTarget(normalizedMode),
      autoTarget: auto.target,
      reason: `${payloadTargetLabel(normalizedMode)} force manuellement`,
      autoReason: auto.reason,
      evidence: auto.evidence,
      fallback: false
    };
  }

  return {
    mode: 'auto',
    target: auto.target,
    autoTarget: auto.target,
    reason: `Auto: ${auto.reason}`,
    autoReason: auto.reason,
    evidence: auto.evidence,
    fallback: auto.fallback
  };
}

module.exports = {
  detectPayloadTargetFromBinarySymbols,
  detectPayloadTargetFromSourceText,
  normalizeEffectivePayloadTarget,
  normalizePayloadTargetMode,
  payloadTargetLabel,
  resolvePayloadTarget,
};
