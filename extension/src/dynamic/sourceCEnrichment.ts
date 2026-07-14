// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file sourceCEnrichment.js
 * @brief Parseur C pragmatique et couche d'enrichissement optionnelle.
 * @details Extrait fonctions, arguments, variables locales et tableaux depuis
 *          un fichier C fourni par l'utilisateur afin d'enrichir l'analyse
 *          binaire sans redefinir la geometrie observee.
 */

const CONTROL_KEYWORDS = new Set([
  'if', 'for', 'while', 'switch', 'return', 'sizeof', 'do', 'else', 'case', 'goto'
]);

const STORAGE_QUALIFIERS = new Set([
  'static', 'extern', 'inline', 'register', 'auto'
]);

const TYPE_KEYWORDS = new Set([
  'const', 'volatile', 'signed', 'unsigned', 'long', 'short',
  'char', 'int', 'float', 'double', 'void', 'size_t', 'ssize_t', 'bool',
  'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
  'int8_t', 'int16_t', 'int32_t', 'int64_t',
  'FILE'
]);

function clean(value) {
  return String(value || '').trim();
}

function normalizeFunctionName(name) {
  return clean(name).replace(/^_+/, '').replace(/@.*/, '').replace(/[<>]/g, '').toLowerCase();
}

function displayFunctionName(name) {
  const raw = clean(name).replace(/@.*/, '').replace(/[<>]/g, '');
  return raw.startsWith('_') && raw.length > 1 ? raw.slice(1) : raw;
}

function stripComments(source) {
  const text = String(source || '');
  let out = '';
  let inLine = false;
  let inBlock = false;
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    const next = text[index + 1] || '';

    if (inLine) {
      if (char === '\n') {
        inLine = false;
        out += char;
      }
      continue;
    }

    if (inBlock) {
      if (char === '*' && next === '/') {
        inBlock = false;
        index += 1;
      } else if (char === '\n') {
        out += '\n';
      }
      continue;
    }

    if (!inSingle && !inDouble) {
      if (char === '/' && next === '/') {
        inLine = true;
        index += 1;
        continue;
      }
      if (char === '/' && next === '*') {
        inBlock = true;
        index += 1;
        continue;
      }
    }

    out += char;

    if (escape) {
      escape = false;
      continue;
    }

    if (char === '\\') {
      escape = true;
      continue;
    }

    if (char === '\'' && !inDouble) {
      inSingle = !inSingle;
      continue;
    }

    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
    }
  }

  return out;
}

function findMatchingBrace(text, openIndex) {
  let depth = 0;
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let index = openIndex; index < text.length; index += 1) {
    const char = text[index];
    if (escape) {
      escape = false;
      continue;
    }
    if (char === '\\') {
      escape = true;
      continue;
    }
    if (char === '\'' && !inDouble) {
      inSingle = !inSingle;
      continue;
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle || inDouble) continue;
    if (char === '{') depth += 1;
    if (char === '}') {
      depth -= 1;
      if (depth === 0) return index;
    }
  }

  return -1;
}

function isLikelyFunctionHeader(returnType, name) {
  const loweredName = clean(name).toLowerCase();
  const loweredType = clean(returnType).toLowerCase();
  if (!loweredName || !loweredType) return false;
  if (CONTROL_KEYWORDS.has(loweredName)) return false;
  if (loweredType.includes('=') || loweredType.includes('return')) return false;
  return [...TYPE_KEYWORDS].some((token) => loweredType.includes(token)) || /\b(?:struct|enum)\s+[a-z_]/i.test(loweredType);
}

function findFunctionBlocks(source) {
  const blocks = [];
  const functionRe = /(^|\n)\s*((?:(?:static|extern|inline|const|volatile|signed|unsigned|long|short|struct\s+\w+|enum\s+\w+|char|int|float|double|void|size_t|ssize_t|bool|uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|FILE)\s+)+)([A-Za-z_]\w*)\s*\(([^()]*)\)\s*\{/g;
  let match = functionRe.exec(source);
  while (match) {
    const returnType = clean(match[2]);
    const name = clean(match[3]);
    const paramsText = clean(match[4]);
    if (!isLikelyFunctionHeader(returnType, name)) {
      match = functionRe.exec(source);
      continue;
    }

    const openIndex = functionRe.lastIndex - 1;
    const closeIndex = findMatchingBrace(source, openIndex);
    if (closeIndex < 0) break;

    blocks.push({
      name,
      returnType: normalizeTypeTokens(returnType, { keepStorage: true }),
      paramsText,
      body: source.slice(openIndex + 1, closeIndex),
      start: match.index,
      end: closeIndex + 1
    });

    functionRe.lastIndex = closeIndex + 1;
    match = functionRe.exec(source);
  }
  return blocks;
}

function normalizeTypeTokens(rawType, { keepStorage = false } = {}) {
  const parts = clean(rawType).split(/\s+/).filter(Boolean);
  const filtered = parts.filter((part) => keepStorage || !STORAGE_QUALIFIERS.has(part));
  return filtered.join(' ');
}

function splitTopLevel(text, separator) {
  const out = [];
  let current = '';
  let depthParen = 0;
  let depthBracket = 0;
  let depthBrace = 0;
  let inSingle = false;
  let inDouble = false;
  let escape = false;

  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (escape) {
      current += char;
      escape = false;
      continue;
    }
    if (char === '\\') {
      current += char;
      escape = true;
      continue;
    }
    if (char === '\'' && !inDouble) {
      inSingle = !inSingle;
      current += char;
      continue;
    }
    if (char === '"' && !inSingle) {
      inDouble = !inDouble;
      current += char;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (char === '(') depthParen += 1;
      if (char === ')') depthParen = Math.max(0, depthParen - 1);
      if (char === '[') depthBracket += 1;
      if (char === ']') depthBracket = Math.max(0, depthBracket - 1);
      if (char === '{') depthBrace += 1;
      if (char === '}') depthBrace = Math.max(0, depthBrace - 1);
      if (char === separator && depthParen === 0 && depthBracket === 0 && depthBrace === 0) {
        if (clean(current)) out.push(clean(current));
        current = '';
        continue;
      }
    }
    current += char;
  }

  if (clean(current)) out.push(clean(current));
  return out;
}

function splitStatements(body) {
  return splitTopLevel(String(body || ''), ';');
}

function primitiveTypeSize(baseType, archBits) {
  const normalized = normalizeTypeTokens(baseType).toLowerCase()
    .replace(/\bconst\b/g, '')
    .replace(/\bvolatile\b/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  const wordSize = Number(archBits) === 32 ? 4 : 8;
  if (!normalized) return wordSize;
  if (normalized.includes('char')) return 1;
  if (normalized.includes('short')) return 2;
  if (normalized === 'float') return 4;
  if (normalized === 'double') return 8;
  if (normalized.includes('int64_t') || normalized.includes('uint64_t')) return 8;
  if (normalized.includes('int32_t') || normalized.includes('uint32_t')) return 4;
  if (normalized.includes('int16_t') || normalized.includes('uint16_t')) return 2;
  if (normalized.includes('int8_t') || normalized.includes('uint8_t') || normalized === 'bool') return 1;
  if (normalized.includes('size_t') || normalized.includes('ssize_t')) return wordSize;
  if (normalized.includes('long long')) return 8;
  if (normalized.includes('long')) return Number(archBits) === 32 ? 4 : 8;
  return 4;
}

function declarationPrefix(statement) {
  const text = clean(statement).replace(/\s+/g, ' ');
  const match = text.match(/^((?:(?:static|extern|inline|register|auto|const|volatile|signed|unsigned|long|short|struct\s+\w+|enum\s+\w+|char|int|float|double|void|size_t|ssize_t|bool|uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|FILE)\s+)+)(.+)$/);
  if (!match) return null;
  return {
    typeText: normalizeTypeTokens(match[1]),
    declarators: clean(match[2])
  };
}

function parseDeclarator(fragment, baseType, archBits, { kind = 'local', order = 0 } = {}) {
  const text = clean(fragment).replace(/\s+/g, ' ');
  if (!text || text === '...') return null;
  const declarator = clean(text.split('=')[0]);
  const match = declarator.match(/^(\*+)?\s*([A-Za-z_]\w*)\s*(?:\[\s*(\d+)\s*\])?$/);
  if (!match) return null;
  const pointerDepth = match[1] ? match[1].length : 0;
  const name = clean(match[2]);
  const arrayLength = Number.isFinite(Number(match[3])) ? Math.trunc(Number(match[3])) : null;
  const scalarSize = pointerDepth > 0 ? (Number(archBits) === 32 ? 4 : 8) : primitiveTypeSize(baseType, archBits);
  const byteSize = arrayLength ? scalarSize * arrayLength : scalarSize;
  const resolvedKind = arrayLength ? 'buffer' : kind;
  const cType = arrayLength
    ? `${normalizeTypeTokens(baseType)}[${arrayLength}]`
    : `${normalizeTypeTokens(baseType)}${pointerDepth ? ` ${'*'.repeat(pointerDepth)}` : ''}`.trim();
  return {
    name,
    cType,
    baseType: normalizeTypeTokens(baseType),
    pointerDepth,
    arrayLength,
    byteSize,
    kind: resolvedKind,
    order
  };
}

function parseDeclarationStatement(statement, archBits, options = {}) {
  const prefix = declarationPrefix(statement);
  if (!prefix) return [];
  if (!prefix.typeText) return [];
  if (CONTROL_KEYWORDS.has(prefix.typeText.toLowerCase())) return [];
  const parts = splitTopLevel(prefix.declarators, ',');
  return parts
    .map((part, index) => parseDeclarator(part, prefix.typeText, archBits, {
      kind: options.kind || 'local',
      order: options.orderBase + index
    }))
    .filter(Boolean);
}

function parseParameterList(paramsText, archBits) {
  const text = clean(paramsText);
  if (!text || text === 'void') return [];
  return splitTopLevel(text, ',')
    .flatMap((part, index) => parseDeclarationStatement(part, archBits, {
      kind: 'argument',
      orderBase: index
    }));
}

function parseLocalDeclarations(body, archBits) {
  const locals = [];
  splitStatements(body).forEach((statement, index) => {
    const trimmed = clean(statement);
    if (!trimmed) return;
    if (/[({]/.test(trimmed.split(/\s+/)[0] || '')) return;
    parseDeclarationStatement(trimmed, archBits, { kind: 'local', orderBase: index * 10 })
      .forEach((local) => locals.push(local));
  });
  return locals;
}

function parseSourceCModel(sourceContent, { sourcePath = '', archBits = 64 } = {}) {
  const cleaned = stripComments(sourceContent);
  const functions = findFunctionBlocks(cleaned).map((block, index) => {
    const params = parseParameterList(block.paramsText, archBits).map((param, order) => ({
      ...param,
      order,
      role: 'argument'
    }));
    const locals = parseLocalDeclarations(block.body, archBits).map((local, order) => ({
      ...local,
      order
    }));
    return {
      index,
      name: displayFunctionName(block.name),
      normalizedName: normalizeFunctionName(block.name),
      returnType: block.returnType,
      params,
      locals
    };
  });

  return {
    sourcePath: clean(sourcePath),
    archBits: Number(archBits) === 32 ? 32 : 64,
    functions
  };
}

function collectTraceFunctionNames(trace) {
  const names = new Set();
  const snapshots = Array.isArray(trace?.snapshots) ? trace.snapshots : [];
  snapshots.forEach((snap) => {
    const normalized = normalizeFunctionName(snap?.func || '');
    if (normalized) names.add(normalized);
  });
  const metaFunctions = Array.isArray(trace?.meta?.functions) ? trace.meta.functions : [];
  metaFunctions.forEach((entry) => {
    const normalized = normalizeFunctionName(entry?.name || '');
    if (normalized) names.add(normalized);
  });
  return names;
}

function buildTraceSourceEnrichment({ sourcePath = '', sourceContent = '', trace = null, archBits = 64 } = {}) {
  const model = parseSourceCModel(sourceContent, { sourcePath, archBits });
  const traceFunctions = collectTraceFunctionNames(trace);
  const matchedFunctions = model.functions
    .filter((fn) => traceFunctions.has(fn.normalizedName))
    .map((fn) => fn.name);
  const unmatchedFunctions = model.functions
    .filter((fn) => !traceFunctions.has(fn.normalizedName))
    .map((fn) => fn.name);

  let status = 'none';
  let message = 'Aucun enrichissement source.';
  let enabled = false;

  if (!model.functions.length) {
    status = 'invalid';
    message = 'Le fichier C fourni n’a pas pu être interprété proprement.';
  } else if (!matchedFunctions.length) {
    status = 'mismatch';
    message = 'Le code source fourni ne correspond que partiellement au binaire ; enrichissement désactivé.';
  } else if (matchedFunctions.length === model.functions.length || matchedFunctions.length >= Math.max(1, Math.min(2, traceFunctions.size || 0))) {
    status = 'matched';
    enabled = true;
    message = 'Code source détecté — analyse enrichie activée.';
  } else {
    status = 'partial';
    enabled = true;
    message = 'Code source détecté — enrichissement partiel.';
  }

  return {
    sourcePath: clean(sourcePath),
    archBits: model.archBits,
    status,
    enabled,
    message,
    matchedFunctions,
    unmatchedFunctions,
    functions: model.functions
  };
}

function resolveSourceFunction(enrichment, functionName) {
  if (!enrichment || enrichment.enabled !== true) return null;
  const normalized = normalizeFunctionName(functionName);
  if (!normalized) return null;
  return (Array.isArray(enrichment?.functions) ? enrichment.functions : []).find((entry) => entry.normalizedName === normalized) || null;
}

function isGenericLocalName(name) {
  const raw = clean(name).toLowerCase();
  return !raw
    || /^var_[0-9a-f]+h?$/i.test(raw)
    || /^buffer(?:_[0-9]+)?$/i.test(raw)
    || /^local(?:_[0-9]+)?$/i.test(raw)
    || /^arg(?:_[0-9]+)?$/i.test(raw)
    || /^unknown(?:_[0-9]+)?$/i.test(raw)
    || /^slot(?:_[0-9]+)?$/i.test(raw);
}

function matchSourceLocalsToModelLocals(modelLocals, sourceLocals) {
  const candidates = Array.isArray(modelLocals) ? modelLocals.map((local) => ({ ...local })) : [];
  const sources = Array.isArray(sourceLocals) ? sourceLocals : [];
  const assignments = new Map();
  const usedSource = new Set();

  const scorePair = (local, source, localIndex) => {
    if (!local || !source) return -Infinity;
    let score = 0;
    const localSize = Number(local?.size || 0);
    const sourceSize = Number(source?.byteSize || 0);
    const localRole = String(local?.role || '').toLowerCase();
    const sourceKind = String(source?.kind || '').toLowerCase();
    const sourceName = clean(source?.name).toLowerCase();
    const localEvidence = Array.isArray(local?.evidence)
      ? local.evidence.map((entry) => clean(entry).toLowerCase()).join(' ')
      : '';

    if (localSize && sourceSize && localSize === sourceSize) score += 500;
    else if (localRole === 'buffer' && sourceKind === 'buffer' && localSize && sourceSize && Math.abs(localSize - sourceSize) <= 16) score += 240;
    // eslint-disable-next-line no-dupe-else-if -- dead branch: line above already catches equal-size cases; kept for future reordering
    else if (localRole !== 'buffer' && sourceKind !== 'buffer' && localSize && sourceSize && localSize === sourceSize) score += 360;

    if (localRole === sourceKind) score += 140;
    if (localRole === 'modified' && source.name.toLowerCase().includes('modified')) score += 600;
    if (localRole === 'buffer' && sourceKind === 'buffer') score += 200;
    if (localRole === 'local' && sourceKind === 'local') score += 80;
    if (localRole === 'padding' && sourceKind !== 'padding') score -= 500;
    if (sourceName === 'check' && /\b(compare|cmp)\b/.test(localEvidence)) score += 260;
    if (sourceName === 'var' && /\b(compare|cmp)\b/.test(localEvidence)) score -= 120;
    // A local whose address was taken (lea) is used as a pointer/array
    // base, not a plain scalar -- it can only be the source's array.
    const localAddressTaken = /\blea to local stack address\b/.test(localEvidence);
    if (localAddressTaken) score += sourceKind === 'buffer' ? 400 : -400;
    if (isGenericLocalName(local?.name)) score += 60;
    score += Math.max(0, 60 - localIndex * 10);
    return score;
  };

  const orderedLocals = [...candidates].sort((left, right) => Number(right.offset || 0) - Number(left.offset || 0));
  orderedLocals.forEach((local, localIndex) => {
    let bestSource = null;
    let bestScore = -Infinity;
    sources.forEach((source) => {
      if (usedSource.has(source.name)) return;
      const score = scorePair(local, source, localIndex);
      if (score > bestScore) {
        bestScore = score;
        bestSource = source;
      }
    });
    if (bestSource && bestScore >= 300) {
      assignments.set(local.offset, bestSource);
      usedSource.add(bestSource.name);
    }
  });

  return assignments;
}

function applySourceHintsToFunctionModel(functionModel, sourceFunction, { archBits = 64 } = {}) {
  if (!functionModel || !sourceFunction) return functionModel;
  const locals = Array.isArray(functionModel.locals) ? functionModel.locals.map((local) => ({ ...local })) : [];
  const assignments = matchSourceLocalsToModelLocals(locals, sourceFunction.locals);
  locals.forEach((local) => {
    const source = assignments.get(local.offset);
    if (!source) return;
    if (isGenericLocalName(local.name) || String(local.name || '').toLowerCase() === String(local.role || '').toLowerCase()) {
      local.name = source.name;
    }
    if (!clean(local.cType) && clean(source.cType)) {
      local.cType = source.cType;
    }
    if (source.kind === 'buffer' && Number(source.byteSize) > 0) {
      local.size = Number(source.byteSize);
      local.role = 'buffer';
    }
    local.confidence = Math.max(Number(local.confidence || 0), 0.93);
    local.source = 'source_c';
    local.evidence = [...new Set([...(local.evidence || []), 'source C'])];
  });

  const parameters = Array.isArray(sourceFunction.params) ? sourceFunction.params.map((param) => ({
    name: param.name,
    cType: param.cType,
    byteSize: param.byteSize,
    kind: param.kind
  })) : [];

  return {
    ...functionModel,
    locals,
    parameters,
    sourceFunction: {
      name: sourceFunction.name,
      returnType: sourceFunction.returnType
    },
    notes: [...new Set([...(functionModel.notes || []), 'source C enrichment'])]
  };
}

module.exports = {
  applySourceHintsToFunctionModel,
  buildTraceSourceEnrichment,
  parseSourceCModel,
  resolveSourceFunction
};
