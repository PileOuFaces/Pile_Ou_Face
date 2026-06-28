/**
 * @file stackSimpleModel.js
 * @brief Projecteur UI du mode SIMPLE.
 * @details Nettoie les labels, injecte des proxies visuels argc/argv et
 *          prepare les cartes lineaires sans modifier le modele canonique profond.
 */

const SPECIAL_ARGUMENTS = ['argc', 'argv', 'envp'];

export function buildSimplifiedStackViewModel({
  frameModel,
  detailModel,
  statusText
} = {}) {
  const entries = Array.isArray(frameModel?.entries) ? frameModel.entries : [];
  const selectedKey = String(detailModel?.key || '').trim();
  const bpRegister = String(frameModel?.bpRegister || 'rbp').toLowerCase();
  const registerArguments = Array.isArray(frameModel?.registerArguments) ? frameModel.registerArguments : [];
  const logicalArguments = Array.isArray(frameModel?.logicalArguments) ? frameModel.logicalArguments : [];

  const items = buildPresentationEntries(entries, {
    bpRegister,
    registerArguments,
    logicalArguments
  }).map((entry) => {
    const selectionKey = entry.selectionKey || entry.key;
    return {
      ...entry,
      key: entry.key,
      selectionKey,
      title: buildPresentationTitle(entry),
      subtitle: entry.offsetLabel || '',
      badges: Array.isArray(entry.badges) ? entry.badges : [],
      isSelected: Boolean(selectionKey && selectionKey === selectedKey),
      valuePreview: entry.valuePreview || '',
      offsetBand: entry.offsetBand || 'unknown',
      isSensitive: Boolean(entry.isSensitive)
    };
  });

  return {
    statusText: String(statusText || '').trim(),
    spMarker: frameModel?.spMarker || null,
    items
  };
}

function buildPresentationEntries(entries, { bpRegister, registerArguments, logicalArguments } = {}) {
  const normalized = (Array.isArray(entries) ? entries : []).map((entry) => ({
    ...entry,
    selectionKey: entry?.key || '',
    name: normalizePresentationName(entry?.name || ''),
    title: '',
    subtitle: entry?.offsetLabel || ''
  }));

  const abi = buildAbiPresentationEntries(normalized, {
    bpRegister,
    registerArguments,
    logicalArguments
  });

  const promotedNames = abi.promotedNames;
  const visibleNormalized = normalized.filter((entry) => !abi.usedSourceKeys.has(entry?.key));

  visibleNormalized.forEach((entry) => {
    if (
      entry?.offset < 0
      && promotedNames.has(String(entry?.name || '').toLowerCase())
      && SPECIAL_ARGUMENTS.includes(String(entry?.name || '').toLowerCase())
    ) {
      entry.name = `${entry.name}_saved`;
    }
  });

  const combined = [...abi.proxies, ...visibleNormalized];
  dedupePresentationNames(combined);
  return combined.sort(comparePresentationEntries);
}

function buildAbiPresentationEntries(entries, { bpRegister, registerArguments, logicalArguments } = {}) {
  if (Array.isArray(logicalArguments) && logicalArguments.length) {
    return buildAbiPresentationEntriesFromLogicalArguments(entries, logicalArguments);
  }

  const wordSize = bpRegister === 'ebp' ? 4 : 8;
  const proxies = [];
  const promotedNames = new Set();
  const usedSourceKeys = new Set();

  const namedAbiArguments = (Array.isArray(registerArguments) ? registerArguments : [])
    .map((entry, index) => ({
      index,
      name: normalizeSpecialArgumentName(entry?.name),
      location: String(entry?.location || '').trim().toLowerCase(),
      size: readPositiveInt(entry?.size) || wordSize
    }))
    .filter((entry) => SPECIAL_ARGUMENTS.includes(entry.name));

  if (!namedAbiArguments.length) {
    return { proxies, promotedNames, usedSourceKeys };
  }

  const genericArgumentEntries = entries
    .filter((entry) => normalizeKind(entry?.kind) === 'argument' && Number.isFinite(entry?.offset) && entry.offset < 0)
    .sort((left, right) => (right.offset ?? 0) - (left.offset ?? 0));

  namedAbiArguments.forEach((argument, index) => {
    if ((Array.isArray(entries) ? entries : []).some((entry) => (
      String(entry?.name || '').toLowerCase() === argument.name
      && Number.isFinite(entry?.offset)
      && entry.offset > 0
    ))) {
      return;
    }

    const source = findAbiSourceEntry(entries, genericArgumentEntries, argument.name, index, usedSourceKeys);
    if (!source) return;
    usedSourceKeys.add(source.key);
    promotedNames.add(argument.name);

    const visualOffset = resolveAbiVisualOffset(argument.name, wordSize);
    proxies.push({
      ...source,
      key: `${source.key}:abi:${argument.name}`,
      selectionKey: source.key,
      name: argument.name,
      offset: visualOffset,
      offsetLabel: formatOffsetLabel(bpRegister, visualOffset),
      offsetBand: 'positive',
      isSynthetic: true,
      badges: ['ABI'],
      detailPayload: buildAbiDetailPayload(source, argument, bpRegister, visualOffset)
    });
  });

  return { proxies, promotedNames, usedSourceKeys };
}

function buildAbiPresentationEntriesFromLogicalArguments(entries, logicalArguments) {
  const proxies = [];
  const promotedNames = new Set();
  const usedSourceKeys = new Set();

  (Array.isArray(logicalArguments) ? logicalArguments : []).forEach((logical) => {
    const storageKey = String(logical?.storageKey || '').trim();
    const source = storageKey
      ? (Array.isArray(entries) ? entries : []).find((entry) => entry?.key === storageKey) || null
      : null;
    if (!source) return;

    usedSourceKeys.add(source.key);
    promotedNames.add(String(logical?.name || '').toLowerCase());
    proxies.push({
      ...source,
      key: cleanLogicalArgumentKey(logical?.key, source?.key, logical?.name),
      selectionKey: source.key,
      name: String(logical?.name || '').trim(),
      offset: Number.isFinite(logical?.offset) ? logical.offset : source.offset,
      offsetLabel: String(logical?.offsetLabel || '').trim() || source.offsetLabel,
      offsetBand: 'positive',
      isSynthetic: true,
      badges: ['ABI'],
      detailPayload: buildLogicalArgumentDetailPayload(source, logical)
    });
  });

  return { proxies, promotedNames, usedSourceKeys };
}

function findAbiSourceEntry(entries, genericArgumentEntries, name, index, usedSourceKeys) {
  void index;
  const exact = (Array.isArray(entries) ? entries : []).find((entry) => (
    !usedSourceKeys.has(entry?.key)
    && String(entry?.name || '').toLowerCase() === name
  ));
  if (exact) return exact;
  return genericArgumentEntries.find((entry) => !usedSourceKeys.has(entry?.key)) || null;
}

function buildAbiDetailPayload(source, argument, bpRegister, visualOffset) {
  const rows = Array.isArray(source?.detailPayload?.rows)
    ? source.detailPayload.rows.map((row) => ({ ...row }))
    : [];

  upsertDetailRow(rows, 'Nom', argument.name);
  upsertDetailRow(rows, 'Categorie', 'argument');
  upsertDetailRow(rows, 'Taille', `${readPositiveInt(source?.size) || readPositiveInt(argument?.size) || 0} octet${(readPositiveInt(source?.size) || readPositiveInt(argument?.size) || 0) > 1 ? 's' : ''}`);
  upsertDetailRow(rows, 'Offset', formatOffsetLabel(bpRegister, visualOffset));
  if (argument?.location) upsertDetailRow(rows, 'Registre source', argument.location);
  if (Number.isFinite(source?.offset) && source.offset < 0) {
    upsertDetailRow(rows, 'Copie locale', source.offsetLabel || formatOffsetLabel(bpRegister, source.offset));
  }

  return {
    subtitle: formatOffsetLabel(bpRegister, visualOffset),
    rows
  };
}

function buildLogicalArgumentDetailPayload(source, logical) {
  const rows = Array.isArray(source?.detailPayload?.rows)
    ? source.detailPayload.rows.map((row) => ({ ...row }))
    : [];

  upsertDetailRow(rows, 'Nom', String(logical?.name || '').trim() || source?.name || 'argument');
  upsertDetailRow(rows, 'Categorie', 'argument');
  if (logical?.cType) upsertDetailRow(rows, 'Type', logical.cType);
  if (logical?.offsetLabel) upsertDetailRow(rows, 'Offset', logical.offsetLabel);
  if (logical?.registerLocation) upsertDetailRow(rows, 'Registre source', logical.registerLocation);
  if (logical?.storageOffsetLabel) upsertDetailRow(rows, 'Copie locale', logical.storageOffsetLabel);
  if (logical?.source === 'source_c') upsertDetailRow(rows, 'Source du nom', 'C');

  return {
    subtitle: String(logical?.offsetLabel || '').trim() || source?.offsetLabel || '',
    rows
  };
}

function upsertDetailRow(rows, label, value) {
  if (!Array.isArray(rows)) return;
  const index = rows.findIndex((row) => String(row?.label || '').trim().toLowerCase() === String(label || '').trim().toLowerCase());
  if (index >= 0) {
    rows[index] = { label, value };
    return;
  }
  rows.push({ label, value });
}

function normalizePresentationName(name) {
  const raw = String(name || '').trim();
  if (!raw) return '';
  return raw
    .replace(/^buffer_0$/i, 'buffer')
    .replace(/^local_0$/i, 'local')
    .replace(/^arg_0$/i, 'arg')
    .replace(/^padding_0$/i, 'padding')
    .replace(/^unknown_0$/i, 'unknown')
    .replace(/^slot_0$/i, 'slot');
}

function dedupePresentationNames(entries) {
  const counts = new Map();
  (Array.isArray(entries) ? entries : []).forEach((entry) => {
    const baseName = String(entry?.name || '').trim();
    if (!baseName) return;
    const key = baseName.toLowerCase();
    const nextIndex = counts.get(key) ?? 0;
    counts.set(key, nextIndex + 1);
    if (nextIndex === 0) return;
    entry.name = `${baseName}_${nextIndex}`;
  });
}

function buildPresentationTitle(entry) {
  const name = String(entry?.name || '').trim() || 'slot';
  const size = readPositiveInt(entry?.size);
  if (normalizeKind(entry?.kind) === 'buffer' && size) {
    return `${name} (${size}B)`;
  }
  return name;
}

function comparePresentationEntries(left, right) {
  const leftOffset = Number.isFinite(left?.offset) ? left.offset : null;
  const rightOffset = Number.isFinite(right?.offset) ? right.offset : null;
  if (leftOffset === null && rightOffset !== null) return 1;
  if (leftOffset !== null && rightOffset === null) return -1;
  if (leftOffset !== null && rightOffset !== null && leftOffset !== rightOffset) {
    return rightOffset - leftOffset;
  }
  return String(left?.name || '').localeCompare(String(right?.name || ''));
}

function resolveAbiVisualOffset(name, wordSize) {
  switch (String(name || '').toLowerCase()) {
    case 'argc':
      return wordSize * 2;
    case 'argv':
      return wordSize * 3;
    case 'envp':
      return wordSize * 4;
    default:
      return wordSize * 2;
  }
}

function formatOffsetLabel(bpRegister, offset) {
  const base = String(bpRegister || 'rbp').toLowerCase();
  const numeric = Number(offset || 0);
  const sign = numeric < 0 ? '-' : '+';
  return `${base}${sign}0x${Math.abs(numeric).toString(16)}`;
}

function normalizeSpecialArgumentName(name) {
  const value = String(name || '').trim().toLowerCase();
  return SPECIAL_ARGUMENTS.includes(value) ? value : '';
}

function cleanLogicalArgumentKey(key, sourceKey, name) {
  const value = String(key || '').trim();
  if (value) return value;
  return `${String(sourceKey || '').trim()}:abi:${String(name || '').trim().toLowerCase()}`;
}

function normalizeKind(kind) {
  const value = String(kind || '').trim().toLowerCase();
  if (!value) return 'unknown';
  if (value === 'return_address') return 'return_address';
  if (value === 'saved_bp') return 'saved_bp';
  return value;
}

function readPositiveInt(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return 0;
  return Math.trunc(numeric);
}
