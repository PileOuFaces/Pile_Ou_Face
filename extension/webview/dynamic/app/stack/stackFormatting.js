import { diagnosticsForStackSlot } from '../diagnostics.js';
import { addrKey, toBigIntAddr } from '../memory.js';
import { toHex } from '../utils.js';

// Style + labels for stack block roles.
export const ROLE_CONFIG = {
  ret: { label: 'RET', className: 'role-ret', tagClass: 'tag-control' },
  control: { label: 'CONTROL', className: 'role-control', tagClass: 'tag-control' },
  local: { label: 'LOCAL', className: 'role-local', tagClass: 'tag-local' },
  modified: { label: 'MODIFIED', className: 'role-modified', tagClass: 'tag-modified' },
  buffer: { label: 'BUFFER', className: 'role-buffer', tagClass: 'tag-buffer' },
  arg: { label: 'ARG', className: 'role-arg', tagClass: 'tag-arg' },
  padding: { label: 'PADDING', className: 'role-unknown', tagClass: 'tag-unknown' },
  spill: { label: 'SPILL', className: 'role-local', tagClass: 'tag-local' },
  unknown: { label: 'UNKNOWN', className: 'role-unknown', tagClass: 'tag-unknown' },
  default: { label: 'DEFAULT', className: 'role-default', tagClass: 'tag-unknown' }
};

// Tooltip text to explain each role.
export const ROLE_TOOLTIPS = {
  ret: 'Return address.',
  control: 'Saved frame/control slot.',
  local: 'Local stack slot inside the current frame.',
  modified: 'DWORD attendu pour la variable modified.',
  buffer: 'Zone buffer.',
  arg: 'Argument sauvegarde dans la frame locale.',
  padding: 'Zone de padding/alignment.',
  spill: 'Valeur spill intermediaire.',
  unknown: 'Slot observe sans semantique fiable.',
  default: 'Slot de pile standard.'
};


/**
 * @brief Deduit le role semantique d'un bloc de pile.
 * @details Priorite: RET/CONTROL avant BUFFER.
 */
export function resolveSemanticRole(item, addr, rbp, retAddrAddr, bufferStart, bufferEnd, analysisStackRoles = {}, modelRegions = []) {
  const explicitRole = normalizeRoleName(item.semanticRole ?? item.role ?? item.kind ?? item.zone ?? item.type);
  if (explicitRole) return explicitRole;
  if (addr !== null && retAddrAddr !== null && addr === retAddrAddr) return 'ret';
  if (addr !== null && rbp !== null && addr === rbp) return 'control';
  const region = findModelRegionForItem(addr, item.size, modelRegions);
  if (region?.role === 'modified') return 'modified';
  if (region?.role === 'buffer') return 'buffer';
  if (region?.role === 'buffer_gap') return 'buffer_gap';
  if (region?.role === 'arg') return 'arg';
  if (region?.role === 'local') return 'local';
  if (region?.role === 'control') return 'control';
  if (region?.role === 'unknown') return 'unknown';
  const normalizedAddr = addr !== null ? normalizeAddressKey(addr) : null;
  const roleFromAnalysis = normalizedAddr ? analysisStackRoles[normalizedAddr] : null;
  if (roleFromAnalysis === 'ret') return 'ret';
  if (roleFromAnalysis === 'control') return 'control';
  if (roleFromAnalysis === 'local') return 'local';
  if (roleFromAnalysis === 'modified') return 'modified';
  if (roleFromAnalysis === 'buffer') return 'buffer';
  if (roleFromAnalysis === 'arg') return 'arg';
  if (roleFromAnalysis === 'unknown') return 'unknown';
  if (roleFromAnalysis === 'default') return 'default';

  const raw = (item.role ?? item.kind ?? item.zone ?? item.type ?? '').toString().toLowerCase();
  if (raw) {
    if (raw.includes('ret')) return 'ret';
    if (raw.includes('modified')) return 'modified';
    if (raw.includes('control') || raw.includes('saved')) return 'control';
    if (raw.includes('buffer')) return 'buffer';
    if (raw.includes('arg')) return 'arg';
    if (raw.includes('local')) return 'local';
    if (raw.includes('unknown')) return 'unknown';
  }

  const name = (item.name ?? item.label ?? '').toString().toLowerCase();
  if (name.includes('ret')) return 'ret';
  if (name.includes('modified')) return 'modified';
  if (name.includes('saved') || name.includes('ebp') || name.includes('rbp')) return 'control';
  if (name.includes('argument')) return 'arg';

  if (
    addr !== null &&
    bufferStart !== null &&
    bufferEnd !== null &&
    addr >= bufferStart &&
    addr < bufferEnd
  ) {
    return 'buffer';
  }

  return 'default';
}

/**
 * @brief Reduit les roles semantiques vers les 3 roles visuels demandes.
 */
export function toVisualRole(role) {
  if (role === 'saved_bp') return 'control';
  if (role === 'return_address') return 'ret';
  if (role === 'argument') return 'arg';
  if (role === 'padding') return 'padding';
  if (role === 'spill') return 'spill';
  if (role === 'ret') return 'ret';
  if (role === 'control') return 'control';
  if (role === 'local') return 'local';
  if (role === 'modified') return 'modified';
  if (role === 'buffer') return 'buffer';
  if (role === 'buffer_gap') return 'buffer';
  if (role === 'arg') return 'arg';
  if (role === 'unknown') return 'unknown';
  return 'default';
}

/**
 * @brief Construit les offsets a afficher.
 * @param item Entree de pile.
 * @param addr Adresse calculee.
 * @param rsp Registre SP.
 * @param rbp Registre BP.
 * @param posValue Position fournie.
 * @param spName Nom SP.
 * @param bpName Nom BP.
 * @return Liste d'offsets.
 */
export function buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName) {
  const offsets = [];
  if (typeof item.offsetFromBpHex === 'string' && item.offsetFromBpHex) {
    offsets.push({ text: `${bpName} ${item.offsetFromBpHex}`, primary: true });
  } else if (addr !== null && rbp !== null) {
    offsets.push({ text: `${bpName} ${formatSignedHexBigInt(addr - rbp)}`, primary: true });
  }
  let spOffset = null;
  let hasExplicitSpOffset = false;
  if (typeof item.offsetFromSpHex === 'string' && item.offsetFromSpHex) {
    offsets.push({
      text: `${spName} ${item.offsetFromSpHex}`,
      primary: offsets.length === 0,
      secondary: offsets.length > 0,
      tooltip: 'Position relative au sommet de pile (SP).'
    });
    hasExplicitSpOffset = true;
  } else if (addr !== null && rsp !== null) {
    spOffset = addr - rsp;
  } else if (typeof posValue === 'number') {
    spOffset = BigInt(posValue);
  }

  if (spOffset !== null && !hasExplicitSpOffset) {
      offsets.push({
        text: `${spName} ${formatSignedHexBigInt(spOffset)}`,
        primary: offsets.length === 0,
        secondary: offsets.length > 0,
        tooltip: 'Position relative au sommet de pile (SP).'
      });
  }

  return offsets;
}

/**
 * @brief Construit le label du repere BP.
 * @param rbp Valeur BP.
 * @param range Plage d'adresses.
 * @param bpName Nom BP.
 * @return Texte de label.
 */
export function buildAxisLabel(rbp, range, bpName) {
  const base = rbp !== null ? `${bpName} (repere fixe) = ${toHex(rbp)}` : `${bpName} (repere fixe)`;
  if (rbp !== null && range && (rbp < range.min || rbp > range.max)) {
    return `${base} (hors fenetre)`;
  }
  return `${base} • haut=RBP+ / bas=RBP-`;
}

/**
 * @brief Calcule la plage d'adresses de pile.
 * @param items Entrees de pile.
 * @param rsp Registre SP.
 * @return Objet {min,max} ou null.
 */
export function getStackAddrRange(items, rsp) {
  let min = null;
  let max = null;
  items.forEach((item) => {
    const addr = resolveStackAddressBigInt(item, rsp);
    if (addr === null) return;
    if (min === null || addr < min) min = addr;
    if (max === null || addr > max) max = addr;
  });
  if (min === null || max === null) return null;
  return { min, max };
}

/**
 * @brief Construit une cle de stabilite pour un item.
 * @param item Entree de pile.
 * @return Cle unique.
 */
export function buildStackKey(item, fallbackIndex = 0) {
  if (item.key) return `key:${item.key}`;
  if (item.addr) return `addr:${item.addr}`;
  const posValue = item.pos ?? item.posi ?? null;
  if (posValue !== null) return `pos:${posValue}`;
  if (item.id !== undefined) return `id:${item.id}`;
  const label = String(item.label ?? item.name ?? 'slot').trim() || 'slot';
  const role = String(item.role ?? item.kind ?? 'default').trim() || 'default';
  const size = Number.isFinite(Number(item.size)) ? Math.trunc(Number(item.size)) : 0;
  return `item:${label}:${role}:${size}:${fallbackIndex}`;
}

export function resolveStackAddressBigInt(item, rsp) {
  const itemAddr = toBigIntAddr(item.addr);
  if (itemAddr !== null) return itemAddr;
  const pos = typeof item.pos === 'number' ? item.pos : item.posi ?? null;
  if (rsp !== null && pos !== null) {
    return rsp + BigInt(Math.trunc(pos));
  }
  return null;
}

export function normalizeAddressKey(value) {
  return addrKey(toBigIntAddr(value));
}

export function normalizeRoleName(role) {
  const raw = String(role || '').toLowerCase();
  if (!raw) return null;
  if (raw === 'saved_bp') return 'saved_bp';
  if (raw === 'return_address') return 'return_address';
  if (raw === 'argument' || raw === 'arg') return 'argument';
  if (raw === 'buffer') return 'buffer';
  if (raw === 'local') return 'local';
  if (raw === 'padding') return 'padding';
  if (raw === 'spill') return 'spill';
  if (raw === 'unknown' || raw === 'uninitialized') return 'unknown';
  if (raw === 'control') return 'control';
  if (raw === 'ret') return 'ret';
  return raw;
}

export function buildItemTooltip(item, visualRole) {
  const parts = [ROLE_TOOLTIPS[visualRole] || ''];
  if (typeof item.comment === 'string' && item.comment) parts.push(item.comment);
  if (typeof item.valueHex === 'string' && item.valueHex) parts.push(`Value ${item.valueHex}`);
  if (Array.isArray(item.flags) && item.flags.length) parts.push(`Flags: ${item.flags.join(', ')}`);
  return parts.filter(Boolean).join(' • ');
}

export function buildHumanSubtitle(item, visualRole, payloadText, payloadHex, modelRegion) {
  const rawLabel = String(item.label ?? item.name ?? modelRegion?.name ?? '').toLowerCase();
  const modelName = String(modelRegion?.name || '').toLowerCase();
  const semanticRole = normalizeRoleName(item.semanticRole ?? item.role ?? item.kind ?? visualRole);
  if (modelName === 'argc' || rawLabel === 'argc') return 'argc';
  if (modelName === 'argv' || rawLabel === 'argv') return 'argv';
  if (modelName === 'modified' || rawLabel === 'modified' || semanticRole === 'modified') return 'modified';
  if (modelName === 'buffer') return 'buffer';
  if (modelRegion?.role === 'buffer_gap') return 'buffer_gap';
  if (semanticRole === 'saved_bp' || rawLabel.includes('saved')) return 'saved_bp';
  if (semanticRole === 'return_address' || visualRole === 'ret' || rawLabel.includes('ret')) return 'ret_addr';
  if (visualRole === 'buffer') return 'buffer';
  if ((semanticRole === 'argument' || visualRole === 'arg') && itemContainsPayload(item, payloadText, payloadHex)) return 'argument';
  if (semanticRole === 'argument' || visualRole === 'arg') return 'argument';
  if (visualRole === 'padding' || visualRole === 'unknown') return 'intermediate';
  if (visualRole === 'local') return 'local';
  return '';
}

export function payloadChunks(payloadText) {
  const text = String(payloadText || '').trim();
  if (!text) return [];
  const chunks = new Set();
  if (text.length >= 4) {
    chunks.add(text.slice(0, Math.min(8, text.length)).toLowerCase());
    chunks.add(text.slice(Math.max(0, text.length - 8)).toLowerCase());
  }
  for (let index = 0; index <= text.length - 4; index += 4) {
    chunks.add(text.slice(index, index + Math.min(8, text.length - index)).toLowerCase());
  }
  return [...chunks].filter(Boolean);
}

export function payloadHexChunks(payloadHex) {
  const hex = String(payloadHex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (hex.length < 8) return [];
  const chunks = new Set();
  chunks.add(hex.slice(0, Math.min(16, hex.length)));
  chunks.add(hex.slice(Math.max(0, hex.length - 16)));
  for (let index = 0; index <= hex.length - 8; index += 8) {
    chunks.add(hex.slice(index, index + 8));
    chunks.add(hex.slice(index, Math.min(index + 16, hex.length)));
  }
  return [...chunks].filter(Boolean);
}

export function itemContainsPayload(item, payloadText, payloadHex = '') {
  const haystack = [
    item.valueDisplay,
    item.ascii,
    item.bytesHex,
    item.label
  ]
    .map((part) => String(part || ''))
    .join(' ')
    .toLowerCase();
  const hexHaystack = String(item.bytesHex || '').replace(/[^0-9a-f]/gi, '').toLowerCase();
  if (!haystack) return false;
  const chunks = payloadChunks(payloadText);
  const hexChunks = payloadHexChunks(payloadHex);
  if (!chunks.length && !hexChunks.length) {
    return haystack.includes('arg_') && haystack.includes('"');
  }
  return chunks.some((chunk) => haystack.includes(chunk))
    || hexChunks.some((chunk) => hexHaystack.includes(chunk));
}

export function isPayloadRelatedItem(item, visualRole, payloadText, payloadHex = '') {
  if (itemContainsPayload(item, payloadText, payloadHex)) return true;
  return visualRole === 'buffer' && Array.isArray(item.flags) && item.flags.includes('ascii_probable');
}

export function formatSignedHexBigInt(value) {
  const v = BigInt(value);
  if (v === 0n) return '+0x0';
  const sign = v < 0n ? '-' : '+';
  const abs = v < 0n ? -v : v;
  return `${sign}0x${abs.toString(16)}`;
}

export function compareStackItemsByAddrDesc(a, b, rsp) {
  const addrA = resolveStackAddressBigInt(a, rsp);
  const addrB = resolveStackAddressBigInt(b, rsp);
  if (addrA !== null && addrB !== null) {
    if (addrA === addrB) return 0;
    return addrA > addrB ? -1 : 1;
  }
  const offsetA = typeof a.pos === 'number' ? a.pos : a.posi ?? 0;
  const offsetB = typeof b.pos === 'number' ? b.pos : b.posi ?? 0;
  return offsetB - offsetA;
}

export function injectControlSlots(stackItems, {
  rsp,
  savedBpAddr,
  retAddrAddr,
  wordSize,
  retValue,
  modifiedAddr,
  modifiedValue
}) {
  const out = Array.isArray(stackItems) ? stackItems.map((item) => ({ ...item })) : [];
  if (savedBpAddr === null && retAddrAddr === null && modifiedAddr === null) return out;
  const is64 = wordSize === 8n || wordSize === 8;

  const targets = [
    { addr: savedBpAddr, label: is64 ? 'saved_rbp' : 'saved_ebp', role: 'saved_bp', forcedValue: null },
    { addr: retAddrAddr, label: 'ret_addr', role: 'return_address', forcedValue: retValue },
    { addr: modifiedAddr, label: 'modified', role: 'modified', forcedValue: modifiedValue, forcedSize: 4 }
  ];

  targets.forEach((target) => {
    if (target.addr === null) return;
    const idx = out.findIndex((item) => resolveStackAddressBigInt(item, rsp) === target.addr);
    if (idx >= 0) {
      out[idx] = {
        ...out[idx],
        value: chooseDisplayValue(target.forcedValue, out[idx].value),
        label: target.label,
        name: target.label,
        role: target.role,
        kind: target.role,
        size: target.forcedSize ?? out[idx].size,
        __forceVisible: true
      };
      return;
    }

    const value = target.forcedValue ?? findValueByAddress(out, target.addr, rsp);
    out.push({
      addr: `0x${target.addr.toString(16)}`,
      pos: toSafeNumber(target.addr, rsp),
      value,
      size: target.forcedSize ?? Number(wordSize),
      label: target.label,
      name: target.label,
      role: target.role,
      kind: target.role,
      __forceVisible: true
    });
  });

  return out;
}

export function findValueByAddress(items, targetAddr, rsp) {
  const match = items.find((item) => resolveStackAddressBigInt(item, rsp) === targetAddr);
  if (!match) return '(unavailable)';
  return match.value ?? match.val ?? '(unavailable)';
}

export function chooseDisplayValue(primaryValue, fallbackValue) {
  if (primaryValue != null && primaryValue !== '(unavailable)' && primaryValue !== '??') {
    return primaryValue;
  }
  return fallbackValue ?? primaryValue ?? '(unavailable)';
}

export function isModifiedMatch(value) {
  const parsed = toBigIntAddr(value);
  if (parsed === null) return false;
  return BigInt.asUintN(32, parsed) === 0x43434343n;
}

export function toSafeNumber(addr, rsp) {
  if (rsp === null) return null;
  const delta = addr - rsp;
  if (delta < BigInt(Number.MIN_SAFE_INTEGER) || delta > BigInt(Number.MAX_SAFE_INTEGER)) {
    return null;
  }
  return Number(delta);
}

export function buildModelRegions(model, rbp, meta = {}) {
  if (rbp === null) return [];

  const regions = [];
  if (model && Array.isArray(model.locals)) {
    regions.push(...model.locals
      .map((local) => {
        const offset = typeof local?.offset === 'number' ? local.offset : null;
        if (offset === null) return null;
        const size = Number.isFinite(local?.size) && Number(local.size) > 0 ? Math.trunc(Number(local.size)) : 1;
        const start = rbp + BigInt(offset);
        const end = start + BigInt(Math.max(1, size));
        const role = local.name === 'modified'
          ? 'modified'
          : local.role === 'buffer'
          ? 'buffer'
          : local.role === 'arg'
          ? 'arg'
          : 'default';
        return {
          start,
          end,
          role,
          name: local.name ?? null,
          cType: local.cType ?? '',
          source: local.source ?? '',
          confidence: Number.isFinite(Number(local.confidence)) ? Number(local.confidence) : null,
          offset
        };
      })
      .filter(Boolean));
  }

  if (!regions.some((region) => region.role === 'buffer')) {
    const bufferOffset = Number.isFinite(Number(meta?.buffer_offset)) ? Math.trunc(Number(meta.buffer_offset)) : null;
    const bufferSize = Number.isFinite(Number(meta?.buffer_size)) && Number(meta.buffer_size) > 0
      ? Math.trunc(Number(meta.buffer_size))
      : null;
    if (bufferOffset !== null && bufferSize !== null) {
      const start = rbp + BigInt(bufferOffset);
      regions.push({
        start,
        end: start + BigInt(Math.max(1, bufferSize)),
        role: 'buffer',
        name: 'buffer',
        cType: 'char[]',
        source: 'meta',
        confidence: 0.75,
        offset: bufferOffset
      });
    }
  }

  const bufferRegion = regions.find((region) => region.role === 'buffer') ?? null;
  const modifiedRegion = regions.find((region) => region.role === 'modified') ?? null;
  if (
    bufferRegion
    && modifiedRegion
    && modifiedRegion.start > bufferRegion.end
  ) {
    regions.push({
      start: bufferRegion.end,
      end: modifiedRegion.start,
      role: 'buffer_gap',
      name: 'buffer_gap',
      cType: '',
      source: 'derived',
      confidence: null,
      offset: Number(bufferRegion.end - rbp)
    });
  }

  return regions.sort((a, b) => modelRolePriority(a.role) - modelRolePriority(b.role));
}

export function buildSemanticStackItems(analysis) {
  const slots = Array.isArray(analysis?.frame?.slots) ? analysis.frame.slots : [];
  if (!slots.length) return [];
  return slots.map((slot, index) => ({
    id: index,
    addr: slot.start ?? null,
    end: slot.end ?? null,
    pos: null,
    size: Number.isFinite(Number(slot.size)) ? Math.trunc(Number(slot.size)) : 1,
    value: slot.valueHex ?? slot.bytesHex ?? slot.valueDisplay ?? '??',
    valueDisplay: slot.valueDisplay ?? slot.valueHex ?? slot.bytesHex ?? '??',
    label: slot.label ?? `slot_${index}`,
    name: slot.label ?? `slot_${index}`,
    role: slot.role ?? 'unknown',
    semanticRole: slot.role ?? 'unknown',
    kind: slot.role ?? 'unknown',
    flags: Array.isArray(slot.flags) ? slot.flags : [],
    changed: Boolean(slot.changed),
    recentWrite: Boolean(slot.recentWrite),
    recentRead: Boolean(slot.recentRead),
    corrupted: Boolean(slot.corrupted),
    comment: slot.comment ?? '',
    source: slot.source ?? '',
    confidence: Number.isFinite(Number(slot.confidence)) ? Number(slot.confidence) : null,
    offsetFromBp: Number.isFinite(Number(slot.offsetFromBp)) ? Number(slot.offsetFromBp) : null,
    offsetFromBpHex: slot.offsetFromBpHex ?? null,
    offsetFromSp: Number.isFinite(Number(slot.offsetFromSp)) ? Number(slot.offsetFromSp) : null,
    offsetFromSpHex: slot.offsetFromSpHex ?? null,
    bytesHex: slot.bytesHex ?? '',
    ascii: slot.ascii ?? '',
    valueHex: slot.valueHex ?? null,
    pointerKind: slot.pointerKind ?? '',
    activePointers: Array.isArray(slot.activePointers) ? slot.activePointers : []
  }));
}

export function findModelRegionForItem(addr, itemSize, modelRegions) {
  if (addr === null || !Array.isArray(modelRegions) || !modelRegions.length) return null;
  const size = Number.isFinite(itemSize) && Number(itemSize) > 0 ? Math.trunc(Number(itemSize)) : 1;
  const itemEnd = addr + BigInt(Math.max(1, size));
  return modelRegions.find((region) => addr < region.end && itemEnd > region.start) ?? null;
}

export function modelRolePriority(role) {
  switch (role) {
    case 'modified': return 0;
    case 'buffer': return 1;
    case 'buffer_gap': return 2;
    case 'arg': return 3;
    default: return 4;
  }
}

export function buildSimpleSourceItems(sorted, context) {
  const {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    diagnostics = [],
    payloadText,
    payloadHex,
    spName,
    bpName
  } = context;

  const items = [];
  sorted.forEach((item, index) => {
    const key = buildStackKey(item, index);
    if (
      !item.__forceVisible &&
      options.showOnlyChanged &&
      options.changedKeys &&
      options.alwaysShowKeys &&
      !options.changedKeys.has(key) &&
      !options.alwaysShowKeys.has(key)
    ) {
      return;
    }

    const addr = resolveStackAddressBigInt(item, rsp);
    const modelRegion = findModelRegionForItem(addr, item.size, modelRegions);
    const semanticRole = resolveSemanticRole(
      item,
      addr,
      rbp,
      retAddrAddr,
      bufferStart,
      bufferEnd,
      analysisStackRoles,
      modelRegions
    );
    const visualRole = toVisualRole(semanticRole);
    const posValue = item.pos ?? item.posi ?? null;
    const offsets = buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName);
    const displayName = item.label ?? item.name ?? modelRegion?.name ?? (item.id !== undefined ? `#${item.id}` : '#?');
    const rawValue = item.valueDisplay ?? item.value ?? item.bytesHex ?? '??';
    const itemDiagnostics = diagnosticsForStackSlot(diagnostics, {
      addressLabel: addr !== null ? toHex(addr) : '',
      kind: semanticRole
    });
    const diagnosticFlags = itemDiagnostics.some((diagnostic) => (
      diagnostic.kind === 'return_address_corrupted'
      || diagnostic.kind === 'saved_bp_corrupted'
      || (diagnostic.kind === 'runtime_crash' && ['return_address', 'saved_bp'].includes(String(diagnostic.slot?.kind || '').toLowerCase()))
      || (['invalid_control_flow', 'fatal_crash', 'control_hijack'].includes(diagnostic.kind) && diagnostic.slot?.kind === 'return_address')
    ))
      ? ['corrupted']
      : [];

    items.push({
      key,
      technicalLabel: displayName,
      rawRole: item.role ?? item.kind ?? item.zone ?? item.type ?? semanticRole,
      semanticRole,
      visualRole,
      modelName: modelRegion?.name ?? '',
      modelRole: modelRegion?.role ?? '',
      modelType: modelRegion?.cType ?? '',
      modelSource: modelRegion?.source ?? '',
      modelConfidence: modelRegion?.confidence ?? null,
      size: item.size ?? 0,
      displayValue: String(rawValue),
      rawValue: String(rawValue),
      valueHex: item.valueHex ?? null,
      addressLabel: addr !== null ? toHex(addr) : '',
      offsetFromBp: Number.isFinite(Number(item.offsetFromBp))
        ? Number(item.offsetFromBp)
        : addr !== null && rbp !== null
        ? Number(addr - rbp)
        : null,
      offsetFromBpLabel: offsets.find((offset) => offset.text.startsWith(`${bpName} `))?.text ?? '',
      offsetFromSp: Number.isFinite(Number(item.offsetFromSp))
        ? Number(item.offsetFromSp)
        : addr !== null && rsp !== null
        ? Number(addr - rsp)
        : null,
      offsetFromSpLabel: offsets.find((offset) => offset.text.startsWith(`${spName} `))?.text ?? '',
      positionLabel: options.abstractMode ? (posValue !== null ? `Pos ${posValue}` : 'Pos ?') : '',
      flags: [...(Array.isArray(item.flags) ? item.flags : []), ...diagnosticFlags],
      diagnostics: itemDiagnostics,
      comment: item.comment ?? '',
      changed: Boolean(item.changed),
      recentWrite: Boolean(item.recentWrite),
      recentRead: Boolean(item.recentRead),
      payloadRelated: isPayloadRelatedItem(item, visualRole, payloadText, payloadHex),
      isAtSp: !options.abstractMode && addr !== null && rsp !== null && addr === rsp,
      isAtBp: !options.abstractMode && addr !== null && rbp !== null && addr === rbp,
      pointerKind: item.pointerKind ?? '',
      bytesHex: item.bytesHex ?? '',
      ascii: item.ascii ?? '',
      source: item.source ?? '',
      confidence: Number.isFinite(Number(item.confidence)) ? Number(item.confidence) : null,
      activePointers: Array.isArray(item.activePointers) ? item.activePointers : []
    });
  });

  return items;
}
