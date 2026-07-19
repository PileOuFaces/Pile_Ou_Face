/**
 * @file stackExpertView.js
 * @brief Expert mode — compact single-row stack frame rendering.
 * @details Reuses the same simplified view model items as frame mode.
 *          Inline detail expansion reuses the existing frame-slot CSS.
 *          buildExpertRowItems is pure and testable without DOM.
 */
import { buildSimplifiedStackViewModel } from './stackSimpleModel.js';
import { dom } from './dom.js';
import { renderStackEmptyState } from './stackEmptyState.js';

/**
 * Map simplified view model items to compact row descriptors.
 * Pure function — no DOM, fully testable.
 * @param {Array} items - output of buildSimplifiedStackViewModel().items
 * @returns {Array}
 */
export function buildExpertRowItems(items) {
  if (!Array.isArray(items)) return [];
  return items.map((slot) => {
    const kind = slot.kind || '';
    const isReturnAddress = kind === 'return_address';
    const isSavedBp = kind === 'saved_bp';
    const isCorrupted = hasExpertCorruptionSignal(slot);
    const isChanged = hasExpertChangedSignal(slot);
    const value = slot.valuePreview || slot.valueDisplay || slot.rawValue || slot.valueHex || '';

    return {
      key: slot.key,
      selectionKey: slot.selectionKey || slot.key,
      kind,
      name: slot.title || slot.name || '',
      offset: slot.subtitle || slot.offsetLabel || '',
      size: formatExpertSize(slot.size),
      offsetBand: slot.offsetBand || 'unknown',
      badges: buildExpertBadges(slot, {
        isReturnAddress,
        isSavedBp,
        isCorrupted,
        isChanged,
        value
      }),
      value,
      isReturnAddress,
      isSavedBp,
      isCorrupted,
      isChanged,
      isSensitive: Boolean(slot.isSensitive),
      diagnosticSeverity: slot.diagnosticSeverity || null,
      hasDiagnostic: Array.isArray(slot.diagnostics) && slot.diagnostics.length > 0,
      detailPayload: slot.detailPayload || null
    };
  });
}

export function buildExpertRiskSummary(rows) {
  const expertRows = Array.isArray(rows) ? rows : [];
  const changedRows = expertRows.filter((row) => row?.isChanged || rowHasBadge(row, 'CHANGED'));
  const returnRows = expertRows.filter((row) => row?.isReturnAddress || rowHasBadge(row, 'RET'));
  const baseRows = expertRows.filter((row) => row?.isSavedBp || rowHasBadge(row, 'RBP'));
  const returnAddressCorrupted = returnRows.some((row) => row?.isCorrupted || rowHasBadge(row, 'CORRUPT'));
  const savedBpCorrupted = baseRows.some((row) => row?.isCorrupted || rowHasBadge(row, 'CORRUPT'));
  const savedBpChanged = baseRows.some((row) => row?.isChanged || rowHasBadge(row, 'CHANGED'));
  const overflowDetected = expertRows.some((row) => rowHasBadge(row, 'OVERFLOW'));
  const userControlled = expertRows.some((row) => rowHasBadge(row, 'USER'));

  let severity = 'OK';
  if (returnAddressCorrupted || overflowDetected) {
    severity = 'DANGER';
  } else if (savedBpCorrupted || savedBpChanged || userControlled) {
    severity = 'WARNING';
  } else if (changedRows.length > 0) {
    severity = 'CHANGED';
  }

  const details = [];
  if (severity !== 'OK') {
    if (returnAddressCorrupted) details.push('RET corrupted');
    if (savedBpCorrupted) details.push('RBP corrupted');
    if (!savedBpCorrupted && savedBpChanged) details.push('saved rbp changed');
    if (overflowDetected) details.push('overflow detected');
    if (changedRows.length > 0) {
      details.push(`${changedRows.length} modified slot${changedRows.length === 1 ? '' : 's'}`);
    }
    if (userControlled) details.push('USER-controlled slot');
  }

  return {
    severity,
    changedCount: changedRows.length,
    returnAddressCorrupted,
    savedBpCorrupted,
    overflowDetected,
    userControlled,
    details
  };
}

/**
 * Render expert compact rows into dom.stack.
 * @param {object} frameModel
 * @param {{ selectedSlotKey?: string, onSelectSlotKey?: Function, onJumpToStep?: Function }} options
 */
export function renderExpertFrameWorkspace(frameModel, { selectedSlotKey, onSelectSlotKey, onJumpToStep } = {}) {
  if (!dom.stack) return;
  dom.stack.replaceChildren();

  const simpleViewModel = buildSimplifiedStackViewModel({
    frameModel,
    detailModel: { key: selectedSlotKey || '' },
    statusText: frameModel?.statusText || ''
  });
  const rows = buildExpertRowItems(simpleViewModel.items || []);

  if (!rows.length) {
    renderExpertEmptyState(frameModel, { onJumpToStep });
    return;
  }

  const summary = buildExpertRiskSummary(rows);
  if (summary.severity !== 'OK') {
    dom.stack.appendChild(buildExpertRiskSummaryElement(summary));
  }

  rows.forEach((row, index) => {
    const isExpanded = row.selectionKey === selectedSlotKey;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = [
      'expert-row',
      `frame-slot-${row.offsetBand}`,
      row.isReturnAddress ? 'is-return' : '',
      row.isSavedBp ? 'is-base' : '',
      row.isSensitive ? 'is-sensitive' : '',
      row.isCorrupted ? 'is-corrupted' : '',
      row.diagnosticSeverity ? `has-diagnostic-${row.diagnosticSeverity}` : '',
      row.hasDiagnostic ? 'has-diagnostic' : '',
      row.isChanged ? 'is-changed' : '',
      isExpanded ? 'is-expanded is-selected' : ''
    ].filter(Boolean).join(' ');
    btn.setAttribute('aria-pressed', isExpanded ? 'true' : 'false');

    const compact = document.createElement('div');
    compact.className = 'expert-row-compact';

    const offset = document.createElement('span');
    offset.className = 'expert-row-offset';
    offset.textContent = row.offset || '?';
    compact.appendChild(offset);

    const name = document.createElement('span');
    name.className = [
      'expert-row-name',
      (row.isReturnAddress || row.isSavedBp) ? 'is-control' : ''
    ].filter(Boolean).join(' ');
    name.textContent = row.name;
    compact.appendChild(name);

    const size = document.createElement('span');
    size.className = 'expert-row-size';
    size.textContent = row.size || '?';
    compact.appendChild(size);

    const badgesWrap = document.createElement('span');
    badgesWrap.className = 'expert-row-badges';
    row.badges.slice(0, 4).forEach((text) => {
      const badge = document.createElement('span');
      badge.className = [
        'expert-row-badge',
        expertBadgeClassName(text)
      ].filter(Boolean).join(' ');
      badge.textContent = text;
      badgesWrap.appendChild(badge);
    });
    compact.appendChild(badgesWrap);

    const val = document.createElement('span');
    val.className = 'expert-row-value';
    val.textContent = row.value || '';
    compact.appendChild(val);

    btn.appendChild(compact);
    btn.appendChild(buildInlineDetails(row, isExpanded));

    if (typeof onSelectSlotKey === 'function') {
      btn.addEventListener('click', () => onSelectSlotKey(isExpanded ? null : row.selectionKey));
    }

    setTimeout(() => btn.classList.add('visible'), 35 * index);
    dom.stack.appendChild(btn);

    if (isExpanded) {
      requestAnimationFrame(() => {
        window.setTimeout(() => btn.scrollIntoView({ block: 'center', behavior: 'smooth' }), 90);
      });
    }
  });
}

function renderExpertEmptyState(frameModel, { onJumpToStep } = {}) {
  return renderStackEmptyState(dom.stack, frameModel, { documentRef: document, onJumpToStep });
}

function buildExpertRiskSummaryElement(summary) {
  const wrapper = document.createElement('div');
  wrapper.className = [
    'expert-risk-summary',
    `expert-risk-summary-${String(summary?.severity || 'OK').toLowerCase()}`
  ].join(' ');

  const severity = document.createElement('span');
  severity.className = 'expert-risk-summary-severity';
  severity.textContent = summary?.severity || 'OK';
  wrapper.appendChild(severity);

  (Array.isArray(summary?.details) ? summary.details : []).forEach((detail) => {
    const item = document.createElement('span');
    item.className = 'expert-risk-summary-item';
    item.textContent = detail;
    wrapper.appendChild(item);
  });

  return wrapper;
}

function buildExpertBadges(slot, state) {
  const badges = [];
  const existingBadges = Array.isArray(slot?.badges) ? slot.badges : [];
  const add = (badge) => {
    const normalized = normalizeExpertBadge(badge);
    if (normalized && !badges.includes(normalized)) badges.push(normalized);
  };

  if (state.isCorrupted) add('CORRUPT');
  if (hasExpertOverflowSignal(slot, existingBadges)) add('OVERFLOW');
  if (state.isChanged) add('CHANGED');
  if (state.isReturnAddress) add('RET');
  if (state.isSavedBp) add('RBP');
  if (hasExpertUserSignal(slot, existingBadges)) add('USER');
  add(resolveExpertPointerBadge(slot, state.value));

  existingBadges.forEach(add);
  return badges.slice(0, 6);
}

function rowHasBadge(row, badge) {
  return (Array.isArray(row?.badges) ? row.badges : [])
    .some((entry) => normalizeExpertBadge(entry) === badge);
}

function hasExpertCorruptionSignal(slot) {
  if (slot?.diagnosticCorrupted || slot?.corrupted) return true;
  if (hasFlag(slot, 'corrupted')) return true;
  return (Array.isArray(slot?.badges) ? slot.badges : []).some((badge) => /corrupt|corrompu/i.test(String(badge || '')));
}

function hasExpertChangedSignal(slot) {
  if (slot?.isChanged || slot?.changed || slot?.recentWrite || slot?.kind === 'modified') return true;
  if (hasFlag(slot, 'changed') || hasFlag(slot, 'recent_write')) return true;
  return (Array.isArray(slot?.badges) ? slot.badges : []).some((badge) => /changed|write/i.test(String(badge || '')));
}

function hasExpertOverflowSignal(slot, existingBadges) {
  if ((Array.isArray(existingBadges) ? existingBadges : []).some((badge) => /overflow/i.test(String(badge || '')))) {
    return true;
  }
  return (Array.isArray(slot?.diagnostics) ? slot.diagnostics : [])
    .some((diagnostic) => String(diagnostic?.kind || '').toLowerCase() === 'buffer_overflow');
}

function hasExpertUserSignal(slot, existingBadges) {
  if (slot?.payloadRelated === true) return true;
  if (hasFlag(slot, 'payload')) return true;
  return (Array.isArray(existingBadges) ? existingBadges : []).some((badge) => /payload|user/i.test(String(badge || '')));
}

function resolveExpertPointerBadge(slot, value) {
  const pointerKind = String(slot?.pointerKind || '').trim().toLowerCase();
  const pointerMap = {
    code: 'PTR:TEXT',
    text: 'PTR:TEXT',
    stack: 'PTR:STACK',
    heap: 'PTR:HEAP',
    libc: 'PTR:LIBC',
    null: 'PTR:NULL'
  };
  if (!pointerMap[pointerKind]) return '';
  const rawValue = String(value || '').trim();
  if (!looksLikeExpertPointer(rawValue) && pointerKind !== 'null') return '';
  return pointerMap[pointerKind];
}

function looksLikeExpertPointer(value) {
  return /^0x[0-9a-f]+$/i.test(String(value || '').trim());
}

function hasFlag(slot, flag) {
  return (Array.isArray(slot?.flags) ? slot.flags : [])
    .some((entry) => String(entry || '').toLowerCase() === flag);
}

function normalizeExpertBadge(badge) {
  const raw = String(badge || '').trim();
  if (!raw) return '';
  const upper = raw.toUpperCase();
  if (upper === 'CORROMPU' || upper === 'CORRUPTED') return 'CORRUPT';
  if (upper === 'WRITE') return 'CHANGED';
  if (upper === 'PAYLOAD') return 'USER';
  if (upper === 'STACK' || upper === 'PTR_STACK') return 'PTR:STACK';
  if (upper === 'TEXT' || upper === 'CODE' || upper === 'PTR_TEXT') return 'PTR:TEXT';
  if (upper === 'HEAP' || upper === 'PTR_HEAP') return 'PTR:HEAP';
  if (upper === 'LIBC' || upper === 'PTR_LIBC') return 'PTR:LIBC';
  if (upper === 'NULL' || upper === 'PTR_NULL') return 'PTR:NULL';
  return upper;
}

function expertBadgeClassName(badge) {
  const key = String(badge || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return key ? `expert-row-badge-${key}` : '';
}

function formatExpertSize(size) {
  const numeric = Number(size);
  if (!Number.isFinite(numeric) || numeric <= 0) return '';
  return `${Math.trunc(numeric)}B`;
}

function buildInlineDetails(row, isExpanded) {
  const wrapper = document.createElement('div');
  wrapper.className = 'frame-slot-inline-details';
  wrapper.setAttribute('aria-hidden', isExpanded ? 'false' : 'true');

  const body = document.createElement('div');
  body.className = 'frame-slot-inline-details-body';

  if (row.detailPayload?.subtitle) {
    const subtitle = document.createElement('div');
    subtitle.className = 'frame-slot-inline-subtitle';
    subtitle.textContent = row.detailPayload.subtitle;
    body.appendChild(subtitle);
  }

  const rowsEl = document.createElement('div');
  rowsEl.className = 'frame-slot-inline-rows';
  (Array.isArray(row.detailPayload?.rows) ? row.detailPayload.rows : []).forEach((r) => {
    const item = document.createElement('div');
    item.className = 'stack-detail-row';
    const label = document.createElement('div');
    label.className = 'stack-detail-label';
    label.textContent = r.label;
    const value = document.createElement('div');
    value.className = 'stack-detail-value';
    value.textContent = r.value;
    item.appendChild(label);
    item.appendChild(value);
    rowsEl.appendChild(item);
  });
  body.appendChild(rowsEl);
  wrapper.appendChild(body);
  return wrapper;
}
