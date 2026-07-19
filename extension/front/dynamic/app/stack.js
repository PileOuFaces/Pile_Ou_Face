/**
 * @file stack.js
 * @brief Rendu de la pile pour le visualiseur.
 * @details Construit les blocs, roles, legendaire et repere RBP.
 */
import { dom } from './dom.js';
import { diagnosticsForStackSlot } from './diagnostics.js';
import { addrKey, readPointer, readU32, toBigIntAddr } from './memory.js';
import { buildSimplifiedStackViewModel } from './stackSimpleModel.js';
import { buildStackWorkspaceModel } from './stackWorkspaceModel.js';
import { isFrameReadyAtCurrentStep } from './stackWorkspaceCore.js';
import { renderStackEmptyState } from './stackEmptyState.js';
import { toHex } from './utils.js';

import {
  ROLE_CONFIG,
  buildAxisLabel,
  buildHumanSubtitle,
  buildItemTooltip,
  buildModelRegions,
  buildOffsets,
  buildSemanticStackItems,
  buildSimpleSourceItems,
  buildStackKey,
  compareStackItemsByAddrDesc,
  findModelRegionForItem,
  getStackAddrRange,
  injectControlSlots,
  isModifiedMatch,
  isPayloadRelatedItem,
  resolveSemanticRole,
  resolveStackAddressBigInt,
  toVisualRole
} from './stack/stackFormatting.js';
import {
  isStackFrameDebugEnabled,
  renderStackFrameDebugPanel
} from './stack/stackDiagnosticsView.js';
import { renderExpertFrameWorkspace } from './stackExpertView.js';

/**
 * @brief Rend la pile sous forme de blocs.
 * @param stackItems Entrees de pile.
 * @param regMap Mapping de registres.
 * @param meta Metadonnees de trace.
 * @param options Options de rendu.
 */
export function renderStack(stackItems, regMap, meta, options = {}) {
  dom.stack.replaceChildren();
  if (dom.stackFunctions) dom.stackFunctions.replaceChildren();
  if (dom.stack) {
    const isAdvancedMode = options.displayMode === 'advanced';
    const isExpertFrameMode = !isAdvancedMode && options.stackPanelMode === 'expert';
    dom.stack.classList.toggle('stack-simple-list', !isAdvancedMode);
    dom.stack.classList.toggle('stack-advanced-list', isAdvancedMode);
    dom.stack.classList.toggle('stack-expert-list', isExpertFrameMode);
  }
  if (dom.stackWorkspace) {
    dom.stackWorkspace.classList.toggle('is-advanced', options.displayMode === 'advanced');
  }

  const displayMode = options.displayMode === 'advanced' ? 'advanced' : 'frame';
  updateStackChrome(displayMode, options, '', false);

  // Resolve addresses and display context.
  const analysis = options.analysis && typeof options.analysis === 'object' ? options.analysis : null;
  const diagnostics = Array.isArray(options.diagnostics) ? options.diagnostics : [];
  const mcp = options.mcp && typeof options.mcp === 'object' ? options.mcp : null;
  const model = mcp?.model && Array.isArray(mcp.model.locals) ? mcp.model : null;
  const analysisStackRoles = analysis?.highlights?.stack?.rolesByAddr ?? {};
  const is64 = regMap.rsp != null || regMap.rbp != null;
  const wordSize = is64 ? 8n : 4n;
  const rsp = toBigIntAddr(regMap.rsp ?? regMap.esp);
  const rbp = toBigIntAddr(regMap.rbp ?? regMap.ebp);
  const analysisSavedBpAddr = toBigIntAddr(analysis?.control?.savedBpAddr);
  const analysisRetAddrAddr = toBigIntAddr(analysis?.control?.retAddrAddr);
  const payloadText = String(options.payloadText || '').trim();
  const payloadHex = String(options.payloadHex || '').trim();
  const savedBpAddr = analysisSavedBpAddr ?? rbp;
  const retAddrAddr = analysisRetAddrAddr ?? (rbp != null ? rbp + wordSize : null);
  const spName = is64 ? 'RSP' : 'ESP';
  const bpName = is64 ? 'RBP' : 'EBP';
  void meta;
  const analysisBufferStart = toBigIntAddr(analysis?.buffer?.start);
  const analysisBufferEnd = toBigIntAddr(analysis?.buffer?.end);
  const semanticSlots = buildSemanticStackItems(analysis);
  // Same Evidence-readiness check the workspace Core uses (frame pointer
  // set up AND frame allocated at this step) -- computed here, before
  // sourceSlots exist yet, from analysis + the analysis-derived
  // semanticSlots (never from model.locals itself).
  const frameIsReady = isFrameReadyAtCurrentStep(analysis, semanticSlots);
  const modelRegions = buildModelRegions(model, rbp, meta, frameIsReady);
  const bufferRegion = modelRegions.find((region) => region.role === 'buffer') ?? null;
  const modifiedRegion = modelRegions.find((region) => region.role === 'modified') ?? null;
  const bufferStart = bufferRegion?.start ?? analysisBufferStart;
  const bufferEnd = bufferRegion?.end ?? analysisBufferEnd;
  const memorySource = { memoryMap: options.memoryMap, stackItems, rsp };
  const modifiedAddr = modifiedRegion?.start ?? (rbp != null ? rbp - 4n : null);
  const modifiedValueBig = modifiedAddr !== null ? readU32(modifiedAddr, memorySource) : null;
  const modifiedValue = modifiedValueBig !== null
    ? `0x${modifiedValueBig.toString(16).padStart(8, '0')}`
    : '(unavailable)';
  const retRawValueBig = retAddrAddr !== null ? readPointer(retAddrAddr, wordSize, memorySource) : null;
  const retValueBig = retRawValueBig === 0n ? null : retRawValueBig;
  const retValue = retValueBig !== null ? `0x${retValueBig.toString(16)}` : '(unavailable)';

  if (options.debugMemory && retAddrAddr !== null) {
    console.log('[RET]', {
      bp: rbp !== null ? addrKey(rbp) : null,
      retSlot: addrKey(retAddrAddr),
      lookupKey: addrKey(retAddrAddr),
      foundBytes: retRawValueBig !== null,
      found: retValueBig !== null
    });
  }
  const stackWithControl = semanticSlots.length
    ? semanticSlots
    : injectControlSlots(stackItems, {
      rsp,
      savedBpAddr,
      retAddrAddr,
      wordSize,
      retValue,
      modifiedAddr,
      modifiedValue
    });

  const sorted = Array.isArray(stackWithControl)
    ? [...stackWithControl].sort((a, b) => compareStackItemsByAddrDesc(a, b, rsp))
    : [];
  const sourceSlots = buildSimpleSourceItems(sorted, {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    diagnostics,
    payloadText,
    payloadHex,
    spName,
    bpName
  });
  const workspaceModel = buildStackWorkspaceModel({
    slots: sourceSlots,
    snapshots: options.snapshots,
    meta,
    currentStep: options.currentStep,
    selectedFunction: options.selectedFunction,
    selectedSlotKey: options.selectedSlotKey,
    snapshot: options.snapshot,
    analysis,
    diagnostics,
    mcp
  });
  updateStackWorkspaceChrome(workspaceModel, {
    onClearSelectedFunction: options.onClearSelectedFunction
  });

  if (!workspaceModel?.hasFunctionSelection) {
    updateStackChrome(displayMode, options, '', false);
    hideDetailPanel();
    renderFunctionList(workspaceModel.functionList, {
      onSelectFunction: options.onSelectFunction
    });
    return workspaceModel;
  }

  if (displayMode === 'frame') {
    updateStackChrome(displayMode, options, workspaceModel.statusText, true);
    if (options.stackPanelMode === 'expert') {
      renderExpertFrameWorkspace(workspaceModel.frameModel, {
        selectedSlotKey: workspaceModel.selectedSlotKey,
        onSelectSlotKey: options.onSelectSlotKey,
        onJumpToStep: options.onJumpToStep
      });
      renderDetailPanel(null, { onCloseDetail: options.onSelectSlotKey });
    } else {
      renderFrameWorkspace(workspaceModel.frameModel, {
        selectedSlotKey: workspaceModel.selectedSlotKey,
        onSelectSlotKey: options.onSelectSlotKey,
        onJumpToStep: options.onJumpToStep
      });
      hideDetailPanel();
    }
    return workspaceModel;
  }

  updateStackChrome(displayMode, options, '', true);
  hideDetailPanel();
  renderAdvancedStack(sorted, {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    diagnostics,
    payloadText,
    payloadHex,
    spName,
    bpName
  });
  return workspaceModel;
}

function updateStackWorkspaceChrome(workspaceModel, { onClearSelectedFunction } = {}) {
  const panelMode = workspaceModel?.panelMode === 'frame' ? 'frame' : 'functions';
  if (dom.stackWorkspace) {
    dom.stackWorkspace.dataset.mode = panelMode;
  }
  if (dom.stackWorkspaceTitle) {
    dom.stackWorkspaceTitle.textContent = workspaceModel?.panelTitle || '.text';
  }
  if (dom.stackWorkspaceSubtitle) {
    dom.stackWorkspaceSubtitle.textContent = workspaceModel?.panelSubtitle || '';
  }
  if (dom.stackWorkspaceBack) {
    const canGoBack = panelMode === 'frame' && typeof onClearSelectedFunction === 'function';
    dom.stackWorkspaceBack.hidden = !canGoBack;
    dom.stackWorkspaceBack.onclick = canGoBack ? () => onClearSelectedFunction() : null;
  }
  if (dom.stackFunctions) {
    dom.stackFunctions.hidden = panelMode !== 'functions';
  }
  if (dom.stack) {
    dom.stack.hidden = panelMode !== 'frame';
  }
  if (dom.stackDetail && panelMode !== 'frame') {
    hideDetailPanel();
  }
}

function renderAdvancedStack(sorted, context) {
  const {
    options,
    rsp,
    rbp,
    retAddrAddr,
    bufferStart,
    bufferEnd,
    analysisStackRoles,
    modelRegions,
    diagnostics,
    payloadText,
    payloadHex,
    spName,
    bpName
  } = context;

  if (!Array.isArray(sorted) || !sorted.length) {
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Pile vide a cette etape.';
    dom.stack.appendChild(status);
    return;
  }

  const showAxis = !options.abstractMode;
  const axis = document.createElement('div');
  axis.className = 'stack-axis';
  if (showAxis) {
    const addrRange = getStackAddrRange(sorted, rsp);
    const label = document.createElement('span');
    label.className = 'stack-axis-label';
    label.textContent = buildAxisLabel(rbp, addrRange, bpName);
    axis.appendChild(label);
  }

  let axisInserted = false;
  if (showAxis && rbp === null) {
    dom.stack.appendChild(axis);
    axisInserted = true;
  }

  let displayIndex = 0;
  sorted.forEach((item, index) => {
    const itemKey = buildStackKey(item, index);
    if (
      !item.__forceVisible &&
      options.showOnlyChanged &&
      options.changedKeys &&
      options.alwaysShowKeys &&
      !options.changedKeys.has(itemKey) &&
      !options.alwaysShowKeys.has(itemKey)
    ) {
      return;
    }
    const div = document.createElement('div');
    const addr = resolveStackAddressBigInt(item, rsp);
    if (showAxis && !axisInserted && rbp !== null && addr !== null && addr < rbp) {
      dom.stack.appendChild(axis);
      axisInserted = true;
    }

    const tags = [];
    const modelRegion = findModelRegionForItem(addr, item.size, modelRegions);
    if (!options.abstractMode) {
      if (Array.isArray(item.activePointers)) {
        item.activePointers.forEach((pointerName) => {
          const tagText = String(pointerName || '').toUpperCase();
          if (tagText && !tags.includes(tagText)) tags.push(tagText);
        });
      }
      if (addr !== null && rsp !== null && addr === rsp) tags.push('SP');
      if (addr !== null && rbp !== null && addr === rbp) tags.push('BP');
      if (modelRegion?.role === 'arg') tags.push('ARG');
      if (modelRegion?.role === 'buffer_gap') tags.push('TO MOD');
      if (addr !== null && bufferStart !== null && bufferEnd !== null && addr >= bufferStart && addr < bufferEnd) {
        tags.push('BUF');
      }
    }

    const role = options.abstractMode
      ? 'default'
      : resolveSemanticRole(item, addr, rbp, retAddrAddr, bufferStart, bufferEnd, analysisStackRoles, modelRegions);
    const itemDiagnostics = diagnosticsForStackSlot(diagnostics, {
      addressLabel: addr !== null ? toHex(addr) : '',
      kind: role
    });
    const corruptedByDiagnostic = itemDiagnostics.some((diagnostic) => (
      diagnostic.kind === 'return_address_corrupted'
      || diagnostic.kind === 'saved_bp_corrupted'
      || (diagnostic.kind === 'runtime_crash' && ['return_address', 'saved_bp'].includes(String(diagnostic.slot?.kind || '').toLowerCase()))
      || (['invalid_control_flow', 'fatal_crash', 'control_hijack'].includes(diagnostic.kind) && diagnostic.slot?.kind === 'return_address')
    ));
    const visualRole = toVisualRole(role);
    const roleConfig = ROLE_CONFIG[visualRole] || ROLE_CONFIG.default;
    div.className = `block ${roleConfig.className}`;
    if (item.changed || (options.changedKeys && options.changedKeys.has(itemKey))) div.classList.add('block-changed');
    if (corruptedByDiagnostic) div.classList.add('block-corrupted');
    if (Array.isArray(item.flags) && item.flags.includes('recent_write')) div.classList.add('block-write');
    if (Array.isArray(item.flags) && item.flags.includes('recent_read')) div.classList.add('block-read');
    div.title = buildItemTooltip(item, visualRole);

    const addrLabel = addr !== null ? toHex(addr) : '??';
    const posValue = item.pos ?? item.posi ?? null;
    const displayName = item.label ?? item.name ?? modelRegion?.name ?? (item.id !== undefined ? `#${item.id}` : '#?');
    const subtitleText = buildHumanSubtitle(item, visualRole, payloadText, payloadHex, modelRegion);
    const offsets = buildOffsets(item, addr, rsp, rbp, posValue, spName, bpName);
    const modifiedOk = visualRole === 'modified' && isModifiedMatch(item.value);
    const payloadRelated = isPayloadRelatedItem(item, visualRole, payloadText, payloadHex);
    if (modifiedOk) div.classList.add('role-modified-ok');
    if (payloadRelated) {
      div.classList.add('block-payload');
      if (!tags.includes('PAYLOAD')) tags.push('PAYLOAD');
    }
    if (corruptedByDiagnostic && !tags.includes('CORROMPU')) tags.push('CORROMPU');

    const header = document.createElement('div');
    header.className = 'block-header';
    const titleWrap = document.createElement('div');
    titleWrap.className = 'block-title-wrap';
    const title = document.createElement('span');
    title.className = 'block-title';
    title.textContent = displayName;
    titleWrap.appendChild(title);
    if (subtitleText) {
      const subtitle = document.createElement('span');
      subtitle.className = 'block-subtitle';
      subtitle.textContent = subtitleText;
      titleWrap.appendChild(subtitle);
    }
    header.appendChild(titleWrap);
    if (!options.abstractMode) {
      const roleTag = document.createElement('span');
      roleTag.className = `block-tag ${roleConfig.tagClass}`;
      roleTag.textContent = modifiedOk ? `${roleConfig.label} • OK` : roleConfig.label;
      header.appendChild(roleTag);
    }

    const body = document.createElement('div');
    body.className = 'block-body';
    const valueEl = document.createElement('div');
    valueEl.className = 'block-value';
    body.appendChild(valueEl);
    const metaEl = document.createElement('div');
    metaEl.className = 'block-meta';
    if (options.abstractMode) {
      const offsetEl = document.createElement('div');
      offsetEl.className = 'block-offset primary';
      offsetEl.textContent = posValue !== null ? `Pos ${posValue}` : 'Pos ?';
      metaEl.appendChild(offsetEl);
    } else if (offsets.length) {
      offsets.forEach((offset) => {
        const offsetEl = document.createElement('div');
        offsetEl.className = [
          'block-offset',
          offset.primary ? 'primary' : '',
          offset.secondary ? 'secondary' : ''
        ].filter(Boolean).join(' ');
        offsetEl.textContent = offset.text;
        if (offset.tooltip) offsetEl.title = offset.tooltip;
        metaEl.appendChild(offsetEl);
      });
    } else {
      const offsetEl = document.createElement('div');
      offsetEl.className = 'block-offset primary';
      offsetEl.textContent = 'Offset non fourni';
      metaEl.appendChild(offsetEl);
    }
    const sizeEl = document.createElement('div');
    sizeEl.className = 'block-offset';
    sizeEl.textContent = `Taille: ${item.size ?? 0} bytes`;
    metaEl.appendChild(sizeEl);
    body.appendChild(metaEl);

    const footer = document.createElement('div');
    footer.className = 'block-footer';
    const addrEl = document.createElement('span');
    addrEl.className = 'block-addr';
    addrEl.textContent = options.abstractMode ? 'pile abstraite' : `addr ${addrLabel}`;
    footer.appendChild(addrEl);
    if (tags.length) {
      const tagsEl = document.createElement('span');
      tagsEl.className = 'block-tags';
      tags.forEach((tagText) => {
        const tagEl = document.createElement('span');
        tagEl.className = 'tag';
        tagEl.textContent = tagText;
        tagsEl.appendChild(tagEl);
      });
      footer.appendChild(tagsEl);
    }

    div.appendChild(header);
    div.appendChild(body);
    div.appendChild(footer);

    const rawValue = item.valueDisplay ?? item.value ?? item.bytesHex ?? '??';
    const jumpTarget = typeof options.resolveCodeJumpTarget === 'function'
      ? options.resolveCodeJumpTarget(rawValue)
      : null;
    valueEl.textContent = String(rawValue);
    if (rawValue === '(unavailable)' || rawValue === '??') {
      valueEl.classList.add('block-value-unavailable');
    } else if (jumpTarget && typeof options.onCodeAddressClick === 'function') {
      valueEl.classList.add('block-value-link');
      valueEl.title = 'Adresse code: cliquer pour aller dans le panneau ASM.';
      valueEl.addEventListener('click', () => options.onCodeAddressClick(jumpTarget));
    } else {
      const maybeAddr = toBigIntAddr(rawValue);
      if (maybeAddr !== null) valueEl.title = 'Adresse stack/data: pas de saut ASM.';
    }

    setTimeout(() => {
      div.classList.add('visible');
    }, 60 * displayIndex);

    displayIndex += 1;
    dom.stack.appendChild(div);
  });

  if (showAxis && !axisInserted) dom.stack.appendChild(axis);
}

function renderFunctionList(functionList, { onSelectFunction } = {}) {
  if (!dom.stackFunctions) return;
  dom.stackFunctions.replaceChildren();
  const items = Array.isArray(functionList) ? functionList : [];
  if (!items.length) {
    const empty = document.createElement('div');
    empty.className = 'stack-empty';
    empty.textContent = 'Aucune fonction dans la trace.';
    dom.stackFunctions.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = [
      'stack-function-item',
      item.isSelected ? 'is-selected' : '',
      item.isCurrent ? 'is-current' : ''
    ].filter(Boolean).join(' ');
    button.setAttribute('aria-pressed', item.isSelected ? 'true' : 'false');

    const name = document.createElement('div');
    name.className = 'stack-function-name';
    name.textContent = `${item.displayName}()`;
    button.appendChild(name);

    const meta = document.createElement('div');
    meta.className = 'stack-function-meta';
    const bits = [];
    if (item.addressLabel) bits.push(item.addressLabel);
    if (item.stepCount) bits.push(`${item.stepCount} step${item.stepCount > 1 ? 's' : ''}`);
    meta.textContent = bits.join(' • ') || (item.sourceBacked ? 'non executee' : `step ${item.firstStep}`);
    button.appendChild(meta);

    if (typeof onSelectFunction === 'function') {
      button.addEventListener('click', () => onSelectFunction(item.displayName));
    }

    dom.stackFunctions.appendChild(button);
  });
}

function renderFrameWorkspace(frameModel, { selectedSlotKey, onSelectSlotKey, onJumpToStep } = {}) {
  if (!dom.stack) return;
  dom.stack.replaceChildren();

  const simpleViewModel = buildSimplifiedStackViewModel({
    frameModel,
    detailModel: { key: selectedSlotKey || '' },
    statusText: frameModel?.statusText || ''
  });
  const entries = Array.isArray(simpleViewModel?.items) ? simpleViewModel.items : [];
  const spMarker = frameModel?.spMarker || null;
  if (spMarker?.register) {
    const marker = document.createElement('div');
    marker.className = 'stack-pointer-marker';

    const label = document.createElement('div');
    label.className = 'stack-pointer-label';
    label.textContent = spMarker.register;
    marker.appendChild(label);

    if (spMarker.addressLabel) {
      const address = document.createElement('div');
      address.className = 'stack-pointer-address';
      address.textContent = spMarker.addressLabel;
      marker.appendChild(address);
    }

    dom.stack.appendChild(marker);
  }

  if (!entries.length) {
    renderFrameEmptyState(frameModel, { onJumpToStep });
    if (isStackFrameDebugEnabled()) {
      renderStackFrameDebugPanel(dom.stack, frameModel);
    }
    return;
  }

  entries.forEach((slot, index) => {
    const selectionKey = slot.selectionKey || slot.key;
    const isExpanded = selectionKey === selectedSlotKey;
    const button = document.createElement('button');
    button.type = 'button';
    button.className = [
      'frame-slot',
      `frame-slot-${slot.offsetBand || 'unknown'}`,
      slot.kind === 'return_address' ? 'is-return' : '',
      slot.kind === 'saved_bp' ? 'is-base' : '',
      slot.isSensitive ? 'is-sensitive' : '',
      slot.diagnosticCorrupted ? 'is-corrupted' : '',
      slot.diagnosticSeverity ? `has-diagnostic-${slot.diagnosticSeverity}` : '',
      Array.isArray(slot.diagnostics) && slot.diagnostics.length ? 'has-diagnostic' : '',
      isExpanded ? 'is-expanded' : '',
      isExpanded ? 'is-selected' : ''
    ].filter(Boolean).join(' ');
    button.setAttribute('aria-pressed', isExpanded ? 'true' : 'false');
    button.title = buildFrameSlotTooltip(slot);

    const summary = document.createElement('div');
    summary.className = 'frame-slot-summary';

    const main = document.createElement('div');
    main.className = 'frame-slot-main';

    const name = document.createElement('div');
    name.className = 'frame-slot-name';
    name.textContent = slot.title || slot.name;
    main.appendChild(name);

    const offset = document.createElement('div');
    offset.className = 'frame-slot-offset';
    offset.textContent = slot.subtitle || slot.offsetLabel || 'offset inconnu';
    main.appendChild(offset);

    summary.appendChild(main);

    const side = document.createElement('div');
    side.className = 'frame-slot-side';

    const badges = Array.isArray(slot.badges) ? slot.badges : [];
    badges.slice(0, 2).forEach((badgeText) => {
      const badge = document.createElement('span');
      badge.className = 'frame-slot-badge';
      badge.textContent = badgeText;
      side.appendChild(badge);
    });

    const chevron = document.createElement('span');
    chevron.className = 'frame-slot-chevron';
    chevron.setAttribute('aria-hidden', 'true');
    chevron.textContent = '▾';
    side.appendChild(chevron);

    summary.appendChild(side);
    button.appendChild(summary);
    button.appendChild(renderInlineFrameDetails(slot, isExpanded));

    if (typeof onSelectSlotKey === 'function') {
      button.addEventListener('click', () => onSelectSlotKey(isExpanded ? null : selectionKey));
    }

    setTimeout(() => {
      button.classList.add('visible');
    }, 35 * index);

    dom.stack.appendChild(button);

    if (isExpanded) {
      requestAnimationFrame(() => {
        window.setTimeout(() => {
          button.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }, 90);
      });
    }
  });

  if (isStackFrameDebugEnabled()) {
    renderStackFrameDebugPanel(dom.stack, frameModel);
  }
}

function renderFrameEmptyState(frameModel, { onJumpToStep } = {}) {
  return renderStackEmptyState(dom.stack, frameModel, { documentRef: document, onJumpToStep });
}

function buildFrameSlotTooltip(slot) {
  return [
    slot?.title || slot?.name,
    slot?.subtitle || slot?.offsetLabel,
    slot?.kind,
    slot?.address,
    slot?.diagnostic?.message
  ].filter(Boolean).join(' • ');
}

function renderInlineFrameDetails(slot, isExpanded) {
  const wrapper = document.createElement('div');
  wrapper.className = 'frame-slot-inline-details';
  wrapper.setAttribute('aria-hidden', isExpanded ? 'false' : 'true');

  const body = document.createElement('div');
  body.className = 'frame-slot-inline-details-body';

  if (slot?.detailPayload?.subtitle) {
    const subtitle = document.createElement('div');
    subtitle.className = 'frame-slot-inline-subtitle';
    subtitle.textContent = slot.detailPayload.subtitle;
    body.appendChild(subtitle);
  }

  const rows = document.createElement('div');
  rows.className = 'frame-slot-inline-rows';
  (Array.isArray(slot?.detailPayload?.rows) ? slot.detailPayload.rows : []).forEach((row) => {
    const item = document.createElement('div');
    item.className = 'stack-detail-row';

    const label = document.createElement('div');
    label.className = 'stack-detail-label';
    label.textContent = row.label;
    item.appendChild(label);

    const value = document.createElement('div');
    value.className = 'stack-detail-value';
    value.textContent = row.value;
    item.appendChild(value);

    rows.appendChild(item);
  });
  body.appendChild(rows);
  wrapper.appendChild(body);
  return wrapper;
}

function renderDetailPanel(detailModel, { onCloseDetail, emptyText } = {}) {
  if (!dom.stackDetail) return;
  dom.stackDetail.replaceChildren();
  if (!detailModel) {
    hideDetailPanel();
    return;
  }
  dom.stackDetail.hidden = false;
  dom.stackDetail.classList.add('is-open');

  const article = document.createElement('article');
  article.className = 'stack-detail-card';

  const header = document.createElement('div');
  header.className = 'stack-detail-header';

  const titleWrap = document.createElement('div');
  titleWrap.className = 'stack-detail-heading';

  const title = document.createElement('div');
  title.className = 'stack-detail-title';
  title.textContent = detailModel.title || 'slot';
  titleWrap.appendChild(title);

  const subtitle = document.createElement('div');
  subtitle.className = 'stack-detail-subtitle';
  subtitle.textContent = detailModel.subtitle || 'slot selectionne';
  titleWrap.appendChild(subtitle);

  header.appendChild(titleWrap);

  const actions = document.createElement('div');
  actions.className = 'stack-detail-actions';

  if (Array.isArray(detailModel.badges) && detailModel.badges.length) {
    const badges = document.createElement('div');
    badges.className = 'stack-detail-badges';
    detailModel.badges.forEach((badgeText) => {
      const badge = document.createElement('span');
      badge.className = 'stack-detail-badge';
      badge.textContent = badgeText;
      badges.appendChild(badge);
    });
    actions.appendChild(badges);
  }

  const close = document.createElement('button');
  close.type = 'button';
  close.className = 'stack-detail-close';
  close.textContent = 'Fermer';
  close.addEventListener('click', () => {
    if (typeof onCloseDetail === 'function') {
      onCloseDetail(null);
      return;
    }
    hideDetailPanel();
  });
  actions.appendChild(close);

  header.appendChild(actions);

  article.appendChild(header);

  const rows = document.createElement('div');
  rows.className = 'stack-detail-rows';
  (Array.isArray(detailModel.rows) ? detailModel.rows : []).forEach((row) => {
    const item = document.createElement('div');
    item.className = 'stack-detail-row';

    const label = document.createElement('div');
    label.className = 'stack-detail-label';
    label.textContent = row.label;
    item.appendChild(label);

    const value = document.createElement('div');
    value.className = 'stack-detail-value';
    value.textContent = row.value;
    item.appendChild(value);

    rows.appendChild(item);
  });
  article.appendChild(rows);
  dom.stackDetail.appendChild(article);
}

function renderDetailPlaceholder(emptyText = 'Cliquez sur un slot pour afficher plus de details.') {
  if (!dom.stackDetail) return;
  dom.stackDetail.hidden = false;
  dom.stackDetail.classList.add('is-open');
  const empty = document.createElement('div');
  empty.className = 'stack-detail-empty';
  empty.textContent = emptyText;
  dom.stackDetail.appendChild(empty);
}

function hideDetailPanel() {
  if (!dom.stackDetail) return;
  dom.stackDetail.replaceChildren();
  dom.stackDetail.hidden = true;
  dom.stackDetail.classList.remove('is-open');
}

/**
 * @brief Rend le legendaire des roles.
 * @param options Options de rendu.
 */
function renderLegend(options = {}) {
  if (!dom.legend) return;
  dom.legend.replaceChildren();
  if (options.abstractMode) return;
  const order = ['ret', 'control', 'arg', 'buffer', 'local', 'spill', 'padding', 'unknown'];
  order.forEach((key) => {
    const config = ROLE_CONFIG[key];
    if (!config) return;
    const item = document.createElement('span');
    item.className = 'legend-item';
    const swatch = document.createElement('span');
    swatch.className = `legend-swatch ${config.className}`;
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(config.label));
    dom.legend.appendChild(item);
  });
  const analysis = options.analysis && typeof options.analysis === 'object' ? options.analysis : null;
  const changedCount = Array.isArray(analysis?.delta?.changedSlots) ? analysis.delta.changedSlots.length : 0;
  const writeCount = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes.length : 0;
  const overflow = analysis?.overflow && typeof analysis.overflow === 'object' ? analysis.overflow : null;
  [
    writeCount ? `writes ${writeCount}` : null,
    changedCount ? `diff ${changedCount}` : null,
    overflow?.active ? `overflow ${overflow.progressBytes ?? 0}B` : null
  ]
    .filter(Boolean)
    .forEach((text) => {
      const badge = document.createElement('span');
      badge.className = 'legend-item legend-item-metric';
      badge.textContent = text;
      dom.legend.appendChild(badge);
    });
}

function updateStackChrome(displayMode, options = {}, summaryText = '', hasFrameSelection = true) {
  const showLegend = hasFrameSelection && displayMode === 'advanced' && !options.abstractMode;
  if (dom.legend) {
    dom.legend.hidden = !showLegend;
  }
  if (showLegend) {
    renderLegend(options);
  } else if (dom.legend) {
    dom.legend.replaceChildren();
  }

  if (!dom.stackSummary) return;
  const text = hasFrameSelection && displayMode === 'frame' ? String(summaryText || '').trim() : '';
  dom.stackSummary.hidden = !text;
  dom.stackSummary.textContent = text;
}

function renderSimpleStack(items, { onToggleExpandedKey } = {}) {
  if (!Array.isArray(items) || !items.length) {
    const status = document.createElement('div');
    status.className = 'status';
    status.textContent = 'Pile vide a cette etape.';
    dom.stack.appendChild(status);
    return;
  }

  items.forEach((item, index) => {
    const card = document.createElement('article');
    card.className = `simple-stack-card simple-stack-card-${item.category}`;
    if (item.isChanged) card.classList.add('is-changed');
    if (item.isImportant) card.classList.add('is-important');
    if (item.isExpanded) card.classList.add('is-expanded');
    card.title = item.hoverText || item.title;

    const header = document.createElement('div');
    header.className = 'simple-stack-header';

    const titleWrap = document.createElement('div');
    titleWrap.className = 'simple-stack-title-wrap';
    const title = document.createElement('div');
    title.className = 'simple-stack-title';
    title.textContent = item.title;
    titleWrap.appendChild(title);
    if (item.subtitle) {
      const subtitle = document.createElement('div');
      subtitle.className = 'simple-stack-subtitle';
      subtitle.textContent = item.subtitle;
      titleWrap.appendChild(subtitle);
    }
    header.appendChild(titleWrap);

    const category = document.createElement('span');
    category.className = 'simple-stack-category';
    category.textContent = item.categoryLabel;
    header.appendChild(category);
    card.appendChild(header);

    if (Array.isArray(item.badges) && item.badges.length) {
      const badges = document.createElement('div');
      badges.className = 'simple-stack-badges';
      item.badges.forEach((badgeText) => {
        const badge = document.createElement('span');
        badge.className = 'simple-stack-badge';
        badge.textContent = badgeText;
        badges.appendChild(badge);
      });
      card.appendChild(badges);
    }

    if (item.previewValue) {
      const preview = document.createElement('div');
      preview.className = 'simple-stack-preview';
      preview.textContent = item.previewValue;
      card.appendChild(preview);
    }

    const canToggle = typeof onToggleExpandedKey === 'function';
    if (canToggle) {
      card.tabIndex = 0;
      card.setAttribute('role', 'button');
      card.setAttribute('aria-expanded', item.isExpanded ? 'true' : 'false');
      const toggle = () => onToggleExpandedKey(item.key);
      card.addEventListener('click', toggle);
      card.addEventListener('keydown', (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          toggle();
        }
      });
    }

    if (item.isExpanded && Array.isArray(item.details) && item.details.length) {
      const details = document.createElement('div');
      details.className = 'simple-stack-details';
      item.details.forEach((row) => {
        const line = document.createElement('div');
        line.className = 'simple-stack-detail-row';
        const label = document.createElement('span');
        label.className = 'simple-stack-detail-label';
        label.textContent = row.label;
        const value = document.createElement('span');
        value.className = 'simple-stack-detail-value';
        value.textContent = row.value;
        line.appendChild(label);
        line.appendChild(value);
        details.appendChild(line);
      });
      details.addEventListener('click', (event) => event.stopPropagation());
      card.appendChild(details);
    }

    setTimeout(() => {
      card.classList.add('visible');
    }, 40 * index);

    dom.stack.appendChild(card);
  });
}
