// Restore last panel or use initial from body
function initPanel() {
  const saved = _loadStorage();
  const initial = document.body.dataset.initialPanel || 'dashboard';
  const panelId = (saved.panel && document.getElementById(`panel-${saved.panel}`)) ? saved.panel : initial;
  currentBinaryMeta = _normalizeBinaryMeta(saved.binaryMeta || null);
  // Restore static binary path
  if (saved.staticBinaryPath && staticBinaryInput) {
    staticBinaryInput.value = saved.staticBinaryPath;
    if (binaryPathInput && !binaryPathInput.value?.trim()) binaryPathInput.value = saved.staticBinaryPath;
  }
  syncNavigationHistoryForBinary(saved.staticBinaryPath || '');
  updateTopBarBinaryDisplay(saved.staticBinaryPath || '', currentBinaryMeta);
  renderRecentBinaries();
  showPanel(panelId);
  updateActiveContextBars(window._lastDisasmAddr);
  vscode.postMessage({ type: 'hubGetSettings' });
}

function showPanel(id) {
  closeBinaryMenu();
  panels.forEach((p) => p.classList.remove('active'));
  iconNavItems.forEach((n) => n.classList.remove('active'));
  document.querySelectorAll('.runtime-nav-item').forEach((n) => n.classList.remove('active'));
  const panel = document.getElementById(`panel-${id}`);
  const nav = document.querySelector(`[data-panel="${id}"]`);
  if (panel) panel.classList.add('active');
  if (nav) nav.classList.add('active');
  syncOllamaFloatingWidgetVisibility(id);
  // Top bar mode badge
  const modeEl = document.getElementById('topBarMode');
  if (modeEl) {
    modeEl.className = 'top-bar-mode';
    if (id === 'static')       { modeEl.textContent = 'STATIC';  modeEl.classList.add('static'); }
    else if (id === 'dynamic') { modeEl.textContent = 'DYNAMIC'; modeEl.classList.add('dynamic'); }
    else                       { modeEl.textContent = id.toUpperCase(); modeEl.classList.add('other'); }
  }
  if (id === 'outils') {
    syncToolsBinaryLabel();
    const saved = _loadStorage();
    showOutilsTab(saved.outilsTab || 'outils');
  }
  if (id === 'dashboard') {
    if (!ollamaUiState.models.length) requestOllamaModels();
  }
  if (id === 'static') {
    const bp = getStaticBinaryPath();
    if (bp) {
      postBinaryAwareMessage('hubLoadAnnotations', { binaryPath: bp });
    }
    const saved = _loadStorage();
    showGroup(saved.group || 'code', saved.tab || null);
    syncStaticWorkspaceSummary();
  }
  if (id === 'dynamic') {
    requestRunTraceInit();
  }
  if (id === 'options') {
    vscode.postMessage({ type: 'hubGetSettings' });
  }
  syncStaticBinary();
  vscode.postMessage({ type: 'hubModeChange', mode: id === 'static' ? 'static' : id === 'dynamic' ? 'dynamic' : 'other' });
  _saveStorage({ panel: id });
}

// Icon nav click handlers
iconNavItems.forEach((item) => {
  item.addEventListener('click', () => {
    const panel = window.POFTelemetryClient?.mapPanel?.(item.dataset.panel);
    if (panel) window.POFTelemetry?.trackEvent?.('panel.opened', { panel });
    showPanel(item.dataset.panel);
  });
});

// Binary button listeners are handled by binarySourceController (binarySourceController.js).
// Click-outside and Escape handlers for binary menu are in binarySourceController.js.

function getActiveStaticGroup() {
  return document.querySelector('.group-tab.active')?.dataset.group || _loadStorage().group || 'code';
}

function _clearStaticSubtabDropMarkers(scope = document) {
  scope.querySelectorAll('.sub-tab.drop-before, .sub-tab.drop-after, .sub-tab.is-dragging').forEach((btn) => {
    btn.classList.remove('drop-before', 'drop-after', 'is-dragging');
  });
}

function _buildStaticSubtabOrderAfterDrop(groupId, dragTabId, dropTabId, dropPosition = 'after') {
  const currentTabs = getAvailableGroupTabs(groupId);
  if (!dragTabId || !dropTabId || dragTabId === dropTabId) return currentTabs;
  const next = currentTabs.filter((tabId) => tabId !== dragTabId);
  const targetIndex = next.indexOf(dropTabId);
  if (targetIndex < 0) return currentTabs;
  const insertIndex = dropPosition === 'before' ? targetIndex : targetIndex + 1;
  next.splice(insertIndex, 0, dragTabId);
  return next;
}

function _getDropPositionForEvent(event, target) {
  const rect = target.getBoundingClientRect();
  return event.clientX < rect.left + rect.width / 2 ? 'before' : 'after';
}

function _handleStaticSubtabDrop(groupId, dragTabId, dropTabId, dropPosition) {
  const nextOrder = _buildStaticSubtabOrderAfterDrop(groupId, dragTabId, dropTabId, dropPosition);
  if (!nextOrder.length) return;
  staticSubtabSuppressClickUntil = Date.now() + 180;
  _persistStaticTabOrder(groupId, nextOrder);
  const activeTab = getActiveStaticTab();
  showGroup(groupId, activeTab);
}

function _attachStaticSubtabDnD(btn, groupId) {
  const tabId = btn.dataset.subTab;
  if (!tabId) return;
  btn.draggable = true;
  btn.addEventListener('dragstart', (event) => {
    staticSubtabDragState = {
      groupId,
      dragTabId: tabId,
      overTabId: '',
      dropPosition: 'after',
      didDrop: false,
    };
    btn.classList.add('is-dragging');
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = 'move';
      event.dataTransfer.setData('text/plain', tabId);
    }
  });
  btn.addEventListener('dragover', (event) => {
    if (!staticSubtabDragState.dragTabId || staticSubtabDragState.dragTabId === tabId || staticSubtabDragState.groupId !== groupId) return;
    event.preventDefault();
    const dropPosition = _getDropPositionForEvent(event, btn);
    staticSubtabDragState.overTabId = tabId;
    staticSubtabDragState.dropPosition = dropPosition;
    _clearStaticSubtabDropMarkers(btn.parentElement || document);
    btn.classList.add(dropPosition === 'before' ? 'drop-before' : 'drop-after');
  });
  btn.addEventListener('drop', (event) => {
    if (!staticSubtabDragState.dragTabId || staticSubtabDragState.dragTabId === tabId || staticSubtabDragState.groupId !== groupId) return;
    event.preventDefault();
    staticSubtabDragState.didDrop = true;
    const dropPosition = _getDropPositionForEvent(event, btn);
    _handleStaticSubtabDrop(groupId, staticSubtabDragState.dragTabId, tabId, dropPosition);
  });
  btn.addEventListener('dragend', () => {
    _clearStaticSubtabDropMarkers(document);
    staticSubtabDragState = {
      groupId: '',
      dragTabId: '',
      overTabId: '',
      dropPosition: 'after',
      didDrop: false,
    };
  });
}

// Group + sub-tab navigation
function showGroup(groupId, tabId, skipAutoLoad = false) {
  if (!GROUPS[groupId]) groupId = 'code';
  const renderedTabs = _getOrderedGroupTabs(groupId);
  if (renderedTabs.length === 0) groupId = getFirstAvailableStaticGroup();
  const availableTabs = getAvailableGroupTabs(groupId);
  const tabsToRender = _getOrderedGroupTabs(groupId);

  // Sync dynamic plugin group tab buttons (created/removed as plugins register)
  const groupTabsBar = document.querySelector('.group-tabs-bar.static-group-tabs');
  if (groupTabsBar) {
    // Remove stale dynamic buttons for groups no longer registered
    groupTabsBar.querySelectorAll('.group-tab[data-dynamic]').forEach((btn) => {
      if (!GROUPS[btn.dataset.group]) btn.remove();
    });
    // Add buttons for newly registered plugin groups that have no HTML button yet
    Object.keys(GROUPS).forEach((gid) => {
      if (groupTabsBar.querySelector(`.group-tab[data-group="${gid}"]`)) return;
      const btn = document.createElement('button');
      btn.className = 'group-tab';
      btn.dataset.group = gid;
      btn.dataset.dynamic = '1';
      btn.textContent = (GROUP_LABELS[gid] || gid).toUpperCase();
      btn.addEventListener('click', () => showGroup(gid));
      groupTabsBar.appendChild(btn);
    });
  }

  document.querySelectorAll('.group-tab').forEach((btn) => {
    const hasTabs = _getOrderedGroupTabs(btn.dataset.group).length > 0;
    btn.hidden = !hasTabs;
    btn.disabled = !hasTabs;
    btn.style.display = hasTabs ? '' : 'none';
    btn.classList.toggle('active', hasTabs && btn.dataset.group === groupId);
  });
  const bar = document.getElementById('subTabsBar');
  if (!bar) return;
  bar.replaceChildren();
  if (!tabsToRender.length) return;
  tabsToRender.forEach((tid) => {
    const btn = document.createElement('button');
    btn.className = 'sub-tab';
    btn.dataset.subTab = tid;
    btn.textContent = GROUP_LABELS[tid] || tid;
    const rawCapability = getRawTabCapability(tid);
    const isLimited = rawCapability?.level === 'limited';
    const isUnsupported = rawCapability?.level === 'unsupported';
    btn.classList.toggle('is-limited', isLimited);
    btn.classList.toggle('is-unavailable', isUnsupported);
    btn.disabled = isUnsupported;
    btn.title = rawCapability?.note
      ? `${GROUP_LABELS[tid] || tid} — ${rawCapability.note}`
      : `${GROUP_LABELS[tid] || tid} — glisser pour réorganiser`;
    const badge = _buildArchBadge(TAB_FEATURE_MAP[tid] || []);
    if (badge) btn.appendChild(badge);
    if (rawCapability?.level === 'limited' || rawCapability?.level === 'unsupported') {
      const stateChip = document.createElement('span');
      stateChip.className = `sub-tab-state-chip ${rawCapability.level}`;
      stateChip.textContent = rawCapability.level === 'limited' ? 'limité' : 'indispo';
      btn.appendChild(stateChip);
    }
    _attachStaticSubtabDnD(btn, groupId);
    btn.addEventListener('click', () => {
      if (Date.now() < staticSubtabSuppressClickUntil) return;
      if (isUnsupported) return;
      const feature = window.POFTelemetryClient?.mapStaticFeature?.(tid);
      if (feature) window.POFTelemetry?.trackEvent?.('static.feature.used', { feature });
      showSubTab(groupId, tid);
    });
    bar.appendChild(btn);
  });
  bar.ondragover = (event) => {
    if (!staticSubtabDragState.dragTabId || staticSubtabDragState.groupId !== groupId) return;
    event.preventDefault();
  };
  bar.ondrop = (event) => {
    if (!staticSubtabDragState.dragTabId || staticSubtabDragState.groupId !== groupId) return;
    const target = event.target.closest('.sub-tab');
    if (target) return;
    event.preventDefault();
    staticSubtabDragState.didDrop = true;
    staticSubtabSuppressClickUntil = Date.now() + 180;
    const nextOrder = getAvailableGroupTabs(groupId).filter((tab) => tab !== staticSubtabDragState.dragTabId);
    nextOrder.push(staticSubtabDragState.dragTabId);
    _persistStaticTabOrder(groupId, nextOrder);
    showGroup(groupId, getActiveStaticTab());
  };
  const targetTab = (tabId && availableTabs.includes(tabId)) ? tabId : availableTabs[0];
  if (!targetTab) {
    document.querySelectorAll('.sub-tab').forEach((btn) => btn.classList.remove('active'));
    document.querySelectorAll('#panel-static .static-panel').forEach((p) => p.classList.remove('active'));
    syncStaticWorkspaceSummary();
    _saveStorage({ group: groupId });
    if (currentArchSupport) _refreshArchSupportBadges();
    return;
  }
  showSubTab(groupId, targetTab, skipAutoLoad);
  _saveStorage({ group: groupId });
  if (currentArchSupport) _refreshArchSupportBadges();
}

function _refreshArchSupportBadges() {
  archBadgeController?.refreshBadges();
}

function showSubTab(groupId, tabId, skipAutoLoad = false) {
  if (!isStaticTabAvailable(tabId)) {
    const fallbackGroup = getFirstAvailableStaticGroup();
    const fallbackTab = getAvailableGroupTabs(fallbackGroup)[0];
    if (fallbackTab && fallbackTab !== tabId) {
      showGroup(fallbackGroup, fallbackTab, skipAutoLoad);
    }
    return;
  }
  document.querySelectorAll('.sub-tab').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.subTab === tabId);
  });
  document.querySelectorAll('#panel-static .static-panel').forEach((p) => p.classList.remove('active'));
  // Convert snake_case tabId to PascalCase panel ID
  const panelId = 'static' + tabId.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');
  const panel = document.getElementById(panelId);
  if (panel) {
    panel.classList.add('active');
  } else {
    // Plugin tab: find the iframe that owns this tabId and show it
    const pluginSlug = typeof getPluginSlugForTab === 'function' ? getPluginSlugForTab(tabId) : null;
    if (pluginSlug) {
      const frame = document.querySelector(`iframe.plugin-iframe[data-plugin-slug="${pluginSlug}"]`);
      if (frame) {
        frame.classList.add('active');
        if (window.PluginIframeRouter) {
          window.PluginIframeRouter.dispatch(frame.dataset.pluginId, { type: 'showTab', tabId });
        }
      }
    }
  }
  if (!skipAutoLoad) _autoLoadTab(tabId);
  requestAnimationFrame(() => requestGraphFit(panel || document));
  if (tabId === 'cfg' && window._lastDisasmAddr) {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        syncCfgActiveAddress(window._lastDisasmAddr, {
          reveal: true,
          revealTable: document.querySelector('#cfgContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      });
    });
  }
  if (tabId === 'callgraph' && window._lastDisasmAddr) {
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        syncCallGraphActiveAddress(window._lastDisasmAddr, {
          reveal: true,
          revealTable: document.querySelector('#callgraphContent .cfg-table-view')?.style.display !== 'none',
          instant: true,
        });
      });
    });
  }
  if (tabId === 'decompile') {
    requestAnimationFrame(() => {
      const selectedAddr = syncDecompileSelection(window._lastDisasmAddr || decompileUiState.selectedAddr);
      const currentBinaryPath = getStaticBinaryPath() || '';
      const currentQuality = _normalizeDecompileQuality(document.getElementById('decompileQualitySelect')?.value || decompileUiState.quality || 'normal');
      const currentDecompiler = _getRequestedDecompilerForQuality(currentQuality);
      const currentProvider = _getConfiguredDecompilerProvider();
      const shouldRefresh = decompileUiState.renderedBinaryPath !== currentBinaryPath
        || decompileUiState.renderedDecompiler !== currentDecompiler
        || decompileUiState.renderedProvider !== currentProvider
        || decompileUiState.renderedQuality !== currentQuality
        || (decompileUiState.renderedAddr || '') !== (selectedAddr || '');
      if (shouldRefresh && currentBinaryPath) requestDecompileForCurrentSelection();
    });
  }
  updateActiveContextBars(window._lastDisasmAddr);
  syncStaticWorkspaceSummary(tabId);
  _saveStorage({ group: groupId, tab: tabId });
}

document.querySelectorAll('.group-tab').forEach((btn) => {
  btn.addEventListener('click', () => showGroup(btn.dataset.group));
});

document.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-context-jump]');
  if (!btn || btn.disabled) return;
  event.preventDefault();
  jumpToContextTab(btn.dataset.contextJump || '');
});
