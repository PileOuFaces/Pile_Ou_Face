/**
 * Classic-script controller for binary and C source selection state in the hub.
 * Manages selected binary display, picker buttons, source C path, and related messages.
 * hub.js remains the compatibility shell and calls forwarding stubs.
 */
(function initHubBinarySourceController(global) {
  const MAX_RECENT = 8;

  function initBinarySourceController(deps) {
    const {
      postMessage,
      staticBinaryInput,
      binaryPathInput,
      dynamicSourcePathInput,
      form,
      _loadStorage,
      _saveStorage,
      _normalizeRawProfile,
      _displayRawArchName,
      _displayEndianName,
      _basenameFromPath,
      clearCrossAnalysisResolutionCache,
      syncNavigationHistoryForBinary,
      syncToolsBinaryLabel,
      renderBookmarks,
      showGroup,
      getActiveStaticTab,
      syncStaticWorkspaceSummary,
      updateActiveContextBars,
      resetStaticBinaryDerivedState,
      requestSymbols,
      requestRunTraceInit,
      setDynamicTraceStatus,
      updateArgvPayloadHint,
      showPanel,
      getPendingStaticQuickAction,
      setPendingStaticQuickAction,
      triggerStaticQuickAction,
      _autoLoadTab,
      getSectionsCacheBinaryPath,
    } = deps || {};

    // Internal state — initialized from storage at creation time
    let currentBinaryMeta = null;
    (function _initMeta() {
      const stored = typeof _loadStorage === 'function' ? _loadStorage() : {};
      currentBinaryMeta = _normalizeBinaryMeta(stored.binaryMeta || null);
    })();

    function safePostMessage(msg) {
      if (typeof postMessage === 'function') postMessage(msg);
    }

    // --- Binary meta helpers (self-contained copies) ---

    function _normalizeBinaryMeta(meta) {
      if (!meta || typeof meta !== 'object') return null;
      const kind = meta.kind === 'raw' ? 'raw' : 'native';
      const normalized = {
        kind,
        format: String(meta.format || (kind === 'raw' ? 'RAW' : '')).trim(),
        arch: String(meta.arch || '').trim(),
      };
      if (kind === 'raw') {
        normalized.rawConfig = typeof _normalizeRawProfile === 'function'
          ? _normalizeRawProfile(meta.rawConfig || meta)
          : null;
        if (!normalized.rawConfig) return null;
        normalized.arch = normalized.arch || normalized.rawConfig.arch;
        normalized.format = 'RAW';
      }
      return normalized;
    }

    function _describeBinaryMeta(meta, opts = {}) {
      if (!meta) return '';
      const parts = [];
      const useRawLabels = opts.useRawLabels !== false;
      if (meta.format) parts.push(meta.format);
      if (meta.kind === 'raw' && meta.rawConfig && useRawLabels) {
        parts.push(typeof _displayRawArchName === 'function'
          ? _displayRawArchName(meta.rawConfig.arch || meta.arch)
          : (meta.rawConfig.arch || meta.arch || ''));
        if (meta.rawConfig.endian) {
          parts.push(typeof _displayEndianName === 'function'
            ? _displayEndianName(meta.rawConfig.endian)
            : meta.rawConfig.endian);
        }
        if (meta.rawConfig.baseAddr) parts.push(`base ${meta.rawConfig.baseAddr}`);
        return parts.join(' • ');
      }
      if (meta.arch) parts.push(meta.arch);
      return parts.join(' • ');
    }

    function _binaryStatusText(meta) {
      return _describeBinaryMeta(meta, { useRawLabels: true });
    }

    // --- State accessors ---

    function getCurrentBinaryMeta() {
      if (currentBinaryMeta) return currentBinaryMeta;
      const stored = typeof _loadStorage === 'function' ? _loadStorage() : {};
      currentBinaryMeta = _normalizeBinaryMeta(stored.binaryMeta || null);
      return currentBinaryMeta;
    }

    function isRawBinarySelected() {
      return getCurrentBinaryMeta()?.kind === 'raw';
    }

    function syncStaticBinary() {
      const staticVal = staticBinaryInput?.value?.trim();
      const useExisting = form?.querySelector('[name="useExistingBinary"]')?.checked === true;
      if (useExisting && staticVal && binaryPathInput && binaryPathInput.value !== staticVal) {
        binaryPathInput.value = staticVal;
      }
    }

    function getStaticBinaryPath() {
      syncStaticBinary();
      return staticBinaryInput?.value?.trim() || '';
    }

    function getSelectedBinary() {
      return getStaticBinaryPath();
    }

    function getSelectedSourceC() {
      return String(dynamicSourcePathInput?.value || '').trim();
    }

    // --- Recent binaries ---

    function getRecentBinaries() {
      const stored = typeof _loadStorage === 'function' ? _loadStorage() : {};
      const recent = stored.recentBinaries;
      return Array.isArray(recent) ? recent : [];
    }

    function rememberRecentBinary(binaryPath, binaryMeta) {
      if (!binaryPath) return getRecentBinaries();
      const normalizedMeta = _normalizeBinaryMeta(binaryMeta);
      const nextEntry = { path: binaryPath, meta: normalizedMeta, ts: Date.now() };
      const recent = getRecentBinaries()
        .filter((entry) => entry && entry.path && entry.path !== binaryPath)
        .slice(0, MAX_RECENT - 1);
      return [nextEntry, ...recent];
    }

    function removeRecentBinary(binaryPath) {
      const target = String(binaryPath || '').trim();
      if (!target) return;
      const nextRecent = getRecentBinaries().filter((entry) => entry?.path !== target);
      if (typeof _saveStorage === 'function') _saveStorage({ recentBinaries: nextRecent });
      renderRecentBinaries();
    }

    function clearRecentBinaries() {
      if (typeof _saveStorage === 'function') _saveStorage({ recentBinaries: [] });
      renderRecentBinaries();
      safePostMessage({ type: 'hubClearRecentBinaries' });
    }

    // --- Top bar display ---

    function updateTopBarRawProfileCard(binaryPath = '', binaryMeta = null) {
      const card = document.getElementById('topBarRawProfileCard');
      const metaWrap = document.getElementById('topBarRawProfileMeta');
      const status = document.getElementById('topBarRawProfileStatus');
      if (!card || !metaWrap || !status) return;
      const meta = _normalizeBinaryMeta(binaryMeta || null);
      const rawConfig = meta?.kind === 'raw' ? meta.rawConfig : null;
      if (!binaryPath || !rawConfig) {
        card.hidden = true;
        metaWrap.replaceChildren();
        return;
      }
      card.hidden = false;
      status.textContent = 'Actif';
      const pills = [
        `arch ${typeof _displayRawArchName === 'function' ? _displayRawArchName(rawConfig.arch || meta.arch) : (rawConfig.arch || meta.arch || '')}`,
        typeof _displayEndianName === 'function' ? _displayEndianName(rawConfig.endian) : rawConfig.endian,
        `base ${rawConfig.baseAddr || '0x0'}`,
      ];
      metaWrap.replaceChildren();
      pills.forEach((text) => {
        const pill = document.createElement('span');
        pill.className = 'top-bar-raw-profile-pill';
        pill.textContent = text;
        metaWrap.appendChild(pill);
      });
    }

    function updateTopBarWorkspaceFlow(binaryPath = '', binaryMeta = null, info = null) {
      const currentStatus = document.getElementById('topBarCurrentBinaryStatus');
      const currentName = document.getElementById('topBarCurrentBinaryName');
      const currentPath = document.getElementById('topBarCurrentBinaryPath');
      const selectBtn = document.getElementById('btnTopBarSelectBinary');
      const normalizedMeta = _normalizeBinaryMeta(binaryMeta || null);
      const hasBinary = !!binaryPath;
      const formatValue = (info && info.format) || normalizedMeta?.format || '';
      const archValue = normalizedMeta?.kind === 'raw'
        ? (typeof _displayRawArchName === 'function'
          ? _displayRawArchName(normalizedMeta?.rawConfig?.arch || normalizedMeta?.arch || '')
          : (normalizedMeta?.rawConfig?.arch || normalizedMeta?.arch || ''))
        : ((info && info.arch) || normalizedMeta?.arch || '');
      const statusSummary = _binaryStatusText(normalizedMeta) || [formatValue, archValue].filter(Boolean).join(' · ');

      if (currentStatus) currentStatus.textContent = hasBinary ? (statusSummary || 'Prêt') : 'Aucun';
      if (currentName) {
        currentName.textContent = hasBinary
          ? ((typeof _basenameFromPath === 'function' ? _basenameFromPath(binaryPath) : binaryPath) || binaryPath)
          : 'Aucun fichier sélectionné';
      }
      if (currentPath) {
        currentPath.textContent = hasBinary ? binaryPath : 'Choisis un fichier pour démarrer.';
      }
      if (selectBtn) selectBtn.textContent = hasBinary ? 'Changer…' : 'Choisir…';
    }

    function updateTopBarBinaryDisplay(binaryPath = '', binaryMeta = null, info = null) {
      const topLabel = document.getElementById('topBarBinaryLabel');
      const topName = document.getElementById('topBarBinaryName');
      const topPath = document.getElementById('topBarBinaryPath');
      const chipFormat = document.getElementById('topBarChipFormat');
      const chipArch = document.getElementById('topBarChipArch');
      if (topLabel) topLabel.textContent = 'Fichier de travail';
      const baseName = typeof _basenameFromPath === 'function' ? _basenameFromPath(binaryPath) : binaryPath;
      if (topName) {
        topName.textContent = binaryPath ? (baseName || binaryPath) : 'Choisir un fichier…';
        topName.classList.toggle('empty', !binaryPath);
      }
      if (topPath) {
        topPath.textContent = binaryPath
          ? binaryPath
          : "Le fichier choisi sera repris dans l'analyse statique et la trace dynamique.";
      }
      const formatValue = (info && info.format) || binaryMeta?.format || '';
      const archValue = binaryMeta?.kind === 'raw'
        ? (typeof _displayRawArchName === 'function'
          ? _displayRawArchName(binaryMeta?.rawConfig?.arch || binaryMeta?.arch || '')
          : (binaryMeta?.rawConfig?.arch || binaryMeta?.arch || ''))
        : ((info && info.arch) || binaryMeta?.arch || '');
      if (chipFormat) {
        chipFormat.textContent = formatValue;
        chipFormat.style.display = formatValue ? '' : 'none';
      }
      if (chipArch) {
        chipArch.textContent = archValue;
        chipArch.style.display = archValue ? '' : 'none';
      }
      updateTopBarWorkspaceFlow(binaryPath, binaryMeta, info);
      updateTopBarRawProfileCard(binaryPath, binaryMeta);
    }

    // --- Binary selection state ---

    function saveBinarySelection(binaryPath, binaryMeta) {
      const normalizedMeta = _normalizeBinaryMeta(binaryMeta);
      currentBinaryMeta = normalizedMeta;
      if (typeof clearCrossAnalysisResolutionCache === 'function') clearCrossAnalysisResolutionCache(binaryPath);
      if (typeof _saveStorage === 'function') {
        _saveStorage({
          staticBinaryPath: binaryPath,
          binaryMeta: normalizedMeta,
          recentBinaries: binaryPath ? rememberRecentBinary(binaryPath, normalizedMeta) : getRecentBinaries(),
        });
      }
      if (typeof syncNavigationHistoryForBinary === 'function') syncNavigationHistoryForBinary(binaryPath);
      updateTopBarBinaryDisplay(binaryPath, normalizedMeta);
      renderRecentBinaries();
    }

    function clearActiveBinarySelection() {
      if (typeof resetStaticBinaryDerivedState === 'function') resetStaticBinaryDerivedState();
      if (staticBinaryInput) staticBinaryInput.value = '';
      if (binaryPathInput) binaryPathInput.value = '';
      currentBinaryMeta = null;
      saveBinarySelection('', null);
      if (typeof syncNavigationHistoryForBinary === 'function') syncNavigationHistoryForBinary('');
      syncDynamicBinaryFieldMode();
      if (typeof syncToolsBinaryLabel === 'function') syncToolsBinaryLabel();
      if (typeof renderBookmarks === 'function') renderBookmarks();
      if (typeof syncStaticWorkspaceSummary === 'function') syncStaticWorkspaceSummary();
      if (typeof updateActiveContextBars === 'function') updateActiveContextBars('');
    }

    // --- Binary menu ---

    function renderRecentBinaries() {
      const container = document.getElementById('topBarRecentList');
      if (!container) return;
      const recent = getRecentBinaries();
      const activePath = getStaticBinaryPath();
      container.replaceChildren();
      if (!recent.length) {
        const empty = document.createElement('div');
        empty.className = 'top-bar-recent-empty';
        empty.textContent = 'Aucun fichier récent pour le moment.';
        container.appendChild(empty);
        return;
      }
      recent.forEach((entry) => {
        if (!entry?.path) return;
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'top-bar-menu-item';
        if (entry.path === activePath) btn.classList.add('is-active');
        btn.title = entry.path;

        const metaWrap = document.createElement('div');
        metaWrap.className = 'top-bar-recent-meta';
        const copy = document.createElement('div');
        copy.className = 'top-bar-recent-copy';
        const name = document.createElement('span');
        name.className = 'top-bar-recent-name';
        name.textContent = entry.path.split('/').pop() || entry.path;
        const fullPath = document.createElement('span');
        fullPath.className = 'top-bar-recent-path';
        fullPath.textContent = entry.path;
        copy.append(name, fullPath);
        metaWrap.appendChild(copy);

        const status = document.createElement('span');
        status.className = 'top-bar-recent-status';
        status.textContent = _binaryStatusText(_normalizeBinaryMeta(entry.meta || null));

        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'top-bar-recent-remove';
        removeBtn.title = `Retirer ${entry.path.split('/').pop() || entry.path} des récents`;
        removeBtn.setAttribute('aria-label', removeBtn.title);
        removeBtn.textContent = '×';
        removeBtn.addEventListener('click', (event) => {
          event.preventDefault();
          event.stopPropagation();
          removeRecentBinary(entry.path);
          safePostMessage({ type: 'hubForgetRecentBinary', binaryPath: entry.path });
        });

        const trailing = document.createElement('div');
        trailing.className = 'top-bar-recent-actions';
        trailing.append(status, removeBtn);

        btn.append(metaWrap, trailing);
        btn.addEventListener('click', () => {
          closeBinaryMenu();
          if (typeof showPanel === 'function') showPanel('static');
          safePostMessage({
            type: 'hubUseBinaryPath',
            binaryPath: entry.path,
            binaryMeta: _normalizeBinaryMeta(entry.meta || null),
          });
        });
        container.appendChild(btn);
      });
    }

    function openBinaryMenu() {
      const menu = document.getElementById('topBarBinaryMenu');
      const button = document.getElementById('topBarBinaryButton');
      if (!menu || !button) return;
      renderRecentBinaries();
      menu.hidden = false;
      button.classList.add('is-open');
    }

    function closeBinaryMenu() {
      const menu = document.getElementById('topBarBinaryMenu');
      const button = document.getElementById('topBarBinaryButton');
      if (!menu || !button) return;
      menu.hidden = true;
      button.classList.remove('is-open');
    }

    function toggleBinaryMenu() {
      const menu = document.getElementById('topBarBinaryMenu');
      if (!menu) return;
      if (menu.hidden) openBinaryMenu();
      else closeBinaryMenu();
    }

    // --- Dynamic binary field mode sync ---

    function syncDynamicBinaryFieldMode() {
      const useExistingControl = form?.querySelector('[name="useExistingBinary"]');
      const useExisting = useExistingControl ? useExistingControl.checked === true : true;
      const label = document.getElementById('dynamicBinaryLabel');
      const hint = document.getElementById('dynamicBinaryHint');
      if (label) label.textContent = useExisting ? 'Binaire actif' : 'Binaire de sortie';
      if (hint) {
        hint.textContent = useExisting
          ? 'Le fichier de travail se choisit depuis la barre du haut.'
          : 'Chemin du fichier compilé utilisé par la trace.';
      }
      if (binaryPathInput) {
        binaryPathInput.readOnly = useExisting;
        binaryPathInput.title = useExisting ? 'Champ synchronisé avec la barre du haut' : '';
        binaryPathInput.placeholder = useExisting ? 'Choisissez le fichier dans la barre du haut' : 'examples/stack3.elf';
        if (useExisting) {
          binaryPathInput.value = getStaticBinaryPath() || '';
        } else if (!binaryPathInput.value.trim()) {
          binaryPathInput.value = 'examples/stack3.elf';
        }
      }
    }

    // --- Apply / finalize selection ---

    function applyStaticBinarySelectionUi(binaryPath, binaryMeta) {
      if (staticBinaryInput) staticBinaryInput.value = binaryPath;
      if (binaryPathInput) binaryPathInput.value = binaryPath;
      currentBinaryMeta = binaryMeta;
      saveBinarySelection(binaryPath, binaryMeta);
      closeBinaryMenu();
      syncDynamicBinaryFieldMode();
      if (typeof syncToolsBinaryLabel === 'function') syncToolsBinaryLabel();
      if (typeof renderBookmarks === 'function') renderBookmarks();
      if (document.getElementById('panel-static')?.classList.contains('active')) {
        const stored = typeof _loadStorage === 'function' ? _loadStorage() : {};
        if (typeof showGroup === 'function' && typeof getActiveStaticTab === 'function') {
          showGroup(stored.group || 'code', getActiveStaticTab() || stored.tab || 'disasm');
        }
      }
      if (typeof syncStaticWorkspaceSummary === 'function') syncStaticWorkspaceSummary();
      if (typeof updateActiveContextBars === 'function') updateActiveContextBars(window._lastDisasmAddr);
    }

    function postBinaryAwareMessage(type, extra = {}) {
      const payload = { type, ...extra };
      const binaryPath = payload.binaryPath || getStaticBinaryPath();
      if (binaryPath && payload.binaryPath === undefined) payload.binaryPath = binaryPath;
      const meta = getCurrentBinaryMeta();
      if (binaryPath && payload.binaryMeta === undefined && meta) payload.binaryMeta = meta;
      safePostMessage(payload);
    }

    function queueStaticBinaryAutoload(binaryPath, { skipAutoLoad = false } = {}) {
      if (!binaryPath) return;
      postBinaryAwareMessage('hubLoadAnnotations', { binaryPath });
      const sectionsBinaryPath = typeof getSectionsCacheBinaryPath === 'function'
        ? getSectionsCacheBinaryPath()
        : null;
      if (sectionsBinaryPath !== binaryPath) {
        postBinaryAwareMessage('hubLoadSections', { binaryPath });
      }
      const activeTab = typeof getActiveStaticTab === 'function' ? getActiveStaticTab() : '';
      const pendingAction = typeof getPendingStaticQuickAction === 'function' ? getPendingStaticQuickAction() : '';
      if (typeof setPendingStaticQuickAction === 'function') setPendingStaticQuickAction('');
      if (pendingAction) {
        if (typeof triggerStaticQuickAction === 'function') triggerStaticQuickAction(pendingAction);
      } else if (!skipAutoLoad) {
        if (typeof _autoLoadTab === 'function') _autoLoadTab(activeTab);
      }
    }

    function finalizeStaticBinarySelection(binaryPath, binaryMeta, { sameSelection = false, skipAutoLoad = false } = {}) {
      if (binaryMeta?.kind !== 'raw' && typeof requestSymbols === 'function') requestSymbols();
      if (!sameSelection) {
        queueStaticBinaryAutoload(binaryPath, { skipAutoLoad });
      }
      if (typeof requestRunTraceInit === 'function') requestRunTraceInit(null, binaryPath);
      if (typeof setDynamicTraceStatus === 'function') setDynamicTraceStatus('Prêt.');
      if (typeof updateArgvPayloadHint === 'function') updateArgvPayloadHint();
    }

    // --- Refresh UI ---

    function refreshBinarySourceUi() {
      const bp = getStaticBinaryPath();
      const meta = getCurrentBinaryMeta();
      updateTopBarBinaryDisplay(bp, meta);
      renderRecentBinaries();
      syncDynamicBinaryFieldMode();
    }

    // --- Message handler ---

    function handleBinarySourceMessage(msg) {
      if (!msg || typeof msg !== 'object') return false;
      if (msg.type === 'hubSetBinaryPath' && msg.binaryPath) {
        const bp = msg.binaryPath.trim();
        const skipAutoLoad = msg.skipAutoLoad === true;
        const nextMeta = _normalizeBinaryMeta(msg.binaryMeta || getCurrentBinaryMeta());
        const prevBp = staticBinaryInput?.value?.trim();
        const prevMetaKey = JSON.stringify(getCurrentBinaryMeta() || null);
        const nextMetaKey = JSON.stringify(nextMeta || null);
        const sameSelection = prevBp === bp && prevMetaKey === nextMetaKey;
        if (!sameSelection && typeof resetStaticBinaryDerivedState === 'function') {
          resetStaticBinaryDerivedState();
        }
        applyStaticBinarySelectionUi(bp, nextMeta);
        finalizeStaticBinarySelection(bp, nextMeta, { sameSelection, skipAutoLoad });
        return true;
      }
      if (msg.type === 'hubForgetRecentBinary' && msg.binaryPath) {
        const target = String(msg.binaryPath || '').trim();
        const activePath = getStaticBinaryPath();
        removeRecentBinary(target);
        if (activePath && target === activePath) {
          clearActiveBinarySelection();
        }
        return true;
      }
      if (msg.type === 'hubSetRecentBinaries' && Array.isArray(msg.recent)) {
        if (typeof _saveStorage === 'function') _saveStorage({ recentBinaries: msg.recent });
        renderRecentBinaries();
        return true;
      }
      return false;
    }

    // --- Event listeners ---

    document.getElementById('topBarBinaryButton')?.addEventListener('click', (event) => {
      event.stopPropagation();
      toggleBinaryMenu();
    });
    document.getElementById('btnTopBarSelectBinary')?.addEventListener('click', () => {
      closeBinaryMenu();
      if (typeof setPendingStaticQuickAction === 'function') setPendingStaticQuickAction('');
      safePostMessage({ type: 'requestBinarySelection' });
    });
    document.getElementById('btnTopBarReconfigureRaw')?.addEventListener('click', () => {
      const binaryPath = getStaticBinaryPath();
      const binaryMeta = getCurrentBinaryMeta();
      if (!binaryPath || binaryMeta?.kind !== 'raw') return;
      closeBinaryMenu();
      if (typeof showPanel === 'function') showPanel('static');
      safePostMessage({
        type: 'hubUseBinaryPath',
        binaryPath,
        binaryMeta,
        rawProfileAction: 'reconfigure',
      });
    });
    document.getElementById('btnClearRecentBinaries')?.addEventListener('click', (event) => {
      event.stopPropagation();
      clearRecentBinaries();
    });
    document.addEventListener('click', (event) => {
      const menu = document.getElementById('topBarBinaryMenu');
      const button = document.getElementById('topBarBinaryButton');
      if (!menu || menu.hidden) return;
      if (menu.contains(event.target) || button?.contains(event.target)) return;
      closeBinaryMenu();
    });
    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') closeBinaryMenu();
    });

    return {
      refreshBinarySourceUi,
      handleBinarySourceMessage,
      getSelectedBinary,
      getSelectedSourceC,
      // Compatibility exports used by hub.js forwarding stubs
      getCurrentBinaryMeta,
      getStaticBinaryPath,
      isRawBinarySelected,
      applyStaticBinarySelectionUi,
      finalizeStaticBinarySelection,
      saveBinarySelection,
      clearActiveBinarySelection,
      openBinaryMenu,
      closeBinaryMenu,
      syncDynamicBinaryFieldMode,
      updateTopBarBinaryDisplay,
      postBinaryAwareMessage,
      renderRecentBinaries,
      clearRecentBinaries,
    };
  }

  const api = { initBinarySourceController };
  global.POFHubBinarySourceController = api;
  if (global.POFHub && typeof global.POFHub === 'object') {
    global.POFHub.binarySourceController = api;
  }
})(window);
