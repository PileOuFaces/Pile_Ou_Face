
// Declared here (binary.js is the primary consumer); hub.js assigns the live instance.
let binarySourceController = null;

function _normalizeRawProfile(profile) {
  if (!profile || typeof profile !== 'object') return null;
  const arch = String(profile.arch || '').trim();
  const baseAddr = String(profile.baseAddr || '0x0').trim();
  const requestedEndian = String(profile.endian || 'little').trim().toLowerCase();
  const endian = arch.startsWith('i386') ? 'little' : (requestedEndian === 'big' ? 'big' : 'little');
  if (!arch || !baseAddr) return null;
  return { arch, baseAddr, endian };
}

const RAW_ARCH_DISPLAY_NAMES = {
  'i386:x86-64': 'x86-64',
  i386: 'x86',
  arm: 'ARM',
  thumb: 'Thumb',
  aarch64: 'AArch64',
  mips32: 'MIPS32',
  mips64: 'MIPS64',
  ppc32: 'PowerPC 32',
  ppc64: 'PowerPC 64',
  sparc: 'SPARC',
  sparcv9: 'SPARC V9',
  sysz: 'SystemZ',
  xcore: 'XCore',
  m68k: 'M68K',
  m680x: 'M680X',
  tms320c64x: 'TMS320C64x',
  evm: 'EVM',
  mos65xx: 'MOS65XX / 6502',
  wasm: 'WebAssembly',
  bpf: 'BPF / eBPF',
  riscv32: 'RISC-V 32',
  riscv64: 'RISC-V 64',
  sh: 'SuperH',
  sh4: 'SuperH4',
  tricore: 'TriCore',
};

function _displayRawArchName(rawArch) {
  const key = String(rawArch || '').trim();
  return RAW_ARCH_DISPLAY_NAMES[key] || key || 'Blob brut';
}

function _displayEndianName(endian) {
  const value = String(endian || '').trim().toLowerCase();
  if (value === 'big') return 'big-endian';
  if (value === 'little') return 'little-endian';
  return value || 'endianness inconnue';
}

function _describeBinaryMeta(meta, opts = {}) {
  if (!meta) return '';
  const parts = [];
  const useRawLabels = opts.useRawLabels !== false;
  if (meta.format) parts.push(meta.format);
  if (meta.kind === 'raw' && meta.rawConfig && useRawLabels) {
    parts.push(_displayRawArchName(meta.rawConfig.arch || meta.arch));
    if (meta.rawConfig.endian) parts.push(_displayEndianName(meta.rawConfig.endian));
    if (meta.rawConfig.baseAddr) parts.push(`base ${meta.rawConfig.baseAddr}`);
    return parts.join(' • ');
  }
  if (meta.arch) parts.push(meta.arch);
  return parts.join(' • ');
}

function _normalizeBinaryMeta(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const kind = meta.kind === 'raw' ? 'raw' : 'native';
  const normalized = {
    kind,
    format: String(meta.format || (kind === 'raw' ? 'RAW' : '')).trim(),
    arch: String(meta.arch || '').trim(),
  };
  if (kind === 'raw') {
    normalized.rawConfig = _normalizeRawProfile(meta.rawConfig || meta);
    if (!normalized.rawConfig) return null;
    normalized.arch = normalized.arch || normalized.rawConfig.arch;
    normalized.format = 'RAW';
  }
  return normalized;
}

function getCurrentBinaryMeta() {
  return binarySourceController ? binarySourceController.getCurrentBinaryMeta() : currentBinaryMeta;
}

function getRecentBinaries() {
  const recent = _loadStorage().recentBinaries;
  return Array.isArray(recent) ? recent : [];
}

function rememberRecentBinary(binaryPath, binaryMeta) {
  if (!binaryPath) return getRecentBinaries();
  const normalizedMeta = _normalizeBinaryMeta(binaryMeta);
  const nextEntry = { path: binaryPath, meta: normalizedMeta, ts: Date.now() };
  return [nextEntry, ...getRecentBinaries()
    .filter((entry) => entry && entry.path && entry.path !== binaryPath)
    .slice(0, MAX_RECENT_BINARIES - 1)];
}

function _binaryStatusText(meta) {
  return _describeBinaryMeta(meta, { useRawLabels: true });
}

function updateTopBarWorkspaceFlow(binaryPath, binaryMeta, info) {
  binarySourceController?.updateTopBarBinaryDisplay?.(binaryPath, binaryMeta, info);
}

function updateTopBarBinaryDisplay(binaryPath, binaryMeta, info) {
  binarySourceController?.updateTopBarBinaryDisplay?.(binaryPath, binaryMeta, info);
}

function updateTopBarRawProfileCard() {
  // Handled internally by binarySourceController via updateTopBarBinaryDisplay
}

function saveBinarySelection(binaryPath, binaryMeta) {
  binarySourceController?.saveBinarySelection?.(binaryPath, binaryMeta);
}

function isStaticTabAvailable(tabId, binaryMeta = getCurrentBinaryMeta()) {
  if (!isStaticTabDisplayable(tabId, binaryMeta)) return false;
  const rawCapability = getRawTabCapability(tabId, binaryMeta);
  if (rawCapability?.level === 'unsupported') return false;
  return true;
}

function getStaticInterfaceMode() {
  return _settingsCache?.interfaceMode === 'simple' ? 'simple' : 'advanced';
}

function getAdvancedStaticFeatureSet() {
  const raw = Array.isArray(_settingsCache?.enabledStaticFeatures)
    ? _settingsCache.enabledStaticFeatures
    : [];
  const allFeatureIds = getStaticFeatureIds();
  const valid = raw.filter((tabId) => allFeatureIds.includes(tabId));
  return new Set(valid.length ? valid : allFeatureIds);
}

function isStaticFeatureEnabled(tabId) {
  if (getStaticInterfaceMode() === 'simple') return STATIC_SIMPLE_FEATURES.has(tabId);
  return getAdvancedStaticFeatureSet().has(tabId);
}

function getRawTabCapability(tabId, binaryMeta = getCurrentBinaryMeta()) {
  if (binaryMeta?.kind !== 'raw') return null;
  return RAW_TAB_CAPABILITIES[tabId] || { level: 'limited', note: 'Compatibilité brute à confirmer pour cette vue.' };
}

function isStaticTabDisplayable(tabId, binaryMeta = getCurrentBinaryMeta()) {
  if (!isStaticFeatureEnabled(tabId)) return false;
  const family = PREMIUM_TAB_FAMILY[tabId];
  if (family && pluginUiState?.families?.[family] !== true) return false;
  if (family && getDisabledFamilies().has(family)) return false;
  if (binaryMeta?.kind === 'raw') return true;
  if (tabId === 'pe_resources') {
    const format = String(binaryMeta?.format || '').trim().toUpperCase();
    if (!format) return true;
    return format === 'PE';
  }
  return true;
}

function _normalizeStoredStaticTabOrder(rawOrder = {}) {
  const normalized = {};
  if (!rawOrder || typeof rawOrder !== 'object') return normalized;
  Object.entries(GROUPS).forEach(([groupId, tabs]) => {
    const saved = Array.isArray(rawOrder[groupId]) ? rawOrder[groupId] : [];
    const ordered = saved.filter((tabId, index) => tabs.includes(tabId) && saved.indexOf(tabId) === index);
    if (ordered.length) normalized[groupId] = [...ordered, ...tabs.filter((tabId) => !ordered.includes(tabId))];
  });
  return normalized;
}

function _getStoredStaticTabOrder() {
  return _normalizeStoredStaticTabOrder(_loadStorage().staticTabOrder);
}

function _getOrderedGroupTabs(groupId, binaryMeta = getCurrentBinaryMeta()) {
  const baseTabs = GROUPS[groupId] || GROUPS.code || [];
  const stored = _getStoredStaticTabOrder()[groupId];
  const storedOrder = stored ? [...stored, ...baseTabs.filter((t) => !stored.includes(t))] : baseTabs;
  return storedOrder.filter((tabId) => isStaticTabDisplayable(tabId, binaryMeta));
}

function _persistStaticTabOrder(groupId, orderedVisibleTabs) {
  const baseTabs = GROUPS[groupId] || GROUPS.code || [];
  const stored = _getStoredStaticTabOrder();
  const currentOrder = Array.isArray(stored[groupId]) && stored[groupId].length
    ? stored[groupId].filter((tabId) => baseTabs.includes(tabId))
    : [...baseTabs];
  const visible = orderedVisibleTabs.filter((tabId, index) => baseTabs.includes(tabId) && orderedVisibleTabs.indexOf(tabId) === index);
  const hidden = currentOrder.filter((tabId) => !visible.includes(tabId));
  stored[groupId] = [...visible, ...hidden];
  _saveStorage({ staticTabOrder: stored });
}

function getAvailableGroupTabs(groupId, binaryMeta = getCurrentBinaryMeta()) {
  return _getOrderedGroupTabs(groupId, binaryMeta).filter((tabId) => isStaticTabAvailable(tabId, binaryMeta));
}

function getFirstAvailableStaticGroup() {
  return Object.keys(GROUPS).find((groupId) => getAvailableGroupTabs(groupId).length > 0) || 'code';
}

function _pluginBadge(label, variant = '') {
  const safeLabel = escapeHtml(String(label || '').trim() || '—');
  const className = variant ? `plugin-badge plugin-badge--${variant}` : 'plugin-badge';
  return `<span class="${className}">${safeLabel}</span>`;
}

function renderPluginManager(state = pluginUiState) {
  const summaryEl = document.getElementById('pluginStateSummary');
  const listEl = document.getElementById('pluginStateList');
  const hintEl = document.getElementById('pluginStateHint');
  if (!summaryEl || !listEl) return;

  const unlockedStatuses = new Set(['active', 'unlocked', 'grace']);
  const stateCounts = state?.stateCounts && typeof state.stateCounts === 'object' ? state.stateCounts : {};
  const activeCount = Number(stateCounts.active || 0);
  const lockedCount = (Array.isArray(state?.plugins) ? state.plugins : []).filter((plugin) => plugin?.licenseRequired && !unlockedStatuses.has(String(plugin?.licenseStatus || '').trim())).length;
  const issueCount = ['invalid', 'incompatible', 'failed'].reduce((count, key) => count + Number(stateCounts[key] || 0), 0);

  summaryEl.innerHTML = [
    `<div class="plugin-summary-chip"><strong>${Number(state?.pluginCount || 0)}</strong><span>plugins détectés</span></div>`,
    `<div class="plugin-summary-chip plugin-summary-chip--active"><strong>${activeCount}</strong><span>actifs dans le host</span></div>`,
    `<div class="plugin-summary-chip plugin-summary-chip--locked"><strong>${lockedCount}</strong><span>verrouillés ou en attente de clé</span></div>`,
    `<div class="plugin-summary-chip plugin-summary-chip--error"><strong>${issueCount}</strong><span>avec erreur ou incompatibilité</span></div>`,
  ].join('');

  const plugins = Array.isArray(state?.plugins) ? state.plugins : [];
  if (!plugins.length) {
    listEl.innerHTML = `<div class="plugin-state-loading">${escapeHtml(state?.error || 'Aucun plugin actif ou détecté pour le moment.')}</div>`;
  } else {
    listEl.innerHTML = plugins.map((plugin) => {
      const licenseLabel = plugin.licenseRequired
        ? `${plugin.licenseMode || 'clé'} · ${plugin.licenseStatus || 'locked'}`
        : 'pas de clé requise';
      const stateVariant = plugin.state === 'active'
        ? 'active'
        : (plugin.state === 'disabled' ? 'disabled' : (plugin.state === 'failed' ? 'error' : 'warning'));
      const licenseUnlocked = !plugin.licenseRequired || unlockedStatuses.has(String(plugin.licenseStatus || '').trim());
      const cardModifier = plugin.state === 'active'
        ? 'active'
        : (!licenseUnlocked ? 'locked' : 'error');
      const licenseVariant = (!licenseUnlocked)
        ? 'locked'
        : (plugin.licenseRequired ? 'info' : 'active');
      const disabledFamilies = getDisabledFamilies();
      const isSoftDisabled = plugin.state === 'active' && !!plugin.family && disabledFamilies.has(plugin.family);
      const toggleTitle = isSoftDisabled
        ? 'Cliquer pour réactiver ce plugin (onglets et analyse croisée)'
        : 'Cliquer pour désactiver ce plugin (masque les onglets et l\'analyse croisée)';
      const stateBadge = plugin.state === 'active' && plugin.id && !!plugin.family
        ? `<button class="plugin-badge plugin-badge--${isSoftDisabled ? 'disabled' : 'active'} plugin-state-toggle" data-plugin-family="${escapeHtml(plugin.family)}" title="${escapeHtml(toggleTitle)}">${isSoftDisabled ? 'inactif' : 'active'}</button>`
        : _pluginBadge(plugin.state || 'unknown', stateVariant);
      const badges = [
        stateBadge,
        _pluginBadge(plugin.licenseRequired ? 'licence' : 'gratuit', licenseVariant),
      ];
      if (plugin.encrypted) badges.push(_pluginBadge('chiffré', 'info'));
      if (plugin.bundleFormat) badges.push(_pluginBadge(plugin.bundleFormat, 'info'));
      const hasFooter = (Array.isArray(plugin.capabilities) && plugin.capabilities.length)
        || (Array.isArray(plugin.commands) && plugin.commands.length);
      return `
        <article class="plugin-card plugin-card--${cardModifier}">
          <div class="plugin-card-body">
            <div class="plugin-card-head">
              <div>
                <h4 class="plugin-card-title">${escapeHtml(plugin.name || plugin.id || 'Plugin')}</h4>
                <div class="plugin-card-subtitle">${escapeHtml(plugin.id || '')} · v${escapeHtml(plugin.version || '0.0.0')} · ${escapeHtml(plugin.kind || '')}</div>
              </div>
              <div class="plugin-card-badges">${badges.join('')}</div>
            </div>
            <div class="plugin-card-meta">
              ${plugin.licenseMessage ? `<div class="plugin-card-meta-row"><strong>Licence</strong>${escapeHtml(plugin.licenseMessage)}</div>` : `<div class="plugin-card-meta-row"><strong>Licence</strong>${escapeHtml(licenseLabel)}</div>`}
              ${plugin.licensee ? `<div class="plugin-card-meta-row"><strong>Titulaire</strong>${escapeHtml(plugin.licensee)}</div>` : ''}
              ${plugin.licenseId ? `<div class="plugin-card-meta-row"><strong>ID</strong>${escapeHtml(plugin.licenseId)}</div>` : ''}
              ${plugin.error ? `<div class="plugin-card-meta-row"><strong>Erreur</strong>${escapeHtml(plugin.error)}</div>` : ''}
              ${plugin.licensePath ? `<div class="plugin-card-meta-row"><strong>Fichier licence</strong><code>${escapeHtml(plugin.licensePath)}</code></div>` : ''}
              ${plugin.rootPath ? `<div class="plugin-card-meta-row"><strong>Dossier</strong><code>${escapeHtml(plugin.rootPath)}</code></div>` : ''}
              ${plugin.licenseMode === 'pofplug' && !licenseUnlocked ? `<div class="plugin-card-meta-row"><button class="btn btn-primary btn-sm" onclick="if(typeof showPanel==='function')showPanel('options')">Se connecter →</button></div>` : ''}
            </div>
          </div>
          ${hasFooter ? `
          <div class="plugin-card-footer">
            ${Array.isArray(plugin.capabilities) && plugin.capabilities.length ? `
              <div class="plugin-capability-list">
                ${plugin.capabilities.map((c) => `<span class="plugin-capability-chip">${escapeHtml(c)}</span>`).join('')}
              </div>` : ''}
            ${Array.isArray(plugin.commands) && plugin.commands.length ? `
              <div class="plugin-capability-list">
                ${plugin.commands.map((cmd) => `<span class="plugin-capability-chip">${escapeHtml(cmd)}</span>`).join('')}
              </div>` : ''}
          </div>` : ''}
        </article>
      `;
    }).join('');
    listEl.querySelectorAll('.plugin-state-toggle').forEach((btn) => {
      btn.addEventListener('click', () => {
        const family = btn.dataset.pluginFamily;
        if (!family) return;
        const cur = getDisabledFamilies();
        if (cur.has(family)) { cur.delete(family); } else { cur.add(family); }
        setDisabledFamilies(cur);
        tabDataCache.cross_analysis = null;
        renderPluginManager(state);
        showGroup(getActiveStaticGroup(), getActiveStaticTab());
      });
    });
  }

  if (hintEl) {
    if (state?.error) hintEl.textContent = state.error;
    else if (!plugins.length) hintEl.textContent = 'Installe un plugin dans le dossier utilisateur pour l’activer dans tous tes projets.';
    else hintEl.textContent = 'Les plugins installés ici sont globaux à ton utilisateur. Les plugins premium suivent la session Compte de l’extension ; les anciennes licences locales restent un mode de migration.';
  }
}

function clearRecentBinaries() {
  if (binarySourceController) { binarySourceController.clearRecentBinaries(); return; }
  _saveStorage({ recentBinaries: [] });
  vscode.postMessage({ type: 'hubClearRecentBinaries' });
}

function removeRecentBinary(binaryPath) {
  if (!binarySourceController) {
    const target = String(binaryPath || '').trim();
    if (!target) return;
    _saveStorage({ recentBinaries: getRecentBinaries().filter((e) => e?.path !== target) });
  }
}

function clearActiveBinarySelection() {
  binarySourceController?.clearActiveBinarySelection?.();
}

function renderRecentBinaries() {
  binarySourceController?.renderRecentBinaries?.();
}

function openBinaryMenu() {
  binarySourceController?.openBinaryMenu?.();
}

function closeBinaryMenu() {
  binarySourceController?.closeBinaryMenu?.();
}

function toggleBinaryMenu() {
  if (!binarySourceController) return;
  if (document.getElementById('topBarBinaryMenu')?.hidden) binarySourceController.openBinaryMenu();
  else binarySourceController.closeBinaryMenu();
}
