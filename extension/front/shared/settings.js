// ── Settings ─────────────────────────────────────────────────────────────────
let _settingsCache = null;
let _settingsDebounce = null;

function renderStaticFeatureSettings(settings = _settingsCache || {}) {
  const checklist = document.getElementById('staticFeatureChecklist');
  if (!checklist) return;

  // Rebuild the checklist to reflect currently registered tabs (including plugin tabs)
  const allFeatureIds = getStaticFeatureIds();
  const existingIds = new Set(
    Array.from(checklist.querySelectorAll('[data-static-feature]')).map((el) => el.dataset.staticFeature)
  );
  const needsRebuild = allFeatureIds.length !== existingIds.size
    || allFeatureIds.some((id) => !existingIds.has(id));

  if (needsRebuild) {
    checklist.replaceChildren();
    Object.entries(GROUPS).forEach(([groupId, tabs]) => {
      tabs.forEach((tabId) => {
        const label = document.createElement('label');
        label.className = 'settings-feature-check';
        label.classList.toggle('is-essential', STATIC_SIMPLE_FEATURES.has(tabId));
        label.title = `${GROUP_LABELS[tabId] || tabId} - ${groupId.toUpperCase()}`;
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.dataset.staticFeature = tabId;
        const text = document.createElement('span');
        text.textContent = GROUP_LABELS[tabId] || tabId;
        label.append(input, text);
        checklist.appendChild(label);
      });
    });
  }

  const savedFeatures = Array.isArray(settings.enabledStaticFeatures)
    ? settings.enabledStaticFeatures.filter((tabId) => allFeatureIds.includes(tabId))
    : [];
  const mode = settings.interfaceMode === 'simple' ? 'simple' : 'advanced';
  const checkedFeatures = mode === 'simple'
    ? STATIC_SIMPLE_FEATURES
    : new Set(savedFeatures.length ? savedFeatures : allFeatureIds);
  checklist.querySelectorAll('[data-static-feature]').forEach((input) => {
    input.checked = checkedFeatures.has(input.dataset.staticFeature);
  });
}

function syncStaticInterfaceModeControls(settings = _settingsCache || {}) {
  const mode = settings.interfaceMode === 'simple' ? 'simple' : 'advanced';
  const hiddenInput = document.getElementById('settingInterfaceMode');
  const picker = document.getElementById('staticFeatureSettings');
  if (hiddenInput) hiddenInput.value = mode;
  document.querySelectorAll('[data-interface-mode]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.interfaceMode === mode);
    btn.setAttribute('aria-pressed', btn.dataset.interfaceMode === mode ? 'true' : 'false');
  });
  if (picker) {
    picker.classList.toggle('is-disabled', mode === 'simple');
    picker.querySelectorAll('input, button').forEach((control) => {
      control.disabled = mode === 'simple';
    });
  }
}

function refreshStaticNavigationForSettings() {
  updateActiveContextBars(window._lastDisasmAddr);
  if (document.getElementById('panel-static')?.classList.contains('active')) {
    const saved = _loadStorage();
    showGroup(saved.group || 'code', saved.tab || getActiveStaticTab());
  }
}

function _applySettings(settings) {
  _settingsCache = settings;
  if (typeof applyGlobalAiGenerationSettings === 'function') {
    applyGlobalAiGenerationSettings(settings);
  }
  if (typeof applyGlobalAiPricingRules === 'function') {
    applyGlobalAiPricingRules(settings.aiPricingRules);
  }
  renderAiPricingRules(settings.aiPricingRules);
  document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
    const key = el.dataset.key;
    if (!(key in settings)) return;
    if (el.type === 'checkbox') el.checked = settings[key] === true;
    else el.value = String(settings[key]);
  });
  renderStaticFeatureSettings(settings);
  syncStaticInterfaceModeControls(settings);
  if (settings.codeFontSize) {
    document.documentElement.style.setProperty('--code-font-size', settings.codeFontSize + 'px');
  }
  // Pre-fill existing panel selects with defaults
  const mappings = { stringsEncoding: 'stringsEncoding', stringsMinLen: 'stringsMinLen', asmSyntax: 'disasmSyntax' };
  for (const [settingKey, elId] of Object.entries(mappings)) {
    const el = document.getElementById(elId);
    if (el && settings[settingKey] != null) el.value = String(settings[settingKey]);
  }
  if (Object.keys(_decompilerAvailability).length || Object.keys(_decompilerMeta).length) {
    populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
    _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  }
  refreshStaticNavigationForSettings();
}

function _collectSettings() {
  const settings = { ...(_settingsCache || {}) };
  document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
    const key = el.dataset.key;
    const type = el.dataset.type;
    if (el.type === 'checkbox') settings[key] = el.checked;
    else if (type === 'float') settings[key] = parseFloat(el.value);
    else if (type === 'int') settings[key] = parseInt(el.value, 10);
    else settings[key] = el.value;
  });
  if (window.POFAiGenerationSettings) {
    const generation = window.POFAiGenerationSettings.fromGlobalSettings(settings);
    settings.aiTemperature = generation.temperature;
    settings.aiTopP = generation.top_p;
    settings.aiMaxTokens = generation.max_tokens;
  }
  settings.aiPricingRules = collectAiPricingRules();
  settings.decompilerLocalPaths = {};
  document.querySelectorAll('#panel-options [data-decompiler-local-path]').forEach((el) => {
    const id = String(el.dataset.decompilerLocalPath || '').trim();
    const value = String(el.value || '').trim();
    if (id && value) settings.decompilerLocalPaths[id] = value;
  });
  settings.interfaceMode = document.getElementById('settingInterfaceMode')?.value === 'simple' ? 'simple' : 'advanced';
  const selectedFeatures = settings.interfaceMode === 'simple'
    ? Array.from(STATIC_SIMPLE_FEATURES)
    : Array.from(document.querySelectorAll('[data-static-feature]'))
      .filter((input) => input.checked)
      .map((input) => input.dataset.staticFeature)
      .filter((tabId) => getStaticFeatureIds().includes(tabId));
  settings.enabledStaticFeatures = selectedFeatures.length ? selectedFeatures : ['disasm'];
  return settings;
}

function createAiPricingRuleRow(rule = {}) {
  const row = document.createElement('div');
  row.className = 'ai-pricing-row';
  row.dataset.pricingId = String(rule.id || `pricing-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`);
  const model = document.createElement('input');
  model.type = 'text';
  model.className = 'input-inner settings-mono';
  model.placeholder = 'provider@modèle ou motif*';
  model.value = String(rule.model || '');
  model.dataset.pricingModel = 'true';
  model.setAttribute('aria-label', 'Modèle ou motif tarifaire');
  const inputPrice = document.createElement('input');
  inputPrice.type = 'number';
  inputPrice.className = 'input-inner';
  inputPrice.min = '0';
  inputPrice.step = '0.01';
  inputPrice.placeholder = '0.00';
  inputPrice.value = rule.inputPerMillion != null ? String(rule.inputPerMillion) : '';
  inputPrice.dataset.pricingInput = 'true';
  inputPrice.setAttribute('aria-label', 'Prix entrée par million de tokens');
  const outputPrice = document.createElement('input');
  outputPrice.type = 'number';
  outputPrice.className = 'input-inner';
  outputPrice.min = '0';
  outputPrice.step = '0.01';
  outputPrice.placeholder = '0.00';
  outputPrice.value = rule.outputPerMillion != null ? String(rule.outputPerMillion) : '';
  outputPrice.dataset.pricingOutput = 'true';
  outputPrice.setAttribute('aria-label', 'Prix sortie par million de tokens');
  const effectiveDate = document.createElement('input');
  effectiveDate.type = 'date';
  effectiveDate.className = 'input-inner';
  effectiveDate.value = String(rule.effectiveDate || '');
  effectiveDate.dataset.pricingDate = 'true';
  effectiveDate.setAttribute('aria-label', 'Date d’effet du tarif');
  const remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'btn btn-secondary ai-pricing-remove';
  remove.textContent = '×';
  remove.title = 'Supprimer ce tarif';
  remove.setAttribute('aria-label', 'Supprimer ce tarif');
  remove.addEventListener('click', () => {
    row.remove();
    renderAiPricingEmptyState();
    _scheduleSave();
  });
  row.append(model, inputPrice, outputPrice, effectiveDate, remove);
  row.querySelectorAll('input').forEach((input) => {
    input.addEventListener('change', _scheduleSave);
    input.addEventListener('input', _scheduleSave);
  });
  return row;
}

function renderAiPricingEmptyState() {
  const list = document.getElementById('aiPricingRulesList');
  if (!list) return;
  const rows = list.querySelectorAll('.ai-pricing-row');
  list.querySelector('.ai-pricing-empty')?.remove();
  if (!rows.length) {
    const empty = document.createElement('p');
    empty.className = 'ai-pricing-empty';
    empty.textContent = 'Aucun tarif configuré : les coûts resteront masqués.';
    list.appendChild(empty);
  }
}

function renderAiPricingRules(rules = []) {
  const list = document.getElementById('aiPricingRulesList');
  if (!list) return;
  list.replaceChildren();
  window.POFAiPricing.normalizeRules(rules).forEach((rule) => {
    list.appendChild(createAiPricingRuleRow(rule));
  });
  renderAiPricingEmptyState();
}

function collectAiPricingRules() {
  const rows = Array.from(document.querySelectorAll('#aiPricingRulesList .ai-pricing-row'));
  return window.POFAiPricing.normalizeRules(rows.map((row) => ({
    id: row.dataset.pricingId,
    model: row.querySelector('[data-pricing-model]')?.value,
    inputPerMillion: row.querySelector('[data-pricing-input]')?.value,
    outputPerMillion: row.querySelector('[data-pricing-output]')?.value,
    effectiveDate: row.querySelector('[data-pricing-date]')?.value,
  })));
}

document.getElementById('btnAiPricingAdd')?.addEventListener('click', () => {
  const list = document.getElementById('aiPricingRulesList');
  if (!list) return;
  list.querySelector('.ai-pricing-empty')?.remove();
  const row = createAiPricingRuleRow();
  list.appendChild(row);
  row.querySelector('[data-pricing-model]')?.focus();
});

function _getDecompilerLocalPathVisibility(key, hasCustomPath = false) {
  const normalizedKey = String(key || '').trim();
  if (!normalizedKey) return 'hidden';
  const current = String(_decompilerLocalUiState.visibilityById?.[normalizedKey] || '').trim();
  if (current === 'visible' || current === 'hidden') return current;
  return hasCustomPath ? 'visible' : 'hidden';
}

function _applyDecompilerLocalPathVisibility(key, visibility) {
  const normalizedKey = String(key || '').trim();
  const normalizedVisibility = String(visibility || 'hidden').trim() === 'visible' ? 'visible' : 'hidden';
  if (!normalizedKey) return;
  _decompilerLocalUiState.visibilityById[normalizedKey] = normalizedVisibility;
  document.querySelectorAll(`#panel-options [data-decompiler-local-toggle="${normalizedKey}"]`).forEach((button) => {
    const isVisible = normalizedVisibility === 'visible';
    button.setAttribute('aria-expanded', isVisible ? 'true' : 'false');
    const icon = button.querySelector('.decompiler-card-toggle-icon');
    if (icon) icon.textContent = isVisible ? '−' : '+';
  });
  document.querySelectorAll(`#panel-options [data-decompiler-local-panel="${normalizedKey}"]`).forEach((panel) => {
    const isVisible = normalizedVisibility === 'visible';
    panel.hidden = !isVisible;
    panel.classList.toggle('is-hidden', !isVisible);
  });
}

function _scheduleSave() {
  clearTimeout(_settingsDebounce);
  _settingsDebounce = setTimeout(() => {
    const settings = _collectSettings();
    _settingsCache = settings;
    syncStaticInterfaceModeControls(settings);
    refreshStaticNavigationForSettings();
    vscode.postMessage({ type: 'hubSaveSettings', settings });
    if (isStaticTabActive('decompile')) {
      vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
      requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
    }
  }, 500);
}

document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
  el.addEventListener('change', _scheduleSave);
  el.addEventListener('input', _scheduleSave);
});

document.querySelectorAll('[data-interface-mode]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.interfaceMode === 'simple' ? 'simple' : 'advanced';
    const input = document.getElementById('settingInterfaceMode');
    if (input) input.value = mode;
    _settingsCache = { ...(_settingsCache || {}), interfaceMode: mode };
    if (mode === 'simple') {
      document.querySelectorAll('[data-static-feature]').forEach((featureInput) => {
        featureInput.checked = STATIC_SIMPLE_FEATURES.has(featureInput.dataset.staticFeature);
      });
      _settingsCache.enabledStaticFeatures = Array.from(STATIC_SIMPLE_FEATURES);
    }
    syncStaticInterfaceModeControls(_settingsCache);
    refreshStaticNavigationForSettings();
    _scheduleSave();
  });
});

document.getElementById('staticFeatureChecklist')?.addEventListener('change', (event) => {
  if (!event.target?.matches?.('[data-static-feature]')) return;
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('btnStaticFeaturesAll')?.addEventListener('click', () => {
  document.querySelectorAll('[data-static-feature]').forEach((input) => { input.checked = true; });
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('btnStaticFeaturesEssential')?.addEventListener('click', () => {
  document.querySelectorAll('[data-static-feature]').forEach((input) => {
    input.checked = STATIC_SIMPLE_FEATURES.has(input.dataset.staticFeature);
  });
  _settingsCache = _collectSettings();
  refreshStaticNavigationForSettings();
  _scheduleSave();
});

document.getElementById('panel-options')?.addEventListener('click', (event) => {
  const btn = event.target.closest('[data-browse]');
  if (!btn) return;
  vscode.postMessage({ type: 'hubPickFile', target: btn.dataset.browse });
});

document.getElementById('decompilerStatusList')?.addEventListener('click', (event) => {
  const localToggle = event.target.closest('[data-decompiler-local-toggle]');
  if (localToggle) {
    event.preventDefault();
    event.stopPropagation();
    const key = String(localToggle.getAttribute('data-decompiler-local-toggle') || '').trim();
    if (!key) return;
    const nextVisibility = _getDecompilerLocalPathVisibility(key) === 'visible' ? 'hidden' : 'visible';
    _applyDecompilerLocalPathVisibility(key, nextVisibility);
    return;
  }
  const interactive = event.target.closest('input, button, select, textarea, option');
  const target = event.target.closest('[data-select-decompiler]');
  if (!target || (interactive && !interactive.hasAttribute('data-select-decompiler'))) return;
  const id = String(target.getAttribute('data-select-decompiler') || '').trim();
  if (!id) return;
  _selectedDecompilerCardId = id;
  if (_decompilerAvailability[id] !== false) {
    if (typeof decompileUiState !== 'undefined') decompileUiState.forcedDecompiler = id;
  }
  _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
  if (isStaticTabActive('decompile')) requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
});

document.getElementById('decompilerStatusList')?.addEventListener('keydown', (event) => {
  if (event.target?.matches?.('input, button, select, textarea, option')) return;
  const target = event.target.closest('[data-select-decompiler]');
  if (!target) return;
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  const id = String(target.getAttribute('data-select-decompiler') || '').trim();
  if (!id) return;
  _selectedDecompilerCardId = id;
  if (_decompilerAvailability[id] !== false) {
    if (typeof decompileUiState !== 'undefined') decompileUiState.forcedDecompiler = id;
  }
  _renderDecompilerStatusList({ ..._decompilerAvailability, _meta: _decompilerMeta });
  populateDecompilerProfiles({ ..._decompilerAvailability, _meta: _decompilerMeta });
  if (isStaticTabActive('decompile')) requestDecompileForCurrentSelection({ skipHistory: true, preserveStackEntry: true });
});

document.getElementById('panel-options')?.addEventListener('input', (event) => {
  if (event.target?.matches?.('[data-decompiler-local-path]')) {
    const key = event.target.dataset.decompilerLocalPath;
    const value = event.target.value;
    document.querySelectorAll(`#panel-options [data-decompiler-local-path="${key}"]`).forEach((input) => {
      if (input !== event.target) input.value = value;
    });
    _scheduleSave();
  }
});

document.getElementById('panel-options')?.addEventListener('change', (event) => {
  if (event.target?.matches?.('[data-decompiler-local-path]')) {
    const key = event.target.dataset.decompilerLocalPath;
    const value = event.target.value;
    document.querySelectorAll(`#panel-options [data-decompiler-local-path="${key}"]`).forEach((input) => {
      if (input !== event.target) input.value = value;
    });
    _scheduleSave();
  }
});

document.getElementById('btnResetSettings')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubResetSettings' });
});
document.getElementById('btnPluginRefresh')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubLoadPluginState' });
});
document.getElementById('btnPluginAdd')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubInstallPlugin' });
});
document.getElementById('btnOpenUserPluginDir')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubOpenPluginDirectory', scope: 'user' });
});

// ─── Gestionnaire de décompilateurs (panneau Options) ──────────────────────

window._decompilerImageUpdates = window._decompilerImageUpdates || {};
window._dockerRuntimeStatus = window._dockerRuntimeStatus || null;

function _formatDockerDigestForUi(digest, fallback = '') {
  const value = String(digest || fallback || '').trim();
  const match = value.match(/sha256:([a-f0-9]{12})[a-f0-9]*/i);
  return match ? match[1].toLowerCase() : '';
}

function _formatDockerDateForUi(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const date = new Date(raw);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('fr-FR', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function _dockerRuntimeSummaryLabel() {
  const status = window._dockerRuntimeStatus;
  if (!status) return 'non vérifié';
  if (!status.dockerFound) return status.errorLabel || 'Docker introuvable';
  if (!status.daemonOk) return status.errorLabel || 'daemon indisponible';
  if (!status.buildxOk) return status.errorLabel || 'buildx indisponible';
  return 'prêt';
}

/**
 * Construit et affiche la grille de statut des décompilateurs.
 * @param {object} available  — résultat de list_available_decompilers()
 */
function _renderDecompilerStatusList(available) {
  const container = document.getElementById('decompilerStatusList');
  const summary = document.getElementById('decompilerStatusSummary');
  if (!container) return;

  const meta = available._meta || {};
  const reasons = meta.reasons || {};
  const dockerImages = meta.docker_images || {};
  const dockerAvail  = meta.docker_images_available || {};
  const dockerPlatform = meta.docker_platform || {};
  const localAvail = meta.local_available || {};
  const localPaths = _settingsCache?.decompilerLocalPaths && typeof _settingsCache.decompilerLocalPaths === 'object'
    ? _settingsCache.decompilerLocalPaths
    : {};
  const activeId = _getActiveDecompilerSource();

  const allIds = Object.keys(available).filter(id => !id.startsWith('_'));

  if (_selectedDecompilerCardId && !allIds.includes(_selectedDecompilerCardId)) {
    _selectedDecompilerCardId = '';
  }
  const selectedId = _selectedDecompilerCardId || (activeId !== 'auto' ? activeId : '');

  if (allIds.length === 0) {
    if (summary) summary.innerHTML = '';
    container.innerHTML = '<div class="decompiler-status-loading">Aucun décompilateur configuré. Ajoutez-en un via le bouton "+" ou modifiez .pile-ou-face/decompilers.json.</div>';
    return;
  }

  const activeProvider = String(meta.provider || _getConfiguredDecompilerProvider() || 'auto').trim() || 'auto';
  const availableCount = allIds.filter((id) => !!available[id]).length;
  const localReadyCount = allIds.filter((id) => !!localAvail[id]).length;
  const dockerConfiguredCount = allIds.filter((id) => !!dockerImages[id]).length;

  if (summary) {
    summary.innerHTML = [
      `<div class="decompiler-summary-chip decompiler-summary-chip--accent"><strong>Provider</strong> ${escapeHtml(activeProvider)}</div>`,
      `<div class="decompiler-summary-chip"><strong>Docker</strong> ${escapeHtml(_dockerRuntimeSummaryLabel())}</div>`,
      `<div class="decompiler-summary-chip"><strong>${availableCount}/${allIds.length}</strong> prêts maintenant</div>`,
      `<div class="decompiler-summary-chip"><strong>${localReadyCount}</strong> prêts en local</div>`,
      `<div class="decompiler-summary-chip"><strong>${dockerConfiguredCount}</strong> avec image Docker</div>`,
    ].join('');
  }

  const cards = allIds.map(id => {
    const avail = !!available[id];
    const label = (meta.labels && meta.labels[id]) || id;
    const image = dockerImages[id] || '';
    const platform = dockerPlatform[id] || '';
    const dockerOk = image ? !!dockerAvail[id] : null;
    const localOk = !!localAvail[id];
    const localSpec = _getLocalPathSpecForDecompiler(id);
    const localPathValue = localSpec ? String(localPaths[localSpec.id] || '') : '';
    const localStatus = localOk
      ? 'Backend prêt'
      : (localSpec ? 'Backend non prêt' : 'Non pris en charge');
    const localStatusClass = localOk
      ? 'decompiler-badge--local-ok'
      : (localSpec ? 'decompiler-badge--local-err' : 'decompiler-badge--docker-off');
    const pathStatus = !localSpec
      ? ''
      : (localPathValue ? 'Chemin configuré' : 'Auto-détection');
    const localDetectionHint = _describeLocalDetectionHint(id, localSpec, localPathValue);
    const imageUpdateInfo = window._decompilerImageUpdates[id] || {};
    const imageUpdateStatus = imageUpdateInfo.image === image ? String(imageUpdateInfo.status || '') : '';
    const dockerStatus = !image
      ? 'Non configuré'
      : (dockerOk
        ? (imageUpdateStatus === 'update-available'
          ? 'Update disponible'
          : imageUpdateStatus === 'checking'
            ? 'Vérification update…'
            : imageUpdateStatus === 'up-to-date'
              ? 'Image à jour'
              : imageUpdateStatus === 'unknown'
                ? (imageUpdateInfo.errorLabel || 'Update non vérifiable')
                : 'Image prête')
        : 'Image absente');
    const dockerStatusClass = !image
      ? 'decompiler-badge--docker-off'
      : (imageUpdateStatus === 'update-available'
        ? 'decompiler-badge--docker-update'
        : (dockerOk ? 'decompiler-badge--docker-ok' : 'decompiler-badge--docker-err'));
    const dockerUpdateHint = imageUpdateStatus === 'update-available'
      ? 'Nouvelle image publiée'
      : imageUpdateStatus === 'up-to-date'
        ? 'Dernière image installée'
        : imageUpdateStatus === 'unknown'
          ? (imageUpdateInfo.errorLabel || 'Update non vérifiable')
          : '';
    const dockerDigest = _formatDockerDigestForUi(imageUpdateInfo.localDigest, imageUpdateInfo.localImageId);
    const dockerCreated = _formatDockerDateForUi(imageUpdateInfo.localCreated);
    const dockerPlatformLabel = imageUpdateInfo.localPlatform || platform || '';
    const dockerCacheHint = imageUpdateInfo.cached && imageUpdateInfo.cacheAgeMs != null
      ? `Statut en cache (${Math.max(1, Math.round(Number(imageUpdateInfo.cacheAgeMs) / 1000))}s)`
      : '';
    const dockerDetailLines = [
      dockerUpdateHint,
      dockerDigest ? `Digest ${dockerDigest}` : '',
      dockerPlatformLabel ? `Plateforme ${dockerPlatformLabel}` : '',
      dockerCreated ? `Créée ${dockerCreated}` : '',
      dockerCacheHint,
      image,
      image ? 'Container à la demande, supprimé après usage' : '',
    ].filter(Boolean);
    const availabilityLabel = avail ? 'Prêt' : 'Indisponible';
    const availabilityClass = avail ? 'decompiler-card-state--ready' : 'decompiler-card-state--off';
    const captionBits = [`Provider ${activeProvider}`];
    if (localSpec) captionBits.push(localOk ? 'backend local détecté' : 'backend local indisponible');
    if (image) captionBits.push(dockerOk ? 'image Docker prête' : 'image Docker à préparer');
    if (dockerUpdateHint) captionBits.push(dockerUpdateHint);
    if (!avail && reasons[id]) {
      captionBits.push(reasons[id]);
    }

    const statusDot = avail
      ? '<span class="decompiler-status-dot decompiler-status-dot--ok" title="Disponible"></span>'
      : '<span class="decompiler-status-dot decompiler-status-dot--err" title="Non disponible"></span>';

    const localBadge = `<span class="decompiler-badge ${localStatusClass}">${escapeHtml(localStatus)}</span>`;
    const dockerBadge = `<span class="decompiler-badge ${dockerStatusClass}"${image ? ` title="${escapeHtml(image)}"` : ''}>${escapeHtml(dockerStatus)}</span>`;

    const customTag = '';
    const isSelected = id === selectedId;
    const isActiveSource = id === activeId && activeId !== 'auto';
    const pathInputId = localSpec ? `settingDecompilerLocalPath_${id}` : '';
    const localVisibility = localSpec
      ? _getDecompilerLocalPathVisibility(localSpec.id, !!localPathValue)
      : 'hidden';
    const pathBlock = localSpec
      ? `<div class="decompiler-card-body">
          <button
            type="button"
            class="decompiler-card-toggle"
            data-decompiler-local-toggle="${localSpec.id}"
            aria-expanded="${localVisibility === 'visible' ? 'true' : 'false'}"
            aria-controls="decompilerLocalPanel_${localSpec.id}"
          >
            <span class="decompiler-card-toggle-copy">
              <span class="decompiler-card-toggle-title">Exécution locale</span>
              <span class="decompiler-card-toggle-subtitle">${escapeHtml(localPathValue ? 'Chemin local configuré' : 'Configurer un chemin local si besoin')}</span>
            </span>
            <span class="decompiler-card-toggle-icon" aria-hidden="true">${localVisibility === 'visible' ? '−' : '+'}</span>
          </button>
          <div id="decompilerLocalPanel_${localSpec.id}" class="decompiler-card-local-panel${localVisibility === 'visible' ? '' : ' is-hidden'}" data-decompiler-local-panel="${localSpec.id}"${localVisibility === 'visible' ? '' : ' hidden'}>
            <div class="decompiler-card-path-hint">${escapeHtml(localSpec.hint)}</div>
            <div class="decompiler-card-path-hint">${escapeHtml(localDetectionHint)}</div>
            <div class="decompiler-card-path-row">
              <input id="${pathInputId}" class="input-inner settings-input settings-mono decompiler-card-path-input" type="text" value="${escapeHtml(localPathValue)}" placeholder="${escapeHtml(localSpec.placeholder)}" data-decompiler-local-path="${localSpec.id}" />
              <button type="button" class="btn btn-secondary btn-sm" data-browse="${pathInputId}">Parcourir</button>
            </div>
          </div>
        </div>`
      : '';

    // Boutons d'actions inline dans la card — tous les décompilateurs sont dans le JSON
    const editBtn = `<button type="button" class="btn btn-secondary btn-xs decompiler-card-btn-edit" data-decompiler-edit="${id}" title="Modifier ${escapeHtml(label)}">✎ Modifier</button>`;
    const hideOrDeleteBtn = `<button type="button" class="btn btn-xs btn-danger-soft decompiler-card-btn-remove" data-decompiler-remove="${id}" title="Supprimer ${escapeHtml(label)}">✕ Supprimer</button>`;
    const pullMode = dockerOk ? 'update' : 'pull';
    const pullBtn = image && (!dockerOk || imageUpdateStatus === 'update-available')
      ? `<button type="button" class="btn btn-primary btn-xs decompiler-card-btn-pull" data-decompiler-pull="${escapeHtml(id)}" data-decompiler-image="${escapeHtml(image)}" data-decompiler-platform="${escapeHtml(platform)}" data-decompiler-pull-mode="${pullMode}" title="${dockerOk ? 'Mettre à jour' : 'Télécharger'} ${escapeHtml(image)}">${dockerOk ? '↻ Mettre à jour' : '⬇ Télécharger'}</button>`
      : '';
    const forcePullBtn = image && dockerOk && imageUpdateStatus && imageUpdateStatus !== 'checking' && imageUpdateStatus !== 'update-available'
      ? `<button type="button" class="btn btn-secondary btn-xs decompiler-card-btn-pull" data-decompiler-pull="${escapeHtml(id)}" data-decompiler-image="${escapeHtml(image)}" data-decompiler-platform="${escapeHtml(platform)}" data-decompiler-pull-mode="force" title="Repull ${escapeHtml(image)}">↻ Repull</button>`
      : '';

    return `<article class="decompiler-card${isSelected ? ' decompiler-card--selected' : ''}${isActiveSource ? ' decompiler-card--active' : ''}${avail ? '' : ' decompiler-card--disabled'}" data-select-decompiler="${id}" role="button" tabindex="0" title="Sélectionner ${escapeHtml(label)}" aria-pressed="${isActiveSource ? 'true' : 'false'}">
      <div class="decompiler-card-topline">
        <div class="decompiler-card-title-wrap">
          <div class="decompiler-card-head">
            <span class="decompiler-row-status">${statusDot}</span>
            <span class="decompiler-row-name">${escapeHtml(label)}${customTag}</span>
            <span class="decompiler-card-id">${escapeHtml(id)}</span>
          </div>
          <p class="decompiler-card-caption">${escapeHtml(captionBits.join(' • '))}</p>
        </div>
        <div class="decompiler-card-topright">
          ${isActiveSource ? '<span class="decompiler-card-pin decompiler-card-pin--active">✓ actif</span>' : ''}
          <div class="decompiler-card-state ${availabilityClass}">${availabilityLabel}</div>
        </div>
      </div>

      <div class="decompiler-row-badges">${localBadge}${dockerBadge}</div>

      <div class="decompiler-card-grid">
        <div class="decompiler-card-metric">
          <span class="decompiler-card-metric-label">Local</span>
          <span class="decompiler-card-metric-value">${escapeHtml(localStatus)}${pathStatus ? `<br>${escapeHtml(pathStatus)}` : ''}${localSpec && localPathValue ? `<br>${escapeHtml(localPathValue)}` : ''}${localDetectionHint ? `<br>${escapeHtml(localDetectionHint)}` : ''}</span>
        </div>
        <div class="decompiler-card-metric">
          <span class="decompiler-card-metric-label">Docker</span>
          <span class="decompiler-card-metric-value">${escapeHtml(dockerStatus)}${dockerDetailLines.length ? `<br>${dockerDetailLines.map(line => escapeHtml(line)).join('<br>')}` : ''}</span>
        </div>
      </div>

      <div class="decompiler-card-pull-area" id="decompilerPullArea_${escapeHtml(id)}" hidden></div>

      ${pathBlock}
      <div class="decompiler-card-actions decompiler-card-actions--inline">
        ${pullBtn}
        ${forcePullBtn}
        ${editBtn}
        ${hideOrDeleteBtn}
      </div>
    </article>`;
  });

  container.innerHTML = cards.join('');
  container.querySelectorAll('[data-decompiler-local-toggle]').forEach((button) => {
    _applyDecompilerLocalPathVisibility(
      button.getAttribute('data-decompiler-local-toggle'),
      button.getAttribute('aria-expanded') === 'true' ? 'visible' : 'hidden',
    );
  });
  _updateDecompilerActionButtons();

  // Délégation d'events pour les boutons inline dans les cards
  container.querySelectorAll('[data-decompiler-edit]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerEdit;
      vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerEdit', requestId: null, args: [id] });
    });
  });
  container.querySelectorAll('[data-decompiler-remove]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerRemove;
      vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerRemove', requestId: null, args: [id] });
    });
  });
  container.querySelectorAll('[data-decompiler-pull]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const id = btn.dataset.decompilerPull;
      const image = btn.dataset.decompilerImage;
      const platform = btn.dataset.decompilerPlatform || '';
      const mode = btn.dataset.decompilerPullMode || 'pull';
      btn.disabled = true;
      btn.textContent = mode === 'update'
        ? '⏳ Mise à jour…'
        : mode === 'force'
          ? '⏳ Repull…'
          : '\u23F3 T\u00E9l\u00E9chargement\u2026';
      const area = document.getElementById('decompilerPullArea_' + id);
      if (area) {
        area.removeAttribute('hidden');
        area.textContent = '';
        const log = document.createElement('div');
        log.className = 'decompiler-pull-log';
        const progress = document.createElement('progress');
        progress.className = 'decompiler-pull-progress';
        progress.value = 0;
        progress.max = 100;
        area.appendChild(log);
        area.appendChild(progress);
      }
      vscode.postMessage({ type: 'hubPullDecompilerImage', decompiler: id, image, platform, mode });
    });
  });
}

// ─── Gestionnaire boutons décompilateurs ──────────────────────────────────────

/** Compteur de requêtes en vol pour gérer les états loading */
let _decompilerCmdPending = new Map(); // requestId → { btnId, label }
let _decompilerCmdSeq = 0;

/**
 * Lance une commande décompilateur depuis le webview avec feedback visuel.
 * @param {string} command   — ID de la commande VS Code à exécuter
 * @param {string} btnId     — ID du bouton HTML à mettre en loading
 * @param {string} loadLabel — Texte affiché pendant le chargement
 */
function _runDecompilerCommand(command, btnId, loadLabel, args = []) {
  const btn = document.getElementById(btnId);
  if (!btn || btn.disabled) return;

  const requestId = `dcmd_${++_decompilerCmdSeq}`;
  _decompilerCmdPending.set(requestId, { btnId, originalLabel: btn.textContent });

  // Désactiver tous les boutons d'action pendant qu'une commande est en vol
  _setDecompilerButtonsLocked(true, null); // null = verrouille TOUS les boutons (y compris Add)
  btn.textContent = loadLabel;
  btn.classList.add('btn--loading');

  vscode.postMessage({ type: 'hubExecuteCommand', command, requestId, args });

  // Sécurité : déverrouiller après 60s si hubCommandResult n'arrive jamais
  setTimeout(() => {
    if (_decompilerCmdPending.has(requestId)) {
      _decompilerCmdPending.delete(requestId);
      _onDecompilerCommandResult({ requestId: null, status: 'timeout' });
    }
  }, 60000);
}

/** Callback appelé quand `hubCommandResult` arrive depuis l'extension */
function _onDecompilerCommandResult(msg) {
  const pending = msg.requestId ? _decompilerCmdPending.get(msg.requestId) : null;
  if (pending) {
    _decompilerCmdPending.delete(msg.requestId);
    const btn = document.getElementById(pending.btnId);
    if (btn) {
      btn.textContent = pending.originalLabel;
      btn.classList.remove('btn--loading');
    }
  }
  // Déverrouiller tous les boutons (y compris Add)
  _setDecompilerButtonsLocked(false);

  // Feedback visuel bref sur le bouton (flash vert/rouge)
  if (pending) {
    const btn = document.getElementById(pending.btnId);
    if (btn && msg.status === 'done') {
      btn.classList.add('btn--flash-ok');
      setTimeout(() => btn.classList.remove('btn--flash-ok'), 1200);
    } else if (btn && msg.status === 'error') {
      btn.classList.add('btn--flash-err');
      setTimeout(() => btn.classList.remove('btn--flash-err'), 1500);
    }
  }

  // La liste est déjà rafraîchie via hubDecompilerList envoyé par staticHandlers
  // Mais si c'est une action sans refresh (test, openConfig), pas besoin de rien faire
}

/** Verrouille/déverrouille les boutons d'action (sauf le bouton actif lui-même) */
function _setDecompilerButtonsLocked(locked, exceptBtnId = null) {
  const ACTION_BTNS = ['btnDecompilerAdd', 'btnDecompilerEdit', 'btnDecompilerRemove', 'btnDecompilerTest'];
  for (const id of ACTION_BTNS) {
    if (id === exceptBtnId) continue;
    const btn = document.getElementById(id);
    if (btn) btn.disabled = locked;
  }
}

// ── Toast system ───────────────────────────────────────────────────────────────
(function _initToastContainer() {
  if (document.getElementById('pof-toast-container')) return;
  const el = document.createElement('div');
  el.id = 'pof-toast-container';
  document.body.appendChild(el);
})();

function _showToast(params) {
  toastController?.showToast(params);
}

// ── Détection changements d'état décompilateurs ───────────────────────────────
// null = pas encore initialisé (premier chargement = silencieux)
let _prevDecompilerAvailability = null;

function _detectDecompilerStateChanges(newResult) {
  const newMeta = newResult._meta || {};
  const newIds = Object.keys(newResult).filter(k => !k.startsWith('_'));
  const labels = newMeta.labels || {};

  if (_prevDecompilerAvailability === null) {
    // Premier chargement — initialiser silencieusement sans toast
    _prevDecompilerAvailability = Object.fromEntries(
      newIds.map(id => [id, !!newResult[id]])
    );
    return;
  }

  for (const id of newIds) {
    const wasAvailable = !!_prevDecompilerAvailability[id];
    const isAvailable  = !!newResult[id];
    const wasKnown = id in _prevDecompilerAvailability;

    if (!wasKnown && isAvailable) {
      // Nouveau décompilateur configuré ET déjà dispo
      _showToast({
        title: `${labels[id] || id} ajouté`,
        sub: 'Décompilateur détecté et prêt',
        icon: '✅',
        variant: 'ready',
        duration: 6000,
      });
    } else if (wasKnown && !wasAvailable && isAvailable) {
      // Était configuré mais indisponible, maintenant prêt
      _showToast({
        title: `${labels[id] || id} prêt`,
        sub: 'Le décompilateur est maintenant disponible',
        icon: '✅',
        variant: 'ready',
        duration: 6000,
      });
    } else if (!wasKnown && !isAvailable) {
      // Nouveau décompilateur configuré mais pas encore disponible
      _showToast({
        title: `${labels[id] || id} ajouté`,
        sub: 'Décompilateur configuré — en attente de disponibilité',
        icon: '⏳',
        variant: 'info',
        duration: 5000,
      });
    }
  }

  // Mettre à jour l'état mémorisé
  _prevDecompilerAvailability = Object.fromEntries(
    newIds.map(id => [id, !!newResult[id]])
  );
}

// ── Bouton Actualiser ──────────────────────────────────────────────────────────
document.getElementById('btnDecompilerRefresh')?.addEventListener('click', () => {
  const btn = document.getElementById('btnDecompilerRefresh');
  if (btn) { btn.disabled = true; btn.classList.add('btn--loading'); }
  const list = document.getElementById('decompilerStatusList');
  if (list) list.innerHTML = '<div class="decompiler-status-loading"><span class="decompiler-status-dot decompiler-status-dot--pending"></span> Interrogation…</div>';
  vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
  // Réactiver après réception de hubDecompilerList (géré plus haut)
  // Sécurité : timeout si pas de réponse
  setTimeout(() => {
    if (btn) { btn.disabled = false; btn.classList.remove('btn--loading'); }
  }, 8000);
});

// Réactiver le bouton refresh dès réception de la liste
const _origHandleDecompilerList = window._hubDecompilerListHook;
(function _patchDecompilerListForRefreshBtn() {
  const origHandler = window.addEventListener;
  // On intercepte via l'event hubDecompilerList déjà traité plus haut dans hub.js
  // Le plus simple : on observe quand _renderDecompilerStatusList est appelé
  const _origRender = _renderDecompilerStatusList;
  // Re-définir n'est pas possible (déclaré function), donc on patch via MutationObserver sur le container
  const list = document.getElementById('decompilerStatusList');
  if (list) {
    new MutationObserver(() => {
      const btn = document.getElementById('btnDecompilerRefresh');
      if (btn && !list.querySelector('.decompiler-status-loading')) {
        btn.disabled = false;
        btn.classList.remove('btn--loading');
      }
    }).observe(list, { childList: true });
  }
})();

// ── Bouton Ajouter ─────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerAdd')?.addEventListener('click', () => {
  _runDecompilerCommand('pileOuFace.decompilerAdd', 'btnDecompilerAdd', '…');
});

// ── Bouton Modifier ────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerEdit')?.addEventListener('click', () => {
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();
  if (selectedId && selectedId !== 'auto') {
    _runDecompilerCommand('pileOuFace.decompilerEdit', 'btnDecompilerEdit', '…', [selectedId]);
  } else {
    _runDecompilerCommand('pileOuFace.decompilerEdit', 'btnDecompilerEdit', '…');
  }
});

// ── Bouton Supprimer ───────────────────────────────────────────────────────────
document.getElementById('btnDecompilerRemove')?.addEventListener('click', () => {
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();
  if (selectedId && selectedId !== 'auto') {
    _runDecompilerCommand('pileOuFace.decompilerRemove', 'btnDecompilerRemove', '…', [selectedId]);
  } else {
    _runDecompilerCommand('pileOuFace.decompilerRemove', 'btnDecompilerRemove', '…');
  }
});

// ── Bouton Tester ──────────────────────────────────────────────────────────────
document.getElementById('btnDecompilerTest')?.addEventListener('click', () => {
  const btn = document.getElementById('btnDecompilerTest');
  if (!btn || btn.disabled) return;
  const selectedId = _selectedDecompilerCardId || _getActiveDecompilerSource();

  const requestId = `dcmd_${++_decompilerCmdSeq}`;
  _decompilerCmdPending.set(requestId, { btnId: 'btnDecompilerTest', originalLabel: btn.textContent });
  _setDecompilerButtonsLocked(true, 'btnDecompilerTest');
  btn.textContent = '…';
  btn.classList.add('btn--loading');

  vscode.postMessage({
    type: 'hubExecuteCommand',
    command: 'pileOuFace.decompilerTest',
    requestId,
    args: selectedId && selectedId !== 'auto' ? [selectedId] : [],
  });
});

// ── Bouton Config JSON ─────────────────────────────────────────────────────────
document.getElementById('btnDecompilerOpenConfig')?.addEventListener('click', () => {
  vscode.postMessage({ type: 'hubExecuteCommand', command: 'pileOuFace.decompilerOpenConfig', requestId: null });
});

// ── Actualisation automatique quand on ouvre le panneau Options ───────────────
(function _hookOptionsPanel() {
  let _lastOptionsVisible = false;
  const observer = new MutationObserver(() => {
    const panel = document.getElementById('panel-options');
    const isVisible = panel && !panel.classList.contains('hidden') && panel.style.display !== 'none';
    if (isVisible && !_lastOptionsVisible) {
      // Vient d'être ouvert
      const list = document.getElementById('decompilerStatusList');
      if (list && (list.querySelector('.decompiler-status-loading') || list.children.length === 0)) {
        vscode.postMessage({ type: 'hubListDecompilers', provider: _getConfiguredDecompilerProvider() });
      }
      vscode.postMessage({ type: 'hubLoadPluginState' });
      vscode.postMessage({ type: 'hubAiProvidersGet' });
    }
    _lastOptionsVisible = !!isVisible;
  });
  // Observer le conteneur principal pour détecter les changements de visibilité
  const root = document.querySelector('.hub-panels') || document.body;
  observer.observe(root, { attributes: true, subtree: true, attributeFilter: ['class', 'style'] });
})();

// ─── Fin gestionnaire décompilateurs ───────────────────────────────────────

// Request symbols when binary path changes
binaryPathInput?.addEventListener('blur', () => {
  const bp = binaryPathInput?.value?.trim();
  if (!bp) return;
  setDynamicTraceStatus('Actualisation du profil binaire...');
  requestRunTraceInit(null, bp);
  requestSymbols();
});

binaryPathInput?.addEventListener('input', () => {
  if (staticBinaryInput) staticBinaryInput.value = binaryPathInput.value;
});

argvPayloadInput?.addEventListener('input', () => {
  updateArgvPayloadHint();
  const raw = argvPayloadInput.value.trim();
  if (!raw) {
    setDynamicTraceStatus('Prêt.');
    return;
  }
  try {
    const parsed = parsePayloadExpressionPreview(raw);
    setDynamicTraceStatus(`${dynamicPayloadTargetLabel(getDynamicEffectivePayloadTarget())} prêt: ${parsed.bytes} byte(s).`);
  } catch (_) {
    setDynamicTraceStatus('Expression payload invalide.');
  }
});

dynamicPayloadTargetMode?.addEventListener('change', () => {
  dynamicTraceInitState.payloadTargetMode = getDynamicPayloadTargetMode();
  updateArgvPayloadHint();
  requestRunTraceInit(null, binaryPathInput?.value?.trim() || '');
});

// Platform
vscode.postMessage({ type: 'getPlatform' });
vscode.postMessage({ type: 'hubLoadPluginState' });

// Sidebar sections collapsibles
document.querySelectorAll('.sidebar-section-header').forEach(btn => {
  btn.addEventListener('click', () => {
    const sec = btn.dataset.section;
    const body = document.querySelector(`[data-section-body="${sec}"]`);
    if (!body) return;
    const collapsed = body.style.display === 'none';
    body.style.display = collapsed ? '' : 'none';
    btn.textContent = (collapsed ? '▼ ' : '▶ ') + btn.textContent.slice(2);
    const state = JSON.parse(localStorage.getItem('pof-sidebar-sections') || '{}');
    state[sec] = !collapsed;
    localStorage.setItem('pof-sidebar-sections', JSON.stringify(state));
  });
});
// Restore collapsed state
const _sidebarState = JSON.parse(localStorage.getItem('pof-sidebar-sections') || '{}');
Object.entries(_sidebarState).forEach(([sec, open]) => {
  const body = document.querySelector(`[data-section-body="${sec}"]`);
  const btn = document.querySelector(`.sidebar-section-header[data-section="${sec}"]`);
  if (!body || !btn) return;
  body.style.display = open ? '' : 'none';
  btn.textContent = (open ? '▼ ' : '▶ ') + btn.textContent.slice(2);
});

const MAX_VISIBLE_TABS = 7;

function updateTabOverflow() {
  staticToolsWidgetsController?.updateTabOverflow();
}

// ── Bookmarks ──────────────────────────────────────────────────────────────
function loadBookmarks() {
  return Object.entries(window._annotations || {})
    .filter(([, entry]) => entry && entry.bookmark)
    .map(([addr, entry]) => ({
      addr,
      label: entry.bookmarkLabel || entry.name || addr,
      color: entry.bookmarkColor || '#4fc1ff',
      timestamp: Date.parse(entry.bookmarkUpdated || entry.updated || '') || 0,
    }))
    .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
}

function addBookmark(addr) {
  if (!getStaticBinaryPath()) return;
  const normalizedAddr = normalizeHexAddress(addr);
  if (!normalizedAddr) return;
  const existing = window._annotations?.[normalizedAddr] || {};
  window._annotations = {
    ...(window._annotations || {}),
    [normalizedAddr]: {
      ...existing,
      bookmark: true,
      bookmarkLabel: existing.bookmarkLabel || existing.name || normalizedAddr,
      bookmarkColor: existing.bookmarkColor || '#4fc1ff',
      bookmarkUpdated: new Date().toISOString(),
    },
  };
  renderBookmarks();
  vscode.postMessage({
    type: 'hubSaveBookmark',
    binaryPath: getStaticBinaryPath(),
    addr: normalizedAddr,
    label: window._annotations[normalizedAddr].bookmarkLabel,
    color: window._annotations[normalizedAddr].bookmarkColor,
  });
}

function renderBookmarks() {
  const container = document.getElementById('bookmarksList');
  if (!container) return;
  const bm = loadBookmarks();
  container.replaceChildren();
  if (bm.length === 0) {
    const p = document.createElement('p');
    p.className = 'hint';
    p.style.padding = '4px 8px';
    p.style.opacity = '0.6';
    p.style.fontSize = '11px';
    p.textContent = 'Aucun bookmark. Ctrl+B dans le désassemblage.';
    container.appendChild(p);
    updateDisasmSessionSummary();
    return;
  }
  bm.forEach(b => {
    const btn = document.createElement('div');
    btn.className = 'bookmark-item';
    btn.style.borderLeft = `2px solid ${b.color || '#4fc1ff'}`;

    const label = document.createElement('span');
    label.className = 'bm-label';
    label.textContent = b.label || b.addr;
    btn.appendChild(label);

    const del = document.createElement('button');
    del.className = 'bm-del';
    del.textContent = '×';
    del.title = 'Supprimer';
    del.addEventListener('click', (e) => {
      e.stopPropagation();
      const entry = window._annotations?.[b.addr];
      if (entry) {
        const nextEntry = { ...entry };
        delete nextEntry.bookmark;
        delete nextEntry.bookmarkLabel;
        delete nextEntry.bookmarkColor;
        delete nextEntry.bookmarkUpdated;
        window._annotations = { ...(window._annotations || {}) };
        if (isAnnotationEntryEmpty(nextEntry)) delete window._annotations[b.addr];
        else window._annotations[b.addr] = nextEntry;
      }
      renderBookmarks();
      vscode.postMessage({ type: 'hubDeleteBookmark', binaryPath: getStaticBinaryPath(), addr: b.addr });
    });
    btn.appendChild(del);

    btn.addEventListener('click', () => {
      const a = b.addr;
      document.getElementById('goToAddrInput').value = a;
      const badge = document.getElementById('annotationAddrBadge');
      if (badge) { badge.textContent = a; badge.dataset.addr = a; badge.classList.add('has-addr'); }
      const annotBtn = document.getElementById('btnAddAnnotation');
      if (annotBtn) annotBtn.disabled = false;
      vscode.postMessage({ type: 'hubGoToAddress', addr: a, binaryPath: getStaticBinaryPath() });
    });
    container.appendChild(btn);
  });
  updateDisasmSessionSummary();
}

document.getElementById('btnClearBookmarks')?.addEventListener('click', () => {
  const nextAnnotations = { ...(window._annotations || {}) };
  Object.keys(nextAnnotations).forEach((addr) => {
    const entry = nextAnnotations[addr];
    if (!entry?.bookmark) return;
    const nextEntry = { ...entry };
    delete nextEntry.bookmark;
    delete nextEntry.bookmarkLabel;
    delete nextEntry.bookmarkColor;
    delete nextEntry.bookmarkUpdated;
    if (isAnnotationEntryEmpty(nextEntry)) delete nextAnnotations[addr];
    else nextAnnotations[addr] = nextEntry;
  });
  window._annotations = nextAnnotations;
  renderBookmarks();
  vscode.postMessage({ type: 'hubClearBookmarks', binaryPath: getStaticBinaryPath() });
});

document.getElementById('btnBookmarkAddr')?.addEventListener('click', () => {
  const addr = window._lastDisasmAddr;
  if (addr) addBookmark(addr);
});

document.addEventListener('keydown', (e) => {
  if (e.ctrlKey && e.key === 'b') {
    const addr = window._lastDisasmAddr;
    if (addr) { addBookmark(addr); e.preventDefault(); }
  }
});

// ── Navigation history ─────────────────────────────────────────────────────
const _navHistory = [];
let _navIndex = -1;

function _loadStoredNavHistoryByBinary() {
  const raw = _loadStorage().navHistoryByBinary;
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
}

function normalizeNavHistoryTab(tab) {
  const normalized = String(tab || '').trim();
  return GROUPS.code.includes(normalized) ? normalized : 'disasm';
}

function normalizeNavHistorySource(source) {
  return String(source || '').trim();
}

function _normalizeNavHistoryEntries(rawEntries, binaryPath) {
  if (!Array.isArray(rawEntries)) return [];
  const normalizedPath = String(binaryPath || '').trim();
  return rawEntries
    .map((entry) => {
      const addr = normalizeHexAddress(entry?.addr || '');
      if (!addr) return null;
      return {
        addr,
        binaryPath: String(entry?.binaryPath || normalizedPath || '').trim(),
        ts: Number(entry?.ts || Date.now()),
        tab: normalizeNavHistoryTab(entry?.tab || 'disasm'),
        spanLength: normalizeSpanLength(entry?.spanLength || 1),
        source: normalizeNavHistorySource(entry?.source || ''),
      };
    })
    .filter(Boolean)
    .slice(-MAX_NAV_HISTORY_ENTRIES);
}

function persistNavigationHistory(binaryPath = getStaticBinaryPath()) {
  const normalizedPath = String(binaryPath || '').trim();
  if (!normalizedPath) return;
  const store = _loadStoredNavHistoryByBinary();
  const next = { ...store };
  const entries = _navHistory
    .filter((entry) => String(entry?.binaryPath || '').trim() === normalizedPath)
    .slice(-MAX_NAV_HISTORY_ENTRIES)
    .map((entry) => ({
      addr: entry.addr,
      binaryPath: normalizedPath,
      ts: Number(entry.ts || Date.now()),
      tab: normalizeNavHistoryTab(entry.tab || 'disasm'),
      spanLength: normalizeSpanLength(entry.spanLength || 1),
      source: normalizeNavHistorySource(entry.source || ''),
    }));
  next[normalizedPath] = {
    entries,
    index: entries.length ? Math.max(0, Math.min(_navIndex, entries.length - 1)) : -1,
    updatedAt: Date.now(),
  };
  const pruned = Object.entries(next)
    .sort((a, b) => Number(b[1]?.updatedAt || 0) - Number(a[1]?.updatedAt || 0))
    .slice(0, MAX_NAV_HISTORY_BINARIES);
  _saveStorage({
    navHistoryByBinary: Object.fromEntries(pruned),
  });
}

function syncNavigationHistoryForBinary(binaryPath = getStaticBinaryPath()) {
  _navHistory.length = 0;
  _navIndex = -1;
  const normalizedPath = String(binaryPath || '').trim();
  if (normalizedPath) {
    const stored = _loadStoredNavHistoryByBinary()[normalizedPath];
    const entries = _normalizeNavHistoryEntries(stored?.entries, normalizedPath);
    _navHistory.push(...entries);
    if (entries.length) {
      const desiredIndex = Number.isFinite(Number(stored?.index)) ? Number(stored.index) : (entries.length - 1);
      _navIndex = Math.max(0, Math.min(desiredIndex, entries.length - 1));
    }
  }
  updateNavButtons();
  renderDisasmNavigationHistory();
}

function formatNavigationHistoryTime(ts) {
  const date = new Date(Number(ts || Date.now()));
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function renderDisasmNavigationHistory() {
  const container = document.getElementById('disasmNavHistoryList');
  const clearBtn = document.getElementById('btnClearNavHistory');
  if (!container) return;
  container.replaceChildren();
  if (clearBtn) clearBtn.disabled = _navHistory.length === 0;
  if (!_navHistory.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = 'Aucune adresse visitée pour le moment.';
    container.appendChild(empty);
    return;
  }
  _navHistory
    .map((entry, index) => ({ entry, index }))
    .slice()
    .reverse()
    .forEach(({ entry, index }) => {
      const summary = getActiveContextSummary(entry.addr);
      const row = document.createElement('div');
      row.className = 'disasm-history-item';
      if (index === _navIndex) row.classList.add('active');

      const main = document.createElement('div');
      main.className = 'disasm-history-main';
      const title = document.createElement('div');
      title.className = 'disasm-history-title';
      title.textContent = summary.functionName || summary.symbolName || `Adresse ${entry.addr}`;
      const meta = document.createElement('div');
      meta.className = 'disasm-history-meta';
      const parts = [entry.addr];
      if (entry.tab && entry.tab !== 'disasm') parts.push(GROUP_LABELS[entry.tab] || entry.tab);
      if (entry.source) parts.push(entry.source);
      if (summary.sectionName) parts.push(summary.sectionName);
      const timeLabel = formatNavigationHistoryTime(entry.ts);
      if (timeLabel) parts.push(timeLabel);
      meta.textContent = parts.join(' · ');
      main.append(title, meta);

      const actions = document.createElement('div');
      actions.className = 'disasm-history-actions';
      if (index === _navIndex) {
        const badge = document.createElement('span');
        badge.className = 'cross-count-badge';
        badge.textContent = 'active';
        actions.appendChild(badge);
      }
      const openBtn = document.createElement('button');
      openBtn.type = 'button';
      openBtn.className = 'btn btn-xs btn-secondary';
      openBtn.textContent = entry.tab && entry.tab !== 'disasm'
        ? `Ouvrir ${GROUP_LABELS[entry.tab] || entry.tab}`
        : 'Ouvrir';
      openBtn.addEventListener('click', () => {
        navJump(index);
      });
      actions.appendChild(openBtn);

      row.append(main, actions);
      container.appendChild(row);
    });
}

function navPush(addr, opts = {}) {
  const normalizedAddr = normalizeHexAddress(addr);
  const binaryPath = getStaticBinaryPath();
  if (!normalizedAddr || !binaryPath) return;
  const nextEntry = {
    addr: normalizedAddr,
    binaryPath,
    ts: Date.now(),
    tab: normalizeNavHistoryTab(opts.tab || getActiveStaticTabId() || 'disasm'),
    spanLength: normalizeSpanLength(opts.spanLength || 1),
    source: normalizeNavHistorySource(opts.source || ''),
  };
  if (_navHistory[_navIndex]?.addr === normalizedAddr) {
    _navHistory[_navIndex] = { ..._navHistory[_navIndex], ...nextEntry };
    persistNavigationHistory(binaryPath);
    updateNavButtons();
    renderDisasmNavigationHistory();
    return;
  }
  _navHistory.splice(_navIndex + 1);
  _navHistory.push(nextEntry);
  if (_navHistory.length > MAX_NAV_HISTORY_ENTRIES) _navHistory.shift();
  _navIndex = _navHistory.length - 1;
  persistNavigationHistory(binaryPath);
  updateNavButtons();
  renderDisasmNavigationHistory();
}

function navOpenEntry(entry) {
  if (!entry?.addr || !entry?.binaryPath) return;
  jumpToAddrInContextTab(
    normalizeNavHistoryTab(entry.tab || 'disasm'),
    entry.addr,
    entry.binaryPath,
    {
      skipHistory: true,
      spanLength: normalizeSpanLength(entry.spanLength || 1),
    }
  );
}

function navBack() {
  if (_navIndex <= 0) return;
  _navIndex--;
  const entry = _navHistory[_navIndex];
  navOpenEntry(entry);
  persistNavigationHistory(entry.binaryPath);
  updateNavButtons();
  renderDisasmNavigationHistory();
}

function navForward() {
  if (_navIndex >= _navHistory.length - 1) return;
  _navIndex++;
  const entry = _navHistory[_navIndex];
  navOpenEntry(entry);
  persistNavigationHistory(entry.binaryPath);
  updateNavButtons();
  renderDisasmNavigationHistory();
}

function navJump(index) {
  if (index < 0 || index >= _navHistory.length) return;
  _navIndex = index;
  const entry = _navHistory[_navIndex];
  navOpenEntry(entry);
  persistNavigationHistory(entry.binaryPath);
  updateNavButtons();
  renderDisasmNavigationHistory();
}

function clearNavigationHistory() {
  const binaryPath = getStaticBinaryPath();
  _navHistory.length = 0;
  _navIndex = -1;
  if (binaryPath) {
    const store = _loadStoredNavHistoryByBinary();
    if (store[binaryPath]) {
      const next = { ...store };
      delete next[binaryPath];
      _saveStorage({ navHistoryByBinary: next });
    }
  }
  updateNavButtons();
  renderDisasmNavigationHistory();
  updateDisasmSessionSummary();
}

function updateNavButtons() {
  const btnBack = document.getElementById('btnNavBack');
  const btnFwd = document.getElementById('btnNavForward');
  if (btnBack) btnBack.disabled = _navIndex <= 0;
  if (btnFwd) btnFwd.disabled = _navIndex >= _navHistory.length - 1;
}

document.getElementById('btnNavBack')?.addEventListener('click', navBack);
document.getElementById('btnNavForward')?.addEventListener('click', navForward);
document.getElementById('btnClearNavHistory')?.addEventListener('click', clearNavigationHistory);
document.addEventListener('keydown', (e) => {
  if (e.altKey && e.key === 'ArrowLeft') { navBack(); e.preventDefault(); }
  if (e.altKey && e.key === 'ArrowRight') { navForward(); e.preventDefault(); }
});

document.addEventListener('keydown', (event) => {
  if (!isStaticTabActive('decompile')) return;
  const isCmdOrCtrl = Boolean(event.metaKey || event.ctrlKey);
  const key = String(event.key || '');
  const lowerKey = key.toLowerCase();
  const typingSomewhereElse = isTypingElement(event.target) && event.target?.id !== 'decompileSearchInput';
  if (isCmdOrCtrl && lowerKey === 'f') {
    event.preventDefault();
    focusDecompileSearchInput();
    return;
  }
  if (typingSomewhereElse) return;
  if (key === 'F3' || (isCmdOrCtrl && lowerKey === 'g')) {
    event.preventDefault();
    stepDecompileSearchHit(event.shiftKey ? -1 : 1);
    return;
  }
  if (!isCmdOrCtrl && !event.altKey && key === '/' && !isTypingElement(event.target)) {
    event.preventDefault();
    focusDecompileSearchInput({ select: false });
  }
});


function initSettingsListeners() {
// ── Settings ─────────────────────────────────────────────────────────────────
// _settingsCache and _settingsDebounce are declared early at the top of this file.

document.querySelectorAll('#panel-options [data-key]').forEach((el) => {
  el.addEventListener('change', _scheduleSave);
  el.addEventListener('input', _scheduleSave);
});

document.querySelectorAll('[data-interface-mode]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const mode = btn.dataset.interfaceMode === 'simple' ? 'simple' : 'advanced';
    const input = document.getElementById('settingInterfaceMode');
    if (input) input.value = mode;
    _settingsCache = { ...(_settingsCache || {}), interfaceMode: mode };
    if (mode === 'simple') {
      document.querySelectorAll('[data-static-feature]').forEach((featureInput) => {
        featureInput.checked = STATIC_SIMPLE_FEATURES.has(featureInput.dataset.staticFeature);
      });
      _settingsCache.enabledStaticFeatures = Array.from(STATIC_SIMPLE_FEATURES);
    }
    syncStaticInterfaceModeControls(_settingsCache);
    refreshStaticNavigationForSettings();
    _scheduleSave();
  });
});


}

// ── AI Providers panel ──────────────────────────────────────────────────────
var _AI_DISPLAY_NAMES = {
  anthropic: 'Claude',
  openai: 'OpenAI',
  mistral: 'Mistral',
  gemini: 'Google Gemini',
  openrouter: 'OpenRouter',
  groq: 'Groq',
  deepseek: 'DeepSeek',
  ollama: 'Ollama',
};
var _AI_KEY_PLACEHOLDERS = {
  anthropic: 'sk-ant-api03-…',
  openai: 'sk-…',
  mistral: 'votre-clé-mistral',
  gemini: 'AIza…',
  openrouter: 'sk-or-v1-…',
  groq: 'gsk_…',
  deepseek: 'sk-…',
};
var _AI_PROVIDER_DESCRIPTIONS = {
  anthropic: 'Claude pour l’analyse approfondie et les longs contextes.',
  openai: 'Modèles GPT et raisonnement OpenAI.',
  mistral: 'Modèles européens rapides et multilingues.',
  gemini: 'Modèles Google Gemini et grands contextes.',
  openrouter: 'Un accès unifié à de nombreux modèles.',
  groq: 'Inférence très rapide sur modèles ouverts.',
  deepseek: 'Modèles DeepSeek orientés raisonnement et code.',
  ollama: 'Exécution locale, sans clé API ni envoi vers le cloud.',
};
var _AI_PROVIDER_MARKS = {
  anthropic: 'A',
  openai: 'O',
  mistral: 'M',
  gemini: 'G',
  openrouter: 'OR',
  groq: 'GQ',
  deepseek: 'DS',
  ollama: '◎',
};

function _renderAiProviders(data) {
  var grid = document.getElementById('aiProvidersState');
  var sel  = document.getElementById('aiDefaultProvider');
  if (!grid || !Array.isArray(data.providers)) { return; }

  while (grid.firstChild) { grid.removeChild(grid.firstChild); }
  while (sel.firstChild)  { sel.removeChild(sel.firstChild); }

  data.providers.forEach(function (p) {
    var isOllama    = p.name === 'ollama';
    var displayName = _AI_DISPLAY_NAMES[p.name] || p.name;

    // Card
    var card = document.createElement('div');
    card.className = 'ai-provider-card ' + (isOllama ? 'local' : 'cloud');
    card.dataset.provider   = p.name;
    card.dataset.keyChanged = 'false';

    // Header
    var header = document.createElement('div');
    header.className = 'ai-provider-card-header';

    var titleWrap = document.createElement('div');
    titleWrap.className = 'ai-provider-card-title';

    var mark = document.createElement('span');
    mark.className = 'ai-provider-mark';
    mark.textContent = _AI_PROVIDER_MARKS[p.name] || displayName.slice(0, 2);

    var titleCopy = document.createElement('span');
    titleCopy.className = 'ai-provider-title-copy';
    var nameSpan = document.createElement('span');
    nameSpan.className = 'ai-provider-card-name';
    nameSpan.textContent = displayName;
    var description = document.createElement('span');
    description.className = 'ai-provider-description';
    description.textContent = _AI_PROVIDER_DESCRIPTIONS[p.name] || '';

    titleCopy.append(nameSpan, description);
    titleWrap.append(mark, titleCopy);

    var status = document.createElement('span');
    var statusLabel = p.valid ? 'Prêt' : (p.configured ? 'À vérifier' : 'Non configuré');
    status.className = 'ai-provider-card-status' + (p.valid ? ' configured' : (p.configured ? ' invalid' : ''));
    status.textContent = statusLabel;

    header.appendChild(titleWrap);
    header.appendChild(status);
    card.appendChild(header);

    // Body: fields + save button on one line, no labels (placeholders only)
    var body = document.createElement('div');
    body.className = 'ai-provider-card-body';

    var fields = document.createElement('div');
    fields.className = 'ai-provider-fields';

    if (!isOllama) {
      // API key field (no label — placeholder describes it)
      var keyField = document.createElement('div');
      keyField.className = 'ai-provider-field ai-provider-field-key';
      var keyLabel = document.createElement('label');
      keyLabel.textContent = 'Clé API';
      var keyRow = document.createElement('div');
      keyRow.className = 'ai-provider-key-row';
      var keyInput = document.createElement('input');
      keyInput.type = 'password';
      keyInput.className = 'input-inner settings-input';
      keyInput.autocomplete = 'off';
      keyInput.placeholder = p.configured
        ? 'Clé enregistrée — saisir pour la remplacer'
        : (_AI_KEY_PLACEHOLDERS[p.name] || 'Saisir la clé');
      keyInput.dataset.role = 'key';
      keyInput.addEventListener('input', function () { card.dataset.keyChanged = 'true'; });
      var toggleBtn = document.createElement('button');
      toggleBtn.type = 'button';
      toggleBtn.className = 'btn-icon ai-provider-key-toggle';
      toggleBtn.title = 'Afficher / masquer';
      toggleBtn.setAttribute('aria-label', 'Afficher ou masquer la clé API');
      toggleBtn.textContent = '👁';
      (function (ki) {
        toggleBtn.addEventListener('click', function () {
          ki.type = ki.type === 'password' ? 'text' : 'password';
        });
      }(keyInput));
      keyRow.appendChild(keyInput);
      keyRow.appendChild(toggleBtn);
      keyField.appendChild(keyLabel);
      keyField.appendChild(keyRow);
      fields.appendChild(keyField);
    }

    // Model field — <select> when list available, <input> otherwise
    var modelField = document.createElement('div');
    modelField.className = 'ai-provider-field';
    var modelLabel = document.createElement('label');
    modelLabel.textContent = 'Modèle';
    var modelInput;
    if (Array.isArray(p.models) && p.models.length > 0) {
      modelInput = document.createElement('select');
      modelInput.className = 'select-modern settings-input';
      p.models.forEach(function (m) {
        var opt = document.createElement('option');
        opt.value = m;
        opt.textContent = m;
        if (m === p.model) { opt.selected = true; }
        modelInput.appendChild(opt);
      });
      // Saved model not in list? Add it as first option
      if (p.model && !p.models.includes(p.model)) {
        var cur = document.createElement('option');
        cur.value = p.model;
        cur.textContent = p.model;
        cur.selected = true;
        modelInput.insertBefore(cur, modelInput.firstChild);
      }
    } else {
      modelInput = document.createElement('input');
      modelInput.type = 'text';
      modelInput.className = 'input-inner settings-input';
      modelInput.value = p.model || '';
      modelInput.placeholder = 'Identifiant du modèle';
    }
    modelInput.dataset.role = 'model';
    modelField.appendChild(modelLabel);
    modelField.appendChild(modelInput);
    fields.appendChild(modelField);

    // Save action kept separate from the fields for a clearer reading flow.
    var actions = document.createElement('div');
    actions.className = 'ai-provider-actions';
    var saveBtn = document.createElement('button');
    saveBtn.type = 'button';
    saveBtn.className = 'btn btn-primary btn-sm';
    saveBtn.textContent = 'Enregistrer';
    (function (c, pName, button) {
      saveBtn.addEventListener('click', function () {
        var model  = (c.querySelector('[data-role="model"]') || {}).value || '';
        var apiKey = '';
        if (c.dataset.keyChanged === 'true') {
          apiKey = (c.querySelector('[data-role="key"]') || {}).value || '';
        }
        button.disabled = true;
        button.textContent = 'Enregistrement…';
        vscode.postMessage({ type: 'hubAiProviderSet', provider: pName, api_key: apiKey, model: model });
      });
    }(card, p.name, saveBtn));

    body.appendChild(fields);
    actions.appendChild(saveBtn);
    body.appendChild(actions);
    card.appendChild(body);

    // Ollama: URL note below the body
    if (isOllama) {
      var urlNote = document.createElement('p');
      urlNote.className = 'ai-provider-url-note';
      urlNote.textContent = 'Serveur local configuré avec OLLAMA_BASE_URL.';
      card.appendChild(urlNote);
    }

    grid.appendChild(card);

    // Default provider option
    var opt = document.createElement('option');
    opt.value = p.name;
    opt.textContent = displayName;
    opt.disabled = !p.valid && p.name !== data.default_provider;
    if (p.name === data.default_provider) { opt.selected = true; }
    sel.appendChild(opt);
  });
}

document.getElementById('aiDefaultProvider')?.addEventListener('change', function (event) {
  var provider = String(event.target?.value || '').trim();
  if (!provider) { return; }
  vscode.postMessage({ type: 'hubAiProviderDefaultSet', provider: provider });
});

// ─── Fin AI Providers ───────────────────────────────────────────────────────
