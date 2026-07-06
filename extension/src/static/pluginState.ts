// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file pluginState.js
 * @brief Helpers de synthese pour l'etat plugin expose au webview static.
 */

function emptyPluginUiState(error = '') {
  const message = String(error || '').trim();
  return {
    loaded: false,
    pluginCount: 0,
    stateCounts: {},
    activePluginIds: [],
    capabilities: [],
    capabilityMap: {},
    attachedCommands: [],
    commandSources: {},
    searchPaths: [],
    families: {},
    plugins: [],
    tabRegistrations: [],
    error: message,
  };
}

function flattenPluginCapabilities(manifest = {}) {
  const sections = manifest?.capabilities && typeof manifest.capabilities === 'object'
    ? manifest.capabilities
    : {};
  const values = new Set();
  Object.values(sections).forEach((entries) => {
    if (!Array.isArray(entries)) return;
    entries.forEach((entry) => {
      const text = String(entry || '').trim();
      if (text) values.add(text);
    });
  });
  return Array.from(values).sort((a, b) => a.localeCompare(b));
}

function inferPluginFamily({ manifest = {} } = {}) {
  const family = String(
    manifest?.ui?.family
    || manifest?.entrypoints?.ui?.family
    || manifest?.family
    || ''
  ).trim().toLowerCase();
  return family || null;
}

function summarizePluginRuntimeState(payload = {}) {
  const plugins = Array.isArray(payload?.plugins) ? payload.plugins : [];
  const searchPaths = Array.isArray(payload?.search_paths)
    ? payload.search_paths.map((entry) => String(entry || '').trim()).filter(Boolean)
    : [];
  const attached = payload?.attached && typeof payload.attached === 'object' ? payload.attached : {};
  const attachedCommands = Array.isArray(attached.commands)
    ? attached.commands.map((entry) => String(entry || '').trim()).filter(Boolean)
    : [];
  const commandSources = attached?.command_sources && typeof attached.command_sources === 'object'
    ? Object.fromEntries(
        Object.entries(attached.command_sources)
          .map(([key, value]) => [String(key || '').trim(), String(value || '').trim()])
          .filter(([key, value]) => !!key && !!value)
      )
    : {};
  const stateCounts = payload?.summary && typeof payload.summary === 'object'
    ? Object.fromEntries(
        Object.entries(payload.summary)
          .map(([key, value]) => [String(key || '').trim(), Number(value || 0)])
          .filter(([key]) => !!key)
      )
    : {};
  const activePluginIds = new Set();
  const capabilities = new Set();
  const activePlugins = [];
  const families = {};
  const allTabRegistrations = [];

  plugins.forEach((record) => {
    if (!record) return;
    const state = String(record.state || '').trim();
    const pluginId = String(record.id || record?.manifest?.id || '').trim();
    if (!pluginId) return;
    const manifest = record.manifest && typeof record.manifest === 'object' ? record.manifest : {};
    const pluginCapabilities = flattenPluginCapabilities(manifest);
    const distribution = manifest.distribution && typeof manifest.distribution === 'object'
      ? manifest.distribution
      : {};
    const licensing = manifest.licensing && typeof manifest.licensing === 'object'
      ? manifest.licensing
      : {};
    const pluginCommands = attachedCommands
      .filter((commandId) => commandSources[commandId] === pluginId)
      .sort((a, b) => a.localeCompare(b));
    const pluginFamily = inferPluginFamily({ manifest });

    const pluginItem = {
      id: pluginId,
      name: String(manifest.name || pluginId),
      version: String(manifest.version || ''),
      kind: String(manifest.kind || ''),
      state,
      family: pluginFamily,
      capabilities: pluginCapabilities,
      rootPath: String(record.root_path || ''),
      encrypted: distribution.encrypted === true,
      bundleFormat: String(distribution.bundle_format || ''),
      licenseRequired: licensing.required === true,
      licenseMode: String(licensing.mode || ''),
      licenseStatus: String(licensing.status || (licensing.required === true ? 'locked' : 'unlocked')),
      licenseMessage: String(licensing.message || ''),
      licensePath: String(licensing.license_path || ''),
      licenseId: String(licensing.license_id || ''),
      licensee: String(licensing.licensee || ''),
      licenseVerified: licensing.verified === true,
      error: String(record.error || ''),
      commands: pluginCommands,
    };
    if (state === 'active') {
      activePluginIds.add(pluginId);
      pluginCapabilities.forEach((capability) => capabilities.add(capability));
      if (pluginFamily) {
        families[pluginFamily] = true;
        const uiTabs = Array.isArray(manifest?.ui?.tabs) ? manifest.ui.tabs : [];
        uiTabs.forEach((tab) => {
          const tabId = String(tab?.tabId || '').trim();
          if (!tabId) return;
          const pluginSlug = String(pluginId).startsWith('pof.') ? String(pluginId).slice(4) : String(pluginId);
          allTabRegistrations.push({
            tabId,
            label: String(tab?.label || tabId),
            family: pluginFamily,
            group: String(tab?.group || pluginFamily),
            hint: String(tab?.hint || ''),
            pluginSlug,
          });
        });
      }
    }
    activePlugins.push(pluginItem);
  });

  const capabilityList = Array.from(capabilities).sort((a, b) => a.localeCompare(b));
  const capabilityMap = Object.fromEntries(capabilityList.map((capability) => [capability, true]));
  const pluginIdList = Array.from(activePluginIds).sort((a, b) => a.localeCompare(b));

  return {
    loaded: true,
    pluginCount: activePlugins.length,
    stateCounts,
    activePluginIds: pluginIdList,
    capabilities: capabilityList,
    capabilityMap,
    attachedCommands,
    commandSources,
    searchPaths,
    families,
    plugins: activePlugins.sort((a, b) => a.name.localeCompare(b.name)),
    tabRegistrations: allTabRegistrations,
    error: '',
  };
}

module.exports = {
  emptyPluginUiState,
  flattenPluginCapabilities,
  summarizePluginRuntimeState,
};
