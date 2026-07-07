// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file webview.js
 * @brief Construction du HTML des webviews.
 */

const vscode = require('vscode');
const fs = require('fs');
const path = require('path');

function _readJsonIfExists(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function _derivePluginSlug(pluginDir, manifest) {
  const buildMeta = _readJsonIfExists(path.join(pluginDir, 'metadata', 'build.json'));
  const slugFromBuild = String(buildMeta?.slug || '').trim();
  if (slugFromBuild) return slugFromBuild;
  const pluginId = String(manifest?.id || '').trim();
  if (pluginId.startsWith('pof.')) return pluginId.slice(4);
  return path.basename(pluginDir);
}

function _resolvePluginAssetPath(pluginDir, manifest, relativeAssetPath) {
  const relPath = String(relativeAssetPath || '').trim();
  if (!relPath) return '';
  const directPath = path.join(pluginDir, relPath);
  if (fs.existsSync(directPath)) return directPath;
  const slug = _derivePluginSlug(pluginDir, manifest);
  const extrasPath = path.join(pluginDir, 'metadata', 'extras', 'plugins', slug, relPath);
  if (fs.existsSync(extrasPath)) return extrasPath;
  return '';
}

function _escapeHtmlAttr(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function _extractInlineStyles(html) {
  let styles = '';
  const withoutStyles = String(html || '').replace(/<style\b[^>]*>([\s\S]*?)<\/style>/gi, (_match, css) => {
    styles += `\n${css || ''}`;
    return '';
  });
  return { html: withoutStyles, styles };
}

function _markPluginPanels(html, pluginSlug, pluginId) {
  const safeSlug = _escapeHtmlAttr(String(pluginSlug || '').replace(/[^a-zA-Z0-9_-]/g, ''));
  const safeId = _escapeHtmlAttr(pluginId || '');
  return String(html || '').replace(/<([a-z][\w:-]*)([^>]*\bclass=(["'])[^"']*\bstatic-panel\b[^"']*\3[^>]*)>/gi, (match, tag, attrs) => {
    if (/\bdata-plugin-scope=/.test(attrs)) return match;
    return `<${tag}${attrs} data-plugin-scope="${safeSlug}" data-plugin-id="${safeId}">`;
  });
}

function _getPluginSearchDirs(storageDir, _globalDir) {
  const dirs: string[] = [];
  if (storageDir) dirs.push(path.join(storageDir, 'plugins'));
  return dirs;
}

const PLUGIN_BRIDGE_PREAMBLE = `<script>
(function () {
  window.onerror = function (message, source, lineno, colno, error) {
    console.error('[PoF-plugin] uncaught error:', message, source, lineno, colno, error && error.stack);
  };
  var _pending = {};
  var _seq = 0;
  window.vscode = {
    postMessage: function (msg) {
      try { window.parent.postMessage({ __pof_plugin: true, payload: msg }, '*'); }
      catch (_) {
        try { window.parent.postMessage({ __pof_plugin: true, payload: JSON.parse(JSON.stringify(msg)) }, '*'); }
        catch (_2) {}
      }
    }
  };
  function _activatePanel(tabId) {
    var panelId = 'static' + String(tabId || '').split('_').map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1); }).join('');
    document.querySelectorAll('.static-panel').forEach(function (p) { p.classList.remove('active'); });
    var panel = document.getElementById(panelId);
    if (panel) panel.classList.add('active');
  }
  window.addEventListener('message', function (e) {
    if (!e.data || !e.data.__pof_host) return;
    var msg = e.data.payload;
    if (msg && msg.__pof_reply && _pending[msg.__seq]) {
      _pending[msg.__seq](msg.result);
      delete _pending[msg.__seq];
    }
    if (msg && msg.type === 'showTab') {
      _activatePanel(msg.tabId);
    }
    if (msg && msg.type === '__binaryPath' && typeof msg.binaryPath === 'string') {
      window._pofCurrentBinaryPath = msg.binaryPath;
    }
    if (msg && msg.type === '__cssVars' && msg.vars && typeof msg.vars === 'object') {
      var keys = Object.keys(msg.vars);
      if (keys.length > 0) {
        var cssText = ':root{' + keys.map(function (k) { return k + ':' + msg.vars[k]; }).join(';') + '}';
        var styleEl = document.getElementById('__pof_css_vars');
        if (!styleEl) { styleEl = document.createElement('style'); styleEl.id = '__pof_css_vars'; document.head.appendChild(styleEl); }
        styleEl.textContent = cssText;
      }
    }
    // Re-dispatch the unwrapped payload so the plugin's own message listeners
    // (written against the original, non-iframe contract) keep working unchanged.
    if (msg && !msg.__pof_reply) {
      window.dispatchEvent(new MessageEvent('message', { data: msg }));
    }
  });
  function _call(method, args) {
    return new Promise(function (resolve) {
      var seq = ++_seq;
      _pending[seq] = resolve;
      var msg = { __pof_plugin: true, __pof_call: true, method: method, args: args, __seq: seq };
      // The host's PluginIframeRouter may not be initialized yet when this iframe's
      // own script runs (iframe srcdoc loads independently of the parent's script
      // execution order) — retry a few times until the pending call is resolved.
      var attempts = 0;
      var trySend = function () {
        if (!_pending[seq]) return; // already resolved
        attempts++;
        window.parent.postMessage(msg, '*');
        if (attempts < 8) setTimeout(trySend, 250);
      };
      trySend();
    });
  }
  window.PoF = {
    version: null,
    // Synchronous: mirrors the __binaryPath broadcast already cached locally,
    // no round-trip needed (and plugin code written pre-iframe expects a string, not a Promise).
    getBinaryPath:       function () { return window._pofCurrentBinaryPath || ''; },
    getTabCache:         function (k) { return _call('getTabCache', [k]); },
    setTabCache:         function (k, v) { return _call('setTabCache', [k, v]); },
    registerTabLoader:   function (tabId, fn) {
      _call('registerTabLoader', [tabId]);
      window.addEventListener('message', function (e) {
        if (e.data && e.data.__pof_host && e.data.payload && e.data.payload.__pof_tabload && e.data.payload.tabId === tabId) {
          if (e.data.payload.binaryPath) window._pofCurrentBinaryPath = e.data.payload.binaryPath;
          fn(e.data.payload.binaryPath);
        }
      });
    },
    saveStorage:         function (d) { return _call('saveStorage', [d]); },
    // Local (in-iframe) loading indicator — the plugin's own DOM, no host round-trip needed.
    setLoading:          function (containerId, message) {
      var el = document.getElementById(containerId);
      if (!el) return;
      el.replaceChildren();
      var p = document.createElement('p');
      p.className = 'loading-state';
      p.textContent = message || 'Chargement…';
      el.appendChild(p);
    },
  };
  // Stubs for host-page globals called by legacy plugin code (before window.PoF migration)
  window._pofCurrentBinaryPath = '';
  window._pofSavedState = {};
  window.getStaticBinaryPath = function () { return window._pofCurrentBinaryPath; };
  window._loadStorage = function () { return window._pofSavedState; };
  window._saveStorage = function (data) {
    if (data && typeof data === 'object') Object.assign(window._pofSavedState, data);
  };
  // Legacy shim: bare registerTabLoader() calls from old bundles
  window.registerTabLoader = function (tabId, fn) {
    if (window.PoF && typeof window.PoF.registerTabLoader === 'function') window.PoF.registerTabLoader(tabId, fn);
  };
  // postBinaryAwareMessage: host helper used by plugin JS
  window.postBinaryAwareMessage = function (type, data) {
    window.vscode.postMessage(Object.assign({ type: type, binaryPath: window._pofCurrentBinaryPath || '' }, data || {}));
  };
  // Host analysis globals referenced by cross-plugin code
  window.asVI = function (v) { return (v && typeof v === 'object' ? v : {}); };
  window.PREMIUM_TAB_FAMILY = window.PREMIUM_TAB_FAMILY || {};
  window.GROUP_LABELS = window.GROUP_LABELS || {};
  // Mirror the host's registerPluginTabs(): populate label/family lookups for
  // every tab across all plugins, so cross-plugin display code (e.g. cross-analysis
  // showing "source: audit") doesn't need direct access to the host's own state.
  window.addEventListener('message', function (e) {
    if (!e.data || !e.data.__pof_host) return;
    var msg = e.data.payload;
    if (!msg || msg.type !== 'hubPluginState' || !msg.state) return;
    var regs = Array.isArray(msg.state.tabRegistrations) ? msg.state.tabRegistrations : [];
    regs.forEach(function (reg) {
      var tabId = String(reg.tabId || '').trim();
      if (!tabId) return;
      if (reg.label) window.GROUP_LABELS[tabId] = reg.label;
      if (reg.family) window.PREMIUM_TAB_FAMILY[tabId] = reg.family;
    });
  });
  window.normalizeHexAddress = function (addr) { return addr ? String(addr).trim() : ''; };
  window.findSectionForAddress = function () { return null; };
  window.getFunctionRowByAddr = function () { return null; };
  window.findNearestFunctionStart = function () { return null; };
  window.vaddrFromFileOffset = function () { return null; };
  window.symbolsCache = window.symbolsCache || [];
  window.sectionsCache = window.sectionsCache || [];
  window.tabDataCache = window.tabDataCache || {};
  window.functionListCache = window.functionListCache || [];
  window.functionsUiState = window.functionsUiState || { selectedAddr: '' };

  // ── Code-navigation helpers (mirrors vulnerability-audit-pro/webview/tab.ts) ──
  // These plugins used to share one global scope with vulnerability-audit-pro
  // before iframe isolation; provided here so every plugin can resolve addresses
  // without duplicating this logic. Address caches are always empty in an
  // isolated iframe, so these gracefully return '' / false instead of crashing.
  function _isExecutableSection(section) {
    if (!section || typeof section !== 'object') return false;
    var name = String(section.name || '').trim().toLowerCase();
    if (!name) return false;
    if (name === '__text' || name === '.text') return true;
    if (name === '__stubs' || name === '.plt' || name === '.plt.sec') return true;
    if (name === '.init' || name === '.fini' || name === '.init.text' || name === '.fini.text') return true;
    if (name.indexOf('.text.') === 0) return true;
    if (name.slice(-5) === '_text') return true;
    return false;
  }
  function _findFunctionRowByName(name, rows) {
    var normalized = String(name || '').trim().toLowerCase();
    var list = Array.isArray(rows) ? rows : (window.functionListCache || []);
    if (!normalized) return null;
    for (var i = 0; i < list.length; i++) {
      var e = list[i] || {};
      var candidates = [e.name, e.function, e.label];
      for (var j = 0; j < candidates.length; j++) {
        if (String(candidates[j] || '').trim().toLowerCase() === normalized) return e;
      }
    }
    return null;
  }
  function _findFunctionAddressByName(name) {
    var row = _findFunctionRowByName(name, null);
    if (row && row.addr) return window.normalizeHexAddress(String(row.addr));
    return '';
  }
  function _findEnclosingFunctionAddr(addr) {
    var normalized = window.normalizeHexAddress(String(addr || ''));
    if (!normalized) return '';
    var exact = window.getFunctionRowByAddr(normalized);
    if (exact && exact.addr) return window.normalizeHexAddress(exact.addr);
    return window.normalizeHexAddress(window.findNearestFunctionStart(normalized) || '');
  }
  window.isCodeNavigationAddress = function (addr) {
    var normalized = window.normalizeHexAddress(String(addr || ''));
    if (!normalized) return false;
    var section = window.findSectionForAddress(normalized);
    if (_isExecutableSection(section)) return true;
    if (window.getFunctionRowByAddr(normalized)) return true;
    var syms = window.symbolsCache || [];
    for (var i = 0; i < syms.length; i++) {
      var type = String(syms[i].type || '').toLowerCase();
      if ((type === 't' || type === 'f') && window.normalizeHexAddress(String(syms[i].addr || '')) === normalized) return true;
    }
    return false;
  };
  window.getPrimaryCodeNavigationAddr = function (item) {
    if (!item || typeof item !== 'object') {
      var row = window.getFunctionRowByAddr(String(item || ''));
      return (row && row.addr) || '';
    }
    var related = item.related || {};
    var callerFunctions = Array.isArray(related.caller_functions) ? related.caller_functions : [];
    var patchTargets = Array.isArray(related.patch_targets) ? related.patch_targets : [];
    var nestedBehavior = Array.isArray(related.behavior) ? related.behavior : [];
    var nestedAnti = Array.isArray(related.anti_analysis) ? related.anti_analysis : [];
    var directCandidates = [
      item.function_addr,
      (callerFunctions[0] || {}).function_addr,
      (window.getFunctionRowByAddr(String(item.addr || '')) || {}).addr,
    ];
    for (var i = 0; i < directCandidates.length; i++) {
      var n1 = window.normalizeHexAddress(String(directCandidates[i] || ''));
      if (n1) return n1;
    }
    var firstNonDataPatch = patchTargets.filter(function (t) { return String((t || {}).kind || '').toLowerCase() !== 'data'; })[0];
    var enclosingCandidates = [
      (related.callsites || [])[0] && related.callsites[0].addr,
      (callerFunctions[0] || {}).callsite_addr,
      firstNonDataPatch && firstNonDataPatch.addr,
    ];
    for (var j = 0; j < enclosingCandidates.length; j++) {
      var n2 = _findEnclosingFunctionAddr(enclosingCandidates[j] || '');
      if (n2) return n2;
    }
    var nameCandidates = [item.function]
      .concat(callerFunctions.map(function (e) { return e.name; }))
      .concat(nestedBehavior.map(function (e) { return e.function; }))
      .concat(nestedAnti.map(function (e) { return e.function; }));
    for (var k = 0; k < nameCandidates.length; k++) {
      var n3 = _findFunctionAddressByName(nameCandidates[k]);
      if (n3) return n3;
    }
    var proofDossiers = Array.isArray(item.proof_dossiers) ? item.proof_dossiers : [];
    for (var m = 0; m < proofDossiers.length; m++) {
      var nested = window.getPrimaryCodeNavigationAddr(proofDossiers[m]);
      if (nested) return nested;
    }
    return '';
  };
  window.getPrimaryNavigationOffset = function (item) {
    var i = item || {};
    var related = i.related || {};
    var candidates = [
      i.offset, i.offset_hex, i.file_offset, i.fileOffset,
      Array.isArray(related.behavior) && related.behavior[0] ? related.behavior[0].offset : '',
      Array.isArray(related.anti_analysis) && related.anti_analysis[0] ? related.anti_analysis[0].offset : '',
      Array.isArray(i.evidence) && i.evidence[0] ? i.evidence[0].offset : '',
    ];
    for (var i2 = 0; i2 < candidates.length; i2++) {
      var normalized = window.normalizeHexLiteral(candidates[i2]);
      if (normalized) return normalized;
    }
    return '';
  };
  window.resolveOffsetToVirtualAddress = function (offset) {
    var normalizedOffset = window.normalizeHexLiteral(offset);
    if (!normalizedOffset) return '';
    var sections = window.sectionsCache || [];
    return window.normalizeHexAddress(window.vaddrFromFileOffset(normalizedOffset, sections) || '');
  };
  window.getPrimaryNavigationLocation = function (item) {
    var i = item || {};
    var related = i.related || {};
    var callsites = Array.isArray(related.callsites) ? related.callsites : [];
    var patchTargets = Array.isArray(related.patch_targets) ? related.patch_targets : [];
    var findingAddr = window.normalizeHexAddress(String(i.addr || i.function_addr || ''));
    var callsiteAddr = window.normalizeHexAddress(String((callsites[0] || {}).addr || ''));
    var patchAddr = window.normalizeHexAddress(String((patchTargets[0] || {}).addr || ''));
    var behaviorArr = Array.isArray(related.behavior) ? related.behavior : [];
    var antiArr = Array.isArray(related.anti_analysis) ? related.anti_analysis : [];
    var behaviorEntry = behaviorArr.filter(function (e) { return e && e.addr; })[0] || {};
    var antiEntry = antiArr.filter(function (e) { return e && e.addr; })[0] || {};
    var offset = window.getPrimaryNavigationOffset(item);
    var derivedAddr = window.resolveOffsetToVirtualAddress(offset);
    return {
      addr: callsiteAddr || findingAddr || patchAddr || window.normalizeHexAddress(behaviorEntry.addr || '') || window.normalizeHexAddress(antiEntry.addr || '') || derivedAddr || '',
      offset: offset,
    };
  };
  window.pickCodeAddressFromXrefs = function (payload) {
    var refs = Array.isArray((payload || {}).refs) ? payload.refs : [];
    for (var i = 0; i < refs.length; i++) {
      var candidates = [refs[i].function_addr, refs[i].from_addr];
      for (var j = 0; j < candidates.length; j++) {
        var normalized = window.normalizeHexAddress(String(candidates[j] || ''));
        if (normalized && window.isCodeNavigationAddress(normalized)) return normalized;
      }
    }
    return '';
  };
  var _xrefRequestSeq = 0;
  window.requestAddressXrefs = function (addr, mode) {
    mode = mode || 'to';
    var normalized = window.normalizeHexAddress(String(addr || ''));
    var binaryPath = window.getStaticBinaryPath();
    if (!normalized || !binaryPath) return Promise.resolve({ refs: [], targets: [], addr: normalized, mode: mode });
    var requestKey = 'xref_' + (++_xrefRequestSeq);
    return new Promise(function (resolve) {
      setTimeout(function () { resolve({ refs: [], targets: [], addr: normalized, mode: mode, timeout: true }); }, 6000);
      window.vscode.postMessage({ type: 'hubLoadXrefs', addr: normalized, binaryPath: binaryPath, mode: mode, requestKey: requestKey });
    });
  };
  window.withTemporaryButtonState = function (button, busyLabel, task) {
    if (!button || button.disabled) return Promise.resolve();
    var originalLabel = button.textContent;
    button.disabled = true;
    button.classList.add('btn--loading');
    if (busyLabel) button.textContent = busyLabel;
    return Promise.resolve().then(function () { return task(); }).finally(function () {
      button.disabled = false;
      button.classList.remove('btn--loading');
      button.textContent = originalLabel;
    });
  };
  // Jumping to strings/xrefs panels requires the HOST's own DOM — no-op gracefully.
  window.openVulnDataXrefs = function () {};
  window.openVulnStrings = function () {};

  // ── Shared plugin panel rendering helpers (mirrors front/static/search.js) ──
  window.normalizePluginPanelPayload = function (raw, arrayKeys) {
    arrayKeys = arrayKeys || [];
    if (Array.isArray(raw)) {
      return { result: {}, items: raw, proofDossiers: [], summary: {}, error: null };
    }
    var result = raw && typeof raw === 'object' ? raw : {};
    var items = [];
    for (var i = 0; i < arrayKeys.length; i++) {
      var key = arrayKeys[i];
      if (Array.isArray(result[key])) { items = result[key]; break; }
    }
    return {
      result: result,
      items: items,
      proofDossiers: Array.isArray(result.proof_dossiers) ? result.proof_dossiers : [],
      summary: result.summary && typeof result.summary === 'object' ? result.summary : {},
      error: result.error || null,
    };
  };
  function _collectEvidenceSummaries(value, maxItems) {
    maxItems = maxItems || 3;
    var pick = function (entry) {
      return String(
        entry.summary || entry.evidence || entry.description || entry.url
        || entry.uri || entry.ip || entry.domain || entry.host || entry.api || entry.value || ''
      ).trim();
    };
    if (Array.isArray(value)) {
      var out = [];
      for (var i = 0; i < value.length; i++) {
        var entry = value[i];
        var text = '';
        if (!entry) text = '';
        else if (typeof entry === 'string') text = entry;
        else if (typeof entry === 'object') text = pick(entry);
        if (text) out.push(text);
      }
      return out.slice(0, maxItems);
    }
    if (value && typeof value === 'object') {
      var summary = pick(value);
      return summary ? [summary] : [];
    }
    if (typeof value === 'string' && value.trim()) return [value.trim()];
    return [];
  }
  window.formatPremiumEvidence = function (value, fallback) {
    fallback = fallback === undefined ? '—' : fallback;
    var parts = _collectEvidenceSummaries(value);
    if (parts.length) return parts.join(' ; ');
    if (value === null || value === undefined || value === '') return fallback;
    return String(value);
  };
  window.buildNavigableAddrNode = function (addr) {
    var text = String(addr || '').trim();
    if (!text) return document.createTextNode('—');
    if (!/^0x[0-9a-f]+$/i.test(text)) return document.createTextNode(text);
    var code = document.createElement('code');
    code.className = 'addr-link';
    code.dataset.addr = text;
    code.textContent = text;
    code.style.cursor = 'pointer';
    code.addEventListener('click', function () {
      var binaryPath = window.getStaticBinaryPath();
      if (!binaryPath) return;
      window.vscode.postMessage({ type: 'hubGoToAddress', addr: text, binaryPath: binaryPath });
    });
    return code;
  };
  window.renderVulnProofDossiers = function (dossiers, opts) {
    opts = opts || {};
    var kindLabel = opts.kindLabel || {};
    var confidenceColor = opts.confidenceColor || {};
    var severityColor = opts.severityColor || {};
    if (!Array.isArray(dossiers) || dossiers.length === 0) return null;
    var grid = document.createElement('div');
    grid.className = 'vuln-dossier-grid';
    var exploitClass = function (level) {
      if (level === 'HIGH') return 'is-high';
      if (level === 'MEDIUM') return 'is-medium';
      return 'is-low';
    };
    var severityClass = function (level) {
      if (level === 'CRITICAL') return 'is-critical';
      if (level === 'HIGH') return 'is-high';
      if (level === 'MEDIUM') return 'is-medium';
      return 'is-low';
    };
    var makeBadge = function (label, value, extraClass, color) {
      var badge = document.createElement('span');
      badge.className = ('vuln-dossier-badge ' + (extraClass || '')).trim();
      if (color) badge.style.color = color;
      badge.textContent = label + ' ' + value;
      return badge;
    };
    dossiers.slice(0, 6).forEach(function (rawDossier) {
      var dossier = window.asVI(rawDossier);
      var related = window.asVI(dossier.related);
      var card = document.createElement('article');
      card.className = 'modern-card vuln-dossier-card';
      var head = document.createElement('div');
      head.className = 'vuln-dossier-head';
      var titleWrap = document.createElement('div');
      var title = document.createElement('h4');
      title.className = 'vuln-dossier-title';
      title.textContent = String(dossier.function || '?');
      var subtitle = document.createElement('p');
      subtitle.className = 'vuln-dossier-subtitle';
      var findingCount = Number(dossier.finding_count || 0);
      var callsiteCount = Array.isArray(related.callsites) ? related.callsites.length : 0;
      var relatedListCounts = Object.entries(related)
        .filter(function (e) { return ['apis', 'families', 'callsites', 'patch_targets'].indexOf(e[0]) === -1 && Array.isArray(e[1]); })
        .map(function (e) { return [e[0], e[1].length]; });
      var relatedTotal = relatedListCounts.reduce(function (total, e) { return total + e[1]; }, 0);
      subtitle.textContent = findingCount + ' signal' + (findingCount > 1 ? 'aux' : '') + ' · ' + callsiteCount + ' callsite' + (callsiteCount > 1 ? 's' : '') + ' · ' + relatedTotal + ' corrélation' + (relatedTotal > 1 ? 's' : '');
      titleWrap.append(title, subtitle);
      var badges = document.createElement('div');
      badges.className = 'vuln-dossier-badges';
      var exploitability = window.asVI(dossier.exploitability);
      var exploitScore = Number(exploitability.score || 0);
      var exploitLevel = String(exploitability.level || 'LOW');
      var dossierKind = String(dossier.kind || '');
      var dossierConfidence = String(dossier.confidence || '');
      var dossierSeverity = String(dossier.severity || '');
      badges.append(
        makeBadge('Preuve', kindLabel[dossierKind] || dossierKind || 'Signal'),
        makeBadge('Confiance', dossierConfidence || '?', exploitClass(dossierConfidence), confidenceColor[dossierConfidence] || ''),
        makeBadge('Exploit', exploitScore ? (exploitLevel + ' ' + exploitScore) : exploitLevel, exploitClass(exploitLevel)),
        makeBadge('Sévérité', dossierSeverity || '?', severityClass(dossierSeverity), severityColor[dossierSeverity] || '')
      );
      relatedListCounts.slice(0, 3).forEach(function (e) {
        if (e[1]) badges.append(makeBadge(String(e[0]), String(e[1])));
      });
      head.append(titleWrap, badges);
      card.appendChild(head);
      var relatedApis = Array.isArray(related.apis) ? related.apis.filter(Boolean) : [];
      if (relatedApis.length) {
        var apiSection = document.createElement('section');
        apiSection.className = 'vuln-dossier-section';
        var apiLabel = document.createElement('div');
        apiLabel.className = 'vuln-dossier-label';
        apiLabel.textContent = 'APIs concernées';
        var apiRow = document.createElement('div');
        apiRow.className = 'vuln-dossier-pill-row';
        relatedApis.slice(0, 6).forEach(function (api) {
          var pill = document.createElement('span');
          pill.className = 'vuln-dossier-pill';
          pill.textContent = String(api);
          apiRow.appendChild(pill);
        });
        apiSection.append(apiLabel, apiRow);
        card.appendChild(apiSection);
      }
      var relatedFamilies = Array.isArray(related.families) ? related.families.filter(Boolean) : [];
      if (relatedFamilies.length) {
        var famSection = document.createElement('section');
        famSection.className = 'vuln-dossier-section';
        var famLabel = document.createElement('div');
        famLabel.className = 'vuln-dossier-label';
        famLabel.textContent = 'Familles de techniques';
        var famRow = document.createElement('div');
        famRow.className = 'vuln-dossier-pill-row';
        relatedFamilies.slice(0, 6).forEach(function (family) {
          var pill = document.createElement('span');
          pill.className = 'vuln-dossier-pill';
          pill.textContent = String(family);
          famRow.appendChild(pill);
        });
        famSection.append(famLabel, famRow);
        card.appendChild(famSection);
      }
      var drivers = Array.isArray(exploitability.drivers) ? exploitability.drivers.filter(Boolean) : [];
      if (drivers.length) {
        var drvSection = document.createElement('section');
        drvSection.className = 'vuln-dossier-section';
        var drvLabel = document.createElement('div');
        drvLabel.className = 'vuln-dossier-label';
        drvLabel.textContent = 'Facteurs';
        var drvList = document.createElement('ul');
        drvList.className = 'vuln-dossier-list';
        drivers.slice(0, 4).forEach(function (driver) {
          var item = document.createElement('li');
          item.textContent = String(driver);
          drvList.appendChild(item);
        });
        drvSection.append(drvLabel, drvList);
        card.appendChild(drvSection);
      }
      var nextSteps = Array.isArray(dossier.next_steps) ? dossier.next_steps.filter(Boolean) : [];
      if (nextSteps.length) {
        var stepSection = document.createElement('section');
        stepSection.className = 'vuln-dossier-section';
        var stepLabel = document.createElement('div');
        stepLabel.className = 'vuln-dossier-label';
        stepLabel.textContent = 'Étapes suggérées';
        var stepList = document.createElement('ul');
        stepList.className = 'vuln-dossier-list';
        nextSteps.slice(0, 4).forEach(function (step) {
          var item = document.createElement('li');
          item.textContent = String(step);
          stepList.appendChild(item);
        });
        stepSection.append(stepLabel, stepList);
        card.appendChild(stepSection);
      }
      var evidence = Array.isArray(dossier.evidence) ? dossier.evidence.filter(function (item) { return item && typeof item === 'object' && item.summary; }) : [];
      if (evidence.length) {
        var evSection = document.createElement('section');
        evSection.className = 'vuln-dossier-section';
        var evLabel = document.createElement('div');
        evLabel.className = 'vuln-dossier-label';
        evLabel.textContent = 'Preuves';
        var evList = document.createElement('ul');
        evList.className = 'vuln-dossier-list';
        evidence.slice(0, 4).forEach(function (entry) {
          var e = window.asVI(entry);
          var item = document.createElement('li');
          item.textContent = String(e.summary);
          evList.appendChild(item);
        });
        evSection.append(evLabel, evList);
        card.appendChild(evSection);
      }
      Object.entries(related).forEach(function (kv) {
        var key = kv[0]; var value = kv[1];
        if (['apis', 'families', 'callsites', 'patch_targets'].indexOf(key) !== -1 || !Array.isArray(value)) return;
        var signals = value.filter(function (item) { return item && typeof item === 'object'; });
        if (!signals.length) return;
        var sigSection = document.createElement('section');
        sigSection.className = 'vuln-dossier-section';
        var sigLabel = document.createElement('div');
        sigLabel.className = 'vuln-dossier-label';
        sigLabel.textContent = 'Corrélation ' + String(key);
        var sigList = document.createElement('ul');
        sigList.className = 'vuln-dossier-list';
        signals.slice(0, 3).forEach(function (rawSignal) {
          var signal = window.asVI(rawSignal);
          var item = document.createElement('li');
          var label = signal.category || signal.technique || signal.kind || signal.name || 'SIGNAL';
          var detail = signal.description || signal.summary || window.formatPremiumEvidence(signal.evidence, '');
          item.textContent = label + (detail ? (': ' + detail) : '');
          sigList.appendChild(item);
        });
        sigSection.append(sigLabel, sigList);
        card.appendChild(sigSection);
      });
      var callsites = Array.isArray(related.callsites) ? related.callsites.filter(function (item) {
        var i = window.asVI(item);
        return i.addr;
      }) : [];
      if (callsites.length) {
        var csSection = document.createElement('section');
        csSection.className = 'vuln-dossier-section';
        var csLabel = document.createElement('div');
        csLabel.className = 'vuln-dossier-label';
        csLabel.textContent = 'Navigation rapide';
        var csLinks = document.createElement('div');
        csLinks.className = 'vuln-dossier-links';
        callsites.slice(0, 4).forEach(function (rawCallsite) {
          var callsite = window.asVI(rawCallsite);
          var wrapper = document.createElement('span');
          var code = document.createElement('code');
          code.className = 'addr-link';
          var csAddr = String(callsite.addr || '');
          code.dataset.addr = csAddr;
          code.textContent = csAddr;
          wrapper.appendChild(code);
          if (callsite.line !== undefined && callsite.line !== null) wrapper.append(':' + callsite.line);
          csLinks.appendChild(wrapper);
        });
        csSection.append(csLabel, csLinks);
        card.appendChild(csSection);
      }
      var patchTargets = Array.isArray(related.patch_targets) ? related.patch_targets.filter(function (item) {
        var i = window.asVI(item);
        return i.addr;
      }) : [];
      if (patchTargets.length) {
        var ptSection = document.createElement('section');
        ptSection.className = 'vuln-dossier-section';
        var ptLabel = document.createElement('div');
        ptLabel.className = 'vuln-dossier-label';
        ptLabel.textContent = 'Offsets patchables';
        var ptLinks = document.createElement('div');
        ptLinks.className = 'vuln-dossier-links';
        patchTargets.slice(0, 4).forEach(function (rawTarget) {
          var target = window.asVI(rawTarget);
          var wrapper = document.createElement('span');
          var node = window.buildNavigableAddrNode(String(target.addr || ''));
          wrapper.appendChild(node);
          ptLinks.appendChild(wrapper);
        });
        ptSection.append(ptLabel, ptLinks);
        card.appendChild(ptSection);
      }
      if (dossier.needs_review) {
        var review = document.createElement('p');
        review.className = 'hint hint-warn';
        review.textContent = 'Revue manuelle recommandée pour confirmer le contexte réel.';
        card.appendChild(review);
      }
      grid.appendChild(card);
    });
    return grid;
  };
  window.appendProofDossierSection = function (nodes, dossiers, opts) {
    opts = opts || {};
    var hintText = opts.hintText || 'Dossiers de preuve par fonction interne. Les adresses ci-dessous sont cliquables pour naviguer dans le désassemblage.';
    var kindLabel = opts.kindLabel || {};
    var confidenceColor = opts.confidenceColor || { HIGH: '#c72e2e', MEDIUM: '#c47a00', LOW: '#0e639c' };
    var severityColor = opts.severityColor || { CRITICAL: '#c72e2e', HIGH: '#c47a00', MEDIUM: '#b5a000', LOW: '#0e639c' };
    if (!Array.isArray(dossiers) || !dossiers.length) return;
    var hint = document.createElement('p');
    hint.className = 'hint';
    hint.textContent = hintText;
    nodes.push(hint);
    var cards = window.renderVulnProofDossiers(dossiers, { kindLabel: kindLabel, confidenceColor: confidenceColor, severityColor: severityColor });
    if (cards) nodes.push(cards);
  };
  window.getDisabledFamilies = function () {
    var raw = window._loadStorage().disabledFamilies;
    return new Set(Array.isArray(raw) ? raw : []);
  };
  window.parseNumericAddress = function (value) {
    if (value == null) return null;
    if (typeof value === 'number') return Number.isFinite(value) ? value : null;
    var text = String(value).trim().toLowerCase();
    if (!text) return null;
    var parsed = text.startsWith('0x') ? parseInt(text, 16) : parseInt(text, 10);
    return Number.isFinite(parsed) ? parsed : null;
  };
  window.normalizeHexLiteral = function (value) {
    var numeric = window.parseNumericAddress(value);
    if (!Number.isFinite(numeric)) return '';
    return '0x' + numeric.toString(16);
  };
  window.setStaticLoading = function (containerId, msg) {
    var el = document.getElementById(containerId);
    if (!el) return;
    el.replaceChildren();
    if (msg) {
      var p = document.createElement('p');
      p.className = 'loading';
      p.textContent = msg;
      el.appendChild(p);
    }
  };
  // Cross-panel navigation (jump to disasm/decompile/functions) requires switching
  // the HOST's own panels — not reachable from an isolated iframe. No-op gracefully
  // instead of throwing so the rest of the plugin's rendering still completes.
  window.showPanel = function () {};
  window.showGroup = function () {};
  window.isStaticTabAvailable = function () { return false; };
  window.jumpToAddrInContextTab = function () {};
  window.setActiveAddressContext = function () {};
  window.ensureDecompileSelectionSourcesLoaded = function () {};
  window.syncFunctionsSelectionFromContext = function () {};
  // Function-review metadata (priority/notes per function address).
  window.findAnnotationForAddress = function () { return null; };
  window.isAnnotationEntryEmpty = function (entry) {
    return !entry || (!entry.comment && !entry.name && !entry.reviewStatus && !entry.reviewNotes);
  };
  window.getFunctionReviewLabel = function (status) {
    if (status === 'important') return 'Prioritaire';
    if (status === 'todo') return 'À revoir';
    if (status === 'in_progress') return 'En cours';
    if (status === 'reviewed') return 'Reviewée';
    return 'Sans revue';
  };
  window.getFunctionReviewNotes = function (entry) {
    return String((entry && (entry.reviewNotes || entry.review_notes)) || '').trim();
  };
  window.buildFunctionReviewHint = function (status, notes, updated, fallbackHint) {
    fallbackHint = fallbackHint || '';
    var dateText = updated ? new Date(updated).toLocaleString('fr-FR') : '';
    var noteText = String(notes || '').trim();
    if (noteText && dateText) return noteText + ' (' + dateText + ')';
    if (noteText) return noteText;
    if (status && status !== 'unreviewed' && dateText) {
      return 'Statut manuel ' + window.getFunctionReviewLabel(status).toLowerCase() + ' enregistré le ' + dateText;
    }
    return String(fallbackHint).trim();
  };
  window.persistFunctionReview = function (entry, reviewStatus, reviewNotes) {
    reviewNotes = reviewNotes || '';
    var addr = window.normalizeHexAddress((entry && entry.addr) || '');
    var binaryPath = window.getStaticBinaryPath();
    if (!addr || !binaryPath) return;
    window.vscode.postMessage({
      type: 'hubSaveFunctionReview',
      binaryPath: binaryPath,
      addr: addr,
      reviewStatus: String(reviewStatus || '').trim(),
      reviewNotes: String(reviewNotes || '').trim(),
    });
  };
})();
</script>`;

function _buildPluginSrcdoc(html, inlineJs, pluginCss, hostCss = '') {
  const safeHost = String(hostCss || '').replace(/<\/style/gi, '<\\/style');
  const safePlugin = String(pluginCss || '').replace(/<\/style/gi, '<\\/style');
  const safeJs = String(inlineJs || '').replace(/<\/script/gi, '<\\/script');
  return [
    '<!DOCTYPE html><html><head>',
    '<meta charset="utf-8">',
    '<style>*{box-sizing:border-box;margin:0}body{overflow:hidden;background:var(--vscode-editor-background,#1e1e1e);color:var(--vscode-foreground,#ccc);font-family:var(--vscode-font-family,sans-serif);font-size:var(--vscode-font-size,13px)}.static-panel{display:none;flex-direction:column;height:100%}.static-panel.active{display:flex}</style>',
    safeHost ? `<style>${safeHost}</style>` : '',
    safePlugin ? `<style>${safePlugin}</style>` : '',
    PLUGIN_BRIDGE_PREAMBLE,
    '</head><body>',
    String(html || ''),
    safeJs ? `<script>${safeJs}</script>` : '',
    '</body></html>',
  ].join('');
}

function loadPluginWebviews(root, options: { storageDir?: string; globalDir?: string; extensionFrontDir?: string; webviewResourceResolver?: (absPath: string) => string } = {}) {
  const { storageDir = '', globalDir = '', extensionFrontDir = '', webviewResourceResolver } = options;
  let groupStyles = '';
  const frames: { pluginId: string; pluginSlug: string; frameId: string; srcdoc: string }[] = [];

  // Read host CSS once — injected into every plugin srcdoc to provide shared design system classes
  let hostCss = '';
  if (extensionFrontDir) {
    for (const rel of ['base.css', path.join('static', 'decompile.css'), path.join('static', 'binary-bar.css')]) {
      try {
        const p = path.join(extensionFrontDir, rel);
        if (fs.existsSync(p)) hostCss += `\n${fs.readFileSync(p, 'utf8')}`;
      } catch (_) {}
    }
  }

  const searchDirs = _getPluginSearchDirs(storageDir, globalDir);

  for (const pluginsDir of searchDirs) {
    if (!fs.existsSync(pluginsDir)) continue;

    let entries;
    try { entries = fs.readdirSync(pluginsDir); } catch (_) { continue; }

    for (const entry of entries) {
      const pluginDir = path.join(pluginsDir, entry);
      const manifestPath = fs.existsSync(path.join(pluginDir, 'plugin.json'))
        ? path.join(pluginDir, 'plugin.json')
        : path.join(pluginDir, 'manifest.json');
      const manifest = _readJsonIfExists(manifestPath);
      if (!manifest) continue;

      const webviewEntry = manifest?.entrypoints?.webview;
      if (!webviewEntry) continue;

      // CSS color for the group-tab (goes into host page, not srcdoc)
      const color = manifest?.ui?.tab_color;
      const family = String(manifest?.ui?.family || '').trim().replace(/[^a-zA-Z0-9_-]/g, '');
      const safeCss = (v) => (typeof v === 'string' && /^[a-zA-Z0-9#(),. %_-]+$/.test(v)) ? v : '';
      if (color && family) {
        groupStyles += `\n.group-tab.active[data-group="${family}"] { background: ${safeCss(color.bg)}; color: ${safeCss(color.fg)}; border-color: ${safeCss(color.border)}; }`;
      }

      // Build srcdoc
      const pluginSlug = _derivePluginSlug(pluginDir, manifest);
      const pluginId = manifest.id || entry;

      const tabHtmlPath = webviewEntry.tab_html ? _resolvePluginAssetPath(pluginDir, manifest, webviewEntry.tab_html) : null;
      let pluginHtml = '';
      let scopedCss = '';

      if (tabHtmlPath && fs.existsSync(tabHtmlPath)) {
        try {
          const rawHtml = fs.readFileSync(tabHtmlPath, 'utf8');
          const extracted = _extractInlineStyles(rawHtml);
          // No CSS scoping inside srcdoc — the iframe already isolates the plugin.
          // Scoping would break :root { --var } declarations in the plugin's own CSS.
          scopedCss = extracted.styles;
          pluginHtml = _markPluginPanels(extracted.html, pluginSlug, pluginId);
        } catch (_) { /* skip */ }
      }

      // Collect inline JS content (always read file content for srcdoc — external URIs won't work)
      let inlineJs = '';
      const scriptPaths = Array.isArray(webviewEntry.scripts) ? webviewEntry.scripts : [];
      for (const rel of scriptPaths) {
        const scriptPath = _resolvePluginAssetPath(pluginDir, manifest, rel);
        if (!fs.existsSync(scriptPath)) continue;
        try {
          inlineJs += `\n${fs.readFileSync(scriptPath, 'utf8')}`;
        } catch (_) { /* skip */ }
      }

      // Only push a frame if there is actual webview content
      if (!pluginHtml.trim() && !inlineJs.trim() && !scopedCss.trim()) continue;

      const srcdoc = _buildPluginSrcdoc(pluginHtml, inlineJs, scopedCss, hostCss);
      const frameId = `pof-plugin-frame-${pluginSlug}`;
      frames.push({ pluginId, pluginSlug, frameId, srcdoc });
    }
  }

  const framesHtml = frames.map((f) => {
    const escapedSrcdoc = _escapeHtmlAttr(f.srcdoc);
    return `<iframe id="${f.frameId}" data-plugin-id="${_escapeHtmlAttr(f.pluginId)}" data-plugin-slug="${_escapeHtmlAttr(f.pluginSlug)}" class="plugin-iframe static-panel" sandbox="allow-scripts allow-same-origin" srcdoc="${escapedSrcdoc}"></iframe>`;
  }).join('\n');

  return { groupStyles: groupStyles.trim(), frames, framesHtml: framesHtml.trim() };
}

function getWebviewContent(webview, extensionUri) {
  const preferredPath = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack.html');
  const legacyPath = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'visualizer.html');
  let html = '';
  if (fs.existsSync(preferredPath.fsPath)) {
    html = fs.readFileSync(preferredPath.fsPath, 'utf8');
  } else {
    html = fs.readFileSync(legacyPath.fsPath, 'utf8');
  }
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'app', 'main.js'));
  const preferredStyle = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack.css');
  const fallbackStyle = vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'legacy-visualizer.css');
  const stylePath = fs.existsSync(preferredStyle.fsPath) ? preferredStyle : fallbackStyle;
  const styleUri = webview.asWebviewUri(stylePath);
  const csp = webview.cspSource;
  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    .replace(/{{styleUri}}/g, styleUri.toString())
    .replace(/{{cspSource}}/g, csp);
}

// static/hub — main static analysis hub (shell + fragments)
function getHubContent(webview, extensionUri, initialPanel = 'dashboard', workspaceRoot = '', globalDir = '', storageDir = '') {
  const read = (...parts) => fs.readFileSync(
    vscode.Uri.joinPath(extensionUri, ...parts).fsPath, 'utf8'
  );

  const { groupStyles: pluginGroupStyles, framesHtml: pluginFrames } =
    (storageDir || globalDir) ? loadPluginWebviews(workspaceRoot, {
      storageDir,
      globalDir,
      extensionFrontDir: vscode.Uri.joinPath(extensionUri, 'front').fsPath,
    }) : { groupStyles: '', framesHtml: '' };

  const html = read('front', 'hub.html')
    .replace('{{panelDashboard}}', read('front', 'shared', 'panel-dashboard.html'))
    .replace('{{panelStatic}}',    read('front', 'static',  'panel-static.html'))
    .replace('{{panelDynamic}}',   read('front', 'dynamic', 'panel-dynamic.html'))
    .replace('{{panelOutils}}',    read('front', 'shared',  'panel-outils.html'))
    .replace('{{panelOptions}}',   read('front', 'shared',  'panel-options.html'));

  const scriptUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'hub.js'));
  // shared modules
  const sharedRawTabCapabilitiesUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'rawTabCapabilities.js'));
  const sharedStateUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'state.js'));
  const sharedBinaryUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'binary.js'));
  const sharedNavUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'nav.js'));
  const sharedMarkdownRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'markdownRenderer.js'));
  const sharedChatMessageActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatMessageActions.js'));
  const sharedChatExportUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatExport.js'));
  const sharedChatHistoryUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatHistory.js'));
  const sharedChatContextBudgetUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'chatContextBudget.js'));
  const sharedAiGenerationSettingsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiGenerationSettings.js'));
  const sharedAiPricingUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiPricing.js'));
  const sharedAiContextActionsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'aiContextActions.js'));
  const sharedOutilsUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'outils.js'));
  const sharedMessagesUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messages.js'));
  const sharedSettingsUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'settings.js'));
  const sharedAnnotationsUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'annotations.js'));
  const sharedAccountUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'account.js'));
  // static modules
  const staticPayloadUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payload.js'));
  const staticSearchUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'search.js'));
  const staticToolsUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'tools.js'));
  const staticDiffUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'diff.js'));
  // dynamic modules
  const dynamicPanelUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'panel.js'));
  // shared controllers
  const sharedHubStateUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'hubState.js'));
  const sharedMessageBusUri            = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messageBus.js'));
  const sharedTaskProgressControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'taskProgressController.js'));
  const sharedMessageRouterUri         = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'messageRouter.js'));
  const sharedStatusControllerUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'statusController.js'));
  const sharedToastControllerUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'toastController.js'));
  const sharedArchBadgeControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'archBadgeController.js'));
  const sharedBinarySourceControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'binarySourceController.js'));
  const sharedExploitNotesControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'exploitNotesController.js'));
  const sharedHubIndexUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'hubIndex.js'));
  const sharedConversionControllerUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'conversionController.js'));
  // static controllers
  const staticPayloadCoreUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadCore.js'));
  const staticPayloadTabsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadTabsController.js'));
  const staticPayloadBuilderControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadBuilderController.js'));
  const staticPayloadStateControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadStateController.js'));
  const staticPayloadPreviewControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'payloadPreviewController.js'));
  const staticFilePayloadControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'filePayloadController.js'));
  const staticExploitHelperControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'exploitHelperController.js'));
  const staticPwntoolsScriptControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'pwntoolsScriptController.js'));
  const staticToolsWidgetsControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'staticToolsWidgetsController.js'));
  // dynamic controllers
  const dynamicPayloadHistoryControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'payloadHistoryController.js'));
  const dynamicVisualizerControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicVisualizerController.js'));
  const dynamicPresetControllerUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicPresetController.js'));
  const dynamicRunTraceControllerUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runTraceController.js'));
  const dynamicRuntimeFallbackRendererUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeFallbackRenderer.js'));
  const dynamicRuntimeSessionControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeSessionController.js'));
  const dynamicRuntimeWorkspaceLayoutControllerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtimeWorkspaceLayoutController.js'));
  const dynamicPayloadUri              = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'dynamicPayload.js'));
  // shared helpers
  const cfgHelpersUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'cfgHelpers.js'));
  const exploitHelperUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'exploitHelper.js'));
  const payloadPreviewUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'payloadPreview.js'));
  const sharedConversionUtilsUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'conversionUtils.js'));
  const elkUri                 = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'elk.bundled.js'));
  // CSS
  const baseCssUri             = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'base.css'));
  const dashboardCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-dashboard.css'));
  const staticBinaryBarCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'binary-bar.css'));
  const staticDisasmCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'disasm.css'));
  const staticCfgCssUri        = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'cfg.css'));
  const staticDecompileCssUri  = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'decompile.css'));
  const staticSearchCssUri     = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'search.css'));
  const staticAnalysisCssUri   = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'analysis.css'));
  const staticToolsCssUri      = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'static', 'tools.css'));
  const dynamicCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'panel-dynamic.css'));
  const dynamicRuntimeSessionCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtime-session.css'));
  const graphicalStackHubCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'graphical-stack-hub.css'));
  const dynamicRuntimeLayoutCssUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'runtime-layout.css'));
  const runtimeModuleUri       = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'dynamic', 'app', 'main.js'));
  const outilsCssUri           = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-outils.css'));
  const optionsCssUri          = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'panel-options.css'));
  const pluginIframeRouterUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, 'front', 'shared', 'pluginIframeRouter.js'));
  const csp = webview.cspSource;

  return html
    .replace(/{{scriptUri}}/g, scriptUri.toString())
    // shared modules
    .replace(/{{sharedRawTabCapabilitiesUri}}/g, sharedRawTabCapabilitiesUri.toString())
    .replace(/{{sharedStateUri}}/g, sharedStateUri.toString())
    .replace(/{{sharedBinaryUri}}/g, sharedBinaryUri.toString())
    .replace(/{{sharedNavUri}}/g, sharedNavUri.toString())
    .replace(/{{sharedMarkdownRendererUri}}/g, sharedMarkdownRendererUri.toString())
    .replace(/{{sharedChatMessageActionsUri}}/g, sharedChatMessageActionsUri.toString())
    .replace(/{{sharedChatExportUri}}/g, sharedChatExportUri.toString())
    .replace(/{{sharedChatHistoryUri}}/g, sharedChatHistoryUri.toString())
    .replace(/{{sharedChatContextBudgetUri}}/g, sharedChatContextBudgetUri.toString())
    .replace(/{{sharedAiGenerationSettingsUri}}/g, sharedAiGenerationSettingsUri.toString())
    .replace(/{{sharedAiPricingUri}}/g, sharedAiPricingUri.toString())
    .replace(/{{sharedAiContextActionsUri}}/g, sharedAiContextActionsUri.toString())
    .replace(/{{sharedOutilsUri}}/g, sharedOutilsUri.toString())
    .replace(/{{sharedMessagesUri}}/g, sharedMessagesUri.toString())
    .replace(/{{sharedSettingsUri}}/g, sharedSettingsUri.toString())
    .replace(/{{sharedAnnotationsUri}}/g, sharedAnnotationsUri.toString())
    .replace(/{{sharedAccountUri}}/g, sharedAccountUri.toString())
    // static modules
    .replace(/{{staticPayloadUri}}/g, staticPayloadUri.toString())
    .replace(/{{staticSearchUri}}/g, staticSearchUri.toString())
    .replace(/{{staticToolsUri}}/g, staticToolsUri.toString())
    .replace(/{{staticDiffUri}}/g, staticDiffUri.toString())
    // dynamic modules
    .replace(/{{dynamicPanelUri}}/g, dynamicPanelUri.toString())
    // shared controllers
    .replace(/{{sharedHubStateUri}}/g, sharedHubStateUri.toString())
    .replace(/{{sharedMessageBusUri}}/g, sharedMessageBusUri.toString())
    .replace(/{{sharedTaskProgressControllerUri}}/g, sharedTaskProgressControllerUri.toString())
    .replace(/{{sharedMessageRouterUri}}/g, sharedMessageRouterUri.toString())
    .replace(/{{sharedStatusControllerUri}}/g, sharedStatusControllerUri.toString())
    .replace(/{{sharedToastControllerUri}}/g, sharedToastControllerUri.toString())
    .replace(/{{sharedArchBadgeControllerUri}}/g, sharedArchBadgeControllerUri.toString())
    .replace(/{{sharedBinarySourceControllerUri}}/g, sharedBinarySourceControllerUri.toString())
    .replace(/{{sharedExploitNotesControllerUri}}/g, sharedExploitNotesControllerUri.toString())
    .replace(/{{sharedHubIndexUri}}/g, sharedHubIndexUri.toString())
    .replace(/{{sharedConversionControllerUri}}/g, sharedConversionControllerUri.toString())
    // static controllers
    .replace(/{{staticPayloadCoreUri}}/g, staticPayloadCoreUri.toString())
    .replace(/{{staticPayloadTabsControllerUri}}/g, staticPayloadTabsControllerUri.toString())
    .replace(/{{staticPayloadBuilderControllerUri}}/g, staticPayloadBuilderControllerUri.toString())
    .replace(/{{staticPayloadStateControllerUri}}/g, staticPayloadStateControllerUri.toString())
    .replace(/{{staticPayloadPreviewControllerUri}}/g, staticPayloadPreviewControllerUri.toString())
    .replace(/{{staticFilePayloadControllerUri}}/g, staticFilePayloadControllerUri.toString())
    .replace(/{{staticExploitHelperControllerUri}}/g, staticExploitHelperControllerUri.toString())
    .replace(/{{staticPwntoolsScriptControllerUri}}/g, staticPwntoolsScriptControllerUri.toString())
    .replace(/{{staticToolsWidgetsControllerUri}}/g, staticToolsWidgetsControllerUri.toString())
    // dynamic controllers
    .replace(/{{dynamicPayloadHistoryControllerUri}}/g, dynamicPayloadHistoryControllerUri.toString())
    .replace(/{{dynamicVisualizerControllerUri}}/g, dynamicVisualizerControllerUri.toString())
    .replace(/{{dynamicPresetControllerUri}}/g, dynamicPresetControllerUri.toString())
    .replace(/{{dynamicRunTraceControllerUri}}/g, dynamicRunTraceControllerUri.toString())
    .replace(/{{dynamicRuntimeFallbackRendererUri}}/g, dynamicRuntimeFallbackRendererUri.toString())
    .replace(/{{dynamicRuntimeSessionControllerUri}}/g, dynamicRuntimeSessionControllerUri.toString())
    .replace(/{{dynamicRuntimeWorkspaceLayoutControllerUri}}/g, dynamicRuntimeWorkspaceLayoutControllerUri.toString())
    .replace(/{{dynamicPayloadUri}}/g, dynamicPayloadUri.toString())
    // shared helpers
    .replace(/{{cfgHelpersUri}}/g, cfgHelpersUri.toString())
    .replace(/{{exploitHelperUri}}/g, exploitHelperUri.toString())
    .replace(/{{payloadPreviewUri}}/g, payloadPreviewUri.toString())
    .replace(/{{sharedConversionUtilsUri}}/g, sharedConversionUtilsUri.toString())
    .replace(/{{elkUri}}/g, elkUri.toString())
    // CSS
    .replace(/{{baseCssUri}}/g, baseCssUri.toString())
    .replace(/{{dashboardCssUri}}/g, dashboardCssUri.toString())
    .replace(/{{staticBinaryBarCssUri}}/g, staticBinaryBarCssUri.toString())
    .replace(/{{staticDisasmCssUri}}/g, staticDisasmCssUri.toString())
    .replace(/{{staticCfgCssUri}}/g, staticCfgCssUri.toString())
    .replace(/{{staticDecompileCssUri}}/g, staticDecompileCssUri.toString())
    .replace(/{{staticSearchCssUri}}/g, staticSearchCssUri.toString())
    .replace(/{{staticAnalysisCssUri}}/g, staticAnalysisCssUri.toString())
    .replace(/{{staticToolsCssUri}}/g, staticToolsCssUri.toString())
    .replace(/{{dynamicCssUri}}/g, dynamicCssUri.toString())
    .replace(/{{dynamicRuntimeSessionCssUri}}/g, dynamicRuntimeSessionCssUri.toString())
    .replace(/{{graphicalStackHubCssUri}}/g, graphicalStackHubCssUri.toString())
    .replace(/{{dynamicRuntimeLayoutCssUri}}/g, dynamicRuntimeLayoutCssUri.toString())
    .replace(/{{runtimeModuleUri}}/g, runtimeModuleUri.toString())
    .replace(/{{outilsCssUri}}/g, outilsCssUri.toString())
    .replace(/{{optionsCssUri}}/g, optionsCssUri.toString())
    .replace(/{{cspSource}}/g, csp)
    .replace('{{pluginGroupStyles}}', pluginGroupStyles)
    .replace('{{pluginFrames}}', pluginFrames)
    .replace(/{{pluginIframeRouterUri}}/g, pluginIframeRouterUri.toString())
    .replace(/<body>/, `<body data-initial-panel="${initialPanel}">`);
}

module.exports = {
  getWebviewContent,
  getHubContent,
  loadPluginWebviews,
  PLUGIN_BRIDGE_PREAMBLE
};
