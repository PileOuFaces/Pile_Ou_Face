/**
 * @file hub.js
 * @brief Contrôleur du hub Pile ou Face — UI alignée MOSCOW.
 */
const vscode = window.POFHubMessageBus?.vscode || acquireVsCodeApi();
const STORAGE_KEY = window.POFHubState?.STORAGE_KEY || 'pile-ou-face-hub';
// hubPayloadCore is declared in hub.js — payloadCore.js must load first (position 185 in hub.html)
let loadAllPending = 0;
let stringsCache = [];
let stringsPage = 1;
let pendingStringsFocusAddr = '';
// Cache des onglets : évite de recharger à chaque clic si les données sont déjà chargées
let tabDataCache = {};  // tabId -> { binaryPath }
let currentArchSupport = null; // arch support matrix pour le binaire courant
let hexCurrentOffset = 0;
let hexCurrentLength = 512;
let hexSections = [];           // [{name, offset, virtual_address, size, type}] — pour sync disasm↔hex
let hexPendingScrollVaddr = null; // { addr, endAddr, activeAddr, anchorAddr, spanLength } après prochain render hex
let hexRenderSessionId = 0;
let hexRenderInProgress = false;
let hexDomState = {
  rowByOffset: new Map(),
  rowDataByOffset: new Map(),
  byteElsByAddr: new Map(),
  asciiElsByAddr: new Map(),
};
let hexActiveUiState = {
  selectedRowEls: [],
  activeRowEl: null,
  selectedByteEls: [],
  selectedAsciiEls: [],
  activeByteEls: [],
  activeAsciiEls: [],
  startAddr: '',
  endAddr: '',
  addr: '',
  anchorAddr: '',
  spanLength: 1,
};
let hexSelectionModel = {
  startAddr: '',
  endAddr: '',
  activeAddr: '',
  anchorAddr: '',
  spanLength: 1,
};
let hexUiState = {
  compact: _loadStorage().hexCompact !== false,
};
let hexPatchHistory = [];
let hexPatchRedoHistory = [];
let stackFrameCache = {};
const pendingStackFrameRequests = new Set();
let cfgUiState = {
  binaryPath: '',
  viewMode: _loadStorage().cfgViewMode || 'graph',
  search: _loadStorage().cfgSearch || '',
  funcAddr: '',
  expandedAddrs: [],
  graphView: null,
  activeAddr: '',
};
let callGraphUiState = {
  binaryPath: '',
  viewMode: _loadStorage().cgViewMode || 'graph',
  search: _loadStorage().cgSearch || '',
  graphView: null,
  activeAddr: '',
};
let decompileUiState = {
  selectedAddr: _loadStorage().decompileAddr || '',
  selectionMode: _loadStorage().decompileSelectionMode || 'context',
  renderedAddr: '',
  renderedBinaryPath: '',
  renderedDecompiler: _loadStorage().decompiler || '',
  renderedProvider: 'auto',
  renderedQuality: _normalizeDecompileQuality(_loadStorage().decompileQuality || 'normal'),
  quality: _normalizeDecompileQuality(_loadStorage().decompileQuality || 'normal'),
  activeStackEntryName: '',
  pendingStackEntryName: '',
  searchQuery: _loadStorage().decompileSearch || '',
  activeSearchHit: -1,
  forcedDecompiler: '',    // '' = auto mode, 'ghidra'|'retdec'|'angr' = user forced
  pillStatuses: {},        // { [decompiler]: { status: 'running'|'done'|'error', score } }
  bestDecompiler: '',      // decompiler name currently displayed as best
  payloads: {},            // { [decompiler]: payload } — cached per-decompiler payloads
};
let decompileHistoryState = {
  entries: [],
  index: -1,
};
let decompilePeekState = {
  el: null,
  target: null,
};
let decompileHighlightFrame = 0;
let decompileRenderToken = 0;
let decompileSearchDebounce = 0;
let decompileHighlightCache = {
  key: '',
  code: '',
  html: '',
};
const MAX_DECOMPILE_RESULT_CACHE = 12;
let decompileResultCache = new Map();
const pendingDecompileRequests = new Set();

let stackUiState = {
  renderedAddr: '',
  renderedBinaryPath: '',
  activeEntryName: '',
  pendingEntryName: '',
};
let typedDataUiState = {
  structSource: '',
  structs: [],
  structsLoaded: false,
  loadingStructs: false,
  pendingEditorOpen: false,
  appliedStructName: '',
  appliedStructOffset: '0x0',
  appliedStructAddr: '',
  hexStructName: '',
  hexStructPreview: null,
};
const OLLAMA_CHAT_MAX_MESSAGES = 40;
const OLLAMA_CHAT_CONTEXT_MESSAGES = 12;
const OLLAMA_CHAT_CONTEXT_MAX_CHARS = 1800;
const OLLAMA_HISTORY_MAX_THREADS = 24;

function _normalizeOllamaConversationMessages(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      const role = String(entry?.role || '').trim().toLowerCase();
      const content = String(entry?.content || '').trim();
      if (!content) return null;
      if (!['user', 'assistant', 'system'].includes(role)) return null;
      const normalized = {
        role,
        content,
        ts: Number(entry?.ts || Date.now()),
      };
      if (entry?.model) normalized.model = String(entry.model);
      const usage = entry?.usage;
      if (usage && typeof usage === 'object') {
        normalized.usage = {
          promptTokens: Math.max(0, Number(usage.promptTokens || usage.prompt_tokens || 0)),
          completionTokens: Math.max(0, Number(usage.completionTokens || usage.completion_tokens || 0)),
          totalTokens: Math.max(0, Number(usage.totalTokens || usage.total_tokens || 0)),
          requestTotalTokens: Math.max(
            0,
            Number(usage.requestTotalTokens || usage.request_total_tokens || 0),
          ),
          requestPromptTokens: Math.max(
            0,
            Number(usage.requestPromptTokens || usage.request_prompt_tokens || 0),
          ),
          requestCompletionTokens: Math.max(
            0,
            Number(usage.requestCompletionTokens || usage.request_completion_tokens || 0),
          ),
        };
      }
      return normalized;
    })
    .filter(Boolean)
    .slice(-OLLAMA_CHAT_MAX_MESSAGES);
}

function _loadStoredOllamaConversation() {
  return _normalizeOllamaConversationMessages(_loadStorage().ollamaConversation);
}

let ollamaUiState = {
  models: [],
  lastModel: _loadStorage().ollamaModel || '',
  baseUrl: _loadStorage().ollamaBaseUrl || 'http://127.0.0.1:11434',
  busy: false,
  conversation: _loadStoredOllamaConversation(),
  history: [],
  activeConversationId: '',
  historyQuery: '',
  historySort: _loadStorage().ollamaHistorySort || 'updated_desc',
  globalGenerationSettings: {
    temperature: 0.7,
    top_p: 0.9,
    max_tokens: 4096,
  },
  pricingRules: [],
};
let currentBinaryMeta = null;
let pendingStaticQuickAction = '';
let detectionUiState = {
  capaCapabilities: [],
  capaError: '',
  yaraMatches: [],
  yaraError: '',
  yaraMode: String(_loadStorage().yaraRulesMode || 'library'),
  activeYaraCount: 0,
  rulesError: '',
};
let functionsUiState = {
  sort: String(_loadStorage().functionsSort || 'priority_desc'),
  quickFilter: String(_loadStorage().functionsQuickFilter || 'all'),
  reviewFilter: String(_loadStorage().functionsReviewFilter || 'all'),
  signalFilter: String(_loadStorage().functionsSignalFilter || 'all'),
  selectedAddr: String(_loadStorage().functionsSelectedAddr || ''),
};
let pluginUiState = {
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
  error: '',
};
let staticSubtabSuppressClickUntil = 0;
let staticSubtabDragState = {
  groupId: '',
  dragTabId: '',
  overTabId: '',
  dropPosition: 'after',
  didDrop: false,
};
const MAX_RECENT_BINARIES = 8;
const MAX_NAV_HISTORY_ENTRIES = 20;
const MAX_NAV_HISTORY_BINARIES = 8;
window.discoveredFunctionsCache = window.discoveredFunctionsCache || [];
window.functionListCache = window.functionListCache || [];
window.functionRadarCache = window.functionRadarCache || null;
window.functionWorkspaceState = window.functionWorkspaceState || null;

const GROUPS = {
  code: ['disasm','discovered','cfg','callgraph','decompile','stack','hex','script'],
  data: ['info','sections','imports','symbols','strings','typed_data','recherche','pe_resources','exceptions'],
};
const GROUP_LABELS = {
  disasm: 'Désassemblage', cfg: 'CFG', callgraph: 'Call Graph',
  discovered: 'Fonctions', decompile: 'Décompilateur', hex: 'Hex View',
  strings: 'Strings', symbols: 'Symboles', sections: 'Sections',
  imports: 'Imports', info: 'Infos binaire', recherche: 'Recherche',
  script: 'Script', stack: 'Stack Frame',
  pe_resources: 'Ressources PE', exceptions: 'Exceptions', typed_data: 'Données typées',
};
// Premium tab → family map — populated at runtime from plugin registrations.
// No premium feature names live in the public extension code.
const PREMIUM_TAB_FAMILY = {};

function _normalizePluginStaticGroup(group, family) {
  const normalizedGroup = String(group || family || '').trim();
  return normalizedGroup || 'code';
}

// Plugin tab registration (populated via registerPluginTabs / clearPluginTabs)
let _pluginTabRegistrations = [];

function registerPluginTabs(tabRegistrations) {
  clearPluginTabs();
  _pluginTabRegistrations = Array.isArray(tabRegistrations) ? tabRegistrations : [];
  _pluginTabRegistrations.forEach(function (reg) {
    const tabId  = String(reg.tabId  || '').trim();
    const label  = String(reg.label  || '').trim();
    const family = String(reg.family || '').trim();
    const group  = _normalizePluginStaticGroup(reg.group, family);
    const hint   = String(reg.hint   || '').trim();
    if (!tabId || !group) return;
    if (!GROUPS[group]) GROUPS[group] = [];
    if (!GROUPS[group].includes(tabId)) GROUPS[group].push(tabId);
    if (label)  GROUP_LABELS[tabId]      = label;
    if (family) PREMIUM_TAB_FAMILY[tabId] = family;
    if (hint)   STATIC_FLOW_HINTS[tabId]  = hint;
  });
}

function clearPluginTabs() {
  _pluginTabRegistrations.forEach(function (reg) {
    const tabId = String(reg.tabId || '').trim();
    const group = String(reg.group || '').trim();
    if (!tabId) return;
    if (GROUPS[group]) {
      GROUPS[group] = GROUPS[group].filter(function (t) { return t !== tabId; });
      if (GROUPS[group].length === 0) delete GROUPS[group];
    }
    delete GROUP_LABELS[tabId];
    delete PREMIUM_TAB_FAMILY[tabId];
    delete STATIC_FLOW_HINTS[tabId];
  });
  _pluginTabRegistrations = [];
}

// Tab loader registration — plugins register their own load handlers
const _tabLoaders = {};

function registerTabLoader(tabId, fn) {
  if (typeof tabId === 'string' && tabId && typeof fn === 'function') {
    _tabLoaders[String(tabId).trim()] = fn;
  }
}

function callTabLoader(tabId, binaryPath, opts) {
  const loader = _tabLoaders[String(tabId || '').trim()];
  if (!loader) return false;
  loader(binaryPath, opts || {});
  return true;
}

function getStaticFeatureIds() { return Object.values(GROUPS).flat(); }
const STATIC_SIMPLE_FEATURES = new Set([
  'disasm',
  'cfg',
  'discovered',
  'decompile',
  'strings',
  'symbols',
  'sections',
  'info',
]);
const STATIC_FLOW_HINTS = {
  disasm:       'Commence ici pour lire le point d entree, sauter vers main et annoter les adresses utiles.',
  cfg:          'Passe ensuite sur le CFG pour comprendre les branches, les blocs et les sorties rapides.',
  callgraph:    'Utilise le call graph pour reperer les noeuds centraux avant de zoomer dans les fonctions.',
  discovered:   'Trie les fonctions, choisis une cible interessante puis pivote vers pseudo-C, CFG ou hex.',
  decompile:    'Valide la logique haut niveau ici, puis compare avec le desassemblage si un bloc semble flou.',
  hex:          'Garde cette vue pour verifier offsets, bytes et patches quand une adresse devient concrete.',
  stack:        'Appuie-toi sur la stack frame apres avoir isole une fonction qui merite une lecture precise.',
  strings:      'Scanne les chaines parlantes en premier, puis remonte vers imports, fonctions ou pseudo-C.',
  symbols:      'Les symboles donnent souvent les meilleurs points d entree avant une lecture plus profonde.',
  sections:     'Regarde les sections pour comprendre la structure du binaire avant d entrer dans le code.',
  imports:      'Observe d abord les API reseau, process et memoire, puis confirme les hypotheses dans le code.',
  info:         'Verifie format, architecture et protections avant de choisir la bonne strategie d exploration.',
  recherche:    'Recherche un motif, puis ouvre le resultat dans la vue technique la plus utile.',
  pe_resources: 'Commence ici pour les artefacts PE embarques, puis pivote vers strings ou hex si besoin.',
  exceptions:   'Les handlers d exceptions aident a comprendre le controle de flux sur des binaires plus tordus.',
  typed_data:   'Cette vue sert bien apres le premier tri quand tu veux donner du sens aux donnees.',
  script:       'Le panneau script est ideal quand tu veux industrialiser une etape repetable de ton analyse.',
  default:      'Ouvre le desassemblage, identifie les zones interessantes, puis pivote vers graphes, data ou offensif.',
  // Premium tab hints are injected at runtime via registerPluginTabs()
};
const STATIC_QUICK_ACTIONS = {
  disasm: { group: 'code', tab: 'disasm' },
  functions: { group: 'code', tab: 'discovered' },
  strings: { group: 'data', tab: 'strings' },
  hex: { group: 'code', tab: 'hex' },
};
// Correspondance tab → feature(s) dans la matrice de support arch
// Tableau = on prend le niveau le plus bas parmi toutes les features
const TAB_FEATURE_MAP = {
  disasm: ['disasm'],
  cfg: ['cfg'],
  callgraph: ['call_graph'],
  discovered: ['discover_functions'],
  stack: ['stack_frame', 'calling_convention'],
};
const FEATURE_LABELS = {
  disasm: 'Désassemblage',
  cfg: 'CFG',
  call_graph: 'Call Graph',
  discover_functions: 'Découverte fonctions',
  stack_frame: 'Stack Frame',
  calling_convention: 'Convention d\'appel',
  xrefs: 'Références croisées',
};
const _SUPPORT_RANK = { full: 3, partial: 2, 'disasm-only': 1, unsupported: 0 };
function _worstSupportEntry(features) {
  if (!currentArchSupport?.support) return null;
  let worst = null;
  for (const f of features) {
    const entry = currentArchSupport.support[f];
    if (!entry) continue;
    if (!worst || (_SUPPORT_RANK[entry.level] ?? 0) < (_SUPPORT_RANK[worst.level] ?? 0)) worst = entry;
  }
  return worst;
}
// Tooltip body-level pour éviter le clipping par overflow:hidden des parents
let _archTooltipEl = null;
function _getArchTooltipEl() {
  if (!_archTooltipEl) {
    _archTooltipEl = document.createElement('div');
    _archTooltipEl.className = 'arch-support-tooltip';
    _archTooltipEl.style.display = 'none';
    document.body.appendChild(_archTooltipEl);
  }
  return _archTooltipEl;
}
function _showArchTooltip(badge, features) {
  if (!currentArchSupport?.support) return;
  const tip = _getArchTooltipEl();
  tip.replaceChildren();
  const arch = currentArchSupport.display_name || currentArchSupport.key || '';
  if (arch) {
    const header = document.createElement('span');
    header.className = 'arch-support-tooltip-arch';
    header.textContent = arch;
    tip.appendChild(header);
  }
  for (const f of features) {
    const entry = currentArchSupport.support[f];
    if (!entry) continue;
    const row = document.createElement('div');
    row.className = 'arch-support-tooltip-row';
    const dot = document.createElement('span');
    dot.className = `arch-support-tooltip-dot arch-support-${entry.level}`;
    const label = document.createElement('span');
    label.className = 'arch-support-tooltip-label';
    label.textContent = FEATURE_LABELS[f] || f;
    const lvl = document.createElement('span');
    lvl.className = `arch-support-tooltip-level arch-support-level-${entry.level}`;
    lvl.textContent = entry.level;
    row.appendChild(dot);
    row.appendChild(label);
    row.appendChild(lvl);
    if (entry.note) {
      const note = document.createElement('div');
      note.className = 'arch-support-tooltip-note';
      note.textContent = entry.note;
      row.appendChild(note);
    }
    tip.appendChild(row);
  }
  tip.style.display = 'flex';
  const rect = badge.getBoundingClientRect();
  const tw = tip.offsetWidth;
  let left = rect.left + rect.width / 2 - tw / 2;
  left = Math.max(6, Math.min(left, window.innerWidth - tw - 6));
  tip.style.left = `${left}px`;
  tip.style.top = `${rect.top - tip.offsetHeight - 8 + window.scrollY}px`;
}
function _hideArchTooltip() {
  if (_archTooltipEl) _archTooltipEl.style.display = 'none';
}
function _buildArchBadge(features) {
  return archBadgeController?.buildArchBadge(features) ?? null;
}
const ACTIVE_CONTEXT_INJECTED_PANELS = [
  'staticStrings',
  'staticSections',
  'staticRecherche',
  'staticInfo',
  'staticPeResources',
  'staticExceptions',
  'staticTypedData',
  'staticBehavior',
  'staticTaint',
  'staticAntiAnalysis',
  'staticDetection',
  'staticRop',
  'staticVulns',
  'staticFlirt',
  'staticFuncSimilarity',
  'staticDeobfuscate',
];
const RAW_UNSUPPORTED_TABS = {
  decompile: ['decompileContent'],
  stack: ['stackContent'],
  behavior: ['behaviorContent'],
  taint: ['taintContent'],
  anti_analysis: ['antiAnalysisContent'],
  attck: ['attckContent'],
  vulns: ['vulnsContent'],
  flirt: ['flirtContent'],
  func_similarity: ['funcSimilarityContent'],
  pe_resources: ['peResourcesContent'],
  exceptions: ['exceptionsContent'],
  bindiff: ['bindiffStats', 'bindiffResults'],
};
const RAW_TAB_CAPABILITIES = {
  disasm: { level: 'full', note: 'Vue principale pour shellcodes et firmwares bruts.' },
  discovered: { level: 'full', note: 'Découverte de fonctions sur le blob désassemblé.' },
  cfg: { level: 'full', note: 'CFG généré à partir du profil d’architecture brut.' },
  callgraph: { level: 'full', note: 'Call graph basé sur les appels détectés dans le blob.' },
  hex: { level: 'full', note: 'Hex, base virtuelle, endian et taille de pointeur restent fiables.' },
  sections: { level: 'full', note: 'Le blob est exposé comme une section brute unique.' },
  info: { level: 'full', note: 'Résumé pseudo-binaire basé sur le profil brut choisi.' },
  strings: { level: 'full', note: 'Extraction de chaînes directement depuis le blob.' },
  recherche: { level: 'full', note: 'Recherche textuelle et offsets disponibles sur le blob.' },
  typed_data: { level: 'full', note: 'Décodage typé à partir de la base, endian et ptr size du profil brut.' },
  script: { level: 'full', note: 'Automatisation disponible tant que le script vise le blob courant.' },
  symbols: { level: 'limited', note: 'Symboles heuristiques ou découverts, sans vraie table native.' },
  imports: { level: 'limited', note: 'Indices heuristiques uniquement, pas de table d’imports réelle.' },
  detection: { level: 'limited', note: 'YARA reste utile ; CAPA ne couvre pas les blobs bruts.' },
  deobfuscate: { level: 'limited', note: 'Résultats utiles sur chaînes et motifs simples, moins fiables qu’un exécutable complet.' },
  rop: { level: 'limited', note: 'Dépend du profil d’architecture brut et du plugin offensif.' },
  func_similarity: { level: 'unsupported', note: 'La similarité a besoin d’un binaire structuré et d’une base de références.' },
  decompile: { level: 'unsupported', note: 'Pas de décompilation fiable sans format exécutable complet.' },
  stack: { level: 'unsupported', note: 'La reconstruction de stack frame n’est pas encore fiable sur blob brut.' },
  pe_resources: { level: 'unsupported', note: 'Un blob brut n’expose pas de ressources PE structurées.' },
  exceptions: { level: 'unsupported', note: 'Pas de tables d’exceptions exploitables sur blob brut.' },
  taint: { level: 'unsupported', note: 'La taint n’est pas encore câblée pour les blobs bruts.' },
  behavior: { level: 'unsupported', note: 'Le comportement shellcode/firmware reste à stabiliser côté plugin.' },
  anti_analysis: { level: 'unsupported', note: 'La vue anti-analyse n’est pas encore exposée proprement pour blob brut.' },
  vulns: { level: 'unsupported', note: 'L’audit vulnérabilités reste pensé pour des exécutables complets.' },
  flirt: { level: 'unsupported', note: 'Les signatures FLIRT attendent des structures natives plus riches.' },
  bindiff: { level: 'unsupported', note: 'Le diff de binaires n’est pas encore prévu pour les blobs bruts.' },
};

// Panels
const panels = document.querySelectorAll('.panel');
const iconNavItems = document.querySelectorAll('.icon-nav-item');
const form = document.getElementById('traceForm');
const runBtn = document.getElementById('runBtn');
const binaryPathInput = form?.querySelector('input[name="binaryPath"]');
const dynamicTraceStatus = document.getElementById('dynamicTraceStatus');
const dynamicArchBits = document.getElementById('dynamicArchBits');
const dynamicPie = document.getElementById('dynamicPie');
const dynamicSourcePathInput = document.getElementById('dynamicSourcePath');
const dynamicSourceHint = document.getElementById('dynamicSourceHint');
const argvPayloadInput = document.getElementById('argvPayload');
const argvPayloadHint = document.getElementById('argvPayloadHint');
const dynamicPayloadTargetMode = document.getElementById('dynamicPayloadTargetMode');
const dynamicTraceHistory = document.getElementById('dynamicTraceHistory');
const btnRefreshDynamicTraceHistory = document.getElementById('btnRefreshDynamicTraceHistory');
const btnClearDynamicTraceHistory = document.getElementById('btnClearDynamicTraceHistory');
let currentPlatform = 'linux';
const exploitNotesWidget = document.getElementById('exploitNotesWidget');
const exploitNotesFab = document.getElementById('exploitNotesFab');
const exploitNotesInput = document.getElementById('exploitNotes');
const EXPLOIT_NOTES_UI_KEY = 'pile-ou-face-exploit-notes-ui';
const EXPLOIT_NOTES_TEXT_KEY = 'pile-ou-face-exploit-notes-text';
const OLLAMA_CHAT_WIDGET_KEY = 'pile-ou-face-ollama-chat-widget';
const OLLAMA_CHAT_WIDGET_SIZE_KEY = 'pile-ou-face-ollama-chat-widget-size';
let dynamicTraceInitState = {
  archBits: 64,
  pie: false,
  sourcePath: '',
  sourceEnrichmentEnabled: false,
  sourceEnrichmentStatus: '',
  sourceEnrichmentMessage: '',
  payloadTargetMode: 'auto',
  payloadTargetAuto: 'argv1',
  payloadTargetEffective: 'argv1',
  payloadTargetReason: 'Auto: aucune source claire, fallback sur argv[1]',
  profile: {
    bufferOffset: '',
    bufferSize: '',
    maxSteps: 800,
    startSymbol: 'main',
    stopSymbol: ''
  }
};
let dynamicTraceHistoryState = {
  items: [],
  activeTracePath: ''
};

// localStorage helpers
function _loadStorage() {
  if (window.POFHubState?.loadStorage) return window.POFHubState.loadStorage();
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch(_) { return {}; }
}
function _saveStorage(updates) {
  if (window.POFHubState?.saveStorage) {
    window.POFHubState.saveStorage(updates);
    return;
  }
  try {
    const prev = _loadStorage();
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...prev, ...updates }));
  } catch(_) {}
}

function _migrateDisabledFamilies() {
  const store = _loadStorage();
  const hasLegacy = ('disabledPlugins' in store) || ('disabledCrossPlugins' in store);
  if (store.disabledFamilies) {
    // Already migrated — just clean up any leftover legacy keys
    if (hasLegacy) {
      const merged = { ...store };
      delete merged.disabledPlugins;
      delete merged.disabledCrossPlugins;
      try { localStorage.setItem(STORAGE_KEY, JSON.stringify(merged)); } catch (_) {}
    }
    return;
  }
  // First migration: convert plugin IDs → family names
  if (Array.isArray(store.disabledPlugins) && store.disabledPlugins.length > 0) {
    const OLD_PLUGIN_FAMILY = {
      'pof.vulnerability-audit-pro': 'audit',
      'pof.vuln-audit-pro': 'audit',
      'pof.malware-triage-pro': 'malware',
      'pof.offensive-research-pro': 'offensif',
      'pof.cross-analysis-pro': 'croisee',
    };
    const families = [...new Set(
      store.disabledPlugins.map((id) => OLD_PLUGIN_FAMILY[id]).filter(Boolean)
    )];
    const merged = { ...store, disabledFamilies: families };
    delete merged.disabledPlugins;
    delete merged.disabledCrossPlugins;
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(merged)); } catch (_) {}
  } else {
    // No plugins were disabled — just initialize disabledFamilies and clean up legacy keys
    const merged = { ...store, disabledFamilies: [] };
    delete merged.disabledPlugins;
    delete merged.disabledCrossPlugins;
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(merged)); } catch (_) {}
  }
}
function getDisabledFamilies() {
  const raw = _loadStorage().disabledFamilies;
  return new Set(Array.isArray(raw) ? raw : []);
}
function setDisabledFamilies(disabledSet) {
  _saveStorage({ disabledFamilies: disabledSet instanceof Set ? [...disabledSet] : [] });
}

function _normalizeDecompileQuality(quality) {
  const normalized = String(quality || decompileUiState.quality || 'normal').trim().toLowerCase();
  if (normalized === 'max' || normalized === 'precision') return 'precision';
  return 'normal';
}
