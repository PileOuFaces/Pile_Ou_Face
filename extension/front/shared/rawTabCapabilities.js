// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Raw blob capability matrix for static hub tabs.
 *
 * Levels:
 * - full: native raw workflow is implemented and covered by core tests.
 * - limited: usable on raw blobs, but depends on heuristics or plugin support.
 * - unsupported: requires structured binary metadata or a raw-specific backend that
 *   is not wired yet.
 */
(function initRawTabCapabilities(global) {
  const RAW_UNSUPPORTED_TABS = Object.freeze({
    decompile: Object.freeze(['decompileContent']),
    stack: Object.freeze(['stackContent']),
    pe_resources: Object.freeze(['peResourcesContent']),
    exceptions: Object.freeze(['exceptionsContent']),
  });

  const RAW_TAB_CAPABILITIES = Object.freeze({
    disasm: Object.freeze({ level: 'full', note: 'Vue principale pour shellcodes et firmwares bruts.' }),
    discovered: Object.freeze({ level: 'full', note: 'Découverte de fonctions sur le blob désassemblé.' }),
    cfg: Object.freeze({ level: 'full', note: 'CFG généré à partir du profil d’architecture brut.' }),
    callgraph: Object.freeze({ level: 'full', note: 'Call graph basé sur les appels détectés dans le blob.' }),
    hex: Object.freeze({ level: 'full', note: 'Hex, base virtuelle, endian et taille de pointeur restent fiables.' }),
    sections: Object.freeze({ level: 'full', note: 'Le blob est exposé comme une section brute unique.' }),
    info: Object.freeze({ level: 'full', note: 'Résumé pseudo-binaire basé sur le profil brut choisi.' }),
    strings: Object.freeze({ level: 'full', note: 'Extraction de chaînes directement depuis le blob.' }),
    recherche: Object.freeze({ level: 'full', note: 'Recherche textuelle et offsets disponibles sur le blob.' }),
    typed_data: Object.freeze({ level: 'full', note: 'Décodage typé à partir de la base, endian et ptr size du profil brut.' }),
    script: Object.freeze({ level: 'full', note: 'Automatisation disponible tant que le script vise le blob courant.' }),
    symbols: Object.freeze({ level: 'limited', note: 'Symboles heuristiques ou découverts, sans vraie table native.' }),
    imports: Object.freeze({ level: 'limited', note: 'Indices heuristiques uniquement, pas de table d’imports réelle.' }),
    detection: Object.freeze({ level: 'limited', note: 'YARA reste utile ; CAPA ne couvre pas les blobs bruts.' }),
    decompile: Object.freeze({ level: 'unsupported', note: 'Pas de décompilation fiable sans format exécutable complet.' }),
    stack: Object.freeze({ level: 'unsupported', note: 'La stack frame statique raw attend un backend sans dépendance LIEF.' }),
    pe_resources: Object.freeze({ level: 'unsupported', note: 'Un blob brut n’expose pas de ressources PE structurées.' }),
    exceptions: Object.freeze({ level: 'unsupported', note: 'Pas de tables d’exceptions exploitables sur blob brut.' }),
  });

  const DEFAULT_RAW_TAB_CAPABILITY = Object.freeze({
    level: 'limited',
    note: 'Compatibilité brute à confirmer pour cette vue.',
  });

  function getRawTabCapability(tabId) {
    return RAW_TAB_CAPABILITIES[tabId] || DEFAULT_RAW_TAB_CAPABILITY;
  }

  function getRawTabsByLevel(level) {
    return Object.entries(RAW_TAB_CAPABILITIES)
      .filter(([, capability]) => capability.level === level)
      .map(([tabId]) => tabId);
  }

  const api = Object.freeze({
    RAW_UNSUPPORTED_TABS,
    RAW_TAB_CAPABILITIES,
    DEFAULT_RAW_TAB_CAPABILITY,
    getRawTabCapability,
    getRawTabsByLevel,
  });

  global.POFRawTabCapabilities = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
