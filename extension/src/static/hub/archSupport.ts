// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file hub/archSupport.ts
 * @brief Utilitaires de lecture et d'interrogation de la matrice feature/arch.
 *
 * Miroir TS du concept Python `FeatureSupport` (binary/arch.py).
 * Fournit des fonctions pures pour lire le payload arch depuis un mapping
 * de désassemblage et interroger le niveau de support d'une feature.
 *
 * Aucune dépendance sur l'état du hub — toutes les fonctions sont pures.
 */

/** Features exposées par le backend (ordre identique à Python FEATURES). */
const FEATURES = Object.freeze([
  'disasm',
  'discover_functions',
  'cfg',
  'xrefs',
  'call_graph',
  'stack_frame',
  'calling_convention',
]);

/**
 * Niveaux de support ordonnés du plus faible au plus fort.
 * Identiques aux valeurs Python FeatureSupport.level.
 */
const FEATURE_LEVELS = Object.freeze(['unsupported', 'disasm-only', 'partial', 'full']);

const _LEVEL_RANK = Object.fromEntries(FEATURE_LEVELS.map((l, i) => [l, i]));

/**
 * Lit le payload arch depuis un fichier mapping JSON de désassemblage.
 *
 * @param {string} mappingPath - Chemin absolu vers le fichier mapping.
 * @param {object} fs          - Module Node.js `fs` injecté.
 * @returns {object|null}      - Payload `{ key, family, display_name, bits, ptr_size, abi, endian, support }` ou null.
 */
const readArchSupportFromMapping = (mappingPath, fs) => {
  if (!mappingPath || !fs.existsSync(mappingPath)) return null;
  try {
    const mapping = JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
    if (mapping?.arch && typeof mapping.arch === 'object') return mapping.arch;
  } catch (_) { /* mapping illisible ou malformé */ }
  return null;
};

/**
 * Retourne l'entrée `{ level, note }` pour une feature donnée.
 *
 * @param {object|null} archPayload - Payload arch issu du mapping.
 * @param {string}      feature     - Nom de la feature (cf. FEATURES).
 * @returns {{ level: string, note: string }|null}
 */
const getFeatureEntry = (archPayload, feature) => {
  const entry = archPayload?.support?.[feature];
  if (!entry || typeof entry.level !== 'string') return null;
  return { level: entry.level, note: entry.note || '' };
};

/**
 * Retourne le niveau de support d'une feature pour le payload courant.
 *
 * @param {object|null} archPayload - Payload arch issu du mapping.
 * @param {string}      feature     - Nom de la feature (cf. FEATURES).
 * @returns {string|null} - `'full'`, `'partial'`, `'disasm-only'`, `'unsupported'`, ou null si inconnu.
 */
const getFeatureLevel = (archPayload, feature) => {
  return getFeatureEntry(archPayload, feature)?.level ?? null;
};

/**
 * Retourne true si la feature atteint au moins le niveau `minLevel`.
 *
 * Ordre : unsupported < disasm-only < partial < full
 *
 * @param {object|null} archPayload - Payload arch issu du mapping.
 * @param {string}      feature     - Nom de la feature (cf. FEATURES).
 * @param {string}      minLevel    - Niveau minimum requis.
 * @returns {boolean}
 */
const isFeatureAtLeast = (archPayload, feature, minLevel) => {
  const level = getFeatureLevel(archPayload, feature);
  if (!level) return false;
  return (_LEVEL_RANK[level] ?? -1) >= (_LEVEL_RANK[minLevel] ?? 0);
};

/**
 * Retourne true si la feature est au minimum `partial` (i.e. pas unsupported / disasm-only).
 */
const isFeatureUsable = (archPayload, feature) => isFeatureAtLeast(archPayload, feature, 'partial');

/**
 * Retourne true si la feature est `full`.
 */
const isFeatureFull = (archPayload, feature) => getFeatureLevel(archPayload, feature) === 'full';

/**
 * Retourne l'entrée la plus dégradée parmi une liste de features.
 * Utile pour afficher un badge de support agrégé.
 *
 * @param {object|null} archPayload - Payload arch issu du mapping.
 * @param {string[]}    features    - Liste de features à agréger.
 * @returns {{ level: string, note: string }|null}
 */
const worstFeatureEntry = (archPayload, features) => {
  let worst = null;
  for (const f of features) {
    const entry = getFeatureEntry(archPayload, f);
    if (!entry) continue;
    if (worst === null || (_LEVEL_RANK[entry.level] ?? 0) < (_LEVEL_RANK[worst.level] ?? 0)) {
      worst = entry;
    }
  }
  return worst;
};

module.exports = {
  FEATURES,
  FEATURE_LEVELS,
  readArchSupportFromMapping,
  getFeatureEntry,
  getFeatureLevel,
  isFeatureAtLeast,
  isFeatureUsable,
  isFeatureFull,
  worstFeatureEntry,
};
