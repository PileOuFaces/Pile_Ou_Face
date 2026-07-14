// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file productConfig.ts
 * @brief Couche de configuration produit.
 *
 * Frontière open-core : la source open-source ne contient AUCUN endpoint,
 * branding ou télémétrie spécifique à la société. Les URLs des providers
 * (auth/entitlement, collaboration) sont lues ici, jamais codées en dur.
 *
 * - `product.default.json` (versionné) : configuration NEUTRE, tout vide.
 * - `product.json` (non versionné, cf. .gitignore) : overlay écrit par le
 *   build commercial officiel pour pointer vers les providers officiels.
 *
 * Un host construit depuis la source seule ne se connecte donc nulle part par
 * défaut : les clients de protocole restent dormants tant qu'aucune URL n'est
 * configurée (par le build officiel, les réglages VS Code ou un self-hoster).
 */

const fs = require('fs');
const path = require('path');

const NEUTRAL_CONFIG = Object.freeze({ authProviderUrl: '', collabProviderUrl: '' });

let _cache = null;

function _extensionRoot() {
  // Bundle esbuild : dist/extension.js → racine un niveau au-dessus.
  // Build tsc historique : out/shared/productConfig.js → deux niveaux.
  const bundledRoot = path.join(__dirname, '..');
  if (fs.existsSync(path.join(bundledRoot, 'product.default.json'))) {
    return bundledRoot;
  }
  return path.join(__dirname, '..', '..');
}

function _readJson(file) {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : null;
  } catch (_) {
    return null;
  }
}

function loadProductConfig(root = _extensionRoot()) {
  const defaults = _readJson(path.join(root, 'product.default.json'));
  const overlay = _readJson(path.join(root, 'product.json'));
  return { ...NEUTRAL_CONFIG, ...(defaults || {}), ...(overlay || {}) };
}

function getProductConfig() {
  if (!_cache) {
    _cache = loadProductConfig();
  }
  return _cache;
}

module.exports = {
  NEUTRAL_CONFIG,
  loadProductConfig,
  getProductConfig,
};
