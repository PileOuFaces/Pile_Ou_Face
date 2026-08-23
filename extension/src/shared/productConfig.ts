// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file productConfig.ts
 * @brief Couche de configuration produit.
 *
 * Frontière open-core : la source open-source ne contient AUCUN endpoint,
 * branding ou télémétrie spécifique à la société. Les URLs des providers
 * (auth/entitlement, collaboration, télémétrie) sont lues ici, jamais codées en dur.
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

const DEPLOYMENT_PROFILES = Object.freeze({
  OFFICIAL_SAAS: 'OFFICIAL_SAAS',
  MANAGED_ON_PREM: 'MANAGED_ON_PREM',
  OSS_DEVELOPMENT: 'OSS_DEVELOPMENT',
  AIRGAP_ENTERPRISE: 'AIRGAP_ENTERPRISE',
});

const NEUTRAL_CONFIG = Object.freeze({
  deploymentProfile: DEPLOYMENT_PROFILES.OSS_DEVELOPMENT,
  deploymentId: 'oss-development',
  authProviderUrl: '',
  collabProviderUrl: '',
  telemetryProviderUrl: '',
});

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

function isDeploymentProfile(value) {
  return Object.values(DEPLOYMENT_PROFILES).includes(value);
}

function validateProductConfig(config) {
  const profile = config?.deploymentProfile;
  if (!isDeploymentProfile(profile)) {
    throw new Error(`Unknown deployment profile: ${String(profile || '<empty>')}`);
  }
  if (profile === DEPLOYMENT_PROFILES.AIRGAP_ENTERPRISE && config.authProviderUrl) {
    throw new Error('AIRGAP_ENTERPRISE must not define an auth provider URL');
  }
  if (
    (profile === DEPLOYMENT_PROFILES.OFFICIAL_SAAS
      || profile === DEPLOYMENT_PROFILES.MANAGED_ON_PREM)
    && (!config.authProviderUrl || !config.deploymentId)
  ) {
    throw new Error(`${profile} requires authProviderUrl and deploymentId`);
  }
  return config;
}

function getProductConfig() {
  if (!_cache) {
    _cache = validateProductConfig(loadProductConfig());
  }
  return _cache;
}

module.exports = {
  DEPLOYMENT_PROFILES,
  NEUTRAL_CONFIG,
  loadProductConfig,
  validateProductConfig,
  getProductConfig,
};
