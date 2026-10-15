// SPDX-License-Identifier: AGPL-3.0-only
/**
 * @file authConfig.ts
 * @brief Resolution de l'URL auth entre valeur sauvegardee, config VS Code et mode dev local.
 *
 * Frontiere open-core : aucune URL societe n'est codee en dur ici. Le defaut
 * distant provient de la couche de config produit (productConfig), NEUTRE en
 * open-source. Sans provider configure (build officiel, reglages ou dev local),
 * la resolution renvoie une chaine vide : le host ne se connecte nulle part.
 */

const fs = require('fs');
const path = require('path');
const { DEPLOYMENT_PROFILES, getProductConfig, validateProductConfig } = require('./productConfig');

const DEFAULT_LOCAL_AUTH_URL = 'http://localhost:8000';

type ExistsSync = (filePath: string) => boolean;

interface LegacyAuthUrlMigrationOptions {
  deploymentProfile?: string;
  legacyUrl?: string;
  configuredUrl?: string;
}

interface ProductConfigInput {
  deploymentProfile?: string;
  deploymentId?: string;
  authProviderUrl?: string;
  collabProviderUrl?: string;
  telemetryProviderUrl?: string;
}

interface ResolveAuthServerUrlOptions {
  savedAuthServerUrl?: string;
  configuredAuthServerUrl?: string;
  projectRoot?: string;
  existsSync?: ExistsSync;
  defaultRemoteAuthUrl?: string;
  productConfig?: ProductConfigInput;
}

interface LegacyAuthUrlMigrationPlan {
  removeLegacy: boolean;
  configuredUrl: string;
}

function normalizeAuthUrl(value: unknown = ''): string {
  const normalized = String(value || '').trim();
  return normalized || '';
}

function isLoopbackUrl(value: string): boolean {
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
  } catch (_) {
    return false;
  }
}

function requireSecureAuthUrl(value: unknown): string {
  const url = normalizeAuthUrl(value);
  if (!url) return '';
  const parsed = new URL(url);
  if (parsed.protocol !== 'https:' && !isLoopbackUrl(url)) {
    throw new Error('Auth server URL must use HTTPS outside loopback');
  }
  return url.replace(/\/$/, '');
}

function planLegacyAuthUrlMigration({
  deploymentProfile,
  legacyUrl = '',
  configuredUrl = '',
}: LegacyAuthUrlMigrationOptions = {}): LegacyAuthUrlMigrationPlan {
  const legacy = normalizeAuthUrl(legacyUrl);
  if (!legacy) return { removeLegacy: false, configuredUrl: normalizeAuthUrl(configuredUrl) };
  if (deploymentProfile === DEPLOYMENT_PROFILES.OSS_DEVELOPMENT && !normalizeAuthUrl(configuredUrl)) {
    return { removeLegacy: true, configuredUrl: requireSecureAuthUrl(legacy) };
  }
  return { removeLegacy: true, configuredUrl: normalizeAuthUrl(configuredUrl) };
}

function hasLocalAuthWorkspace(projectRoot: unknown, existsSync: ExistsSync = fs.existsSync): boolean {
  const root = String(projectRoot || '').trim();
  if (!root) return false;
  const candidates = [
    path.join(root, 'Pile_ou_Face_auth'),
    path.join(root, 'Pile_Ou_Face_auth'),
    path.join(root, '..', 'Pile_ou_Face_auth'),
    path.join(root, '..', 'Pile_Ou_Face_auth'),
  ];
  return candidates.some((candidate) => {
    try {
      return existsSync(path.join(candidate, 'app', 'main.py'));
    } catch (_) {
      return false;
    }
  });
}

function resolveAuthServerUrl({
  savedAuthServerUrl = '',
  configuredAuthServerUrl = '',
  projectRoot = '',
  existsSync = fs.existsSync,
  defaultRemoteAuthUrl = undefined,
  productConfig = undefined,
}: ResolveAuthServerUrlOptions = {}): string {
  const product = validateProductConfig(productConfig || {
    ...getProductConfig(),
    ...(defaultRemoteAuthUrl !== undefined ? { authProviderUrl: defaultRemoteAuthUrl } : {}),
  });
  const profile = product.deploymentProfile;
  const remoteDefault = requireSecureAuthUrl(product.authProviderUrl);
  const saved = requireSecureAuthUrl(savedAuthServerUrl);
  const configured = requireSecureAuthUrl(configuredAuthServerUrl);
  const localWorkspaceDetected = hasLocalAuthWorkspace(projectRoot, existsSync);

  if (profile === DEPLOYMENT_PROFILES.AIRGAP_ENTERPRISE) return '';
  if (profile === DEPLOYMENT_PROFILES.OFFICIAL_SAAS
    || profile === DEPLOYMENT_PROFILES.MANAGED_ON_PREM) {
    return remoteDefault;
  }

  // Migration : une valeur sauvegardee egale au defaut distant configure est
  // reroutee vers localhost en dev local. Ne se declenche jamais si le defaut
  // est neutre (vide).
  if (saved && !(remoteDefault && saved === remoteDefault && !configured && localWorkspaceDetected)) {
    return saved;
  }
  if (configured) return configured;
  if (localWorkspaceDetected) return DEFAULT_LOCAL_AUTH_URL;
  return saved || remoteDefault;
}

module.exports = {
  DEFAULT_LOCAL_AUTH_URL,
  hasLocalAuthWorkspace,
  isLoopbackUrl,
  planLegacyAuthUrlMigration,
  requireSecureAuthUrl,
  resolveAuthServerUrl,
};
