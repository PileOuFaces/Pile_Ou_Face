// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
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
const { getProductConfig } = require('./productConfig');

const DEFAULT_LOCAL_AUTH_URL = 'http://localhost:8000';

function normalizeAuthUrl(value = '') {
  const normalized = String(value || '').trim();
  return normalized || '';
}

function hasLocalAuthWorkspace(projectRoot, existsSync = fs.existsSync) {
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
} = {}) {
  const remoteDefault = normalizeAuthUrl(
    defaultRemoteAuthUrl !== undefined ? defaultRemoteAuthUrl : getProductConfig().authProviderUrl,
  );
  const saved = normalizeAuthUrl(savedAuthServerUrl);
  const configured = normalizeAuthUrl(configuredAuthServerUrl);
  const localWorkspaceDetected = hasLocalAuthWorkspace(projectRoot, existsSync);

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
  resolveAuthServerUrl,
};
