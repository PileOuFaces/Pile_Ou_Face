// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file authConfig.ts
 * @brief Resolution de l'URL auth entre valeur sauvegardee, config VS Code et mode dev local.
 */

const fs = require('fs');
const path = require('path');

const DEFAULT_REMOTE_AUTH_URL = 'https://auth.pileouface.io';
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
} = {}) {
  const saved = normalizeAuthUrl(savedAuthServerUrl);
  const configured = normalizeAuthUrl(configuredAuthServerUrl);
  const localWorkspaceDetected = hasLocalAuthWorkspace(projectRoot, existsSync);

  if (saved && !(saved === DEFAULT_REMOTE_AUTH_URL && !configured && localWorkspaceDetected)) {
    return saved;
  }
  if (configured) return configured;
  if (localWorkspaceDetected) return DEFAULT_LOCAL_AUTH_URL;
  return saved || DEFAULT_REMOTE_AUTH_URL;
}

module.exports = {
  DEFAULT_LOCAL_AUTH_URL,
  DEFAULT_REMOTE_AUTH_URL,
  hasLocalAuthWorkspace,
  resolveAuthServerUrl,
};
