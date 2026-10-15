// SPDX-License-Identifier: AGPL-3.0-only
'use strict';

const PROFILES = new Set([
  'OFFICIAL_SAAS',
  'MANAGED_ON_PREM',
  'OSS_DEVELOPMENT',
  'AIRGAP_ENTERPRISE',
]);

function buildProductConfig(profile, env = process.env) {
  if (!PROFILES.has(profile)) throw new Error(`Unknown deployment profile: ${profile}`);
  const base = {
    deploymentProfile: profile,
    deploymentId: '',
    authProviderUrl: '',
    collabProviderUrl: '',
    telemetryProviderUrl: '',
  };
  if (profile === 'OFFICIAL_SAAS') {
    return { ...base, deploymentId: 'official-saas', authProviderUrl: 'https://auth.pileouface.dev' };
  }
  if (profile === 'MANAGED_ON_PREM') {
    const deploymentId = String(env.POF_DEPLOYMENT_ID || '').trim();
    const authProviderUrl = String(env.POF_AUTH_PROVIDER_URL || '').trim();
    if (!deploymentId || !authProviderUrl) {
      throw new Error('MANAGED_ON_PREM requires POF_DEPLOYMENT_ID and POF_AUTH_PROVIDER_URL');
    }
    return { ...base, deploymentId, authProviderUrl };
  }
  if (profile === 'AIRGAP_ENTERPRISE') {
    return { ...base, deploymentId: String(env.POF_DEPLOYMENT_ID || 'airgap-enterprise').trim() };
  }
  return { ...base, deploymentId: 'oss-development' };
}

function configureManifest(manifest, profile) {
  const copy = JSON.parse(JSON.stringify(manifest));
  const properties = copy.contributes?.configuration?.properties || {};
  if (profile !== 'OSS_DEVELOPMENT') delete properties['pileOuFace.authServerUrl'];
  return copy;
}

module.exports = { PROFILES, buildProductConfig, configureManifest };
