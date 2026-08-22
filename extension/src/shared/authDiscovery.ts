// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const DISCOVERY_PATH = '/.well-known/pile-ou-face-auth/v1';

function normalizeAuthOrigin(value) {
  let parsed;
  try { parsed = new URL(String(value || '').trim()); } catch { throw new Error('invalid auth origin'); }
  if (parsed.username || parsed.password || parsed.search || parsed.hash
      || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw new Error('auth endpoint must be an absolute origin');
  }
  if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname))) {
    throw new Error('auth endpoint must use HTTPS outside loopback');
  }
  return parsed.origin;
}

function validateAuthDiscovery(origin, payload, expectedDeploymentId = '') {
  const normalizedOrigin = normalizeAuthOrigin(origin);
  if (!payload || payload.protocol_version !== '1') throw new Error('unsupported auth protocol version');
  if (typeof payload.deployment_id !== 'string' || !payload.deployment_id) throw new Error('missing deployment_id');
  if (expectedDeploymentId && payload.deployment_id !== expectedDeploymentId) throw new Error('unexpected deployment_id');
  if (payload.issuer !== normalizedOrigin) throw new Error('auth issuer mismatch');
  if (payload.audience !== 'pile-ou-face-host') throw new Error('auth audience mismatch');
  if (payload.lease_audience !== 'pof-plugin-runtime') throw new Error('lease audience mismatch');
  if (payload.jwks_uri !== `${normalizedOrigin}/auth/jwks`) throw new Error('auth jwks_uri mismatch');
  if (!Array.isArray(payload.capabilities) || !payload.capabilities.includes('auth')) {
    throw new Error('auth capability missing');
  }
  return Object.freeze({ ...payload, origin: normalizedOrigin });
}

async function discoverAuthServer(origin, { expectedDeploymentId = '', fetchImpl = fetch } = {}) {
  const normalizedOrigin = normalizeAuthOrigin(origin);
  const response = await fetchImpl(`${normalizedOrigin}${DISCOVERY_PATH}`);
  if (!response.ok) throw new Error(`auth discovery failed: ${response.status}`);
  return validateAuthDiscovery(normalizedOrigin, await response.json(), expectedDeploymentId);
}

module.exports = { DISCOVERY_PATH, normalizeAuthOrigin, validateAuthDiscovery, discoverAuthServer };
