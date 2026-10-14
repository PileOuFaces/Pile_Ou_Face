// SPDX-License-Identifier: AGPL-3.0-only

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const DISCOVERY_PATH = '/.well-known/pile-ou-face-auth/v1';

interface AuthDiscoveryPayload {
  protocol_version: string;
  deployment_id: string;
  issuer: string;
  audience: string;
  lease_audience: string;
  jwks_uri: string;
  capabilities: readonly unknown[];
  [key: string]: unknown;
}

interface AuthDiscoveryOptions {
  expectedDeploymentId?: string;
  fetchImpl?: typeof fetch;
}

type ValidatedAuthDiscovery = Readonly<AuthDiscoveryPayload & { origin: string }>;

function normalizeAuthOrigin(value: unknown): string {
  let parsed: URL;
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

function validateAuthDiscovery(
  origin: unknown,
  payload: unknown,
  expectedDeploymentId = '',
): ValidatedAuthDiscovery {
  const normalizedOrigin = normalizeAuthOrigin(origin);
  if (!payload || typeof payload !== 'object') throw new Error('unsupported auth protocol version');
  const discovery = payload as Record<string, unknown>;
  if (discovery.protocol_version !== '1') throw new Error('unsupported auth protocol version');
  if (typeof discovery.deployment_id !== 'string' || !discovery.deployment_id) throw new Error('missing deployment_id');
  if (expectedDeploymentId && discovery.deployment_id !== expectedDeploymentId) throw new Error('unexpected deployment_id');
  if (discovery.issuer !== normalizedOrigin) throw new Error('auth issuer mismatch');
  if (discovery.audience !== 'pile-ou-face-host') throw new Error('auth audience mismatch');
  if (discovery.lease_audience !== 'pof-plugin-runtime') throw new Error('lease audience mismatch');
  if (discovery.jwks_uri !== `${normalizedOrigin}/auth/jwks`) throw new Error('auth jwks_uri mismatch');
  if (!Array.isArray(discovery.capabilities) || !discovery.capabilities.includes('auth')) {
    throw new Error('auth capability missing');
  }
  return Object.freeze({
    ...(discovery as AuthDiscoveryPayload),
    origin: normalizedOrigin,
  });
}

async function discoverAuthServer(
  origin: unknown,
  { expectedDeploymentId = '', fetchImpl = fetch }: AuthDiscoveryOptions = {},
): Promise<ValidatedAuthDiscovery> {
  const normalizedOrigin = normalizeAuthOrigin(origin);
  const response = await fetchImpl(`${normalizedOrigin}${DISCOVERY_PATH}`);
  if (!response.ok) throw new Error(`auth discovery failed: ${response.status}`);
  return validateAuthDiscovery(normalizedOrigin, await response.json(), expectedDeploymentId);
}

module.exports = { DISCOVERY_PATH, normalizeAuthOrigin, validateAuthDiscovery, discoverAuthServer };
