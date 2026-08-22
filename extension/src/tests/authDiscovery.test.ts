// @ts-nocheck
const { expect } = require('chai');
const {
  normalizeAuthOrigin,
  validateAuthDiscovery,
  discoverAuthServer,
} = require('../shared/authDiscovery');

function discovery(overrides = {}) {
  return {
    protocol_version: '1',
    deployment_id: 'deployment-test',
    issuer: 'https://auth.example',
    audience: 'pile-ou-face-host',
    lease_audience: 'pof-plugin-runtime',
    jwks_uri: 'https://auth.example/auth/jwks',
    capabilities: ['auth', 'online-standard-licensing'],
    ...overrides,
  };
}

describe('auth discovery v1', () => {
  it('accepts HTTPS origins and loopback HTTP only', () => {
    expect(normalizeAuthOrigin('https://auth.example/')).to.equal('https://auth.example');
    expect(normalizeAuthOrigin('http://127.0.0.1:8791')).to.equal('http://127.0.0.1:8791');
    expect(() => normalizeAuthOrigin('http://auth.example')).to.throw(/HTTPS/);
    expect(() => normalizeAuthOrigin('https://auth.example/path')).to.throw(/origin/);
  });

  it('validates issuer, audiences, deployment, JWKS and protocol before use', () => {
    expect(validateAuthDiscovery('https://auth.example', discovery(), 'deployment-test').deployment_id)
      .to.equal('deployment-test');
    for (const payload of [
      discovery({ protocol_version: '2' }),
      discovery({ deployment_id: 'other' }),
      discovery({ issuer: 'https://attacker.example' }),
      discovery({ audience: 'other-host' }),
      discovery({ lease_audience: 'other-runtime' }),
      discovery({ jwks_uri: 'https://attacker.example/jwks' }),
      discovery({ capabilities: [] }),
    ]) {
      expect(() => validateAuthDiscovery('https://auth.example', payload, 'deployment-test')).to.throw();
    }
  });

  it('fetches the versioned well-known endpoint', async () => {
    let requested = '';
    const result = await discoverAuthServer('https://auth.example/', {
      expectedDeploymentId: 'deployment-test',
      fetchImpl: async (url) => {
        requested = url;
        return { ok: true, json: async () => discovery() };
      },
    });
    expect(requested).to.equal('https://auth.example/.well-known/pile-ou-face-auth/v1');
    expect(result.origin).to.equal('https://auth.example');
  });
});
