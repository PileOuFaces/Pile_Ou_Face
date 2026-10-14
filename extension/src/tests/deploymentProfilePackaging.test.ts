const { expect } = require('chai');
const manifest = require('../../package.json');
const { buildProductConfig, configureManifest } = require('../../scripts/deployment-profile');

describe('deployment profile packaging', () => {
  it('pins the official SaaS artifact to the .dev authority', () => {
    expect(buildProductConfig('OFFICIAL_SAAS')).to.include({
      deploymentId: 'official-saas',
      authProviderUrl: 'https://auth.pileouface.dev',
    });
  });

  it('requires an administered identity and endpoint for managed on-prem', () => {
    expect(() => buildProductConfig('MANAGED_ON_PREM', {})).to.throw('requires');
    expect(buildProductConfig('MANAGED_ON_PREM', {
      POF_DEPLOYMENT_ID: 'customer-a',
      POF_AUTH_PROVIDER_URL: 'https://auth.customer.example',
    })).to.include({ deploymentId: 'customer-a', authProviderUrl: 'https://auth.customer.example' });
  });

  it('keeps OSS neutral and airgap offline', () => {
    expect(buildProductConfig('OSS_DEVELOPMENT').authProviderUrl).to.equal('');
    expect(buildProductConfig('AIRGAP_ENTERPRISE').authProviderUrl).to.equal('');
  });

  it('exposes the endpoint setting only in OSS artifacts', () => {
    expect(configureManifest(manifest, 'OSS_DEVELOPMENT').contributes.configuration.properties)
      .to.have.property('pileOuFace.authServerUrl');
    expect(configureManifest(manifest, 'OFFICIAL_SAAS').contributes.configuration.properties)
      .not.to.have.property('pileOuFace.authServerUrl');
  });
});
