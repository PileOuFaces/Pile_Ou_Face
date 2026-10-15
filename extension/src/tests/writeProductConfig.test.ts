const { expect } = require('chai');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

describe('official product config generation', () => {
  it('uses the official deployment profile with the complete provider contract', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-official-productcfg-'));
    const outputPath = path.join(tempDir, 'product.json');
    const scriptPath = path.resolve(__dirname, '../../scripts/write-product-config.mjs');

    try {
      execFileSync(process.execPath, [scriptPath, outputPath], {
        stdio: 'pipe',
      });

      const config = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
      expect(Object.keys(config)).to.deep.equal([
        'deploymentProfile',
        'deploymentId',
        'authProviderUrl',
        'collabProviderUrl',
        'telemetryProviderUrl',
      ]);
      expect(config).to.deep.equal({
        deploymentProfile: 'OFFICIAL_SAAS',
        deploymentId: 'official-saas',
        authProviderUrl: 'https://auth.pileouface.dev',
        collabProviderUrl: '',
        telemetryProviderUrl: '',
      });
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
