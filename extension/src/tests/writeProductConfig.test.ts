const { expect } = require('chai');
const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

describe('official product config generation', () => {
  it('writes the production auth URL using the complete three-field contract', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-official-productcfg-'));
    const outputPath = path.join(tempDir, 'product.json');
    const scriptPath = path.resolve(__dirname, '../../scripts/write-product-config.mjs');

    try {
      execFileSync(process.execPath, [scriptPath, outputPath], {
        env: {
          ...process.env,
          POF_AUTH_PROVIDER_URL: 'https://auth.pileouface.dev',
          POF_COLLAB_PROVIDER_URL: '',
          POF_TELEMETRY_PROVIDER_URL: '',
        },
        stdio: 'pipe',
      });

      const config = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
      expect(Object.keys(config)).to.deep.equal([
        'authProviderUrl',
        'collabProviderUrl',
        'telemetryProviderUrl',
      ]);
      expect(config).to.deep.equal({
        authProviderUrl: 'https://auth.pileouface.dev',
        collabProviderUrl: '',
        telemetryProviderUrl: '',
      });
    } finally {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
