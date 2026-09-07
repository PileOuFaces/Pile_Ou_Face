const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const { PLUGIN_BRIDGE_PREAMBLE } = require('../shared/webview');

describe('window.PoF shared contract', () => {
  const extensionRoot = path.resolve(__dirname, '..', '..');
  const stateSource = fs.readFileSync(path.join(extensionRoot, 'front', 'shared', 'state.js'), 'utf8');
  const runtimeSource = fs.readFileSync(path.join(extensionRoot, 'backends', 'plugins', 'runtime.py'), 'utf8');

  it('keeps the host, iframe bridge, and backend compatibility versions aligned', () => {
    const hostVersion = stateSource.match(/window\.PoF\s*=\s*\{[\s\S]*?version:\s*'([^']+)'/)?.[1];
    const bridgeVersion = PLUGIN_BRIDGE_PREAMBLE.match(/window\.PoF\s*=\s*\{[\s\S]*?version:\s*'([^']+)'/)?.[1];
    const runtimeVersion = runtimeSource.match(/^POF_VERSION\s*=\s*"([^"]+)"/m)?.[1];

    expect(hostVersion).to.equal('1.1.0');
    expect(bridgeVersion).to.equal(hostVersion);
    expect(runtimeVersion).to.equal(hostVersion);
  });

  for (const method of ['getGroupLabels', 'getTabFamilies', 'getDisabledFamilies', 'setLoading', 'navigateTo']) {
    it(`exposes ${method} on both host and iframe facades`, () => {
      expect(stateSource).to.match(new RegExp(`\\b${method}\\s*:`));
      expect(PLUGIN_BRIDGE_PREAMBLE).to.match(new RegExp(`\\b${method}\\s*:`));
    });
  }
});
