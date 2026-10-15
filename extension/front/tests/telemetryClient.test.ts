const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadClient(messageBus = null) {
  const messages = [];
  const window = messageBus
    ? { POFHubMessageBus: { postMessage: (message) => messages.push(message) } }
    : {};
  const source = fs.readFileSync(
    path.resolve(__dirname, '../shared/telemetryClient.js'),
    'utf8',
  );
  vm.runInNewContext(source, { window });
  return { messages, window };
}

describe('telemetry client webview bridge', () => {
  it('posts only the explicit event envelope through the hub message bus', () => {
    const { messages, window } = loadClient(true);
    expect(window.POFTelemetry.trackEvent('panel.opened', { panel: 'static' })).to.equal(true);
    expect(messages).to.deep.equal([{
      type: 'pof.telemetry',
      eventName: 'panel.opened',
      properties: { panel: 'static' },
    }]);
  });

  it('supports the standalone visualizer with an injected postMessage function', () => {
    const { window } = loadClient();
    const messages = [];
    const client = window.POFTelemetryClient.create((message) => messages.push(message));
    client.trackEvent('dynamic.stack_mode.changed', {
      stackMode: 'advanced', surface: 'standalone',
    });
    expect(messages).to.have.length(1);
  });

  it('does not post malformed calls', () => {
    const { messages, window } = loadClient(true);
    expect(window.POFTelemetry.trackEvent('', {})).to.equal(false);
    expect(window.POFTelemetry.trackEvent('panel.opened', null)).to.equal(false);
    expect(messages).to.deep.equal([]);
  });

  it('maps UI values only to registry enum values', () => {
    const { window } = loadClient();
    const client = window.POFTelemetryClient;

    expect(client.mapPanel('outils')).to.equal('tools');
    expect(client.mapPanel('options')).to.equal('settings');
    expect(client.mapPanel('not-a-panel')).to.equal(null);
    expect(client.mapBinaryFormat('Mach-O')).to.equal('macho');
    expect(client.mapBinaryFormat('unknown format')).to.equal('unknown');
    expect(client.mapArch('AMD64')).to.equal('x64');
    expect(client.mapArch('')).to.equal('unknown');
    expect(client.mapPayloadMode('payload_builder')).to.equal('builder');
    expect(client.mapPayloadMode('pwntools_script')).to.equal('pwntools');
    expect(client.mapPayloadMode('invalid')).to.equal(null);
    expect(client.mapStaticFeature('disasm')).to.equal('disassembly');
    expect(client.mapStaticFeature('typed_data')).to.equal('typed_data');
    expect(client.mapStaticFeature('plugin-tab')).to.equal(null);
  });
});
