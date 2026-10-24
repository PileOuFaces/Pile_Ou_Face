const http = require('node:http');
const { expect } = require('chai');
const sinon = require('sinon');

const { initializeExtensionTelemetry } = require('../shared/telemetry/telemetry');

function createVscodeHarness({ telemetryLevel = 'all' } = {}) {
  const telemetryEnabled = telemetryLevel !== 'off';
  const usageEnabled = telemetryLevel === 'all';
  const logUsage = sinon.spy();
  const vscode = {
    version: '1.120.2',
    env: {
      isTelemetryEnabled: telemetryEnabled,
      createTelemetryLogger(sender) {
        return {
          isUsageEnabled: usageEnabled,
          logUsage(eventName, properties) {
            logUsage(eventName, properties);
            sender.sendEventData(eventName, properties);
          },
          dispose() {},
        };
      },
    },
    workspace: {
      getConfiguration: (section) => ({
        get: (key, fallback) => section === 'telemetry' && key === 'telemetryLevel'
          ? telemetryLevel
          : fallback,
      }),
    },
  };
  return { logUsage, vscode };
}

async function startLocalTelemetryServer() {
  let receive;
  const requestReceived = new Promise((resolve) => { receive = resolve; });
  const server = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      receive({
        method: request.method,
        path: request.url,
        contentType: request.headers['content-type'],
        body: Buffer.concat(chunks).toString('utf8'),
      });
      response.writeHead(204);
      response.end();
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return { close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())), port, requestReceived };
}

describe('extension activation telemetry transport', () => {
  it('sends one allowlisted OFFICIAL_SAAS activation event to the local /v1/events endpoint', async () => {
    const server = await startLocalTelemetryServer();
    const diagnostics = [];
    const outboundUrls = [];
    const { logUsage, vscode } = createVscodeHarness();
    let completeTransport;
    const transportCompleted = new Promise((resolve) => { completeTransport = resolve; });
    const localFetch = async (url, options) => {
      outboundUrls.push(String(url));
      const response = await fetch(`http://127.0.0.1:${server.port}${new URL(url).pathname}`, options);
      completeTransport();
      return response;
    };
    const activationTelemetry = initializeExtensionTelemetry({
      vscode,
      context: { extension: { packageJSON: { version: '0.2.0' } }, subscriptions: [] },
      productConfig: {
        deploymentProfile: 'OFFICIAL_SAAS',
        telemetryProviderUrl: 'https://telemetry.example.test',
      },
      transport: require('../shared/telemetry/telemetryTransport').createTelemetryTransport({
        endpoint: 'https://telemetry.example.test',
        fetchImpl: localFetch,
      }),
      onDiagnostic: (status) => diagnostics.push(status),
      platform: 'linux',
    });

    try {
      expect(vscode.workspace.getConfiguration('telemetry').get('telemetryLevel')).to.equal('all');
      expect(activationTelemetry.isEnabled()).to.equal(true);
      expect(logUsage.calledOnceWithExactly('extension.activated', {
        extensionVersion: '0.2.0',
        vscodeVersionMajor: '1',
        platform: 'linux',
      })).to.equal(true);
      const request = await server.requestReceived;
      await transportCompleted;
      expect(outboundUrls).to.deep.equal(['https://telemetry.example.test/v1/events']);
      expect(request).to.include({ method: 'POST', path: '/v1/events', contentType: 'application/json' });
      const envelope = JSON.parse(request.body);
      expect(envelope).to.deep.equal({
        schemaVersion: 1,
        eventName: 'extension.activated',
        properties: { extensionVersion: '0.2.0', vscodeVersionMajor: '1', platform: 'linux' },
      });
      expect(diagnostics).to.deep.equal([]);
    } finally {
      activationTelemetry.dispose();
      await server.close();
    }
  });

  it('does not make an HTTP request when VS Code telemetry is disabled', async () => {
    let requests = 0;
    const diagnostics = [];
    const { vscode } = createVscodeHarness({ telemetryLevel: 'off' });
    const telemetry = initializeExtensionTelemetry({
      vscode,
      context: { extension: { packageJSON: { version: '0.2.0' } }, subscriptions: [] },
      productConfig: {
        deploymentProfile: 'OFFICIAL_SAAS',
        telemetryProviderUrl: 'https://telemetry.example.test',
      },
      transport: require('../shared/telemetry/telemetryTransport').createTelemetryTransport({
        endpoint: 'https://telemetry.example.test',
        fetchImpl: async () => { requests += 1; return { ok: true, status: 204 }; },
      }),
      onDiagnostic: (status) => diagnostics.push(status),
    });

    expect(vscode.workspace.getConfiguration('telemetry').get('telemetryLevel')).to.equal('off');
    expect(telemetry.isEnabled()).to.equal(false);
    expect(requests).to.equal(0);
    expect(diagnostics).to.deep.equal(['disabled']);
    telemetry.dispose();
  });

  it('does not make a usage request when VS Code only permits error telemetry', () => {
    let requests = 0;
    const diagnostics = [];
    const { vscode } = createVscodeHarness({ telemetryLevel: 'error' });
    const telemetry = initializeExtensionTelemetry({
      vscode,
      context: { extension: { packageJSON: { version: '0.2.0' } }, subscriptions: [] },
      productConfig: {
        deploymentProfile: 'OFFICIAL_SAAS',
        telemetryProviderUrl: 'https://telemetry.example.test',
      },
      transport: require('../shared/telemetry/telemetryTransport').createTelemetryTransport({
        endpoint: 'https://telemetry.example.test',
        fetchImpl: async () => { requests += 1; return { ok: true, status: 204 }; },
      }),
      onDiagnostic: (status) => diagnostics.push(status),
    });

    expect(vscode.workspace.getConfiguration('telemetry').get('telemetryLevel')).to.equal('error');
    expect(telemetry.isEnabled()).to.equal(false);
    expect(requests).to.equal(0);
    expect(diagnostics).to.deep.equal(['disabled']);
    telemetry.dispose();
  });
});
