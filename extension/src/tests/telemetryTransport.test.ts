const { expect } = require('chai');
const sinon = require('sinon');

const {
  DEFAULT_MAX_IN_FLIGHT,
  createTelemetryTransport,
  normalizeTelemetryEndpoint,
} = require('../shared/telemetry/telemetryTransport');

describe('privacy telemetry transport', () => {
  it('accepts HTTPS endpoints only', () => {
    expect(normalizeTelemetryEndpoint('https://telemetry.example/ingest')).to.equal('https://telemetry.example/ingest');
    expect(normalizeTelemetryEndpoint('http://telemetry.example/ingest')).to.equal('');
    expect(normalizeTelemetryEndpoint('file:///tmp/telemetry')).to.equal('');
    expect(normalizeTelemetryEndpoint('not a url')).to.equal('');
  });

  it('posts one JSON body without credentials or retry metadata', async () => {
    const fetchImpl = sinon.stub().resolves({ ok: true });
    const transport = createTelemetryTransport({
      endpoint: 'https://telemetry.example/ingest', fetchImpl,
    });
    const body = '{"schemaVersion":1,"eventName":"panel.opened","properties":{"panel":"static"}}';
    expect(await transport.sendBody(body)).to.equal(true);
    expect(fetchImpl.calledOnce).to.equal(true);
    expect(fetchImpl.firstCall.args[1]).to.include({ method: 'POST', body });
    expect(fetchImpl.firstCall.args[1].headers).to.deep.equal({ 'content-type': 'application/json' });
    expect(fetchImpl.firstCall.args[1]).to.not.have.property('credentials');
  });

  for (const status of [400, 429, 500]) {
    it(`returns false without retry for HTTP ${status}`, async () => {
      const fetchImpl = sinon.stub().resolves({ ok: false, status });
      const transport = createTelemetryTransport({
        endpoint: 'https://telemetry.example/ingest', fetchImpl,
      });
      expect(await transport.sendBody('{}')).to.equal(false);
      expect(fetchImpl.calledOnce).to.equal(true);
    });
  }

  it('swallows network failures', async () => {
    const transport = createTelemetryTransport({
      endpoint: 'https://telemetry.example/ingest',
      fetchImpl: sinon.stub().rejects(new Error('/home/alice/challenge')),
    });
    expect(await transport.sendBody('{}')).to.equal(false);
  });

  it('does not call fetch when no valid endpoint is configured', async () => {
    const fetchImpl = sinon.spy();
    const transport = createTelemetryTransport({ endpoint: '', fetchImpl });
    expect(await transport.sendBody('{}')).to.equal(false);
    expect(fetchImpl.called).to.equal(false);
  });

  it('bounds concurrent requests and drops excess events', async () => {
    const pending = [];
    const fetchImpl = sinon.stub().callsFake(() => new Promise((resolve) => pending.push(resolve)));
    const transport = createTelemetryTransport({
      endpoint: 'https://telemetry.example/ingest', fetchImpl,
    });
    const sends = Array.from({ length: DEFAULT_MAX_IN_FLIGHT + 1 }, () => transport.sendBody('{}'));
    expect(fetchImpl.callCount).to.equal(DEFAULT_MAX_IN_FLIGHT);
    expect(await sends.at(-1)).to.equal(false);
    pending.forEach((resolve) => resolve({ ok: true }));
    expect(await Promise.all(sends.slice(0, -1))).to.deep.equal(
      Array(DEFAULT_MAX_IN_FLIGHT).fill(true),
    );
  });

  it('aborts active requests on disposal without throwing', async () => {
    const fetchImpl = sinon.stub().callsFake((_url, options) => new Promise((resolve, reject) => {
      options.signal.addEventListener('abort', () => reject(new Error('aborted')));
    }));
    const transport = createTelemetryTransport({
      endpoint: 'https://telemetry.example/ingest', fetchImpl,
    });
    const pending = transport.sendBody('{}');
    transport.dispose();
    expect(await pending).to.equal(false);
  });
});
