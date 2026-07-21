const { expect } = require('chai');
const sinon = require('sinon');

const { createTelemetryService, durationBucket } = require('../shared/telemetry/telemetry');
const { EVENT_NAMES } = require('../shared/telemetry/telemetryEvents');

function createHarness({ globalEnabled = true, productEnabled = true, configured = true } = {}) {
  const logUsage = sinon.stub();
  const abortInFlight = sinon.spy();
  const transport = {
    abortInFlight,
    dispose: sinon.spy(),
    isConfigured: sinon.stub().returns(configured),
    sendBody: sinon.spy(),
  };
  let telemetryListener = null;
  let configListener = null;
  let currentProductEnabled = productEnabled;
  const logger = { logUsage, dispose: sinon.spy() };
  const vscode = {
    env: {
      isTelemetryEnabled: globalEnabled,
      createTelemetryLogger: sinon.stub().returns(logger),
      onDidChangeTelemetryEnabled: sinon.stub().callsFake((listener) => {
        telemetryListener = listener;
        return { dispose: sinon.spy() };
      }),
    },
    workspace: {
      getConfiguration: () => ({ get: () => currentProductEnabled }),
      onDidChangeConfiguration: sinon.stub().callsFake((listener) => {
        configListener = listener;
        return { dispose: sinon.spy() };
      }),
    },
  };
  const service = createTelemetryService({ vscode, endpoint: 'https://telemetry.example', transport });
  return {
    abortInFlight,
    configListener,
    logUsage,
    logger,
    service,
    setProductEnabled(value) { currentProductEnabled = value; },
    telemetryListener,
    transport,
    vscode,
  };
}

describe('privacy telemetry consent', () => {
  it('sends a validated usage event when every gate is enabled', () => {
    const harness = createHarness();
    expect(harness.service.trackEvent(EVENT_NAMES.PANEL_OPENED, { panel: 'static' })).to.equal(true);
    expect(harness.logUsage.calledOnceWithExactly(EVENT_NAMES.PANEL_OPENED, { panel: 'static' })).to.equal(true);
    expect(harness.vscode.env.createTelemetryLogger.firstCall.args[1]).to.deep.equal({
      ignoreBuiltInCommonProperties: true,
      ignoreUnhandledErrors: true,
    });
  });

  for (const disabledGate of ['global', 'product', 'endpoint']) {
    it(`calls no logger when the ${disabledGate} gate is disabled`, () => {
      const harness = createHarness({
        globalEnabled: disabledGate !== 'global',
        productEnabled: disabledGate !== 'product',
        configured: disabledGate !== 'endpoint',
      });
      expect(harness.service.trackEvent(EVENT_NAMES.PANEL_OPENED, { panel: 'static' })).to.equal(false);
      expect(harness.logUsage.called).to.equal(false);
    });
  }

  it('rejects unknown properties before the logger', () => {
    const harness = createHarness();
    expect(harness.service.trackEvent(EVENT_NAMES.PANEL_OPENED, {
      panel: 'static', error: '/home/alice/challenge',
    })).to.equal(false);
    expect(harness.logUsage.called).to.equal(false);
  });

  it('does not accept an Error object as failure properties', () => {
    const harness = createHarness();
    expect(harness.service.trackFailure(EVENT_NAMES.RUN_TRACE_FAILED, new Error('/home/alice/challenge'))).to.equal(false);
    expect(harness.logUsage.called).to.equal(false);
  });

  it('never lets a logger failure escape into the product workflow', () => {
    const harness = createHarness();
    harness.logUsage.throws(new Error('logger unavailable'));
    expect(() => harness.service.trackEvent(
      EVENT_NAMES.PANEL_OPENED,
      { panel: 'static' },
    )).to.not.throw();
    expect(harness.service.trackEvent(EVENT_NAMES.PANEL_OPENED, { panel: 'static' })).to.equal(false);
  });

  it('aborts in-flight requests when VS Code disables telemetry', () => {
    const harness = createHarness();
    harness.vscode.env.isTelemetryEnabled = false;
    harness.telemetryListener(false);
    expect(harness.abortInFlight.calledOnce).to.equal(true);
  });

  it('aborts in-flight requests when the product setting changes to disabled', () => {
    const harness = createHarness();
    harness.setProductEnabled(false);
    harness.configListener({ affectsConfiguration: (key) => key === 'pileOuFace.telemetry.enabled' });
    expect(harness.abortInFlight.calledOnce).to.equal(true);
  });

  it('buckets durations without exposing exact values', () => {
    expect(durationBucket(20)).to.equal('<1s');
    expect(durationBucket(1000)).to.equal('1-5s');
    expect(durationBucket(5000)).to.equal('5-15s');
    expect(durationBucket(15000)).to.equal('15-60s');
    expect(durationBucket(60000)).to.equal('>60s');
  });
});
