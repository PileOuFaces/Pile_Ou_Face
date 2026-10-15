const { expect } = require('chai');
const sinon = require('sinon');
const { createRunTraceTelemetry } = require('../dynamic/runTraceTelemetry');

describe('run trace privacy telemetry', () => {
  function createHarness(properties = {}) {
    let clock = 1000;
    const telemetry = {
      trackOperation: sinon.spy(),
      trackFailure: sinon.spy(),
    };
    const operation = createRunTraceTelemetry({
      telemetry,
      arch: 'unknown',
      payloadMode: 'builder',
      target: 'auto',
      sourceProvided: false,
      ...properties,
      now: () => clock,
    });
    return {
      operation,
      telemetry,
      advance: (milliseconds) => { clock += milliseconds; },
    };
  }

  it('emits only categorized start and completion properties', () => {
    const harness = createHarness({
      arch: 'x64',
      payloadMode: 'pwntools',
      target: 'argv1',
      sourceProvided: true,
      ignoredSensitiveValue: '/home/alice/private/challenge.c:41414141',
    });

    harness.operation.start();
    harness.advance(6200);
    harness.operation.complete(true);

    expect(harness.telemetry.trackOperation.firstCall.args).to.deep.equal([
      'dynamic.run_trace.started',
      { arch: 'x64', payloadMode: 'pwntools', target: 'argv1', sourceProvided: true },
    ]);
    expect(harness.telemetry.trackOperation.secondCall.args).to.deep.equal([
      'dynamic.run_trace.completed',
      { payloadMode: 'pwntools', durationBucket: '5-15s', crashDetected: true },
    ]);
    expect(JSON.stringify(harness.telemetry.trackOperation.args)).to.not.include('challenge.c');
    expect(JSON.stringify(harness.telemetry.trackOperation.args)).to.not.include('41414141');
  });

  it('normalizes file inputs and controlled failure categories', () => {
    const harness = createHarness({
      arch: 'x86',
      payloadMode: 'file',
      target: 'file',
    });

    harness.operation.start();
    harness.advance(300);
    harness.operation.fail('arbitrary backend error');

    expect(harness.telemetry.trackOperation.firstCall.args[1]).to.deep.equal({
      arch: 'x86', payloadMode: 'file', target: 'file', sourceProvided: false,
    });
    expect(harness.telemetry.trackFailure.firstCall.args).to.deep.equal([
      'dynamic.run_trace.failed',
      { payloadMode: 'file', durationBucket: '<1s', errorCategory: 'unknown' },
    ]);
  });

  it('marks cancellation locally without emitting a failure event', () => {
    const harness = createHarness();
    harness.operation.start();
    expect(harness.operation.cancel()).to.equal(true);
    expect(harness.operation.complete(false)).to.equal(false);
    expect(harness.operation.fail('unknown')).to.equal(false);
    expect(harness.telemetry.trackFailure.callCount).to.equal(0);
    expect(harness.telemetry.trackOperation.callCount).to.equal(1);
    expect(harness.operation.getOutcome()).to.equal('cancelled');
  });
});
