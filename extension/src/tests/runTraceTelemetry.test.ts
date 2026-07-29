const { expect } = require('chai');
const sinon = require('sinon');
const {
  cpuBucket,
  createRunTraceTelemetry,
  rssBucket,
} = require('../dynamic/runTraceTelemetry');

describe('run trace privacy telemetry', () => {
  function createHarness(properties = {}) {
    let clock = 1000;
    const telemetry = {
      trackOperation: sinon.spy(),
      trackFailure: sinon.spy(),
    };
    const operation = createRunTraceTelemetry({
      telemetry,
      extensionVersion: '0.3.0',
      binaryFormat: 'unknown',
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
      binaryFormat: 'elf',
      payloadMode: 'pwntools',
      target: 'argv1',
      sourceProvided: true,
      ignoredSensitiveValue: '/home/alice/private/challenge.c:41414141',
    });

    harness.operation.start();
    harness.advance(6200);
    harness.operation.complete({
      terminationCategory: 'target_crash',
      cpuBucket: '1-5s',
      rssBucket: '64-256MiB',
    });

    expect(harness.telemetry.trackOperation.firstCall.args).to.deep.equal([
      'dynamic.run_trace.started',
      {
        extensionVersion: '0.3.0',
        binaryFormat: 'elf',
        arch: 'x64',
        payloadMode: 'pwntools',
        target: 'argv1',
        sourceProvided: true,
      },
    ]);
    expect(harness.telemetry.trackOperation.secondCall.args).to.deep.equal([
      'dynamic.run_trace.completed',
      {
        extensionVersion: '0.3.0',
        binaryFormat: 'elf',
        arch: 'x64',
        payloadMode: 'pwntools',
        durationBucket: '5-15s',
        terminationCategory: 'target_crash',
        cpuBucket: '1-5s',
        rssBucket: '64-256MiB',
      },
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
      extensionVersion: '0.3.0',
      binaryFormat: 'unknown',
      arch: 'x86',
      payloadMode: 'file',
      target: 'file',
      sourceProvided: false,
    });
    expect(harness.telemetry.trackFailure.firstCall.args).to.deep.equal([
      'dynamic.run_trace.failed',
      {
        extensionVersion: '0.3.0',
        binaryFormat: 'unknown',
        arch: 'x86',
        payloadMode: 'file',
        durationBucket: '<1s',
        errorCategory: 'unknown',
        cpuBucket: 'unavailable',
        rssBucket: 'unavailable',
      },
    ]);
  });

  it('emits cancellation as a bounded terminal event', () => {
    const harness = createHarness();
    harness.operation.start();
    expect(harness.operation.cancel()).to.equal(true);
    expect(harness.operation.complete()).to.equal(false);
    expect(harness.operation.fail('unknown')).to.equal(false);
    expect(harness.telemetry.trackFailure.callCount).to.equal(1);
    expect(harness.telemetry.trackOperation.callCount).to.equal(1);
    expect(harness.telemetry.trackFailure.firstCall.args[1].errorCategory).to.equal('cancelled');
    expect(harness.operation.getOutcome()).to.equal('cancelled');
  });

  it('buckets CPU time and peak RSS without retaining raw values', () => {
    expect(cpuBucket(-1)).to.equal('unavailable');
    expect(cpuBucket(99)).to.equal('<100ms');
    expect(cpuBucket(6200)).to.equal('5-15s');
    expect(rssBucket(null)).to.equal('unavailable');
    expect(rssBucket(Number.NaN)).to.equal('unavailable');
    expect(rssBucket(300 * 1024 * 1024)).to.equal('256-512MiB');
  });
});
