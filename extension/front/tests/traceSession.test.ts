/* global describe, it, before, __dirname */
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

describe('dynamic trace session helpers', () => {
  let helpers;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/traceSession.js');
    const source = fs.readFileSync(modulePath, 'utf8');
    const dataUrl = `data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`;
    helpers = await import(dataUrl);
  });

  function createStorage(initial = {}) {
    const values = new Map(Object.entries(initial));
    return {
      getItem: (key) => values.get(key) ?? null,
      setItem: (key, value) => values.set(key, String(value)),
      values
    };
  }

  it('resolves explicit run ids and stable fallback ids', () => {
    expect(helpers.resolveTraceId({ traceRunId: 7, snapshots: [] })).to.equal('run:7');
    expect(helpers.resolveTraceId({ traceRunId: 7, meta: { trace_run_id: 8 }, snapshots: [] })).to.equal('run:8');

    const first = helpers.resolveTraceId({
      snapshots: [{ step: 1, rip: '0x401000' }, { step: 2, rip: '0x401004' }],
      meta: { disasm_path: '/tmp/a.asm' }
    });
    const second = helpers.resolveTraceId({
      meta: { disasm_path: '/tmp/a.asm' },
      snapshots: [{ rip: '0x401000', step: 1 }, { rip: '0x401004', step: 2 }]
    });

    expect(first).to.equal(second);
    expect(first).to.match(/^trace:/);
  });

  it('resets on a new trace and restores the last viewed step for the same trace', () => {
    const previousKey = 'previous-trace';
    const stepKey = 'steps';
    const storage = createStorage();

    expect(helpers.chooseInitialStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    })).to.equal(1);

    helpers.persistViewedStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      step: 20
    });

    expect(helpers.chooseInitialStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    })).to.equal(20);

    expect(helpers.chooseInitialStep({
      storage,
      traceId: 'run:2',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    })).to.equal(1);
  });

  it('keeps step 20 when the same runId is re-initialized', () => {
    const previousKey = 'previous-trace';
    const stepKey = 'steps';
    const storage = createStorage();

    helpers.persistViewedStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      step: 20
    });

    const step = helpers.chooseInitStepForTrace({
      storage,
      incomingTraceId: 'run:1',
      currentTraceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    });

    expect(step).to.equal(20);
  });

  it('resets to step 1 when a new runId arrives after step 20', () => {
    const previousKey = 'previous-trace';
    const stepKey = 'steps';
    const storage = createStorage();

    helpers.persistViewedStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      step: 20
    });
    helpers.persistViewedStep({
      storage,
      traceId: 'run:2',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      step: 33
    });

    const step = helpers.chooseInitStepForTrace({
      storage,
      incomingTraceId: 'run:2',
      currentTraceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    });

    expect(step).to.equal(1);
    expect(helpers.readStepStore(storage, stepKey)).to.not.have.property('run:2');
  });

  it('does not reset on page reveal without a new runId', () => {
    const previousKey = 'previous-trace';
    const stepKey = 'steps';
    const storage = createStorage();

    helpers.persistViewedStep({
      storage,
      traceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      step: 20
    });

    const step = helpers.chooseInitStepForTrace({
      storage,
      incomingTraceId: 'run:1',
      currentTraceId: 'run:1',
      previousTraceIdKey: previousKey,
      stepStoreKey: stepKey,
      snapshotCount: 80
    });

    expect(step).to.equal(20);
  });
});
