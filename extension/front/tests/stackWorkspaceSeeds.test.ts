/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stackWorkspaceSeeds::seedFromObservation — must not drop the backend Evidence verdict', () => {
  let mod: {
    seedFromObservation: (observation: any, bpAddress: bigint | null, opts?: any) => Record<string, any>;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceSeeds.js');
    mod = await import(pathToFileURL(modulePath).href);
  });

  it('propagates size_exact=false unchanged', () => {
    const seed = mod.seedFromObservation({ offset: -16, size: 40, size_exact: false }, 1000n, { synthetic: false });
    expect(seed.size_exact).to.equal(false);
  });

  it('propagates observed_write_size and estimated_bound unchanged', () => {
    const seed = mod.seedFromObservation({ offset: -16, size: 40, observed_write_size: 12, estimated_bound: 64 }, 1000n, { synthetic: false });
    expect(seed.observed_write_size).to.equal(12);
    expect(seed.estimated_bound).to.equal(64);
  });

  it('propagates classification and evidenceClassification unchanged', () => {
    const seed = mod.seedFromObservation({
      offset: -16,
      size: 40,
      classification: 'buffer',
      evidenceClassification: 'buffer_confirmed'
    }, 1000n, { synthetic: false });
    expect(seed.classification).to.equal('buffer');
    expect(seed.evidenceClassification).to.equal('buffer_confirmed');
  });

  it('propagates the same 5 fields unchanged for synthetic seeds too', () => {
    const seed = mod.seedFromObservation({
      offset: -16,
      size: 40,
      size_exact: true,
      observed_write_size: 8,
      estimated_bound: 32,
      classification: 'local',
      evidenceClassification: 'local_confirmed'
    }, 1000n, { synthetic: true });
    expect(seed.size_exact).to.equal(true);
    expect(seed.observed_write_size).to.equal(8);
    expect(seed.estimated_bound).to.equal(32);
    expect(seed.classification).to.equal('local');
    expect(seed.evidenceClassification).to.equal('local_confirmed');
  });

  it('an observation without any Evidence fields behaves exactly as before: undefined, no crash, kind/role/size untouched', () => {
    const seed = mod.seedFromObservation({ offset: -16, size: 40, kind: 'local', source: 'auto' }, 1000n, { synthetic: false, kindOverride: 'local' });
    expect(seed.size_exact).to.equal(undefined);
    expect(seed.observed_write_size).to.equal(undefined);
    expect(seed.estimated_bound).to.equal(undefined);
    expect(seed.classification).to.equal(undefined);
    expect(seed.evidenceClassification).to.equal(undefined);
    expect(seed.kind).to.equal('local');
    expect(seed.offset).to.equal(-16);
    expect(seed.size).to.equal(40);
  });
});
