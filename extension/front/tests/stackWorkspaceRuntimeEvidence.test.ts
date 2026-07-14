/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stackWorkspaceRuntimeEvidence — must not drop the backend Evidence verdict', () => {
  let mod: {
    buildRuntimeObservations: (slots: unknown[], bpAddress: bigint | null) => Record<string, any>[];
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceRuntimeEvidence.js');
    mod = await import(pathToFileURL(modulePath).href);
  });

  it('propagates size_exact=false unchanged', () => {
    const [observation] = mod.buildRuntimeObservations([
      { offsetFromBp: -0x10, size: 40, size_exact: false, role: 'buffer' }
    ], 1000n);
    expect(observation.size_exact).to.equal(false);
  });

  it('propagates observed_write_size unchanged', () => {
    const [observation] = mod.buildRuntimeObservations([
      { offsetFromBp: -0x10, size: 40, observed_write_size: 12 }
    ], 1000n);
    expect(observation.observed_write_size).to.equal(12);
  });

  it('propagates estimated_bound unchanged', () => {
    const [observation] = mod.buildRuntimeObservations([
      { offsetFromBp: -0x10, size: 40, estimated_bound: 64 }
    ], 1000n);
    expect(observation.estimated_bound).to.equal(64);
  });

  it('propagates classification and evidenceClassification unchanged', () => {
    const [observation] = mod.buildRuntimeObservations([
      { offsetFromBp: -0x10, size: 40, classification: 'buffer', evidenceClassification: 'buffer_confirmed' }
    ], 1000n);
    expect(observation.classification).to.equal('buffer');
    expect(observation.evidenceClassification).to.equal('buffer_confirmed');
  });

  it('legacy slots without any Evidence fields still work (no crash, fields stay undefined)', () => {
    const [observation] = mod.buildRuntimeObservations([
      { offsetFromBp: -4, size: 8, technicalLabel: 'saved_ebp' }
    ], 1000n);
    expect(observation).to.exist;
    expect(observation.size_exact).to.equal(undefined);
    expect(observation.observed_write_size).to.equal(undefined);
    expect(observation.estimated_bound).to.equal(undefined);
    expect(observation.classification).to.equal(undefined);
    expect(observation.evidenceClassification).to.equal(undefined);
  });
});
