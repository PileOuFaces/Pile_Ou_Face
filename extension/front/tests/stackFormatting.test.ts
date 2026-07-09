/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stack stackFormatting — Evidence fields must survive, never be lost', () => {
  let mod: {
    buildSemanticStackItems: (analysis: unknown) => Record<string, any>[];
    buildSimpleSourceItems: (sorted: unknown[], context: Record<string, any>) => Record<string, any>[];
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stack/stackFormatting.js');
    mod = await import(pathToFileURL(modulePath).href);
  });

  function minimalContext(overrides: Record<string, unknown> = {}) {
    return {
      options: {},
      rsp: null,
      rbp: null,
      retAddrAddr: null,
      bufferStart: null,
      bufferEnd: null,
      analysisStackRoles: {},
      modelRegions: [],
      diagnostics: [],
      payloadText: '',
      payloadHex: '',
      spName: 'RSP',
      bpName: 'RBP',
      ...overrides
    };
  }

  it('propagates size_exact=false from a backend-shaped item unchanged', () => {
    const [item] = mod.buildSemanticStackItems({
      frame: { slots: [{ offsetFromBp: -0x10, size: 40, size_exact: false, role: 'buffer' }] }
    });
    const [result] = mod.buildSimpleSourceItems([item], minimalContext());
    expect(result.size_exact).to.equal(false);
  });

  it('propagates observed_write_size unchanged', () => {
    const [item] = mod.buildSemanticStackItems({
      frame: { slots: [{ offsetFromBp: -0x10, size: 40, observed_write_size: 12, role: 'buffer' }] }
    });
    const [result] = mod.buildSimpleSourceItems([item], minimalContext());
    expect(result.observed_write_size).to.equal(12);
  });

  it('propagates estimated_bound unchanged', () => {
    const [item] = mod.buildSemanticStackItems({
      frame: { slots: [{ offsetFromBp: -0x10, size: 40, estimated_bound: 64, role: 'buffer' }] }
    });
    const [result] = mod.buildSimpleSourceItems([item], minimalContext());
    expect(result.estimated_bound).to.equal(64);
  });

  it('propagates classification and evidenceClassification unchanged', () => {
    const [item] = mod.buildSemanticStackItems({
      frame: { slots: [{
        offsetFromBp: -0x10,
        size: 40,
        role: 'buffer',
        classification: 'buffer',
        evidenceClassification: 'buffer_confirmed'
      }] }
    });
    const [result] = mod.buildSimpleSourceItems([item], minimalContext());
    expect(result.classification).to.equal('buffer');
    expect(result.evidenceClassification).to.equal('buffer_confirmed');
  });

  it('legacy items without any Evidence fields still work (no crash, fields stay undefined)', () => {
    const legacyItem = {
      addr: null,
      pos: 0,
      size: 8,
      label: 'saved_ebp',
      role: 'saved_bp',
      kind: 'saved_bp',
      value: '0x1000',
      flags: []
    };
    const [result] = mod.buildSimpleSourceItems([legacyItem], minimalContext());
    expect(result).to.exist;
    expect(result.visualRole).to.equal('control');
    expect(result.size_exact).to.equal(undefined);
    expect(result.observed_write_size).to.equal(undefined);
    expect(result.estimated_bound).to.equal(undefined);
    expect(result.classification).to.equal(undefined);
    expect(result.evidenceClassification).to.equal(undefined);
  });
});
