const { expect } = require('chai');
const { buildFunctionModel } = require('../dynamic/pedagogy');

function traceWithBackendSlot(slot, disasmEntries = [], metaOverrides = {}) {
  return {
    snapshots: [{ step: 1, func: 'main', instr: '', effects: {} }],
    meta: {
      view_mode: 'dynamic',
      start_symbol: 'main',
      word_size: 8,
      disasm: disasmEntries,
      ...metaOverrides
    },
    analysisByStep: {
      '1': {
        function: { name: 'main', addr: '0x401000', range_start: '0x401000', range_end: '0x401100' },
        frame: { slots: [slot] }
      }
    }
  };
}

describe('dynamic/pedagogy — must never contradict the backend Evidence Model', () => {
  it('a backend local named "buffer" stays local even when a lea matches its offset', () => {
    const trace = traceWithBackendSlot(
      { label: 'buffer', role: 'local', size: 8, offsetFromBp: -0x20, confidence: 0.7, source: 'auto' },
      [{ addr: '0x401000', mnemonic: 'lea', operands: 'rax, [rbp - 0x20]' }]
    );

    const model = buildFunctionModel(trace, 'main');
    const local = model.locals.find((entry) => entry.offset === -0x20);

    expect(local.role).to.equal('local');
    expect(local.size).to.equal(8);
    expect(local.confidence).to.equal(0.7);
  });

  it('a backend buffer is never resized or rescored by a competing disassembly guess', () => {
    const trace = traceWithBackendSlot(
      { label: 'local_buf_40h', role: 'buffer', size: 64, offsetFromBp: -0x40, confidence: 0.6, source: 'dynamic' },
      [{ addr: '0x401000', mnemonic: 'lea', operands: 'rax, [rbp - 0x40]' }],
      { buffer_offset: -0x40, buffer_size: 128 }
    );

    const model = buildFunctionModel(trace, 'main');
    const local = model.locals.find((entry) => entry.offset === -0x40);

    expect(local.role).to.equal('buffer');
    expect(local.size).to.equal(64);
    expect(local.confidence).to.equal(0.6);
  });

  it('a CTF sentinel pattern can still create a pedagogical fallback when the backend has no role there', () => {
    const trace = traceWithBackendSlot(
      { label: 'unrelated', role: 'unknown', size: 4, offsetFromBp: -0x8, confidence: 0.7, source: 'auto' },
      [{ addr: '0x401000', mnemonic: 'cmp', operands: 'dword ptr [rbp - 0x4], 0x43434343' }]
    );

    const model = buildFunctionModel(trace, 'main');
    const fallback = model.locals.find((entry) => entry.offset === -0x4);

    expect(fallback).to.exist;
    expect(fallback.source).to.equal('pedagogy_fallback');
    expect(fallback.confidence).to.be.at.most(0.5);
  });

  it('a backend size_exact=false is passed through and never turned into an exact size', () => {
    const trace = traceWithBackendSlot({
      label: 'local_buf_unknown',
      role: 'buffer',
      size: 48,
      size_exact: false,
      offsetFromBp: -0x30,
      confidence: 0.5,
      source: 'dynamic'
    });

    const model = buildFunctionModel(trace, 'main');
    const local = model.locals.find((entry) => entry.offset === -0x30);

    expect(local.sizeExact).to.equal(false);
    expect(local.size).to.equal(48);
  });

  it('a low backend confidence is never boosted by a competing pattern at the same offset', () => {
    const trace = traceWithBackendSlot(
      { label: 'var_10', role: 'local', size: 4, offsetFromBp: -0x10, confidence: 0.2, source: 'auto' },
      [{ addr: '0x401000', mnemonic: 'cmp', operands: 'dword ptr [rbp - 0x10], 0x1000' }]
    );

    const model = buildFunctionModel(trace, 'main');
    const local = model.locals.find((entry) => entry.offset === -0x10);

    expect(local.confidence).to.equal(0.2);
  });
});
