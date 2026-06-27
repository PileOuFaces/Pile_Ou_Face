const { expect } = require('chai');
const {
  buildFunctionRanges,
  buildTraceAddressEnrichment,
  detectDangerousLocalBufferHints,
  formatAddress,
  lookupRuntimeAddress
} = require('../src/dynamic/traceEnrichment');

describe('dynamic trace enrichment', () => {
  it('resolves an exact symbol address', () => {
    const result = lookupRuntimeAddress('0x401030', {
      symbols: [{ name: 'puts@plt', addr: '0x401030', type: 'T', size: 16 }]
    });

    expect(result).to.deep.include({
      rip: '0x401030',
      functionName: 'puts',
      functionOffset: 0,
      symbol: 'puts@plt'
    });
  });

  it('resolves an address inside a function range', () => {
    const trace = {
      analysisByStep: {
        '1': {
          function: {
            name: 'vuln',
            addr: '0x401160',
            range_start: '0x401160',
            range_end: '0x4011a0'
          }
        }
      }
    };
    const functionRanges = buildFunctionRanges(trace, []);
    const result = lookupRuntimeAddress(0x401184, { functionRanges });

    expect(result).to.deep.equal({
      rip: '0x401184',
      functionName: 'vuln',
      functionOffset: 0x24
    });
  });

  it('keeps unknown addresses stable without function metadata', () => {
    const result = lookupRuntimeAddress('0x500000', {
      symbols: [{ name: 'main', addr: '0x401000', type: 'T', size: 32 }]
    });

    expect(result).to.deep.equal({ rip: '0x500000' });
  });

  it('builds byStep enrichment from mixed snapshot address formats', () => {
    const trace = {
      snapshots: [
        { step: 1, rip: '401000' },
        { step: 2, registers: [{ name: 'rip', value: '0x401010' }] }
      ],
      analysisByStep: {
        '1': {
          function: { name: 'main', range_start: '0x401000', range_end: '0x401020' }
        }
      }
    };
    const enrichment = buildTraceAddressEnrichment(trace, {
      symbols: [{ name: 'main', addr: '0x401000', type: 'T', size: 0x20 }]
    });

    expect(enrichment.byStep['1']).to.include({ rip: '0x401000', functionName: 'main', functionOffset: 0 });
    expect(enrichment.byStep['2']).to.include({ rip: '0x401010', functionName: 'main', functionOffset: 0x10 });
    expect(formatAddress('401010')).to.equal('0x401010');
  });

  it('detects a local buffer passed to strcpy through rdi', () => {
    const trace = {
      snapshots: [{ step: 1, rip: '0x401184' }],
      meta: {
        disasm: [
          { addr: '0x401176', mnemonic: 'lea', operands: 'rax, [rbp - 0x20]' },
          { addr: '0x40117a', mnemonic: 'mov', operands: 'rdi, rax' },
          { addr: '0x401180', mnemonic: 'call', operands: 'strcpy@plt' }
        ]
      },
      analysisByStep: {
        '1': {
          function: { name: 'vuln', range_start: '0x401160', range_end: '0x4011a0' }
        }
      }
    };

    const hints = detectDangerousLocalBufferHints(trace, {
      functionRanges: buildFunctionRanges(trace, [])
    });
    expect(hints).to.have.lengthOf(1);
    expect(hints[0]).to.deep.include({
      kind: 'buffer',
      label: 'buffer',
      function: 'vuln',
      base: 'rbp',
      offset: -0x20,
      offsetLabel: 'rbp-0x20',
      call: 'strcpy',
      callAddress: '0x401180',
      source: 'static',
      confidence: 'high'
    });

    const enrichment = buildTraceAddressEnrichment(trace);
    expect(enrichment.byStep['1'].stackHints).to.deep.include(hints[0]);
  });

  it('detects a direct lea rdi destination for dangerous calls', () => {
    const trace = {
      snapshots: [{ step: 4, rip: '0x401090' }],
      meta: {
        disasm: [
          { addr: '0x401080', text: 'lea rdi, [rbp-0x30]' },
          { addr: '0x401085', text: 'call gets@plt' }
        ],
        functions: [{ name: 'read_name', addr: '0x401070', size: '0x40' }]
      }
    };

    const enrichment = buildTraceAddressEnrichment(trace);
    expect(enrichment.byStep['4'].stackHints).to.have.lengthOf(1);
    expect(enrichment.byStep['4'].stackHints[0]).to.include({
      kind: 'buffer',
      function: 'read_name',
      base: 'rbp',
      offset: -0x30,
      call: 'gets',
      source: 'static'
    });
  });

  it('PIE trace: rebased snapshot rip with ELF-relative meta.functions does not produce _fini functionName', () => {
    // Regression for login-leakage-hard: base=0x400000, main ELF offset 0x1d4d,
    // _fini ELF offset 0x1e58 (no size).  Snapshot rip is rebased (0x401d4d).
    // meta.functions contains PIE-relative addresses.
    // findFunctionRange must not return _fini for the rebased main address.
    const trace = {
      snapshots: [
        { step: 1, rip: '0x401d4d', func: 'main' },
        { step: 2, rip: '0x401d51', func: 'main' }
      ],
      meta: {
        functions: [
          { name: 'main',            addr: '0x1d4d', size: 141,  type: 'T' },
          { name: '__libc_csu_fini', addr: '0x1e50', size: 5,    type: 'T' },
          { name: '_fini',           addr: '0x1e58', size: null,  type: 'T' }
        ]
      },
      analysisByStep: {}
    };

    const enrichment = buildTraceAddressEnrichment(trace, { symbols: [] });

    // The enrichment may be empty (no function name resolved for rebased vs
    // PIE-relative mismatch), but must never assign _fini or libc_csu_fini.
    [1, 2].forEach((step) => {
      const entry = enrichment.byStep[String(step)] as any;
      if (entry && entry.functionName) {
        expect(entry.functionName).to.not.equal('fini');
        expect(entry.functionName).to.not.equal('_fini');
        expect(entry.functionName).to.not.include('libc_csu_fini');
      }
    });
  });
});
