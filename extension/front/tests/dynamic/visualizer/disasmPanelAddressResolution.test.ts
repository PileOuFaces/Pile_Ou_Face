const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

/**
 * Regression tests for PIE rebase address mismatch in disasmPanel.js.
 *
 * login-leakage-hard: disasm addresses are ELF-relative (max ~0x1e54),
 * but snapshot RIP values are rebased (0x401d4d with base 0x400000).
 * Before the fix, findDisasmEntryForAddress returned the last disasm entry
 * (inside __libc_csu_fini, addr 0x1e54) as nearestLower for any rebased
 * address, causing the disasm panel to highlight the wrong instruction.
 */
describe('dynamic/visualizer disasmPanel address resolution', () => {
  let mod: {
    findDisasmEntryForAddress: (lines: unknown[], addr: unknown) => unknown;
    resolveActiveDisasmFileLine: (lines: unknown[], addr: unknown) => number | null;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../dynamic/app/disasmPanel.js');
    let source = fs.readFileSync(modulePath, 'utf8');
    source = source.replace(
      /^import \{ dom \}.*$/m,
      'const dom = {};'
    );
    source = source.replace(
      /^import \{ diagnosticKindLabel.*\}.*$/m,
      'const diagnosticKindLabel = () => ""; const diagnosticMatchesAddress = () => false; const primaryDiagnostic = () => null;'
    );
    mod = await import(`data:text/javascript;base64,${Buffer.from(source, 'utf8').toString('base64')}`);
  });

  // Disasm lines mimicking login-leakage-hard ELF-relative addresses.
  // main starts at 0x1d4d, __libc_csu_fini at 0x1e50.
  function makeDisasmLines() {
    return [
      { addr: '0x1d4d', mnemonic: 'endbr64', operands: '', line: 1 },
      { addr: '0x1d51', mnemonic: 'push',    operands: 'rbp',    line: 2 },
      { addr: '0x1d52', mnemonic: 'mov',     operands: 'rbp, rsp', line: 3 },
      { addr: '0x1d92', mnemonic: 'call',    operands: '0x401190', line: 15 },
      { addr: '0x1e50', mnemonic: 'endbr64', operands: '', line: 100 },
      { addr: '0x1e54', mnemonic: 'ret',     operands: '', line: 101 },
    ];
  }

  it('exact match on ELF-relative address returns correct entry', () => {
    const lines = makeDisasmLines();
    const result = mod.findDisasmEntryForAddress(lines, '0x1d4d') as any;
    expect(result).to.not.equal(null);
    expect(result.exact).to.equal(true);
    expect(result.entry.mnemonic).to.equal('endbr64');
  });

  it('rebased address far outside disasm range returns null, not last disasm entry', () => {
    // 0x401d4d = base 0x400000 + main_offset 0x1d4d.
    // All disasm entries are ELF-relative (max 0x1e54), so 0x401d4d is ~4 MB away.
    // Before the fix this returned the last entry (ret inside __libc_csu_fini).
    const lines = makeDisasmLines();
    const result = mod.findDisasmEntryForAddress(lines, '0x401d4d');
    expect(result, 'rebased address should return null, not a wrong nearestLower').to.equal(null);
  });

  it('resolveActiveDisasmFileLine returns null for rebased address, not a libc_csu_fini line', () => {
    const lines = makeDisasmLines();
    const line = mod.resolveActiveDisasmFileLine(lines, '0x401d92');
    // Before the fix this would return 101 (the ret line inside __libc_csu_fini).
    expect(line, 'should be null, not 101 (libc_csu_fini ret line)').to.equal(null);
  });

  it('nearestLower still works for gaps within the disasm range', () => {
    // An address inside a function body that falls between labelled instructions.
    // 0x1d60 is between 0x1d52 and 0x1d92 — a legitimate nearestLower case.
    const lines = makeDisasmLines();
    const result = mod.findDisasmEntryForAddress(lines, '0x1d60') as any;
    expect(result).to.not.equal(null);
    expect(result.exact).to.equal(false);
    expect(result.entry.mnemonic).to.equal('mov'); // nearest lower is 0x1d52
  });

  it('large rebased address with PIE base 0x555555400000 returns null', () => {
    // Some PIE loaders use randomized base like 0x555555400000.
    const lines = makeDisasmLines();
    const result = mod.findDisasmEntryForAddress(lines, '0x555555401d4d');
    expect(result).to.equal(null);
  });
});
