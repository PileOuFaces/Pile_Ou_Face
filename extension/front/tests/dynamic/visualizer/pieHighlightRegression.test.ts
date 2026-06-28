const { expect } = require('chai');
const fs = require('fs');
const path = require('path');

/**
 * Regression tests for PIE highlight correctness after the toDisasmAddress
 * fix in main.js.
 *
 * These tests verify that:
 * 1. A PIE runtime RIP (rebased) maps to the correct disasm instruction after
 *    ELF-relative normalization.
 * 2. Non-PIE addresses still resolve correctly.
 * 3. Current instruction highlight is non-null after stepping through a trace.
 * 4. No fallback highlight points to an unrelated lower address when the
 *    address is out of range (regression: nearestLower returned _fini).
 * 5. An address inside <challenge> highlights a challenge instruction, not
 *    _fini or __libc_csu_fini.
 */
describe('dynamic/visualizer PIE highlight regression', () => {
  let mod: {
    findDisasmEntryForAddress: (lines: unknown[], addr: unknown) => any;
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

  // Mirrors the ELF-relative disasm addresses of login-leakage-hard.
  function makePieDisasmLines() {
    return [
      // challenge body
      { addr: '0x1bb5', mnemonic: 'endbr64',  operands: '',           line: 50 },
      { addr: '0x1bb9', mnemonic: 'push',      operands: 'rbp',        line: 51 },
      { addr: '0x1bba', mnemonic: 'mov',        operands: 'rbp, rsp',  line: 52 },
      { addr: '0x1c00', mnemonic: 'call',       operands: '0x1100',    line: 60 },
      // main body
      { addr: '0x1d4d', mnemonic: 'endbr64',   operands: '',           line: 100 },
      { addr: '0x1d51', mnemonic: 'push',       operands: 'rbp',        line: 101 },
      { addr: '0x1d52', mnemonic: 'mov',        operands: 'rbp, rsp',  line: 102 },
      { addr: '0x1d92', mnemonic: 'call',       operands: '0x1bb5',    line: 110 },
      // __libc_csu_fini / _fini area
      { addr: '0x1e50', mnemonic: 'endbr64',   operands: '',           line: 200 },
      { addr: '0x1e54', mnemonic: 'ret',        operands: '',           line: 201 },
    ];
  }

  // Mirrors a non-PIE binary: disasm addresses are absolute (matching snapshot RIP).
  function makeNoPieDisasmLines() {
    return [
      { addr: '0x401d4d', mnemonic: 'endbr64', operands: '',          line: 100 },
      { addr: '0x401d51', mnemonic: 'push',    operands: 'rbp',       line: 101 },
      { addr: '0x401d52', mnemonic: 'mov',     operands: 'rbp, rsp',  line: 102 },
    ];
  }

  // Mirrors toDisasmAddress logic in main.js: subtract base when PIE.
  function normalize(runtimeAddr: string, base: string): string {
    const b = parseInt(base, 16);
    if (!b) return runtimeAddr;
    const a = parseInt(runtimeAddr, 16);
    if (isNaN(a)) return runtimeAddr;
    const rel = a - b;
    if (rel < 0) return runtimeAddr;
    return `0x${rel.toString(16)}`;
  }

  // 1. PIE runtime RIP maps to correct disasm instruction after normalization.
  it('1. PIE runtime RIP normalized to ELF-relative finds correct disasm entry', () => {
    const lines = makePieDisasmLines();
    const base = '0x400000';
    const rip = '0x401d4d'; // main rebased

    const elfRelative = normalize(rip, base); // → '0x1d4d'
    expect(elfRelative).to.equal('0x1d4d');

    const result = mod.findDisasmEntryForAddress(lines, elfRelative);
    expect(result, 'must find an entry for normalized address').to.not.equal(null);
    expect(result.exact).to.equal(true);
    expect(result.entry.mnemonic).to.equal('endbr64');
    expect(result.entry.line).to.equal(100);
  });

  // 2. Non-PIE binary: absolute RIP matches absolute disasm address directly.
  it('2. non-PIE absolute RIP highlights the correct disasm instruction', () => {
    const lines = makeNoPieDisasmLines();
    // No base subtraction needed (base=0 or absent).
    const rip = '0x401d4d';

    const result = mod.findDisasmEntryForAddress(lines, rip);
    expect(result, 'must find exact match for non-PIE absolute address').to.not.equal(null);
    expect(result.exact).to.equal(true);
    expect(result.entry.mnemonic).to.equal('endbr64');
  });

  // 3. Current instruction highlight is non-null for every step of a PIE trace.
  it('3. highlight is non-null for all steps after PIE normalization', () => {
    const lines = makePieDisasmLines();
    const base = '0x400000';
    const stepRips = [
      '0x401d4d', // main+0
      '0x401d51', // main+4
      '0x401d52', // main+5
      '0x401d92', // main+0x45
    ];

    stepRips.forEach((rip) => {
      const elfRelative = normalize(rip, base);
      const lineNum = mod.resolveActiveDisasmFileLine(lines, elfRelative);
      expect(lineNum, `step RIP ${rip} → ${elfRelative} must produce a non-null line`).to.not.equal(null);
      expect(lineNum).to.be.greaterThan(0);
    });
  });

  // 4. Without normalization, rebased RIP does NOT fall back to a lower unrelated address.
  //    (Tests that the nearestLower guard prevents _fini contamination.)
  it('4. rebased RIP without normalization returns null, not a lower unrelated line', () => {
    const lines = makePieDisasmLines();
    // Raw rebased address — no normalization.  Should return null, never the
    // ret line at 0x1e54 (line 201, inside __libc_csu_fini).
    const result = mod.findDisasmEntryForAddress(lines, '0x401d4d');
    expect(result, 'un-normalized PIE address must return null').to.equal(null);
  });

  // 5. Normalized challenge address highlights a challenge instruction, not _fini.
  it('5. challenge address normalizes to challenge disasm, not _fini/libc_csu_fini', () => {
    const lines = makePieDisasmLines();
    const base = '0x400000';
    const challengeRips = [
      '0x401bb5', // challenge+0
      '0x401bb9', // challenge+4
      '0x401c00', // challenge body (call)
    ];

    challengeRips.forEach((rip) => {
      const elfRelative = normalize(rip, base);
      const result = mod.findDisasmEntryForAddress(lines, elfRelative);
      expect(result, `${rip} → ${elfRelative} must find a challenge entry`).to.not.equal(null);
      // Must not land on _fini / __libc_csu_fini area (lines 200-201).
      const lineNum = Number(result.entry?.line);
      expect(lineNum, `challenge address must not resolve to fini area (line ${lineNum})`).to.be.lessThan(200);
    });
  });
});
