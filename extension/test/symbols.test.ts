const { expect } = require('chai');

const {
  findSymbolByCandidates,
  isMachOFormat,
  mainSymbolCandidates,
  normalizeStartSymbolForBinary,
  preferredMainSymbol,
  symbolLookupCandidates,
} = require('../src/shared/symbols');

describe('shared symbol helpers', () => {
  it('prefers plain C symbols for ELF even when the host is macOS', () => {
    const info = { format: 'ELF' };

    expect(preferredMainSymbol(info)).to.equal('main');
    expect(mainSymbolCandidates(info)).to.deep.equal(['main', '_main']);
    expect(normalizeStartSymbolForBinary('_main', info)).to.equal('main');
    expect(symbolLookupCandidates('_win', info)).to.deep.equal(['win', '_win']);
  });

  it('prefers underscored C symbols for Mach-O binaries only', () => {
    const info = { format: 'Mach-O' };

    expect(isMachOFormat(info)).to.equal(true);
    expect(preferredMainSymbol(info)).to.equal('_main');
    expect(mainSymbolCandidates(info)).to.deep.equal(['_main', 'main']);
    expect(normalizeStartSymbolForBinary('main', info)).to.equal('_main');
    expect(symbolLookupCandidates('win', info)).to.deep.equal(['_win', 'win']);
  });

  it('finds symbols using format-aware candidate order', () => {
    const symbols = [{ name: '_main' }, { name: 'main' }];

    expect(findSymbolByCandidates(symbols, mainSymbolCandidates({ format: 'ELF' }))).to.equal('main');
    expect(findSymbolByCandidates(symbols, mainSymbolCandidates({ format: 'Mach-O' }))).to.equal('_main');
  });
});
