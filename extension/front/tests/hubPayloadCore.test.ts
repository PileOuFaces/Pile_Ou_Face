const { expect } = require('chai');

const payloadCore = require('../webview/hub/payloadCore');

describe('hub payload core helpers', () => {
  it('keeps payload preview sizing deterministic for simple expressions', () => {
    expect(payloadCore.parsePayloadExpressionPreview('A*8')).to.deep.equal({
      bytes: 8,
      preview: 'AAAAAAAA'
    });
    expect(payloadCore.parsePayloadExpressionPreview('\\x41\\x42 + C*2')).to.deep.equal({
      bytes: 4,
      preview: '\\x41\\x42CC'
    });
  });

  it('normalizes target and mode aliases without touching public labels', () => {
    expect(payloadCore.normalizePayloadTargetMode('stdin')).to.equal('stdin');
    expect(payloadCore.normalizePayloadTargetMode('bad')).to.equal('auto');
    expect(payloadCore.payloadTargetLabel('both')).to.equal('stdin + argv[1]');
    expect(payloadCore.normalizePayloadMode('python')).to.equal('payload_builder');
    expect(payloadCore.normalizePayloadBuilderLevel('ADVANCED')).to.equal('advanced');
  });

  it('normalizes pwntools capture bytes from hex, arrays, and raw strings', () => {
    expect(payloadCore.normalizeCaptureHex({ hex: '41 42 43 0a' })).to.equal('4142430a');
    expect(payloadCore.normalizeCaptureHex({ data: [0x41, 0x42, 0x43] })).to.equal('414243');
    expect(payloadCore.normalizeCaptureHex({ data: 'ABC' })).to.equal('414243');
    expect(payloadCore.hexHasNullByte('41420043')).to.equal(true);
  });

  it('preserves source C hint text and endian guidance used by the hub', () => {
    expect(payloadCore.buildSourceHintText({
      sourcePath: 'demo.c',
      sourceEnrichmentEnabled: true
    })).to.equal('Code source détecté — analyse enrichie activée.');

    const hint = payloadCore.buildPayloadEndianHint('\\x64\\xFF\\xF1\\xBF');
    expect(hint).to.contain('0xbff1ff64');
    expect(hint).to.contain('\\xBF\\xF1\\xFF\\x64');
  });
});
