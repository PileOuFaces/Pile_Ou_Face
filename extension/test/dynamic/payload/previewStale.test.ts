const { expect } = require('chai');

const preview = require('../../../webview/shared/payloadPreview');
const payloadFixture = require('../fixtures/payloads/payload-builder-aa.json');
const fileFixture = require('../fixtures/payloads/file-mode-argv1.json');

describe('dynamic/payload preview invariants', () => {
  it('preview-bytes-and-run-bytes-match-for-payload-builder', () => {
    const bytes = [0x41, 0x41, 0x41, 0x41];
    const fingerprint = preview.buildPayloadPreviewFingerprint({
      mode: payloadFixture.mode,
      targetMode: payloadFixture.targetMode,
      input: payloadFixture.payloadExpr
    });

    const state = preview.buildResolvedPreviewState({
      mode: payloadFixture.mode,
      target: payloadFixture.target,
      resolvedPayloadBytes: bytes,
      size: payloadFixture.size,
      payloadExpr: payloadFixture.payloadExpr,
      inputConfig: payloadFixture
    }, { fingerprint });

    expect(state.previewHexDisplay).to.equal(payloadFixture.previewHex);
    expect(state.previewAsciiDisplay).to.equal(payloadFixture.previewAscii);
    expect(state.inputConfig.payloadBytesHex).to.equal('41414141');
    expect(state.resolvedPayloadBytes.map((byte: number) => byte.toString(16).padStart(2, '0')).join('')).to.equal(state.inputConfig.payloadBytesHex);
  });

  it('stale-preview-cannot-be-considered-fresh-after-source-change', () => {
    const oldFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', input: 'A*4' });
    const newFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', input: 'B*4' });
    const state = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: [0x41, 0x41, 0x41, 0x41],
      size: 4
    }, { fingerprint: oldFingerprint });

    expect(preview.isPreviewStateFresh(state, newFingerprint)).to.equal(false);
    expect(preview.isPreviewStateFresh(preview.createStalePreviewState({ fingerprint: oldFingerprint }), oldFingerprint)).to.equal(false);
  });

  it('switching-payload-tabs-invalidates-preview-fingerprint', () => {
    const builderFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', input: 'A*4' });
    const fileFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'file', guestPath: '/tmp/pof-input.txt' });
    const state = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: [0x41, 0x41, 0x41, 0x41],
      size: 4
    }, { fingerprint: builderFingerprint });

    expect(preview.isPreviewStateFresh(state, fileFingerprint)).to.equal(false);
  });

  it('file-mode-argv1-is-path-not-file-content', () => {
    expect(fileFixture.mode).to.equal('file');
    expect(fileFixture.file.passAs).to.equal('argv1');
    expect(fileFixture.file.guestPath).to.equal('/tmp/pof-input.txt');
    expect(fileFixture.file.guestPath).to.not.equal(fileFixture.inlineContent);
  });
});
