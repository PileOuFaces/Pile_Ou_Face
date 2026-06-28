const { expect } = require('chai');

const preview = require('../../../shared/payloadPreview');
const payloadFixture = require('../fixtures/payloads/payload-builder-aa.json');

describe('dynamic/workflows payload preview to run trace', () => {
  it('run-trace-config-uses-the-same-bytes-as-ready-preview', () => {
    const fingerprint = preview.buildPayloadPreviewFingerprint({
      mode: payloadFixture.mode,
      input: payloadFixture.payloadExpr,
      targetMode: payloadFixture.targetMode
    });
    const previewState = preview.buildResolvedPreviewState({
      mode: payloadFixture.mode,
      target: payloadFixture.target,
      resolvedPayloadBytes: [0x41, 0x41, 0x41, 0x41],
      size: 4,
      payloadExpr: payloadFixture.payloadExpr,
      inputConfig: payloadFixture
    }, { fingerprint });

    const runTraceConfig = {
      injectPayload: true,
      payloadExpr: previewState.payloadExpr,
      payloadTargetMode: payloadFixture.targetMode,
      input: previewState.inputConfig
    };

    expect(preview.isPreviewStateFresh(previewState, fingerprint)).to.equal(true);
    expect(runTraceConfig.input.payloadBytesHex).to.equal('41414141');
    expect(previewState.resolvedPayloadBytes).to.deep.equal([0x41, 0x41, 0x41, 0x41]);
  });

  it('stale-preview-is-not-fresh-for-run-trace-after-tab-switch', () => {
    const oldFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', input: 'A*4' });
    const nextFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'pwntools_script', selectedCaptureKind: 'sendline' });
    const previewState = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: [0x41, 0x41, 0x41, 0x41],
      inputConfig: payloadFixture
    }, { fingerprint: oldFingerprint });

    expect(preview.isPreviewStateFresh(previewState, nextFingerprint)).to.equal(false);
  });
});
