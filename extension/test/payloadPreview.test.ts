const { expect } = require('chai');

const helper = require('../webview/shared/exploitHelper');
const preview = require('../webview/shared/payloadPreview');

describe('payload preview state', () => {
  it('formats a simple preview from the current payload source', () => {
    const resolved = helper.buildPayload('A*8', 'beginner', {
      arch: 'amd64',
      endian: 'little',
      targetMode: 'stdin',
    });

    const state = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: resolved.bytes,
      generatedPwntoolsSnippet: resolved.generatedSnippet,
      size: resolved.size,
      warnings: resolved.warnings,
      payloadExpr: resolved.payloadExpr,
    }, {
      fingerprint: preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', builderLevel: 'beginner', input: 'A*8' }),
    });

    expect(state.size).to.equal(8);
    expect(state.previewAsciiDisplay).to.equal('AAAAAAAA');
    expect(state.previewHexDisplay).to.equal('41 41 41 41 41 41 41 41');
    expect(state.generatedPwntoolsSnippet).to.contain('payload = b"A" * 8');
  });

  it('invalidates stale previews when the payload source changes', () => {
    const firstResolved = helper.buildPayload('cyclic(128)', 'advanced', {
      arch: 'amd64',
      endian: 'little',
      targetMode: 'stdin',
    });
    const secondResolved = helper.buildPayload('A*8', 'beginner', {
      arch: 'amd64',
      endian: 'little',
      targetMode: 'stdin',
    });
    const firstFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', builderLevel: 'advanced', input: 'cyclic(128)' });
    const secondFingerprint = preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', builderLevel: 'beginner', input: 'A*8' });

    const firstState = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: firstResolved.bytes,
      generatedPwntoolsSnippet: firstResolved.generatedSnippet,
      size: firstResolved.size,
    }, {
      fingerprint: firstFingerprint,
    });
    const secondState = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: secondResolved.bytes,
      generatedPwntoolsSnippet: secondResolved.generatedSnippet,
      size: secondResolved.size,
    }, {
      fingerprint: secondFingerprint,
    });

    expect(preview.isPreviewStateFresh(firstState, secondFingerprint)).to.equal(false);
    expect(secondState.previewAsciiDisplay).to.equal('AAAAAAAA');
    expect(secondState.previewHexDisplay).to.equal('41 41 41 41 41 41 41 41');
    expect(secondState.generatedPwntoolsSnippet).to.not.contain('cyclic(128)');
  });

  it('invalidates the preview when the mode changes', () => {
    const state = preview.buildResolvedPreviewState({
      target: 'stdin',
      resolvedPayloadBytes: [0x41, 0x41],
      generatedPwntoolsSnippet: 'payload = b"AA"',
      size: 2,
    }, {
      fingerprint: preview.buildPayloadPreviewFingerprint({ mode: 'payload_builder', builderLevel: 'beginner', input: 'AA' }),
    });

    const pythonFingerprint = preview.buildPayloadPreviewFingerprint({
      mode: 'payload_builder',
      builderLevel: 'advanced',
      input: 'b"A"*2',
    });

    expect(preview.isPreviewStateFresh(state, pythonFingerprint)).to.equal(false);
  });
});
