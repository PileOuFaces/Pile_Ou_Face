const { expect } = require('chai');

const generationSettings = require('../shared/aiGenerationSettings');

describe('AI generation settings', () => {
  it('normalizes supported generation values', () => {
    expect(generationSettings.normalize({
      temperature: '1.2',
      top_p: '0.75',
      max_tokens: '2048',
    })).to.deep.equal({
      temperature: 1.2,
      top_p: 0.75,
      max_tokens: 2048,
    });
  });

  it('clamps unsafe values', () => {
    expect(generationSettings.normalize({
      temperature: 9,
      top_p: 0,
      max_tokens: 999999,
    })).to.deep.equal({
      temperature: 2,
      top_p: 0.01,
      max_tokens: 131072,
    });
  });

  it('maps extension global settings to provider options', () => {
    expect(generationSettings.fromGlobalSettings({
      aiTemperature: 0.4,
      aiTopP: 0.8,
      aiMaxTokens: 1024,
    })).to.deep.equal({
      temperature: 0.4,
      top_p: 0.8,
      max_tokens: 1024,
    });
  });
});
