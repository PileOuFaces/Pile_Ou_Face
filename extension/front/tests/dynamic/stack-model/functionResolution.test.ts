const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stack-model function resolution regressions', () => {
  let resolveModelForFunctionSelection: Function;
  let resolveModelForFunction: Function;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../dynamic/app/stackWorkspaceDebug.js');
    ({ resolveModelForFunctionSelection, resolveModelForFunction } = await import(pathToFileURL(modulePath).href));
  });

  it('stale-model-main-ids-never-resolve-for-challenge', () => {
    const model = {
      name: 'challenge',
      locals: [
        { id: 'main:rbp:buffer:-64:64:frame', offset: -64, name: 'buffer', role: 'buffer', size: 64 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge', 'challenge');

    expect(result.model).to.equal(null);
    expect(resolveModelForFunction(model, 'challenge', 'challenge')).to.equal(null);
    expect(result).to.include({
      requestedFunction: 'challenge',
      resolvedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('stale-model-win-ids-never-resolve-for-challenge', () => {
    const model = {
      name: 'challenge',
      locals: [
        { id: 'win:rbp:return_address:8:8:frame', offset: 8, name: 'return address', role: 'return_address', size: 8 }
      ]
    };

    const result = resolveModelForFunctionSelection(model, 'challenge()', 'challenge');

    expect(result.model).to.equal(null);
    expect(result.rejectedFunction).to.equal('win');
    expect(result.rejectedReason).to.equal('function_mismatch');
  });

  it('challenge-symbol-labels-normalize-to-one-function-identity', () => {
    const labels = ['challenge', 'challenge()', 'sym.challenge', 'challenge@0x1ec8', '<challenge>'];
    labels.forEach((label) => {
      const model = {
        name: label,
        locals: [
          { id: 'challenge:rbp:buffer:-448:440:frame', offset: -448, name: 'buffer', role: 'buffer', size: 440 }
        ]
      };

      const result = resolveModelForFunctionSelection(model, 'challenge()', 'main');

      expect(result.model, label).to.equal(model);
      expect(result.requestedFunction, label).to.equal('challenge');
      expect(result.resolvedFunction, label).to.equal('challenge');
      expect(result.rejectedReason, label).to.equal('');
    });
  });
});
