/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stackWorkspaceClassification::classifyObservationSeedKind — must trust a reliable backend role', () => {
  let mod: {
    classifyObservationSeedKind: (observation: any, functionName: string, bpRegister: string, meta: any) => string;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceClassification.js');
    mod = await import(pathToFileURL(modulePath).href);
  });

  it('role/kind="buffer" with a generic label (local_54h, no "buf" in it) stays buffer, never local', () => {
    const observation = {
      role: 'buffer',
      kind: 'buffer',
      offset: -0x60,
      size: 84,
      size_exact: true,
      label: 'local_54h'
    };
    expect(mod.classifyObservationSeedKind(observation, 'main', 'rbp', { arch_bits: 64 })).to.equal('buffer');
  });

  it('no reliable backend role: the existing label-heuristic fallback still classifies a generic local_XXh label as local', () => {
    const observation = {
      kind: 'unknown',
      offset: -0x18,
      size: 4,
      label: 'local_18h'
    };
    expect(mod.classifyObservationSeedKind(observation, 'main', 'rbp', { arch_bits: 64 })).to.equal('local');
  });
});
