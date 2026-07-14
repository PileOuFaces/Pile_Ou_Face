/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stackWorkspaceAnchoring — a reliable backend size must never be overwritten by a recovered runtime extent', () => {
  let anchoringMod: {
    recoveredCandidateFromRange: (args: unknown) => Record<string, unknown> | null;
    applyRecoveredExtentToSeed: (seed: any, recovered: any, observations: unknown[], wordSize: number) => void;
  };
  let seedsMod: {
    seedFromObservation: (observation: any, bpAddress: bigint | null, opts?: any) => Record<string, any>;
    normalizeSeed: (seed: any) => Record<string, any> | null;
  };

  before(async () => {
    const anchoringPath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceAnchoring.js');
    anchoringMod = await import(pathToFileURL(anchoringPath).href);
    const seedsPath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceSeeds.js');
    seedsMod = await import(pathToFileURL(seedsPath).href);
  });

  it('char buffer[84] (size_exact=true): a 4-byte recovered write span (strcpy("aaa")) never shrinks it', () => {
    const seed: any = {
      offset: -0x60, size: 84, kind: 'buffer', role: 'buffer',
      size_exact: true, confidence: 0.98, start: 1000n - 0x60n
    };
    const recovered = anchoringMod.recoveredCandidateFromRange({
      start: 1000n - 0x60n, size: 4, bpValue: 1000n, externalSymbol: 'strcpy'
    });

    anchoringMod.applyRecoveredExtentToSeed(seed, recovered, [], 8);

    expect(seed.size).to.equal(84);
    expect(seed.kind).to.equal('buffer');
  });

  it('end-to-end: observation carries size_exact=true through seedFromObservation/normalizeSeed, then blocks the recovered override', () => {
    const bpAddress = 1000n;
    const observation = { offset: -0x60, size: 84, role: 'buffer', kind: 'buffer', size_exact: true, source: 'trace' };
    const rawSeed = seedsMod.seedFromObservation(observation, bpAddress, { synthetic: false });
    const seed = seedsMod.normalizeSeed(rawSeed);

    expect(seed?.size_exact).to.equal(true);

    const recovered = anchoringMod.recoveredCandidateFromRange({
      start: bpAddress - 0x60n, size: 4, bpValue: bpAddress, externalSymbol: 'strcpy'
    });
    anchoringMod.applyRecoveredExtentToSeed(seed, recovered, [], 8);

    expect(seed?.size).to.equal(84);
  });

  it('a heuristic buffer (size_exact=false, no reliable role) is still recoverable from a runtime write -- unchanged prior behavior', () => {
    const seed: any = { offset: -40, size: 4, kind: 'unknown', start: 960n };
    const recovered = anchoringMod.recoveredCandidateFromRange({
      start: 960n, size: 32, bpValue: 1000n, externalSymbol: 'strcpy'
    });

    anchoringMod.applyRecoveredExtentToSeed(seed, recovered, [], 8);

    expect(seed.kind).to.equal('buffer');
    expect(seed.size).to.equal(32);
  });

  it('a backend-confirmed local (role=local) is never promoted to buffer by a recovered write span', () => {
    const seed: any = { offset: -40, size: 4, kind: 'local', role: 'local', start: 960n };
    const recovered = anchoringMod.recoveredCandidateFromRange({
      start: 960n, size: 10, bpValue: 1000n, externalSymbol: 'strcpy'
    });

    anchoringMod.applyRecoveredExtentToSeed(seed, recovered, [], 8);

    expect(seed.kind).to.equal('local');
  });

  it('a recovered candidate never claims confidence=1 or source=derived (js_fallback, 0.5)', () => {
    const recovered = anchoringMod.recoveredCandidateFromRange({
      start: 904n, size: 44, bpValue: 1000n, externalSymbol: 'strcpy'
    });

    expect(recovered?.source).to.equal('js_fallback');
    expect(recovered?.confidence).to.equal(0.5);
  });
});
