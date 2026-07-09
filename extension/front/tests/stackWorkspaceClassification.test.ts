/* global describe, it, before, __dirname */
const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

describe('dynamic/stackWorkspaceClassification::classifyObservationSeedKind — must trust a reliable backend role', () => {
  let mod: {
    classifyObservationSeedKind: (observation: any, functionName: string, bpRegister: string, meta: any) => string;
  };
  let stackModelMod: {
    buildStackWorkspaceModel: (args: unknown) => any;
  };
  let formattingMod: {
    buildSemanticStackItems: (analysis: unknown) => any[];
    buildSimpleSourceItems: (sorted: unknown[], context: Record<string, any>) => any[];
    compareStackItemsByAddrDesc: (a: unknown, b: unknown, rsp: bigint | null) => number;
  };

  before(async () => {
    const modulePath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceClassification.js');
    mod = await import(pathToFileURL(modulePath).href);
    const stackModelPath = path.resolve(__dirname, '../dynamic/app/stackWorkspaceModel.js');
    stackModelMod = await import(pathToFileURL(stackModelPath).href);
    const formattingPath = path.resolve(__dirname, '../dynamic/app/stack/stackFormatting.js');
    formattingMod = await import(pathToFileURL(formattingPath).href);
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

  it('end-to-end: an Evidence buffer region (short observed write, no exact size) renders as buffer, not local_1', () => {
    const rbp = 0x1000n;
    const analysis = {
      function: { name: 'main' },
      frame: {
        slots: [
          {
            role: 'buffer',
            label: 'local_buf_unknown',
            size: 0x60,
            size_exact: false,
            offsetFromBp: -0x60,
            confidence: 0.5,
            source: 'evidence'
          }
        ],
        basePointer: '0x1000',
        stackPointer: '0xf90',
        frameSize: 0x70
      },
      control: { savedBpAddr: '0x1000', retAddrAddr: '0x1008' }
    };

    const semanticSlots = formattingMod.buildSemanticStackItems(analysis);
    const sorted = [...semanticSlots].sort((a, b) => formattingMod.compareStackItemsByAddrDesc(a, b, rbp));
    const sourceSlots = formattingMod.buildSimpleSourceItems(sorted, {
      options: {},
      rsp: rbp,
      rbp,
      retAddrAddr: rbp + 8n,
      bufferStart: null,
      bufferEnd: null,
      analysisStackRoles: {},
      modelRegions: [],
      diagnostics: [],
      payloadText: '',
      payloadHex: '',
      spName: 'RSP',
      bpName: 'RBP'
    });

    const workspace = stackModelMod.buildStackWorkspaceModel({
      slots: sourceSlots,
      snapshots: [{ step: 3, func: 'main' }],
      meta: { arch_bits: 64 },
      currentStep: 3,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis,
      mcp: { model: null }
    });

    const kinds = workspace.frameModel.entries.map((entry: any) => entry.kind);
    expect(kinds).to.include('buffer');
    expect(kinds).to.not.include('local');
  });
});
