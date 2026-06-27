const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

const trace = require('../fixtures/traces/main-challenge-trace.json');
const mainModel = require('../fixtures/stack-models/main-frame-model.json');
const challengeModel = require('../fixtures/stack-models/challenge-frame-model.json');
const latentFrames = require('../fixtures/stack-models/latent-leakage-hard-frames.json');

describe('dynamic/stack-model stale model rejection workflows', () => {
  let buildStackWorkspaceModel: Function;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../webview/dynamic/app/stackWorkspaceCore.js');
    ({ buildStackWorkspaceModel } = await import(pathToFileURL(modulePath).href));
  });

  function analysisFor(functionName: string) {
    const basePointer = functionName === 'challenge' ? '0x7fffffffe1c0' : '0x7fffffffe040';
    return {
      function: { name: functionName },
      frame: {
        basePointer,
        stackPointer: functionName === 'challenge' ? '0x7fffffffe000' : '0x7fffffffe000',
        frameSize: functionName === 'challenge' ? 0x1c0 : 0x40
      },
      control: {
        savedBpAddr: basePointer,
        retAddrAddr: functionName === 'challenge' ? '0x7fffffffe1c8' : '0x7fffffffe048'
      }
    };
  }

  function buildWorkspace(selectedFunction: string, snapshotFunc: string, model: unknown) {
    return buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: snapshotFunc === 'challenge' ? 2 : 1,
      selectedFunction,
      snapshot: { func: snapshotFunc },
      analysis: analysisFor(snapshotFunc),
      mcp: { model }
    });
  }

  it('switching-main-to-challenge-does-not-keep-main-model', () => {
    const mainWorkspace = buildWorkspace('main', 'main', mainModel);
    expect(mainWorkspace.frameModel.functionName).to.equal('main');
    expect(mainWorkspace.frameModel.entries.some((entry: any) => String(entry.key).startsWith('main:'))).to.equal(true);

    const challengeWorkspace = buildWorkspace('challenge', 'main', mainModel);

    expect(challengeWorkspace.frameModel.functionName).to.equal('challenge');
    expect(challengeWorkspace.frameModel.entries).to.deep.equal([]);
    expect(challengeWorkspace.frameModel.emptyText).to.equal('challenge() is selected, but the current trace step is still in main().');
    expect(challengeWorkspace.frameModel.emptyState).to.include({
      guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
      actionLabel: 'Jump to first challenge() step',
      actionStep: 2
    });
    expect(challengeWorkspace.frameModel.debug).to.include({
      requestedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('trace-json-challenge-renders-only-challenge-scoped-frame-ids', () => {
    const workspace = buildWorkspace('challenge', 'challenge', challengeModel);
    const keys = workspace.frameModel.entries.map((entry: any) => String(entry.key || entry.id || ''));

    expect(workspace.frameModel.functionName).to.equal('challenge');
    expect(keys).to.not.deep.equal([]);
    expect(keys.every((key: string) => key.startsWith('challenge:'))).to.equal(true);
    expect(keys.some((key: string) => key.startsWith('main:') || key.startsWith('win:'))).to.equal(false);
  });

  it('one-frame-cannot-mix-main-win-and-challenge-item-identities', () => {
    const mixedModel = {
      name: 'challenge',
      locals: [
        challengeModel.locals[0],
        { id: 'main:rbp:buffer:-64:64:frame', offset: -64, name: 'main_buf', role: 'buffer', size: 64 }
      ]
    };

    const workspace = buildWorkspace('challenge', 'challenge', mixedModel);
    const keys = workspace.frameModel.entries.map((entry: any) => String(entry.key || entry.id || ''));

    expect(keys.some((key: string) => key.startsWith('main:') || key.startsWith('win:'))).to.equal(false);
    expect(keys.every((key: string) => key.startsWith('challenge:'))).to.equal(true);
    expect(workspace.frameModel.debug).to.include({
      requestedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });
  });

  it('latent-leakage-hard-style-main-and-challenge-frames-stay-separated', () => {
    const mainWorkspace = buildWorkspace('main', 'main', latentFrames.main);
    const mainEntries = mainWorkspace.frameModel.entries;
    expect(mainWorkspace.frameModel.functionName).to.equal('main');
    expect(mainEntries.some((entry: any) => String(entry.key || entry.id).startsWith('main:'))).to.equal(true);
    expect(mainEntries.some((entry: any) => entry.offset === -64 && entry.size === 64)).to.equal(true);

    const staleChallengeWorkspace = buildWorkspace('challenge', 'main', latentFrames.main);
    expect(staleChallengeWorkspace.frameModel.functionName).to.equal('challenge');
    expect(staleChallengeWorkspace.frameModel.entries).to.deep.equal([]);
    expect(staleChallengeWorkspace.frameModel.emptyText).to.equal('challenge() is selected, but the current trace step is still in main().');
    expect(staleChallengeWorkspace.frameModel.emptyState).to.include({
      guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
      actionLabel: 'Jump to first challenge() step',
      actionStep: 2
    });
    expect(staleChallengeWorkspace.frameModel.debug).to.include({
      requestedFunction: 'challenge',
      rejectedFunction: 'main',
      rejectedReason: 'function_mismatch'
    });

    const challengeWorkspace = buildWorkspace('challenge', 'challenge', latentFrames.challenge);
    const challengeEntries = challengeWorkspace.frameModel.entries;
    const challengeKeys = challengeEntries.map((entry: any) => String(entry.key || entry.id || ''));

    expect(challengeWorkspace.frameModel.functionName).to.equal('challenge');
    expect(challengeKeys.every((key: string) => key.startsWith('challenge:'))).to.equal(true);
    expect(challengeKeys.some((key: string) => key.startsWith('main:') || key.startsWith('win:'))).to.equal(false);
    expect(challengeEntries.some((entry: any) => entry.offset === -448 && entry.size === 448)).to.equal(true);
    expect(challengeEntries.some((entry: any) => entry.offset === -64 && entry.size === 64)).to.equal(false);
    expect(challengeEntries.some((entry: any) => entry.offset === -8 && /canary/i.test(`${entry.name || entry.key || entry.id || ''}`))).to.equal(true);
    expect(challengeEntries.some((entry: any) => entry.offset === 0 && entry.kind === 'saved_bp')).to.equal(true);
    expect(challengeEntries.some((entry: any) => entry.offset === 8 && entry.kind === 'return_address')).to.equal(true);
  });

  it('selected-function-with-no-executed-step-shows-no-step-guidance-without-jump-action', () => {
    const workspace = buildStackWorkspaceModel({
      slots: [],
      snapshots: [{ step: 1, func: 'main', rip: '0x401000' }],
      meta: trace.meta,
      currentStep: 1,
      selectedFunction: 'challenge',
      snapshot: { func: 'main' },
      analysis: analysisFor('main'),
      mcp: { model: latentFrames.main }
    });

    expect(workspace.frameModel.entries).to.deep.equal([]);
    expect(workspace.frameModel.emptyState).to.include({
      message: 'challenge() is selected, but the current trace step is still in main().',
      guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
      noExecutedStepText: 'No executed step for challenge() in this trace.',
      actionLabel: '',
      actionStep: null
    });
  });
});
