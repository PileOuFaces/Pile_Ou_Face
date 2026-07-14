const { expect } = require('chai');
const path = require('path');
const { pathToFileURL } = require('url');

const trace = require('../fixtures/traces/main-challenge-trace.json');
const mainModel = require('../fixtures/stack-models/main-frame-model.json');
const latentFrames = require('../fixtures/stack-models/latent-leakage-hard-frames.json');

describe('dynamic/workflows active function switch', () => {
  let buildStackWorkspaceModel: Function;

  before(async () => {
    const modulePath = path.resolve(__dirname, '../../../dynamic/app/stackWorkspaceCore.js');
    ({ buildStackWorkspaceModel } = await import(pathToFileURL(modulePath).href));
  });

  it('selecting-challenge-after-main-renders-no-stale-main-stack', () => {
    const mainFrame = buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        function: { name: 'main' },
        frame: { basePointer: '0x1000', stackPointer: '0x0fc0', frameSize: 64 },
        control: { savedBpAddr: '0x1000', retAddrAddr: '0x1008' }
      },
      mcp: { model: mainModel }
    });
    expect(mainFrame.frameModel.entries.some((entry: any) => String(entry.key).startsWith('main:'))).to.equal(true);

    const challengeFrame = buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: 1,
      selectedFunction: 'challenge',
      snapshot: { func: 'main' },
      analysis: {
        function: { name: 'main' },
        frame: { basePointer: '0x1000', stackPointer: '0x0fc0', frameSize: 64 },
        control: { savedBpAddr: '0x1000', retAddrAddr: '0x1008' }
      },
      mcp: { model: mainModel }
    });

    expect(challengeFrame.frameModel.functionName).to.equal('challenge');
    expect(challengeFrame.frameModel.entries).to.have.length(0);
    expect(challengeFrame.frameModel.emptyText).to.equal('challenge() is selected, but the current trace step is still in main().');
    expect(challengeFrame.frameModel.emptyState).to.include({
      guidance: 'Go to a step inside challenge() to view its runtime stack frame.',
      actionLabel: 'Jump to first challenge() step',
      actionStep: 2
    });
    expect(challengeFrame.frameModel.debug.rejectedReason).to.equal('function_mismatch');
  });

  it('selecting-challenge-renders-correct-frame-or-empty-state-never-stale-main-rbp-0x40', () => {
    const selectedMain = buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: 1,
      selectedFunction: 'main',
      snapshot: { func: 'main' },
      analysis: {
        function: { name: 'main' },
        // This fixture deliberately passes slots: [] (only exercises stale
        // model/function-switch rejection, not raw per-step observations)
        // -- frameReady tells the temporal gating this frame is
        // established so model.locals content still shows.
        frame: { basePointer: '0x7fffffffe040', stackPointer: '0x7fffffffe000', frameSize: 64, frameReady: true },
        control: { savedBpAddr: '0x7fffffffe040', retAddrAddr: '0x7fffffffe048' }
      },
      mcp: { model: latentFrames.main }
    });
    expect(selectedMain.frameModel.entries.some((entry: any) => entry.offset === -64 && entry.size === 64)).to.equal(true);

    const selectedChallengeWithStaleMain = buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: 2,
      selectedFunction: 'challenge',
      snapshot: { func: 'challenge' },
      analysis: {
        function: { name: 'challenge' },
        frame: { basePointer: '0x7fffffffe1c0', stackPointer: '0x7fffffffe000', frameSize: 448 },
        control: { savedBpAddr: '0x7fffffffe1c0', retAddrAddr: '0x7fffffffe1c8' }
      },
      mcp: { model: latentFrames.main }
    });
    expect(selectedChallengeWithStaleMain.frameModel.entries).to.deep.equal([]);
    expect(selectedChallengeWithStaleMain.frameModel.debug.rejectedReason).to.equal('function_mismatch');

    const selectedChallenge = buildStackWorkspaceModel({
      slots: [],
      snapshots: trace.snapshots,
      meta: trace.meta,
      currentStep: 2,
      selectedFunction: 'challenge',
      snapshot: { func: 'challenge' },
      analysis: {
        function: { name: 'challenge' },
        frame: { basePointer: '0x7fffffffe1c0', stackPointer: '0x7fffffffe000', frameSize: 448, frameReady: true },
        control: { savedBpAddr: '0x7fffffffe1c0', retAddrAddr: '0x7fffffffe1c8' }
      },
      mcp: { model: latentFrames.challenge }
    });
    const entries = selectedChallenge.frameModel.entries;
    const keys = entries.map((entry: any) => String(entry.key || entry.id || ''));

    expect(keys.some((key: string) => key.startsWith('main:'))).to.equal(false);
    expect(entries.some((entry: any) => entry.offset === -64 && entry.size === 64)).to.equal(false);
    expect(entries.some((entry: any) => entry.offset === -448 && entry.size === 448)).to.equal(true);
  });
});
