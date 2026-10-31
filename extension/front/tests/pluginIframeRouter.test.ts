const { expect } = require('chai');
const path = require('path');

// Minimal mock environment for Node (tsx mocha has no browser APIs)
let _listeners: Array<(e: any) => void> = [];

const mockPoF = {
  getBinaryPath: () => Promise.resolve('/path/to/bin'),
  getTabCache: (k: string) => Promise.resolve(`cached-${k}`),
  setTabCache: (_k: string, _v: any) => Promise.resolve(undefined),
  saveStorage: (_d: any) => Promise.resolve(undefined),
  registerTabLoader: (_tabId: string) => Promise.resolve(undefined),
};

let _tabOwners: Record<string, string> = {};

const mockWindow = {
  addEventListener: (type: string, fn: (e: any) => void) => {
    if (type === 'message') _listeners.push(fn);
  },
  PoF: mockPoF,
  getPluginSlugForTab: (tabId: string) => _tabOwners[tabId] || null,
};

function makeFrame(pluginId: string) {
  const received: any[] = [];
  const slug = pluginId.startsWith('pof.') ? pluginId.slice(4) : pluginId;
  return {
    dataset: { pluginId, pluginSlug: slug },
    contentWindow: {
      postMessage: (msg: any, _origin: string) => { received.push(msg); },
    },
    _received: received,
  };
}

// Emit a message as if it came from a frame's contentWindow
function emit(data: any, sourceWindow?: any, origin = 'null') {
  const event = { data, source: sourceWindow, origin, stopped: false, stopImmediatePropagation() { this.stopped = true; } };
  _listeners.forEach(fn => fn(event));
  return event;
}

describe('PluginIframeRouter', () => {
  let router: any;

  beforeEach(() => {
    _listeners = [];
    _tabOwners = { audit: 'my-plugin', tab: 'a' };
    // Fresh require each time to reset internal state
    const routerPath = path.resolve(__dirname, '../../front/shared/pluginIframeRouter.js');
    delete require.cache[routerPath];
    router = require(routerPath);
    router.init(mockWindow, { postMessage: () => {} });
  });

  it('dispatches a message to a registered frame by pluginId', () => {
    const frame = makeFrame('pof.my-plugin');
    router.register('my-plugin', frame);
    router.dispatch('pof.my-plugin', { type: 'hello' });

    expect(frame._received).to.have.length(1);
    expect(frame._received[0]).to.deep.include({ __pof_host: true });
    expect(frame._received[0].payload).to.deep.equal({ type: 'hello' });
  });

  it('broadcasts to all registered frames', () => {
    const f1 = makeFrame('pof.p1');
    const f2 = makeFrame('pof.p2');
    router.register('p1', f1);
    router.register('p2', f2);
    router.broadcast({ type: 'binaryChange', binaryPath: '/a/b' });

    expect(f1._received).to.have.length(1);
    expect(f2._received).to.have.length(1);
    expect(f1._received[0].payload).to.deep.equal({ type: 'binaryChange', binaryPath: '/a/b' });
  });

  it('forwards non-PoF plugin messages to vscode', async () => {
    const sent: any[] = [];
    const vscode = { postMessage: (msg: any) => sent.push(msg) };
    router.init(mockWindow, vscode);

    const frame = makeFrame('pof.my-plugin');
    router.register('my-plugin', frame);

    emit(
      { __pof_plugin: true, payload: { type: 'hubPluginInvoke', cmd: 'audit.run' } },
      frame.contentWindow,
    );
    await new Promise(r => setTimeout(r, 0));

    expect(sent).to.have.length(1);
    expect(sent[0]).to.deep.include({ type: 'hubPluginInvoke' });
  });

  it('reports tab loaders only after the plugin registration handshake', async () => {
    const frame = makeFrame('pof.my-plugin');
    router.register('my-plugin', frame);
    expect(router.hasTabLoader('my-plugin', 'audit')).to.equal(false);

    emit({
      __pof_plugin: true,
      __pof_call: true,
      method: 'registerTabLoader',
      args: ['audit'],
      __seq: 7,
    }, frame.contentWindow);
    await new Promise(r => setTimeout(r, 0));

    expect(router.hasTabLoader('my-plugin', 'audit')).to.equal(true);
  });

  it('handles a PoF proxy call and sends reply to source frame', async () => {
    const frame = makeFrame('pof.my-plugin');
    router.register('my-plugin', frame);

    emit(
      { __pof_plugin: true, __pof_call: true, method: 'getTabCache', args: ['audit'], __seq: 42 },
      frame.contentWindow,
    );
    await new Promise(r => setTimeout(r, 20));

    const reply = frame._received.find((m: any) => m.payload && m.payload.__pof_reply);
    expect(reply).to.exist;
    expect(reply.payload.__seq).to.equal(42);
    expect(reply.payload.result).to.equal('cached-audit');
  });

  describe('trust boundary', () => {
    const tick = () => new Promise(r => setTimeout(r, 0));
    let sent: any[];

    beforeEach(() => {
      sent = [];
      router.init(mockWindow, { postMessage: (msg: any) => sent.push(msg) });
    });

    const forward = (type: string, extra: any = {}) => ({ __pof_plugin: true, payload: { type, ...extra } });

    it('refuses a window that is not a registered frame', async () => {
      const stranger = { postMessage: () => { throw new Error('must not reply'); } };
      emit(forward('hubPluginInvoke'), stranger);
      emit({ __pof_plugin: true, __pof_call: true, method: 'getTabCache', args: ['x'], __seq: 1 }, stranger);
      await tick();
      expect(sent).to.deep.equal([]);
    });

    it('imposes the frame identity over any claimed one', async () => {
      const frameA = makeFrame('pof.plugin-a');
      router.register('plugin-a', frameA);
      emit(forward('hubPluginInvoke', { __pofPluginId: 'pof.plugin-b', plugin_id: 'pof.plugin-b' }), frameA.contentWindow);
      await tick();
      expect(sent[0].__pofPluginId).to.equal('pof.plugin-a');
    });

    for (const type of ['hubRunScript', 'hubGrantPluginConsent', 'hubRevokePluginConsent', 'hubSaveSettings', 'runTrace', 'hubLoadPluginState', '__proto__']) {
      it(`refuses ${type} from a plugin frame`, async () => {
        const frame = makeFrame('pof.my-plugin');
        router.register('my-plugin', frame);
        emit(forward(type), frame.contentWindow);
        await tick();
        expect(sent).to.deep.equal([]);
      });
    }

    it('keeps rule management to the plugin that owns it', async () => {
      const malware = makeFrame('pof.malware-triage-pro');
      const other = makeFrame('pof.other');
      router.register('malware-triage-pro', malware);
      router.register('other', other);
      emit(forward('hubUpdateUserRule'), other.contentWindow);
      emit(forward('hubUpdateUserRule'), malware.contentWindow);
      await tick();
      expect(sent).to.have.length(1);
      expect(sent[0].__pofPluginId).to.equal('pof.malware-triage-pro');
    });

    it('allows every message the official plugins send', async () => {
      const usedBy: Record<string, string[]> = {
        'pof.cross-analysis-pro': ['hubPluginInvoke', 'hubError', 'hubGoToAddress', 'hubGoToFileOffset'],
        'pof.malware-triage-pro': ['hubPluginInvoke', 'hubError', 'hubGoToAddress', 'hubGoToFileOffset', 'hubListRules',
          'hubGetRuleContent', 'hubToggleRule', 'hubUpdateUserRule', 'hubDeleteUserRule', 'hubBrowseImportRule', 'requestRulesSelection'],
        'pof.offensive-research-pro': ['hubPluginInvoke', 'hubGoToAddress', 'hubPickFile'],
        'pof.vulnerability-audit-pro': ['hubPluginInvoke', 'hubError', 'hubGoToAddress', 'hubGoToFileOffset',
          'hubLoadDataXrefs', 'hubLoadImportXrefs', 'hubRevealStringAtAddress'],
      };
      for (const [pluginId, types] of Object.entries(usedBy)) {
        const frame = makeFrame(pluginId);
        router.register(pluginId.slice(4), frame);
        for (const type of types) {
          sent.length = 0;
          emit(forward(type), frame.contentWindow);
          await tick();
          expect(sent, `${pluginId} ${type}`).to.have.length(1);
        }
      }
    });

    it('allows every message the injected bridge sends', async () => {
      const webviewSource = require('fs').readFileSync(path.resolve(__dirname, '../../src/shared/webview.ts'), 'utf8');
      const preamble = webviewSource.slice(0, webviewSource.indexOf('function _buildPluginSrcdoc'));
      const types = Array.from(new Set(
        Array.from(preamble.matchAll(/postMessage\(\{\s*type:\s*'(\w+)'/g), (m: any) => m[1]),
      ));
      expect(types).to.include.members(['hubDebugLog', 'hubLoadXrefs', 'hubSaveFunctionReview']);
      const frame = makeFrame('pof.my-plugin');
      router.register('my-plugin', frame);
      for (const type of types) {
        sent.length = 0;
        emit(forward(type), frame.contentWindow);
        await tick();
        expect(sent, String(type)).to.have.length(1);
      }
    });

    it('answers a refused PoF method without calling it', async () => {
      let called = false;
      (mockPoF as any).dangerous = () => { called = true; };
      const frame = makeFrame('pof.my-plugin');
      router.register('my-plugin', frame);
      emit({ __pof_plugin: true, __pof_call: true, method: 'dangerous', args: [], __seq: 9 }, frame.contentWindow);
      await tick();
      delete (mockPoF as any).dangerous;
      expect(called).to.equal(false);
      const reply = frame._received.find((m: any) => m.payload?.__pof_reply);
      expect(reply.payload.__seq).to.equal(9);
      expect(reply.payload.result).to.equal(undefined);
    });

    it('does not let a plugin take the tab of another plugin', async () => {
      const frame = makeFrame('pof.intruder');
      router.register('intruder', frame);
      emit({ __pof_plugin: true, __pof_call: true, method: 'registerTabLoader', args: ['audit'], __seq: 3 }, frame.contentWindow);
      await tick();
      expect(router.hasTabLoader('intruder', 'audit')).to.equal(false);
    });

    it('does not let a plugin take over a native tab', async () => {
      const frame = makeFrame('pof.intruder');
      router.register('intruder', frame);
      emit({ __pof_plugin: true, __pof_call: true, method: 'registerTabLoader', args: ['decompile'], __seq: 3 }, frame.contentWindow);
      await tick();
      expect(router.hasTabLoader('intruder', 'decompile')).to.equal(false);
    });

    for (const key of ['decompile', 'audit']) {
      it(`keeps the cache of ${key} away from a plugin that does not own it`, async () => {
        let written = false;
        const original = mockPoF.setTabCache;
        mockPoF.setTabCache = () => { written = true; return Promise.resolve(undefined); };
        const frame = makeFrame('pof.intruder');
        router.register('intruder', frame);
        emit({ __pof_plugin: true, __pof_call: true, method: 'setTabCache', args: [key, {}], __seq: 4 }, frame.contentWindow);
        emit({ __pof_plugin: true, __pof_call: true, method: 'getTabCache', args: [key], __seq: 5 }, frame.contentWindow);
        await tick();
        mockPoF.setTabCache = original;
        expect(written).to.equal(false);
        const reads = frame._received.filter((m: any) => m.payload?.__pof_reply && m.payload.__seq === 5);
        expect(reads[0].payload.result).to.equal(undefined);
      });
    }

    it('refuses tab methods before the plugin tabs are known', async () => {
      const frame = makeFrame('pof.my-plugin');
      router.register('my-plugin', frame);
      _tabOwners = {};
      emit({ __pof_plugin: true, __pof_call: true, method: 'registerTabLoader', args: ['audit'], __seq: 6 }, frame.contentWindow);
      await tick();
      expect(router.hasTabLoader('my-plugin', 'audit')).to.equal(false);
    });

    describe('saveStorage', () => {
      const saved = async (pluginId: string, updates: any) => {
        const calls: any[] = [];
        const original = mockPoF.saveStorage;
        mockPoF.saveStorage = (data: any) => { calls.push(data); return Promise.resolve(undefined); };
        const frame = makeFrame(pluginId);
        router.register(pluginId.slice(4), frame);
        emit({ __pof_plugin: true, __pof_call: true, method: 'saveStorage', args: [updates], __seq: 8 }, frame.contentWindow);
        await tick();
        mockPoF.saveStorage = original;
        return calls[0];
      };

      for (const [pluginId, updates] of Object.entries({
        'pof.cross-analysis-pro': {
          crossAnalysisQuery: 'q', crossAnalysisRisk: 'all', crossAnalysisSource: 'all',
          crossAnalysisMode: 'm', crossAnalysisSort: 's', crossAnalysisCollapsedSections: ['a'],
        },
        'pof.malware-triage-pro': {
          yaraRulesMode: 'builtin', yaraRulesPath: '/rules', detectionCapaCollapsed: true,
          detectionYaraCollapsed: false, detectionRulesCollapsed: true,
        },
        'pof.vulnerability-audit-pro': {
          vulnKind: 'all', vulnReview: 'all', vulnCwe: 'all', vulnContext: 'all',
          vulnComparison: 'all', vulnTriage: 'all', vulnSort: 'priority_desc',
        },
      })) {
        it(`keeps every key ${pluginId} really saves`, async () => {
          expect(await saved(pluginId, updates)).to.deep.equal(updates);
        });
      }

      it('drops host settings while keeping legitimate keys', async () => {
        const result = await saved('pof.vulnerability-audit-pro', {
          vulnKind: 'all', scriptCode: 'evil()', ollamaBaseUrl: 'http://evil', disabledFamilies: [],
        });
        expect(result).to.deep.equal({ vulnKind: 'all' });
      });

      it('does not let a plugin write the keys of another plugin', async () => {
        expect(await saved('pof.vulnerability-audit-pro', { yaraRulesPath: '/evil' })).to.deep.equal({});
      });

      it('gives an unknown plugin no storage access', async () => {
        expect(await saved('pof.other', { vulnKind: 'all' })).to.deep.equal({});
      });

      it('ignores values that are not plain objects', async () => {
        expect(await saved('pof.vulnerability-audit-pro', ['scriptCode'])).to.deep.equal({});
        expect(await saved('pof.vulnerability-audit-pro', 'scriptCode')).to.deep.equal({});
      });
    });

    it('hides sandboxed messages from the listeners of the hub', () => {
      const frame = makeFrame('pof.my-plugin');
      router.register('my-plugin', frame);
      expect(emit({ type: 'hubPluginFrames', frames: [] }, frame.contentWindow).stopped).to.equal(true);
      expect(emit({ type: 'hubPluginFrames', frames: [] }, { other: true }).stopped).to.equal(true);
    });

    it('leaves messages from the extension alone', () => {
      const host = {};
      expect(emit({ type: 'hubPluginState' }, host, 'vscode-webview://abc').stopped).to.equal(false);
    });

    it('registers its listener in the capture phase', () => {
      let capture: any;
      const win = { addEventListener: (_t: string, _f: any, option: any) => { capture = option; }, PoF: mockPoF };
      router.init(win, { postMessage: () => {} });
      expect(capture).to.equal(true);
    });

    describe('syncFrames', () => {
      const makeHost = () => {
        const children: any[] = [];
        const host: any = {
          children,
          appendChild: (el: any) => children.push(el),
          ownerDocument: {
            createElement: () => {
              const attrs: Record<string, string> = {};
              const order: string[] = [];
              const el: any = {
                dataset: {},
                order,
                contentWindow: { postMessage: () => {} },
                setAttribute: (k: string, v: string) => { attrs[k] = v; order.push(k); },
                getAttribute: (k: string) => attrs[k],
                addEventListener: () => {},
                remove: () => children.splice(children.indexOf(el), 1),
              };
              return el;
            },
          },
        };
        return host;
      };
      const spec = (over: any = {}) => ({
        pluginId: 'pof.a', pluginSlug: 'a', frameId: 'pof-plugin-frame-a', srcdoc: '<p>a</p>', ...over,
      });

      it('creates a frame sandboxed before its content is set', () => {
        const host = makeHost();
        router.syncFrames([spec()], host);
        const [frame] = host.children;
        expect(frame.getAttribute('sandbox')).to.equal('allow-scripts');
        expect(frame.order).to.deep.equal(['sandbox', 'srcdoc']);
        expect(frame.dataset.pluginId).to.equal('pof.a');
      });

      it('removes a revoked plugin and its capabilities', async () => {
        const host = makeHost();
        router.syncFrames([spec()], host);
        const [frame] = host.children;
        emit({ __pof_plugin: true, __pof_call: true, method: 'registerTabLoader', args: ['tab'], __seq: 1 }, frame.contentWindow);
        await tick();
        expect(router.hasTabLoader('a', 'tab')).to.equal(true);

        router.syncFrames([], host);
        expect(host.children).to.deep.equal([]);
        expect(router.hasTabLoader('a', 'tab')).to.equal(false);
        emit({ __pof_plugin: true, payload: { type: 'hubPluginInvoke' } }, frame.contentWindow);
        await tick();
        expect(sent).to.deep.equal([]);
      });

      it('keeps a running frame when nothing changed', () => {
        const host = makeHost();
        router.syncFrames([spec()], host);
        const [frame] = host.children;
        router.syncFrames([spec()], host);
        expect(host.children).to.deep.equal([frame]);
      });

      it('replaces a frame whose content changed', () => {
        const host = makeHost();
        router.syncFrames([spec()], host);
        const [frame] = host.children;
        router.syncFrames([spec({ srcdoc: '<p>b</p>' })], host);
        expect(host.children).to.have.length(1);
        expect(host.children[0]).not.to.equal(frame);
      });
    });
  });
});
