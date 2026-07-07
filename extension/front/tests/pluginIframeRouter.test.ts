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

const mockWindow = {
  addEventListener: (type: string, fn: (e: any) => void) => {
    if (type === 'message') _listeners.push(fn);
  },
  PoF: mockPoF,
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
function emit(data: any, sourceWindow?: any) {
  _listeners.forEach(fn => fn({ data, source: sourceWindow }));
}

describe('PluginIframeRouter', () => {
  let router: any;

  beforeEach(() => {
    _listeners = [];
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

  it('handles a PoF proxy call and sends reply to source frame', async () => {
    const frame = makeFrame('pof.my-plugin');
    router.register('my-plugin', frame);

    emit(
      { __pof_plugin: true, __pof_call: true, method: 'getBinaryPath', args: [], __seq: 42 },
      frame.contentWindow,
    );
    await new Promise(r => setTimeout(r, 20));

    const reply = frame._received.find((m: any) => m.payload && m.payload.__pof_reply);
    expect(reply).to.exist;
    expect(reply.payload.__seq).to.equal(42);
    expect(reply.payload.result).to.equal('/path/to/bin');
  });
});
