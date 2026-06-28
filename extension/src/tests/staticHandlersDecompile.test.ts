const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('hubLoadDecompile parallel', () => {
  afterEach(() => sinon.restore());

  // Helper to build a stub staticHandlers
  function makeHandlers(execFile, posted = [], overrides = {}) {
    const proxyStubs = {
      child_process: { execFile },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({}),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (v) => v },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (v) => v,
      },
    };
    if (overrides.fs) proxyStubs.fs = overrides.fs;
    const staticHandlers = proxyquire('../static/staticHandlers', proxyStubs);
    return staticHandlers({
      root: '/workspace',
      panel: { webview: { postMessage: (m) => posted.push(m) } },
      context: { globalState: { get: () => ({}), update: async () => {} } },
    });
  }

  it('posts hubDecompileStatus running before subprocess resolves', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted);
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'auto' });
    const statusRunning = posted.filter(m => m.type === 'hubDecompileStatus' && m.status === 'running');
    expect(statusRunning.length).to.be.greaterThan(0);
  });

  it('posts hubDecompile with isSilentUpdate false for first result', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted);
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'auto' });
    const firstResult = posted.find(m => m.type === 'hubDecompile');
    expect(firstResult).to.exist;
    expect(firstResult.isSilentUpdate).to.equal(false);
  });

  it('launches only one subprocess when decompiler is forced', async () => {
    let callCount = 0;
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      callCount++;
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const handlers = makeHandlers(execFile);
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'ghidra' });
    expect(callCount).to.equal(1);
  });

  it('uses backend list fallback before single auto subprocess when config read fails', async () => {
    let callCount = 0;
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      callCount++;
      if (args.includes('--list')) {
        cb(null, JSON.stringify({ ghidra: true, retdec: true, _meta: {} }), '');
        return;
      }
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const fsStub = {
      readFileSync: sinon.stub().throws(new Error('boom')),
      existsSync: sinon.stub().returns(false),
      statSync: sinon.stub(),
    };
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { fs: fsStub });
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'auto' });
    const listCall = execFile.getCall(0);
    expect(listCall.args[1]).to.include('--list');
    expect(listCall.args[1]).to.include('--binary');
    expect(listCall.args[1]).to.include('/bin/foo');
    const running = posted.filter(m => m.type === 'hubDecompileStatus' && m.status === 'running');
    expect(running.map(m => m.decompiler)).to.deep.equal(['ghidra', 'retdec']);
    expect(callCount).to.equal(3);
    expect(fsStub.readFileSync.called).to.equal(false);
  });

  it('falls back to decompilers.json only when backend list resolution fails', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      if (args.includes('--list')) {
        cb(new Error('list failed'));
        return;
      }
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const fsStub = {
      readFileSync: sinon.stub().returns(JSON.stringify({
        decompilers: {
          ghidra: { enabled: true },
          retdec: { enabled: false },
          angr: {},
        },
      })),
      existsSync: sinon.stub().returns(false),
      statSync: sinon.stub(),
    };
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { fs: fsStub });
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'auto' });
    const running = posted.filter(m => m.type === 'hubDecompileStatus' && m.status === 'running');
    expect(running.map(m => m.decompiler)).to.deep.equal(['ghidra', 'angr']);
    expect(fsStub.readFileSync.calledOnce).to.equal(true);
  });

  // Regression: forcedDecompiler='' in the webview sends decompiler:'' to Node.js.
  // This must trigger --list + parallel launch, NOT a single forced subprocess.
  it('empty string decompiler runs --list and launches all available decompilers', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      if (args.includes('--list')) {
        cb(null, JSON.stringify({ ghidra: true, angr: true, retdec: true, _meta: { timeouts: { ghidra: 180, angr: 180, retdec: 120 } } }), '');
        return;
      }
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const fsStub = { existsSync: sinon.stub().returns(false), statSync: sinon.stub() };
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { fs: fsStub });
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: '' });
    // First call must be --list --binary
    const listCall = execFile.getCall(0);
    expect(listCall.args[1]).to.include('--list');
    expect(listCall.args[1]).to.include('--binary');
    // Running pills must cover all 3, not just retdec
    const running = posted.filter(m => m.type === 'hubDecompileStatus' && m.status === 'running');
    expect(running.map(m => m.decompiler)).to.deep.equal(['ghidra', 'angr', 'retdec']);
    // 1 list + 3 decompile subprocesses
    expect(execFile.callCount).to.equal(4);
  });

  it('undefined decompiler behaves identically to auto — launches all from --list', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      if (args.includes('--list')) {
        cb(null, JSON.stringify({ retdec: true, ghidra: true, _meta: { timeouts: {} } }), '');
        return;
      }
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const fsStub = { existsSync: sinon.stub().returns(false), statSync: sinon.stub() };
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { fs: fsStub });
    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000' }); // no decompiler key
    const running = posted.filter(m => m.type === 'hubDecompileStatus' && m.status === 'running');
    expect(running.map(m => m.decompiler)).to.deep.equal(['retdec', 'ghidra']);
    expect(execFile.callCount).to.equal(3); // 1 list + 2 decompile
  });

  it('hubListDecompilers posts hubDecompilerList with all declared decompilers', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(args).to.include('--list');
      expect(args).not.to.include('--binary');
      cb(null, JSON.stringify({ ghidra: true, angr: false, retdec: true, _meta: { labels: {}, docker_images: {} } }), '');
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted);
    await handlers.hubListDecompilers({ provider: 'auto' });
    const listMsg = posted.find(m => m.type === 'hubDecompilerList');
    expect(listMsg).to.exist;
    expect(listMsg.result).to.have.property('ghidra', true);
    expect(listMsg.result).to.have.property('angr', false);
    expect(listMsg.result).to.have.property('retdec', true);
  });
});
