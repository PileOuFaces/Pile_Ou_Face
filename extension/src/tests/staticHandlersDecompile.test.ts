const { expect } = require('chai');
const { EventEmitter } = require('events');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('hubLoadDecompile parallel', () => {
  afterEach(() => sinon.restore());

  // Helper to build a stub staticHandlers
  function makeHandlers(execFile, posted = [], overrides = {}) {
    const savedSettings = overrides.savedSettings || {};
    const proxyStubs = {
      child_process: { execFile, ...(overrides.child_process || {}) },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({}),
        buildDecompilerImageEnv: overrides.buildDecompilerImageEnv || (() => ({})),
        resolveDockerExecutable: () => '/usr/bin/docker',
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
      context: { globalState: { get: () => savedSettings, update: async () => {} } },
      logChannel: overrides.logChannel,
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

  it('injects configured decompiler image env into decompile subprocesses', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(opts.env).to.include({
        POF_DECOMPILER_IMAGE_RETDEC: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec:1.0.0',
      });
      cb(null, JSON.stringify({ ok: true, code: 'int main() {}', score: 10 }), '');
    });
    const buildDecompilerImageEnv = sinon.stub().returns({
      POF_DECOMPILER_IMAGE_RETDEC: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec:1.0.0',
    });
    const handlers = makeHandlers(execFile, [], {
      savedSettings: {
        decompilerImages: {
          retdec: { source: 'ours', version: '1.0.0' },
        },
      },
      buildDecompilerImageEnv,
    });

    await handlers.hubLoadDecompile({ binaryPath: '/bin/foo', addr: '0x1000', decompiler: 'retdec' });

    expect(buildDecompilerImageEnv.called).to.equal(true);
  });

  it('posts update availability when a remote Docker digest differs', async () => {
    const oldDigest = `sha256:${'a'.repeat(64)}`;
    const newDigest = `sha256:${'b'.repeat(64)}`;
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(args).to.include('--list');
      cb(null, JSON.stringify({
        retdec: true,
        _meta: {
          labels: { retdec: 'RetDec' },
          docker_images: { retdec: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec:latest' },
          docker_images_available: { retdec: true },
          docker_platform: { retdec: 'linux/amd64' },
        },
      }), '');
    });
    const spawn = sinon.stub().callsFake((bin, args) => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = sinon.stub();
      process.nextTick(() => {
        if (args.includes('image')) {
          child.stdout.emit('data', JSON.stringify([
            { RepoDigests: [`ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec@${oldDigest}`] },
          ]));
        } else if (args.includes('buildx')) {
          child.stdout.emit('data', `Name: ghcr.io/pileoufaces/pile-ou-face/decompiler-retdec:latest\nDigest:    ${newDigest}\n`);
        } else {
          child.stdout.emit('data', JSON.stringify({ Descriptor: { digest: newDigest } }));
        }
        child.emit('close', 0);
      });
      return child;
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { child_process: { spawn } });
    await handlers.hubListDecompilers({ provider: 'auto' });
    await new Promise(resolve => setTimeout(resolve, 10));

    const updateMsgs = posted.filter(m => m.type === 'hubDecompilerImageUpdates');
    expect(updateMsgs.length).to.equal(2);
    expect(updateMsgs[0].updates.retdec.status).to.equal('checking');
    expect(updateMsgs[1].updates.retdec.status).to.equal('update-available');
  });

  it('treats a matching remote image index digest as up to date', async () => {
    const indexDigest = `sha256:${'c'.repeat(64)}`;
    const platformDigest = `sha256:${'d'.repeat(64)}`;
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(args).to.include('--list');
      cb(null, JSON.stringify({
        ghidra: true,
        _meta: {
          labels: { ghidra: 'Ghidra' },
          docker_images: { ghidra: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-ghidra:latest' },
          docker_images_available: { ghidra: true },
          docker_platform: {},
        },
      }), '');
    });
    const spawn = sinon.stub().callsFake((bin, args) => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = sinon.stub();
      process.nextTick(() => {
        if (args.includes('image')) {
          child.stdout.emit('data', JSON.stringify([
            { RepoDigests: [`ghcr.io/pileoufaces/pile-ou-face/decompiler-ghidra@${indexDigest}`] },
          ]));
        } else if (args.includes('buildx')) {
          child.stdout.emit('data', [
            'Name:      ghcr.io/pileoufaces/pile-ou-face/decompiler-ghidra:latest',
            'MediaType: application/vnd.oci.image.index.v1+json',
            `Digest:    ${indexDigest}`,
            `  Name: ghcr.io/pileoufaces/pile-ou-face/decompiler-ghidra:latest@${platformDigest}`,
          ].join('\n'));
        } else {
          child.stdout.emit('data', JSON.stringify({ Descriptor: { digest: platformDigest } }));
        }
        child.emit('close', 0);
      });
      return child;
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { child_process: { spawn } });
    await handlers.hubListDecompilers({ provider: 'auto' });
    await new Promise(resolve => setTimeout(resolve, 10));

    const updateMsgs = posted.filter(m => m.type === 'hubDecompilerImageUpdates');
    expect(updateMsgs.length).to.equal(2);
    expect(updateMsgs[1].updates.ghidra.status).to.equal('up-to-date');
  });

  it('reuses cached Docker image update status on repeated list refreshes', async () => {
    const digest = `sha256:${'e'.repeat(64)}`;
    const image = 'ghcr.io/pileoufaces/pile-ou-face/decompiler-cache-test:latest';
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(args).to.include('--list');
      cb(null, JSON.stringify({
        cachetest: true,
        _meta: {
          labels: { cachetest: 'Cache Test' },
          docker_images: { cachetest: image },
          docker_images_available: { cachetest: true },
          docker_platform: {},
        },
      }), '');
    });
    const spawn = sinon.stub().callsFake((bin, args) => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = sinon.stub();
      process.nextTick(() => {
        if (args.includes('image')) {
          child.stdout.emit('data', JSON.stringify([
            { RepoDigests: [`${image.replace(':latest', '')}@${digest}`], Created: '2026-06-30T10:00:00Z', Os: 'linux', Architecture: 'arm64' },
          ]));
        } else if (args.includes('buildx')) {
          child.stdout.emit('data', `Name: ${image}\nDigest:    ${digest}\n`);
        } else {
          child.stdout.emit('data', JSON.stringify({ Descriptor: { digest } }));
        }
        child.emit('close', 0);
      });
      return child;
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted, { child_process: { spawn } });

    await handlers.hubListDecompilers({ provider: 'auto' });
    await new Promise(resolve => setTimeout(resolve, 10));
    await handlers.hubListDecompilers({ provider: 'auto' });
    await new Promise(resolve => setTimeout(resolve, 10));

    const imageStatusCalls = spawn.getCalls().filter((call) => {
      const args = call.args[1] || [];
      return args.includes('image') || args.includes('manifest') || (args.includes('buildx') && args.includes('imagetools'));
    });
    expect(imageStatusCalls.length).to.equal(3);
    const updateMsgs = posted.filter(m => m.type === 'hubDecompilerImageUpdates');
    expect(updateMsgs.length).to.equal(3);
    expect(updateMsgs[0].updates.cachetest.status).to.equal('checking');
    expect(updateMsgs[1].updates.cachetest.status).to.equal('up-to-date');
    expect(updateMsgs[2].updates.cachetest.status).to.equal('up-to-date');
    expect(updateMsgs[2].updates.cachetest.cached).to.equal(true);
    expect(updateMsgs[2].updates.cachetest.localDigestShort).to.equal('eeeeeeeeeeee');
    expect(updateMsgs[2].updates.cachetest.localPlatform).to.equal('linux/arm64');
  });

  it('compacts Docker pull progress instead of posting every layer line', async () => {
    const execFile = sinon.stub().callsFake((bin, args, opts, cb) => {
      expect(args).to.include('--list');
      cb(null, JSON.stringify({ _meta: { docker_images: {}, docker_images_available: {} } }), '');
    });
    const logLines = [];
    const spawn = sinon.stub().callsFake((bin, args) => {
      const child = new EventEmitter();
      child.stdout = new EventEmitter();
      child.stderr = new EventEmitter();
      child.kill = sinon.stub();
      process.nextTick(() => {
        if (args.includes('pull')) {
          child.stdout.emit('data', [
            'Pulling from pileoufaces/pile-ou-face/decompiler-logtest',
            'aaa111: Pulling fs layer',
            'bbb222: Pulling fs layer',
            'aaa111: Pull complete',
            'bbb222: Pull complete',
            'Digest: sha256:' + 'f'.repeat(64),
            'Status: Image is up to date',
          ].join('\n'));
          child.emit('close', 0);
          return;
        }
        child.stdout.emit('data', 'Docker ok');
        child.emit('close', 0);
      });
      return child;
    });
    const posted = [];
    const handlers = makeHandlers(execFile, posted, {
      child_process: { spawn },
      logChannel: { appendLine: (line) => logLines.push(line) },
    });

    await handlers.hubPullDecompilerImage({
      decompiler: 'logtest',
      image: 'ghcr.io/pileoufaces/pile-ou-face/decompiler-logtest:latest',
      mode: 'force',
    });
    await new Promise(resolve => setTimeout(resolve, 20));

    const progressLines = posted
      .filter(m => m.type === 'hubDecompilerPullProgress')
      .map(m => m.line);
    expect(progressLines.some(line => line.includes('aaa111: Pull complete'))).to.equal(false);
    expect(progressLines.some(line => line.includes('bbb222: Pull complete'))).to.equal(false);
    expect(progressLines).to.include('Layers 2/2');
    expect(progressLines.some(line => line.startsWith('Digest:'))).to.equal(true);
    expect(logLines.some(line => line.includes('[decompiler/docker] pull.start'))).to.equal(true);
    expect(logLines.some(line => line.includes('[decompiler/docker] pull.done'))).to.equal(true);
  });
});
