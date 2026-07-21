const { expect } = require('chai');
const { EventEmitter } = require('events');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('plugin runtime online key transport — MODE selection', () => {
  afterEach(() => sinon.restore());

  /**
   * Build a staticHandlers instance with controlled stubs.
   * @param {object} opts
   * @param {object}   opts.fakeKeys                - {pluginId: key} returned by AuthService (empty = no online auth)
   * @param {string[]} opts.licenseFiles            - filenames returned by fs.readdirSync for the licenses dir
   * @param {boolean}  opts.authThrows              - if true, AuthService.getContentKeys() throws (network error)
   * @param {Function} opts.refreshKeysIfStaleStub  - optional stub for AuthService.refreshKeysIfStale()
   * @param {Array}    opts.captureMessages         - optional array to capture panel.webview.postMessage calls
   */
  function makeHandlers({ fakeKeys = {}, licenseFiles = [], authThrows = false, refreshKeysIfStaleStub = null, captureMessages = null } = {}) {
    const execFileStub = sinon.stub().callsFake((_bin, _args, _opts, cb) => {
      cb(null, JSON.stringify({ ok: true, plugins: [] }), '');
    });
    const spawnCalls = [];
    const spawnStub = sinon.stub().callsFake((_bin, _args, opts) => {
      const proc = new EventEmitter();
      proc.stdout = new EventEmitter();
      proc.stderr = new EventEmitter();
      proc.stdin = {
        chunks: [],
        write: sinon.stub().callsFake((chunk) => {
          proc.stdin.chunks.push(String(chunk));
        }),
        end: sinon.stub(),
      };
      spawnCalls.push({ args: [_bin, _args, opts], proc });
      process.nextTick(() => {
        proc.stdout.emit('data', JSON.stringify({ ok: true, plugins: [] }));
        proc.emit('close', 0);
      });
      return proc;
    });

    const getContentKeys = authThrows
      ? sinon.stub().rejects(new Error('auth unavailable'))
      : sinon.stub().resolves(fakeKeys);

    const refreshKeysIfStale = refreshKeysIfStaleStub !== null
      ? refreshKeysIfStaleStub
      : sinon.stub().resolves({ refreshed: false, revoked: false });

    const proxyStubs = {
      vscode: {
        workspace: {
          getConfiguration: () => ({ inspect: () => ({}) }),
        },
      },
      child_process: { execFile: execFileStub, spawn: spawnStub },
      fs: {
        readdirSync: sinon.stub().callsFake((dir) => {
          if (String(dir).includes('licenses')) return licenseFiles;
          return [];
        }),
        existsSync: sinon.stub().returns(false),
        readFileSync: sinon.stub().returns('{}'),
      },
      path: require('path'),
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({}),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (v) => v },
      '../shared/authService': {
        AuthService: {
          getInstance: sinon.stub().returns({ getContentKeys, refreshKeysIfStale }),
        },
      },
      '../shared/authConfig': {
        resolveAuthServerUrl: () => 'http://localhost:8000',
      },
      './pluginState': {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (v) => v,
      },
    };

    const staticHandlers = proxyquire('../static/staticHandlers', proxyStubs);
    const handlers = staticHandlers({
      root: '/workspace',
      panel: {
        webview: {
          postMessage: (msg) => {
            if (captureMessages) captureMessages.push(msg);
          },
        },
      },
      context: {
        globalState: { get: () => ({}), update: async () => {} },
        secrets: {},
      },
      logChannel: null,
    });

    return { handlers, execFileStub, spawnStub, spawnCalls };
  }

  function runtimeEnv(spawnCalls) {
    return spawnCalls[0].args[2].env;
  }

  function runtimeStdin(spawnCalls) {
    return spawnCalls[0].proc.stdin.chunks.join('');
  }

  // -------------------------------------------------------------------------
  // MODE 1 — online keys available
  // -------------------------------------------------------------------------

  it('MODE 1 — online keys present: BINHOST flags are set and keys are written to stdin', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'base64key==', 'pof.plugin-y': 'anotherkey==' },
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.have.property('BINHOST_CONTENT_KEYS_STDIN', '1');
    expect(env).to.not.have.property('POF_CONTENT_KEY_POF_PLUGIN_X');
    expect(env).to.not.have.property('POF_CONTENT_KEY_POF_PLUGIN_Y');
    expect(JSON.parse(runtimeStdin(spawnCalls))).to.deep.equal({
      content_keys: { 'pof.plugin-x': 'base64key==', 'pof.plugin-y': 'anotherkey==' },
    });
  });

  it('MODE 1 priority — online keys + license files present: online wins, flag is set', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'key==' },
      licenseFiles: ['pof.plugin-x.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.have.property('BINHOST_CONTENT_KEYS_STDIN', '1');
  });

  // -------------------------------------------------------------------------
  // Offline license files are never accepted by ONLINE_STANDARD
  // -------------------------------------------------------------------------

  it('Locked — local .license.json cannot enable a plugin without an online lease', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: {},
      licenseFiles: ['pof.plugin-x.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.not.have.property('BINHOST_CONTENT_KEYS_STDIN');
    expect(runtimeStdin(spawnCalls)).to.equal('');
  });

  it('Locked — auth failure cannot fall back to local license files', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      authThrows: true,
      licenseFiles: ['pof.plugin-y.license.json', 'pof.plugin-z.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.not.have.property('BINHOST_CONTENT_KEYS_STDIN');
  });

  it('Locked — unrelated local files cannot enable a plugin', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: {},
      licenseFiles: ['README.md', 'install.sh', 'notes.txt'],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.not.have.property('BINHOST_CONTENT_KEYS_STDIN');
  });

  // -------------------------------------------------------------------------
  // Locked — no online keys, no license files
  // -------------------------------------------------------------------------

  it('Locked — no online keys + no license files: BINHOST flag is set', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: {},
      licenseFiles: [],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.not.have.property('BINHOST_CONTENT_KEYS_STDIN');
    // No content keys injected
    const keyVars = Object.keys(env).filter((k) => k.startsWith('POF_CONTENT_KEY_'));
    expect(keyVars).to.have.length(0);
    expect(runtimeStdin(spawnCalls)).to.equal('');
  });

  it('Locked — AuthService throws + no license files: BINHOST flag is set', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      authThrows: true,
      licenseFiles: [],
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.not.have.property('BINHOST_CONTENT_KEYS_STDIN');
  });

  // -------------------------------------------------------------------------
  // Plugin ID normalisation
  // -------------------------------------------------------------------------

  it('plugin IDs with hyphens and dots are normalised to underscores in env var names', async () => {
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: { 'pof.plugin-z': 'mykey==' },
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.not.have.property('POF_CONTENT_KEY_POF_PLUGIN_Z');
    expect(JSON.parse(runtimeStdin(spawnCalls))).to.deep.equal({
      content_keys: { 'pof.plugin-z': 'mykey==' },
    });
  });

  // -------------------------------------------------------------------------
  // TTL — refresh stale keys
  // -------------------------------------------------------------------------

  it('TTL — refresh réussi : MODE 1 maintenu avec clés fraîches', async () => {
    const refreshKeysIfStale = sinon.stub().resolves({ refreshed: true, revoked: false });
    const { handlers, spawnCalls } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'refreshed-key==' },
      refreshKeysIfStaleStub: refreshKeysIfStale,
    });

    await handlers.hubLoadPluginState();

    const env = runtimeEnv(spawnCalls);
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.have.property('BINHOST_CONTENT_KEYS_STDIN', '1');
    expect(env).to.not.have.property('POF_CONTENT_KEY_POF_PLUGIN_X');
    expect(JSON.parse(runtimeStdin(spawnCalls))).to.deep.equal({
      content_keys: { 'pof.plugin-x': 'refreshed-key==' },
    });
  });

  it('TTL — révocation (revoked=true) : postMessage accountState loggedIn=false', async () => {
    const postedMessages = [];
    const refreshKeysIfStale = sinon.stub().resolves({ refreshed: false, revoked: true });
    const { handlers } = makeHandlers({
      fakeKeys: {},
      refreshKeysIfStaleStub: refreshKeysIfStale,
      captureMessages: postedMessages,
    });

    await handlers.hubLoadPluginState();

    const accountMsg = postedMessages.find((m) => m.type === 'accountState');
    expect(accountMsg).to.exist;
    expect(accountMsg.loggedIn).to.equal(false);
  });
});
