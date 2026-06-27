const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('buildPluginRuntimeEnv — MODE selection', () => {
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
      child_process: { execFile: execFileStub },
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

    const staticHandlers = proxyquire('../src/static/staticHandlers', proxyStubs);
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

    return { handlers, execFileStub };
  }

  // -------------------------------------------------------------------------
  // MODE 1 — online keys available
  // -------------------------------------------------------------------------

  it('MODE 1 — online keys present: BINHOST flag is set and keys are injected', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'base64key==', 'pof.audit-pro': 'anotherkey==' },
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.have.property('POF_CONTENT_KEY_POF_PLUGIN_X', 'base64key==');
    expect(env).to.have.property('POF_CONTENT_KEY_POF_AUDIT_PRO', 'anotherkey==');
  });

  it('MODE 1 priority — online keys + license files present: online wins, flag is set', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'key==' },
      licenseFiles: ['pof.plugin-x.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
  });

  // -------------------------------------------------------------------------
  // MODE 3 — no online keys, offline license files present
  // -------------------------------------------------------------------------

  it('MODE 3 — no online keys + .license.json files: BINHOST flag is absent', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: {},
      licenseFiles: ['pof.plugin-x.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.not.have.property('BINHOST_DISABLE_LICENSE_FALLBACK');
  });

  it('MODE 3 — AuthService throws + license files: BINHOST flag is absent', async () => {
    const { handlers, execFileStub } = makeHandlers({
      authThrows: true,
      licenseFiles: ['pof.audit-pro.license.json', 'pof.cross-analysis.license.json'],
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.not.have.property('BINHOST_DISABLE_LICENSE_FALLBACK');
  });

  it('MODE 3 — only .license.json files count, not other files', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: {},
      licenseFiles: ['README.md', 'install.sh', 'notes.txt'],
    });

    await handlers.hubLoadPluginState();

    // No .license.json → locked, not MODE 3
    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
  });

  // -------------------------------------------------------------------------
  // Locked — no online keys, no license files
  // -------------------------------------------------------------------------

  it('Locked — no online keys + no license files: BINHOST flag is set', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: {},
      licenseFiles: [],
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    // No content keys injected
    const keyVars = Object.keys(env).filter((k) => k.startsWith('POF_CONTENT_KEY_'));
    expect(keyVars).to.have.length(0);
  });

  it('Locked — AuthService throws + no license files: BINHOST flag is set', async () => {
    const { handlers, execFileStub } = makeHandlers({
      authThrows: true,
      licenseFiles: [],
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
  });

  // -------------------------------------------------------------------------
  // Plugin ID normalisation
  // -------------------------------------------------------------------------

  it('plugin IDs with hyphens and dots are normalised to underscores in env var names', async () => {
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: { 'pof.cross-analysis-pro': 'mykey==' },
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('POF_CONTENT_KEY_POF_CROSS_ANALYSIS_PRO', 'mykey==');
  });

  // -------------------------------------------------------------------------
  // TTL — refresh stale keys
  // -------------------------------------------------------------------------

  it('TTL — refresh réussi : MODE 1 maintenu avec clés fraîches', async () => {
    const refreshKeysIfStale = sinon.stub().resolves({ refreshed: true, revoked: false });
    const { handlers, execFileStub } = makeHandlers({
      fakeKeys: { 'pof.plugin-x': 'refreshed-key==' },
      refreshKeysIfStaleStub: refreshKeysIfStale,
    });

    await handlers.hubLoadPluginState();

    const env = execFileStub.getCall(0).args[2].env;
    expect(env).to.have.property('BINHOST_DISABLE_LICENSE_FALLBACK', '1');
    expect(env).to.have.property('POF_CONTENT_KEY_POF_PLUGIN_X', 'refreshed-key==');
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
