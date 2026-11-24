// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-012 (suite, #519) : le réglage pythonPath est respecté partout où Python est lancé.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const utils = require('../shared/utils');

const { SETTINGS_STATE_KEY: SETTINGS_KEY, PYTHON_PATH_ATTESTATION_KEY } = require('../shared/settingsSchema');
// Chemin avec espaces : vérifie qu'il est transmis tel quel, sans découpage.
const CONFIGURED_PYTHON = path.join(os.tmpdir(), 'pof python env', 'bin', 'python3');
const EXTENSION_ROOT = path.resolve(__dirname, '../..');

// Le pythonPath configuré est attesté, comme après une sélection native (POF-P1-002).
const liveStoreFor = (read) => ({
  get: (key, fallback) => {
    if (key === SETTINGS_KEY) return read();
    if (key === PYTHON_PATH_ATTESTATION_KEY) return CONFIGURED_PYTHON;
    return fallback;
  },
});
const storeWith = (settings) => liveStoreFor(() => settings);
const EMPTY_STORE = storeWith({});
const CONFIGURED_STORE = storeWith({ pythonPath: CONFIGURED_PYTHON });

describe('resolvePythonExecutable (utils)', () => {
  let previousExtensionPath;
  beforeEach(() => { previousExtensionPath = utils.getExtensionPath(); });
  afterEach(() => {
    utils.setExtensionPath(previousExtensionPath);
    utils.setSettingsStore(null);
  });

  it('returns the configured pythonPath', () => {
    expect(utils.resolvePythonExecutable('/repo', CONFIGURED_STORE)).to.equal(CONFIGURED_PYTHON);
  });

  it('keeps the current detection without a setting', () => {
    for (const store of [EMPTY_STORE, storeWith({ pythonPath: '   ' }), undefined]) {
      expect(utils.resolvePythonExecutable('/repo', store))
        .to.equal(utils.detectPythonExecutable('/repo'));
    }
  });

  it('uses the store registered at activation when none is given', () => {
    utils.setSettingsStore(CONFIGURED_STORE);
    expect(utils.resolvePythonExecutable('/repo')).to.equal(CONFIGURED_PYTHON);
  });

  it('falls back to detection when the store cannot be read', () => {
    const brokenStore = { get: () => { throw new Error('state unavailable'); } };
    expect(utils.resolvePythonExecutable('/repo', brokenStore))
      .to.equal(utils.detectPythonExecutable('/repo'));
  });
});

describe('staticCache Python executable', () => {
  const loadCache = (spawnSync) => proxyquire('../shared/staticCache', { child_process: { spawnSync } });
  let storageDir;
  let binaryPath;
  let previousExtensionPath;

  beforeEach(() => {
    previousExtensionPath = utils.getExtensionPath();
    utils.setExtensionPath(EXTENSION_ROOT);
    storageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cache-python-'));
    binaryPath = path.join(storageDir, 'sample.bin');
    fs.writeFileSync(binaryPath, 'binary');
  });
  afterEach(() => {
    utils.setExtensionPath(previousExtensionPath);
    utils.setSettingsStore(null);
    fs.rmSync(storageDir, { recursive: true, force: true });
  });

  it('launches the configured pythonPath', () => {
    utils.setSettingsStore(CONFIGURED_STORE);
    const spawnSync = sinon.stub().returns({ status: 0, stdout: '{"found":false}' });
    loadCache(spawnSync).readCache(storageDir, binaryPath, 'info');
    expect(spawnSync.calledOnce).to.equal(true);
    expect(spawnSync.firstCall.args[0]).to.equal(CONFIGURED_PYTHON);
  });

  it('keeps the current detection without a setting', () => {
    const spawnSync = sinon.stub().returns({ status: 0, stdout: '{"found":false}' });
    loadCache(spawnSync).readCache(storageDir, binaryPath, 'info');
    expect(spawnSync.firstCall.args[0]).to.equal(utils.detectPythonExecutable(EXTENSION_ROOT));
  });
});

describe('sharedHandlers Python executable', () => {
  const ROOT = '/repo';
  const bridgeOptions = {};
  let execFile;

  let spawn;
  const fakeProcess = () => {
    const { PassThrough } = require('stream');
    const proc = new (require('events').EventEmitter)();
    Object.assign(proc, { stdout: new PassThrough(), stderr: new PassThrough(), stdin: new PassThrough(), kill: () => {} });
    return proc;
  };
  const loadHandlers = (globalState) => {
    execFile = sinon.stub().callsFake(() => ({ stdin: { write: () => {}, end: () => {} } }));
    spawn = sinon.stub().callsFake(fakeProcess);
    const captureBridge = (name) => (options) => { bridgeOptions[name] = options; return {}; };
    const sharedHandlers = proxyquire('../shared/sharedHandlers', {
      vscode: { window: {}, Uri: { file: (value) => ({ fsPath: value }) } },
      child_process: { execFile, spawn },
      './annotationsBridge': { makeAnnotationsBridge: captureBridge('annotations') },
      './chatHistoryBridge': { makeChatHistoryBridge: captureBridge('chatHistory') },
      './patchHistoryBridge': { makePatchHistoryBridge: captureBridge('patchHistory') },
    });
    return sharedHandlers({
      root: ROOT,
      panel: { webview: { postMessage: () => {} } },
      context: { globalState },
    });
  };

  afterEach(() => utils.setSettingsStore(null));

  it('passes the configured pythonPath to every bridge and AI handler', () => {
    const handlers = loadHandlers(CONFIGURED_STORE);
    for (const name of ['annotations', 'chatHistory', 'patchHistory']) {
      expect(bridgeOptions[name].getPythonExecutable(), name).to.equal(CONFIGURED_PYTHON);
    }
    handlers.hubAiProvidersGet();
    expect(execFile.firstCall.args[0]).to.equal(CONFIGURED_PYTHON);
  });

  // Every AI handler that starts Python, with a message it accepts.
  const AI_HANDLER_CALLS = [
    ['hubAiProvidersGet', {}],
    ['hubAiProviderSet', { provider: 'openai', api_key: 'k', model: 'm' }],
    ['hubAiProviderTest', { provider: 'openai' }],
    ['hubAiProviderDefaultSet', { provider: 'openai' }],
    ['hubAiProviderPrompt', { requestId: 'r1', provider: 'openai', model: 'm' }],
  ];
  const launchedPython = () => (execFile.called ? execFile.firstCall.args[0] : spawn.firstCall.args[0]);

  for (const [handlerName, message] of AI_HANDLER_CALLS) {
    it(`${handlerName}: runs the attested pythonPath, then a newly saved one without recreating the hub`, () => {
      let saved = { pythonPath: CONFIGURED_PYTHON };
      const handlers = loadHandlers(liveStoreFor(() => saved));
      handlers[handlerName](message);
      expect(launchedPython()).to.equal(CONFIGURED_PYTHON);

      // Same handlers object (hub still open): the next launch reads the setting again.
      saved = {};
      execFile.resetHistory();
      spawn.resetHistory();
      handlers[handlerName](message);
      expect(launchedPython()).to.equal(utils.detectPythonExecutable(ROOT));
    });

    it(`${handlerName}: never runs a pythonPath that no native selection attested`, () => {
      const unattested = path.join(os.tmpdir(), 'injected', 'bin', 'python3');
      const handlers = loadHandlers(storeWith({ pythonPath: unattested }));
      handlers[handlerName](message);
      expect(launchedPython()).to.not.equal(unattested);
      expect(launchedPython()).to.equal(utils.detectPythonExecutable(ROOT));
    });
  }

  it('keeps the current detection without a setting', () => {
    const handlers = loadHandlers(EMPTY_STORE);
    const detected = utils.detectPythonExecutable(ROOT);
    for (const name of ['annotations', 'chatHistory', 'patchHistory']) {
      expect(bridgeOptions[name].getPythonExecutable(), name).to.equal(detected);
    }
    handlers.hubAiProvidersGet();
    expect(execFile.firstCall.args[0]).to.equal(detected);
  });
});

describe('hub Python executable', () => {
  let vscode;
  let previous;

  beforeEach(() => {
    vscode = require('vscode');
    // Shared vscode mock: everything changed below is restored after each test.
    previous = {
      ViewColumn: vscode.ViewColumn,
      Uri: vscode.Uri,
      workspaceFolders: vscode.workspace.workspaceFolders,
      onDidChangeTextEditorSelection: vscode.window.onDidChangeTextEditorSelection,
      createWebviewPanel: vscode.window.createWebviewPanel,
    };
    vscode.ViewColumn = { Beside: 2 };
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: '/repo' } }];
    vscode.Uri = { file: (p) => ({ fsPath: p, scheme: 'file' }) };
    vscode.window.onDidChangeTextEditorSelection = sinon.stub().returns({ dispose: () => {} });
    vscode.window.createWebviewPanel = sinon.stub().returns({
      disposed: false,
      reveal: sinon.spy(),
      onDidDispose: sinon.stub().returns({ dispose: () => {} }),
      webview: {
        html: '',
        postMessage: sinon.spy(),
        onDidReceiveMessage: sinon.stub().returns({ dispose: () => {} }),
      },
    });
  });
  afterEach(() => {
    vscode.ViewColumn = previous.ViewColumn;
    vscode.Uri = previous.Uri;
    vscode.workspace.workspaceFolders = previous.workspaceFolders;
    vscode.window.onDidChangeTextEditorSelection = previous.onDidChangeTextEditorSelection;
    vscode.window.createWebviewPanel = previous.createWebviewPanel;
    sinon.restore();
  });

  const HUB_ROOT = '/repo';
  const PROBE_SCRIPT = path.join(HUB_ROOT, 'probe.py');

  // Ouvre le hub et renvoie une fonction qui déclenche un lancement Python réel
  // (runPythonJson) puis renvoie l'exécutable reçu par child_process.execFile.
  const openHubWith = (globalState) => {
    const execFile = sinon.stub();
    const { createAnalysisContext } = require('../static/hub/analysisContext');
    let analysisCtx = null;
    const { createHub } = proxyquire('../static/hub', {
      child_process: { execFile },
      '../shared/webview': { getHubContent: () => '<!doctype html>' },
      './handlers': { createHandlers: () => ({}) },
      './hub/analysisContext': {
        createAnalysisContext: (ctx) => { analysisCtx = ctx; return createAnalysisContext(ctx); },
      },
    });
    createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { ...globalState, update: async () => {} },
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand: sinon.stub(),
      detectPythonExecutable: utils.detectPythonExecutable,
      ensureStaticAsm: sinon.stub().returns({ ok: true }),
      readTraceJson: sinon.stub(),
      writeTraceJson: sinon.spy(),
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview: sinon.spy(),
    })();
    expect(analysisCtx, 'analysis context').to.not.equal(null);
    return () => {
      execFile.resetHistory();
      // La promesse ne se résout jamais (execFile est un stub) : seul l'appel compte.
      analysisCtx.runPythonJson(PROBE_SCRIPT, []);
      const launch = execFile.getCalls().find((call) => call.args[1]?.[0] === PROBE_SCRIPT);
      expect(launch, 'runPythonJson launch').to.not.equal(undefined);
      return launch.args[0];
    };
  };
  const launchedPythonFor = (globalState) => openHubWith(globalState)();

  it('launches the configured pythonPath', () => {
    expect(launchedPythonFor(CONFIGURED_STORE)).to.equal(CONFIGURED_PYTHON);
  });

  it('keeps the current detection without a setting', () => {
    expect(launchedPythonFor(EMPTY_STORE))
      .to.equal(utils.detectPythonExecutable(utils.resolveProjectRoot(HUB_ROOT)));
  });

  it('uses a pythonPath saved while the hub is open for the next analysis', async () => {
    const state = new Map();
    const liveStore = { get: (key, fallback) => (state.has(key) ? state.get(key) : fallback) };
    const launchAnalysis = openHubWith(liveStore);
    expect(launchAnalysis()).to.equal(utils.detectPythonExecutable(utils.resolveProjectRoot(HUB_ROOT)));

    // Enregistrement par le vrai handler (réglage + attestation), hub toujours ouvert.
    const { createSettingsActions } = require('../static/hub/settingsActions');
    const settingsActions = createSettingsActions({
      panel: { webview: { postMessage: () => {} } },
      context: { globalState: { ...liveStore, update: async (key, value) => { state.set(key, value); } } },
      vscode: { window: { showErrorMessage: () => {} } },
      root: HUB_ROOT,
      logChannel: { appendLine: () => {} },
      selectPythonExecutable: async () => ({ ok: true, path: CONFIGURED_PYTHON }),
    });
    await settingsActions.hubSelectPythonPath({ requestId: 1 });

    expect(launchAnalysis()).to.equal(CONFIGURED_PYTHON);
  });
});

describe('extension activation Python executable', () => {
  let vscode;
  let previousVscode;
  let previousExtensionPath;
  let workspaceDir;
  let extension;
  let ensurePythonDependencies;
  let staticProviders;

  beforeEach(() => {
    vscode = require('vscode');
    previousVscode = {
      folders: vscode.workspace.workspaceFolders,
      onDidChangeConfiguration: vscode.workspace.onDidChangeConfiguration,
    };
    previousExtensionPath = utils.getExtensionPath();
    workspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-activate-python-'));
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: workspaceDir } }];
    vscode.workspace.onDidChangeConfiguration = () => ({ dispose: () => {} });
  });
  afterEach(() => {
    extension?._unregisterGlobalErrorHandlers();
    vscode.workspace.workspaceFolders = previousVscode.folders;
    vscode.workspace.onDidChangeConfiguration = previousVscode.onDidChangeConfiguration;
    utils.setExtensionPath(previousExtensionPath);
    utils.setSettingsStore(null);
    fs.rmSync(workspaceDir, { recursive: true, force: true });
  });

  // Exécute le vrai activate() en neutralisant le câblage sans rapport avec Python.
  const activateWith = (globalState, update = async () => {}) => {
    ensurePythonDependencies = sinon.stub().resolves();
    staticProviders = null;
    extension = proxyquire('../extension', {
      './shared/utils': { ensurePythonDependencies, ensureStorageDir: () => workspaceDir },
      './shared/telemetry/telemetry': { initializeExtensionTelemetry: () => ({}) },
      './shared/runtimeAudit': { configureRuntimeAudit: () => {} },
      './shared/productConfig': { getProductConfig: () => ({}) },
      './shared/authConfig': {
        planLegacyAuthUrlMigration: () => ({ removeLegacy: false }),
        resolveAuthServerUrl: () => '',
      },
      './shared/authService': { AuthService: { getInstance: () => ({ refresh: async () => {} }) } },
      './dynamic/visualizer': { createVisualizer: () => () => {} },
      './static/hub': { createHub: () => () => {} },
      './shared/commands': { registerSharedCommands: () => [] },
      './static/commands': {
        registerStaticCommands: (_ctx, _deps, providers) => { staticProviders = providers; return []; },
      },
      './static/decompilerCommands': { registerDecompilerCommands: () => [] },
      './shared/mcpSetupBridge': { makeMcpSetupBridge: () => ({}) },
      './static/mcpAgentsPanel': { createMcpAgentsPanel: () => ({}) },
      './static/mcpAgentCommands': {
        registerMcpAgentCommands: () => [],
        createMcpStatusBarItem: () => ({ dispose: () => {} }),
      },
    });
    extension.activate({
      extensionPath: EXTENSION_ROOT,
      globalState: { ...globalState, update },
      subscriptions: [],
      secrets: {},
    });
  };

  it('prepares Python dependencies with the configured pythonPath', () => {
    activateWith(CONFIGURED_STORE);
    expect(ensurePythonDependencies.calledOnce).to.equal(true);
    expect(ensurePythonDependencies.firstCall.args[0]).to.equal(CONFIGURED_PYTHON);
    expect(staticProviders.getPythonExe()).to.equal(CONFIGURED_PYTHON);
  });

  it('keeps the current detection without a setting', () => {
    activateWith(EMPTY_STORE);
    const detected = utils.detectPythonExecutable(utils.resolveProjectRoot(workspaceDir));
    expect(ensurePythonDependencies.calledOnce).to.equal(true);
    expect(ensurePythonDependencies.firstCall.args[0]).to.equal(detected);
    expect(staticProviders.getPythonExe()).to.equal(detected);
  });

  it('applies a pythonPath saved after activation without reloading', () => {
    let saved = {};
    activateWith(liveStoreFor(() => saved));
    saved = { pythonPath: CONFIGURED_PYTHON };
    expect(staticProviders.getPythonExe()).to.equal(CONFIGURED_PYTHON);
  });

  it('migrates saved settings at activation', () => {
    const update = sinon.stub().resolves();
    activateWith(storeWith({ lang: 'en', legacyFlag: true, pythonPath: 'sh -c evil' }), update);
    expect(update.calledWith(SETTINGS_KEY, { lang: 'en' })).to.equal(true);
    const detected = utils.detectPythonExecutable(utils.resolveProjectRoot(workspaceDir));
    expect(ensurePythonDependencies.firstCall.args[0]).to.equal(detected);
  });

  it('never runs a well-formed legacy pythonPath that no native selection attested', () => {
    const update = sinon.stub().resolves();
    const legacyPython = path.join(os.tmpdir(), 'pof legacy', 'bin', 'python3');
    activateWith(storeWith({ lang: 'en', pythonPath: legacyPython }), update);
    expect(update.calledWith(SETTINGS_KEY, { lang: 'en' })).to.equal(true);
    const detected = utils.detectPythonExecutable(utils.resolveProjectRoot(workspaceDir));
    expect(ensurePythonDependencies.firstCall.args[0]).to.equal(detected);
    expect(staticProviders.getPythonExe()).to.equal(detected);
  });
});
