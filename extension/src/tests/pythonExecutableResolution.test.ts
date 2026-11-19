// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-012 (suite, #519) : le réglage pythonPath est respecté partout où Python est lancé.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const proxyquire = require('proxyquire');
const utils = require('../shared/utils');

const SETTINGS_KEY = 'pof-settings';
// Chemin avec espaces : vérifie qu'il est transmis tel quel, sans découpage.
const CONFIGURED_PYTHON = path.join(os.tmpdir(), 'pof python env', 'bin', 'python3');
const EXTENSION_ROOT = path.resolve(__dirname, '../..');

const storeWith = (settings) => ({ get: (key, fallback) => (key === SETTINGS_KEY ? settings : fallback) });
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

  const loadHandlers = (globalState) => {
    execFile = sinon.stub();
    const captureBridge = (name) => (options) => { bridgeOptions[name] = options; return {}; };
    const sharedHandlers = proxyquire('../shared/sharedHandlers', {
      vscode: { window: {}, Uri: { file: (value) => ({ fsPath: value }) } },
      child_process: { execFile },
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

  beforeEach(() => {
    vscode = require('vscode');
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
  afterEach(() => sinon.restore());

  const openHubWith = (globalState) => {
    const { createHub } = proxyquire('../static/hub', {
      '../shared/webview': { getHubContent: () => '<!doctype html>' },
      './handlers': { createHandlers: () => ({}) },
    });
    const detectPythonExecutable = sinon.spy(utils.detectPythonExecutable);
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
      detectPythonExecutable,
      ensureStaticAsm: sinon.stub().returns({ ok: true }),
      readTraceJson: sinon.stub(),
      writeTraceJson: sinon.spy(),
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview: sinon.spy(),
    })();
    return detectPythonExecutable;
  };

  it('resolves the configured pythonPath', () => {
    const detect = openHubWith(CONFIGURED_STORE);
    expect(detect.called).to.equal(true);
    expect(detect.firstCall.returnValue).to.equal(CONFIGURED_PYTHON);
  });

  it('keeps the current detection without a setting', () => {
    const detect = openHubWith(EMPTY_STORE);
    expect(detect.firstCall.returnValue).to.equal(utils.detectPythonExecutable(detect.firstCall.args[0]));
  });
});

describe('extension activation Python executable', () => {
  // activate() wires the whole extension; this guards the call sites statically.
  const source = fs.readFileSync(path.join(__dirname, '..', 'extension.ts'), 'utf8');

  it('registers the settings store and resolves Python through the setting', () => {
    expect(source).to.match(/setSettingsStore\(context\.globalState\)/);
    expect(source).to.not.match(/detectPythonExecutable\(root\)/);
    expect(source.match(/resolvePythonExecutable\(root, context\.globalState\)/g)).to.have.length(2);
  });
});
