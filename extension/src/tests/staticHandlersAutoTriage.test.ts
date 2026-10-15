// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const { EventEmitter } = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { PassThrough } = require('stream');
const proxyquire = require('proxyquire').noCallThru();

function createHarness(options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-auto-triage-test-'));
  const storageDir = path.join(root, 'storage');
  fs.mkdirSync(storageDir, { recursive: true });
  const binaryPath = path.join(root, 'sample.bin');
  fs.writeFileSync(binaryPath, 'binary');
  fs.writeFileSync(path.join(storageDir, 'sample.disasm.mapping.json'), '{}');
  const posted = [];
  const state = new Map();
  const updates = [];
  const proc = new EventEmitter();
  proc.stdout = new PassThrough();
  proc.stderr = new PassThrough();
  proc.kill = () => true;
  let spawnArgs = null;
  const destination = path.join(root, 'export.md');

  const values = {
    'pileOuFace:autoTriage.model': 'openai@gpt-test',
    'pileOuFace.autoTriage:maxFunctions': 12,
    'pileOuFace.autoTriage:maxSeconds': 90,
    'pileOuFace.autoTriage:maxTokensPerRequest': 1024,
    'pileOuFace.autoTriage:maxTotalTokens': 9000,
  };
  const vscode = {
    env: { language: 'fr' },
    ViewColumn: { Beside: 2 },
    Uri: { file: (fsPath) => ({ fsPath }) },
    workspace: {
      getConfiguration(section) {
        return {
          get(key, fallback) { return values[`${section}:${key}`] ?? fallback; },
          inspect() { return {}; },
        };
      },
      openTextDocument: async (uri) => uri,
    },
    window: {
      showErrorMessage() {},
      showInformationMessage() {},
      showWarningMessage: async () => 'Autoriser',
      showSaveDialog: async () => ({ fsPath: destination }),
      showTextDocument: async () => {},
    },
  };
  const childProcess = {
    execFile(_python, _args, _config, callback) {
      callback(null, JSON.stringify({ consented: true }), '');
    },
    spawn(_python, args) {
      spawnArgs = args;
      return proc;
    },
  };
  const staticHandlers = proxyquire('../static/staticHandlers', {
    vscode,
    child_process: childProcess,
    '../shared/utils': {
      detectPythonExecutable: () => '/usr/bin/python3',
      buildRuntimeEnv: () => ({ POF_DEFAULT_AI_PROVIDER: 'ollama', OLLAMA_MODEL: 'fallback' }),
      logDebug() {},
      logWarning() {},
    },
    './pluginState': { emptyPluginUiState: () => ({}), summarizePluginRuntimeState: (value) => value },
    '../shared/authService': { AuthService: class {} },
    '../shared/authConfig': { resolveAuthServerUrl: () => 'http://localhost' },
  });
  const context = {
    extensionPath: root,
    globalState: {
      get(key, fallback) { return state.has(key) ? state.get(key) : fallback; },
      update(key, value) { state.set(key, value); updates.push([key, value]); },
    },
  };
  const handlers = staticHandlers({
    root,
    storageDir,
    globalDir: storageDir,
    panel: { webview: { postMessage: (message) => posted.push(message) } },
    context,
  });
  return {
    root, storageDir, binaryPath, posted, state, updates, proc, destination, handlers,
    get spawnArgs() { return spawnArgs; },
    cleanup() { fs.rmSync(root, { recursive: true, force: true }); },
  };
}

describe('staticHandlers auto-triage', () => {
  it('returns configured preflight information and availability', async () => {
    const app = createHarness();
    try {
      await app.handlers.hubAutoTriagePreflight({ binaryPath: app.binaryPath });
      expect(app.posted.at(-1)).to.deep.include({
        type: 'hubAutoTriagePreflight',
        available: true,
        provider: 'openai',
        model: 'gpt-test',
        maxFunctions: 12,
        maxSeconds: 90,
        maxTokens: 1024,
        maxTotalTokens: 9000,
      });
    } finally { app.cleanup(); }
  });

  it('rejects a missing binary before spawning Python', async () => {
    const app = createHarness();
    try {
      await app.handlers.hubAutoTriageStart({ requestId: 'bad', binaryPath: '/missing.bin' });
      expect(app.posted.at(-1)).to.include({
        type: 'hubAutoTriageDone', requestId: 'bad', ok: false, error: 'Binaire introuvable.',
      });
      expect(app.spawnArgs).to.equal(null);
    } finally { app.cleanup(); }
  });

  it('spawns with configured budgets and persists a successful report', async () => {
    const app = createHarness();
    try {
      await app.handlers.hubAutoTriageStart({ requestId: 'run-1', binaryPath: app.binaryPath });
      expect(app.spawnArgs).to.include.members([
        '--provider', 'openai', '--model', 'gpt-test',
        '--max-functions', '12', '--max-seconds', '90',
        '--max-tokens', '1024', '--max-total-tokens', '9000',
      ]);
      app.proc.stdout.write(`${JSON.stringify({ type: 'selection_done', model: 'gpt-resolved' })}\n`);
      app.proc.stdout.write(`${JSON.stringify({ type: 'done', stats: { processed: 3, tokens_used: 42 } })}\n`);
      app.proc.stdout.end();
      app.proc.emit('close', 0);

      const done = app.posted.find((message) => message.type === 'hubAutoTriageDone');
      expect(done).to.include({ requestId: 'run-1', binaryPath: app.binaryPath, ok: true });
      const results = app.state.get('pof.autoTriage.results');
      expect(results[app.binaryPath]).to.deep.include({ provider: 'openai', model: 'gpt-resolved' });
      expect(results[app.binaryPath].stats).to.deep.equal({ processed: 3, tokens_used: 42 });
    } finally { app.cleanup(); }
  });

  it('returns persisted report metadata and exports the Markdown file', async () => {
    const app = createHarness();
    try {
      const reportPath = path.join(app.root, 'report.md');
      fs.writeFileSync(reportPath, '# report');
      app.state.set('pof.autoTriage.reports', { [app.binaryPath]: reportPath });
      app.state.set('pof.autoTriage.results', { [app.binaryPath]: { completedAt: '2026-07-31' } });

      await app.handlers.hubAutoTriageGetReport({ binaryPath: app.binaryPath });
      expect(app.posted.at(-1)).to.deep.equal({
        type: 'hubAutoTriageReportInfo',
        binaryPath: app.binaryPath,
        reportPath,
        result: { completedAt: '2026-07-31' },
      });
      await app.handlers.hubAutoTriageExportReport({ reportPath });
      expect(fs.readFileSync(app.destination, 'utf8')).to.equal('# report');
    } finally { app.cleanup(); }
  });
});
