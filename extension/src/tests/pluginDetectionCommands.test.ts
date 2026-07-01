const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const proxyquire = require('proxyquire').noCallThru();

describe('hub detection plugin commands', () => {
  let tempRoot;
  let vscode;
  let panel;
  let onMessage;
  let createHub;
  let existsSyncStub;
  let statSyncStub;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-detection-'));
    vscode = require('vscode');
    vscode.ViewColumn = { Beside: 2 };
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: '/repo' } }];
    vscode.window.showErrorMessage = sinon.stub();
    vscode.window.showWarningMessage = sinon.stub();
    vscode.window.showInformationMessage = sinon.stub();
    vscode.window.onDidChangeTextEditorSelection = sinon.stub().returns({ dispose: () => {} });
    vscode.workspace.createFileSystemWatcher = sinon.stub().returns({
      onDidChange: () => {},
      onDidCreate: () => {},
      onDidDelete: () => {},
      dispose: () => {},
    });

    onMessage = null;
    panel = {
      disposed: false,
      reveal: sinon.spy(),
      onDidDispose: sinon.stub().returns({ dispose: () => {} }),
      webview: {
        html: '',
        postMessage: sinon.spy(),
        onDidReceiveMessage: sinon.stub().callsFake((handler) => {
          onMessage = handler;
          return { dispose: () => {} };
        }),
      },
    };
    vscode.window.createWebviewPanel = sinon.stub().returns(panel);
    vscode.Uri = { file: (p) => ({ fsPath: p, scheme: 'file' }) };

    const originalExistsSync = fs.existsSync.bind(fs);
    existsSyncStub = sinon.stub(fs, 'existsSync').callsFake((targetPath) => (
      targetPath === '/repo/bin/demo.bin'
        || targetPath === '/repo/rules/demo.yar'
        || originalExistsSync(targetPath)
    ));
    const originalStatSync = fs.statSync.bind(fs);
    statSyncStub = sinon.stub(fs, 'statSync').callsFake((targetPath) => {
      if (String(targetPath).startsWith(tempRoot)) {
        return originalStatSync(targetPath);
      }
      return {
        isDirectory: () => false,
        isFile: () => true,
        mtimeMs: 0,
      };
    });
  });

  afterEach(() => {
    sinon.restore();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  function buildHubWithExec(execFile, options = {}) {
    const repoRoot = options.repoRoot || '/repo';
    const storageRoot = options.storageRoot || path.join(repoRoot, '.state');
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: repoRoot } }];
    ({ createHub } = proxyquire('../static/hub', {
      child_process: { execFile },
      '../shared/webview': {
        getHubContent: () => '<!doctype html>',
      },
      './handlers': {
        createHandlers: () => ({}),
      },
      '../shared/sharedHandlers': {
        isSupportedBinary: () => true,
        inspectBinaryInput: () => ({ supported: true, format: 'ELF' }),
        getRawArchDescriptor: () => ({ arch: 'i386:x86-64' }),
        normalizeRawProfile: (value) => value || null,
      },
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} },
        globalStorageUri: { fsPath: storageRoot },
      },
      storageDir: storageRoot,
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand: async () => {},
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm: () => ({ ok: true }),
      readTraceJson: () => ({}),
      writeTraceJson: () => {},
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview: () => {},
    });

    openHub();
  }

  it('routes YARA scans through the malware plugin runtime command', async () => {
    const execFile = sinon.stub().callsFake((cmd, args, opts, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: true,
          result: {
            matches: [{ rule: 'demo', matches: [{ offset: '0x10' }] }],
          },
        }),
        '',
      );
    });
    buildHubWithExec(execFile);

    await onMessage({
      type: 'hubYaraScan',
      binaryPath: '/repo/bin/demo.bin',
      rulesPath: '/repo/rules/demo.yar',
      binaryMeta: { format: 'ELF' },
    });

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.include.members([
      '/repo/backends/plugins/runtime.py',
      'invoke',
      'malware.yara.run',
    ]);
    const message = panel.webview.postMessage.firstCall.args[0];
    expect(message).to.deep.equal({
      type: 'hubYara',
      matches: [{ rule: 'demo', matches: [{ offset: '0x10' }] }],
      error: undefined,
    });
  });

  it('returns a plugin required payload when the CAPA command is unavailable', async () => {
    const execFile = sinon.stub().callsFake((cmd, args, opts, callback) => {
      callback(
        null,
        JSON.stringify({
          ok: false,
          error: 'Commande plugin introuvable: malware.capa.run',
          command: 'malware.capa.run',
          available_commands: [],
        }),
        '',
      );
    });
    buildHubWithExec(execFile);

    await onMessage({
      type: 'hubCapaScan',
      binaryPath: '/repo/bin/demo.bin',
      binaryMeta: { format: 'ELF' },
    });

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.include.members([
      '/repo/backends/plugins/runtime.py',
      'invoke',
      'malware.capa.run',
    ]);
    const message = panel.webview.postMessage.firstCall.args[0];
    expect(message).to.deep.equal({
      type: 'hubCapa',
      capabilities: [],
      error: 'Commande plugin introuvable: malware.capa.run',
    });
  });

  it('builds a library YARA bundle from enabled project and global rules', async () => {
    const repoRoot = path.join(tempRoot, 'repo');
    const storageRoot = path.join(tempRoot, 'state');
    fs.mkdirSync(path.join(repoRoot, 'bin'), { recursive: true });
    fs.mkdirSync(path.join(repoRoot, '.pile-ou-face', 'rules', 'yara'), { recursive: true });
    fs.mkdirSync(path.join(storageRoot, 'rules', 'yara'), { recursive: true });
    fs.writeFileSync(path.join(repoRoot, 'bin', 'demo.bin'), Buffer.from('demo'));
    fs.writeFileSync(path.join(repoRoot, '.pile-ou-face', 'rules', 'yara', 'project_rule.yar'), 'rule ProjectRule { condition: true }');
    fs.writeFileSync(path.join(storageRoot, 'rules', 'yara', 'global_rule.yar'), 'rule GlobalRule { condition: true }');

    const execFile = sinon.stub().callsFake((cmd, args, opts, callback) => {
      if (args.some((arg) => String(arg).endsWith('rules_manager.py'))) {
        callback(
          null,
          JSON.stringify({
            rules: [
              {
                id: 'user:yara:project_rule.yar',
                type: 'yara',
                scope: 'project',
                enabled: true,
                path: path.join(repoRoot, '.pile-ou-face', 'rules', 'yara', 'project_rule.yar'),
              },
              {
                id: 'global:yara:global_rule.yar',
                type: 'yara',
                scope: 'global',
                enabled: true,
                path: path.join(storageRoot, 'rules', 'yara', 'global_rule.yar'),
              },
            ],
          }),
          '',
        );
        return;
      }
      const payloadArgIndex = args.indexOf('--payload-json');
      const payload = JSON.parse(args[payloadArgIndex + 1]);
      callback(
        null,
        JSON.stringify({
          ok: true,
          result: {
            matches: [],
            resolvedRulesPath: payload.rulesPath,
          },
        }),
        '',
      );
    });
    buildHubWithExec(execFile, { repoRoot, storageRoot });

    await onMessage({
      type: 'hubYaraScan',
      binaryPath: path.join(repoRoot, 'bin', 'demo.bin'),
      rulesMode: 'library',
      binaryMeta: { format: 'ELF' },
    });

    expect(execFile.callCount).to.equal(2);
    const runtimeArgs = execFile.secondCall.args[1];
    expect(runtimeArgs).to.include.members([
      path.join(repoRoot, 'backends/plugins/runtime.py'),
      'invoke',
      'malware.yara.run',
    ]);
    const payloadArgIndex = runtimeArgs.indexOf('--payload-json');
    const payload = JSON.parse(runtimeArgs[payloadArgIndex + 1]);
    expect(fs.statSync(payload.rulesPath).isDirectory()).to.equal(true);
    expect(fs.readdirSync(payload.rulesPath).sort()).to.have.members([
      '01__project_rule.yar',
      '02__global_rule.yar',
    ]);
  });
});
