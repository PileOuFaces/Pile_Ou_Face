const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const sinon = require('sinon');
const proxyquire = require('proxyquire');

describe('hub runTrace isolation', () => {
  let vscode;
  let panel;
  let onMessage;
  let createHub;
  let runCommand;
  let readTraceJson;
  let writeTraceJson;
  let openVisualizerWebview;
  let ensureStaticAsm;
  let existsSyncStub;
  let readdirSyncStub;
  let statSyncStub;
  let unlinkSyncStub;
  let outputPaths;

  const flush = () => new Promise((resolve) => setImmediate(resolve));

  beforeEach(() => {
    const realExistsSync = fs.existsSync.bind(fs);
    const realReaddirSync = fs.readdirSync.bind(fs);
    const realStatSync = fs.statSync.bind(fs);
    vscode = require('vscode');
    vscode.ViewColumn = { Beside: 2 };
    vscode.ProgressLocation = { Notification: 15 };
    vscode.workspace.workspaceFolders = [{ uri: { fsPath: '/repo' } }];
    vscode.window.showErrorMessage = sinon.stub();
    vscode.window.showWarningMessage = sinon.stub();
    vscode.window.showInformationMessage = sinon.stub();
    vscode.window.onDidChangeTextEditorSelection = sinon.stub().returns({ dispose: () => {} });
    vscode.window.withProgress = sinon.stub().callsFake(async (_opts, task) => task({ report: () => {} }));

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
        })
      }
    };
    vscode.window.createWebviewPanel = sinon.stub().returns(panel);
    vscode.Uri = { file: (p) => ({ fsPath: p, scheme: 'file' }) };

    outputPaths = new Set();
    outputPaths.add('/tmp/pof');
    existsSyncStub = sinon.stub(fs, 'existsSync').callsFake((targetPath) => (
      String(targetPath).startsWith('/tmp/pof')
        ? outputPaths.has(targetPath)
        : realExistsSync(targetPath)
    ));
    readdirSyncStub = sinon.stub(fs, 'readdirSync').callsFake((targetPath, ...args) => (
      String(targetPath) === '/tmp/pof'
        ? []
        : realReaddirSync(targetPath, ...args)
    ));
    statSyncStub = sinon.stub(fs, 'statSync').callsFake((targetPath, ...args) => {
      if (String(targetPath).startsWith('/tmp/pof')) {
        const normalized = String(targetPath);
        return {
          mtimeMs: 0,
          isFile: () => outputPaths.has(normalized) && normalized !== '/tmp/pof',
          isDirectory: () => normalized === '/tmp/pof'
        };
      }
      return realStatSync(targetPath, ...args);
    });
    unlinkSyncStub = sinon.stub(fs, 'unlinkSync').callsFake((targetPath) => {
      outputPaths.delete(targetPath);
    });

    runCommand = sinon.stub().callsFake(async (_command, args) => {
      const outputFlagIndex = args.indexOf('--output');
      const outputPath = outputFlagIndex >= 0 ? args[outputFlagIndex + 1] : '';
      return new Promise((resolve) => {
        outputPaths.add(`pending:${outputPath}`);
        outputPaths.add(outputPath);
        resolve();
      });
    });

    readTraceJson = sinon.stub().callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: targetPath.includes('run-2-') ? 'latest' : 'stale' }],
      risks: [],
      meta: { output_path: targetPath }
    }));
    writeTraceJson = sinon.spy();
    openVisualizerWebview = sinon.spy();
    ensureStaticAsm = sinon.stub().returns({ ok: true });

    ({ createHub } = proxyquire('../static/hub', {
      '../shared/webview': {
        getHubContent: () => '<!doctype html>'
      },
      './handlers': {
        createHandlers: () => ({})
      }
    }));
  });

  afterEach(() => {
    sinon.restore();
  });

  it('ignores an older runTrace result when a newer run finishes first', async () => {
    const pendingRuns = [];
    runCommand.callsFake(async (_command, args) => {
      const outputFlagIndex = args.indexOf('--output');
      const outputPath = outputFlagIndex >= 0 ? args[outputFlagIndex + 1] : '';
      return new Promise((resolve) => {
        pendingRuns.push({
          outputPath,
          resolve: () => {
            outputPaths.add(outputPath);
            resolve();
          }
        });
      });
    });

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    const firstRun = onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'static',
        sourcePath: 'examples/demo_analysis.c'
      }
    });
    const secondRun = onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'static',
        sourcePath: 'examples/demo_analysis.c'
      }
    });

    expect(pendingRuns).to.have.length(2);
    expect(pendingRuns[0].outputPath).to.not.equal(pendingRuns[1].outputPath);
    expect(path.basename(pendingRuns[0].outputPath)).to.match(/^output\.run-1-/);
    expect(path.basename(pendingRuns[1].outputPath)).to.match(/^output\.run-2-/);

    pendingRuns[1].resolve();
    await secondRun;
    await flush();

    expect(readTraceJson.calledOnceWithExactly(pendingRuns[1].outputPath)).to.equal(true);
    expect(writeTraceJson.calledTwice).to.equal(true);
    expect(writeTraceJson.firstCall.args[0]).to.equal(pendingRuns[1].outputPath);
    expect(writeTraceJson.secondCall.args[0]).to.equal('/tmp/pof/output.json');
    expect(openVisualizerWebview.calledOnce).to.equal(true);
    expect(openVisualizerWebview.firstCall.args[0].meta.output_path).to.equal(pendingRuns[1].outputPath);
    expect(openVisualizerWebview.firstCall.args[0].meta.trace_run_id).to.equal(2);

    pendingRuns[0].resolve();
    await firstRun;
    await flush();

    expect(readTraceJson.calledOnce).to.equal(true);
    expect(writeTraceJson.calledTwice).to.equal(true);
    expect(openVisualizerWebview.calledOnce).to.equal(true);

    const doneMessages = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .filter((message) => message?.type === 'runTraceDone');
    expect(doneMessages).to.have.length(1);
  });

  it('routes auto payloads to stdin when the C source reads stdin', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme1.elf').returns(true);
    existsSyncStub.withArgs('/repo/examples/rootme1.c').returns(true);

    const realReadFileSync = fs.readFileSync.bind(fs);
    sinon.stub(fs, 'readFileSync').callsFake((targetPath, ...args) => {
      if (String(targetPath) === '/repo/examples/rootme1.c') {
        return 'int main(void) { char buf[40]; fgets(buf, 45, stdin); }';
      }
      return realReadFileSync(targetPath, ...args);
    });

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      const outputFlagIndex = args.indexOf('--output');
      const outputPath = outputFlagIndex >= 0 ? args[outputFlagIndex + 1] : '';
      outputPaths.add(outputPath);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: (input) => String(input || ''),
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme1.elf',
        sourcePath: 'examples/rootme1.c',
        payloadExpr: 'A*44',
        payloadTargetMode: 'auto',
        injectPayload: true
      }
    });

    expect(capturedArgs).to.be.an('array');
    expect(capturedArgs[capturedArgs.indexOf('--stdin') + 1]).to.equal('A*44');
    expect(capturedArgs).to.not.include('--argv1');
    expect(writeTraceJson.firstCall.args[1].meta.payload_target).to.equal('stdin');
    expect(writeTraceJson.firstCall.args[1].meta.payload_label).to.equal('stdin');
  });

  it('does not restore a previous C source into runTrace init automatically', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme2.elf').returns(true);
    outputPaths.add('/tmp/pof/output.json');

    const realReadFileSync = fs.readFileSync.bind(fs);
    sinon.stub(fs, 'readFileSync').callsFake((targetPath, ...args) => {
      if (String(targetPath) === '/tmp/pof/output.json') {
        return JSON.stringify({
          snapshots: [],
          risks: [],
          meta: {
            binary: 'examples/rootme2.elf',
            source: 'examples/rootme2.c',
            source_enrichment: {
              sourcePath: 'examples/rootme2.c',
              enabled: true,
              status: 'partial',
              message: 'Code source détecté — enrichissement partiel.'
            }
          }
        });
      }
      return realReadFileSync(targetPath, ...args);
    });

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([
          { name: 'main', type: 'T' },
          { name: '__isoc23_scanf@GLIBC_2.38', type: 'U' }
        ]));
        return;
      }
      callback(null, '{}');
    });

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: (input) => String(input || ''),
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'requestRunTraceInit',
      binaryPath: 'examples/rootme2.elf',
      sourcePath: '',
      payloadTargetMode: 'auto'
    });

    const initMessage = panel.webview.postMessage.lastCall.args[0];
    expect(initMessage.type).to.equal('initRunTrace');
    expect(initMessage.sourcePath).to.equal('');
    expect(initMessage.sourceEnrichmentEnabled).to.equal(false);
    expect(initMessage.sourceEnrichmentMessage).to.equal('');
    expect(initMessage.payloadTargetEffective).to.equal('stdin');
    expect(initMessage.payloadTargetReason).to.contain('scanf import');
  });

  it('does not auto-select a sibling C source for payload target routing', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme2.elf').returns(true);
    existsSyncStub.withArgs('/repo/examples/rootme2.c').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      outputPaths.add(args[args.indexOf('--output') + 1]);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: (input) => String(input || ''),
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme2.elf',
        payloadExpr: 'A*264',
        payloadTargetMode: 'auto',
        injectPayload: true
      }
    });

    expect(capturedArgs).to.include('--argv1');
    expect(capturedArgs[capturedArgs.indexOf('--argv1') + 1]).to.equal('A*264');
    expect(capturedArgs[capturedArgs.indexOf('--stdin') + 1]).to.equal('');
    expect(writeTraceJson.firstCall.args[1].meta.payload_target).to.equal('argv1');
  });

  it('routes auto payloads to stdin from binary imports without C source', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme2.elf').returns(true);
    existsSyncStub.withArgs('/repo/examples/rootme2.c').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([
          { name: 'main', type: 'T' },
          { name: '__isoc23_scanf@GLIBC_2.38', type: 'U' }
        ]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      outputPaths.add(args[args.indexOf('--output') + 1]);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: (input) => String(input || ''),
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme2.elf',
        payloadExpr: 'A*264',
        payloadTargetMode: 'auto',
        injectPayload: true
      }
    });

    expect(capturedArgs).to.include('--stdin');
    expect(capturedArgs[capturedArgs.indexOf('--stdin') + 1]).to.equal('A*264');
    expect(capturedArgs).to.not.include('--argv1');
    expect(writeTraceJson.firstCall.args[1].meta.payload_target).to.equal('stdin');
    expect(writeTraceJson.firstCall.args[1].meta.payload_target_reason).to.contain('scanf import');
  });

  it('includes analysisByStep in dynamicTraceReady, the same field the standalone visualizer gets via init', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme2.elf').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main', type: 'T' }]));
        return;
      }
      callback(null, '{}');
    });

    const analysisByStepFixture = {
      '1': {
        frame: { slots: [], basePointer: '0x1000', stackPointer: '0xff8', frameSize: 0x70 },
        control: { savedBpAddr: '0x1000', retAddrAddr: '0x1008' }
      }
    };

    runCommand.callsFake(async (_command, args) => {
      outputPaths.add(args[args.indexOf('--output') + 1]);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath },
      analysisByStep: analysisByStepFixture
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: (input) => String(input || ''),
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme2.elf',
        payloadTargetMode: 'auto'
      }
    });

    const dynamicTraceReadyMessage = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .find((message) => message.type === 'dynamicTraceReady');

    expect(dynamicTraceReadyMessage).to.exist;
    expect(dynamicTraceReadyMessage.binaryPath).to.equal('examples/rootme2.elf');
    expect(dynamicTraceReadyMessage.analysisByStep).to.deep.equal(analysisByStepFixture);
    const runTraceDoneMessage = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .find((message) => message.type === 'runTraceDone');
    expect(runTraceDoneMessage).to.deep.equal({
      type: 'runTraceDone',
      binaryPath: 'examples/rootme2.elf',
    });
  });

  it('passes generated payload bytes through stdin-hex and persists input meta', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme1.elf').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      const outputPath = args[args.indexOf('--output') + 1];
      outputPaths.add(outputPath);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme1.elf',
        payloadExpr: '\\x41\\x42\\x43\\x44',
        payloadTargetMode: 'stdin',
        injectPayload: true,
        input: {
          mode: 'exploit_helper',
          template: 'overwrite_variable',
          targetMode: 'stdin',
          payloadBytesHex: '41424344',
          sourceFields: { offset: '0', value: '0x44434241' },
          generatedSnippet: 'payload = b"ABCD"',
          size: 4,
          previewHex: '41424344',
          previewAscii: 'ABCD',
          warnings: []
        }
      }
    });

    expect(capturedArgs).to.include('--stdin-hex');
    expect(capturedArgs[capturedArgs.indexOf('--stdin-hex') + 1]).to.equal('41424344');
    const writtenTrace = writeTraceJson.firstCall.args[1];
    expect(writtenTrace.meta.input.mode).to.equal('exploit_helper');
    expect(writtenTrace.meta.input.template).to.equal('overwrite_variable');
    expect(writtenTrace.meta.input.previewHex).to.equal('41424344');
  });

  it('accepts payload_builder mode and keeps builder metadata', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme1.elf').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      const outputPath = args[args.indexOf('--output') + 1];
      outputPaths.add(outputPath);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme1.elf',
        payloadExpr: '\\x41\\x41\\x41\\x41\\x41\\x41\\x41\\x41',
        payloadTargetMode: 'stdin',
        injectPayload: true,
        input: {
          mode: 'payload_builder',
          targetMode: 'stdin',
          payloadBytesHex: '4141414141414141',
          sourceFields: { input: 'A*8', builderLevel: 'beginner' },
          generatedSnippet: 'from pwn import *\npayload = b"A" * 8',
          size: 8,
          previewHex: '4141414141414141',
          previewAscii: 'AAAAAAAA',
          warnings: []
        }
      }
    });

    expect(capturedArgs).to.include('--stdin-hex');
    expect(capturedArgs[capturedArgs.indexOf('--stdin-hex') + 1]).to.equal('4141414141414141');
    const writtenTrace = writeTraceJson.firstCall.args[1];
    expect(writtenTrace.meta.input.mode).to.equal('payload_builder');
    expect(writtenTrace.meta.input.builderLevel).to.equal('beginner');
    expect(writtenTrace.meta.input.sourceFields.input).to.equal('A*8');
  });

  it('accepts pwntools_script mode and keeps capture metadata', async () => {
    existsSyncStub.withArgs('/repo/examples/rootme1.elf').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      const outputPath = args[args.indexOf('--output') + 1];
      outputPaths.add(outputPath);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/rootme1.elf',
        payloadTargetMode: 'stdin',
        injectPayload: true,
        input: {
          mode: 'pwntools_script',
          targetMode: 'stdin',
          payloadBytesHex: '4142430a',
          sourceFileName: 'solve.py',
          selectedCaptureKind: 'sendlineafter',
          target: 'stdin',
          sourceFields: { captureId: 'cap-1' },
          generatedSnippet: 'from pwn import *\nio.sendline(payload)',
          size: 4,
          previewHex: '4142430a',
          previewAscii: 'ABC.',
          warnings: []
        }
      }
    });

    expect(capturedArgs).to.include('--stdin-hex');
    expect(capturedArgs[capturedArgs.indexOf('--stdin-hex') + 1]).to.equal('4142430a');
    const writtenTrace = writeTraceJson.firstCall.args[1];
    expect(writtenTrace.meta.input.mode).to.equal('pwntools_script');
    expect(writtenTrace.meta.input.sourceFileName).to.equal('solve.py');
    expect(writtenTrace.meta.input.selectedCaptureKind).to.equal('sendlineafter');
  });

  it('passes file mode as argv1 plus virtual-file mapping', async () => {
    existsSyncStub.withArgs('/repo/examples/my_vm1').returns(true);
    existsSyncStub.withArgs('/repo/input.vm').returns(true);

    sinon.stub(cp, 'execFile').callsFake((_cmd, args, _opts, callback) => {
      const script = String(args?.[0] || '');
      if (script.includes('headers')) {
        callback(null, JSON.stringify({ format: 'ELF', bits: 64, type: 'EXEC' }));
        return;
      }
      if (script.includes('symbols')) {
        callback(null, JSON.stringify([{ name: 'main' }]));
        return;
      }
      callback(null, '{}');
    });

    let capturedArgs = null;
    runCommand.callsFake(async (_command, args) => {
      capturedArgs = args;
      const outputPath = args[args.indexOf('--output') + 1];
      outputPaths.add(outputPath);
    });
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: { output_path: targetPath, virtual_file_warnings: [] }
    }));

    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    openHub();

    await onMessage({
      type: 'runTrace',
      config: {
        traceMode: 'dynamic',
        useExistingBinary: true,
        binaryPath: 'examples/my_vm1',
        input: {
          mode: 'file',
          targetMode: 'argv1',
          sourceFields: { source: 'path', guestPath: '/tmp/pof-input.txt', hostPath: '/repo/input.vm' },
          size: 0,
          warnings: []
        },
        file: {
          source: 'path',
          guestPath: '/tmp/pof-input.txt',
          hostPath: '/repo/input.vm',
          passAs: 'argv1'
        }
      }
    });

    expect(capturedArgs).to.include('--argv1');
    expect(capturedArgs[capturedArgs.indexOf('--argv1') + 1]).to.equal('/tmp/pof-input.txt');
    expect(capturedArgs).to.include('--virtual-file');
    expect(capturedArgs[capturedArgs.indexOf('--virtual-file') + 1]).to.equal('/tmp/pof-input.txt=/repo/input.vm');
    const writtenTrace = writeTraceJson.firstCall.args[1];
    expect(writtenTrace.meta.input.mode).to.equal('file');
    expect(writtenTrace.meta.input.file.guestPath).to.equal('/tmp/pof-input.txt');
  });

  it('lists and deletes historical trace artifacts without touching output.json', async () => {
    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      storageDir: '/tmp/pof',
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    outputPaths.add('/tmp/pof/output.run-1-a.json');
    outputPaths.add('/tmp/pof/output.run-1-a.disasm.asm');
    outputPaths.add('/tmp/pof/output.run-2-b.json');
    outputPaths.add('/tmp/pof/output.run-2-b.disasm.asm');
    outputPaths.add('/tmp/pof/output.json');
    readdirSyncStub.returns([
      'output.run-1-a.json',
      'output.run-2-b.json',
      'output.json'
    ]);
    statSyncStub.callsFake((targetPath) => ({
      mtimeMs: targetPath.includes('run-2-') ? 200 : 100
    }));
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: {
        output_path: targetPath,
        trace_run_id: targetPath.includes('run-2-') ? 2 : 1,
        binary: '/repo/examples/stack3_strcpy..elf',
        argv1: targetPath.includes('run-2-') ? 'BBBB' : 'AAAA',
        start_symbol: 'main'
      }
    }));

    openHub();

    await onMessage({ type: 'requestDynamicTraceHistory' });

    const historyMessage = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .find((message) => message?.type === 'dynamicTraceHistory');

    expect(historyMessage).to.not.equal(undefined);
    expect(historyMessage.items.map((item) => item.runId)).to.deep.equal([2, 1]);

    await onMessage({ type: 'deleteDynamicTraceHistory', tracePath: '/tmp/pof/output.run-2-b.json' });

    expect(unlinkSyncStub.calledWithExactly('/tmp/pof/output.run-2-b.json')).to.equal(true);
    expect(unlinkSyncStub.calledWithExactly('/tmp/pof/output.run-2-b.disasm.asm')).to.equal(true);
    expect(unlinkSyncStub.neverCalledWith('/tmp/pof/output.json')).to.equal(true);
  });

  it('reveals the active historical trace instead of reopening it', async () => {
    const revealCurrentTrace = sinon.stub().returns(true);
    openVisualizerWebview = Object.assign(sinon.spy(), { revealCurrentTrace });
    const tracePath = '/tmp/pof/output.run-1-a.json';
    const openHub = createHub({
      context: {
        extensionUri: {},
        subscriptions: [],
        workspaceState: { get: () => ({}), update: async () => {} },
        globalState: { get: () => ({}), update: async () => {} }
      },
      storageDir: '/tmp/pof',
      logChannel: { appendLine: () => {}, append: () => {} },
      getTempDir: () => '/tmp/pof',
      ensureTempDir: () => '/tmp/pof',
      runCommand,
      detectPythonExecutable: () => '/usr/bin/python3',
      ensureStaticAsm,
      readTraceJson,
      writeTraceJson,
      setViewMode: () => {},
      payloadToHex: () => '',
      parseStdinExpression: () => '',
      check32BitToolchain: () => ({ ok: true }),
      openVisualizerWebview
    });

    outputPaths.add(tracePath);
    outputPaths.add('/tmp/pof/output.run-1-a.disasm.asm');
    readdirSyncStub.returns(['output.run-1-a.json']);
    readTraceJson.callsFake((targetPath) => ({
      snapshots: [{ step: 1, func: 'main' }],
      risks: [],
      meta: {
        output_path: targetPath,
        trace_run_id: 1,
        binary: '/repo/examples/stack3_strcpy..elf',
        start_symbol: 'main'
      }
    }));

    openHub();

    await onMessage({ type: 'openDynamicTraceHistory', tracePath });
    expect(openVisualizerWebview.calledOnce).to.equal(true);
    expect(readTraceJson.calledWithExactly(tracePath)).to.equal(true);
    expect(writeTraceJson.calledOnce).to.equal(true);

    readTraceJson.resetHistory();
    writeTraceJson.resetHistory();
    openVisualizerWebview.resetHistory();

    await onMessage({ type: 'openDynamicTraceHistory', tracePath });

    expect(revealCurrentTrace.calledOnce).to.equal(true);
    expect(openVisualizerWebview.notCalled).to.equal(true);
    expect(readTraceJson.notCalled).to.equal(true);
    expect(writeTraceJson.notCalled).to.equal(true);
    const historyMessages = panel.webview.postMessage.getCalls()
      .map((call) => call.args[0])
      .filter((message) => message?.type === 'dynamicTraceHistory');
    expect(historyMessages[historyMessages.length - 1].activeTracePath).to.equal(tracePath);
  });
});
