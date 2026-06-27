// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const EventEmitter = require('events');
const fs = require('fs');
const os = require('os');
const path = require('path');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('static analysis cancellation', () => {
  function makeCancellationToken() {
    let listener = null;
    return {
      isCancellationRequested: false,
      onCancellationRequested: sinon.stub().callsFake((cb) => {
        listener = cb;
        return { dispose: sinon.spy() };
      }),
      cancel() {
        this.isCancellationRequested = true;
        if (listener) listener();
      },
    };
  }

  it('terminates runCommand child process when the cancellation token fires', async () => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = sinon.spy();
    const spawn = sinon.stub().returns(child);
    const output = { appendLine: sinon.spy(), append: sinon.spy() };
    const token = makeCancellationToken();
    const { runCommand } = proxyquire('../src/shared/utils', {
      vscode: { window: { createOutputChannel: () => output } },
      child_process: { spawn },
    });

    const promise = runCommand('python3', ['slow.py'], '/tmp', output, {}, { cancelToken: token });
    token.cancel();
    child.emit('close', null);

    try {
      await promise;
      throw new Error('expected runCommand to reject after cancellation');
    } catch (err) {
      expect(String(err.message || err)).to.include('python3 cancelled');
    }
    expect(child.kill.calledWith('SIGTERM')).to.equal(true);
    expect(output.appendLine.calledWith('[cmd] cancelled: python3')).to.equal(true);
  });

  it('makes disassembly progress cancellable and passes the token to runCommand', async () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cancellable-analysis-'));
    const binaryPath = path.join(root, 'sample.elf');
    const tempDir = path.join(root, '.pile-ou-face');
    fs.writeFileSync(binaryPath, 'ELF');
    fs.mkdirSync(tempDir, { recursive: true });

    const token = makeCancellationToken();
    const progress = { report: sinon.spy() };
    let progressOptions = null;
    const vscode = {
      ProgressLocation: { Notification: 15 },
      window: {
        withProgress: sinon.stub().callsFake(async (opts, task) => {
          progressOptions = opts;
          return task(progress, token);
        }),
      },
    };
    const runCommand = sinon.stub().resolves();
    const { createAnalysisContext } = require('../src/static/hub/analysisContext');
    const ctx = createAnalysisContext({
      root,
      pythonExe: 'python3',
      logChannel: { appendLine: sinon.spy(), append: sinon.spy() },
      runCommand,
      runPythonJson: sinon.stub().resolves({ arch: 'x86_64' }),
      runPythonTextFile: sinon.stub(),
      resolvePathFromWorkspace: (value) => path.resolve(root, value),
      toWebviewPath: (value) => value,
      ensureTempDir: () => tempDir,
      getRawProfile: () => null,
      vscode,
      fs,
      path,
      crypto: require('crypto'),
      inspectBinaryInput: () => ({ supported: true, format: 'ELF' }),
      normalizeRawProfile: () => null,
      getRawArchDescriptor: () => ({}),
      readCache: sinon.stub(),
      writeCache: sinon.stub(),
      getDisasmScript: () => path.join(root, 'disasm.py'),
      getHeadersScript: () => path.join(root, 'headers.py'),
      getSymbolsScript: () => path.join(root, 'symbols.py'),
      getOffsetToVaddrScript: () => path.join(root, 'offset.py'),
      getDiscoverFunctionsScript: () => path.join(root, 'discover.py'),
      getExampleCandidates: () => [],
      normalizeAddress: (value) => value,
    });

    await ctx.ensureDisasmArtifacts({
      binaryPath,
      emitProgress: true,
      progressTitle: 'Analyse annulable',
    });

    expect(progressOptions).to.include({
      title: 'Analyse annulable',
      cancellable: true,
    });
    const streamHooks = runCommand.firstCall.args[5];
    expect(streamHooks.cancelToken).to.equal(token);
    token.cancel();
    expect(progress.report.lastCall.args[0].message).to.equal('Annulation…');

    fs.rmSync(root, { recursive: true, force: true });
  });
});
