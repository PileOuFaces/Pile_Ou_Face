// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-002 : pythonPath ne vient que d'une sélection native vérifiée comme Python 3.
const { expect } = require('chai');
const sinon = require('sinon');
const { selectPythonExecutable, verifyPythonExecutable } = require('../shared/pythonPathSelection');

const PYTHON = '/opt/pof venv/bin/python3';
const fileStat = () => ({ isFile: () => true });
const probeReturning = (stdout) => sinon.stub().callsFake((_exe, _args, _opts, callback) => callback(null, stdout, ''));

describe('verifyPythonExecutable', () => {
  it('accepts a Python 3 interpreter and probes it without a shell', async () => {
    const execFile = probeReturning('3\n');
    expect(await verifyPythonExecutable(PYTHON, { execFile, statSync: fileStat })).to.deep.equal({ ok: true, path: PYTHON });
    expect(execFile.firstCall.args[0]).to.equal(PYTHON);
    expect(execFile.firstCall.args[1][0]).to.equal('-c');
    expect(execFile.firstCall.args[2].timeout).to.be.a('number');
  });

  it('rejects relative paths and non-Python file names without running them', async () => {
    const execFile = probeReturning('3');
    for (const candidate of ['python3', '/bin/sh', '/usr/bin/curl']) {
      const result = await verifyPythonExecutable(candidate, { execFile, statSync: fileStat });
      expect(result.ok, candidate).to.equal(false);
    }
    expect(execFile.called).to.equal(false);
  });

  it('rejects directories, Python 2 and files that cannot run', async () => {
    const directory = { isFile: () => false };
    expect((await verifyPythonExecutable(PYTHON, { execFile: probeReturning('3'), statSync: () => directory })).ok).to.equal(false);
    expect((await verifyPythonExecutable(PYTHON, { execFile: probeReturning('2'), statSync: fileStat })).ok).to.equal(false);
    const failing = sinon.stub().callsFake((_exe, _args, _opts, callback) => callback(new Error('ENOEXEC'), '', ''));
    const result = await verifyPythonExecutable(PYTHON, { execFile: failing, statSync: fileStat });
    expect(result.ok).to.equal(false);
    expect(result.error).to.contain('ENOEXEC');
  });
});

describe('selectPythonExecutable', () => {
  const vscodeWith = (picked) => ({
    window: { showOpenDialog: sinon.stub().resolves(picked) },
    Uri: { file: (fsPath) => ({ fsPath }) },
  });

  it('uses the native file picker', async () => {
    const vscode = vscodeWith([{ fsPath: PYTHON }]);
    const result = await selectPythonExecutable(vscode, { execFile: probeReturning('3'), statSync: fileStat });
    expect(vscode.window.showOpenDialog.calledOnce).to.equal(true);
    expect(vscode.window.showOpenDialog.firstCall.args[0]).to.include({ canSelectFiles: true, canSelectMany: false });
    expect(result).to.deep.equal({ ok: true, path: PYTHON });
  });

  it('reports a cancelled selection', async () => {
    expect(await selectPythonExecutable(vscodeWith(undefined))).to.deep.equal({ ok: false, cancelled: true });
  });
});
