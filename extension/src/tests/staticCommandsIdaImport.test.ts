// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('static command IDA import', () => {
  function setup(sourcePath) {
    const registered = new Map();
    const showOpenDialog = sinon.stub();
    showOpenDialog.onFirstCall().resolves([{ fsPath: sourcePath }]);
    showOpenDialog.onSecondCall().resolves([{ fsPath: '/tmp/sample.elf' }]);
    const execFile = sinon.stub().callsFake((_python, _args, _options, callback) => {
      callback(null, JSON.stringify({ imported: 2, skipped: 1, conflicts: 0 }));
    });
    const vscodeStub = {
      commands: { registerCommand: sinon.stub().callsFake((id, handler) => {
        registered.set(id, handler);
        return { dispose() {} };
      }) },
      window: {
        activeTextEditor: null,
        showOpenDialog,
        showInformationMessage: sinon.stub(),
        showErrorMessage: sinon.stub(),
      },
    };
    const { registerStaticCommands } = proxyquire('../static/commands', {
      vscode: vscodeStub,
      child_process: { execFile },
      '../shared/paths': { getDisasmScript: () => '', getXrefsScript: () => '' },
      '../shared/utils': { getExtensionPath: () => '/extension' },
    });
    registerStaticCommands(
      {},
      { ensureTempDir: () => '/tmp', storageDir: '/storage', runCommand: sinon.stub(), logChannel: {} },
      { root: '/workspace', pythonExe: 'python3', refreshSidebar: sinon.stub() },
    );
    return { handler: registered.get('pileOuFace.importFromIda'), execFile };
  }

  it('routes an IDAPython JSON export to the shared canonical importer', async () => {
    const { handler, execFile } = setup('/tmp/ida.json');
    await handler();
    expect(execFile.firstCall.args[1]).to.include('/extension/backends/static/annotations/canonical_import.py');
    expect(execFile.firstCall.args[1]).to.include('--input');
  });

  it('routes an i64 database to the direct best-effort adapter', async () => {
    const { handler, execFile } = setup('/tmp/database.i64');
    await handler();
    expect(execFile.firstCall.args[1]).to.include('/extension/backends/static/annotations/idb_import.py');
    expect(execFile.firstCall.args[1]).to.include('--idb');
  });
});
