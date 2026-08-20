// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('static command Ghidra import', () => {
  it('selects an export and binary, runs the canonical importer, then refreshes', async () => {
    const registeredCommands = new Map();
    const showOpenDialog = sinon.stub();
    showOpenDialog.onFirstCall().resolves([{ fsPath: '/tmp/export.json' }]);
    showOpenDialog.onSecondCall().resolves([{ fsPath: '/tmp/sample.elf' }]);
    const showInformationMessage = sinon.stub();
    const execFile = sinon.stub().callsFake((_python, _args, _options, callback) => {
      callback(null, JSON.stringify({ imported: 3, skipped: 1, conflicts: 2 }));
    });
    const refreshSidebar = sinon.stub();
    const vscodeStub = {
      commands: {
        registerCommand: sinon.stub().callsFake((id, handler) => {
          registeredCommands.set(id, handler);
          return { dispose() {} };
        }),
      },
      window: {
        activeTextEditor: null,
        showOpenDialog,
        showInformationMessage,
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
      { root: '/workspace', pythonExe: 'python3', refreshSidebar },
    );
    await registeredCommands.get('pileOuFace.importFromGhidra')();

    expect(execFile.calledOnce).to.equal(true);
    expect(execFile.firstCall.args[1]).to.deep.equal([
      '/extension/backends/static/annotations/canonical_import.py',
      '--binary', '/tmp/sample.elf',
      '--input', '/tmp/export.json',
      '--workspace-root', '/storage',
    ]);
    expect(refreshSidebar.calledOnceWith('/tmp/sample.elf')).to.equal(true);
    expect(showInformationMessage.firstCall.args[0]).to.include('3 importé(s), 1 ignoré(s), 2 conflit(s)');
  });
});
