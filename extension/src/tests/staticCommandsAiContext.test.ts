// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const proxyquire = require('proxyquire').noCallThru();
const sinon = require('sinon');

describe('static commands AI disassembly context', () => {
  function createDocument(lines, filePath = '/tmp/sample.disasm.asm') {
    return {
      uri: { fsPath: filePath },
      lineAt: (index) => ({ text: lines[index] || '' }),
      getText: (selection) => selection.selectedText || '',
    };
  }

  it('extracts the active instruction and enclosing function', () => {
    const { getDisasmSelectionContext } = require('../src/static/commands');
    const document = createDocument([
      'main:',
      '  0x401000:  55                   push     rbp',
      '  0x401001:  48 89 e5             mov      rbp, rsp',
    ]);
    const selection = {
      active: { line: 2 },
      selectedText: '',
    };

    expect(getDisasmSelectionContext(document, selection)).to.deep.equal({
      addr: '0x401001',
      functionName: 'main',
      instructionText: '0x401001:  48 89 e5             mov      rbp, rsp',
    });
  });

  it('opens the AI dashboard with binary, address and selected code', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-ai-disasm-'));
    const disasmPath = path.join(tempDir, 'sample.disasm.asm');
    const mappingPath = path.join(tempDir, 'sample.disasm.mapping.json');
    fs.writeFileSync(disasmPath, 'main:\n  0x401000:  55  push rbp\n');
    fs.writeFileSync(mappingPath, JSON.stringify({ binary: '/tmp/sample.elf' }));

    const registeredCommands = new Map();
    const openHub = sinon.stub();
    const vscodeStub = {
      commands: {
        registerCommand: sinon.stub().callsFake((id, handler) => {
          registeredCommands.set(id, handler);
          return { dispose() {} };
        }),
      },
      window: {
        activeTextEditor: {
          document: createDocument([
            'main:',
            '  0x401000:  55                   push     rbp',
          ], disasmPath),
          selection: {
            active: { line: 1 },
            selectedText: '',
          },
        },
        showWarningMessage: sinon.stub(),
      },
    };
    const { registerStaticCommands } = proxyquire('../src/static/commands', {
      vscode: vscodeStub,
      child_process: {},
      '../shared/paths': {
        getDisasmScript: () => '',
        getXrefsScript: () => '',
      },
    });

    registerStaticCommands(
      {},
      { ensureTempDir: () => tempDir, runCommand: sinon.stub(), logChannel: {} },
      { root: tempDir, pythonExe: 'python3', openHub },
    );
    await registeredCommands.get('pileOuFace.askAiAboutDisasm')();

    expect(openHub.calledOnce).to.equal(true);
    expect(openHub.firstCall.args[0]).to.equal('dashboard');
    expect(openHub.firstCall.args[1].aiPrompt).to.include('Binaire : /tmp/sample.elf');
    expect(openHub.firstCall.args[1].aiPrompt).to.include('Fonction : main');
    expect(openHub.firstCall.args[1].aiPrompt).to.include('Adresse active : 0x401000');
    expect(openHub.firstCall.args[1].aiPrompt).to.include('push     rbp');

    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});
