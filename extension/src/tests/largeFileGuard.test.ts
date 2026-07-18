// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const { confirmOpenLargeTextFile } = require('../shared/largeFileGuard');

function makeVscodeStub(response) {
  return { window: { showWarningMessage: sinon.stub().resolves(response) } };
}

describe('largeFileGuard', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-large-file-guard-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('allows opening a small file without prompting', async () => {
    const filePath = path.join(dir, 'small.asm');
    fs.writeFileSync(filePath, 'hello');
    const vscode = makeVscodeStub('Ouvrir quand même');
    const ok = await confirmOpenLargeTextFile(filePath, { fs, vscode, warnBytes: 10 * 1024 * 1024 });
    expect(ok).to.equal(true);
    expect(vscode.window.showWarningMessage.called).to.equal(false);
  });

  it('prompts and allows opening a large file when the user confirms', async () => {
    const filePath = path.join(dir, 'big.asm');
    fs.writeFileSync(filePath, Buffer.alloc(2048));
    const vscode = makeVscodeStub('Ouvrir quand même');
    const ok = await confirmOpenLargeTextFile(filePath, { fs, vscode, warnBytes: 1024 });
    expect(ok).to.equal(true);
    expect(vscode.window.showWarningMessage.calledOnce).to.equal(true);
  });

  it('declines opening a large file when the user dismisses the prompt', async () => {
    const filePath = path.join(dir, 'big2.asm');
    fs.writeFileSync(filePath, Buffer.alloc(2048));
    const vscode = makeVscodeStub(undefined);
    const ok = await confirmOpenLargeTextFile(filePath, { fs, vscode, warnBytes: 1024 });
    expect(ok).to.equal(false);
  });

  it('does not prompt again for a path already confirmed this session', async () => {
    const filePath = path.join(dir, 'big3.asm');
    fs.writeFileSync(filePath, Buffer.alloc(2048));
    const vscode = makeVscodeStub('Ouvrir quand même');
    await confirmOpenLargeTextFile(filePath, { fs, vscode, warnBytes: 1024 });
    const ok = await confirmOpenLargeTextFile(filePath, { fs, vscode, warnBytes: 1024 });
    expect(ok).to.equal(true);
    expect(vscode.window.showWarningMessage.calledOnce).to.equal(true);
  });

  it('allows opening when the file does not exist (nothing to guard)', async () => {
    const vscode = makeVscodeStub(undefined);
    const ok = await confirmOpenLargeTextFile(path.join(dir, 'missing.asm'), { fs, vscode, warnBytes: 1024 });
    expect(ok).to.equal(true);
    expect(vscode.window.showWarningMessage.called).to.equal(false);
  });
});
