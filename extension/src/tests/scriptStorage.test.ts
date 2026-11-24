// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scriptFileName, saveScript } = require('../static/scriptStorage');

describe('hub script storage (hubSaveScript)', () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pof-scripts-'));

  it('keeps simple names and adds .py when missing', () => {
    expect(scriptFileName('exploit.py')).to.deep.equal({ ok: true, value: 'exploit.py' });
    expect(scriptFileName(' my script ')).to.deep.equal({ ok: true, value: 'my script.py' });
  });

  for (const name of ['../../.bashrc', '..', '/etc/passwd', 'a/b.py', 'a\\b.py', '.hidden', '', 'x\u0000.py', 'C:evil.py', ['a.py'], 'a'.repeat(200)]) {
    it(`refuses the name ${JSON.stringify(name).slice(0, 40)}`, () => {
      expect(scriptFileName(name).ok).to.equal(false);
    });
  }

  it('writes inside the scripts folder only', () => {
    const base = tmp();
    const dir = path.join(base, 'scripts');
    const result = saveScript(dir, 'demo', 'print(1)\n');
    expect(result).to.deep.equal({ ok: true, value: path.join(dir, 'demo.py') });
    expect(fs.readFileSync(path.join(dir, 'demo.py'), 'utf8')).to.equal('print(1)\n');
    expect(saveScript(dir, '../../.bashrc', 'x').ok).to.equal(false);
    expect(fs.existsSync(path.join(base, '.bashrc'))).to.equal(false);
  });

  it('refuses non-text and oversized content', () => {
    const dir = path.join(tmp(), 'scripts');
    expect(saveScript(dir, 'a.py', { toString: () => 'x' }).ok).to.equal(false);
    expect(saveScript(dir, 'a.py', 'x'.repeat(1024 * 1024 + 1)).ok).to.equal(false);
  });

  it('replaces a symlink planted at the script name instead of writing through it', function () {
    if (process.platform === 'win32') this.skip();
    const base = tmp();
    const dir = path.join(base, 'scripts');
    fs.mkdirSync(dir);
    const victim = path.join(base, 'victim');
    fs.writeFileSync(victim, 'keep');
    fs.symlinkSync(victim, path.join(dir, 'a.py'));
    saveScript(dir, 'a.py', 'print(2)\n');
    expect(fs.readFileSync(victim, 'utf8')).to.equal('keep');
    expect(fs.lstatSync(path.join(dir, 'a.py')).isSymbolicLink()).to.equal(false);
  });
});
