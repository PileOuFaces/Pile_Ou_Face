// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cp = require('child_process');
const {
  baseCandidates, isSupportedVersion, findCompatibleBase, probeInterpreter, probeEnv, PROBE_SCRIPT,
} = require('../shared/pythonInterpreter');

describe('pythonInterpreter (#549)', () => {
  it('supports CPython 3.10 to 3.13 only', () => {
    expect(isSupportedVersion({ major: 3, minor: 9 })).to.equal(false);
    expect(isSupportedVersion({ major: 3, minor: 10 })).to.equal(true);
    expect(isSupportedVersion({ major: 3, minor: 13 })).to.equal(true);
    expect(isSupportedVersion({ major: 3, minor: 14 })).to.equal(false);
    expect(isSupportedVersion({ major: 4, minor: 0 })).to.equal(false);
  });

  it('tries explicit supported versions (newest first) before the generic names', () => {
    expect(baseCandidates('linux').map((c) => c.command)).to.deep.equal([
      'python3.13', 'python3.12', 'python3.11', 'python3.10', 'python3', 'python',
    ]);
    const win = baseCandidates('win32', { LOCALAPPDATA: 'C:\\Users\\André\\AppData\\Local', ProgramFiles: 'C:\\Program Files' });
    expect(win.map((c) => c.command)).to.deep.equal([
      'C:\\Users\\André\\AppData\\Local\\Programs\\Python\\Python313\\python.exe',
      'C:\\Program Files\\Python313\\python.exe',
      'C:\\Users\\André\\AppData\\Local\\Programs\\Python\\Python312\\python.exe',
      'C:\\Program Files\\Python312\\python.exe',
      'C:\\Users\\André\\AppData\\Local\\Programs\\Python\\Python311\\python.exe',
      'C:\\Program Files\\Python311\\python.exe',
      'C:\\Users\\André\\AppData\\Local\\Programs\\Python\\Python310\\python.exe',
      'C:\\Program Files\\Python310\\python.exe',
      'python',
      'python3',
    ]);
    // Never the py launcher: it can install a missing Python on demand, before any consent.
    expect(win.some((c) => /(^|\\)py(\.exe)?$/i.test(c.command))).to.equal(false);
  });

  it('returns the first supported interpreter and every interpreter seen', async () => {
    const replies = { python3: '3 15 darwin arm64 /opt/homebrew/bin/python3.15', 'python3.11': '3 11 darwin arm64 /usr/local/bin/python3.11' };
    const exec = async (file) => (replies[file] ? { ok: true, stdout: replies[file] } : { ok: false, stdout: '' });
    const { found, seen } = await findCompatibleBase('darwin', exec);
    expect(found.executable).to.equal('/usr/local/bin/python3.11');
    expect(seen.map((p) => p.executable)).to.deep.equal(['/usr/local/bin/python3.11']);
  });

  it('ignores interpreters that do not answer the probe', async () => {
    expect(await probeInterpreter({ command: 'x', args: [] }, async () => ({ ok: true, stdout: 'garbage' }))).to.equal(null);
    expect(await probeInterpreter({ command: 'x', args: [] }, async () => ({ ok: false, stdout: '' }))).to.equal(null);
  });

  it('keeps executable paths with spaces', async () => {
    const probe = await probeInterpreter({ command: 'x', args: [] }, async () => ({ ok: true, stdout: '3 12 win32 AMD64 C:\\Program Files\\Python312\\python.exe\r\n' }));
    expect(probe.executable).to.equal('C:\\Program Files\\Python312\\python.exe');
  });

  it('probes with UTF-8 output and without on-demand Python installation', () => {
    const env = probeEnv({ PATH: '/usr/bin', PYLAUNCHER_ALLOW_INSTALL: '1', PYTHON_MANAGER_AUTOMATIC_INSTALL: 'true', PYTHONIOENCODING: 'cp1252' });
    expect(env.PATH).to.equal('/usr/bin');
    expect(env).to.not.have.property('PYLAUNCHER_ALLOW_INSTALL');
    expect(env.PYTHON_MANAGER_AUTOMATIC_INSTALL).to.equal('false');
    expect(env.PYTHONUTF8).to.equal('1');
    expect(env.PYTHONIOENCODING).to.equal('utf-8');
  });

  it('reports an accented interpreter path intact even when Python writes its pipes in cp1252', function () {
    if (process.platform === 'win32') this.skip();
    let python;
    try {
      python = cp.execFileSync('python3', ['-c', 'import sys; print(sys.executable)'], { encoding: 'utf8' }).trim();
    } catch {
      this.skip();
    }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-André-'));
    const link = path.join(dir, 'python3');
    fs.symlinkSync(python, link);
    // The probe script alone must not depend on the pipe encoding (cp1252 on many Windows setups).
    const out = cp.execFileSync(link, ['-c', PROBE_SCRIPT], { env: { ...process.env, PYTHONIOENCODING: 'cp1252', PYTHONUTF8: '0' } });
    expect(out.toString('utf8').trim().split(' ').slice(4).join(' ')).to.equal(link);
  });
});

