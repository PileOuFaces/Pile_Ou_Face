// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const { baseCandidates, isSupportedVersion, findCompatibleBase, probeInterpreter } = require('../shared/pythonInterpreter');

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
    expect(baseCandidates('win32').map((c) => [c.command, ...c.args].join(' '))).to.deep.equal([
      'py -3.13', 'py -3.12', 'py -3.11', 'py -3.10', 'python', 'python3',
    ]);
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
});
