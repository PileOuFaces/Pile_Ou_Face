// SPDX-License-Identifier: AGPL-3.0-only
// Dossier temporaire privé par utilisateur : jamais un chemin /tmp partagé et prévisible.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');
const {
  privateDirProblem,
  privateTempBase,
  ensurePrivateSubdir,
  safeFileStem,
  writeFileAtomic,
  resetPrivateTempBaseForTests,
} = require('../shared/privateTempDir');

const POSIX = process.platform !== 'win32';

/** Reads `file` in one open that fails if it is a symbolic link (no check-then-use). */
function readRegularFile(file) {
  const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    return fs.readFileSync(fd, 'utf8');
  } finally {
    fs.closeSync(fd);
  }
}
const OWN_UID = POSIX ? process.getuid() : 0;
const OTHER_UID = OWN_UID + 4242;

describe('private temporary directory', () => {
  let fakeTmp;
  let warn;
  // Real filesystem, isolated tmpdir; `fsApi: fs` disables the per-process cache.
  const deps = (extra = {}) => ({ tmpdir: () => fakeTmp, fsApi: fs, warn, ...extra });
  const expectedBase = () => path.join(fakeTmp, `pile-ou-face-${POSIX ? OWN_UID : 'x'}`);

  beforeEach(() => {
    fakeTmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-private-tmp-'));
    warn = sinon.spy();
  });
  afterEach(() => {
    fs.rmSync(fakeTmp, { recursive: true, force: true });
    resetPrivateTempBaseForTests();
  });

  (POSIX ? it : it.skip)('creates the per-user base with mode 0700 and accepts it', () => {
    const base = privateTempBase(deps());
    expect(base).to.equal(expectedBase());
    expect(fs.statSync(base).mode & 0o777).to.equal(0o700);
    expect(warn.called).to.equal(false);
  });

  (POSIX ? it : it.skip)('never reuses a base another account planted as a symbolic link', () => {
    const elsewhere = fs.mkdtempSync(path.join(fakeTmp, 'attacker-'));
    fs.symlinkSync(elsewhere, expectedBase());
    const base = privateTempBase(deps());
    expect(base).to.not.equal(expectedBase());
    expect(path.dirname(base)).to.equal(fakeTmp);
    expect(fs.lstatSync(base).isSymbolicLink()).to.equal(false);
    expect(fs.statSync(base).mode & 0o777).to.equal(0o700);
    expect(warn.firstCall.args[0]).to.contain('symbolic link');
  });

  (POSIX ? it : it.skip)('never reuses a base open to other users', () => {
    fs.mkdirSync(expectedBase(), { mode: 0o700 });
    fs.chmodSync(expectedBase(), 0o777);
    const base = privateTempBase(deps());
    expect(base).to.not.equal(expectedBase());
    expect(warn.firstCall.args[0]).to.contain('accessible to other users');
  });

  (POSIX ? it : it.skip)('never reuses a base owned by another account', () => {
    fs.mkdirSync(path.join(fakeTmp, `pile-ou-face-${OTHER_UID}`), { mode: 0o700 });
    // Same directory name for the "other" uid: as if it had been created by someone else.
    const base = privateTempBase(deps({ getuid: () => OTHER_UID }));
    expect(base).to.not.equal(path.join(fakeTmp, `pile-ou-face-${OTHER_UID}`));
    expect(warn.firstCall.args[0]).to.contain(`owned by uid ${OWN_UID}`);
  });

  it('reports a regular file at the base path', () => {
    const file = path.join(fakeTmp, 'not-a-dir');
    fs.writeFileSync(file, '');
    expect(privateDirProblem(file, { fsApi: fs })).to.equal('is not a directory');
  });

  it('on Windows, never reuses a predictable directory another account could pre-create', () => {
    // Node cannot check Windows ACLs: a squatted pile-ou-face-<user> must not be adopted.
    const squatted = path.join(fakeTmp, 'pile-ou-face-Jane_Doe');
    fs.mkdirSync(squatted);
    const first = privateTempBase(deps({ platform: 'win32', username: () => 'Jane Doe' }));
    const second = privateTempBase(deps({ platform: 'win32', username: () => 'Jane Doe' }));
    for (const base of [first, second]) {
      expect(base).to.not.equal(squatted);
      expect(path.dirname(base)).to.equal(fakeTmp);
      expect(path.basename(base)).to.match(/^pile-ou-face-[A-Za-z0-9]{6}$/);
    }
    expect(first).to.not.equal(second);
  });

  (POSIX ? it : it.skip)('creates private subdirectories inside the base', () => {
    const dir = ensurePrivateSubdir('triage', deps());
    expect(path.dirname(dir)).to.equal(expectedBase());
    expect(fs.statSync(dir).mode & 0o777).to.equal(0o700);
  });

  it('turns an untrusted identifier into a plain file stem (no traversal)', () => {
    for (const hostile of ['../../../home/user/.bashrc', 'a/b\\c', '..', '', '\0', 'x'.repeat(10000)]) {
      const stem = safeFileStem(hostile);
      expect(stem).to.match(/^[0-9a-f]{24}$/);
    }
    expect(safeFileStem('same')).to.equal(safeFileStem('same'));
  });

  (POSIX ? it : it.skip)('writes atomically: a symlink planted at the target is replaced, not followed', () => {
    const victim = path.join(fakeTmp, 'victim.txt');
    fs.writeFileSync(victim, 'untouched');
    const target = path.join(fakeTmp, 'cache.json');
    fs.symlinkSync(victim, target);
    writeFileAtomic(target, '{"ok":true}');
    expect(fs.readFileSync(victim, 'utf8')).to.equal('untouched');
    expect(readRegularFile(target)).to.equal('{"ok":true}');
    expect(fs.readdirSync(fakeTmp).filter((name) => name.endsWith('.tmp'))).to.deep.equal([]);
  });

  (POSIX ? it : it.skip)('writes atomically even when a dangling symlink points outside', () => {
    const outside = path.join(fakeTmp, 'would-be-created');
    const target = path.join(fakeTmp, 'symbols.json');
    fs.symlinkSync(outside, target);
    writeFileAtomic(target, '[]');
    expect(fs.existsSync(outside)).to.equal(false);
    expect(readRegularFile(target)).to.equal('[]');
  });
});

describe('getTempDir / ensureTempDir use the private base', () => {
  afterEach(() => resetPrivateTempBaseForTests());

  (POSIX ? it : it.skip)('never returns the old shared os.tmpdir()/pile-ou-face/<hash> path', () => {
    const utils = require('../shared/utils');
    const dir = utils.getTempDir(process.cwd());
    expect(dir.startsWith(path.join(os.tmpdir(), 'pile-ou-face') + path.sep)).to.equal(false);
    expect(path.dirname(dir)).to.equal(privateTempBase());
    const ensured = utils.ensureTempDir(process.cwd());
    expect(fs.statSync(ensured).mode & 0o777).to.equal(0o700);
    expect(privateDirProblem(path.dirname(ensured))).to.equal(null);
  });
});
