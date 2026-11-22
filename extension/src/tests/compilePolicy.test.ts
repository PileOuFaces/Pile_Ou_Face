// SPDX-License-Identifier: AGPL-3.0-only
// #548 : le webview (non fiable) ne doit ni exécuter de code via les options du
// compilateur, ni lui faire lire un autre fichier, ni écrire hors des chemins
// choisis dans le dialogue natif.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  validateCompileFlags,
  validateLangTarget,
  validateSourcePath,
  checkStaticCompileMessage,
  privateOutputName,
  createExportRegistry,
  exportCompiledBinary,
} = require('../static/compilePolicy');
const { checkCompileRequest } = require('../static/compileHandlers');
const { writeFileAtomic } = require('../shared/privateTempDir');

const PANEL_FLAGS = [
  '-O2', '-g', '-fstack-protector-strong', '-z', 'execstack', '-fno-pie', '-no-pie',
  '-Wl,-z,relro,-z,now', '-static', '-s',
];

// Options GCC/Clang qui exécutent du code, lisent un fichier arbitraire ou
// redirigent la sortie.
const BYPASSES = [
  ['-wrapper', '/bin/sh,-c,id'],
  ['-fplugin=/tmp/evil.so'],
  ['-fplugin-arg-evil-x=y'],
  ['-specs=/tmp/evil.specs'],
  ['-B/tmp/evil'],
  ['-B', '/tmp/evil'],
  ['@/tmp/response-file'],
  ['-Xclang', '-load', '-Xclang', '/tmp/evil.so'],
  ['-fpass-plugin=/tmp/evil.so'],
  ['--config=/tmp/evil.cfg'],
  ['-fuse-ld=/tmp/evil-ld'],
  ['--ld-path=/tmp/evil-ld'],
  ['-Wl,--plugin=/tmp/evil.so'],
  ['-Xlinker', '--plugin=/tmp/evil.so'],
  ['-include', '/etc/shadow'],
  ['-o', '/home/user/.bashrc'],
  ['-z', 'now'],
  ['-z'],
  ['-O2 -wrapper /bin/sh'],
  ['--sysroot=/tmp/evil'],
  ['-isystem', '/tmp/evil'],
];

function tmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pof-compile-policy-'));
}

describe('compilePolicy (#548)', () => {
  it('accepts exactly the options the panel produces', () => {
    expect(validateCompileFlags(PANEL_FLAGS, 'c')).to.deep.equal({ ok: true, value: PANEL_FLAGS });
    expect(validateCompileFlags(undefined, 'rust')).to.deep.equal({ ok: true, value: [] });
  });

  for (const bypass of BYPASSES) {
    it(`refuses ${JSON.stringify(bypass)} (whole request, not silently dropped)`, () => {
      const result = validateCompileFlags(['-O0', ...bypass], 'c');
      expect(result.ok).to.equal(false);
    });
  }

  it('refuses non-list, non-string and oversized option payloads', () => {
    expect(validateCompileFlags('-O2', 'c').ok).to.equal(false);
    expect(validateCompileFlags([{ toString: () => '-O2' }], 'c').ok).to.equal(false);
    expect(validateCompileFlags(new Array(64).fill('-O2'), 'c').ok).to.equal(false);
  });

  it('refuses options for Rust and Go (the panel sends none)', () => {
    expect(validateCompileFlags(['-O2'], 'rust').ok).to.equal(false);
    expect(validateCompileFlags(['-O2'], 'go').ok).to.equal(false);
  });

  it('accepts every target of the shipped toolchains (no regression for cross targets)', () => {
    const { COMPILE_TARGETS } = require('../static/compilePolicy');
    const compilersDir = path.resolve(__dirname, '..', '..', '..', 'docker', 'compilers');
    const shipped = new Set();
    for (const name of fs.readdirSync(compilersDir)) {
      const file = path.join(compilersDir, name, 'compilers.json');
      if (!fs.existsSync(file)) continue;
      const text = fs.readFileSync(file, 'utf8');
      for (const match of text.matchAll(/"((?:elf|pe|macho)-[a-z0-9]+)"/g)) shipped.add(match[1]);
    }
    expect(shipped.size).to.be.greaterThan(8);
    expect([...shipped].filter((t) => !COMPILE_TARGETS.includes(t))).to.deep.equal([]);
  });

  it('only accepts known languages and targets', () => {
    expect(validateLangTarget('c', 'elf-x64').ok).to.equal(true);
    expect(validateLangTarget('sh', 'elf-x64').ok).to.equal(false);
    expect(validateLangTarget('c', 'elf-x64 -wrapper').ok).to.equal(false);
  });

  describe('source path', () => {
    it('accepts a regular source file and returns its real path', () => {
      const dir = tmpDir();
      const source = path.join(dir, 'main.c');
      fs.writeFileSync(source, 'int main(){return 0;}\n');
      expect(validateSourcePath(source, 'c')).to.deep.equal({ ok: true, value: fs.realpathSync(source) });
    });

    it('refuses relative paths, missing files, directories and non-source files', () => {
      const dir = tmpDir();
      fs.writeFileSync(path.join(dir, 'id_rsa'), 'secret');
      fs.mkdirSync(path.join(dir, 'folder.c'));
      expect(validateSourcePath('main.c', 'c').ok).to.equal(false);
      expect(validateSourcePath(path.join(dir, 'absent.c'), 'c').ok).to.equal(false);
      expect(validateSourcePath(path.join(dir, 'folder.c'), 'c').ok).to.equal(false);
      expect(validateSourcePath(path.join(dir, 'id_rsa'), 'c').ok).to.equal(false);
      expect(validateSourcePath(path.join(dir, 'main.rs'), 'c').ok).to.equal(false);
    });

    it('refuses a .c symlink that points to a non-source file (e.g. a private key)', function () {
      if (process.platform === 'win32') this.skip();
      const dir = tmpDir();
      fs.writeFileSync(path.join(dir, 'id_rsa'), 'secret');
      fs.symlinkSync(path.join(dir, 'id_rsa'), path.join(dir, 'innocent.c'));
      expect(validateSourcePath(path.join(dir, 'innocent.c'), 'c').ok).to.equal(false);
    });
  });

  it('names the private output from the source stem only', () => {
    expect(privateOutputName('/x/hello.c', 'elf-x64')).to.equal('hello.elf');
    expect(privateOutputName('/x/hello.c', 'pe-x64')).to.equal('hello.exe');
    expect(privateOutputName('/x/hello.c', 'macho-arm64')).to.equal('hello');
    expect(privateOutputName('../../.bashrc', 'elf-x64')).to.equal('.bashrc.elf');
    expect(privateOutputName('..', 'elf-x64')).to.equal('output.elf');
    expect(privateOutputName('/x/a b;rm -rf.c', 'elf-x64')).to.equal('a_b_rm_-rf.elf');
  });

  describe('export to a chosen path', () => {
    it('only allows paths picked in the native save dialog', () => {
      const registry = createExportRegistry();
      expect(registry.attested('/home/user/.bashrc')).to.equal(null);
      registry.remember('/home/user/out/hello.elf');
      expect(registry.attested('/home/user/out/hello.elf')).to.equal('/home/user/out/hello.elf');
      expect(registry.attested('/home/user/out/other.elf')).to.equal(null);
      expect(registry.attested(['/home/user/out/hello.elf'])).to.equal(null);
    });

    it('never accepts a different spelling of the chosen path (symlinked parent + "..")', function () {
      if (process.platform === 'win32') this.skip();
      // /chosen/link -> /elsewhere : "/chosen/link/../out.elf" normalises to "/chosen/out.elf"
      // but the OS resolves it to "/elsewhere/../out.elf".
      const base = tmpDir();
      const chosenDir = path.join(base, 'chosen');
      const elsewhere = path.join(base, 'elsewhere', 'deep');
      fs.mkdirSync(chosenDir);
      fs.mkdirSync(elsewhere, { recursive: true });
      fs.symlinkSync(elsewhere, path.join(chosenDir, 'link'));
      const registry = createExportRegistry();
      registry.remember(path.join(chosenDir, 'out.elf'));
      expect(registry.attested(`${chosenDir}/link/../out.elf`)).to.equal(null);
    });

    it('replaces a symlink planted at the chosen path instead of writing through it', function () {
      if (process.platform === 'win32') this.skip();
      const dir = tmpDir();
      const victim = path.join(dir, 'victim.txt');
      fs.writeFileSync(victim, 'keep me');
      const built = path.join(dir, 'built.elf');
      fs.writeFileSync(built, 'ELF');
      const chosen = path.join(dir, 'chosen.elf');
      fs.symlinkSync(victim, chosen);
      exportCompiledBinary(built, chosen, writeFileAtomic);
      expect(fs.readFileSync(victim, 'utf8')).to.equal('keep me');
      expect(fs.lstatSync(chosen).isSymbolicLink()).to.equal(false);
      expect(fs.readFileSync(chosen, 'utf8')).to.equal('ELF');
      expect(fs.statSync(chosen).mode & 0o777).to.equal(0o755);
    });
  });

  describe('compileRequest', () => {
    const source = () => {
      const file = path.join(tmpDir(), 'main.c');
      fs.writeFileSync(file, 'int main(){return 0;}\n');
      return file;
    };

    it('accepts a panel request without output (private directory)', () => {
      const result = checkCompileRequest({ src: source(), lang: 'c', target: 'elf-x64', flags: ['-O0', '-g'] }, createExportRegistry());
      expect(result.ok).to.equal(true);
      expect(result.value.exportPath).to.equal(null);
    });

    it('refuses an output path the user did not pick in the dialog', () => {
      const result = checkCompileRequest(
        { src: source(), lang: 'c', target: 'elf-x64', output: path.join(os.homedir(), '.bashrc') },
        createExportRegistry(),
      );
      expect(result.ok).to.equal(false);
    });

    it('refuses free options even with a valid source and output', () => {
      const registry = createExportRegistry();
      registry.remember('/tmp/out.elf');
      const result = checkCompileRequest(
        { src: source(), lang: 'c', target: 'elf-x64', output: '/tmp/out.elf', flags: ['-wrapper', '/bin/sh,-c,id'] },
        registry,
      );
      expect(result.ok).to.equal(false);
    });
  });

  describe('hubCompileStaticBinary', () => {
    const valid = () => {
      const file = path.join(tmpDir(), 'main.c');
      fs.writeFileSync(file, 'int main(){return 0;}\n');
      return { sourcePath: file, archBits: '64', pieChoice: 'no', optim: '-O2', debug: '-g', canary: 'off', relro: 'full' };
    };

    it('accepts panel values', () => {
      expect(checkStaticCompileMessage(valid())).to.equal(null);
    });

    for (const [field, value] of [
      ['extraFlags', '-wrapper /bin/sh,-c,id'],
      ['optim', '-fplugin=/tmp/evil.so'],
      ['debug', '-specs=/tmp/evil'],
      ['binaryPath', '/home/user/.bashrc'],
      ['archBits', '16'],
      ['relro', 'everything'],
    ]) {
      it(`refuses ${field}=${JSON.stringify(value)}`, () => {
        expect(checkStaticCompileMessage({ ...valid(), [field]: value })).to.be.a('string');
      });
    }
  });
});
