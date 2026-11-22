// SPDX-License-Identifier: AGPL-3.0-only
// #531 : un dossier de décompilateur local (Ghidra) n'est fixé que par le dialogue natif du
// Host ; la structure du dossier est vérifiée, mais elle ne remplace pas ce choix.
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const sinon = require('sinon');

const {
  SETTINGS_STATE_KEY,
  migrateStoredSettings,
  readStoredSettings,
  validateSettingsUpdate,
} = require('../shared/settingsSchema');
const { DECOMPILER_PATHS_ATTESTATION_KEY } = require('../shared/decompilerPathsSchema');
const { checkInstallFolder, decompilerEnvFromPaths } = require('../shared/decompilerLocalPaths');
const { createSettingsActions } = require('../static/hub/settingsActions');

const POSIX_FILES = ['support/analyzeHeadless', 'Ghidra/application.properties'];
const WINDOWS_FILES = ['support/analyzeHeadless.bat', 'Ghidra/application.properties'];

// Real folders follow the host platform's layout (Windows: analyzeHeadless.bat).
const HOST_FILES = process.platform === 'win32' ? WINDOWS_FILES : POSIX_FILES;

function makeGhidraFolder(files = HOST_FILES) {
  const folder = fs.mkdtempSync(path.join(os.tmpdir(), 'pof ghidra '));
  for (const relative of files) {
    const target = path.join(folder, ...relative.split('/'));
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, '');
  }
  return fs.realpathSync(folder);
}

/** Fake filesystem for another platform: `files` are full paths in that platform's syntax. */
function fakeFs(folders, files) {
  const statSync = (candidate) => {
    if (folders.includes(candidate)) return { isDirectory: () => true, isFile: () => false };
    if (files.includes(candidate)) return { isDirectory: () => false, isFile: () => true };
    throw Object.assign(new Error(`ENOENT: ${candidate}`), { code: 'ENOENT' });
  };
  return { statSync, realpathSync: (candidate) => { statSync(candidate); return candidate; } };
}

function makeStore(settings = {}, attested = undefined) {
  const values = new Map<string, any>([[SETTINGS_STATE_KEY, settings], [DECOMPILER_PATHS_ATTESTATION_KEY, attested]]);
  return {
    get: (key, fallback) => (values.get(key) !== undefined ? values.get(key) : fallback),
    update: sinon.spy(async (key, next) => { values.set(key, next); }),
    current: () => values.get(SETTINGS_STATE_KEY),
    attested: () => values.get(DECOMPILER_PATHS_ATTESTATION_KEY),
  };
}

function makeActions(store, selectInstallFolder) {
  const posted = [];
  const vscode = { window: { showErrorMessage: sinon.spy() } };
  const actions = createSettingsActions({
    panel: { webview: { postMessage: (message) => posted.push(message) } },
    context: { globalState: store },
    vscode,
    root: '/workspace',
    logChannel: { appendLine: () => {} },
    selectInstallFolder,
  });
  return { actions, posted, vscode };
}

describe('decompiler local folders (#531)', () => {
  const created = [];
  afterEach(() => {
    sinon.restore();
    while (created.length) fs.rmSync(created.pop(), { recursive: true, force: true });
  });
  const ghidraFolder = (files?) => {
    const folder = makeGhidraFolder(files);
    created.push(folder);
    return folder;
  };

  describe('structural check (not a proof of authenticity)', () => {
    it('accepts a folder with the Ghidra layout and returns its canonical path', function () {
      // Creating a symbolic link needs extra privileges on Windows.
      if (process.platform === 'win32') this.skip();
      const folder = ghidraFolder();
      const link = `${folder}-link`;
      fs.symlinkSync(folder, link);
      created.push(link);
      expect(checkInstallFolder('ghidra', link)).to.deep.equal({ ok: true, path: folder });
    });

    for (const [label, files] of [
      ['without the analyzeHeadless launcher', ['Ghidra/application.properties']],
      ['without Ghidra/application.properties', [HOST_FILES[0]]],
      ['empty', []],
    ]) {
      it(`refuses a folder ${label}`, () => {
        const result = checkInstallFolder('ghidra', ghidraFolder(files as string[]));
        expect(result.ok).to.equal(false);
        expect(result.error).to.contain('does not look like a ghidra installation');
      });
    }

    it('refuses relative paths, files, missing folders and unsupported decompilers', () => {
      const folder = ghidraFolder();
      expect(checkInstallFolder('ghidra', 'opt/ghidra').ok).to.equal(false);
      expect(checkInstallFolder('ghidra', path.join(folder, ...HOST_FILES[0].split('/'))).ok).to.equal(false);
      expect(checkInstallFolder('ghidra', path.join(folder, 'missing')).ok).to.equal(false);
      expect(checkInstallFolder('retdec', folder).ok).to.equal(false);
      expect(checkInstallFolder('ghidra', `${folder}\0x`).ok).to.equal(false);
    });

    it('uses the Windows layout (analyzeHeadless.bat) on win32', () => {
      const root = 'C:\\Tools\\ghidra_11.2_PUBLIC';
      const files = WINDOWS_FILES.map((relative) => path.win32.join(root, ...relative.split('/')));
      const deps = { platform: 'win32', ...fakeFs([root], files) };
      expect(checkInstallFolder('ghidra', root, deps)).to.deep.equal({ ok: true, path: root });
      // The POSIX launcher alone does not satisfy the Windows layout, and vice versa.
      const posixOnly = POSIX_FILES.map((relative) => path.win32.join(root, ...relative.split('/')));
      expect(checkInstallFolder('ghidra', root, { platform: 'win32', ...fakeFs([root], posixOnly) }).ok).to.equal(false);
      expect(checkInstallFolder('ghidra', 'relative\\ghidra', deps).ok).to.equal(false);
    });

    it('uses the POSIX layout on macOS (Homebrew cask path)', () => {
      const root = '/opt/homebrew/Caskroom/ghidra/11.2/ghidra_11.2_PUBLIC';
      const files = POSIX_FILES.map((relative) => path.posix.join(root, relative));
      const deps = { platform: 'darwin', ...fakeFs([root], files) };
      expect(checkInstallFolder('ghidra', root, deps)).to.deep.equal({ ok: true, path: root });
    });

    it('does not grant trust: a folder with the right layout is still refused from the webview', () => {
      const lookalike = ghidraFolder(); // contains a file named analyzeHeadless, nothing more
      expect(checkInstallFolder('ghidra', lookalike).ok).to.equal(true);
      const result = validateSettingsUpdate({ decompilerLocalPaths: { ghidra: lookalike } }, {});
      expect(result.ok).to.equal(false);
      expect(result.errors.join(' ')).to.contain('can only be set by the extension host');
    });
  });

  describe('webview updates', () => {
    const CURRENT = { decompilerLocalPaths: { ghidra: '/opt/ghidra' } };
    const MALICIOUS = [
      ['an arbitrary folder', { ghidra: '/tmp/evil' }],
      ['a relative folder', { ghidra: '../../evil' }],
      ['a UNC share', { ghidra: '\\\\attacker\\share\\ghidra' }],
      ['an unsupported decompiler', { retdec: '/opt/retdec' }],
      ['a prototype key', JSON.parse('{"__proto__": {"ghidra": "/tmp/evil"}}')],
      ['a non-object value', '/tmp/evil'],
      ['an array', ['/tmp/evil']],
      ['a non-string path', { ghidra: { path: '/tmp/evil' } }],
    ];
    for (const [label, value] of MALICIOUS) {
      it(`refuses ${label}`, () => {
        expect(validateSettingsUpdate({ decompilerLocalPaths: value }, CURRENT).ok, label).to.equal(false);
      });
    }

    it('keeps the current value, clears an entry with "", and keeps entries it omits', () => {
      expect(validateSettingsUpdate({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, CURRENT).settings.decompilerLocalPaths)
        .to.deep.equal({ ghidra: '/opt/ghidra' });
      expect(validateSettingsUpdate({ decompilerLocalPaths: { ghidra: '' } }, CURRENT).settings.decompilerLocalPaths)
        .to.deep.equal({});
      expect(validateSettingsUpdate({ decompilerLocalPaths: {} }, CURRENT).settings.decompilerLocalPaths)
        .to.deep.equal({ ghidra: '/opt/ghidra' });
      expect(validateSettingsUpdate({ lang: 'en' }, CURRENT).settings.decompilerLocalPaths)
        .to.deep.equal({ ghidra: '/opt/ghidra' });
    });
  });

  describe('migration of stored values', () => {
    it('drops a stored folder that no host attestation covers (written by an older webview)', () => {
      const { settings, dropped } = migrateStoredSettings(
        { lang: 'en', decompilerLocalPaths: { ghidra: '/tmp/evil' } },
        { attestedDecompilerPaths: {} },
      );
      expect(settings).to.deep.equal({ lang: 'en', decompilerLocalPaths: {} });
      expect(dropped).to.deep.equal(['decompilerLocalPaths.ghidra']);
    });

    it('keeps an attested folder, including during a change (previous folder still attested)', () => {
      for (const attested of [{ ghidra: '/opt/ghidra' }, { ghidra: ['/opt/new', '/opt/ghidra'] }]) {
        const { settings } = migrateStoredSettings(
          { decompilerLocalPaths: { ghidra: '/opt/ghidra' } },
          { attestedDecompilerPaths: attested },
        );
        expect(settings.decompilerLocalPaths).to.deep.equal({ ghidra: '/opt/ghidra' });
      }
    });

    it('drops the whole value when its shape is invalid (unknown decompiler, relative path)', () => {
      for (const stored of [{ retdec: '/opt/retdec' }, { ghidra: 'relative/ghidra' }]) {
        const { settings, dropped } = migrateStoredSettings(
          { decompilerLocalPaths: stored },
          { attestedDecompilerPaths: { ghidra: 'relative/ghidra', retdec: '/opt/retdec' } },
        );
        expect(settings).to.not.have.property('decompilerLocalPaths');
        expect(dropped).to.deep.equal(['decompilerLocalPaths']);
      }
    });

    it('reads the attestation from the store (readStoredSettings)', () => {
      const store = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, { ghidra: '/opt/ghidra' });
      expect(readStoredSettings(store).decompilerLocalPaths).to.deep.equal({ ghidra: '/opt/ghidra' });
      const unattested = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } });
      expect(readStoredSettings(unattested).decompilerLocalPaths).to.deep.equal({});
    });
  });

  describe('backend environment', () => {
    it('exports an attested folder that still has the Ghidra layout', () => {
      const folder = ghidraFolder();
      expect(decompilerEnvFromPaths({ ghidra: folder })).to.deep.equal({ GHIDRA_INSTALL_DIR: folder });
    });

    it('ignores, and logs, a folder whose layout changed since it was selected', () => {
      const folder = ghidraFolder();
      fs.rmSync(path.join(folder, 'support'), { recursive: true }); // launcher gone
      const log = sinon.spy();
      expect(decompilerEnvFromPaths({ ghidra: folder }, { log })).to.deep.equal({});
      expect(log.calledOnce).to.equal(true);
    });

    it('never exports an unattested folder: the migration removes it first', () => {
      const folder = ghidraFolder();
      const store = makeStore({ decompilerLocalPaths: { ghidra: folder } });
      expect(decompilerEnvFromPaths(readStoredSettings(store).decompilerLocalPaths)).to.deep.equal({});
    });
  });

  describe('host selection (hubSelectDecompilerLocalPath)', () => {
    it('stores and attests the folder picked in the native dialog', async () => {
      const store = makeStore({ lang: 'fr' });
      const select = sinon.stub().resolves({ ok: true, path: '/opt/ghidra' });
      const { actions, posted } = makeActions(store, select);
      await actions.hubSelectDecompilerLocalPath({ decompilerId: 'ghidra' });
      expect(select.calledOnce).to.equal(true);
      expect(store.current()).to.deep.equal({ lang: 'fr', decompilerLocalPaths: { ghidra: '/opt/ghidra' } });
      expect(store.attested()).to.deep.equal({ ghidra: '/opt/ghidra' });
      expect(posted).to.deep.equal([
        { type: 'hubDecompilerLocalPathSelected', decompilerId: 'ghidra', changed: true, path: '/opt/ghidra' },
      ]);
    });

    it('keeps an attested folder visible to readers while switching to a new one', async () => {
      const store = makeStore({ decompilerLocalPaths: { ghidra: '/opt/old' } }, { ghidra: '/opt/old' });
      const seen = [];
      const update = store.update;
      store.update = sinon.spy(async (key, next) => {
        await update(key, next);
        seen.push(readStoredSettings(store).decompilerLocalPaths.ghidra);
      });
      const { actions } = makeActions(store, sinon.stub().resolves({ ok: true, path: '/opt/new' }));
      await actions.hubSelectDecompilerLocalPath({ decompilerId: 'ghidra' });
      expect(seen).to.deep.equal(['/opt/old', '/opt/new', '/opt/new']);
      expect(store.attested()).to.deep.equal({ ghidra: '/opt/new' });
    });

    it('never opens the dialog for an unsupported or forged decompiler id', async () => {
      for (const decompilerId of ['retdec', '__proto__', '', { id: 'ghidra' }, undefined]) {
        const store = makeStore({});
        const select = sinon.stub();
        const { actions, posted } = makeActions(store, select);
        await actions.hubSelectDecompilerLocalPath({ decompilerId, path: '/tmp/evil' });
        expect(select.called).to.equal(false);
        expect(store.update.called).to.equal(false);
        expect(posted[0]).to.include({ type: 'hubDecompilerLocalPathSelected', changed: false });
      }
    });

    it('ignores a path sent along with the request: only the dialog decides', async () => {
      const store = makeStore({});
      const select = sinon.stub().resolves({ ok: false, cancelled: true });
      const { actions } = makeActions(store, select);
      await actions.hubSelectDecompilerLocalPath({ decompilerId: 'ghidra', path: '/tmp/evil' });
      expect(store.update.called).to.equal(false);
    });

    it('reports a folder with the wrong layout and stores nothing', async () => {
      const store = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, { ghidra: '/opt/ghidra' });
      const { actions, posted, vscode } = makeActions(
        store,
        sinon.stub().resolves({ ok: false, error: 'This folder does not look like a ghidra installation.' }),
      );
      await actions.hubSelectDecompilerLocalPath({ decompilerId: 'ghidra' });
      expect(store.update.called).to.equal(false);
      expect(vscode.window.showErrorMessage.calledOnce).to.equal(true);
      expect(posted[0]).to.include({ changed: false, path: '/opt/ghidra' });
    });

    it('clears a folder on explicit request (entry and attestation), and only for supported ids', async () => {
      const store = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, { ghidra: '/opt/ghidra' });
      const { actions, posted } = makeActions(store, sinon.stub());
      await actions.hubClearDecompilerLocalPath({ decompilerId: 'ghidra' });
      expect(store.current().decompilerLocalPaths).to.deep.equal({});
      expect(store.attested()).to.deep.equal({});
      expect(posted[0]).to.deep.equal({ type: 'hubDecompilerLocalPathSelected', decompilerId: 'ghidra', changed: true, path: '' });
      const untouched = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, { ghidra: '/opt/ghidra' });
      await makeActions(untouched, sinon.stub()).actions.hubClearDecompilerLocalPath({ decompilerId: '__proto__' });
      expect(untouched.update.called).to.equal(false);
    });

    it('reset also forgets the folder attestations', async () => {
      const store = makeStore({ decompilerLocalPaths: { ghidra: '/opt/ghidra' } }, { ghidra: '/opt/ghidra' });
      const { actions } = makeActions(store, sinon.stub());
      await actions.hubResetSettings({ requestId: 1 });
      expect(store.attested()).to.equal(undefined);
      expect(readStoredSettings(store).decompilerLocalPaths).to.deep.equal({});
    });
  });
});
