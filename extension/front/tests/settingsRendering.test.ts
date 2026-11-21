// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-002 : les valeurs issues des réglages sont rendues en texte, jamais en HTML,
// et pythonPath ne part jamais du webview.
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');
const sinon = require('sinon');

const HTML_PAYLOAD = '<img src="x" onerror="window.__pwned = true">';
const SELECTED_PYTHON = '/opt/pof venv/bin/python3';

function mountSettings() {
  const dom = new JSDOM(`<div id="panel-options">
    <input id="settingInterfaceMode" data-key="interfaceMode" value="advanced">
    <input id="settingLang" data-key="lang" value="fr">
    <select id="settingBindiffThreshold" data-key="bindiffThreshold" data-type="float">
      <option value="0.40">40 %</option><option value="0.60">60 %</option>
    </select>
    <input id="settingPythonPath" data-key="pythonPath" readonly>
    <button data-select-python-path></button>
    <button data-clear-python-path></button>
    <div id="staticFeatureSettings"><div id="staticFeatureChecklist"></div></div>
    <div id="decompilerStatusSummary"></div>
    <div id="decompilerStatusList"></div>
  </div>`, { runScripts: 'outside-only', url: 'https://hub.test' });
  const messages = [];
  Object.assign(dom.window, {
    vscode: { postMessage: (message) => messages.push(message) },
    GROUPS: { code: ['disasm'] },
    GROUP_LABELS: {},
    STATIC_SIMPLE_FEATURES: new Set(['disasm']),
    getStaticFeatureIds: () => ['disasm'],
    updateActiveContextBars: () => {},
    _decompilerAvailability: {},
    _decompilerMeta: {},
    binaryPathInput: null,
    argvPayloadInput: null,
    dynamicPayloadTargetMode: null,
    isStaticTabActive: () => false,
    POFAiPricing: { normalizeRules: (rules) => rules || [] },
    // Deliberately a no-op: setting values must not depend on escaping to stay text.
    escapeHtml: (value) => String(value),
    _selectedDecompilerCardId: '',
    _decompilerLocalUiState: { visibilityById: {} },
    _getActiveDecompilerSource: () => 'auto',
    _getConfiguredDecompilerProvider: () => HTML_PAYLOAD,
    _getLocalPathSpecForDecompiler: () => ({ id: 'ghidra', hint: 'hint', placeholder: '/opt/ghidra' }),
    _describeLocalDetectionHint: () => '',
    _updateDecompilerActionButtons: () => {},
  });
  const clock = sinon.useFakeTimers({ global: dom.window });
  const sourcePath = path.resolve(__dirname, '../shared/settings.js');
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), dom.getInternalVMContext(), { filename: sourcePath });
  return { dom, clock, messages };
}

describe('settings rendering and pythonPath ownership', () => {
  let fixture;
  afterEach(() => {
    fixture?.clock.restore();
    fixture?.dom.window.close();
  });

  it('renders setting values containing HTML as text', () => {
    fixture = mountSettings();
    const { dom } = fixture;
    const { document } = dom.window;
    dom.window._applySettings({ interfaceMode: 'advanced', decompilerLocalPaths: { ghidra: HTML_PAYLOAD } }, 0);
    dom.window._renderDecompilerStatusList({
      ghidra: true,
      _meta: { labels: { ghidra: 'Ghidra' }, local_available: { ghidra: true } },
    });

    const list = document.getElementById('decompilerStatusList');
    const summary = document.getElementById('decompilerStatusSummary');
    expect(list.querySelector('img'), 'decompiler cards').to.equal(null);
    expect(summary.querySelector('img'), 'summary').to.equal(null);
    expect(list.querySelector('[data-decompiler-card-text="localPath"]').textContent).to.equal(HTML_PAYLOAD);
    expect(list.querySelector('[data-decompiler-local-path]').value).to.equal(HTML_PAYLOAD);
    expect(list.querySelector('[data-decompiler-card-text="caption"]').textContent).to.contain(HTML_PAYLOAD);
    expect(summary.textContent).to.contain(HTML_PAYLOAD);
    expect(dom.window.__pwned).to.equal(undefined);
  });

  it('never sends a pythonPath value typed in the webview', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    const { document } = dom.window;
    dom.window._applySettings({ interfaceMode: 'advanced', lang: 'fr', pythonPath: SELECTED_PYTHON }, 0);
    document.getElementById('settingPythonPath').value = '/tmp/other/python3';
    document.getElementById('settingLang').value = 'en';
    dom.window._scheduleSave();
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    expect(save.settings.lang).to.equal('en');
    expect(save.settings).to.not.have.property('pythonPath');
  });

  it('asks the host for a native selection and can only clear the value', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    const { document } = dom.window;
    dom.window._applySettings({ interfaceMode: 'advanced', pythonPath: SELECTED_PYTHON }, 0);
    document.querySelector('[data-select-python-path]').click();
    expect(messages.some((message) => message.type === 'hubSelectPythonPath')).to.equal(true);

    document.querySelector('[data-clear-python-path]').click();
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    expect(save.settings.pythonPath).to.equal('');
  });

  it('reloads the host settings after a rejected save', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    dom.window._applySettings({ interfaceMode: 'advanced' }, 0);
    dom.window._scheduleSave();
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    dom.window._settingsSaved({ ok: false, requestId: save.requestId });
    expect(messages[messages.length - 1].type).to.equal('hubGetSettings');
    expect(dom.window.document.documentElement.dataset.hubSettingsSavePending).to.equal('false');
  });

  it('shows a stored numeric value in a select whose options are formatted differently', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    const select = dom.window.document.getElementById('settingBindiffThreshold');
    dom.window._applySettings({ interfaceMode: 'advanced', bindiffThreshold: 0.6 }, 0);
    expect(select.value).to.equal('0.60');
    dom.window._scheduleSave();
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    expect(save.settings.bindiffThreshold).to.equal(0.6);
  });

  it('never sends NaN for an empty numeric control (the host would reject the whole save)', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    dom.window._applySettings({ interfaceMode: 'advanced', bindiffThreshold: 0.4 }, 0);
    dom.window.document.getElementById('settingBindiffThreshold').value = '';
    dom.window.document.getElementById('settingInterfaceMode').value = 'simple';
    dom.window._scheduleSave();
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    expect(save.settings.bindiffThreshold).to.equal(0.4);
    expect(JSON.parse(JSON.stringify(save.settings)).bindiffThreshold).to.equal(0.4);
  });

  it('applies the interpreter chosen in the native picker even while a save is pending', () => {
    fixture = mountSettings();
    const { dom } = fixture;
    dom.window._applySettings({ interfaceMode: 'advanced', pythonPath: '' }, 0);
    dom.window._scheduleSave();
    dom.window._pythonPathSelected({ type: 'hubPythonPathSelected', changed: true, pythonPath: SELECTED_PYTHON });
    expect(dom.window.document.getElementById('settingPythonPath').value).to.equal(SELECTED_PYTHON);
  });

  for (const [label, interrupt] of [
    ['a reset', (window) => window._resetSettings()],
    ['a native selection', (window) => window._pythonPathSelected({ changed: true, pythonPath: SELECTED_PYTHON })],
  ]) {
    it(`does not replay a clear request cancelled by ${label}`, () => {
      fixture = mountSettings();
      const { dom, clock, messages } = fixture;
      const { document } = dom.window;
      dom.window._applySettings({ interfaceMode: 'advanced', pythonPath: SELECTED_PYTHON }, 0);
      document.querySelector('[data-clear-python-path]').click();
      interrupt(dom.window);
      clock.tick(500);
      dom.window._applySettings({ interfaceMode: 'advanced', pythonPath: SELECTED_PYTHON }, dom.window._settingsRequestId);
      document.getElementById('settingLang').value = 'en';
      dom.window._scheduleSave();
      clock.tick(500);
      const saves = messages.filter((message) => message.type === 'hubSaveSettings');
      expect(saves[saves.length - 1].settings.lang).to.equal('en');
      // Neither the pending save nor a later one may clear the interpreter.
      for (const save of saves) expect(save.settings).to.not.have.property('pythonPath');
    });
  }

  it('keeps a pending "Auto" request when the native selection is cancelled', () => {
    fixture = mountSettings();
    const { dom, clock, messages } = fixture;
    const { document } = dom.window;
    dom.window._applySettings({ interfaceMode: 'advanced', pythonPath: SELECTED_PYTHON }, 0);
    document.querySelector('[data-clear-python-path]').click();
    dom.window._pythonPathSelected({ type: 'hubPythonPathSelected', changed: false, pythonPath: SELECTED_PYTHON });
    clock.tick(500);
    const save = messages.find((message) => message.type === 'hubSaveSettings');
    expect(save.settings.pythonPath).to.equal('');
    expect(document.getElementById('settingPythonPath').value).to.equal('');
  });
});
