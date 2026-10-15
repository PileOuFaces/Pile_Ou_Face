// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');
const sinon = require('sinon');

function mountSettings() {
  const dom = new JSDOM(`<div id="panel-options">
    <input id="settingInterfaceMode" data-key="interfaceMode" value="advanced">
    <input id="settingFontSize" data-key="codeFontSize" data-type="int" value="13">
    <button data-interface-mode="simple"></button>
    <button data-interface-mode="advanced"></button>
    <div id="staticFeatureSettings"><div id="staticFeatureChecklist"></div></div>
    <button id="btnResetSettings"></button>
  </div>`, { runScripts: 'outside-only', url: 'https://hub.test' });
  const messages = [];
  Object.assign(dom.window, {
    vscode: { postMessage: (message) => messages.push(message) },
    GROUPS: { code: ['disasm', 'callgraph'] },
    GROUP_LABELS: {},
    STATIC_SIMPLE_FEATURES: new Set(['disasm']),
    getStaticFeatureIds: () => ['disasm', 'callgraph'],
    updateActiveContextBars: () => {},
    _decompilerAvailability: {},
    _decompilerMeta: {},
    binaryPathInput: null,
    argvPayloadInput: null,
    dynamicPayloadTargetMode: null,
    isStaticTabActive: () => false,
    POFAiPricing: { normalizeRules: (rules) => rules },
  });
  const clock = sinon.useFakeTimers({ global: dom.window });
  const sourcePath = path.resolve(__dirname, '../shared/settings.js');
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), dom.getInternalVMContext(), { filename: sourcePath });
  dom.window.initSettingsListeners();
  const settings = { interfaceMode: 'advanced', enabledStaticFeatures: ['disasm', 'callgraph'], codeFontSize: 13 };
  dom.window._applySettings(settings, 0);
  return { dom, clock, messages, settings };
}

describe('settings persistence across delayed host responses', () => {
  let fixture;
  afterEach(() => {
    fixture?.clock.restore();
    fixture?.dom.window.close();
  });

  it('keeps a mode change when the previous settings arrive before the debounced save', () => {
    fixture = mountSettings();
    const { dom, clock, messages, settings } = fixture;
    dom.window.document.querySelector('[data-interface-mode="simple"]').click();
    dom.window._applySettings(settings, 0);
    expect(dom.window.document.getElementById('settingInterfaceMode').value).to.equal('simple');
    clock.tick(500);
    expect(messages.filter((message) => message.type === 'hubSaveSettings')).to.have.length(1);
    expect(messages.find((message) => message.type === 'hubSaveSettings').settings.interfaceMode).to.equal('simple');
  });
});
