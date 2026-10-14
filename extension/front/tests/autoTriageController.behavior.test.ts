// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require('chai');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { JSDOM } = require('jsdom');

function mountController(options = {}) {
  const html = fs.readFileSync(
    path.resolve(__dirname, '../shared/panel-dashboard.html'),
    'utf8',
  );
  const sourcePath = path.resolve(__dirname, '../static/autoTriageController.js');
  const dom = new JSDOM(html, { runScripts: 'outside-only' });
  for (const selector of options.removeSelectors || []) {
    dom.window.document.querySelectorAll(selector).forEach((element) => element.remove());
  }
  const messages = [];
  const listeners = [];
  let binaryPath = options.binaryPath === undefined ? '/tmp/sample.bin' : options.binaryPath;
  const bus = {
    postMessage(message) { messages.push(message); },
    onMessage(listener) { listeners.push(listener); },
  };
  Object.assign(dom.window, {
    POFHubMessageBus: bus,
    ollamaUiState: { modelUserSelected: Boolean(options.selectedModel) },
    getCurrentOllamaModel: () => options.selectedModel || '',
  });
  if (!options.omitBinaryGetter) dom.window.getStaticBinaryPath = () => binaryPath;
  vm.runInContext(fs.readFileSync(sourcePath, 'utf8'), dom.getInternalVMContext(), {
    filename: sourcePath,
  });
  dom.window.POFHubAutoTriageController.initAutoTriage();
  return {
    window: dom.window,
    document: dom.window.document,
    messages,
    emit(message) { listeners.forEach((listener) => listener({ data: message })); },
    setBinaryPath(value) { binaryPath = value; },
  };
}

function preflight(binaryPath = '/tmp/sample.bin') {
  return {
    type: 'hubAutoTriagePreflight',
    binaryPath,
    available: true,
    provider: 'ollama',
    model: 'qwen3:8b',
    maxFunctions: 20,
    maxSeconds: 60,
    maxTokens: 2048,
    maxTotalTokens: 10000,
  };
}

describe('auto-triage controller behavior', () => {
  it('refreshes report, preflight and annotations for the active binary', () => {
    const app = mountController();
    expect(app.messages.map((message) => message.type)).to.deep.equal([
      'hubAutoTriageGetReport',
      'hubAutoTriagePreflight',
      'hubLoadAnnotations',
    ]);
    expect(app.messages[1]).to.include({ provider: '', model: '' });
  });

  it('uses an explicitly selected provider/model and handles an empty workspace', () => {
    const selected = mountController({ selectedModel: 'openai@gpt-5' });
    expect(selected.messages[1]).to.include({ provider: 'openai', model: 'gpt-5' });

    const empty = mountController({ binaryPath: '' });
    expect(empty.messages).to.deep.equal([]);
    expect(empty.document.querySelector('[data-auto-triage-help]').textContent)
      .to.equal('Choisis d’abord un binaire dans l’analyse statique.');

    const ollama = mountController({ selectedModel: 'gemma4:e4b' });
    expect(ollama.messages[1]).to.include({ provider: 'ollama', model: 'gemma4:e4b' });
  });

  it('confirms exactly one run and ignores a delayed preflight response', () => {
    const app = mountController();
    app.emit(preflight());
    const prepare = app.document.querySelector('[data-action="auto-triage"]');
    const modal = app.document.querySelector('[data-auto-triage-modal]');
    const confirm = app.document.querySelector('[data-action="auto-triage-confirm"]');

    expect(prepare.disabled).to.equal(false);
    prepare.click();
    expect(modal.hidden).to.equal(false);
    confirm.click();
    expect(modal.hidden).to.equal(true);

    const starts = app.messages.filter((message) => message.type === 'hubAutoTriageStart');
    expect(starts).to.have.length(1);
    expect(starts[0]).to.include({ binaryPath: '/tmp/sample.bin', provider: '', model: '' });

    app.emit(preflight());
    expect(modal.hidden).to.equal(true);
    confirm.click();
    expect(app.messages.filter((message) => message.type === 'hubAutoTriageStart')).to.have.length(1);
  });

  it('updates progress, reloads annotations and supports cancellation', () => {
    const app = mountController();
    app.emit(preflight());
    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');

    app.emit({
      type: 'hubAutoTriageEvent',
      binaryPath: '/tmp/sample.bin',
      requestId: start.requestId,
      event: { type: 'function_start', index: 1, total: 4 },
    });
    expect(app.document.querySelector('[data-action="auto-triage"]').textContent)
      .to.equal('Auto-triage in progress · 2/4');

    app.emit({
      type: 'hubAutoTriageEvent',
      binaryPath: '/tmp/sample.bin',
      requestId: start.requestId,
      event: { type: 'function_done', index: 1, total: 4 },
    });
    expect(app.messages.filter((message) => message.type === 'hubLoadAnnotations')).to.have.length(2);

    app.document.querySelector('[data-action="auto-triage-cancel"]').click();
    expect(app.messages.at(-1)).to.deep.equal({ type: 'hubAiCancel', requestId: start.requestId });
  });

  it('ignores stale binary messages and renders a successful result', () => {
    const app = mountController();
    app.emit(preflight('/tmp/other.bin'));
    expect(app.document.querySelector('[data-action="auto-triage"]').disabled).to.equal(true);

    app.emit(preflight());
    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');
    app.emit({
      type: 'hubAutoTriageDone',
      requestId: start.requestId,
      binaryPath: '/tmp/sample.bin',
      ok: true,
      cancelled: false,
      reportPath: '/tmp/report.md',
    });

    expect(app.document.querySelector('[data-auto-triage-state]').textContent).to.equal('Completed');
    expect(app.document.querySelector('[data-auto-triage-result]').hidden).to.equal(false);
    expect(app.document.querySelector('[data-action="auto-triage-cancel"]').hidden).to.equal(true);
  });

  it('renders annotations, selection budgets and persisted cancelled results', () => {
    const app = mountController();
    app.emit(preflight());
    app.emit({ type: 'hubAnnotations', binaryPath: '/tmp/sample.bin', functionAddrs: ['0x1', '0x2'] });
    expect(app.document.querySelector('[data-auto-triage-functions]').textContent).to.equal('2 détectée(s)');

    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');
    app.emit({
      type: 'hubAutoTriageEvent', binaryPath: '/tmp/sample.bin', requestId: start.requestId,
      event: { type: 'selection_done', provider: 'openai', model: 'gpt', max_functions: 2, max_seconds: 5, max_total_tokens: 99 },
    });
    expect(app.document.querySelector('[data-auto-triage-model]').textContent).to.equal('openai@gpt');

    app.emit({
      type: 'hubAutoTriageDone', requestId: start.requestId, binaryPath: '/tmp/sample.bin',
      ok: true, cancelled: true, reportPath: '/tmp/cancelled.md',
    });
    app.emit({
      type: 'hubAutoTriageReportInfo', binaryPath: '/tmp/sample.bin', reportPath: '/tmp/cancelled.md',
      result: { completedAt: '2026-07-31T10:00:00Z', cancelled: true, provider: 'openai', model: 'gpt', stats: { processed: 2, tokens_used: 99 } },
    });
    expect(app.document.querySelector('[data-auto-triage-state]').textContent).to.equal('Resume required');
    expect(app.document.querySelector('[data-auto-triage-result-title]').textContent)
      .to.equal('Analysis interrupted — resume available');

    app.document.querySelector('[data-action="auto-triage-open-report"]').click();
    app.document.querySelector('[data-action="auto-triage-export-report"]').click();
    expect(app.messages.slice(-2).map((message) => message.type)).to.deep.equal([
      'hubAutoTriageOpenReport', 'hubAutoTriageExportReport',
    ]);
  });

  it('closes with Escape and reports failures without exposing a report', () => {
    const app = mountController();
    app.emit(preflight());
    app.document.querySelector('[data-action="auto-triage"]').click();
    const modal = app.document.querySelector('[data-auto-triage-modal]');
    modal.querySelector('[role="dialog"]').dispatchEvent(new app.window.KeyboardEvent('keydown', { key: 'Escape' }));
    expect(modal.hidden).to.equal(true);

    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');
    app.emit({
      type: 'hubAutoTriageDone', requestId: start.requestId, binaryPath: '/tmp/sample.bin',
      ok: false, error: 'provider offline',
    });
    expect(app.document.querySelector('[data-auto-triage-state]').textContent).to.equal('Failed');
    expect(app.document.querySelector('[data-auto-triage-help]').textContent).to.equal('provider offline');
    expect(app.document.querySelector('[data-auto-triage-result]').hidden).to.equal(true);

    app.emit(preflight());
    expect(app.document.querySelector('[data-auto-triage-help]').textContent)
      .to.equal('provider offline');

    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    expect(app.document.querySelector('[data-auto-triage-help]').textContent).to.equal('');
  });

  it('opens from a host request after preflight and ignores unrelated completions', () => {
    const app = mountController();
    app.emit({ type: 'hubAutoTriageOpenPanel', binaryPath: '/tmp/sample.bin' });
    expect(app.messages.at(-1).type).to.equal('hubAutoTriagePreflight');
    app.emit(preflight());
    expect(app.document.querySelector('[data-auto-triage-modal]').hidden).to.equal(false);
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');
    app.emit({ type: 'hubError', requestId: 'other-request' });
    expect(app.document.querySelector('[data-action="auto-triage"]').disabled).to.equal(true);
    app.emit({ type: 'hubError', requestId: start.requestId });
    expect(app.document.querySelector('[data-action="auto-triage-cancel"]').hidden).to.equal(false);
  });

  it('cancels the previous binary when starting another and reuses cached preflight', () => {
    const app = mountController();
    app.emit(preflight());
    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const first = app.messages.find((message) => message.type === 'hubAutoTriageStart');

    app.setBinaryPath('/tmp/next.bin');
    app.emit(preflight('/tmp/next.bin'));
    app.emit({ type: 'hubAutoTriageOpenPanel', binaryPath: '/tmp/next.bin' });
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    expect(app.messages).to.deep.include({ type: 'hubAiCancel', requestId: first.requestId });
    expect(app.messages.filter((message) => message.type === 'hubAutoTriageStart')).to.have.length(2);
  });

  it('remains safe when optional dashboard elements and the binary getter are absent', () => {
    const app = mountController({
      omitBinaryGetter: true,
      removeSelectors: [
        '[data-action="auto-triage-open-report"]',
        '[data-action="auto-triage-export-report"]',
        '[data-action="auto-triage"]',
        '[data-action="auto-triage-cancel"]',
        '[data-auto-triage-modal]',
        '[data-auto-triage-state]',
        '[data-auto-triage-help]',
        '[data-auto-triage-result]',
      ],
    });
    expect(app.messages).to.deep.equal([]);
    app.emit(preflight(''));
    app.emit({ type: 'hubAnnotations', binaryPath: '', functionAddrs: null });
    app.window.POFHubAutoTriageController.startRun('');
    app.window.POFHubAutoTriageController.refreshReportButton();
  });

  it('handles unavailable, malformed and unrelated host messages defensively', () => {
    const app = mountController();
    app.emit({ ...preflight(), available: false });
    expect(app.document.querySelector('[data-auto-triage-help]').textContent)
      .to.equal('Désassemble d’abord ce binaire pour activer l’auto-triage.');
    app.emit({ type: 'hubAnnotations', binaryPath: '/tmp/other.bin', functionAddrs: ['0x1'] });
    app.emit({ type: 'hubAnnotations', binaryPath: '/tmp/sample.bin', functionAddrs: null });
    app.emit({ type: 'hubAutoTriageEvent', binaryPath: '', requestId: 'none', event: null });
    app.emit({ type: 'unknown' });
    app.emit({ type: 'hubAutoTriageDone', binaryPath: '/tmp/sample.bin', requestId: 'stale', ok: true });

    app.emit(preflight());
    app.document.querySelector('[data-action="auto-triage"]').click();
    app.document.querySelector('[data-action="auto-triage-confirm"]').click();
    const start = app.messages.find((message) => message.type === 'hubAutoTriageStart');
    app.emit({ type: 'hubAutoTriageDone', binaryPath: '/tmp/sample.bin', requestId: start.requestId, ok: false });
    expect(app.document.querySelector('[data-auto-triage-help]').textContent)
      .to.equal('Auto-triage failed.');
  });
});
