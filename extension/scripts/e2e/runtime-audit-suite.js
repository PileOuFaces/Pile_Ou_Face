// SPDX-License-Identifier: AGPL-3.0-only
const assert = require('assert');
const childProcess = require('child_process');
const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');
const { PassThrough, Writable } = require('stream');
const Mocha = require('mocha');
const vscode = require('vscode');
const {
  payloadAssertionsForMessage,
  requiresUiConsumed,
  responseTypesForMessage,
} = require('./runtime-audit-feature-map');
const {
  HubPage,
  captureUiFailure,
  connectToHubWebview,
} = require('./vscode-ui-driver');

const AUDIT_FILE = 'audit-runtime-usage.jsonl';
const E2E_AUDIT_MOCHA_TIMEOUT_MS = 120000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function findAuditFiles(root) {
  const results = [];
  const stack = [root];
  while (stack.length) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && entry.name === AUDIT_FILE) {
        results.push(fullPath);
      }
    }
  }
  return results;
}

function readEvents(filePath) {
  return fs.readFileSync(filePath, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => JSON.parse(line));
}

async function waitForAuditEvents(userDataDir, predicate, timeoutMs = 15000) {
  const startedAt = Date.now();
  let lastFiles = [];
  let lastEvents = [];
  while (Date.now() - startedAt < timeoutMs) {
    lastFiles = findAuditFiles(userDataDir);
    const allEvents = [];
    for (const filePath of lastFiles) {
      const events = readEvents(filePath);
      allEvents.push(...events);
    }
    lastEvents = allEvents;
    if (predicate(allEvents, lastFiles.join(','))) return { filePath: lastFiles.join(','), events: allEvents };
    await sleep(250);
  }
  const names = lastEvents.map((event) => `${event.kind}:${event.name}`).join(', ');
  throw new Error(`Timed out waiting for runtime audit events. files=${lastFiles.join(', ') || '<none>'} events=${names || '<none>'}`);
}

function hasEvent(events, kind, name) {
  return events.some((event) => event.kind === kind && event.name === name);
}

function readFixtureSpecs() {
  if (process.env.POF_E2E_FIXTURES_JSON) {
    return JSON.parse(process.env.POF_E2E_FIXTURES_JSON);
  }
  const fixtureBinary = process.env.POF_E2E_FIXTURE_BINARY;
  assert.ok(fixtureBinary, 'POF_E2E_FIXTURE_BINARY is required');
  return [{ name: 'fixture', path: fixtureBinary, entry: '0x400078', sizeBytes: fs.statSync(fixtureBinary).size }];
}

function appendPerfEvent(type, payload = {}) {
  const perfPath = process.env.POF_E2E_PERF_PATH;
  if (!perfPath) return;
  fs.mkdirSync(path.dirname(perfPath), { recursive: true });
  const event = {
    ts: new Date().toISOString(),
    type,
    memory: process.memoryUsage(),
    ...payload,
  };
  fs.appendFileSync(perfPath, `${JSON.stringify(event)}\n`);
}

function startPerfSampler(scenario, details = {}) {
  appendPerfEvent('scenario_start', { scenario, details });
  const timer = setInterval(() => {
    appendPerfEvent('sample', { scenario, details });
  }, 250);
  return (result = {}) => {
    clearInterval(timer);
    appendPerfEvent('scenario_stop', { scenario, details, result });
  };
}

function countEvents(events, predicate) {
  return events.filter(predicate).length;
}

async function waitForCommandAudit(userDataDir, commandId, timeoutMs) {
  return waitForAuditEvents(userDataDir, (candidateEvents) => (
    hasEvent(candidateEvents, 'command', commandId)
  ), timeoutMs);
}

function countCurrentAuditEvents(userDataDir, predicate) {
  let total = 0;
  for (const filePath of findAuditFiles(userDataDir)) {
    total += readEvents(filePath).filter(predicate).length;
  }
  return total;
}

function readCurrentAuditEvents(userDataDir) {
  const events = [];
  for (const filePath of findAuditFiles(userDataDir)) {
    events.push(...readEvents(filePath));
  }
  return events;
}

async function waitForAuditQuiet(userDataDir, { quietMs = 100, timeoutMs = 1000, pollMs = 50 } = {}) {
  const startedAt = Date.now();
  let lastCount = readCurrentAuditEvents(userDataDir).length;
  let stableSince = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    await sleep(pollMs);
    const currentCount = readCurrentAuditEvents(userDataDir).length;
    if (currentCount !== lastCount) {
      lastCount = currentCount;
      stableSince = Date.now();
      continue;
    }
    if (Date.now() - stableSince >= quietMs) return { eventCount: currentCount, quietMs };
  }
  return { eventCount: lastCount, quietMs: Date.now() - stableSince, timedOut: true };
}

function eventKey(event) {
  return `${event.kind || 'unknown'}:${event.name || '<unnamed>'}`;
}

function summarizeAuditDelta(beforeEvents, afterEvents) {
  const beforeCounts = new Map();
  for (const event of beforeEvents) {
    beforeCounts.set(eventKey(event), (beforeCounts.get(eventKey(event)) || 0) + 1);
  }

  const deltaCounts = new Map();
  for (const event of afterEvents) {
    const key = eventKey(event);
    const remainingBefore = beforeCounts.get(key) || 0;
    if (remainingBefore > 0) {
      beforeCounts.set(key, remainingBefore - 1);
      continue;
    }
    deltaCounts.set(key, (deltaCounts.get(key) || 0) + 1);
  }

  const byKind = {};
  const names = [];
  for (const [key, count] of deltaCounts.entries()) {
    const [kind, ...nameParts] = key.split(':');
    byKind[kind] = (byKind[kind] || 0) + count;
    names.push({ kind, name: nameParts.join(':'), count });
  }
  names.sort((left, right) => right.count - left.count || left.kind.localeCompare(right.kind) || left.name.localeCompare(right.name));

  return {
    totalEvents: names.reduce((total, item) => total + item.count, 0),
    byKind,
    topNames: names.slice(0, 8),
    repeatedNames: names.filter((item) => item.count >= 3).slice(0, 8),
  };
}

const AUTOLOAD_FANOUT_MESSAGES = new Set([
  'hubSaveAnnotation',
  'hubSaveBookmark',
  'hubSaveFunctionReview',
  'hubDeleteBookmark',
  'hubClearBookmarks',
  'hubDeleteAnnotation',
  'hubUseBinaryPath',
]);

function payloadAssertionMatchesEvent(event, assertion) {
  if (!event || event.kind !== 'webview_post_message') return false;
  if (event.name !== assertion.responseType) return false;
  if (assertion.allowErrors !== true && (event.hasError || event.hasResultError || event.ok === false || event.resultOk === false)) {
    return false;
  }
  const keys = new Set(Array.isArray(event.keys) ? event.keys : []);
  for (const key of assertion.requiredKeys || []) {
    if (!keys.has(key)) return false;
  }
  for (const [key, minValue] of Object.entries(assertion.minCounts || {})) {
    if (!Number.isFinite(event[key]) || event[key] < minValue) return false;
  }
  for (const [key, maxValue] of Object.entries(assertion.maxCounts || {})) {
    if (!Number.isFinite(event[key]) || event[key] > maxValue) return false;
  }
  for (const [key, expectedValue] of Object.entries(assertion.exactFields || {})) {
    if (event[key] !== expectedValue) return false;
  }
  return true;
}

async function dispatchHubMessageAndWait(userDataDir, message, timeoutMs = 20000) {
  assert.ok(message?.type, 'hub message type is required');
  const before = countCurrentAuditEvents(userDataDir, (event) => (
    event.kind === 'webview_message' && event.name === message.type
  ));
  await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', message);
  return waitForAuditEvents(userDataDir, (candidateEvents) => (
    countEvents(candidateEvents, (event) => event.kind === 'webview_message' && event.name === message.type) > before
  ), timeoutMs);
}

async function dispatchHubMessageAndWaitForResponses(userDataDir, message, responseTypes = [], options = {}) {
  assert.ok(message?.type, 'hub message type is required');
  const timeoutMs = options.timeoutMs || 20000;
  const requireUiConsumed = options.requireUiConsumed === true;
  const payloadAssertions = Array.isArray(options.payloadAssertions) ? options.payloadAssertions : [];
  const expectedResponses = [...new Set(responseTypes.filter(Boolean))];
  const beforeInbound = countCurrentAuditEvents(userDataDir, (event) => (
    event.kind === 'webview_message' && event.name === message.type
  ));
  const beforeResponses = new Map(expectedResponses.map((responseType) => [
    responseType,
    countCurrentAuditEvents(userDataDir, (event) => (
      event.kind === 'webview_post_message' && event.name === responseType
    )),
  ]));
  const beforeUiConsumed = new Map(expectedResponses.map((responseType) => [
    responseType,
    countCurrentAuditEvents(userDataDir, (event) => (
      event.kind === 'webview_message'
      && event.name === 'hubUiConsumed'
      && event.responseType === responseType
    )),
  ]));
  const beforePayloadAssertions = new Map(payloadAssertions.map((assertion, index) => [
    index,
    countCurrentAuditEvents(userDataDir, (event) => payloadAssertionMatchesEvent(event, assertion)),
  ]));

  await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', message);
  try {
    return await waitForAuditEvents(userDataDir, (candidateEvents) => {
      const inboundOk = countEvents(candidateEvents, (event) => (
        event.kind === 'webview_message' && event.name === message.type
      )) > beforeInbound;
      if (!inboundOk) return false;
      const responsesPosted = expectedResponses.every((responseType) => (
        countEvents(candidateEvents, (event) => (
          event.kind === 'webview_post_message' && event.name === responseType
        )) > (beforeResponses.get(responseType) || 0)
      ));
      if (!responsesPosted) return false;
      if (requireUiConsumed) {
        const uiConsumed = expectedResponses.every((responseType) => (
          countEvents(candidateEvents, (event) => (
            event.kind === 'webview_message'
            && event.name === 'hubUiConsumed'
            && event.responseType === responseType
          )) > (beforeUiConsumed.get(responseType) || 0)
        ));
        if (!uiConsumed) return false;
      }
      return payloadAssertions.every((assertion, index) => (
        countEvents(candidateEvents, (event) => payloadAssertionMatchesEvent(event, assertion)) > (beforePayloadAssertions.get(index) || 0)
      ));
    }, timeoutMs);
  } catch (error) {
    const mode = payloadAssertions.length
      ? 'response payload assertion(s)'
      : (requireUiConsumed ? 'response(s) consumed by UI' : 'response(s)');
    throw new Error(`Timed out waiting for ${message.type} ${mode}: ${expectedResponses.join(', ')}. ${error.message || error}`);
  }
}

function findDisasmEditor() {
  return vscode.window.visibleTextEditors.find((editor) => (
    editor.document.uri.fsPath.endsWith('.disasm.asm')
  ));
}

function findDisasmDocument() {
  return vscode.workspace.textDocuments.find((document) => (
    document.uri.fsPath.endsWith('.disasm.asm')
  ));
}

function findDecompilerConfigDocument() {
  return vscode.workspace.textDocuments.find((document) => (
    document.uri.fsPath.endsWith('decompilers.json')
  ));
}

function readDecompilerConfigFromOpenDocument() {
  const document = findDecompilerConfigDocument();
  if (!document) return null;
  return JSON.parse(fs.readFileSync(document.uri.fsPath, 'utf8'));
}

function selectFirstAddressLine(editor) {
  assert.ok(editor, 'a disassembly editor must be visible');
  for (let lineNumber = 0; lineNumber < editor.document.lineCount; lineNumber += 1) {
    const line = editor.document.lineAt(lineNumber);
    if (/^\s*(?:0x)?[0-9a-fA-F]+:/.test(line.text)) {
      const addressMatch = line.text.match(/^\s*((?:0x)?[0-9a-fA-F]+):/);
      const start = line.firstNonWhitespaceCharacterIndex;
      const end = start + (addressMatch?.[1] || '').length;
      editor.selection = new vscode.Selection(
        new vscode.Position(lineNumber, start),
        new vscode.Position(lineNumber, end)
      );
      return addressMatch?.[1] || '';
    }
  }
  throw new Error(`No address line found in ${editor.document.uri.fsPath}`);
}

async function withWindowMocks(mocks, callback) {
  const originals = {};
  for (const [name, replacement] of Object.entries(mocks)) {
    originals[name] = {
      descriptor: Object.getOwnPropertyDescriptor(vscode.window, name),
      value: vscode.window[name],
    };
    try {
      Object.defineProperty(vscode.window, name, {
        value: replacement,
        writable: true,
        configurable: true,
      });
    } catch {
      vscode.window[name] = replacement;
    }
  }
  try {
    return await callback();
  } finally {
    for (const [name, original] of Object.entries(originals)) {
      try {
        if (original.descriptor) {
          Object.defineProperty(vscode.window, name, original.descriptor);
        } else {
          delete vscode.window[name];
        }
      } catch {
        vscode.window[name] = original.value;
      }
    }
  }
}

async function withCommandMocks(mocks, callback) {
  const originals = {};
  for (const [name, replacement] of Object.entries(mocks)) {
    originals[name] = vscode.commands[name];
    vscode.commands[name] = replacement;
  }
  try {
    return await callback();
  } finally {
    for (const [name, original] of Object.entries(originals)) {
      vscode.commands[name] = original;
    }
  }
}

function isAiProviderScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'mcp', 'ai_provider.py')));
}

function isOllamaBridgeScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'mcp', 'ollama_bridge.py')));
}

function isAiConsentScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'mcp', 'ai_consent.py')));
}

function isAutoTriageScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'mcp', 'auto_triage.py')));
}

function isDecompileAugmentScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'static', 'decompile', 'augment.py')));
}

function isXrefsScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'static', 'disasm', 'xrefs.py')));
}

function isSymbolsScript(args) {
  return Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'static', 'binary', 'symbols.py')));
}

function createMockProviderList() {
  return JSON.stringify({
    providers: [{ name: 'openai', configured: true, model: 'e2e-model' }],
    default_provider: 'openai',
  });
}

function createMockDecompilerList() {
  return JSON.stringify({
    e2e_tool: true,
    _meta: {
      provider: 'auto',
      labels: { e2e_tool: 'E2E Tool' },
      docker_images: {},
      docker_images_available: {},
      local_available: { e2e_tool: true },
    },
  });
}

function isDecompilerListScript(args) {
  return Array.isArray(args)
    && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'static', 'decompile', 'decompile.py')))
    && args.includes('--list');
}

async function withChildProcessMocks(mocks, callback) {
  const originals = {};
  for (const [name, replacement] of Object.entries(mocks)) {
    originals[name] = childProcess[name];
    childProcess[name] = replacement;
  }
  try {
    return await callback();
  } finally {
    for (const [name, original] of Object.entries(originals)) {
      childProcess[name] = original;
    }
  }
}

async function withGlobalMocks(mocks, callback) {
  const originals = {};
  for (const [name, replacement] of Object.entries(mocks)) {
    originals[name] = globalThis[name];
    globalThis[name] = replacement;
  }
  try {
    return await callback();
  } finally {
    for (const [name, original] of Object.entries(originals)) {
      globalThis[name] = original;
    }
  }
}

function jsonResponse(body, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
}

async function run() {
  const mocha = new Mocha({ ui: 'bdd', color: true, timeout: E2E_AUDIT_MOCHA_TIMEOUT_MS });
  const suite = Mocha.Suite.create(mocha.suite, 'runtime usage audit e2e');

  suite.addTest(new Mocha.Test('creates audit JSONL and records hub startup events', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');

    const extension = vscode.extensions.getExtension('PileOuFaces.stack-visualizer');
    assert.ok(extension, 'Pile ou Face extension must be installed in the test host');
    await extension.activate();

    const stopPerf = startPerfSampler('hub-startup');
    try {
      await vscode.commands.executeCommand('pileOuFace.goToAddress');

      const { events } = await waitForAuditEvents(userDataDir, (candidateEvents) => (
        hasEvent(candidateEvents, 'audit', 'audit_start')
        && hasEvent(candidateEvents, 'command', 'pileOuFace.goToAddress')
        && hasEvent(candidateEvents, 'webview_message', 'hubReady')
        && hasEvent(candidateEvents, 'webview_message', 'hubLoadPluginState')
      ));

      assert.ok(hasEvent(events, 'webview_message', 'hubReady'), 'hubReady should be audited');
      stopPerf({ ok: true });
    } catch (error) {
      stopPerf({ ok: false, error: String(error && error.message ? error.message : error) });
      throw error;
    }
  }));

  suite.addTest(new Mocha.Test('guides the user from an empty workspace without enabling unavailable actions', async () => {
    let target = null;
    try {
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      const hub = new HubPage(target);

      await hub.openPanel('dashboard');
      await hub.topBarBinaryName().waitForText('Choisir un fichier', 30000);
      await hub.autoTriageBinary().waitForText('Aucun binaire', 30000);
      assert.equal(await hub.autoTriageButton().isEnabled(), false, 'auto-triage must stay disabled without a binary');

      await hub.dashboardStaticAction().click();
      await hub.expectActive(hub.panel('static'), 'static panel opened from the empty dashboard');
      await hub.topBarBinaryMenu().waitFor({ state: 'visible' });
      await hub.currentBinaryName().waitForText('Aucun fichier sélectionné', 30000);
      await hub.disassemblyBinarySummary().waitForText('Aucun fichier', 30000);
      assert.equal(await hub.decompileAugmentButton().isEnabled(), false, 'AI augmentation must stay disabled without decompiled code');
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-empty-workspace',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('persists the simplified static interface across a hub reload', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    let target = null;
    let hub = null;
    const isSettingsSave = (event) => event.kind === 'webview_message' && event.name === 'hubSaveSettings';
    try {
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      hub = new HubPage(target);
      await hub.openPanel('options');

      const savesBeforeSimpleMode = countCurrentAuditEvents(userDataDir, isSettingsSave);
      await hub.interfaceModeButton('simple').click();
      await hub.interfaceModeInput().waitForValue('simple', 30000);
      await hub.interfaceModeButton('simple').waitForAttribute('aria-pressed', 'true', 30000);
      await hub.staticFeaturePicker().waitForAttribute('class', 'is-disabled', 30000);
      await waitForAuditEvents(userDataDir, (events) => countEvents(events, isSettingsSave) > savesBeforeSimpleMode);

      await hub.openPanel('static');
      await hub.group('code').click();
      assert.equal(await hub.subTab('callgraph').textContent(), null, 'specialized call graph tab must be hidden in simple mode');
      assert.notEqual(await hub.subTab('disasm').textContent(), null, 'essential disassembly tab must remain visible in simple mode');

      target.close();
      target = null;
      hub = null;
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      hub = new HubPage(target);
      await hub.openPanel('options');
      await hub.interfaceModeInput().waitForValue('simple', 30000);
      await hub.interfaceModeButton('simple').waitForAttribute('aria-pressed', 'true', 30000);

      const savesBeforeRestore = countCurrentAuditEvents(userDataDir, isSettingsSave);
      await hub.interfaceModeButton('advanced').clickDom();
      await hub.interfaceModeInput().waitForValue('advanced', 30000);
      await hub.staticFeaturesAllButton().waitForEnabled(30000);
      await hub.staticFeaturesAllButton().clickDom();
      await waitForAuditEvents(userDataDir, (events) => countEvents(events, isSettingsSave) > savesBeforeRestore);
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-settings-persistence',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      try {
        if (!hub) {
          await vscode.commands.executeCommand('pileOuFace.goToAddress');
          target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
          hub = new HubPage(target);
        }
        if (hub) {
          const savesBeforeCleanup = countCurrentAuditEvents(userDataDir, isSettingsSave);
          await hub.openPanel('options');
          if (await hub.interfaceModeButton('advanced').getAttribute('aria-pressed') !== 'true') {
            await hub.interfaceModeButton('advanced').clickDom();
            await hub.interfaceModeInput().waitForValue('advanced', 30000);
          }
          await hub.staticFeaturesAllButton().clickDom();
          await waitForAuditEvents(userDataDir, (events) => countEvents(events, isSettingsSave) > savesBeforeCleanup);
        }
      } catch {
        // Preserve the original assertion while keeping best-effort test isolation.
      }
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('retries auto-triage from the real confirmation UI without reopening the modal', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
    const [auditPath] = findAuditFiles(userDataDir)
      .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs);
    assert.ok(auditPath, 'runtime audit file must identify the extension storage directory');
    const storageDir = path.dirname(auditPath);
    const binaryPath = path.join(storageDir, 'e2e-auto-triage.bin');
    const mappingPath = path.join(storageDir, 'e2e-auto-triage.disasm.mapping.json');
    let reportPath = '';
    let target = null;
    let attempt = 0;
    const originalExecFile = childProcess.execFile;
    const originalSpawn = childProcess.spawn;
    try {
      fs.copyFileSync(fixture.path, binaryPath);
      fs.writeFileSync(mappingPath, JSON.stringify({ function_addrs: ['0x400078'] }), 'utf8');

      await withChildProcessMocks({
        execFile: (file, args = [], options = {}, callback = undefined) => {
          if (!isAiConsentScript(args)) {
            return originalExecFile.call(childProcess, file, args, options, callback);
          }
          const cb = typeof options === 'function' ? options : callback;
          const proc = new EventEmitter();
          process.nextTick(() => cb?.(null, JSON.stringify({ consented: true }), ''));
          return proc;
        },
        spawn: (file, args = [], options = {}) => {
          if (!isAutoTriageScript(args)) {
            return originalSpawn.call(childProcess, file, args, options);
          }
          attempt += 1;
          const proc = new EventEmitter();
          proc.stdout = new PassThrough();
          proc.stderr = new PassThrough();
          proc.kill = () => true;
          reportPath = String(args[args.indexOf('--report-out') + 1] || '');
          process.nextTick(() => {
            if (attempt === 1) {
              proc.stderr.end('provider offline');
              proc.stdout.end();
              proc.emit('close', 1);
              return;
            }
            fs.writeFileSync(reportPath, '# Rapport auto-triage E2E\n', 'utf8');
            proc.stdout.write(`${JSON.stringify({ type: 'selection_done', total: 1, provider: 'openai', model: 'e2e-model' })}\n`);
            proc.stdout.write(`${JSON.stringify({ type: 'function_done', index: 0, total: 1 })}\n`);
            proc.stdout.write(`${JSON.stringify({ type: 'done', stats: { processed: 1, tokens_used: 7 } })}\n`);
            proc.stdout.end();
            proc.stderr.end();
            proc.emit('close', 0);
          });
          return proc;
        },
      }, async () => {
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        const hub = new HubPage(target);
        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubUseBinaryPath',
          binaryPath,
        });
        await hub.binaryPath().waitForValue(path.basename(binaryPath), 30000);
        await hub.openPanel('dashboard');
        await hub.autoTriageBinary().waitForText(path.basename(binaryPath), 30000);
        await hub.autoTriageButton().waitFor({ state: 'visible' });
        await hub.autoTriageButton().waitForEnabled(30000);
        assert.equal(await hub.autoTriageButton().isEnabled(), true, 'auto-triage must be available after preflight');

        await hub.autoTriageButton().click();
        await hub.autoTriageModal().waitFor({ state: 'visible' });
        assert.equal(await hub.autoTriageModal().getAttribute('hidden'), null, 'confirmation modal must be open');
        await hub.autoTriageConfirmButton().click();
        await hub.autoTriageState().waitForText('Échec', 30000);
        await hub.autoTriageHelp().waitForText('provider offline', 30000);
        assert.equal(await hub.autoTriageModal().getAttribute('hidden'), '', 'confirmation modal must close after the failed run starts');
        assert.equal(await hub.autoTriageButton().isEnabled(), true, 'retry must be available after a provider error');

        await hub.autoTriageButton().click();
        await hub.autoTriageModal().waitFor({ state: 'visible' });
        await hub.autoTriageConfirmButton().click();
        await hub.autoTriageState().waitForText('Terminé', 30000);
        await hub.autoTriageResult().waitFor({ state: 'visible' });
        await hub.autoTriageResultTitle().waitForText('Dernier auto-triage terminé', 30000);
        assert.equal(await hub.autoTriageModal().getAttribute('hidden'), '', 'confirmation modal must stay closed after success');
        assert.equal(attempt, 2, 'one failed run and one successful retry must execute');
      });
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-auto-triage-retry',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
      for (const filePath of [binaryPath, mappingPath, reportPath].filter(Boolean)) {
        try { fs.rmSync(filePath, { force: true }); } catch { /* Best-effort fixture cleanup. */ }
      }
    }
  }));

  suite.addTest(new Mocha.Test('accepts global decompile augmentation and restores it from cache through the real UI', async () => {
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
    const functionAddr = String(fixture.entry || '0x400078');
    const rawCode = 'int main(void) { return 0; }';
    const functionCode = 'int main(void) { /* function retry succeeded */ return 0; }';
    const augmentedCode = 'int main(void) { /* validated by E2E */ return 0; }';
    let target = null;
    let accepted = false;
    let suggestCalls = 0;
    let functionDecompileAttempts = 0;
    const originalExecFile = childProcess.execFile;
    const augmentationResult = () => ({
      ok: true,
      found: accepted,
      cached: accepted,
      cache_key: 'e2e-decompile-augmentation',
      raw_code: rawCode,
      augmented_code: augmentedCode,
      accepted_ids: accepted ? ['summary'] : [],
      proposal: { summary: 'Nom et commentaire proposés par le test E2E' },
    });
    try {
      await withChildProcessMocks({
        execFile: (file, args = [], options = {}, callback = undefined) => {
          const cb = typeof options === 'function' ? options : callback;
          if (isAiConsentScript(args)) {
            const proc = new EventEmitter();
            process.nextTick(() => cb?.(null, JSON.stringify({ consented: true }), ''));
            return proc;
          }
          if (isDecompileAugmentScript(args)) {
            const proc = new EventEmitter();
            const action = String(args[args.indexOf('--action') + 1] || '');
            process.nextTick(() => {
              if (action === 'suggest') suggestCalls += 1;
              if (action === 'accept') accepted = true;
              cb?.(null, JSON.stringify(augmentationResult()), '');
            });
            return proc;
          }
          if (isSymbolsScript(args)) {
            const proc = new EventEmitter();
            const result = JSON.stringify({
              symbols: [{ addr: functionAddr, name: 'main', type: 'T', size: 16 }],
            });
            process.nextTick(() => cb?.(null, result, ''));
            return proc;
          }
          if (Array.isArray(args) && args.some((arg) => String(arg || '').endsWith(path.join('backends', 'static', 'decompile', 'decompile.py')))) {
            const proc = new EventEmitter();
            let result;
            if (args.includes('--list')) {
              result = createMockDecompilerList();
            } else if (args.includes('--addr')) {
              functionDecompileAttempts += 1;
              result = JSON.stringify(functionDecompileAttempts === 1
                ? { ok: false, error: 'fixture decompiler unavailable', error_type: 'tool_error' }
                : {
                  ok: true,
                  addr: functionAddr,
                  name: 'main',
                  code: functionCode,
                  score: 100,
                });
            } else {
              result = JSON.stringify({
                ok: true,
                functions: [{ addr: functionAddr, name: 'main', code: rawCode }],
                score: 100,
              });
            }
            process.nextTick(() => cb?.(null, result, ''));
            return proc;
          }
          return originalExecFile.call(childProcess, file, args, options, callback);
        },
      }, async () => {
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        let hub = new HubPage(target);
        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubUseBinaryPath',
          binaryPath: fixture.path,
        });
        await hub.binaryPath().waitForValue(path.basename(fixture.path), 30000);
        await hub.openPanel('static');
        await hub.openStaticTab('code', 'decompile');
        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubLoadSymbols',
          binaryPath: fixture.path,
          useCache: false,
        });
        await hub.decompileOutput().waitForText(rawCode, 30000);
        assert.equal(await hub.decompileFunctionSelect().inputValue(), '', 'the fixture remains in global decompile mode');
        assert.equal(await hub.decompileAugmentButton().isEnabled(), true, 'a global result with one function must enable augmentation');

        await hub.decompileFunctionSelect().waitForText('main', 30000);
        await hub.decompileFunctionSelect().fill(functionAddr);
        await hub.decompileContent().waitForText('Erreur du décompilateur — vérifiez les logs', 30000);
        assert.equal(await hub.decompileFunctionSelect().inputValue(), functionAddr, 'the failed function selection must stay selected');
        await hub.decompileRebuildButton().clickDom();
        await hub.decompileOutput().waitForText('function retry succeeded', 30000);
        assert.equal(functionDecompileAttempts, 2, 'one failed function run and one successful retry must execute');

        await hub.decompileFunctionSelect().fill('');
        await hub.decompileOutput().waitForText(rawCode, 30000);

        await hub.decompileAugmentButton().click();
        await hub.decompileAugmentReview().waitFor({ state: 'visible', timeout: 30000 });
        await hub.decompileAugmentSuggestions().waitForText('Nom et commentaire proposés', 30000);
        await hub.decompileAugmentAcceptButton().click();
        await hub.decompileAugmentStatus().waitForText('Version IA appliquée et enregistrée dans le cache.', 30000);
        await hub.decompileOutput().waitForText('validated by E2E', 30000);
        assert.equal(await hub.decompileAugmentReview().getAttribute('hidden'), '', 'review must close after acceptance');
        assert.equal(suggestCalls, 1, 'the provider suggestion must run exactly once');

        target.close();
        target = null;
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        hub = new HubPage(target);
        await hub.openPanel('static');
        await hub.openStaticTab('code', 'decompile');
        await hub.decompileOutput().waitForText('validated by E2E', 30000);
        await hub.decompileAugmentStatus().waitForText('Version IA acceptée restaurée depuis le cache.', 30000);
        assert.equal(suggestCalls, 1, 'restoring the accepted cache must not call the provider again');
      });
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-decompile-augmentation-cache',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('installs and authorizes a plugin, then runs scripts through the real UI', async () => {
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
    const pluginBundlePath = path.join(path.dirname(fixture.path), 'e2e-safe-plugin.pofplug');
    let target = null;
    let installed = false;
    let consented = false;
    let consentCalls = 0;
    let pluginInvocations = 0;
    let scriptAttempts = 0;
    const originalExecFile = childProcess.execFile;
    const originalSpawn = childProcess.spawn;
    const pluginRuntimeResult = () => JSON.stringify({
      search_paths: [],
      summary: installed ? { [consented ? 'active' : 'pending_consent']: 1 } : {},
      attached: {
        commands: consented ? ['e2e.inspect'] : [],
        command_sources: consented ? { 'e2e.inspect': 'pof.e2e-safe-plugin' } : {},
      },
      plugins: installed ? [{
        id: 'pof.e2e-safe-plugin',
        state: consented ? 'active' : 'pending_consent',
        root_path: path.dirname(pluginBundlePath),
        manifest: {
          name: 'E2E Safe Plugin',
          version: '1.0.0',
          kind: 'analysis-pack',
          capabilities: { analysis: ['safe-fixture'] },
          ui: { family: 'e2e' },
        },
      }] : [],
    });
    try {
      fs.writeFileSync(pluginBundlePath, 'deterministic plugin fixture\n', 'utf8');
      await withWindowMocks({
        showOpenDialog: async () => [vscode.Uri.file(pluginBundlePath)],
      }, async () => withChildProcessMocks({
        execFile: (file, args = [], options = {}, callback = undefined) => {
          const cb = typeof options === 'function' ? options : callback;
          const script = String(args[0] || '');
          const proc = new EventEmitter();
          if (script.endsWith(path.join('backends', 'plugins', 'install_plugin.py'))) {
            installed = true;
            process.nextTick(() => cb?.(null, JSON.stringify({
              ok: true,
              plugin_id: 'pof.e2e-safe-plugin',
              installed_to: path.dirname(pluginBundlePath),
            }), ''));
            return proc;
          }
          if (script.endsWith(path.join('backends', 'plugins', 'runtime.py'))) {
            if (args.includes('consent-grant')) {
              consentCalls += 1;
              consented = true;
              process.nextTick(() => cb?.(null, JSON.stringify({ ok: true }), ''));
              return proc;
            }
            if (args.includes('invoke-feature')) pluginInvocations += 1;
            process.nextTick(() => cb?.(null, pluginRuntimeResult(), ''));
            return proc;
          }
          if (script.endsWith(path.join('backends', 'static', 'repl', 'repl.py'))) {
            scriptAttempts += 1;
            if (scriptAttempts === 1) {
              process.nextTick(() => cb?.(null, JSON.stringify({
                ok: true,
                stdout: 'script fixture succeeded\n',
                stderr: '',
                duration_ms: 7,
              }), ''));
            } else {
              const error = new Error('script fixture failed');
              error.stderr = 'script fixture exploded';
              process.nextTick(() => cb?.(error, '', error.stderr));
            }
            return proc;
          }
          return originalExecFile.call(childProcess, file, args, options, callback);
        },
        spawn: (file, args = [], options = {}) => {
          const script = String(args[0] || '');
          if (!script.endsWith(path.join('backends', 'plugins', 'runtime.py'))) {
            return originalSpawn.call(childProcess, file, args, options);
          }
          if (args.includes('consent-grant')) {
            consentCalls += 1;
            consented = true;
          }
          if (args.includes('invoke-feature')) pluginInvocations += 1;
          const proc = new EventEmitter();
          proc.stdin = new PassThrough();
          proc.stdout = new PassThrough();
          proc.stderr = new PassThrough();
          proc.kill = () => true;
          process.nextTick(() => {
            proc.stdout.end(args.includes('consent-grant')
              ? JSON.stringify({ ok: true })
              : pluginRuntimeResult());
            proc.stderr.end();
            proc.emit('close', 0);
          });
          return proc;
        },
      }, async () => {
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        const hub = new HubPage(target);
        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubUseBinaryPath',
          binaryPath: fixture.path,
        });
        await hub.binaryPath().waitForValue(path.basename(fixture.path), 30000);

        await hub.openPanel('options');
        await hub.pluginInstallButton().click();
        await hub.toastContainer().waitForText('Plugin installé', 30000);
        await hub.pluginStateList().waitForText('E2E Safe Plugin', 30000);
        await hub.pluginStateList().waitForText('en attente d’autorisation', 30000);
        assert.equal(consentCalls, 0, 'a newly installed plugin must not be authorized implicitly');
        assert.equal(pluginInvocations, 0, 'a plugin awaiting consent must not execute');

        await hub.pluginConsentButton().click();
        await hub.pluginStateList().waitForText('e2e.inspect', 30000);
        assert.equal(consentCalls, 1, 'authorization must be triggered once from the real UI');

        await hub.openPanel('static');
        await hub.openStaticTab('code', 'script');
        await hub.scriptEditor().fill('print("script fixture")');
        await hub.scriptRunButton().click();
        await hub.scriptStatus().waitForText('✓', 30000);
        await hub.scriptOutput().waitForText('script fixture succeeded', 30000);

        await hub.scriptEditor().fill('raise RuntimeError("fixture")');
        await hub.scriptRunButton().click();
        await hub.scriptStatus().waitForText('Erreur', 30000);
        await hub.scriptOutput().waitForText('script fixture exploded', 30000);
        assert.equal(scriptAttempts, 2, 'success and error scripts must both execute from the UI');
      }));
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-plugin-consent-script',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
      try { fs.rmSync(pluginBundlePath, { force: true }); } catch { /* Best-effort fixture cleanup. */ }
    }
  }));

  suite.addTest(new Mocha.Test('drives the hub through real webview controls', async () => {
    let target = null;
    try {
      const [fixture] = readFixtureSpecs();
      assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      const hub = new HubPage(target);

      await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
        type: 'hubUseBinaryPath',
        binaryPath: fixture.path,
      });
      await hub.binaryPath().waitForValue(path.basename(fixture.path), 30000);

      await hub.openPanel('dashboard');
      await hub.openPanel('static');
      await hub.openStaticTab('data', 'typed_data');

      await hub.openTypeManager();
      await hub.typeEditorSource().fill('struct E2EUiType { int x; int y; };');
      await hub.typeEditorSaveButton().click();
      await hub.typeEditorStatus().waitForText('sauvegardé(s)', 30000);
      await hub.typeEditorCatalog().waitForText('E2EUiType', 30000);

      await hub.typeEditorCloseButton().clickDom();
      await hub.typedDataSection().waitForText('.text', 30000);
      await hub.typedDataSection().fill('.text');
      await hub.typedDataStructSelect().waitForText('E2EUiType', 30000);
      await hub.typedDataStructSelect().fill('E2EUiType');
      await hub.typedDataStructOffset().fill('0x0');
      await hub.typedDataApplyStructButton().click();
      await hub.typedDataStructStatus().waitForText('struct E2EUiType @ +0x0', 30000);
      await hub.typedDataContent().waitForText('E2EUiType', 30000);
      await hub.typedDataContent().waitForText('x', 30000);
      await hub.typedDataContent().waitForText('y', 30000);

      await hub.openTypeManager();
      await hub.typeEditorCatalog().waitForText('E2EUiType', 30000);

      const invalidSource = 'struct E2EInvalidType { int; };';
      await hub.typeEditorSource().fill(invalidSource);
      await hub.typeEditorSaveButton().click();
      await hub.typeEditorStatus().waitForText('Type manquant', 30000);
      await hub.typeEditor().waitFor({ state: 'visible' });
      assert.equal(await hub.typeEditorSource().inputValue(), invalidSource);
      assert.match(
        String(await hub.typeEditorStatus().getAttribute('class') || ''),
        /\bis-error\b/,
      );
      await hub.typeEditorCloseButton().clickDom();

      await hub.openPanel('outils');
      await hub.offsetHexInput().fill('0x14');
      await hub.offsetDecimalInput().waitForValue('20', 30000);
      await hub.offsetBaseInput().fill('0x400000');
      await hub.offsetDeltaInput().fill('0x78');
      await hub.offsetResultInput().waitForValue('0x400078', 30000);

      await hub.openPanel('dashboard');
      await hub.expectActive(hub.panel('dashboard'), 'dashboard panel after returning');
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-real-webview-controls',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('restores the selected binary and visible analysis after reopening the hub', async () => {
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
    const binaryName = path.basename(fixture.path);
    let target = null;
    const originalExecFile = childProcess.execFile;
    try {
      await withChildProcessMocks({
        execFile: (file, args = [], options = {}, callback = undefined) => {
          if (!isSymbolsScript(args)) {
            return originalExecFile.call(childProcess, file, args, options, callback);
          }
          const cb = typeof options === 'function' ? options : callback;
          const proc = new EventEmitter();
          const payload = {
            symbols: [{
              addr: String(fixture.entry || '0x400078'),
              name: 'entry_e2e',
              type: 'T',
              size: 16,
            }],
          };
          process.nextTick(() => cb?.(null, JSON.stringify(payload), ''));
          return proc;
        },
      }, async () => {
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        let hub = new HubPage(target);

        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubUseBinaryPath',
          binaryPath: fixture.path,
        });
        await hub.binaryPath().waitForValue(binaryName, 30000);
        await hub.topBarBinaryName().waitForText(binaryName, 30000);
        await hub.openPanel('static');
        await hub.openStaticTab('data', 'info');
        const visibleInfo = await hub.binaryInfo().waitForText('Entry point', 30000);
        assert.match(visibleInfo, /Format/);
        assert.match(visibleInfo, /Bits/);

        await hub.openStaticTab('data', 'sections');
        const visibleSections = await hub.binarySections().waitForText('.text', 30000);
        assert.match(visibleSections, /section\(s\)/);

        await hub.openStaticTab('code', 'discovered');
        const visibleFunctionCount = await hub.binaryFunctionsCount().waitForText('fonction', 30000);
        assert.match(visibleFunctionCount, /\d+ fonction/);
        await hub.binaryFunctions().waitFor({ state: 'visible', timeout: 30000 });

        const functionExportPath = path.join(
          process.env.POF_E2E_ARTIFACTS_DIR,
          'function-dossier-e2e.json',
        );
        await withWindowMocks({
          showSaveDialog: async () => vscode.Uri.file(functionExportPath),
        }, async () => {
          await hub.functionDossierButton().click();
          const startedAt = Date.now();
          while (!fs.existsSync(functionExportPath) && Date.now() - startedAt < 5000) {
            await sleep(50);
          }
        });
        assert.ok(fs.existsSync(functionExportPath), 'the function dossier must be written after the UI export');
        const exportedFunction = JSON.parse(fs.readFileSync(functionExportPath, 'utf8'));
        assert.ok(String(exportedFunction.function.name || '').trim(), 'the exported function must keep a visible name');
        assert.equal(exportedFunction.function.addr, String(fixture.entry || '0x400078'));

        await hub.firstFunctionDisasmButton().click();
        await hub.expectActive(hub.subTab('disasm'), 'disassembly opened from the function list');
        await hub.goToAddressInput().waitForValue(String(fixture.entry || '0x400078'), 30000);

        target.close();
        target = null;
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        hub = new HubPage(target);

        await hub.binaryPath().waitForValue(binaryName, 30000);
        await hub.topBarBinaryName().waitForText(binaryName, 30000);
        await hub.openPanel('static');
        await hub.openStaticTab('data', 'info');
        const restoredInfo = await hub.binaryInfo().waitForText('Entry point', 30000);
        assert.equal(restoredInfo, visibleInfo, 'the reopened hub must render the same binary analysis');
      });
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-analysis-reload',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('creates, restores, updates and deletes an annotation through the UI', async () => {
    let target = null;
    try {
      const [fixture] = readFixtureSpecs();
      assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      const hub = new HubPage(target);

      await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
        type: 'hubUseBinaryPath',
        binaryPath: fixture.path,
      });
      await hub.binaryPath().waitForValue(path.basename(fixture.path), 30000);
      await hub.openPanel('static');
      await hub.openStaticTab('code', 'disasm');

      await hub.entryPointButton().click();
      await hub.annotationAddress().waitForAttribute('data-addr', '0x', 30000);
      await hub.annotationName().fill('e2e_entry');
      await hub.annotationComment().fill('Annotation créée depuis l’interface');
      await hub.annotationSubmitButton().clickDom();
      await hub.annotationsList().waitForText('e2e_entry', 30000);
      await hub.annotationsList().waitForText('Annotation créée depuis l’interface', 30000);

      await hub.openPanel('dashboard');
      await hub.openPanel('static');
      await hub.openStaticTab('code', 'disasm');
      await hub.annotationsList().waitForText('e2e_entry', 30000);

      await hub.firstAnnotationEditButton().clickDom();
      await hub.annotationName().waitForValue('e2e_entry', 30000);
      await hub.annotationName().fill('e2e_entry_updated');
      await hub.annotationComment().fill('Annotation modifiée depuis l’interface');
      await hub.annotationSubmitButton().clickDom();
      await hub.annotationsList().waitForText('e2e_entry_updated', 30000);
      await hub.annotationsList().waitForText('Annotation modifiée depuis l’interface', 30000);

      await hub.firstAnnotationDeleteButton().clickDom();
      await hub.annotationsList().waitForText('Aucune annotation.', 30000);

      await hub.openPanel('dashboard');
      await hub.openPanel('static');
      await hub.openStaticTab('code', 'disasm');
      await hub.annotationsList().waitForText('Aucune annotation.', 30000);
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-annotation-lifecycle',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('isolates annotations when switching between recent binaries and reopening the hub', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    let target = null;
    try {
      const [sourceFixture] = readFixtureSpecs()
        .sort((left, right) => Number(left.sizeBytes || 0) - Number(right.sizeBytes || 0));
      assert.ok(sourceFixture?.path && fs.existsSync(sourceFixture.path), 'UI fixture binary must exist');
      const isolationRoot = process.env.POF_E2E_WORKSPACE_DIR || path.dirname(sourceFixture.path);
      const fixtureA = {
        ...sourceFixture,
        path: path.join(isolationRoot, `e2e-isolation-a-${process.pid}.elf`),
      };
      const fixtureB = {
        ...sourceFixture,
        path: path.join(isolationRoot, `e2e-isolation-b-${process.pid}.elf`),
      };
      fs.copyFileSync(sourceFixture.path, fixtureA.path);
      fs.appendFileSync(fixtureA.path, `pof-e2e-isolation-a-${process.pid}`);
      fs.copyFileSync(sourceFixture.path, fixtureB.path);
      fs.appendFileSync(fixtureB.path, `pof-e2e-isolation-b-${process.pid}`);
      const binaryAName = path.basename(fixtureA.path);
      const binaryBName = path.basename(fixtureB.path);

      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      let hub = new HubPage(target);
      const countDisasmResponses = () => countCurrentAuditEvents(userDataDir, (event) => (
        event.kind === 'webview_post_message' && event.name === 'hubDisasmReady'
      ));
      const waitForNextDisasm = (previousCount) => waitForAuditEvents(userDataDir, (events) => (
        countEvents(events, (event) => event.kind === 'webview_post_message' && event.name === 'hubDisasmReady') > previousCount
      ), 30000);

      let disasmResponses = countDisasmResponses();
      await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
        type: 'hubUseBinaryPath',
        binaryPath: fixtureA.path,
      });
      await hub.binaryPath().waitForValue(binaryAName, 30000);
      await waitForNextDisasm(disasmResponses);
      await hub.entryPointButton().clickDom();
      await hub.annotationAddress().waitForAttribute('data-addr', '0x', 30000);
      await hub.annotationName().fill('e2e_binary_a');
      await hub.annotationComment().fill('Annotation isolée du premier binaire');
      await hub.annotationSubmitButton().clickDom();
      await hub.annotationsList().waitForText('e2e_binary_a', 30000);

      disasmResponses = countDisasmResponses();
      await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
        type: 'hubUseBinaryPath',
        binaryPath: fixtureB.path,
      });
      await hub.binaryPath().waitForValue(binaryBName, 30000);
      await waitForNextDisasm(disasmResponses);
      await hub.annotationsList().waitForText('Aucune annotation.', 30000);
      await hub.entryPointButton().clickDom();
      await hub.annotationAddress().waitForAttribute('data-addr', '0x', 30000);
      await hub.annotationName().fill('e2e_binary_b');
      await hub.annotationComment().fill('Annotation isolée du second binaire');
      await hub.annotationSubmitButton().clickDom();
      await hub.annotationsList().waitForText('e2e_binary_b', 30000);

      disasmResponses = countDisasmResponses();
      await hub.topBarBinaryButton().clickDom();
      await hub.topBarBinaryMenu().waitFor({ state: 'visible', timeout: 30000 });
      await hub.recentBinaryButton(binaryAName).clickDom();
      await hub.binaryPath().waitForValue(binaryAName, 30000);
      await waitForNextDisasm(disasmResponses);
      await hub.annotationsList().waitForText('e2e_binary_a', 30000);
      assert.ok(
        !String(await hub.annotationsList().textContent() || '').includes('e2e_binary_b'),
        'the first binary must not display the second binary annotation',
      );

      target.close();
      target = null;
      await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
      await vscode.commands.executeCommand('pileOuFace.goToAddress');
      target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
      hub = new HubPage(target);
      await hub.binaryPath().waitForValue(binaryAName, 30000);
      await hub.annotationsList().waitForText('e2e_binary_a', 30000);

      disasmResponses = countDisasmResponses();
      await hub.topBarBinaryButton().clickDom();
      await hub.topBarBinaryMenu().waitFor({ state: 'visible', timeout: 30000 });
      await hub.recentBinaryButton(binaryBName).clickDom();
      await hub.binaryPath().waitForValue(binaryBName, 30000);
      await waitForNextDisasm(disasmResponses);
      await hub.annotationsList().waitForText('e2e_binary_b', 30000);
      assert.ok(
        !String(await hub.annotationsList().textContent() || '').includes('e2e_binary_a'),
        'the second binary must not display the first binary annotation',
      );
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-binary-isolation',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('navigates incoming and outgoing xrefs through the real UI', async () => {
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path && fs.existsSync(fixture.path), 'UI fixture binary must exist');
    const targetAddr = String(fixture.entry || '0x400078');
    const sourceAddr = '0x400080';
    let target = null;
    const xrefsModes = [];
    const originalExecFile = childProcess.execFile;
    try {
      await withChildProcessMocks({
        execFile: (file, args = [], options = {}, callback = undefined) => {
          if (!isXrefsScript(args)) {
            return originalExecFile.call(childProcess, file, args, options, callback);
          }
          const cb = typeof options === 'function' ? options : callback;
          const proc = new EventEmitter();
          const mode = String(args[args.indexOf('--mode') + 1] || 'to');
          xrefsModes.push(mode);
          const payload = mode === 'from'
            ? { refs: [], targets: [targetAddr] }
            : {
              refs: [{
                from_addr: sourceAddr,
                function_name: 'caller_e2e',
                function_addr: sourceAddr,
                type: 'call',
                text: `call ${targetAddr}`,
              }],
              targets: [],
            };
          process.nextTick(() => cb?.(null, JSON.stringify(payload), ''));
          return proc;
        },
      }, async () => {
        await vscode.commands.executeCommand('pileOuFace.goToAddress');
        target = await connectToHubWebview(process.env.POF_E2E_CDP_ENDPOINT);
        const hub = new HubPage(target);
        await vscode.commands.executeCommand('pileOuFace.e2eDispatchHubMessage', {
          type: 'hubUseBinaryPath',
          binaryPath: fixture.path,
        });
        await hub.binaryPath().waitForValue(path.basename(fixture.path), 30000);
        await hub.openPanel('static');
        await hub.openStaticTab('code', 'disasm');

        await hub.goToAddressInput().fill(targetAddr);
        await hub.xrefsMode().fill('to');
        await hub.xrefsButton().clickDom();
        await hub.xrefsResult().waitForText(`Références vers ${targetAddr}`, 30000);
        await hub.xrefsResult().waitForText('caller_e2e', 30000);
        await hub.xrefsResult().waitForText(`call ${targetAddr}`, 30000);

        await hub.firstXrefsJumpButton().clickDom();
        await hub.goToAddressInput().waitForValue(sourceAddr, 30000);
        await hub.annotationAddress().waitForAttribute('data-addr', sourceAddr, 30000);

        await hub.xrefsMode().fill('from');
        await hub.xrefsButton().clickDom();
        await hub.xrefsResult().waitForText(`Références depuis ${sourceAddr}`, 30000);
        await hub.xrefsResult().waitForText(targetAddr, 30000);
        assert.ok(xrefsModes.includes('to'), 'an incoming xrefs lookup must execute');
        assert.ok(xrefsModes.includes('from'), 'an outgoing xrefs lookup must execute');
      });
    } catch (error) {
      const artifacts = await captureUiFailure(
        target,
        process.env.POF_E2E_ARTIFACTS_DIR,
        'hub-xrefs-navigation',
      );
      error.message = `${error.message}${artifacts.length ? `\nUI artifacts: ${artifacts.join(', ')}` : ''}`;
      throw error;
    } finally {
      target?.close();
    }
  }));

  suite.addTest(new Mocha.Test('records static disassembly commands across fixture sizes', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    const fixtures = readFixtureSpecs();
    assert.ok(fixtures.length > 0, 'at least one fixture is required');

    for (const [index, fixture] of fixtures.entries()) {
      assert.ok(fs.existsSync(fixture.path), `fixture binary must exist: ${fixture.path}`);
      const scenario = `static-disasm:${fixture.name}`;
      const details = {
        fixture: fixture.name,
        sizeBytes: fixture.sizeBytes,
        kind: fixture.kind || '',
        compiler: fixture.compiler || '',
        opt: fixture.opt || '',
        arch: fixture.arch || '',
        stripped: fixture.stripped === true,
      };
      const stopPerf = startPerfSampler(scenario, details);
      try {
        await vscode.commands.executeCommand('pileOuFace.goToSymbolInDisasm', fixture.entry || '0x400078', fixture.path);

        const expectedCount = index + 1;
        const { events } = await waitForAuditEvents(userDataDir, (candidateEvents) => (
          countEvents(candidateEvents, (event) => event.kind === 'command' && event.name === 'pileOuFace.goToSymbolInDisasm') >= expectedCount
          && countEvents(candidateEvents, (event) => event.kind === 'process' && event.source === 'runCommand') >= expectedCount
        ));

        const baseName = path.basename(fixture.path, path.extname(fixture.path));
        const expectedSuffix = `${baseName}.disasm.asm`;
        const disasmDocument = vscode.workspace.textDocuments.find((document) => (
          document.uri.fsPath.endsWith(expectedSuffix)
        ));
        assert.ok(disasmDocument, `disassembly command should open ${expectedSuffix}`);
        assert.ok(hasEvent(events, 'command', 'pileOuFace.goToSymbolInDisasm'), 'disassembly command should be audited');
        stopPerf({ ok: true });
      } catch (error) {
        stopPerf({ ok: false, error: String(error && error.message ? error.message : error) });
        throw error;
      }
    }
  }));

  suite.addTest(new Mocha.Test('records simple shared commands', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');

    await vscode.workspace.getConfiguration('pileOuFace').update('perfDiagnostics', true, vscode.ConfigurationTarget.Global);
    const disasmEditor = findDisasmEditor();
    assert.ok(disasmEditor, 'a disassembly editor must be visible for simple command smoke coverage');
    await vscode.window.showTextDocument(disasmEditor.document, { preview: false });
    const commands = [
      'pileOuFace.goToAddress',
      'pileOuFace.showLogs',
      'pileOuFace.perfSnapshot',
      'pileOuFace.decompilerList',
      'pileOuFace.decompilerOpenConfig',
    ];

    const originalExecFile = childProcess.execFile;
    await withWindowMocks({
      activeTextEditor: disasmEditor,
      showErrorMessage: async (message) => {
        assert.fail(`unexpected VS Code error during simple command coverage: ${message}`);
      },
      showWarningMessage: async (message, ...items) => {
        assert.ok(
          !String(message || '').includes('Ouvrez un fichier de désassemblage'),
          `unexpected disassembly warning during simple command coverage: ${message}`
        );
        return items.find((item) => item === 'OK') || undefined;
      },
    }, async () => withChildProcessMocks({
      execFile: (file, args = [], options = {}, callback = undefined) => {
        const cb = typeof options === 'function' ? options : callback;
        if (!isDecompilerListScript(args)) {
          return originalExecFile.call(childProcess, file, args, options, callback);
        }
        const proc = new EventEmitter();
        process.nextTick(() => {
          cb?.(null, createMockDecompilerList(), '');
        });
        return proc;
      },
    }, async () => {
      for (const commandId of commands) {
        const stopPerf = startPerfSampler(`command:${commandId}`);
        const auditEventsBefore = readCurrentAuditEvents(userDataDir);
        try {
          await vscode.commands.executeCommand(commandId);
          await waitForCommandAudit(userDataDir, commandId);
          let stateValidated = false;
          if (commandId === 'pileOuFace.decompilerOpenConfig') {
            const configDocument = findDecompilerConfigDocument();
            assert.ok(configDocument, 'decompilerOpenConfig should open decompilers.json');
            assert.ok(fs.existsSync(configDocument.uri.fsPath), 'decompilerOpenConfig should create decompilers.json on disk');
            const config = readDecompilerConfigFromOpenDocument();
            assert.ok(config && typeof config.decompilers === 'object', 'decompilers.json should contain a decompilers object');
            stateValidated = true;
          }
          stopPerf({
            ok: true,
            stateValidated,
            auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
          });
        } catch (error) {
          stopPerf({
            ok: false,
            error: String(error && error.message ? error.message : error),
            auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
          });
          throw error;
        }
      }
    }));
  }));

  suite.addTest(new Mocha.Test('records section disassembly command against a fixture binary', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path, 'fixture path is required');
    assert.ok(fs.existsSync(fixture.path), `fixture binary must exist: ${fixture.path}`);

    const stopPerf = startPerfSampler('static-disasm-section', {
      fixture: fixture.name,
      sizeBytes: fixture.sizeBytes,
      section: '.text',
    });
    try {
      await vscode.commands.executeCommand('pileOuFace.disasmSection', '.text', fixture.path);
      const { events } = await waitForAuditEvents(userDataDir, (candidateEvents) => (
        hasEvent(candidateEvents, 'command', 'pileOuFace.disasmSection')
        && candidateEvents.some((event) => event.kind === 'process' && event.source === 'runCommand')
      ));
      assert.ok(hasEvent(events, 'command', 'pileOuFace.disasmSection'), 'section disassembly command should be audited');
      stopPerf({ ok: true });
    } catch (error) {
      stopPerf({ ok: false, error: String(error && error.message ? error.message : error) });
      throw error;
    }
  }));

  suite.addTest(new Mocha.Test('records editor-backed static commands on generated disassembly', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');

    const editor = findDisasmEditor();
    const selectedAddress = selectFirstAddressLine(editor);
    assert.ok(selectedAddress, 'an address should be selected in the disassembly editor');
    await vscode.window.showTextDocument(editor.document, { preview: false });

    const commands = [
      'pileOuFace.askAiAboutDisasm',
      'pileOuFace.xrefsFrom',
      'pileOuFace.xrefsTo',
    ];

    const errorMessages = [];
    await withWindowMocks({
      activeTextEditor: editor,
      showErrorMessage: async (message, ...items) => {
        errorMessages.push(String(message || ''));
        return items[0];
      },
      showWarningMessage: async (message, ...items) => {
        assert.ok(
          !String(message || '').includes('Ouvrez un fichier de désassemblage'),
          `unexpected disassembly warning during editor-backed command coverage: ${message}`
        );
        return items.find((item) => item === 'OK') || undefined;
      },
    }, async () => {
      for (const commandId of commands) {
        const stopPerf = startPerfSampler(`editor-command:${commandId}`, { selectedAddress });
        try {
          await vscode.commands.executeCommand(commandId);
          await waitForCommandAudit(userDataDir, commandId);
          assert.deepStrictEqual(errorMessages, [], `${commandId} should not show error notifications`);
          stopPerf({ ok: true });
        } catch (error) {
          stopPerf({ ok: false, error: String(error && error.message ? error.message : error) });
          throw error;
        }
      }
    });
  }));

  suite.addTest(new Mocha.Test('records dialog-backed commands with deterministic VS Code mocks', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path, 'fixture path is required');
    const editor = findDisasmEditor();
    assert.ok(editor, 'a disassembly editor must be visible');
    const disasmDocument = findDisasmDocument() || editor.document;
    const disasmEditor = await vscode.window.showTextDocument(disasmDocument, { preview: false });

    const exportPath = path.join(process.env.POF_E2E_WORKSPACE_DIR || path.dirname(fixture.path), 'e2e-exported.disasm.txt');
    const fakeDecompilerPath = path.join(process.env.POF_E2E_WORKSPACE_DIR || path.dirname(fixture.path), 'e2e-fake-decompiler.py');
    const fakeDecompilerPython = process.env.PYTHON || 'python3';
    fs.writeFileSync(fakeDecompilerPath, [
      'import argparse',
      'import json',
      'parser = argparse.ArgumentParser()',
      'parser.add_argument("--binary")',
      'parser.add_argument("--addr", default="0x0")',
      'args = parser.parse_args()',
      'print(json.dumps({"addr": args.addr, "code": "int e2e_fake(void) { return 0; }", "functions": []}))',
      '',
    ].join('\n'), 'utf8');
    const capturedWebviews = [];
    const errorMessages = [];
    await withWindowMocks({
      activeTextEditor: disasmEditor,
      createWebviewPanel: (viewType, title, showOptions, options) => {
        const panel = {
          viewType,
          title,
          showOptions,
          options,
          webview: { html: '' },
          dispose() {},
          onDidDispose() { return { dispose() {} }; },
        };
        capturedWebviews.push(panel);
        return panel;
      },
      showQuickPick: async (items, options = {}) => {
        const title = `${options.title || ''}`.toLowerCase();
        const entries = Array.isArray(items) ? items : [];
        if (title.includes('mode')) return entries.find((item) => item.value === 'local') || entries[0];
        if (title.includes('provider')) return entries.find((item) => item.value === 'local') || entries[0];
        if (title.includes('finaliser')) return entries.find((item) => item.value === 'save') || entries[0];
        return entries[0];
      },
      showInputBox: async (options = {}) => {
        const prompt = `${options.title || ''} ${options.prompt || ''}`.toLowerCase();
        if (prompt.includes('binaire')) return fixture.path;
        if (prompt.includes('identifiant')) return 'e2e-tool';
        if (prompt.includes('nom affich')) return 'E2E Tool';
        if (prompt.includes('commande locale')) return `"${fakeDecompilerPython}" "${fakeDecompilerPath}" --binary {binary} --addr {addr}`;
        if (prompt.includes('binaire complet')) return '';
        return '0x40';
      },
      showSaveDialog: async () => vscode.Uri.file(exportPath),
      showOpenDialog: async () => [vscode.Uri.file(fixture.path)],
      showInformationMessage: async () => 'OK',
      showErrorMessage: async (message, ...items) => {
        errorMessages.push(String(message || ''));
        return items[0];
      },
      showWarningMessage: async (message, ...items) => {
        if (String(message || '').includes('Supprimer')) return items.find((item) => item === 'Supprimer') || 'Supprimer';
        return items.find((item) => item === 'OK') || undefined;
      },
      withProgress: async (_options, task) => task(
        { report() {} },
        { onCancellationRequested: () => ({ dispose() {} }) }
      ),
    }, async () => {
      const commands = [
        { id: 'pileOuFace.calculator', args: [] },
        { id: 'pileOuFace.sidebarRefresh', args: [] },
        { id: 'pileOuFace.exportDisasm', args: [] },
        { id: 'pileOuFace.decompilerAdd', args: [] },
        { id: 'pileOuFace.decompilerEdit', args: ['e2e-tool'] },
        { id: 'pileOuFace.decompilerTest', args: ['e2e-tool'] },
        { id: 'pileOuFace.decompilerRemove', args: ['e2e-tool'] },
      ];
      for (const { id: commandId, args } of commands) {
        const stopPerf = startPerfSampler(`dialog-command:${commandId}`);
        const auditEventsBefore = readCurrentAuditEvents(userDataDir);
        try {
          if (commandId === 'pileOuFace.exportDisasm') {
            const exportDocument = findDisasmDocument();
            assert.ok(exportDocument, 'exportDisasm should have a disassembly document to export');
            await vscode.window.showTextDocument(exportDocument, { preview: false });
          }
          await vscode.commands.executeCommand(commandId, ...args);
          await waitForCommandAudit(userDataDir, commandId);
          let stateValidated = false;
          if (commandId === 'pileOuFace.calculator') {
            const calcPanel = capturedWebviews.find((panel) => panel.viewType === 'pileOuFaceCalc');
            assert.ok(calcPanel, 'calculator should create a result webview panel');
            assert.ok(String(calcPanel.webview.html || '').includes('0x40'), 'calculator result should include the input value');
            assert.ok(String(calcPanel.webview.html || '').includes('64'), 'calculator result should include the decimal value');
            stateValidated = true;
          } else if (commandId === 'pileOuFace.exportDisasm') {
            assert.ok(fs.existsSync(exportPath), `exportDisasm should write ${exportPath}`);
            const exported = fs.readFileSync(exportPath, 'utf8');
            assert.ok(exported.includes(':'), 'exported disassembly should contain address lines');
            stateValidated = true;
          } else if (commandId === 'pileOuFace.decompilerAdd') {
            const config = readDecompilerConfigFromOpenDocument();
            assert.ok(config?.decompilers?.['e2e-tool'], 'decompilerAdd should write e2e-tool to decompilers.json');
            assert.deepStrictEqual(config.decompilers['e2e-tool'].command, [fakeDecompilerPython, fakeDecompilerPath, '--binary', '{binary}', '--addr', '{addr}']);
            stateValidated = true;
          } else if (commandId === 'pileOuFace.decompilerEdit') {
            const config = readDecompilerConfigFromOpenDocument();
            assert.ok(config?.decompilers?.['e2e-tool'], 'decompilerEdit should keep e2e-tool in decompilers.json');
            assert.strictEqual(config.decompilers['e2e-tool'].label, 'E2E Tool');
            stateValidated = true;
          } else if (commandId === 'pileOuFace.decompilerRemove') {
            const config = readDecompilerConfigFromOpenDocument();
            assert.ok(config && !config.decompilers?.['e2e-tool'], 'decompilerRemove should remove e2e-tool from decompilers.json');
            stateValidated = true;
          }
          assert.deepStrictEqual(errorMessages, [], `${commandId} should not show error notifications`);
          stopPerf({
            ok: true,
            stateValidated,
            auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
          });
        } catch (error) {
          stopPerf({
            ok: false,
            error: String(error && error.message ? error.message : error),
            auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
          });
          throw error;
        }
      }
    });
  }));

  suite.addTest(new Mocha.Test('records backend hub handlers through the E2E dispatcher', async () => {
    const userDataDir = process.env.POF_E2E_USER_DATA_DIR;
    assert.ok(userDataDir, 'POF_E2E_USER_DATA_DIR is required');
    const [fixture] = readFixtureSpecs();
    assert.ok(fixture?.path, 'fixture path is required');
    assert.ok(fs.existsSync(fixture.path), `fixture binary must exist: ${fixture.path}`);

    const binaryPath = fixture.path;
    const addr = fixture.entry || '0x400078';
    const workspaceDir = process.env.POF_E2E_WORKSPACE_DIR || path.dirname(binaryPath);
    const scriptPath = path.join(workspaceDir, 'e2e-runtime-audit-script.py');
    const sourcePath = path.join(workspaceDir, 'e2e-runtime-audit-source.c');
    const rulePath = path.join(workspaceDir, 'e2e-runtime-audit-rule.yar');
    const pluginBundlePath = path.join(workspaceDir, 'e2e-runtime-audit-plugin.pofplug');
    const licensePath = path.join(workspaceDir, 'e2e-runtime-audit-plugin.license');
    const patchBinaryPath = path.join(workspaceDir, 'e2e-runtime-audit-patch-copy.bin');
    fs.writeFileSync(scriptPath, 'print({"ok": True})\n', 'utf8');
    fs.writeFileSync(sourcePath, 'int main(void) { return 0; }\n', 'utf8');
    fs.writeFileSync(rulePath, 'rule E2ERuntimeAuditRule { condition: true }\n', 'utf8');
    fs.writeFileSync(pluginBundlePath, 'not a real plugin bundle\n', 'utf8');
    fs.writeFileSync(licensePath, 'not a real plugin license\n', 'utf8');
    fs.copyFileSync(binaryPath, patchBinaryPath);

    await vscode.commands.executeCommand('pileOuFace.goToAddress');
    await waitForAuditEvents(userDataDir, (candidateEvents) => (
      hasEvent(candidateEvents, 'command', 'pileOuFace.goToAddress')
      && hasEvent(candidateEvents, 'webview_message', 'hubReady')
    ));

    const messages = [
      { type: 'hubReady' },
      { type: 'hubGetSettings' },
      { type: 'hubModeChange', mode: 'static' },
      { type: 'hubDebugLog', scope: 'e2e.runtime-audit', event: 'named-span', details: { ok: true } },
      { type: 'hubError', message: 'E2E runtime audit expected error notification' },
      { type: 'hubLoadPluginState' },
      { type: 'hubOllamaListModels', baseUrl: 'http://127.0.0.1:1' },
      { type: 'hubListDecompilers', provider: 'auto' },
      { type: 'pof.auth.getState' },
      { type: 'hubOpenDisasm', binaryPath, useCache: false, openInEditor: false },
      { type: 'getPlatform' },
      { type: 'compilerListRequest' },
      { type: 'listGeneratedFiles' },
      { type: 'hubRequestRecentBinaries' },
      { type: 'hubLoadAnnotations', binaryPath },
      { type: 'hubSaveAnnotation', binaryPath, addr, comment: 'E2E runtime audit annotation', name: 'e2e_entry' },
      { type: 'hubSaveBookmark', binaryPath, addr, label: 'E2E entry', color: '#4ec9b0' },
      { type: 'hubSaveFunctionReview', binaryPath, addr, reviewStatus: 'reviewed', reviewNotes: 'E2E review' },
      { type: 'hubDeleteBookmark', binaryPath, addr },
      { type: 'hubClearBookmarks', binaryPath },
      { type: 'hubDeleteAnnotation', binaryPath, addr },
      { type: 'hubClearRecentBinaries' },
      { type: 'hubUseBinaryPath', binaryPath },
      { type: 'hubLoadInfo', binaryPath, useCache: false },
      { type: 'hubLoadSections', binaryPath, useCache: false },
      { type: 'hubLoadSymbols', binaryPath, useCache: false },
      { type: 'hubLoadStrings', binaryPath, minLen: 4, encoding: 'utf-8', useCache: false },
      { type: 'hubLoadXrefs', binaryPath, addr, mode: 'from', requestKey: 'e2e-xrefs-from' },
      { type: 'hubGoToEntryPoint', binaryPath, symbol: '__entry__' },
      { type: 'hubGoToAddress', binaryPath, addr, spanLength: 1 },
      { type: 'hubGoToFileOffset', binaryPath, fileOffset: '0x0', spanLength: 1 },
      { type: 'hubLoadCfg', binaryPath, useCache: false },
      { type: 'hubLoadCfgForAddr', binaryPath, addr, useCache: false },
      { type: 'hubLoadCallGraph', binaryPath, useCache: false },
      { type: 'hubLoadDiscoveredFunctions', binaryPath, useCache: false },
      { type: 'hubLoadImports', binaryPath },
      { type: 'hubLoadExports', binaryPath },
      { type: 'hubLoadImportXrefs', binaryPath, fnName: 'puts' },
      { type: 'hubLoadHexView', binaryPath, offset: 0, length: 128 },
      { type: 'hubSearchBinary', binaryPath, pattern: 'ELF', mode: 'text', caseSensitive: false },
      { type: 'hubLoadPatches', binaryPath },
      { type: 'hubLoadStackFrame', binaryPath, addr },
      { type: 'hubLoadFunctions', binaryPath },
      { type: 'hubLoadDecompile', binaryPath, addr, decompiler: 'e2e-missing-decompiler', useCache: false },
      { type: 'hubLoadPeResources', binaryPath },
      { type: 'hubLoadExceptionHandlers', binaryPath },
      { type: 'hubLoadTypedData', binaryPath, valueType: 'u8', page: 0 },
      { type: 'hubPreviewTypedStruct', binaryPath, structName: 'E2E_Missing', structAddr: addr },
      { type: 'hubLoadStructs', binaryPath },
      { type: 'hubSaveStructs', binaryPath, sourceText: 'struct E2EPoint { int x; int y; };' },
      { type: 'hubSaveTypedStructRef', binaryPath, appliedStruct: { name: 'E2EPoint', addr, fields: [] } },
      { type: 'hubPayloadToHex', payload: 'A*4' },
      { type: 'hubAutoFromCmp', binaryPath, cmpAddr: addr },
      { type: 'hubRunScript', binaryPath, code: 'print({"ok": True})' },
      { type: 'hubSaveScript', name: 'e2e-runtime-audit.py', content: 'print({"ok": True})\n' },
      { type: 'hubLoadScript' },
      { type: 'hubLoadPwntoolsScript' },
      { type: 'hubAnalyzePwntoolsScript', scriptContent: '', sourceFileName: 'empty-payload.py', binaryPath },
      { type: 'hubAiCancel', requestId: 'e2e-missing-ai-request' },
      { type: 'hubAiProvidersGet' },
      { type: 'hubAiProviderSet', provider: 'openai', model: 'e2e-model', api_key: 'e2e-key' },
      { type: 'hubAiProviderTest', provider: 'openai' },
      { type: 'hubAiProviderDefaultSet', provider: 'openai' },
      { type: 'hubAiProviderPrompt', requestId: 'e2e-provider-prompt', provider: 'openai', model: 'e2e-model', prompt: 'hello' },
      {
        type: 'hubCompileStaticBinary',
        sourcePath: path.join(workspaceDir, 'missing-e2e-source.c'),
        binaryPath: path.join(workspaceDir, 'missing-e2e-output'),
      },
      {
        type: 'runTrace',
        payload: {
          sourcePath,
          useExistingBinary: false,
          traceMode: 'static',
        },
      },
      { type: 'hubPickFile', fileType: 'binary', target: 'binaryPath' },
      { type: 'hubPickFile', fileType: 'sourceC', target: 'dynamicSourcePath' },
      { type: 'hubExportCfgSvg', svg: '<svg xmlns="http://www.w3.org/2000/svg"><text>E2E</text></svg>' },
      { type: 'hubExportConversation', markdown: '# E2E conversation\n', json: { messages: [] }, suggestedName: 'e2e-conversation' },
      { type: 'hubExportData', dataType: 'symbols', format: 'json', data: [{ name: 'e2e_symbol', addr }], suggestedName: 'e2e-symbols.json' },
      { type: 'hubExportDisasm', binaryPath },
      { type: 'hubExecuteCommand', requestId: 'e2e-show-logs', command: 'pileOuFace.showLogs' },
      { type: 'hubListRules' },
      { type: 'hubAddUserRule', name: 'e2e-empty-rule', ruleType: 'yara', content: 'rule E2EEmpty { condition: true }', scope: 'global' },
      { type: 'hubBrowseImportRule', ruleType: 'yara', scope: 'global' },
      { type: 'hubGetRuleContent', ruleId: 'missing-e2e-rule-id' },
      { type: 'hubToggleRule', ruleId: 'missing-e2e-rule-id', enabled: false },
      { type: 'hubUpdateUserRule', ruleId: 'missing-e2e-rule-id', name: 'missing', content: 'rule Missing { condition: false }' },
      { type: 'hubDeleteUserRule', ruleId: 'missing-e2e-rule-id' },
      { type: 'hubPatchBytes', binaryPath: patchBinaryPath, offset: 0, bytesHex: '7f' },
      { type: 'hubRedoPatch', binaryPath: patchBinaryPath },
      { type: 'hubRevertPatch', binaryPath: patchBinaryPath, patchId: 'missing-e2e-patch-id' },
      { type: 'hubRevertAllPatches', binaryPath: patchBinaryPath },
      { type: 'hubForgetRecentBinary', binaryPath },
      { type: 'hubGrantPluginConsent', pluginId: 'e2e.runtime-audit' },
      { type: 'hubPluginInvoke', requestId: 'e2e-plugin-missing-feature' },
      { type: 'hubInstallPlugin', scope: 'workspace' },
      { type: 'hubInstallDecompiler', tool: 'e2e-custom' },
      { type: 'hubPullDecompilerImage', decompiler: '', image: '' },
      { type: 'hubOllamaModelSelected', model: 'e2e-runtime-audit-model' },
      { type: 'hubOllamaPrompt', requestId: 'e2e-ollama-prompt', model: 'e2e-ollama-model', prompt: 'hello' },
      { type: 'hubOpenPluginDirectory', scope: 'workspace' },
      { type: 'hubResetSettings' },
      { type: 'hubSaveSettings', settings: { interfaceMode: 'advanced', lang: 'fr' } },
      { type: 'pof.auth.login', email: 'e2e@example.invalid', password: 'e2e-password' },
      { type: 'pof.auth.logout' },
      { type: 'requestDynamicTraceHistory' },
      { type: 'clearDynamicTraceHistory' },
      { type: 'openDynamicTraceHistory', tracePath: '/missing/e2e-trace.json' },
      { type: 'deleteDynamicTraceHistory', tracePath: '/missing/e2e-trace.json' },
    ];
    let exportCounter = 0;
    const infoMessages = [];
    const warningMessages = [];
    const errorMessages = [];
    await withWindowMocks({
      showOpenDialog: async (options = {}) => {
        const title = `${options.title || ''}`.toLowerCase();
        if (title.includes('plugin compil')) return [vscode.Uri.file(pluginBundlePath)];
        if (title.includes('licence plugin')) return [vscode.Uri.file(licensePath)];
        if (title.includes('importer des règles')) return [vscode.Uri.file(rulePath)];
        if (title.includes('pwntools') || title.includes('script python')) return [vscode.Uri.file(scriptPath)];
        if (title.includes('source c')) return [vscode.Uri.file(sourcePath)];
        return [vscode.Uri.file(binaryPath)];
      },
      showQuickPick: async (items) => (Array.isArray(items) ? items[0] : undefined),
      showSaveDialog: async (options = {}) => {
        const defaultPath = options.defaultUri?.fsPath || path.join(workspaceDir, `e2e-export-${exportCounter}`);
        exportCounter += 1;
        return vscode.Uri.file(path.join(workspaceDir, `${exportCounter}-${path.basename(defaultPath)}`));
      },
      showInformationMessage: async (message, _options, ...items) => {
        infoMessages.push(String(message || ''));
        return items.find((item) => item === 'Annuler') || 'OK';
      },
      showWarningMessage: async (message, ...items) => {
        warningMessages.push(String(message || ''));
        return items.find((item) => item === 'OK') || undefined;
      },
      showErrorMessage: async (message) => {
        errorMessages.push(String(message || ''));
        return 'OK';
      },
    }, async () => {
      const originalExecuteCommand = vscode.commands.executeCommand;
      const originalExecFile = childProcess.execFile;
      const originalSpawn = childProcess.spawn;
      const originalFetch = globalThis.fetch;
      await withCommandMocks({
        executeCommand: async (command, ...args) => {
          if (command === 'revealFileInOS') return undefined;
          return originalExecuteCommand.call(vscode.commands, command, ...args);
        },
      }, async () => {
        await withGlobalMocks({
          fetch: async (url, options = {}) => {
            const value = String(url || '');
            if (value.includes('/auth/login')) {
              return jsonResponse({
                access_token: 'e2e-access-token',
                refresh_token: 'e2e-refresh-token',
                content_keys: {},
              });
            }
            if (value.includes('/auth/me')) {
              return jsonResponse({ email: 'e2e@example.invalid', active_plugin_ids: [] });
            }
            if (value.includes('/auth/logout')) {
              return jsonResponse({ ok: true });
            }
            return originalFetch(url, options);
          },
        }, async () => withChildProcessMocks({
          execFile: (file, args = [], options = {}, callback = undefined) => {
            const cb = typeof options === 'function' ? options : callback;
            if (!isAiProviderScript(args)) {
              return originalExecFile.call(childProcess, file, args, options, callback);
            }
            const proc = new EventEmitter();
            proc.stdin = new Writable({ write(_chunk, _encoding, done) { done(); } });
            process.nextTick(() => {
              const command = args.find((arg) => ['list', 'set', 'set-default'].includes(String(arg)));
              const stdout = command === 'set' || command === 'set-default'
                ? JSON.stringify({ ok: true })
                : createMockProviderList();
              cb?.(null, stdout, '');
            });
            return proc;
          },
          spawn: (file, args = [], options = {}) => {
            if (!isAiProviderScript(args) && !isOllamaBridgeScript(args)) {
              return originalSpawn.call(childProcess, file, args, options);
            }
            const proc = new EventEmitter();
            proc.stdin = new Writable({ write(_chunk, _encoding, done) { done(); } });
            proc.stdout = new PassThrough();
            proc.stderr = new PassThrough();
            proc.kill = () => {};
            process.nextTick(() => {
              proc.stdout.write(`${JSON.stringify({ type: 'token', content: 'ok' })}\n`);
              proc.stdout.write(`${JSON.stringify({ type: 'done', ok: true, text: 'ok', usage: { total_tokens: 1 } })}\n`);
              proc.stdout.end();
              proc.emit('close', 0);
            });
            return proc;
          },
        }, async () => {
          for (const message of messages) {
            const responseTypes = responseTypesForMessage(message.type);
            const requireUiConsumed = requiresUiConsumed(message.type);
            const payloadAssertions = payloadAssertionsForMessage(message.type);
            const infoCountBefore = infoMessages.length;
            const errorCountBefore = errorMessages.length;
            const quietBefore = await waitForAuditQuiet(userDataDir);
            const stopPerf = startPerfSampler(`hub-handler:${message.type}`, {
              binaryPath: message.binaryPath ? path.basename(message.binaryPath) : '',
              responseTypes,
              requireUiConsumed,
              payloadAssertions: payloadAssertions.map((assertion) => assertion.responseType),
              quietBeforeTimedOut: quietBefore.timedOut === true,
            });
            const auditEventsBefore = readCurrentAuditEvents(userDataDir);
            try {
              if (responseTypes.length) {
                await dispatchHubMessageAndWaitForResponses(userDataDir, message, responseTypes, {
                  requireUiConsumed,
                  payloadAssertions,
                });
              } else {
                await dispatchHubMessageAndWait(userDataDir, message);
              }
              let stateValidated = false;
              if (message.type === 'hubError') {
                const newErrors = errorMessages.slice(errorCountBefore);
                assert.ok(newErrors.some((entry) => entry.includes(message.message)), 'hubError should surface the expected VS Code error message');
                stateValidated = true;
              } else if (message.type === 'hubInstallDecompiler') {
                const newInfos = infoMessages.slice(infoCountBefore);
                assert.ok(newInfos.some((entry) => entry.includes(String(message.tool))), 'hubInstallDecompiler should show install guidance for the requested tool');
                stateValidated = true;
              } else if (message.type === 'hubClearRecentBinaries') {
                await dispatchHubMessageAndWaitForResponses(
                  userDataDir,
                  { type: 'hubRequestRecentBinaries' },
                  responseTypesForMessage('hubRequestRecentBinaries'),
                  {
                    payloadAssertions: payloadAssertionsForMessage('hubRequestRecentBinaries'),
                  }
                );
                stateValidated = true;
              } else if (message.type === 'hubOllamaModelSelected') {
                await dispatchHubMessageAndWaitForResponses(
                  userDataDir,
                  { type: 'hubOllamaListModels', baseUrl: 'http://127.0.0.1:1' },
                  responseTypesForMessage('hubOllamaListModels'),
                  {
                    payloadAssertions: payloadAssertionsForMessage('hubOllamaListModels'),
                  }
                );
                stateValidated = true;
              }
              const quietAfter = await waitForAuditQuiet(userDataDir, AUTOLOAD_FANOUT_MESSAGES.has(message.type)
                ? { quietMs: 500, timeoutMs: 5000 }
                : {});
              stopPerf({
                ok: true,
                responseTypes,
                uiConsumed: requireUiConsumed,
                payloadValidated: payloadAssertions.length > 0,
                stateValidated,
                quietBefore,
                quietAfter,
                auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
              });
            } catch (error) {
              stopPerf({
                ok: false,
                error: String(error && error.message ? error.message : error),
                auditDelta: summarizeAuditDelta(auditEventsBefore, readCurrentAuditEvents(userDataDir)),
              });
              throw error;
            }
          }
        }));
      });
    });
  }));

  if (['1', 'true', 'yes'].includes(String(process.env.POF_E2E_UI_ONLY || '').toLowerCase())) {
    mocha.grep(/real webview controls|real confirmation UI|restores it from cache through the real UI|restores the selected binary and visible analysis|incoming and outgoing xrefs through the real UI/);
  }

  return new Promise((resolve, reject) => {
    mocha.run((failures) => {
      if (failures > 0) {
        reject(new Error(`${failures} E2E test(s) failed`));
      } else {
        resolve();
      }
    });
  });
}

module.exports = { run };
