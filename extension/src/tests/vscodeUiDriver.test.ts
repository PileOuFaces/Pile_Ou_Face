// SPDX-License-Identifier: AGPL-3.0-only
import { strict as assert } from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';

const {
  CdpLocator,
  CdpTarget,
  HubPage,
  captureUiFailure,
  connectToHubWebview,
} = require('../../scripts/e2e/vscode-ui-driver');

class FakeSocket {
  listeners = new Map<string, Function[]>();
  sent: string[] = [];
  closed = false;

  addEventListener(name: string, callback: Function) {
    this.listeners.set(name, [...(this.listeners.get(name) || []), callback]);
    if (name === 'open') queueMicrotask(() => callback({}));
  }

  emit(name: string, event: any) {
    for (const listener of this.listeners.get(name) || []) listener(event);
  }

  send(payload: string) {
    this.sent.push(payload);
    const request = JSON.parse(payload);
    queueMicrotask(() => this.emit('message', {
      data: JSON.stringify({
        id: request.id,
        result: request.method === 'Runtime.evaluate'
          ? { result: { value: true } }
          : { ok: true },
      }),
    }));
  }

  close() {
    this.closed = true;
    this.emit('close', {});
  }
}

describe('VS Code UI E2E driver', () => {
  it('builds escaped DOM expressions for selectors', () => {
    const locator = new CdpLocator({}, 'button[data-label="quoted"]');
    const expression = locator.expression('return Boolean(el);');
    assert.match(expression, /document\.querySelector\("button\[data-label=\\"quoted\\"\]"\)/);
  });

  it('drives panels and static tabs through locator clicks', async () => {
    const calls: string[] = [];
    const locators = new Map<string, any>();
    const target = {
      locator(selector: string) {
        if (!locators.has(selector)) {
          locators.set(selector, {
            async click() { calls.push(`click:${selector}`); },
            async waitFor() { calls.push(`wait:${selector}`); },
            async waitForAttribute() { calls.push(`wait-attribute:${selector}`); },
            async getAttribute() { return 'panel active'; },
          });
        }
        return locators.get(selector);
      },
    };
    const hub = new HubPage(target);

    await hub.openPanel('static');
    await hub.openStaticTab('data', 'typed_data');

    assert.ok(calls.includes('click:.icon-nav-item[data-panel="static"]'));
    assert.ok(calls.includes('click:.group-tab[data-group="data"]'));
    assert.ok(calls.includes('click:.sub-tab[data-sub-tab="typed_data"]'));
  });

  it('exposes the decompile augmentation journey through stable selectors', () => {
    const selectors: string[] = [];
    const target = {
      locator(selector: string) {
        selectors.push(selector);
        return { selector };
      },
    };
    const hub = new HubPage(target);

    hub.decompileFunctionSelect();
    hub.decompileOutput();
    hub.decompileAugmentButton();
    hub.decompileAugmentStatus();
    hub.decompileAugmentReview();
    hub.decompileAugmentSuggestions();
    hub.decompileAugmentAcceptButton();

    assert.deepEqual(selectors, [
      '#decompileAddrSelect',
      '#decompileContent .decompile-output',
      '#btnAugmentDecompile',
      '#decompileAugmentStatus',
      '#decompileAugmentReview',
      '#decompileAugmentSuggestions',
      '#btnAcceptDecompileAugment',
    ]);
  });

  it('exposes address navigation and xrefs through stable selectors', () => {
    const selectors: string[] = [];
    const target = {
      locator(selector: string) {
        selectors.push(selector);
        return { selector };
      },
    };
    const hub = new HubPage(target);

    hub.goToAddressInput();
    hub.xrefsMode();
    hub.xrefsButton();
    hub.xrefsResult();
    hub.firstXrefsJumpButton();

    assert.deepEqual(selectors, [
      '#goToAddrInput',
      '#xrefsMode',
      '#btnXrefs',
      '#xrefsResultContent',
      '#xrefsResultContent .xrefs-jump-btn',
    ]);
  });

  it('exposes binary analysis through a stable selector', () => {
    const selectors: string[] = [];
    const target = {
      locator(selector: string) {
        selectors.push(selector);
        return { selector };
      },
    };

    const hub = new HubPage(target);
    hub.binaryInfo();
    hub.binarySections();
    hub.binaryFunctions();
    hub.binaryFunctionsCount();

    assert.deepEqual(selectors, [
      '#infoContent',
      '#sectionsContent',
      '#functionsContent',
      '#functionsCount',
    ]);
  });

  it('falls back to a DOM click when Electron ignores panel navigation coordinates', async () => {
    const calls: string[] = [];
    const target = {
      locator(selector: string) {
        return {
          async click() { calls.push(`physical:${selector}`); },
          async clickDom() { calls.push(`dom:${selector}`); },
          async waitFor() {},
          async waitForAttribute() { throw new Error('physical click ignored'); },
          async getAttribute() { return 'panel active'; },
        };
      },
    };

    await new HubPage(target).openPanel('options');

    assert.deepEqual(calls, [
      'physical:.icon-nav-item[data-panel="options"]',
      'dom:.icon-nav-item[data-panel="options"]',
    ]);
  });

  it('uses CDP to inspect, fill and physically click a DOM control', async () => {
    const sent: string[] = [];
    const evaluations: string[] = [];
    const target = {
      async evaluate(expression: string) {
        evaluations.push(expression);
        if (expression.includes('aria-disabled')) return true;
        if (expression.includes('getAttribute')) return 'btn active';
        if (expression.includes('textContent')) return 'Résultat prêt';
        if (expression.includes("String(el.value)")) return 'true';
        if (expression.includes('rect.left')) return { x: 12, y: 18 };
        return true;
      },
      async send(method: string) { sent.push(method); },
    };
    const locator = new CdpLocator(target, '#action');

    await locator.waitFor({ state: 'visible', timeout: 50 });
    assert.equal(await locator.getAttribute('class'), 'btn active');
    assert.equal(await locator.isEnabled(), true);
    assert.equal(await locator.waitForText('prêt', 50), 'Résultat prêt');
    assert.equal(await locator.inputValue(), 'true');
    assert.equal(await locator.waitForValue('true', 50), 'true');
    assert.equal(await locator.waitForAttribute('class', 'active', 50), 'btn active');
    await locator.waitForEnabled(50);
    await locator.fill('nouvelle valeur');
    await locator.click();
    await locator.clickDom();

    assert.deepEqual(sent, ['Input.dispatchMouseEvent', 'Input.dispatchMouseEvent']);
    const scrollIndex = evaluations.findIndex((expression) => expression.includes("scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' })"));
    const coordinatesIndex = evaluations.findIndex((expression) => expression.includes('rect.left'));
    assert.ok(scrollIndex >= 0, 'the target is scrolled into view');
    assert.ok(coordinatesIndex > scrollIndex, 'click coordinates use the updated layout');
    assert.ok(evaluations.some((expression) => expression.includes('el.click()')));
  });

  it('reports disabled controls and inactive UI states', async () => {
    const disabledTarget = {
      async evaluate(expression: string) {
        if (expression.includes('rect.left')) return null;
        if (expression.includes('el.click()')) return false;
        if (expression.includes("'value' in el")) return false;
        return true;
      },
      async send() {},
      locator() {
        return {
          async waitFor() {},
          async getAttribute() { return 'panel'; },
        };
      },
    };
    const locator = new CdpLocator(disabledTarget, '#disabled');
    await assert.rejects(locator.click(), /disabled or missing/);
    await assert.rejects(locator.clickDom(), /disabled or missing/);
    await assert.rejects(locator.fill('x'), /cannot be filled/);
    const hub = new HubPage(disabledTarget);
    await assert.rejects(hub.expectActive(disabledTarget.locator(), 'inactive panel'), /not active/);
  });

  it('correlates CDP requests and exposes locators', async () => {
    const socket = new FakeSocket();
    const target = new CdpTarget(socket);

    assert.equal(await target.evaluate('true'), true);
    assert.ok(target.locator('#hub') instanceof CdpLocator);
    assert.equal((await target.send('Page.enable')).ok, true);
    target.close();
    assert.equal(socket.closed, true);
  });

  it('routes attached target commands through their CDP session', async () => {
    const socket = new FakeSocket();
    const target = new CdpTarget(socket, 'iframe-session');
    socket.emit('message', {
      data: JSON.stringify({
        method: 'Runtime.executionContextCreated',
        sessionId: 'iframe-session',
        params: { context: { id: 42 } },
      }),
    });
    target.contextId = target.executionContextIds[0];

    assert.equal(await target.evaluate('true'), true);
    assert.equal(JSON.parse(socket.sent[0]).sessionId, 'iframe-session');
    assert.equal(JSON.parse(socket.sent[0]).params.contextId, 42);
  });

  it('surfaces CDP protocol errors, evaluation exceptions and closed requests', async () => {
    const protocolSocket = new FakeSocket();
    protocolSocket.send = function send(payload: string) {
      const request = JSON.parse(payload);
      queueMicrotask(() => this.emit('message', {
        data: JSON.stringify({ id: request.id, error: { message: 'protocol failed' } }),
      }));
    };
    await assert.rejects(new CdpTarget(protocolSocket).send('Broken.method'), /protocol failed/);

    const evaluationSocket = new FakeSocket();
    evaluationSocket.send = function send(payload: string) {
      const request = JSON.parse(payload);
      queueMicrotask(() => this.emit('message', {
        data: JSON.stringify({
          id: request.id,
          result: { exceptionDetails: { text: 'evaluation failed' } },
        }),
      }));
    };
    await assert.rejects(new CdpTarget(evaluationSocket).evaluate('throw 1'), /evaluation failed/);

    const closingSocket = new FakeSocket();
    closingSocket.send = function send() {};
    const closingTarget = new CdpTarget(closingSocket);
    const pending = closingTarget.send('Still.pending', {}, 100);
    closingSocket.close();
    await assert.rejects(pending, /target closed/);

    const silentSocket = new FakeSocket();
    silentSocket.send = function send() {};
    const shortTimeoutTarget = new CdpTarget(silentSocket, null, 1);
    await assert.rejects(shortTimeoutTarget.send('Never.responds'), /CDP Never\.responds timed out/);
  });

  it('times out when a DOM state never becomes observable', async () => {
    const target = { async evaluate() { return false; } };
    const locator = new CdpLocator(target, '#missing');
    await assert.rejects(locator.waitFor({ timeout: 1 }), /Timed out waiting/);
    await assert.rejects(locator.waitForText('never', 1), /Timed out waiting/);
    await assert.rejects(locator.waitForValue('never', 1), /Timed out waiting/);
    await assert.rejects(locator.waitForAttribute('class', 'never', 1), /Timed out waiting/);
  });

  it('models the type manager journey with stable selectors', async () => {
    const calls: string[] = [];
    const target = {
      locator(selector: string) {
        return {
          selector,
          async click() { calls.push(`click:${selector}`); },
          async waitFor() { calls.push(`wait:${selector}`); },
        };
      },
    };
    const hub = new HubPage(target);

    await hub.openTypeManager();
    assert.equal(hub.binaryPath().selector, '#staticBinaryPath');
    assert.equal(hub.typeEditorSource().selector, '#pof-typed-struct-popup textarea');
    assert.equal(hub.typeEditorCatalog().selector, '#pof-typed-struct-popup .typed-data-type-catalog');
    assert.equal(hub.typeEditorStatus().selector, '#pof-typed-struct-popup .typed-data-struct-editor-status');
    assert.equal(hub.typeEditorSaveButton().selector, '#pof-typed-struct-popup [data-action="save-types"]');
    assert.equal(hub.typeEditorCloseButton().selector, '#pof-typed-struct-popup .typed-data-struct-editor-actions .btn:first-child');
    assert.equal(hub.topBarBinaryName().selector, '#topBarBinaryName');
    assert.equal(hub.topBarBinaryMenu().selector, '#topBarBinaryMenu');
    assert.equal(hub.currentBinaryName().selector, '#topBarCurrentBinaryName');
    assert.equal(hub.dashboardStaticAction().selector, '.action-card[data-action="static-open"]');
    assert.equal(hub.autoTriageBinary().selector, '[data-auto-triage-binary]');
    assert.equal(hub.autoTriageButton().selector, '[data-action="auto-triage"]');
    assert.equal(hub.autoTriageModal().selector, '[data-auto-triage-modal]');
    assert.equal(hub.autoTriageConfirmButton().selector, '[data-action="auto-triage-confirm"]');
    assert.equal(hub.autoTriageState().selector, '[data-auto-triage-state]');
    assert.equal(hub.autoTriageHelp().selector, '[data-auto-triage-help]');
    assert.equal(hub.autoTriageResult().selector, '[data-auto-triage-result]');
    assert.equal(hub.autoTriageResultTitle().selector, '[data-auto-triage-result-title]');
    assert.equal(hub.disassemblyBinarySummary().selector, '#disasmSummaryBinary');
    assert.equal(hub.topBarBinaryButton().selector, '#topBarBinaryButton');
    assert.equal(
      hub.recentBinaryButton('fixture.elf').selector,
      '#topBarRecentList > .top-bar-menu-item[title="fixture.elf"]',
    );
    assert.equal(hub.firstFunctionDisasmButton().selector, '#functionsContent .functions-row-action[data-view="disasm"]');
    assert.equal(hub.functionDossierButton().selector, '#functionsDetails .functions-export-action');
    assert.equal(hub.offsetHexInput().selector, '#offsetHex');
    assert.equal(hub.offsetDecimalInput().selector, '#offsetDec');
    assert.equal(hub.offsetBaseInput().selector, '#offsetBase');
    assert.equal(hub.offsetDeltaInput().selector, '#offsetDelta');
    assert.equal(hub.offsetResultInput().selector, '#offsetResult');
    assert.equal(hub.decompileAugmentButton().selector, '#btnAugmentDecompile');
    assert.equal(hub.interfaceModeButton('simple').selector, '[data-interface-mode="simple"]');
    assert.equal(hub.interfaceModeInput().selector, '#settingInterfaceMode');
    assert.equal(hub.staticFeaturePicker().selector, '#staticFeatureSettings');
    assert.equal(hub.staticFeaturesAllButton().selector, '#btnStaticFeaturesAll');
    assert.equal(hub.entryPointButton().selector, '#btnGoToEntry');
    assert.equal(hub.annotationAddress().selector, '#annotationAddrBadge');
    assert.equal(hub.annotationName().selector, '#annotationName');
    assert.equal(hub.annotationComment().selector, '#annotationComment');
    assert.equal(hub.annotationSubmitButton().selector, '#btnAddAnnotation');
    assert.equal(hub.annotationsList().selector, '#annotationsList');
    assert.equal(hub.firstAnnotationEditButton().selector, '#annotationsList .annotation-item .ann-edit');
    assert.equal(hub.firstAnnotationDeleteButton().selector, '#annotationsList .annotation-item .ann-delete');
    assert.deepEqual(calls, [
      'click:#btnTypedEditStructs',
      'wait:#pof-typed-struct-popup',
    ]);
  });

  it('discovers the hub webview target through the local CDP endpoint', async () => {
    const originalFetch = globalThis.fetch;
    const originalWebSocket = globalThis.WebSocket;
    const sockets: FakeSocket[] = [];
    const socketUrls: string[] = [];
    globalThis.fetch = (async (url: string) => ({
      json: async () => url.endsWith('/json/version')
        ? { webSocketDebuggerUrl: 'ws://local/browser' }
        : [
          {
            type: 'page',
            url: 'vscode-file://vscode-app/workbench.html',
            webSocketDebuggerUrl: 'ws://local/page',
          },
          {
            id: 'hub-frame',
            type: 'iframe',
            url: 'vscode-webview://pile-ou-face/index.html',
          },
        ],
    })) as any;
    globalThis.WebSocket = class {
      socket: FakeSocket;
      constructor(url: string) {
        socketUrls.push(url);
        this.socket = new FakeSocket();
        this.socket.send = function send(payload: string) {
          this.sent.push(payload);
          const request = JSON.parse(payload);
          queueMicrotask(() => this.emit('message', {
            data: JSON.stringify({
              id: request.id,
              result: request.method === 'Target.attachToTarget'
                ? { sessionId: 'hub-session' }
                : { result: { value: true } },
            }),
          }));
        };
        sockets.push(this.socket);
        return this.socket as any;
      }
    } as any;
    try {
      const target = await connectToHubWebview('http://127.0.0.1:9222', 100);
      assert.ok(target instanceof CdpTarget);
      assert.equal(target.sessionId, 'hub-session');
      assert.deepEqual(socketUrls, ['ws://local/browser']);
      target.close();
      assert.equal(sockets[0].closed, true);
    } finally {
      globalThis.fetch = originalFetch;
      globalThis.WebSocket = originalWebSocket;
    }
  });

  it('writes screenshot and DOM artifacts for a failed UI path', async () => {
    const artifactsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-ui-driver-test-'));
    const target = {
      async send() { return { data: Buffer.from('png').toString('base64') }; },
      async evaluate() { return '<html><body>failure</body></html>'; },
    };
    try {
      const artifacts = await captureUiFailure(target, artifactsDir, 'UI failure');
      assert.equal(artifacts.length, 2);
      assert.equal(fs.readFileSync(path.join(artifactsDir, 'ui-failure.png'), 'utf8'), 'png');
      assert.match(fs.readFileSync(path.join(artifactsDir, 'ui-failure.html'), 'utf8'), /failure/);
    } finally {
      fs.rmSync(artifactsDir, { recursive: true, force: true });
    }
  });

  it('keeps the original failure when UI artifacts cannot be captured', async () => {
    const artifactsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-ui-driver-errors-'));
    const target = {
      async send() { throw new Error('gone'); },
      async evaluate() { throw new Error('gone'); },
    };
    try {
      assert.deepEqual(await captureUiFailure(target, artifactsDir, 'gone'), []);
      assert.deepEqual(await captureUiFailure(null, artifactsDir, 'gone'), []);
    } finally {
      fs.rmSync(artifactsDir, { recursive: true, force: true });
    }
  });

  it('rejects discovery when the CDP endpoint is missing', async () => {
    await assert.rejects(connectToHubWebview('', 1), /CDP_ENDPOINT/);
  });

  it('preserves the last CDP discovery error for CI diagnostics', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => { throw new Error('CDP offline'); }) as any;
    try {
      await assert.rejects(connectToHubWebview('http://127.0.0.1:9222', 1), /Last error: CDP offline/);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
