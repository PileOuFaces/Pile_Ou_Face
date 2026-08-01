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

  it('uses CDP to inspect, fill and physically click a DOM control', async () => {
    const sent: string[] = [];
    const target = {
      async evaluate(expression: string) {
        if (expression.includes('aria-disabled')) return true;
        if (expression.includes('getAttribute')) return 'btn active';
        if (expression.includes('textContent')) return 'Résultat prêt';
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
    await locator.fill('nouvelle valeur');
    await locator.click();

    assert.deepEqual(sent, ['Input.dispatchMouseEvent', 'Input.dispatchMouseEvent']);
  });

  it('reports disabled controls and inactive UI states', async () => {
    const disabledTarget = {
      async evaluate(expression: string) {
        if (expression.includes('rect.left')) return null;
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
  });

  it('times out when a DOM state never becomes observable', async () => {
    const target = { async evaluate() { return false; } };
    const locator = new CdpLocator(target, '#missing');
    await assert.rejects(locator.waitFor({ timeout: 1 }), /Timed out waiting/);
    await assert.rejects(locator.waitForText('never', 1), /Timed out waiting/);
  });

  it('discovers the hub webview target through the local CDP endpoint', async () => {
    const originalFetch = globalThis.fetch;
    const originalWebSocket = globalThis.WebSocket;
    const sockets: FakeSocket[] = [];
    globalThis.fetch = (async () => ({
      json: async () => [{
        type: 'iframe',
        url: 'https://file+.vscode-resource.vscode-cdn.net/index.html',
        webSocketDebuggerUrl: 'ws://local/webview',
      }],
    })) as any;
    globalThis.WebSocket = class {
      socket: FakeSocket;
      constructor() {
        this.socket = new FakeSocket();
        sockets.push(this.socket);
        return this.socket as any;
      }
    } as any;
    try {
      const target = await connectToHubWebview('http://127.0.0.1:9222', 100);
      assert.ok(target instanceof CdpTarget);
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
});
