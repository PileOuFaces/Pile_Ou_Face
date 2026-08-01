// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');

const DEFAULT_TIMEOUT_MS = 15000;

class CdpTarget {
  constructor(socket, sessionId = null) {
    this.socket = socket;
    this.sessionId = sessionId;
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (!message.id || !this.pending.has(message.id)) return;
      const { resolve, reject } = this.pending.get(message.id);
      this.pending.delete(message.id);
      if (message.error) reject(new Error(message.error.message || JSON.stringify(message.error)));
      else resolve(message.result || {});
    });
    socket.addEventListener('close', () => {
      for (const { reject } of this.pending.values()) reject(new Error('CDP target closed'));
      this.pending.clear();
    });
  }

  send(method, params = {}, timeoutMs = 3000) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`CDP ${method} timed out`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
      this.socket.send(JSON.stringify({
        id,
        method,
        params,
        ...(this.sessionId ? { sessionId: this.sessionId } : {}),
      }));
    });
  }

  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true,
    });
    if (result.exceptionDetails) {
      throw new Error(result.exceptionDetails.exception?.description || result.exceptionDetails.text || 'DOM evaluation failed');
    }
    return result.result?.value;
  }

  locator(selector) {
    return new CdpLocator(this, selector);
  }

  close() {
    this.socket.close();
  }
}

class CdpLocator {
  constructor(target, selector) {
    this.target = target;
    this.selector = selector;
  }

  expression(body) {
    return `(() => { const el = document.querySelector(${JSON.stringify(this.selector)}); ${body} })()`;
  }

  async waitFor({ state = 'visible', timeout = DEFAULT_TIMEOUT_MS } = {}) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const matched = await this.target.evaluate(this.expression(`
        if (!el) return false;
        if (${JSON.stringify(state)} === 'attached') return true;
        const style = getComputedStyle(el);
        const rect = el.getBoundingClientRect();
        return style.visibility !== 'hidden' && style.display !== 'none' && rect.width > 0 && rect.height > 0;
      `));
      if (matched) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for ${state} element ${this.selector}`);
  }

  async getAttribute(name) {
    return this.target.evaluate(this.expression(`return el ? el.getAttribute(${JSON.stringify(name)}) : null;`));
  }

  async isEnabled() {
    return this.target.evaluate(this.expression('return Boolean(el && !el.disabled && el.getAttribute("aria-disabled") !== "true");'));
  }

  async textContent() {
    return this.target.evaluate(this.expression('return el ? el.textContent : null;'));
  }

  async waitForText(expected, timeout = DEFAULT_TIMEOUT_MS) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const content = String(await this.textContent() || '');
      if (content.includes(expected)) return content;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for ${this.selector} to contain ${JSON.stringify(expected)}`);
  }

  async fill(value) {
    await this.waitFor({ state: 'visible' });
    const filled = await this.target.evaluate(this.expression(`
      if (!el || !('value' in el)) return false;
      el.focus();
      el.value = ${JSON.stringify(value)};
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    `));
    if (!filled) throw new Error(`Element cannot be filled: ${this.selector}`);
  }

  async click() {
    await this.waitFor({ state: 'visible' });
    const point = await this.target.evaluate(this.expression(`
      if (!el || el.disabled) return null;
      const rect = el.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    `));
    if (!point) throw new Error(`Element is disabled or missing: ${this.selector}`);
    await this.target.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: point.x, y: point.y, button: 'left', clickCount: 1 });
    await this.target.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: point.x, y: point.y, button: 'left', clickCount: 1 });
  }
}

async function openSocket(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = new globalThis.WebSocket(url);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error(`Timed out opening CDP target ${url}`));
    }, timeoutMs);
    socket.addEventListener('open', () => {
      clearTimeout(timer);
      resolve(socket);
    }, { once: true });
    socket.addEventListener('error', () => {
      clearTimeout(timer);
      reject(new Error(`Unable to open CDP target ${url}`));
    }, { once: true });
  });
}

async function connectToHubWebview(endpoint, timeoutMs = DEFAULT_TIMEOUT_MS) {
  if (!endpoint) throw new Error('POF_E2E_CDP_ENDPOINT is required for UI E2E');
  const deadline = Date.now() + timeoutMs;
  let targetSummary = '';
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const response = await globalThis.fetch(`${endpoint}/json/list`);
      const targets = await response.json();
      const versionResponse = await globalThis.fetch(`${endpoint}/json/version`);
      const browser = await versionResponse.json();
      targetSummary = targets.map((target) => `${target.type}:${target.url || target.title || ''}`).join(', ');
      const webviewTargets = targets.filter((candidate) => (
        candidate.type === 'webview'
        || candidate.type === 'iframe'
        || String(candidate.url || '').startsWith('vscode-webview://')
      ));
      for (const candidate of webviewTargets) {
        const socketUrl = candidate.webSocketDebuggerUrl || browser.webSocketDebuggerUrl;
        if (!socketUrl) continue;
        const socket = await openSocket(socketUrl, Math.min(2000, timeoutMs));
        const connection = new CdpTarget(socket);
        let target = connection;
        try {
          if (!candidate.webSocketDebuggerUrl) {
            if (!candidate.id) throw new Error('CDP iframe target has no id');
            const attached = await connection.send('Target.attachToTarget', {
              targetId: candidate.id,
              flatten: true,
            });
            if (!attached.sessionId) throw new Error('CDP iframe attachment returned no session');
            target = new CdpTarget(socket, attached.sessionId);
          }
          if (await target.evaluate('Boolean(document.querySelector("#panel-dashboard"))')) return target;
        } catch (error) {
          lastError = error instanceof Error ? error.message : String(error);
        }
        connection.close();
      }
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Pile ou Face hub webview was not found through CDP. Targets: ${targetSummary || '<none>'}. Last error: ${lastError || '<none>'}`);
}

class HubPage {
  constructor(target) {
    this.target = target;
  }

  panelNav(panelId) {
    return this.target.locator(`.icon-nav-item[data-panel="${panelId}"]`);
  }

  panel(panelId) {
    return this.target.locator(`#panel-${panelId}`);
  }

  group(groupId) {
    return this.target.locator(`.group-tab[data-group="${groupId}"]`);
  }

  subTab(tabId) {
    return this.target.locator(`.sub-tab[data-sub-tab="${tabId}"]`);
  }

  async expectActive(locator, description) {
    await locator.waitFor({ state: 'visible' });
    const classes = String(await locator.getAttribute('class') || '').split(/\s+/);
    if (!classes.includes('active')) throw new Error(`${description} is visible but not active`);
  }

  async openPanel(panelId) {
    await this.panelNav(panelId).click();
    await this.expectActive(this.panel(panelId), `panel ${panelId}`);
    await this.expectActive(this.panelNav(panelId), `navigation ${panelId}`);
  }

  async openStaticTab(groupId, tabId) {
    await this.group(groupId).click();
    await this.expectActive(this.group(groupId), `group ${groupId}`);
    await this.subTab(tabId).click();
    await this.expectActive(this.subTab(tabId), `sub-tab ${tabId}`);
  }
}

async function captureUiFailure(target, artifactsDir, testName) {
  if (!target || !artifactsDir) return [];
  fs.mkdirSync(artifactsDir, { recursive: true });
  const safeName = String(testName || 'ui-failure').replace(/[^a-z0-9_-]+/gi, '-').toLowerCase();
  const screenshotPath = path.join(artifactsDir, `${safeName}.png`);
  const htmlPath = path.join(artifactsDir, `${safeName}.html`);
  const written = [];
  try {
    const screenshot = await target.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
    fs.writeFileSync(screenshotPath, Buffer.from(screenshot.data, 'base64'));
    written.push(screenshotPath);
  } catch {
    // The HTML dump below can still diagnose failures when screenshots are unavailable.
  }
  try {
    fs.writeFileSync(htmlPath, await target.evaluate('document.documentElement.outerHTML'), 'utf8');
    written.push(htmlPath);
  } catch {
    // Keep the original test failure when the webview disappeared before capture.
  }
  return written;
}

module.exports = {
  CdpLocator,
  CdpTarget,
  HubPage,
  captureUiFailure,
  connectToHubWebview,
};
