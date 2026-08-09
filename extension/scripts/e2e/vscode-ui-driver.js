// SPDX-License-Identifier: AGPL-3.0-only
const fs = require('fs');
const path = require('path');

const DEFAULT_TIMEOUT_MS = 15000;
const configuredCdpCommandTimeoutMs = Number.parseInt(process.env.POF_E2E_CDP_COMMAND_TIMEOUT_MS || '', 10);
const DEFAULT_CDP_COMMAND_TIMEOUT_MS = Number.isFinite(configuredCdpCommandTimeoutMs)
  ? Math.max(1000, configuredCdpCommandTimeoutMs)
  : 10000;

class CdpTarget {
  constructor(socket, sessionId = null, commandTimeoutMs = DEFAULT_CDP_COMMAND_TIMEOUT_MS) {
    this.socket = socket;
    this.sessionId = sessionId;
    this.commandTimeoutMs = commandTimeoutMs;
    this.contextId = null;
    this.executionContextIds = [];
    this.nextId = 1;
    this.pending = new Map();
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(String(event.data));
      if (
        message.method === 'Runtime.executionContextCreated'
        && (!this.sessionId || message.sessionId === this.sessionId)
        && message.params?.context?.id
      ) {
        this.executionContextIds.push(message.params.context.id);
      }
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

  send(method, params = {}, timeoutMs = this.commandTimeoutMs) {
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

  async evaluate(expression, contextId = this.contextId) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      returnByValue: true,
      awaitPromise: true,
      ...(contextId ? { contextId } : {}),
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

  async inputValue() {
    return this.target.evaluate(this.expression("return el && 'value' in el ? String(el.value) : null;"));
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

  async waitForValue(expected, timeout = DEFAULT_TIMEOUT_MS) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const value = String(await this.inputValue() || '');
      if (value.includes(expected)) return value;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for ${this.selector} value to contain ${JSON.stringify(expected)}`);
  }

  async waitForAttribute(name, expected, timeout = DEFAULT_TIMEOUT_MS) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const value = String(await this.getAttribute(name) || '');
      if (value.includes(expected)) return value;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for ${this.selector} attribute ${JSON.stringify(name)} to contain ${JSON.stringify(expected)}`);
  }

  async waitForEnabled(timeout = DEFAULT_TIMEOUT_MS) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      if (await this.isEnabled()) return;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error(`Timed out waiting for ${this.selector} to become enabled`);
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
    const scrolled = await this.target.evaluate(this.expression(`
      if (!el || el.disabled) return false;
      el.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' });
      return true;
    `));
    if (!scrolled) throw new Error(`Element is disabled or missing: ${this.selector}`);
    const point = await this.target.evaluate(this.expression(`
      if (!el || el.disabled) return null;
      const rect = el.getBoundingClientRect();
      return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
    `));
    if (!point) throw new Error(`Element is disabled or missing: ${this.selector}`);
    await this.target.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: point.x, y: point.y, button: 'left', clickCount: 1 });
    await this.target.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: point.x, y: point.y, button: 'left', clickCount: 1 });
  }

  async clickDom() {
    await this.waitFor({ state: 'visible' });
    const clicked = await this.target.evaluate(this.expression(`
      if (!el || el.disabled) return false;
      el.click();
      return true;
    `));
    if (!clicked) throw new Error(`Element is disabled or missing: ${this.selector}`);
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
          await target.send('Runtime.enable');
          const contexts = target.executionContextIds.length ? target.executionContextIds : [null];
          for (const contextId of contexts) {
            try {
              if (await target.evaluate('Boolean(globalThis.document?.querySelector("#panel-dashboard"))', contextId)) {
                target.contextId = contextId;
                return target;
              }
            } catch (error) {
              lastError = error instanceof Error ? error.message : String(error);
            }
          }
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

  binaryPath() {
    return this.target.locator('#staticBinaryPath');
  }

  useCacheToggle() {
    return this.target.locator('#useCache');
  }

  topBarBinaryName() {
    return this.target.locator('#topBarBinaryName');
  }

  topBarBinaryButton() {
    return this.target.locator('#topBarBinaryButton');
  }

  topBarBinaryMenu() {
    return this.target.locator('#topBarBinaryMenu');
  }

  recentBinaryButton(binaryPath) {
    const requestedPath = String(binaryPath);
    const candidates = [...new Set([requestedPath, path.basename(requestedPath)])];
    const selector = candidates
      .map((candidate) => `#topBarRecentList > .top-bar-menu-item[title=${JSON.stringify(candidate)}]`)
      .join(', ');
    return this.target.locator(selector);
  }

  currentBinaryName() {
    return this.target.locator('#topBarCurrentBinaryName');
  }

  binaryInfo() {
    return this.target.locator('#infoContent');
  }

  binaryInfoRetryButton() {
    return this.target.locator('#btnRetryBinaryInfo');
  }

  binarySections() {
    return this.target.locator('#sectionsContent');
  }

  binaryFunctions() {
    return this.target.locator('#functionsContent');
  }

  binaryFunctionsCount() {
    return this.target.locator('#functionsCount');
  }

  firstFunctionDisasmButton() {
    return this.target.locator('#functionsContent .functions-row-action[data-view="disasm"]');
  }

  functionDossierButton() {
    return this.target.locator('#functionsDetails .functions-export-action');
  }

  offsetHexInput() {
    return this.target.locator('#offsetHex');
  }

  offsetDecimalInput() {
    return this.target.locator('#offsetDec');
  }

  offsetBaseInput() {
    return this.target.locator('#offsetBase');
  }

  offsetDeltaInput() {
    return this.target.locator('#offsetDelta');
  }

  offsetResultInput() {
    return this.target.locator('#offsetResult');
  }

  dashboardStaticAction() {
    return this.target.locator('.action-card[data-action="static-open"]');
  }

  autoTriageBinary() {
    return this.target.locator('[data-auto-triage-binary]');
  }

  autoTriageButton() {
    return this.target.locator('[data-action="auto-triage"]');
  }

  autoTriageModal() {
    return this.target.locator('[data-auto-triage-modal]');
  }

  autoTriageConfirmButton() {
    return this.target.locator('[data-action="auto-triage-confirm"]');
  }

  autoTriageCancelButton() {
    return this.target.locator('[data-action="auto-triage-cancel"]');
  }

  autoTriageState() {
    return this.target.locator('[data-auto-triage-state]');
  }

  autoTriageHelp() {
    return this.target.locator('[data-auto-triage-help]');
  }

  autoTriageResult() {
    return this.target.locator('[data-auto-triage-result]');
  }

  autoTriageResultTitle() {
    return this.target.locator('[data-auto-triage-result-title]');
  }

  aiProviderCard(provider) {
    return this.target.locator(`#aiProvidersState [data-provider="${provider}"]`);
  }

  aiProviderKey(provider) {
    return this.target.locator(`#aiProvidersState [data-provider="${provider}"] [data-role="key"]`);
  }

  aiProviderModel(provider) {
    return this.target.locator(`#aiProvidersState [data-provider="${provider}"] [data-role="model"]`);
  }

  aiProviderSaveButton(provider) {
    return this.target.locator(`#aiProvidersState [data-provider="${provider}"] .ai-provider-actions button`);
  }

  aiProviderStatus(provider) {
    return this.target.locator(`#aiProvidersState [data-provider="${provider}"] .ai-provider-card-status`);
  }

  aiDefaultProvider() {
    return this.target.locator('#aiDefaultProvider');
  }

  async setAiDefaultProvider(provider) {
    const select = this.aiDefaultProvider();
    const savedTitle = `Provider automatique enregistré : ${provider}`;
    const deadline = Date.now() + DEFAULT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      try {
        await this.openPanel('options');
        await select.fill(provider);
        await select.waitForAttribute('title', savedTitle, 750);
        return;
      } catch {
        // Hub initialization can rerender settings after the first interaction.
      }
    }
    await select.waitForAttribute('title', savedTitle, 1);
  }

  disassemblyBinarySummary() {
    return this.target.locator('#disasmSummaryBinary');
  }

  decompileAugmentButton() {
    return this.target.locator('#btnAugmentDecompile');
  }

  decompileFunctionSelect() {
    return this.target.locator('#decompileAddrSelect');
  }

  decompileContent() {
    return this.target.locator('#decompileContent');
  }

  decompileOutput() {
    return this.target.locator('#decompileContent .decompile-output');
  }

  decompileRebuildButton() {
    return this.target.locator('#btnRebuildDecompile');
  }

  decompileAugmentStatus() {
    return this.target.locator('#decompileAugmentStatus');
  }

  decompileAugmentReview() {
    return this.target.locator('#decompileAugmentReview');
  }

  decompileAugmentSuggestions() {
    return this.target.locator('#decompileAugmentSuggestions');
  }

  decompileAugmentAcceptButton() {
    return this.target.locator('#btnAcceptDecompileAugment');
  }

  pluginInstallButton() {
    return this.target.locator('#btnPluginAdd');
  }

  pluginStateList() {
    return this.target.locator('#pluginStateList');
  }

  pluginConsentButton() {
    return this.target.locator('#pluginStateList .plugin-consent-grant');
  }

  pluginConsentRefuseButton() {
    return this.target.locator('#pluginStateList .plugin-consent-refuse');
  }

  toastContainer() {
    return this.target.locator('#pof-toast-container');
  }

  scriptEditor() {
    return this.target.locator('#scriptEditor');
  }

  scriptRunButton() {
    return this.target.locator('#btnRunScript');
  }

  scriptStatus() {
    return this.target.locator('#scriptStatus');
  }

  scriptOutput() {
    return this.target.locator('#scriptOutput');
  }

  interfaceModeButton(mode) {
    return this.target.locator(`[data-interface-mode="${mode}"]`);
  }

  async selectInterfaceMode(mode) {
    const button = this.interfaceModeButton(mode);
    const input = this.interfaceModeInput();
    const deadline = Date.now() + DEFAULT_TIMEOUT_MS;
    while (Date.now() < deadline) {
      try {
        await this.openPanel('options');
        await button.click();
        await Promise.all([
          input.waitForValue(mode, 750),
          button.waitForAttribute('aria-pressed', 'true', 750),
        ]);
        return;
      } catch {
        // Retry if late hub initialization restored the previous panel/settings.
      }
    }
    await input.waitForValue(mode, 1);
  }

  interfaceModeInput() {
    return this.target.locator('#settingInterfaceMode');
  }

  staticFeaturePicker() {
    return this.target.locator('#staticFeatureSettings');
  }

  staticFeaturesAllButton() {
    return this.target.locator('#btnStaticFeaturesAll');
  }

  typeManagerButton() {
    return this.target.locator('#btnTypedEditStructs');
  }

  typeEditor() {
    return this.target.locator('#pof-typed-struct-popup');
  }

  typeEditorSource() {
    return this.target.locator('#pof-typed-struct-popup textarea');
  }

  typeEditorCatalog() {
    return this.target.locator('#pof-typed-struct-popup .typed-data-type-catalog');
  }

  typeEditorStatus() {
    return this.target.locator('#pof-typed-struct-popup .typed-data-struct-editor-status');
  }

  typeEditorSaveButton() {
    return this.target.locator('#pof-typed-struct-popup [data-action="save-types"]');
  }

  typeEditorCloseButton() {
    return this.target.locator('#pof-typed-struct-popup .typed-data-struct-editor-actions .btn:first-child');
  }

  typedDataSection() {
    return this.target.locator('#typedDataSection');
  }

  typedDataStructSelect() {
    return this.target.locator('#typedDataStructSelect');
  }

  typedDataStructOffset() {
    return this.target.locator('#typedDataStructOffset');
  }

  typedDataApplyStructButton() {
    return this.target.locator('#btnTypedApplyStruct');
  }

  typedDataStructStatus() {
    return this.target.locator('#typedDataStructStatus');
  }

  typedDataContent() {
    return this.target.locator('#typedDataContent');
  }

  entryPointButton() {
    return this.target.locator('#btnGoToEntry');
  }

  goToAddressInput() {
    return this.target.locator('#goToAddrInput');
  }

  xrefsMode() {
    return this.target.locator('#xrefsMode');
  }

  xrefsButton() {
    return this.target.locator('#btnXrefs');
  }

  xrefsResult() {
    return this.target.locator('#xrefsResultContent');
  }

  firstXrefsJumpButton() {
    return this.target.locator('#xrefsResultContent .xrefs-jump-btn');
  }

  annotationAddress() {
    return this.target.locator('#annotationAddrBadge');
  }

  annotationName() {
    return this.target.locator('#annotationName');
  }

  annotationComment() {
    return this.target.locator('#annotationComment');
  }

  annotationSubmitButton() {
    return this.target.locator('#btnAddAnnotation');
  }

  annotationsList() {
    return this.target.locator('#annotationsList');
  }

  firstAnnotationEditButton() {
    return this.target.locator('#annotationsList .annotation-item .ann-edit');
  }

  firstAnnotationDeleteButton() {
    return this.target.locator('#annotationsList .annotation-item .ann-delete');
  }

  async expectActive(locator, description, timeout = DEFAULT_TIMEOUT_MS) {
    await locator.waitFor({ state: 'attached' });
    try {
      await locator.waitForAttribute('class', 'active', timeout);
    } catch {
      throw new Error(`${description} is not active`);
    }
  }

  async openPanel(panelId) {
    const navigation = this.panelNav(panelId);
    const panel = this.panel(panelId);
    const deadline = Date.now() + DEFAULT_TIMEOUT_MS;
    await navigation.click();
    while (Date.now() < deadline) {
      try {
        await Promise.all([
          navigation.waitForAttribute('class', 'active', 500),
          panel.waitForAttribute('class', 'active', 500),
        ]);
        return;
      } catch {
        // The DOM can be visible before the webview listeners finish mounting.
        // Retry the real navigation control until both observable states agree.
      }
      await navigation.clickDom();
    }
    await this.expectActive(panel, `panel ${panelId}`, 1);
  }

  async openStaticTab(groupId, tabId) {
    await this.group(groupId).click();
    await this.expectActive(this.group(groupId), `group ${groupId}`);
    const subTab = this.subTab(tabId);
    await subTab.click();
    try {
      await subTab.waitForAttribute('class', 'active', 500);
    } catch {
      await subTab.clickDom();
    }
    await this.expectActive(subTab, `sub-tab ${tabId}`);
  }

  async openTypeManager() {
    await this.typeManagerButton().click();
    await this.typeEditor().waitFor({ state: 'visible' });
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
