// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function loadBinarySourceControllerSandbox() {
  const elements = new Map();
  const listeners = [];
  const document = {
    createElement(tag) {
      return {
        tagName: String(tag).toUpperCase(),
        children: [],
        classList: { add() {}, remove() {}, toggle() {}, contains() { return false; } },
        style: {},
        setAttribute() {},
        addEventListener() {},
        append(...children) { this.children.push(...children); },
        appendChild(child) { this.children.push(child); return child; },
        replaceChildren(...children) { this.children = children; },
      };
    },
    addEventListener(type, listener) {
      listeners.push({ type, listener });
    },
    getElementById(id) {
      if (!elements.has(id)) {
        elements.set(id, {
          id,
          value: "",
          hidden: true,
          readOnly: false,
          title: "",
          placeholder: "",
          textContent: "",
          children: [],
          style: {},
          classList: { add() {}, remove() {}, toggle() {}, contains() { return id === "panel-static"; } },
          addEventListener() {},
          setAttribute() {},
          append(...children) { this.children.push(...children); },
          appendChild(child) { this.children.push(child); return child; },
          replaceChildren(...children) { this.children = children; },
          contains() { return false; },
        });
      }
      return elements.get(id);
    },
  };
  const sandbox = {
    window: null,
    document,
    POFHub: {},
    Date,
    JSON,
  };
  sandbox.window = sandbox;
  const filename = path.resolve(__dirname, "../shared/binarySourceController.js");
  vm.runInNewContext(fs.readFileSync(filename, "utf8"), sandbox, { filename });
  return { sandbox, elements, listeners };
}

function input(value = "") {
  return { value };
}

function formWithUseExistingBinary(checked = true) {
  return {
    querySelector(selector) {
      return selector === '[name="useExistingBinary"]' ? { checked } : null;
    },
  };
}

describe("disasm autoload loop guard (skipAutoLoad threaded through nav chain)", () => {
  const binarySourceControllerSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/binarySourceController.js"),
    "utf8",
  );
  const navSource = () => fs.readFileSync(
    path.resolve(__dirname, "../shared/nav.js"),
    "utf8",
  );

  it("passes skipAutoLoad from hubSetBinaryPath through to applyStaticBinarySelectionUi", () => {
    const source = binarySourceControllerSource();
    const handlerStart = source.indexOf("msg.type === 'hubSetBinaryPath'");
    expect(handlerStart, "hubSetBinaryPath handler not found").to.be.greaterThan(-1);
    const handlerEnd = source.indexOf("msg.type === 'hubForgetRecentBinary'", handlerStart);
    const handler = source.slice(handlerStart, handlerEnd);

    // hubSetBinaryPath is posted with skipAutoLoad:true right before hubDisasmReady
    // fires (see finalizeDisasmOpen). If the UI-refresh path triggered by this
    // message doesn't propagate that flag all the way down to _autoLoadTab, the
    // refresh re-triggers disassembly before the cache populated by
    // hubDisasmReady's handler has a chance to short-circuit it, causing an
    // infinite disasm loop.
    expect(handler).to.include("applyStaticBinarySelectionUi(bp, nextMeta, skipAutoLoad)");
  });

  it("drops stale automatic hubSetBinaryPath responses before mutating the selected binary", () => {
    const source = binarySourceControllerSource();
    const handlerStart = source.indexOf("msg.type === 'hubSetBinaryPath'");
    expect(handlerStart, "hubSetBinaryPath handler not found").to.be.greaterThan(-1);
    const handlerEnd = source.indexOf("msg.type === 'hubForgetRecentBinary'", handlerStart);
    const handler = source.slice(handlerStart, handlerEnd);

    const staleGuardIndex = handler.indexOf("normalizeBinaryPathForCompare(prevBp) !== normalizeBinaryPathForCompare(bp)");
    const applyIndex = handler.indexOf("applyStaticBinarySelectionUi(bp, nextMeta, skipAutoLoad)");
    expect(staleGuardIndex, "stale hubSetBinaryPath guard missing").to.be.greaterThan(-1);
    expect(applyIndex, "selection mutation missing").to.be.greaterThan(-1);
    expect(staleGuardIndex).to.be.lessThan(applyIndex);

    const staleGuardBlock = handler.slice(staleGuardIndex, applyIndex);
    expect(staleGuardBlock).to.include("event: 'ignored-stale-response'");
    expect(staleGuardBlock).to.include("return true;");
  });

  it("keeps the active binary unchanged when a stale auto hubSetBinaryPath arrives", () => {
    const { sandbox } = loadBinarySourceControllerSandbox();
    const messages = [];
    const calls = [];
    const broadcasts = [];
    const staticBinaryInput = input("/tmp/current.bin");
    const binaryPathInput = input("/tmp/current.bin");

    sandbox.window.PluginIframeRouter = {
      broadcast: (message) => broadcasts.push(message),
    };

    const controller = sandbox.POFHubBinarySourceController.initBinarySourceController({
      postMessage: (message) => messages.push(message),
      staticBinaryInput,
      binaryPathInput,
      form: formWithUseExistingBinary(true),
      _loadStorage: () => ({ staticBinaryPath: "/tmp/current.bin", binaryMeta: null, group: "code", tab: "disasm" }),
      _saveStorage: (payload) => calls.push(["save", payload]),
      _basenameFromPath: (value) => String(value).split("/").pop(),
      resetStaticBinaryDerivedState: () => calls.push(["reset"]),
      showGroup: (...args) => calls.push(["showGroup", ...args]),
      getActiveStaticTab: () => "disasm",
      requestSymbols: () => calls.push(["requestSymbols"]),
      requestRunTraceInit: (...args) => calls.push(["requestRunTraceInit", ...args]),
      setDynamicTraceStatus: (status) => calls.push(["setDynamicTraceStatus", status]),
      _autoLoadTab: (tab) => calls.push(["autoLoad", tab]),
    });

    const handled = controller.handleBinarySourceMessage({
      type: "hubSetBinaryPath",
      binaryPath: "/tmp/old.bin",
      skipAutoLoad: true,
    });

    expect(handled).to.equal(true);
    expect(staticBinaryInput.value).to.equal("/tmp/current.bin");
    expect(binaryPathInput.value).to.equal("/tmp/current.bin");
    expect(calls).to.deep.equal([]);
    expect(broadcasts).to.deep.equal([]);
    expect(messages).to.deep.equal([{
      type: "hubDebugLog",
      scope: "static-binary",
      event: "ignored-stale-response",
      details: {
        currentBinaryPath: "/tmp/current.bin",
        responseBinaryPath: "/tmp/old.bin",
        messageType: "hubSetBinaryPath",
      },
    }]);
  });

  it("still applies a matching auto hubSetBinaryPath without re-triggering autoload", () => {
    const { sandbox } = loadBinarySourceControllerSandbox();
    const messages = [];
    const calls = [];
    const broadcasts = [];
    const staticBinaryInput = input("/tmp/current.bin");
    const binaryPathInput = input("/tmp/current.bin");

    sandbox.window.PluginIframeRouter = {
      broadcast: (message) => broadcasts.push(message),
    };

    const controller = sandbox.POFHubBinarySourceController.initBinarySourceController({
      postMessage: (message) => messages.push(message),
      staticBinaryInput,
      binaryPathInput,
      form: formWithUseExistingBinary(true),
      _loadStorage: () => ({ staticBinaryPath: "/tmp/current.bin", binaryMeta: null, group: "code", tab: "disasm" }),
      _saveStorage: (payload) => calls.push(["save", payload]),
      _basenameFromPath: (value) => String(value).split("/").pop(),
      resetStaticBinaryDerivedState: () => calls.push(["reset"]),
      showGroup: (...args) => calls.push(["showGroup", ...args]),
      getActiveStaticTab: () => "disasm",
      requestSymbols: () => calls.push(["requestSymbols"]),
      requestRunTraceInit: (...args) => calls.push(["requestRunTraceInit", ...args]),
      setDynamicTraceStatus: (status) => calls.push(["setDynamicTraceStatus", status]),
      updateArgvPayloadHint: () => calls.push(["updateArgvPayloadHint"]),
      _autoLoadTab: (tab) => calls.push(["autoLoad", tab]),
    });

    const handled = controller.handleBinarySourceMessage({
      type: "hubSetBinaryPath",
      binaryPath: "/tmp/current.bin",
      skipAutoLoad: true,
    });

    expect(handled).to.equal(true);
    expect(staticBinaryInput.value).to.equal("/tmp/current.bin");
    expect(binaryPathInput.value).to.equal("/tmp/current.bin");
    expect(calls.map((call) => call[0])).to.include.members([
      "save",
      "showGroup",
      "requestSymbols",
      "requestRunTraceInit",
      "setDynamicTraceStatus",
      "updateArgvPayloadHint",
    ]);
    expect(calls.map((call) => call[0])).to.not.include("reset");
    expect(calls.map((call) => call[0])).to.not.include("autoLoad");
    expect(calls.find((call) => call[0] === "showGroup")).to.deep.equal(["showGroup", "code", "disasm", true]);
    expect(broadcasts).to.deep.equal([{ type: "__binaryPath", binaryPath: "/tmp/current.bin" }]);
    expect(messages.some((message) => message.event === "ignored-stale-response")).to.equal(false);
  });

  it("showGroup forwards skipAutoLoad to showSubTab", () => {
    const source = navSource();
    const fnStart = source.indexOf("function showGroup(");
    expect(fnStart, "showGroup not found").to.be.greaterThan(-1);
    const fnEnd = source.indexOf("function _refreshArchSupportBadges", fnStart);
    const fn = source.slice(fnStart, fnEnd);

    expect(fn).to.include("skipAutoLoad");

    const callIndex = fn.indexOf("showSubTab(groupId, targetTab, skipAutoLoad)");
    expect(callIndex, "showGroup must forward skipAutoLoad to showSubTab").to.be.greaterThan(-1);
  });

  it("showSubTab only calls _autoLoadTab when skipAutoLoad is not set", () => {
    const source = navSource();
    const fnStart = source.indexOf("function showSubTab(");
    expect(fnStart, "showSubTab not found").to.be.greaterThan(-1);
    const nextFnStart = source.indexOf("\nfunction ", fnStart + 1);
    const fnEnd = nextFnStart > -1 ? nextFnStart : source.indexOf("document.querySelectorAll('.group-tab')", fnStart);
    const fn = source.slice(fnStart, fnEnd);

    // Assert the guard and the call form a single compound statement, not just
    // that the guard text appears somewhere before the call — otherwise a
    // refactor could split them apart (e.g. an unrelated `if (!skipAutoLoad)`
    // followed later by an unconditional `_autoLoadTab(tabId)`) and this test
    // would keep passing while silently reintroducing the infinite loop.
    expect(fn).to.include("if (!skipAutoLoad) _autoLoadTab(tabId)");
  });
});
