// SPDX-License-Identifier: AGPL-3.0-only
const { expect } = require("chai");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

function loadClassicController(relativePath) {
  const filename = path.resolve(__dirname, "..", relativePath);
  const sandbox = {
    window: null,
    POFHub: {},
  };
  sandbox.window = sandbox;
  vm.runInNewContext(fs.readFileSync(filename, "utf8"), sandbox, { filename });
  return sandbox;
}

function field(value = "") {
  return {
    value,
    listeners: {},
    addEventListener(event, listener) {
      this.listeners[event] = listener;
    },
    fire(event) {
      this.listeners[event]?.();
    },
  };
}

function button() {
  return field("");
}

describe("webview static file payload controller", () => {
  it("builds snapshots with inline defaults and path payloads", () => {
    const sandbox = loadClassicController("webview/static/filePayloadController.js");
    const source = field("inline");
    const guestPath = field("");
    const hostPath = field(" /tmp/input.bin ");
    const inlineContent = field("AAAA");

    const controller = sandbox.POFHubFilePayloadController.initFilePayloadController({
      payloadFileSource: source,
      payloadFileGuestPath: guestPath,
      payloadFileHostPath: hostPath,
      payloadFileContent: inlineContent,
    });

    expect(controller.getFilePayloadSnapshot()).to.deep.equal({
      mode: "file",
      source: "inline",
      guestPath: "/tmp/pof-input.txt",
      hostPath: "/tmp/input.bin",
      inlineContent: "AAAA",
    });

    source.value = "path";
    guestPath.value = " /guest/payload ";
    expect(controller.getFilePayloadSnapshot()).to.include({
      source: "path",
      guestPath: "/guest/payload",
    });
  });

  it("invalidates preview when file fields change", () => {
    const sandbox = loadClassicController("webview/static/filePayloadController.js");
    const guestPath = field("/tmp/a");
    const hostPath = field("/tmp/b");
    const content = field("payload");
    let invalidations = 0;

    sandbox.POFHubFilePayloadController.initFilePayloadController({
      payloadFileGuestPath: guestPath,
      payloadFileHostPath: hostPath,
      payloadFileContent: content,
      invalidateDynamicPayloadPreview: () => { invalidations += 1; },
    });

    guestPath.fire("input");
    hostPath.fire("change");
    content.fire("input");
    expect(invalidations).to.equal(3);
  });

  it("requests host file picking from the select button", () => {
    const sandbox = loadClassicController("webview/static/filePayloadController.js");
    const selectButton = button();
    const messages = [];
    const statuses = [];

    sandbox.POFHubFilePayloadController.initFilePayloadController({
      btnDynamicSelectPayloadFile: selectButton,
      postMessage: (message) => messages.push(message),
      setDynamicTraceStatus: (status) => statuses.push(status),
    });

    selectButton.fire("click");

    expect(statuses).to.deep.equal(["Sélection du fichier payload..."]);
    expect(messages).to.deep.equal([{ type: "hubPickFile", target: "payloadFileHostPath" }]);
  });

  it("handles picked-file messages and ignores unrelated messages", () => {
    const sandbox = loadClassicController("webview/static/filePayloadController.js");
    const hostPath = field("");
    const calls = [];

    const controller = sandbox.POFHubFilePayloadController.initFilePayloadController({
      payloadFileHostPath: hostPath,
      setDynamicPayloadMode: (mode) => calls.push(["mode", mode]),
      refreshFilePanels: () => calls.push(["refresh"]),
      invalidateDynamicPayloadPreview: () => calls.push(["invalidate"]),
    });

    expect(controller.handleFilePayloadMessage({ type: "other" })).to.equal(false);
    expect(controller.handleFilePayloadMessage({
      type: "hubPickedFile",
      target: "payloadFileHostPath",
      path: "/tmp/payload.bin",
    })).to.equal(true);

    expect(hostPath.value).to.equal("/tmp/payload.bin");
    expect(calls).to.deep.equal([
      ["mode", "file"],
      ["refresh"],
      ["invalidate"],
    ]);
  });
});

describe("webview static payload builder controller", () => {
  it("reads and writes builder levels and hints", () => {
    const sandbox = loadClassicController("webview/static/payloadBuilderController.js");
    let level = "beginner";
    const controller = sandbox.POFHubPayloadBuilderController.initPayloadBuilderController({
      payloadBuilderInput: field("A*8"),
      getBuilderLevel: () => level,
      setBuilderLevel: (next) => {
        level = next;
        return next;
      },
      normalizePayloadBuilderLevel: (value, fallback = "beginner") => (
        value === "advanced" || value === "beginner" ? value : fallback
      ),
    });

    expect(controller.getBuilderLevel()).to.equal("beginner");
    expect(controller.getBuilderHint()).to.contain("Beginner");
    expect(controller.setBuilderLevel("advanced")).to.equal("advanced");
    expect(controller.getBuilderHint()).to.contain("Advanced");
  });

  it("builds a complete payload snapshot", () => {
    const sandbox = loadClassicController("webview/static/payloadBuilderController.js");
    const controller = sandbox.POFHubPayloadBuilderController.initPayloadBuilderController({
      payloadBuilderInput: field("A*16"),
      getBuilderLevel: () => "advanced",
      getDynamicPayloadTargetMode: () => "stdin",
      getDynamicResolvedArch: () => "i386",
      getEndian: () => "big",
      getBadchars: () => "\\x00",
    });

    expect(controller.getBuilderPayloadSnapshot()).to.deep.equal({
      mode: "payload_builder",
      builderLevel: "advanced",
      input: "A*16",
      targetMode: "stdin",
      arch: "i386",
      endian: "big",
      badchars: "\\x00",
    });
  });

  it("normalizes helper payload output into a dynamic input config", () => {
    const sandbox = loadClassicController("webview/static/payloadBuilderController.js");
    const helperCalls = [];
    const normalizeCalls = [];
    const controller = sandbox.POFHubPayloadBuilderController.initPayloadBuilderController({
      payloadBuilderInput: field("A*4"),
      getBuilderLevel: () => "beginner",
      getDynamicPayloadTargetMode: () => "argv1",
      getDynamicResolvedArch: () => "amd64",
      getEndian: () => "little",
      getBadchars: () => "",
      getExploitHelperApi: () => ({
        buildPayload(source, level, options) {
          helperCalls.push({ source, level, options });
          return { size: 4, payloadExpr: "A*4", resolvedPayloadBytes: [65, 65, 65, 65] };
        },
      }),
      normalizeGeneratedPreview: (resolved, context) => {
        normalizeCalls.push({ resolved, context });
        return { ...resolved, previewAscii: "AAAA" };
      },
    });

    expect(controller.buildBuilderInputConfig()).to.deep.include({
      size: 4,
      payloadExpr: "A*4",
      previewAscii: "AAAA",
      currentPayloadSource: "A*4",
    });
    expect(helperCalls).to.deep.equal([{
      source: "A*4",
      level: "beginner",
      options: {
        arch: "amd64",
        endian: "little",
        badchars: "",
        targetMode: "argv1",
      },
    }]);
    expect(normalizeCalls[0].context).to.deep.equal({
      mode: "payload_builder",
      targetMode: "argv1",
      currentPayloadSource: "A*4",
    });
  });

  it("updates status for input, empty input and invalid expressions", () => {
    const sandbox = loadClassicController("webview/static/payloadBuilderController.js");
    const input = field("A*8");
    const statuses = [];
    let shouldThrow = false;
    const controller = sandbox.POFHubPayloadBuilderController.initPayloadBuilderController({
      payloadBuilderInput: input,
      getBuilderLevel: () => "beginner",
      getDynamicEffectivePayloadTarget: () => "stdin",
      dynamicPayloadTargetLabel: (target) => target,
      updateArgvPayloadHint: () => {},
      invalidateDynamicPayloadPreview: () => {},
      setDynamicTraceStatus: (status) => statuses.push(status),
      getExploitHelperApi: () => ({
        buildPayload() {
          if (shouldThrow) throw new Error("bad payload");
          return { size: 8 };
        },
      }),
    });

    controller.handlePayloadBuilderInput();
    input.value = "";
    controller.handlePayloadBuilderInput();
    input.value = "bad(";
    shouldThrow = true;
    controller.handlePayloadBuilderInput();

    expect(statuses).to.deep.equal([
      "stdin prêt: 8 byte(s).",
      "Prêt.",
      "Expression payload invalide.",
    ]);
  });

  it("refreshes the builder UI through the injected renderer", () => {
    const sandbox = loadClassicController("webview/static/payloadBuilderController.js");
    let renderCount = 0;
    const controller = sandbox.POFHubPayloadBuilderController.initPayloadBuilderController({
      payloadBuilderInput: field(""),
      renderBuilderUi: () => { renderCount += 1; },
    });

    controller.refreshPayloadBuilderUi();
    expect(renderCount).to.equal(1);
  });
});

describe("webview static payload state controller", () => {
  function createStateController(overrides = {}) {
    const sandbox = loadClassicController("webview/static/payloadStateController.js");
    const state = {
      mode: overrides.mode || "payload_builder",
      trace: overrides.trace || {},
    };
    const deps = {
      TextEncoder,
      normalizePayloadMode: (mode) => (
        ["payload_builder", "file", "exploit_helper", "pwntools_script"].includes(mode)
          ? mode
          : "payload_builder"
      ),
      normalizePayloadTargetMode: (mode) => (
        ["auto", "argv1", "stdin", "both"].includes(String(mode || ""))
          ? String(mode || "")
          : "auto"
      ),
      normalizeEffectiveTarget: (target) => (
        ["argv1", "stdin", "both"].includes(String(target || ""))
          ? String(target || "")
          : "argv1"
      ),
      payloadTargetLabel: (target) => (
        target === "both" ? "stdin + argv[1]" : String(target || "argv[1]")
      ),
      payloadTabsController: {
        getMode: () => state.mode,
        setMode: (mode) => {
          state.mode = mode;
          return mode;
        },
      },
      dynamicPayloadTargetMode: { value: overrides.targetMode || "auto" },
      getDynamicTraceInitState: () => state.trace,
      getDynamicResolvedArch: () => "amd64",
      hexHasNullByte: (hex) => /(?:^|..)00/.test(String(hex || "")),
      hexToByteArray: (hex) => String(hex || "").match(/../g)?.map((part) => parseInt(part, 16)) || [],
      ...overrides.deps,
    };
    return {
      controller: sandbox.POFHubPayloadStateController.initPayloadStateController(deps),
      state,
      deps,
    };
  }

  it("normalizes payload mode and target selection", () => {
    const { controller, state } = createStateController({
      targetMode: "auto",
      trace: {
        payloadTargetAuto: "stdin",
        payloadTargetReason: "Auto: fgets détecté.",
      },
    });

    expect(controller.getPayloadMode()).to.equal("payload_builder");
    expect(controller.setPayloadMode("file")).to.equal("file");
    expect(state.mode).to.equal("file");
    expect(controller.getPayloadTargetMode()).to.equal("auto");
    expect(controller.getEffectivePayloadTarget()).to.equal("stdin");
    expect(controller.getPayloadTargetHint()).to.equal("Auto: fgets détecté.");
    expect(controller.getInputTargetModeForPayload()).to.equal("argv1");
  });

  it("uses manual target hints before auto-detected targets", () => {
    const { controller } = createStateController({
      targetMode: "both",
      trace: { payloadTargetAuto: "stdin" },
    });

    expect(controller.getPayloadTargetMode()).to.equal("both");
    expect(controller.getEffectivePayloadTarget()).to.equal("both");
    expect(controller.getPayloadTargetHint()).to.equal("stdin + argv[1] force manuellement.");
  });

  it("builds active snapshots for every payload mode", () => {
    const { controller, state } = createStateController({
      deps: {
        payloadBuilderController: {
          getBuilderPayloadSnapshot: () => ({
            builderLevel: "advanced",
            input: "cyclic(64)",
            targetMode: "stdin",
            arch: "i386",
            endian: "big",
            badchars: "\\x00",
          }),
        },
        filePayloadController: {
          getFilePayloadSnapshot: () => ({
            source: "path",
            guestPath: "/guest/in",
            hostPath: "/host/in",
          }),
        },
        exploitHelperController: {
          collectExploitHelperFields: () => ({ template: "ret2win", offset: 72 }),
        },
        pwntoolsScriptController: {
          getSourceSnapshot: () => ({
            sourceFileName: "solve.py",
            scriptPath: "/tmp/solve.py",
            scriptContent: "print('x')",
            selectedCapture: { captureId: "c1" },
          }),
        },
      },
    });

    expect(controller.getActivePayloadSnapshot()).to.include({
      mode: "payload_builder",
      builderLevel: "advanced",
      input: "cyclic(64)",
      targetMode: "stdin",
    });

    state.mode = "file";
    expect(controller.getActivePayloadSnapshot()).to.deep.equal({
      mode: "file",
      source: "path",
      guestPath: "/guest/in",
      hostPath: "/host/in",
      inlineContent: "",
    });

    state.mode = "exploit_helper";
    expect(controller.getActivePayloadSnapshot()).to.deep.equal({
      mode: "exploit_helper",
      template: "ret2win",
      offset: 72,
    });

    state.mode = "pwntools_script";
    expect(controller.getActivePayloadSnapshot()).to.deep.equal({
      mode: "pwntools_script",
      sourceFileName: "solve.py",
      scriptPath: "/tmp/solve.py",
      scriptContent: "print('x')",
      selectedCapture: { captureId: "c1" },
    });
  });

  it("builds file input configs for inline content and missing host paths", () => {
    const { controller } = createStateController({
      mode: "file",
      deps: {
        filePayloadController: {
          getFilePayloadSnapshot: () => ({
            source: "inline",
            guestPath: "/tmp/in.txt",
            inlineContent: "AZ",
          }),
        },
      },
    });

    expect(controller.buildActiveInputConfig()).to.deep.include({
      mode: "file",
      targetMode: "argv1",
      currentPayloadSource: "AZ",
      size: 2,
      previewAscii: "AZ",
    });
    expect(controller.buildActiveInputConfig().resolvedPayloadBytes).to.deep.equal([65, 90]);
    expect(controller.buildActiveInputConfig().warnings).to.deep.equal([]);

    const missingPathController = createStateController({
      mode: "file",
      deps: {
        filePayloadController: {
          getFilePayloadSnapshot: () => ({
            source: "path",
            guestPath: "/tmp/in.txt",
            hostPath: "",
          }),
        },
      },
    }).controller;
    const missingPath = missingPathController.buildActiveInputConfig();
    expect(missingPath.warnings).to.deep.equal(["Fichier local requis."]);
    expect(missingPath.currentPayloadSource).to.equal("");
    expect(missingPath.file).to.include({
      source: "path",
      guestPath: "/tmp/in.txt",
      hostPath: "",
      passAs: "argv1",
    });
  });

  it("delegates builder and exploit-helper input config generation", () => {
    const { controller, state } = createStateController({
      deps: {
        payloadBuilderController: {
          buildBuilderInputConfig: () => ({ mode: "payload_builder", size: 8 }),
        },
        exploitHelperController: {
          getExploitHelperPayload: () => ({ mode: "exploit_helper", size: 72 }),
        },
      },
    });

    expect(controller.buildActiveInputConfig()).to.deep.equal({ mode: "payload_builder", size: 8 });
    state.mode = "exploit_helper";
    expect(controller.buildActiveInputConfig()).to.deep.equal({ mode: "exploit_helper", size: 72 });
  });

  it("builds pwntools input configs and warns about argv null bytes", () => {
    const { controller, state } = createStateController({
      mode: "pwntools_script",
      deps: {
        getPwntoolsCaptureEntries: () => [
          {
            id: "c1",
            hex: "410042",
            targetHint: "argv1",
            kind: "sendline",
            processArgs: ["./vuln"],
            size: 3,
            asciiPreview: "A\\0B",
          },
        ],
        pwntoolsScriptController: {
          getAnalysisResult: () => ({ warnings: ["analyse partielle"], sourceFileName: "solve.py" }),
          getSelectedCapture: () => ({ captureId: "c1", target: "argv1" }),
          getScriptName: () => "solve.py",
          getScriptContent: () => "payload = b'A\\0B'",
        },
      },
    });

    const config = controller.buildActiveInputConfig();
    expect(state.mode).to.equal("pwntools_script");
    expect(config).to.deep.include({
      mode: "pwntools_script",
      targetMode: "argv1",
      payloadBytesHex: "410042",
      size: 3,
      previewAscii: "A\\0B",
      sourceFileName: "solve.py",
      selectedCaptureKind: "sendline",
      target: "argv1",
    });
    expect(config.resolvedPayloadBytes).to.deep.equal([0x41, 0x00, 0x42]);
    expect(config.warnings).to.deep.equal([
      "analyse partielle",
      "argv[1] ne peut pas transporter un octet NUL exact.",
    ]);
  });

  it("reports missing pwntools analysis and empty capture sets", () => {
    const { controller } = createStateController({
      mode: "pwntools_script",
      deps: {
        pwntoolsScriptController: {
          getAnalysisResult: () => null,
        },
      },
    });

    expect(() => controller.buildActiveInputConfig()).to.throw("Analyse pwntools requise");

    const emptyCaptureController = createStateController({
      mode: "pwntools_script",
      deps: {
        pwntoolsScriptController: {
          getAnalysisResult: () => ({}),
        },
        getPwntoolsCaptureEntries: () => [],
      },
    }).controller;
    expect(() => emptyCaptureController.buildActiveInputConfig()).to.throw("Aucun payload capturé");
  });

  it("invalidates previews and refreshes child controller UIs", () => {
    const calls = [];
    const { controller, deps } = createStateController({
      deps: {
        markPreviewStale: (reason) => {
          calls.push(["stale", reason]);
          return { status: "stale" };
        },
        payloadBuilderController: { refreshPayloadBuilderUi: () => calls.push(["builder"]) },
        filePayloadController: { refreshFilePayloadUi: () => calls.push(["file"]) },
        exploitHelperController: { refreshExploitHelperUi: () => calls.push(["helper"]) },
        pwntoolsScriptController: { refreshPwntoolsScriptUi: () => calls.push(["pwntools"]) },
      },
    });

    expect(controller.invalidatePayloadPreview("input")).to.deep.equal({ status: "stale" });
    controller.refreshPayloadStateUi();
    expect(calls).to.deep.equal([
      ["stale", "input"],
      ["builder"],
      ["file"],
      ["helper"],
      ["pwntools"],
    ]);

    delete deps.markPreviewStale;
  });
});
