const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const path = require("path");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

function makePanelSink() {
  const messages = [];
  return {
    messages,
    panel: {
      webview: {
        postMessage: (message) => {
          messages.push(message);
        },
      },
    },
  };
}

describe("sharedHandlers", () => {
  let tempRoot;
  let sink;
  let vscodeStub;
  let fileManagerStub;
  let patchHistoryBridge;

  beforeEach(() => {
    tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "pof-shared-handlers-"));
    sink = makePanelSink();
    vscodeStub = {
      window: {
        showWarningMessage: sinon.stub(),
        showQuickPick: sinon.stub(),
        showInputBox: sinon.stub(),
        showErrorMessage: sinon.stub(),
        showInformationMessage: sinon.stub(),
        showOpenDialog: sinon.stub(),
        showSaveDialog: sinon.stub(),
      },
      Uri: {
        file: (p) => ({ fsPath: p }),
      },
    };
    fileManagerStub = {
      cleanupForBinary: sinon.stub().returns({ removedArtifacts: 1, removedCache: 2, removedSupport: 1, purgedStale: 3, total: 7 }),
      listAll: sinon.stub().returns({ artifacts: [], cache: [], staleCache: [], totalSize: 0, totalFiles: 0 }),
      cleanupAll: sinon.stub().returns({ removedArtifacts: 0, removedCache: 0 }),
      purgeStaleCache: sinon.stub().returns({ removed: 0 }),
    };
    patchHistoryBridge = {
      deleteHistory: sinon.stub().resolves({ ok: true, removed: 1 }),
      purgeMissing: sinon.stub().resolves({ ok: true, removed: 0 }),
    };
  });

  afterEach(() => {
    sinon.restore();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("offers recent cleanup when a selected file no longer exists", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const clearRawProfile = sinon.stub().resolves();
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      clearRawProfile,
      patchHistoryBridge,
    });
    const missingPath = path.join(tempRoot, "ghost.bin");

    vscodeStub.window.showWarningMessage.onFirstCall().resolves("Remove and clean up");

    await handlers.hubUseBinaryPath({ binaryPath: missingPath });

    expect(clearRawProfile.calledOnceWithExactly(missingPath)).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.calledOnce).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.firstCall.args[1]).to.equal(missingPath);
    expect(sink.messages.map((message) => message.type)).to.include("hubForgetRecentBinary");
    expect(sink.messages.map((message) => message.type)).to.include("generatedFiles");
    expect(vscodeStub.window.showInformationMessage.calledOnce).to.equal(true);
  });

  it("cleans generated files when a recent binary is removed", async () => {
    const forgetRecentBinary = sinon.stub().resolves([]);
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
      "./recentBinaries": {
        forgetRecentBinary,
        getRecentBinaries: () => [],
        clearRecentBinaries: sinon.stub().resolves([]),
        rememberRecentBinary: sinon.stub().resolves([]),
      },
    });
    const clearRawProfile = sinon.stub().resolves();
    const handlers = sharedHandlers({
      root: tempRoot,
      storageDir: path.join(tempRoot, "storage"),
      panel: sink.panel,
      context: { workspaceState: { get: () => [], update: sinon.stub().resolves() } },
      clearRawProfile,
      patchHistoryBridge,
    });
    const binaryPath = path.join(tempRoot, "sample.exe");

    await handlers.hubForgetRecentBinary({ binaryPath });

    expect(forgetRecentBinary.calledOnce).to.equal(true);
    expect(clearRawProfile.calledOnceWithExactly(binaryPath)).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.calledOnce).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.firstCall.args[1]).to.equal(binaryPath);
    expect(patchHistoryBridge.deleteHistory.calledOnceWithExactly(binaryPath)).to.equal(true);
    expect(sink.messages.map((message) => message.type)).to.include("generatedFiles");
  });

  it("purges stale SQLite patch histories with workspace cache entries", async () => {
    fileManagerStub.purgeStaleCache.returns({ removed: 2 });
    patchHistoryBridge.purgeMissing.resolves({ ok: true, removed: 3 });
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      patchHistoryBridge,
    });

    await handlers.purgeStaleCache();

    expect(patchHistoryBridge.purgeMissing.calledOnceWithExactly(tempRoot)).to.equal(true);
    expect(vscodeStub.window.showInformationMessage.firstCall.args[0]).to.include("5 stale cache entry");
  });

  it("allows reconfiguring a stored raw profile when reopening a blob", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const setRawProfile = sinon.stub().resolves();
    const getRawProfile = sinon.stub().returns({
      arch: "i386:x86-64",
      baseAddr: "0x500000",
      endian: "little",
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      getRawProfile,
      setRawProfile,
      clearRawProfile: sinon.stub().resolves(),
    });

    const rawPath = path.join(tempRoot, "blob.bin");
    fs.writeFileSync(rawPath, Buffer.from("shellcode"));

    vscodeStub.window.showQuickPick.onCall(0).resolves({ value: "reconfigure" });
    vscodeStub.window.showQuickPick.onCall(1).resolves({ value: "mips32" });
    vscodeStub.window.showQuickPick.onCall(2).resolves({ value: "big" });
    vscodeStub.window.showInputBox.resolves("0x800000");

    await handlers.hubUseBinaryPath({ binaryPath: rawPath });

    expect(setRawProfile.calledOnce).to.equal(true);
    expect(setRawProfile.firstCall.args[0]).to.equal(rawPath);
    expect(setRawProfile.firstCall.args[1]).to.deep.include({
      arch: "mips32",
      baseAddr: "0x800000",
      endian: "big",
    });
    const setBinaryMessage = sink.messages.find((message) => message.type === "hubSetBinaryPath");
    expect(setBinaryMessage).to.exist;
    expect(setBinaryMessage.binaryMeta.kind).to.equal("raw");
    expect(setBinaryMessage.binaryMeta.rawConfig).to.deep.include({
      arch: "mips32",
      baseAddr: "0x800000",
      endian: "big",
    });
  });

  it("supports forcing raw blob reconfiguration directly from the current session", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const setRawProfile = sinon.stub().resolves();
    const getRawProfile = sinon.stub().returns({
      arch: "thumb",
      baseAddr: "0x710000",
      endian: "little",
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      getRawProfile,
      setRawProfile,
      clearRawProfile: sinon.stub().resolves(),
    });

    const rawPath = path.join(tempRoot, "blob-thumb.bin");
    fs.writeFileSync(rawPath, Buffer.from("shellcode"));

    vscodeStub.window.showQuickPick.onCall(0).resolves({ value: "thumb" });
    vscodeStub.window.showQuickPick.onCall(1).resolves({ value: "big" });
    vscodeStub.window.showInputBox.resolves("0x720000");

    await handlers.hubUseBinaryPath({
      binaryPath: rawPath,
      rawProfileAction: "reconfigure",
      binaryMeta: {
        kind: "raw",
        rawConfig: {
          arch: "thumb",
          baseAddr: "0x710000",
          endian: "little",
        },
      },
    });

    expect(setRawProfile.calledOnce).to.equal(true);
    expect(vscodeStub.window.showQuickPick.callCount).to.equal(2);
    expect(setRawProfile.firstCall.args[1]).to.deep.include({
      arch: "thumb",
      baseAddr: "0x720000",
      endian: "big",
    });
  });

  it("loads AI chat history through the SQLite bridge", async () => {
    const chatHistoryBridge = {
      loadHistory: sinon.stub().resolves({
        conversations: [{ id: "conv-1", messages: [] }],
        activeConversationId: "conv-1",
      }),
      saveHistory: sinon.stub().resolves(),
    };
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      chatHistoryBridge,
    });

    await handlers.hubLoadChatHistory();

    expect(chatHistoryBridge.loadHistory.calledOnce).to.equal(true);
    expect(sink.messages).to.deep.include({
      type: "hubChatHistory",
      conversations: [{ id: "conv-1", messages: [] }],
      activeConversationId: "conv-1",
    });
  });

  it("saves AI chat history through the SQLite bridge", async () => {
    const chatHistoryBridge = {
      loadHistory: sinon.stub().resolves({}),
      saveHistory: sinon.stub().resolves(),
    };
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      chatHistoryBridge,
    });
    const conversations = [{ id: "conv-1", messages: [] }];

    await handlers.hubSaveChatHistory({ conversations, activeConversationId: "conv-1" });

    expect(chatHistoryBridge.saveHistory.calledOnceWithExactly({
      conversations,
      activeConversationId: "conv-1",
    })).to.equal(true);
  });

  it("exports an AI conversation in the selected format", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
    });
    const outputPath = path.join(tempRoot, "analyse.md");
    vscodeStub.window.showQuickPick.resolves({ value: "markdown" });
    vscodeStub.window.showSaveDialog.resolves({ fsPath: outputPath });

    await handlers.hubExportConversation({
      markdown: "# Analyse\n\nContenu\n",
      json: { schema: "pile-ou-face.ai-conversation.v1" },
      suggestedName: "../Analyse dangereuse",
    });

    expect(vscodeStub.window.showSaveDialog.firstCall.args[0].defaultUri.fsPath).to.equal(
      path.join(tempRoot, "Analyse-dangereuse.md"),
    );
    expect(fs.readFileSync(outputPath, "utf8")).to.equal("# Analyse\n\nContenu\n");
    expect(vscodeStub.window.showInformationMessage.calledOnce).to.equal(true);
  });

  it("loads annotations directly from the SQLite bridge", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const storageDir = path.join(tempRoot, "storage");
    const binaryPath = path.join(tempRoot, "sqlite-only.bin");
    fs.writeFileSync(binaryPath, Buffer.from("binary-content"));

    const currentAnnotations = { "0x2000": { comment: "already in sqlite" } };
    const annotationsBridgeStub = {
      loadAnnotations: sinon.stub().resolves(currentAnnotations),
    };

    const handlers = sharedHandlers({
      root: tempRoot,
      storageDir,
      panel: sink.panel,
      annotationsBridge: annotationsBridgeStub,
    });

    await handlers.hubLoadAnnotations({ binaryPath });

    expect(annotationsBridgeStub.loadAnnotations.calledOnceWithExactly(binaryPath)).to.equal(true);

    const annotationsMessage = sink.messages.find((message) => message.type === "hubAnnotations");
    expect(annotationsMessage).to.exist;
    expect(annotationsMessage.binaryPath).to.equal(binaryPath);
    expect(annotationsMessage.annotations).to.deep.equal(currentAnnotations);
  });

  it("includes function addresses from the disassembly mapping when loading annotations", async () => {
    const sharedHandlers = proxyquire("../shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const storageDir = path.join(tempRoot, "storage");
    fs.mkdirSync(storageDir, { recursive: true });
    const binaryPath = path.join(tempRoot, "sample.bin");
    fs.writeFileSync(binaryPath, Buffer.from("binary-content"));
    fs.writeFileSync(
      path.join(storageDir, "sample.disasm.mapping.json"),
      JSON.stringify({
        binary: binaryPath,
        functions: [{ addr: "0x80490a0", name: "_start" }],
        lines: [{ addr: "0x80490a0", function_addr: "0x80490a0" }],
      }),
      "utf8",
    );

    const currentAnnotations = { "0x80490a0": { comment: "aaaa", name: "test" } };
    const annotationsBridgeStub = {
      loadAnnotations: sinon.stub().resolves(currentAnnotations),
    };

    const handlers = sharedHandlers({
      root: tempRoot,
      storageDir,
      panel: sink.panel,
      annotationsBridge: annotationsBridgeStub,
    });

    await handlers.hubLoadAnnotations({ binaryPath });

    const annotationsMessage = sink.messages.find((message) => message.type === "hubAnnotations");
    expect(annotationsMessage).to.exist;
    expect(annotationsMessage.annotations).to.deep.equal(currentAnnotations);
    expect(annotationsMessage.functionAddrs).to.deep.equal(["0x80490a0"]);
  });

  describe("replies that arrive after the hub was closed", () => {
    function makeClosablePanel({ deliver = () => Promise.resolve(true) } = {}) {
      const messages = [];
      const disposeListeners = [];
      let disposed = false;
      const webview = {
        postMessage: (message) => {
          messages.push(message);
          return deliver(message);
        },
      };
      return {
        messages,
        close: () => {
          disposed = true;
          disposeListeners.forEach((listener) => listener());
        },
        panel: {
          onDidDispose: (listener) => disposeListeners.push(listener),
          get webview() {
            if (disposed) throw new Error("Webview is disposed");
            return webview;
          },
        },
      };
    }

    function makeExecFileStub() {
      const calls = [];
      const execFile = (_file, args, _options, callback) => {
        calls.push({ args, callback });
        return { stdin: { write: sinon.stub(), end: sinon.stub() } };
      };
      return { calls, execFile };
    }

    function loadHandlers(stubs = {}) {
      return proxyquire("../shared/sharedHandlers", {
        vscode: vscodeStub,
        "./fileManager": fileManagerStub,
        ...stubs,
      });
    }

    const flush = () => new Promise((resolve) => setImmediate(resolve));

    it("drops every AI provider update reply once the hub is closed, including a failed refresh", () => {
      for (const scenario of ["set fails", "set rejected", "refresh fails"]) {
        const hub = makeClosablePanel();
        const proc = makeExecFileStub();
        const handlers = loadHandlers({ child_process: { execFile: proc.execFile } })({
          root: tempRoot,
          panel: hub.panel,
        });
        handlers.hubAiProviderSet({ provider: "ollama", api_key: "", model: "m" });
        hub.close();
        expect(() => {
          if (scenario === "set fails") proc.calls[0].callback(new Error("exit 1"), "");
          if (scenario === "set rejected") proc.calls[0].callback(null, JSON.stringify({ ok: false, error: "bad" }));
          if (scenario === "refresh fails") {
            proc.calls[0].callback(null, JSON.stringify({ ok: true }));
            proc.calls[1].callback(new Error("exit 1"), "not json");
          }
        }, scenario).to.not.throw();
        expect(hub.messages, scenario).to.deep.equal([]);
      }
    });

    it("still reports a failed refresh while the hub is open", () => {
      const hub = makeClosablePanel();
      const proc = makeExecFileStub();
      const handlers = loadHandlers({ child_process: { execFile: proc.execFile } })({
        root: tempRoot,
        panel: hub.panel,
      });
      handlers.hubAiProviderSet({ provider: "ollama", api_key: "", model: "m" });
      proc.calls[0].callback(null, JSON.stringify({ ok: true }));
      proc.calls[1].callback(new Error("exit 1"), "not json");
      expect(hub.messages).to.deep.equal([
        { type: "hubAiProvidersResult", data: { error: "Update saved — refresh failed" } },
      ]);
    });

    it("does not report annotations closed mid-load as a load failure", async () => {
      const hub = makeClosablePanel();
      let resolveLoad;
      const annotationsBridge = {
        loadAnnotations: sinon.stub().returns(new Promise((resolve) => { resolveLoad = resolve; })),
      };
      const handlers = loadHandlers()({ root: tempRoot, panel: hub.panel, annotationsBridge });
      const pending = handlers.hubLoadAnnotations({ binaryPath: path.join(tempRoot, "a.bin") });
      hub.close();
      resolveLoad({ "0x10": { comment: "late" } });
      await pending;
      expect(vscodeStub.window.showErrorMessage.called).to.equal(false);
      expect(hub.messages).to.deep.equal([]);
    });

    it("still shows a real annotation load error while the hub is open", async () => {
      const hub = makeClosablePanel();
      const annotationsBridge = { loadAnnotations: sinon.stub().rejects(new Error("database locked")) };
      const handlers = loadHandlers()({ root: tempRoot, panel: hub.panel, annotationsBridge });
      await handlers.hubLoadAnnotations({ binaryPath: path.join(tempRoot, "a.bin") });
      expect(vscodeStub.window.showErrorMessage.calledOnceWithExactly("Unable to load annotations: database locked"))
        .to.equal(true);
    });

    it("logs a rejected or thrown delivery to an open hub without an unhandled rejection", async () => {
      const unhandled = [];
      const onUnhandled = (reason) => unhandled.push(reason);
      process.on("unhandledRejection", onUnhandled);
      try {
        const cases = {
          rejected: () => Promise.reject(new Error("transport closed")),
          thrown: () => { throw new Error("serialization failed"); },
          unprintable: () => { throw { get message() { throw new Error("boom"); } }; },
        };
        for (const [name, deliver] of Object.entries(cases)) {
          const logWarning = sinon.stub();
          const hub = makeClosablePanel({ deliver });
          const handlers = loadHandlers({ "./utils": { logWarning } })({ root: tempRoot, panel: hub.panel });
          expect(() => handlers.getPlatform(), name).to.not.throw();
          await flush();
          expect(logWarning.calledOnce, name).to.equal(true);
          expect(logWarning.firstCall.args[0], name).to.match(/^\[hub\] message platformInfo not delivered: /);
        }
        await flush();
        expect(unhandled).to.deep.equal([]);
      } finally {
        process.removeListener("unhandledRejection", onUnhandled);
      }
    });

    it("logs a delivery that fails after the hub closed only if the failure is not the closing", async () => {
      const cases = [
        ["serialization failed", true],
        ["Transport failure: Webview is disposed", true],
        ["Webview is disposed unexpectedly", true],
        ["Webview is disposed", false],
      ];
      for (const [reason, logged] of cases) {
        let rejectDelivery;
        const logWarning = sinon.stub();
        const hub = makeClosablePanel({ deliver: () => new Promise((_, reject) => { rejectDelivery = reject; }) });
        const handlers = loadHandlers({ "./utils": { logWarning } })({ root: tempRoot, panel: hub.panel });
        handlers.getPlatform();
        hub.close();
        rejectDelivery(new Error(reason));
        await flush();
        expect(logWarning.called, reason).to.equal(logged);
      }
    });
  });
});
