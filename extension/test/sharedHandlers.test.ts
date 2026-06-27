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
  });

  afterEach(() => {
    sinon.restore();
    fs.rmSync(tempRoot, { recursive: true, force: true });
  });

  it("offers recent cleanup when a selected file no longer exists", async () => {
    const sharedHandlers = proxyquire("../src/shared/sharedHandlers", {
      vscode: vscodeStub,
      "./fileManager": fileManagerStub,
    });
    const clearRawProfile = sinon.stub().resolves();
    const handlers = sharedHandlers({
      root: tempRoot,
      panel: sink.panel,
      clearRawProfile,
    });
    const missingPath = path.join(tempRoot, "ghost.bin");

    vscodeStub.window.showWarningMessage.onFirstCall().resolves("Retirer et nettoyer");

    await handlers.hubUseBinaryPath({ binaryPath: missingPath });

    expect(clearRawProfile.calledOnceWithExactly(missingPath)).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.calledOnce).to.equal(true);
    expect(fileManagerStub.cleanupForBinary.firstCall.args[1]).to.equal(missingPath);
    expect(sink.messages.map((message) => message.type)).to.include("hubForgetRecentBinary");
    expect(sink.messages.map((message) => message.type)).to.include("generatedFiles");
    expect(vscodeStub.window.showInformationMessage.calledOnce).to.equal(true);
  });

  it("allows reconfiguring a stored raw profile when reopening a blob", async () => {
    const sharedHandlers = proxyquire("../src/shared/sharedHandlers", {
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
    const sharedHandlers = proxyquire("../src/shared/sharedHandlers", {
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

  it("exports an AI conversation in the selected format", async () => {
    const sharedHandlers = proxyquire("../src/shared/sharedHandlers", {
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
});
