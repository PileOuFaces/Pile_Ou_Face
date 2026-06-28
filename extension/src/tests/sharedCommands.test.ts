const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("shared commands", () => {
  let registeredCommands;
  let vscodeStub;
  let recentBinariesStub;

  beforeEach(() => {
    registeredCommands = new Map();
    vscodeStub = {
      commands: {
        registerCommand: sinon.stub().callsFake((commandId, handler) => {
          registeredCommands.set(commandId, handler);
          return { dispose() {} };
        }),
      },
      window: {
        showQuickPick: sinon.stub(),
        showInputBox: sinon.stub(),
        createWebviewPanel: sinon.stub(),
      },
      QuickPickItemKind: {
        Separator: -1,
      },
      ViewColumn: {
        Beside: 2,
      },
    };
    recentBinariesStub = {
      getRecentBinaries: sinon.stub(),
      describeRecentBinaryMeta: sinon.stub().callsFake((meta) => meta?.format || "binaire"),
    };
  });

  function loadRegisterSharedCommands({ existsSync = () => true } = {}) {
    return proxyquire("../shared/commands", {
      vscode: vscodeStub,
      "./recentBinaries": recentBinariesStub,
      fs: { existsSync },
    }).registerSharedCommands;
  }

  it("opens the binary picker directly when no recent file exists", async () => {
    recentBinariesStub.getRecentBinaries.returns([]);
    const registerSharedCommands = loadRegisterSharedCommands({ existsSync: () => false });
    const openHub = sinon.stub();
    const logChannel = { show: sinon.stub() };

    registerSharedCommands({}, { logChannel, openHub });
    await registeredCommands.get("pileOuFace.open")();

    expect(vscodeStub.window.showQuickPick.called).to.equal(false);
    expect(openHub.calledOnceWithExactly("static", { requestBinarySelection: true })).to.equal(true);
    expect(logChannel.show.calledOnceWithExactly(true)).to.equal(true);
  });

  it("offers recent files and reopens the selected one", async () => {
    recentBinariesStub.getRecentBinaries.returns([
      {
        path: "/tmp/firmware.bin",
        meta: { kind: "native", format: "ELF", arch: "arm64" },
      },
    ]);
    vscodeStub.window.showQuickPick.callsFake(async (items) => items.find((item) => item.action === "recent"));
    const registerSharedCommands = loadRegisterSharedCommands();
    const openHub = sinon.stub();

    registerSharedCommands({}, { logChannel: { show: sinon.stub() }, openHub });
    await registeredCommands.get("pileOuFace.open")();

    expect(vscodeStub.window.showQuickPick.calledOnce).to.equal(true);
    expect(openHub.calledOnceWithExactly("static", {
      binaryPath: "/tmp/firmware.bin",
      binaryMeta: { kind: "native", format: "ELF", arch: "arm64" },
    })).to.equal(true);
  });
});
