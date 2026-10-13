const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

function makeVscodeStub() {
  const registered = {};
  const statusBarItem = {
    text: "",
    tooltip: "",
    command: "",
    show: sinon.stub(),
    dispose: sinon.stub(),
  };
  const vscodeStub = {
    commands: {
      registerCommand: sinon.stub().callsFake((id, fn) => {
        registered[id] = fn;
        return { dispose: () => {} };
      }),
    },
    window: {
      showInformationMessage: sinon.stub(),
      showErrorMessage: sinon.stub(),
      showQuickPick: sinon.stub(),
      createStatusBarItem: sinon.stub().returns(statusBarItem),
    },
    StatusBarAlignment: { Right: 2 },
  };
  return { vscodeStub, registered, statusBarItem };
}

describe("mcpAgentCommands", () => {
  function load(vscodeStub) {
    return proxyquire("../static/mcpAgentCommands", { vscode: vscodeStub });
  }

  it("registers the 3 commands and opens the panel on mcpOpenAgentsPanel", () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    const panel = { open: sinon.stub() };
    const bridge = { doctor: sinon.stub(), rollback: sinon.stub() };
    const subs = registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel, logChannel: null });

    expect(subs.length).to.equal(3);
    expect(Object.keys(registered)).to.include.members([
      "pileOuFace.mcpOpenAgentsPanel",
      "pileOuFace.mcpDoctor",
      "pileOuFace.mcpRollback",
    ]);

    registered["pileOuFace.mcpOpenAgentsPanel"]();
    expect(panel.open.calledOnce).to.equal(true);
  });

  it("mcpDoctor shows an info message on a successful handshake", async () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    const diagnosis = { handshake_ok: true, interpreter: "/usr/bin/python3", protocol_version: "2024-11-05" };
    const bridge = { doctor: sinon.stub().resolves(diagnosis), rollback: sinon.stub() };
    const logChannel = { appendLine: sinon.stub() };
    registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel: { open: () => {} }, logChannel });

    await registered["pileOuFace.mcpDoctor"]();

    expect(bridge.doctor.calledWith("/proj")).to.equal(true);
    expect(vscodeStub.window.showInformationMessage.calledOnce).to.equal(true);
    expect(vscodeStub.window.showErrorMessage.called).to.equal(false);
    expect(logChannel.appendLine.calledOnce).to.equal(true);
  });

  it("mcpDoctor shows an error message when the handshake fails", async () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    const diagnosis = { handshake_ok: false, error: "timeout" };
    const bridge = { doctor: sinon.stub().resolves(diagnosis), rollback: sinon.stub() };
    registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel: { open: () => {} }, logChannel: null });

    await registered["pileOuFace.mcpDoctor"]();

    expect(vscodeStub.window.showErrorMessage.calledWith("MCP handshake failed: timeout")).to.equal(true);
  });

  it("mcpRollback does nothing when the quick pick is dismissed", async () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    vscodeStub.window.showQuickPick.resolves(undefined);
    const bridge = { doctor: sinon.stub(), rollback: sinon.stub() };
    registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel: { open: () => {} }, logChannel: null });

    await registered["pileOuFace.mcpRollback"]();

    expect(bridge.rollback.called).to.equal(false);
  });

  it("mcpRollback restores the picked agent's config and shows an info message", async () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    vscodeStub.window.showQuickPick.resolves({ label: "Claude Code", value: "claude" });
    const bridge = { doctor: sinon.stub(), rollback: sinon.stub().resolves({ errors: [] }) };
    registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel: { open: () => {} }, logChannel: null });

    await registered["pileOuFace.mcpRollback"]();

    expect(bridge.rollback.calledWith("claude", "/proj", "project")).to.equal(true);
    expect(vscodeStub.window.showInformationMessage.calledWith("Restored config for Claude Code from backup.")).to.equal(true);
  });

  it("mcpRollback shows an error message when the bridge reports errors", async () => {
    const { vscodeStub, registered } = makeVscodeStub();
    const { registerMcpAgentCommands } = load(vscodeStub);
    vscodeStub.window.showQuickPick.resolves({ label: "Codex", value: "codex" });
    const bridge = { doctor: sinon.stub(), rollback: sinon.stub().resolves({ errors: [{ error: "no backup" }] }) };
    registerMcpAgentCommands({}, { bridge, getProjectDir: () => "/proj", panel: { open: () => {} }, logChannel: null });

    await registered["pileOuFace.mcpRollback"]();

    expect(vscodeStub.window.showErrorMessage.calledWith("Rollback failed: no backup")).to.equal(true);
  });

  describe("createMcpStatusBarItem", () => {
    it("creates a status bar item bound to the open-panel command and refreshes to OK on success", async () => {
      const { vscodeStub, statusBarItem } = makeVscodeStub();
      const { createMcpStatusBarItem } = load(vscodeStub);
      const clock = sinon.useFakeTimers();
      try {
        const diagnosis = { handshake_ok: true, interpreter: "/usr/bin/python3" };
        const bridge = { doctor: sinon.stub().resolves(diagnosis) };
        const bar = createMcpStatusBarItem({ bridge, getProjectDir: () => "/proj" });
        expect(statusBarItem.command).to.equal("pileOuFace.mcpOpenAgentsPanel");
        expect(statusBarItem.show.calledOnce).to.equal(true);

        await clock.tickAsync(0);
        expect(statusBarItem.text).to.equal("$(check) MCP");

        bar.dispose();
        expect(statusBarItem.dispose.calledOnce).to.equal(true);
      } finally {
        clock.restore();
      }
    });

    it("refreshes to a warning state when the handshake fails", async () => {
      const { vscodeStub, statusBarItem } = makeVscodeStub();
      const { createMcpStatusBarItem } = load(vscodeStub);
      const clock = sinon.useFakeTimers();
      try {
        const bridge = { doctor: sinon.stub().resolves({ handshake_ok: false, error: "timeout" }) };
        const bar = createMcpStatusBarItem({ bridge, getProjectDir: () => "/proj" });

        await clock.tickAsync(0);
        expect(statusBarItem.text).to.equal("$(warning) MCP");
        expect(statusBarItem.tooltip).to.include("timeout");

        bar.dispose();
      } finally {
        clock.restore();
      }
    });
  });
});
