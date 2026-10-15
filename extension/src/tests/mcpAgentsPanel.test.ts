const { expect } = require("chai");
const path = require("path");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

function makeUri(fsPath) {
  return { fsPath, toString: () => `uri://${fsPath}` };
}

function makeVscodeStub() {
  const panelListeners = {};
  const fakeWebview = {
    html: "",
    postMessage: sinon.stub(),
    asWebviewUri: (uri) => makeUri(uri.fsPath),
    cspSource: "vscode-resource:",
    onDidReceiveMessage: (fn) => { panelListeners.onMessage = fn; return { dispose: () => {} }; },
  };
  const fakePanel = {
    webview: fakeWebview,
    reveal: sinon.stub(),
    onDidDispose: (fn) => { panelListeners.onDispose = fn; return { dispose: () => {} }; },
  };
  const createWebviewPanel = sinon.stub().returns(fakePanel);
  const vscodeStub = {
    window: { createWebviewPanel },
    ViewColumn: { Beside: 2 },
    Uri: { joinPath: (base, ...parts) => makeUri(path.join(base.fsPath, ...parts)) },
  };
  return { vscodeStub, fakePanel, panelListeners, createWebviewPanel };
}

describe("mcpAgentsPanel", () => {
  function load(vscodeStub) {
    return proxyquire("../static/mcpAgentsPanel", { vscode: vscodeStub });
  }

  const extensionUri = makeUri(path.resolve(__dirname, "..", ".."));

  it("open() creates a singleton panel and loads mcpAgents.html with resolved placeholders", () => {
    const { vscodeStub, fakePanel, createWebviewPanel } = makeVscodeStub();
    const { createMcpAgentsPanel } = load(vscodeStub);
    const bridge = { preview: sinon.stub(), apply: sinon.stub(), rollback: sinon.stub(), doctor: sinon.stub() };
    const panel = createMcpAgentsPanel({
      context: { extensionUri },
      bridge,
      getProjectDir: () => "/proj",
    });

    panel.open();
    expect(createWebviewPanel.calledOnce).to.equal(true);
    expect(fakePanel.webview.html).to.not.include("{{scriptUri}}");
    expect(fakePanel.webview.html).to.not.include("{{cspSource}}");
    expect(fakePanel.webview.html).to.include("uri://");

    panel.open();
    expect(createWebviewPanel.calledOnce).to.equal(true);
    expect(fakePanel.reveal.calledOnce).to.equal(true);
  });

  it("dispatches mcpPreview to bridge.preview and posts mcpPreviewResult", async () => {
    const { vscodeStub, fakePanel, panelListeners } = makeVscodeStub();
    const { createMcpAgentsPanel } = load(vscodeStub);
    const payload = { dry_run: true, project_dir: "/proj", actions: [] };
    const bridge = { preview: sinon.stub().resolves(payload), apply: sinon.stub(), rollback: sinon.stub(), doctor: sinon.stub() };
    const panel = createMcpAgentsPanel({ context: { extensionUri }, bridge, getProjectDir: () => "/proj" });
    panel.open();

    await panelListeners.onMessage({ type: "mcpPreview", requestId: "r1", agent: "claude", scope: "project" });

    expect(bridge.preview.calledWith("claude", "/proj", "project")).to.equal(true);
    expect(fakePanel.webview.postMessage.calledWith({ type: "mcpPreviewResult", requestId: "r1", result: payload })).to.equal(true);
  });

  it("dispatches mcpRunDoctor to bridge.doctor and posts mcpDoctorResult", async () => {
    const { vscodeStub, fakePanel, panelListeners } = makeVscodeStub();
    const { createMcpAgentsPanel } = load(vscodeStub);
    const diagnosis = { handshake_ok: true, error: null };
    const bridge = { preview: sinon.stub(), apply: sinon.stub(), rollback: sinon.stub(), doctor: sinon.stub().resolves(diagnosis) };
    const panel = createMcpAgentsPanel({ context: { extensionUri }, bridge, getProjectDir: () => "/proj" });
    panel.open();

    await panelListeners.onMessage({ type: "mcpRunDoctor", requestId: "r2" });

    expect(bridge.doctor.calledWith("/proj")).to.equal(true);
    expect(fakePanel.webview.postMessage.calledWith({ type: "mcpDoctorResult", requestId: "r2", result: diagnosis })).to.equal(true);
  });

  it("posts an error payload under the matching result type when the bridge rejects", async () => {
    const { vscodeStub, fakePanel, panelListeners } = makeVscodeStub();
    const { createMcpAgentsPanel } = load(vscodeStub);
    const bridge = {
      preview: sinon.stub(), apply: sinon.stub(), doctor: sinon.stub(),
      rollback: sinon.stub().rejects(new Error("no backup")),
    };
    const panel = createMcpAgentsPanel({ context: { extensionUri }, bridge, getProjectDir: () => "/proj" });
    panel.open();

    await panelListeners.onMessage({ type: "mcpRollback", requestId: "r3", agent: "claude", scope: "project" });

    expect(fakePanel.webview.postMessage.calledWith({ type: "mcpRollbackResult", requestId: "r3", error: "no backup" })).to.equal(true);
  });
});
