const { expect } = require("chai");
const proxyquire = require("proxyquire");
const sinon = require("sinon");

describe("chatHistoryBridge", () => {
  function makeBridge(runPythonStub) {
    return proxyquire("../shared/chatHistoryBridge", {
      "./pythonRunner": { makeRunPython: () => runPythonStub },
    }).makeChatHistoryBridge({ workspacePath: "/workspace" });
  }

  it("loads the workspace history from SQLite", async () => {
    const payload = { conversations: [], activeConversationId: "" };
    const runPython = sinon.stub().resolves({ stdout: JSON.stringify(payload) });

    const result = await makeBridge(runPython).loadHistory();

    expect(result).to.deep.equal(payload);
    expect(runPython.firstCall.args[0]).to.deep.equal([
      "backends/shared/chat_history.py",
      "load",
      "--workspace",
      "/workspace",
    ]);
  });

  it("sends history snapshots through stdin", async () => {
    const runPython = sinon.stub().resolves({ stdout: '{"conversations":[]}' });
    const bridge = makeBridge(runPython);
    const payload = { conversations: [{ id: "conv-1" }], activeConversationId: "conv-1" };

    await bridge.saveHistory(payload);

    expect(runPython.firstCall.args[0]).to.include("save");
    expect(JSON.parse(runPython.firstCall.args[1].input)).to.deep.equal(payload);
  });

  it("serializes mutations so an older snapshot cannot win", async () => {
    const resolvers = [];
    const runPython = sinon.stub().callsFake(() => new Promise((resolve) => resolvers.push(resolve)));
    const bridge = makeBridge(runPython);

    const first = bridge.saveHistory({ conversations: [{ id: "old" }] });
    const second = bridge.saveHistory({ conversations: [{ id: "new" }] });
    await new Promise((resolve) => setImmediate(resolve));
    expect(runPython.callCount).to.equal(1);
    resolvers.shift()({ stdout: "{}" });
    await first;
    await new Promise((resolve) => setImmediate(resolve));
    expect(runPython.callCount).to.equal(2);
    resolvers.shift()({ stdout: "{}" });
    await second;

    expect(JSON.parse(runPython.secondCall.args[1].input).conversations[0].id).to.equal("new");
  });

  it("accepts a new snapshot after a failed write", async () => {
    const runPython = sinon.stub();
    runPython.onFirstCall().rejects(new Error("database busy"));
    runPython.onSecondCall().resolves({ stdout: "{}" });
    const bridge = makeBridge(runPython);

    let failure;
    try {
      await bridge.saveHistory({ conversations: [{ id: "old" }] });
    } catch (error) {
      failure = error;
    }
    await bridge.saveHistory({ conversations: [{ id: "new" }] });

    expect(failure).to.be.an("error");
    expect(runPython.callCount).to.equal(2);
  });
});
