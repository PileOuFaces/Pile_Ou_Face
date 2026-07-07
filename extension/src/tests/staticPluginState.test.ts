const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

function loadStaticHandlers(execFile) {
  return proxyquire("../static/staticHandlers", {
    child_process: { execFile },
    "../shared/utils": {
      detectPythonExecutable: () => "/usr/bin/python3",
      buildRuntimeEnv: () => ({}),
    },
  });
}

function createHandlers(staticHandlers, postMessage) {
  return staticHandlers({
    root: "/workspace",
    panel: { webview: { postMessage } },
    context: { globalState: { get: () => ({}) } },
  });
}

describe("staticHandlers plugin bridge", () => {
  afterEach(() => {
    sinon.restore();
  });

  it("posts the summarized plugin state back to the webview", async () => {
    const execFile = sinon.stub().callsFake((_pythonBin, _args, _options, callback) => {
      callback(
        null,
        JSON.stringify({
          search_paths: ["/workspaceStorage/df663d3d38c329fe16f94cf93e5fd4d5/PileOuFaces.stack-visualizer/plugins"],
          summary: { active: 1 },
          attached: {
            commands: ["demo.scan.run"],
            command_sources: { "demo.scan.run": "pof.demo-plugin" },
          },
          plugins: [
            {
              id: "pof.demo-plugin",
              state: "active",
              manifest: {
                name: "Demo Plugin",
                version: "1.0.0",
                kind: "analysis-pack",
                distribution: { encrypted: true, bundle_format: "pofplug" },
                licensing: { required: true, mode: "key", status: "unlocked", message: "" },
                ui: { family: "demo" },
                capabilities: { analysis: ["demo.scan"] },
              },
            },
          ],
        }),
        "",
      );
    });
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile), postMessage);

    await handlers.hubLoadPluginState();

    expect(execFile.firstCall.args[1]).to.deep.equal([
      "/workspace/backends/plugins/runtime.py",
      "--host-version",
      "0.1.0",
      "--api-version",
      "1",
      "list",
      "--attach",
    ]);
    expect(postMessage.firstCall.args[0]).to.include({ type: "hubPluginState" });
    expect(postMessage.firstCall.args[0].state).to.include({
      loaded: true,
      pluginCount: 1,
    });
    expect(postMessage.firstCall.args[0].state.attachedCommands).to.deep.equal(["demo.scan.run"]);
  });

  it("invokes a plugin feature through the generic bridge", async () => {
    const execFile = sinon.stub().callsFake((_pythonBin, args, _options, callback) => {
      if (args.includes("invoke-feature") && args.includes("demo_feature")) {
        callback(
          null,
          JSON.stringify({
            ok: true,
            command: "demo.scan.run",
            result: { ok: true, value: 42 },
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile), postMessage);

    await handlers.hubPluginInvoke({
      requestId: "req-1",
      feature: "demo_feature",
      binaryPath: "/tmp/demo.bin",
      payload: { mode: "fast" },
    });

    expect(execFile.firstCall.args[1]).to.include.members([
      "/workspace/backends/plugins/runtime.py",
      "invoke-feature",
      "demo_feature",
    ]);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubPluginResult",
      requestId: "req-1",
      feature: "demo_feature",
      plugin_id: "",
      result: { ok: true, value: 42 },
    });
  });

  it("returns a generic error when no feature is provided", async () => {
    const execFile = sinon.stub();
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile), postMessage);

    await handlers.hubPluginInvoke({ requestId: "req-2" });

    expect(execFile.called).to.equal(false);
    expect(postMessage.firstCall.args[0]).to.deep.equal({
      type: "hubPluginResult",
      requestId: "req-2",
      feature: "",
      plugin_id: "",
      result: {
        ok: false,
        error: "feature manquante",
        plugin_required: "",
        feature: "",
      },
    });
  });
});
