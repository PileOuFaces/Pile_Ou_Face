const { expect } = require("chai");
const { EventEmitter } = require("events");
const proxyquire = require("proxyquire").noCallThru();
const sinon = require("sinon");

function loadStaticHandlers(execFile, spawn) {
  return proxyquire("../static/staticHandlers", {
    child_process: { execFile, spawn },
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
      type: "hubPluginProgress",
      requestId: "req-1",
      feature: "demo_feature",
      percent: null,
      message: "Démarrage…",
    });
    const resultMessage = postMessage.getCalls().map((call) => call.args[0]).find((msg) => msg.type === "hubPluginResult");
    expect(resultMessage).to.deep.equal({
      type: "hubPluginResult",
      requestId: "req-1",
      feature: "demo_feature",
      plugin_id: "",
      result: { ok: true, value: 42 },
    });
  });

  it("streams plugin progress lines to VS Code and the webview", async () => {
    const execFile = sinon.stub();
    const spawn = sinon.stub().callsFake(() => {
      const proc = new EventEmitter();
      proc.stdout = new EventEmitter();
      proc.stderr = new EventEmitter();
      proc.kill = sinon.spy();
      process.nextTick(() => {
        proc.stderr.emit("data", 'POF_PROGRESS {"percent":25,"message":"Inspection packer"}\n');
        proc.stdout.emit("data", 'POF_PROGRESS {"percent":80,"message":"Signatures"}\n');
        proc.stdout.emit("data", JSON.stringify({
          ok: true,
          plugin_id: "pof.demo-plugin",
          command: "demo.scan.run",
          result: { ok: true, value: 99 },
        }));
        proc.emit("close", 0);
      });
      return proc;
    });
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile, spawn), postMessage);

    await handlers.hubPluginInvoke({
      requestId: "req-progress",
      feature: "demo_feature",
      payload: {},
    });

    const messages = postMessage.getCalls().map((call) => call.args[0]);
    expect(messages.filter((msg) => msg.type === "hubPluginProgress")).to.deep.equal([
      {
        type: "hubPluginProgress",
        requestId: "req-progress",
        feature: "demo_feature",
        percent: null,
        message: "Démarrage…",
      },
      {
        type: "hubPluginProgress",
        requestId: "req-progress",
        feature: "demo_feature",
        percent: 25,
        message: "Inspection packer",
      },
      {
        type: "hubPluginProgress",
        requestId: "req-progress",
        feature: "demo_feature",
        percent: 80,
        message: "Signatures",
      },
    ]);
    expect(messages.find((msg) => msg.type === "hubPluginResult")).to.deep.equal({
      type: "hubPluginResult",
      requestId: "req-progress",
      feature: "demo_feature",
      plugin_id: "pof.demo-plugin",
      result: { ok: true, value: 99 },
    });
    expect(execFile.called).to.equal(false);
    expect(spawn.calledOnce).to.equal(true);
  });

  it("grants plugin consent then re-fetches the plugin state", async () => {
    const execFile = sinon.stub().callsFake((_pythonBin, args, _options, callback) => {
      if (args.includes("consent-grant")) {
        expect(args).to.include("acme.new-plugin");
        callback(null, JSON.stringify({ ok: true, plugin_id: "acme.new-plugin", consent: {} }), "");
        return;
      }
      if (args.includes("list")) {
        callback(
          null,
          JSON.stringify({
            search_paths: [],
            summary: { active: 1 },
            attached: { commands: [], command_sources: {} },
            plugins: [
              {
                id: "acme.new-plugin",
                state: "active",
                manifest: {
                  name: "New Plugin",
                  version: "1.0.0",
                  kind: "analysis-pack",
                  ui: { family: "acme" },
                },
              },
            ],
          }),
          "",
        );
        return;
      }
      callback(new Error(`unexpected args: ${args.join(" ")}`));
    });
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile), postMessage);

    await handlers.hubGrantPluginConsent({ pluginId: "acme.new-plugin" });

    expect(execFile.callCount).to.equal(2);
    expect(execFile.firstCall.args[1]).to.include.members(["consent-grant", "acme.new-plugin"]);
    expect(postMessage.firstCall.args[0]).to.include({ type: "hubPluginState" });
    expect(postMessage.firstCall.args[0].state.plugins[0]).to.include({
      id: "acme.new-plugin",
      state: "active",
    });
  });

  it("does nothing when hubGrantPluginConsent is called without a pluginId", async () => {
    const execFile = sinon.stub();
    const postMessage = sinon.spy();
    const handlers = createHandlers(loadStaticHandlers(execFile), postMessage);

    await handlers.hubGrantPluginConsent({});

    expect(execFile.called).to.equal(false);
    expect(postMessage.called).to.equal(false);
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
