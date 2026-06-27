const { expect } = require("chai");
const proxyquire = require("proxyquire").noCallThru();

describe("staticHandlers functions radar", () => {
  it("loads symbols, calling conventions and radar together", async () => {
    const posted = [];
    const execFile = (pythonExe, args, opts, cb) => {
      const script = args[0];
      if (script.endsWith("backends/static/binary/symbols.py")) {
        cb(null, JSON.stringify({ symbols: [{ addr: "0x401000", name: "entry", type: "T", size: 32 }] }), "");
        return;
      }
      if (script.endsWith("backends/static/disasm/calling_convention.py")) {
        cb(null, JSON.stringify({ conventions: { "0x401000": { convention: "sysv" } } }), "");
        return;
      }
      if (script.endsWith("backends/static/analysis/function_radar.py")) {
        cb(null, JSON.stringify({ summary: { function_count: 1 }, functions: [{ addr: "0x401000", priority_score: 61 }] }), "");
        return;
      }
      cb(new Error(`unexpected script: ${script}`));
    };

    const staticHandlers = proxyquire("../static/staticHandlers", {
      vscode: {},
      child_process: { execFile },
      "../shared/utils": {
        detectPythonExecutable: () => "/usr/bin/python3",
        buildRuntimeEnv: () => ({ PATH: process.env.PATH || "" }),
      },
      "../shared/sharedHandlers": {
        normalizeRawArchName: (value) => value,
      },
      "./pluginState": {
        emptyPluginUiState: () => ({}),
        summarizePluginRuntimeState: (value) => value,
      },
    });

    const handlers = staticHandlers({
      root: "/repo",
      panel: { webview: { postMessage: (msg) => posted.push(msg) } },
      context: { globalState: { get: () => ({}) } },
    });

    await handlers.hubLoadFunctions({ binaryPath: "/tmp/demo.bin" });

    expect(posted).to.have.length(1);
    expect(posted[0]).to.deep.equal({
      type: "hubFunctionsDone",
      data: {
        symbols: { symbols: [{ addr: "0x401000", name: "entry", type: "T", size: 32 }] },
        cc: { conventions: { "0x401000": { convention: "sysv" } } },
        radar: { summary: { function_count: 1 }, functions: [{ addr: "0x401000", priority_score: 61 }] },
      },
    });
  });
});
